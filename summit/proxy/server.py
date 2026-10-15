from __future__ import annotations

import socket
import sqlite3
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProxyServer:
    """Minimal intercepting HTTP proxy with a SQLite site map.

    v0.1 scope, kept honest:
      - plain HTTP requests are forwarded and logged
      - HTTPS CONNECT tunnels are logged and passed through (TLS interception
        is on the roadmap and needs a generated CA certificate)

    Known limitation: request bodies are only read from the initial buffer,
    which covers typical proxy use (browsers send small bodies in one packet)
    but not multi-megabyte uploads.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, db_path: str = "summit_sitemap.db") -> None:
        self.host = host
        self.port = port
        self.db_path = db_path
        self._server: socket.socket | None = None
        self._running = False
        self._db_lock = threading.Lock()
        self._forwarder = requests.Session()
        # Keep the response bytes plain so we can relay them untouched.
        self._forwarder.headers["Accept-Encoding"] = "identity"
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sitemap ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts TEXT, method TEXT, url TEXT, status INTEGER, length INTEGER)"
        )
        conn.commit()
        conn.close()

    def _log(self, method: str, url: str, status: int, length: int) -> None:
        with self._db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO sitemap (ts, method, url, status, length) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), method, url, status, length),
            )
            conn.commit()
            conn.close()

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(50)
        self._running = True
        print(f"[*] summit proxy listening on {self.host}:{self.port} (site map: {self.db_path})")
        while self._running:
            try:
                conn, _addr = self._server.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._server is not None:
            self._server.close()

    def _handle(self, conn: socket.socket) -> None:
        try:
            head = self._read_head(conn)
            if not head:
                return
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = request_line.split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                self._handle_connect(conn, target)
            else:
                self._handle_http(conn, method, target, head)
        finally:
            conn.close()

    @staticmethod
    def _read_head(conn: socket.socket, limit: int = 65536) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < limit:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk
        return data

    def _handle_connect(self, conn: socket.socket, target: str) -> None:
        host, _, port_text = target.partition(":")
        port = int(port_text or 443)
        self._log("CONNECT", f"https://{target}", 0, 0)
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        # TLS interception is not implemented yet, so we relay the encrypted stream.
        client_to_remote = threading.Thread(target=self._pipe, args=(conn, remote), daemon=True)
        remote_to_client = threading.Thread(target=self._pipe, args=(remote, conn), daemon=True)
        client_to_remote.start()
        remote_to_client.start()
        client_to_remote.join()
        remote.close()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass

    def _handle_http(self, conn: socket.socket, method: str, target: str, head: bytes) -> None:
        split = urlsplit(target)
        if not split.netloc:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        headers: dict[str, str] = {}
        body = b""
        pieces = head.split(b"\r\n\r\n", 1)
        if len(pieces) == 2:
            for raw_line in pieces[0].split(b"\r\n")[1:]:
                decoded = raw_line.decode("latin-1")
                if ":" in decoded:
                    key, _, value = decoded.partition(":")
                    headers[key.strip()] = value.strip()
            body = pieces[1]
        for hop in ("proxy-connection", "keep-alive", "connection"):
            headers.pop(hop, None)
        try:
            response = self._forwarder.request(
                method,
                target,
                headers=headers,
                data=body if body else None,
                timeout=30,
                allow_redirects=False,
                verify=False,
            )
        except requests.RequestException:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        headers_out = "".join(f"{key}: {value}\r\n" for key, value in response.headers.items())
        conn.sendall((status_line + headers_out + "\r\n").encode("latin-1", errors="replace") + response.content)
        self._log(method, target, response.status_code, len(response.content))
