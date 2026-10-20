"""Out-of-band collaboration server - HTTP callbacks without a SaaS.

Blind SSRF, blind XXE and blind command injection have no response
channel. The standard answer is an external collaborator service; the
summit answer is to bring your own listener. `summit oob` starts a
small threaded HTTP server that records every hit and lets a scan
correlate a payload token with an incoming callback.

The listener only records and acknowledges - it never executes
anything, never proxies, and binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

_RAW_TOKEN_RE = re.compile(rb"([a-z]{2,12}[a-z0-9]{0,8}[0-9a-f]{16})")


def _extract_raw_token(data: bytes) -> str:
    """Pull our probe token out of a non-HTTP payload (JNDI/LDAP bind).

    Prefixes are alphanumeric (`log4j`, `xxe`, `shell`), so the pattern
    allows digits between the letter prefix and the 16 hex characters.
    """
    match = _RAW_TOKEN_RE.search(data)
    return match.group(1).decode() if match else ""



def new_token(prefix: str = "sm") -> str:
    return f"{prefix}{secrets.token_hex(8)}"


@dataclass
class OobHit:
    token: str
    method: str
    path: str
    query: str
    headers: dict[str, str] = field(default_factory=dict)
    remote: str = ""
    timestamp: float = field(default_factory=time.time)

    def summary(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        remote = self.remote or "unknown"
        query = f"?{self.query}" if self.query else ""
        return f"{stamp}  {self.method:<6} {self.path}{query}  from {remote}  token={self.token or '-'}"


def _extract_token(path: str, query: str) -> str:
    query_token = parse_qs(query).get("token", [""])[0]
    if query_token:
        return query_token
    # /probe/<token> or /<token> - ignore favicon and health probes.
    segments = [segment for segment in urlsplit(path).path.split("/") if segment]
    if segments and segments[-1] not in ("favicon.ico", "health", "healthz", "robots.txt"):
        return segments[-1]
    return ""


class _Handler(BaseHTTPRequestHandler):
    server_version = "summit-oob/1.0"

    def _record(self, method: str) -> None:
        split = urlsplit(self.path)
        token = _extract_token(split.path, split.query)
        hit = OobHit(
            token=token,
            method=method,
            path=split.path or "/",
            query=split.query,
            headers={key: value for key, value in self.headers.items()},
            remote=self.client_address[0] if self.client_address else "",
        )
        self.server.owner.record(hit)  # type: ignore[attr-defined]
        body = f"summit-oob hit {token or 'recorded'}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._record("GET")

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        self._record("POST")

    def do_PUT(self) -> None:  # noqa: N802 - http.server API
        self._record("PUT")

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        self._record("HEAD")

    def log_message(self, *args) -> None:
        # The hit log is the interface; the default stderr line is noise.
        pass


class OobServer:
    """Threaded HTTP listener that records callback hits by token."""

    def __init__(self, bind: str = "127.0.0.1", port: int = 9999, advertise_host: str = "") -> None:
        self.bind = bind
        self.port = port
        self.advertise_host = advertise_host or ("127.0.0.1" if bind in ("0.0.0.0", "") else bind)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._raw_server: socket.socket | None = None
        self._raw_thread: threading.Thread | None = None
        self.raw_port = 0
        self._hits: list[OobHit] = []
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        if self._server is not None:
            return self.base_url
        server = ThreadingHTTPServer((self.bind, self.port), _Handler)
        server.daemon_threads = True
        server.owner = self  # type: ignore[attr-defined]
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, name="summit-oob", daemon=True)
        self._thread.start()
        self._start_raw()
        return self.base_url

    def _start_raw(self) -> None:
        """A plain TCP listener catches JNDI/LDAP callbacks.

        Log4Shell resolves `jndi:ldap://host:port/token` with an LDAP
        bind - bytes an HTTP server refuses. The token still travels in
        the bind DN, so a raw accept() is enough to prove the lookup.
        """
        if self._raw_server is not None:
            return
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.bind, 0))
        raw.listen(16)
        raw.settimeout(0.5)
        self.raw_port = raw.getsockname()[1]
        self._raw_server = raw
        self._raw_thread = threading.Thread(target=self._serve_raw, name="summit-oob-raw", daemon=True)
        self._raw_thread.start()

    def _serve_raw(self) -> None:
        server = self._raw_server
        while self._raw_server is server and server is not None:
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2.0)
                data = conn.recv(4096)
            except OSError:
                data = b""
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            self.record(OobHit(
                token=_extract_raw_token(data),
                method="TCP",
                path="(jndi)",
                query="",
                remote=address[0] if address else "",
            ))

    def stop(self) -> None:
        if self._raw_server is not None:
            try:
                self._raw_server.close()
            except OSError:
                pass
            self._raw_server = None
            self._raw_thread = None
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def base_url(self) -> str:
        return f"http://{self.advertise_host}:{self.port}"

    def callback_url(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    @property
    def raw_base(self) -> str:
        """Host:port of the raw TCP listener (JNDI/LDAP callbacks)."""
        return f"{self.advertise_host}:{self.raw_port}"

    def raw_url(self, token: str) -> str:
        return f"{self.raw_base}/{token}"

    # -- hit bookkeeping ---------------------------------------------------

    def record(self, hit: OobHit) -> None:
        with self._lock:
            self._hits.append(hit)

    @property
    def hits(self) -> list[OobHit]:
        with self._lock:
            return list(self._hits)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()

    def seen(self, token: str) -> bool:
        with self._lock:
            return any(hit.token == token for hit in self._hits)

    def wait_for(self, token: str, timeout: float = 5.0, interval: float = 0.1) -> OobHit | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for hit in self._hits:
                    if hit.token == token:
                        return hit
            time.sleep(interval)
        return None

    def format_hits(self) -> str:
        hits = self.hits
        if not hits:
            return "no callbacks yet"
        return "\n".join(hit.summary() for hit in hits)
