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

import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


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
        return self.base_url

    def stop(self) -> None:
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
