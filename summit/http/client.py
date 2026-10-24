from __future__ import annotations

import threading
import time

import requests

from .. import __version__
from ..ratelimit import RateLimiter
from .models import HttpRequest, HttpResponse

DEFAULT_HEADERS = {
    "User-Agent": f"Summit/{__version__} (+https://github.com/pennacle-security/summit)",
    "Accept-Language": "en-US,en;q=0.9",
}

# Only Content-Length is stripped - requests manages it. Host is honored when
# explicitly provided (repeater files, host-header-injection probes); requests
# derives it from the URL otherwise.
_STRIPPED_HEADERS = ("content-length",)


class HttpClient:
    """Thin wrapper around requests with timeout, delay and TLS-verify controls."""

    def __init__(
        self,
        timeout: float = 10.0,
        verify_tls: bool = True,
        user_agent: str | None = None,
        delay: float = 0.0,
        rate: float | None = None,
        retries: int = 1,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self.rate_limiter = RateLimiter(1.0 / rate) if rate and rate > 0 else None
        self.retries = max(0, retries)
        self.request_count = 0
        self._count_lock = threading.Lock()
        self.session = requests.Session()
        # Scans stay deterministic: never inherit proxy/TLS settings from the
        # environment. This also keeps requests' eager redirect-target parsing
        # (Response.next is computed even with allow_redirects=False) away from
        # hostile Location headers, which could otherwise raise ValueError
        # mid-send on a crafted 3xx target.
        self.session.trust_env = False
        self.session.headers.update(DEFAULT_HEADERS)
        if user_agent:
            self.session.headers["User-Agent"] = user_agent

    def send(self, request: HttpRequest, allow_redirects: bool = False) -> HttpResponse:
        attempt = 0
        while True:
            if self.rate_limiter is not None:
                self.rate_limiter.wait()
            elif self.delay:
                time.sleep(self.delay)
            started = time.monotonic()
            with self._count_lock:
                self.request_count += 1
            try:
                response = self.session.request(
                    request.method,
                    request.url,
                    headers={k: v for k, v in request.headers.items() if k.lower() not in _STRIPPED_HEADERS},
                    data=request.body,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=allow_redirects,
                )
            except requests.RequestException:
                if attempt < self.retries:
                    attempt += 1
                    time.sleep(min(2**attempt, 8))
                    continue
                raise
            # Rate-limited or backend hiccup: honor Retry-After (capped), back off, retry.
            if response.status_code in (429, 503) and attempt < self.retries:
                attempt += 1
                retry_after = response.headers.get("Retry-After", "")
                pause = float(retry_after) if retry_after.isdigit() else 2**attempt
                time.sleep(min(max(pause, 1.0), 30.0))
                continue
            break
        elapsed = time.monotonic() - started
        # response.raw keeps the raw header list, so multiple Set-Cookie survive.
        raw_headers = response.raw.headers if response.raw is not None else None
        set_cookies = list(raw_headers.getlist("Set-Cookie")) if raw_headers is not None else []
        return HttpResponse(
            status=response.status_code,
            headers=dict(response.headers),
            body=response.content,
            request=request,
            elapsed=elapsed,
            set_cookies=set_cookies,
        )

    def get(self, url: str) -> HttpResponse:
        return self.send(HttpRequest(method="GET", url=url))
