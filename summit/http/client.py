from __future__ import annotations

import time

import requests
import urllib3

from .models import HttpRequest, HttpResponse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": "Summit/0.1 (+https://github.com/pennacle-security/summit)",
    "Accept-Language": "en-US,en;q=0.9",
}

# Requests/urllib3 manage these themselves; forwarding stale values breaks uploads.
_STRIPPED_HEADERS = ("host", "content-length")


class HttpClient:
    """Thin wrapper around requests with timeout, delay and TLS-verify controls."""

    def __init__(
        self,
        timeout: float = 10.0,
        verify_tls: bool = False,
        user_agent: str | None = None,
        delay: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if user_agent:
            self.session.headers["User-Agent"] = user_agent

    def send(self, request: HttpRequest) -> HttpResponse:
        if self.delay:
            time.sleep(self.delay)
        started = time.monotonic()
        response = self.session.request(
            request.method,
            request.url,
            headers={k: v for k, v in request.headers.items() if k.lower() not in _STRIPPED_HEADERS},
            data=request.body,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=False,
        )
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
