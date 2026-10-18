"""Server-side request forgery, out-of-band confirmed (CWE-918).

SSRF cannot be proven from the response alone - most fetchers return a
status code you could get from any endpoint. This check therefore only
reports a finding when the target actually calls back to a listener we
control (`summit scan --oob-listen`). No listener, no finding: the
zero-false-positive rule outranks coverage here.
"""

from __future__ import annotations

from typing import Callable

from ...oob import new_token
from ..core import Check, Finding, InjectionPoint
from ...http.client import HttpClient

_PARAM_HINTS = (
    "url", "uri", "link", "src", "dest", "destination", "redirect", "next", "target",
    "continue", "fetch", "proxy", "image", "img", "avatar", "callback", "webhook",
    "feed", "host", "domain", "site", "ref", "return", "out", "view", "file", "path", "load",
)


class SsrfCheck(Check):
    check_id = "ssrf"
    title = "Server-side request forgery (OOB-confirmed)"
    severity = "high"

    def __init__(
        self,
        callback_base: str,
        hit_checker: Callable[[str], bool] | None = None,
        wait_timeout: float = 3.0,
    ) -> None:
        self.callback_base = callback_base.rstrip("/")
        self.hit_checker = hit_checker
        self.wait_timeout = wait_timeout

    def _worthy(self, point: InjectionPoint) -> bool:
        value = point.original_value.strip().lower()
        if value.startswith(("http://", "https://", "//")):
            return True
        return any(hint in point.param.lower() for hint in _PARAM_HINTS)

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if not self.callback_base or not self._worthy(point):
            return []
        token = new_token("ssrf")
        callback = f"{self.callback_base}/{token}"
        payloads = [
            callback,
            f"{callback}?u={token}",
            f"//{callback.split('//', 1)[1]}",
        ]
        for payload in payloads:
            try:
                client.send(point.with_value(payload))
            except Exception:
                continue
            if self.hit_checker is not None and self.hit_checker(token):
                return [
                    Finding(
                        check_id="ssrf",
                        title="Server-side request forgery (out-of-band confirmed)",
                        severity="high",
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=(
                            f"Submitting a callback URL in '{point.param}' made the server issue a "
                            "request to our listener. No browser is involved: the server itself fetched "
                            "an attacker-chosen URL, which is the core of SSRF. It can reach internal "
                            "networks, cloud metadata (169.254.169.254) and localhost services."
                        ),
                        evidence=f"OOB hit received for token {token} after payload {payload[:80]}",
                        remediation=(
                            "Do not let user input choose outbound URLs. Resolve and allow-list hosts, "
                            "block private/link-local ranges, and require authentication on fetch endpoints."
                        ),
                    )
                ]
        return []
