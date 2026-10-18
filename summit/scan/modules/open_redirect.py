from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint
from ..runtime import deep

# .example never resolves, so this probe can not hit a real third party.
REDIRECT_TARGET = "summit-open-redirect-probe.example"

PAYLOADS = [
    f"https://{REDIRECT_TARGET}/",
    f"//{REDIRECT_TARGET}/",
    f"/\\{REDIRECT_TARGET}/",
]

# Deep mode: parsing quirks that survive naive "must start with our host" checks.
DEEP_PAYLOADS = [
    f"////{REDIRECT_TARGET}/",
    f"https:{REDIRECT_TARGET}/",
    f"/%2F%2F{REDIRECT_TARGET}/",
    f"/\\/\\{REDIRECT_TARGET}/",
]

_URL_PARAM_HINTS = ("url", "redirect", "next", "return", "goto", "link", "target", "dest", "continue")


class OpenRedirectCheck(Check):
    check_id = "open-redirect"
    title = "Open redirect"
    severity = "medium"

    def _is_url_like(self, point: InjectionPoint) -> bool:
        value = point.original_value.strip().lower()
        if value.startswith(("http", "//", "/")):
            return True
        name = point.param.lower()
        return any(hint in name for hint in _URL_PARAM_HINTS)

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if not self._is_url_like(point):
            return []
        payloads = (PAYLOADS + DEEP_PAYLOADS) if deep() else PAYLOADS
        for payload in payloads:
            request = point.with_value(payload)
            response = client.send(request)
            if response.status in (301, 302, 303, 307, 308) and REDIRECT_TARGET in response.header("location"):
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=f"Parameter '{point.param}' causes a redirect to an external host.",
                        evidence=f"Location: {response.header('location')}",
                        remediation="Validate redirect targets against a server-side allowlist.",
                    )
                ]
            snippet = response.text[:5000].lower()
            if response.status == 200 and REDIRECT_TARGET in snippet:
                if "<meta http-equiv=\"refresh\"" in snippet or "window.location" in snippet or "location.href" in snippet:
                    return [
                        Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=self.severity,
                            url=point.request.url,
                            param=point.param,
                            confidence="likely",
                            detail=f"Parameter '{point.param}' is reflected into a client-side redirect construct.",
                            evidence=REDIRECT_TARGET,
                            remediation="Validate redirect targets against a server-side allowlist.",
                        )
                    ]
        return []
