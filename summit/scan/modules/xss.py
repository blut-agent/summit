from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint

PAYLOADS = [
    '"><svg/onload=alert(1)>',
    "'\"><img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "javascript:alert(1)",
]


class XssReflectCheck(Check):
    check_id = "xss-reflection"
    title = "Reflected XSS (potential)"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in PAYLOADS:
            request = point.request.with_query_param(point.param, payload)
            response = client.send(request)
            if payload in response.text:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        detail=f"Parameter '{point.param}' reflects the payload unencoded. Confirm in a browser - context matters.",
                        evidence=payload,
                        remediation="HTML-encode output based on context (attribute/body/JS) and apply a strict CSP.",
                    )
                ]
        return []
