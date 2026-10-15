from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint

# Stage 1 marker: a canary string that should never appear in a real page.
# If the parameter does not reflect it, the parameter is not reflected at
# all and the payload stage is skipped entirely. This is what keeps the
# check cheap, quiet, and low on false positives.
CANARY = "sx9summitcanaryx9s"

# Stage 2 payloads. HTML-breaking payloads that come back raw are a strong
# signal; the javascript: scheme payload only proves reflection, so it
# stays at "potential".
PAYLOADS = [
    '"><svg/onload=alert(1)>',
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "' onmouseover='alert(1)",
    "<script>alert(1)</script>",
    "javascript:alert(1)",
]


class XssReflectCheck(Check):
    check_id = "xss-reflection"
    title = "Reflected XSS (potential)"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        # Stage 1: cheap canary probe. No reflection -> no payload spraying.
        canary_response = client.send(point.request.with_query_param(point.param, CANARY))
        if CANARY not in canary_response.text:
            return []

        # Stage 2: the parameter reflects raw input, so try context payloads.
        for payload in PAYLOADS:
            request = point.request.with_query_param(point.param, payload)
            response = client.send(request)
            if payload in response.text:
                confirmed = "<" in payload
                return [
                    Finding(
                        check_id=self.check_id,
                        title="Reflected XSS" if confirmed else "Reflected XSS (potential)",
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed" if confirmed else "potential",
                        detail=(
                            f"Parameter '{point.param}' reflects input unencoded and the payload "
                            f"{payload!r} lands in the response. Confirm execution context in a browser."
                        ),
                        evidence=payload,
                        remediation="HTML-encode output based on context (attribute/body/JS) and apply a strict CSP.",
                    )
                ]

        # The parameter reflects input but every payload came back encoded or
        # stripped. Factual, info-level, and worth knowing.
        return [
            Finding(
                check_id="xss-reflection-hardened",
                title="User input reflected but encoded/filtered",
                severity="info",
                url=point.request.url,
                param=point.param,
                confidence="confirmed",
                detail=(
                    f"Parameter '{point.param}' reflects the canary marker, but every XSS payload "
                    "came back encoded or stripped. Likely safe - encoding or filtering is in place."
                ),
                evidence=CANARY,
                remediation="Keep the output encoding and re-test after framework upgrades.",
            )
        ]
