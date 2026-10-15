"""CORS origin-reflection probe.

The passive check catches the wildcard+credentials misconfiguration.
This one catches the subtler and more dangerous pattern: a server that
reflects an arbitrary Origin header back into Access-Control-Allow-Origin
while allowing credentials. Any website the victim visits can then read
authenticated responses. The probe uses a domain under .example that
cannot resolve - nothing leaves the machine.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint

PROBE_ORIGIN = "https://summit-cors-probe.example"


class CorsReflectionCheck(Check):
    check_id = "cors-reflection"
    title = "CORS reflects arbitrary origin with credentials"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        response = client.send(point.request.with_header("Origin", PROBE_ORIGIN))
        allow_origin = response.header("access-control-allow-origin")
        allow_credentials = response.header("access-control-allow-credentials").strip().lower()
        if PROBE_ORIGIN not in allow_origin or allow_credentials != "true":
            return []
        return [
            Finding(
                check_id=self.check_id,
                title=self.title,
                severity=self.severity,
                url=point.request.url,
                param=point.param,
                confidence="confirmed",
                detail=(
                    f"Sending Origin: {PROBE_ORIGIN} makes the server answer "
                    f"Access-Control-Allow-Origin: {allow_origin} with credentials allowed. "
                    "Any website can read this endpoint's authenticated responses from a victim's browser."
                ),
                evidence=f"ACAO: {allow_origin}; ACAC: true",
                remediation="Whitelist trusted origins server-side; never reflect the Origin header.",
            )
        ]
