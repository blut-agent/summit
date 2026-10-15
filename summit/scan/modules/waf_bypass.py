"""WAF-aware probing: when a naive filter blocks the standard payloads,
tamper variants often still land. This check runs everywhere but is
cheap - one canary request decides whether tampering is worth trying -
and it only reports a bypass when the ORIGINAL payload shows up decoded
in the response. Encoded-but-inert reflections do not count.
"""

from __future__ import annotations

from urllib.parse import quote

from ...http.client import HttpClient
from ...waf import detect_waf
from ..core import Check, Finding, InjectionPoint

CANARY = "sx9summitcanaryx9s"
PAYLOAD = "'\"><svg/onload=alert(1)>"

BLOCK_STATUSES = (403, 406, 418, 429)


def tamper_variants(payload: str) -> list[tuple[str, str]]:
    return [
        ("double URL-encoding", quote(quote(payload, safe=""), safe="")),
        ("single URL-encoding", quote(payload, safe="")),
        ("comment splitting", payload.replace("svg", "sv<!-- -->g").replace("onload", "on<!-- -->load")),
        ("case alternation", "".join(ch.upper() if index % 2 else ch.lower() for index, ch in enumerate(payload))),
    ]


class WafBypassCheck(Check):
    check_id = "waf-bypass"
    title = "WAF filter bypass"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        canary_response = client.send(point.request.with_query_param(point.param, CANARY))
        waf = detect_waf(canary_response)
        blocked = canary_response.status in BLOCK_STATUSES or waf is not None
        if not blocked and CANARY in canary_response.text:
            return []  # nothing filtered here; the plain XSS check covers this path

        for label, variant in tamper_variants(PAYLOAD):
            response = client.send(point.request.with_query_param(point.param, variant))
            if response.status == 200 and PAYLOAD in response.text:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=(
                            f"Parameter '{point.param}' is filtered"
                            + (f" ({waf[0]} in front)" if waf else "")
                            + f", but the payload landed decoded in the response after {label}. "
                            "The filter normalizes input inconsistently."
                        ),
                        evidence=f"{label}: {variant}",
                        remediation="Normalize/decode input before filtering, at the application layer - not in the WAF rule alone.",
                    )
                ]
        return []
