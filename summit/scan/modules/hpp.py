"""HTTP Parameter Pollution (CWE-235) - duplicate parameter detection.

When a parameter appears twice in a URL (`?id=1&id=2`), different
server-side technologies handle it differently: PHP takes the last
value, ASP.NET concatenates, Apache takes the first. An attacker can
exploit this inconsistency to bypass validation on one layer while the
other layer sees a different value.

Detection: send the same parameter twice with different values. If the
server processes both (visible in the response as a change from the
baseline), the parameter is vulnerable to HPP.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Check, Finding, InjectionPoint


class HppCheck(Check):
    check_id = "hpp"
    title = "HTTP Parameter Pollution"
    severity = "medium"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        marker_a = "summit-hpp-a"
        marker_b = "summit-hpp-b"

        # Build URL with duplicated parameter: ?param=A&param=B
        split = urlsplit(point.request.url)
        base_query = split.query
        dup_query = (
            f"{base_query}&{point.param}={marker_a}&{point.param}={marker_b}"
            if base_query
            else f"{point.param}={marker_a}&{point.param}={marker_b}"
        )
        from urllib.parse import urlunsplit
        dup_url = urlunsplit(split._replace(query=dup_query))

        response = client.send(HttpRequest(method="GET", url=dup_url))
        baseline = client.send(point.request)

        # If BOTH markers appear in the response, the server concatenates
        # or processes both values - that is HPP.
        if marker_a in response.text and marker_b in response.text:
            if marker_a in baseline.text or marker_b in baseline.text:
                return []  # markers already present - not attributable to us
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="confirmed",
                    detail=(
                        f"Sending parameter '{point.param}' twice with different values "
                        f"({marker_a!r} and {marker_b!r}) caused the server to process BOTH values. "
                        "Different technologies handle duplicate parameters differently, which "
                        "attackers exploit to bypass validation on one layer while the other "
                        "layer sees a different value."
                    ),
                    evidence=f"both markers reflected: {marker_a!r} + {marker_b!r}",
                    remediation="Reject duplicate parameter names server-side; use a strict parameter parsing policy.",
                )
            ]

        # Check if only the last value is reflected (server takes last) - HPP signal
        if marker_b in response.text and marker_a not in response.text:
            if marker_b not in baseline.text and marker_a not in baseline.text:
                # Server takes last value - this is normal for PHP but exploitable
                # when a WAF checks the first value
                return [
                    Finding(
                        check_id=self.check_id,
                        title=f"{self.title} (last-value wins)",
                        severity="low",
                        url=point.request.url,
                        param=point.param,
                        confidence="potential",
                        detail=(
                            f"Parameter '{point.param}' appears twice and the server only uses the "
                            "last value. If a WAF or proxy checks the first value, this creates "
                            "a validation bypass: the WAF sees one value, the application sees another."
                        ),
                        evidence=f"last-value-wins: {marker_b!r} reflected, {marker_a!r} ignored",
                        remediation="Reject duplicate parameter names or implement consistent parameter handling across all layers.",
                    )
                ]
        return []
