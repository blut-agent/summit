"""Host header injection probe.

Applications that build absolute URLs from the Host header (password
reset links, canonical tags, redirects) can be poisoned by sending a
Host of our choosing. The probe sets a marker domain and only reports
when the marker comes back - and only when it does NOT appear in a
baseline request, so pre-existing content can not trigger it.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint

MARKER = "summit-host-probe.example"


class HostHeaderInjectionCheck(Check):
    check_id = "host-header-injection"
    title = "Host header injection"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        response = client.send(point.request.with_header("Host", MARKER))
        in_body = MARKER in response.text
        in_location = MARKER in response.header("location")
        if not in_body and not in_location:
            return []

        baseline = client.send(point.request)
        if MARKER in baseline.text:
            return []  # the marker string was already on the page - not injection

        return [
            Finding(
                check_id=self.check_id,
                title=self.title,
                severity=self.severity,
                url=point.request.url,
                param=point.param,
                confidence="confirmed" if in_body else "likely",
                detail=(
                    f"Setting the Host header to {MARKER!r} makes the application echo it"
                    + (" in the response body" if in_body else " in the Location header")
                    + ". Wherever that URL reaches a user (reset links, redirects), "
                    "this is password-reset-poisoning surface."
                ),
                evidence=f"Host: {MARKER} -> reflected",
                remediation="Build absolute URLs from server-side configuration; never trust the Host header.",
            )
        ]
