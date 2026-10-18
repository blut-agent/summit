"""CRLF / HTTP response splitting (CWE-113).

Injects `%0d%0aHeader-Name: value` into a query parameter. If the server
echoes the parameter into a response header without stripping control
characters, the injected header materializes for real - detectable with
certainty because we named the header ourselves.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

INJECTED_HEADER = "X-Summit-CRLF"
PAYLOAD = "summit-ok\r\nX-Summit-CRLF: injected"


class CrlfInjectionCheck(Check):
    check_id = "crlf-injection"
    title = "CRLF injection / HTTP response splitting"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        request = point.with_value(PAYLOAD)
        response = client.send(request)
        if response.header(INJECTED_HEADER).lower() == "injected":
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="confirmed",
                    detail=(
                        f"Parameter '{point.param}' accepted CRLF sequences and the server emitted "
                        f"our {INJECTED_HEADER} header. Response splitting allows cache poisoning, "
                        "session fixation via injected cookies, and XSS via injected bodies."
                    ),
                    evidence=f"{INJECTED_HEADER}: injected",
                    remediation="Strip CR/LF from any user input that reaches response headers; use header APIs that reject control characters.",
                )
            ]
        return []
