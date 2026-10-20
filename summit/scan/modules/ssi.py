"""Server-side includes injection (CWE-96) - execution, not reflection.

An SSI directive only counts when the server executes it. The probe
asks the shell to echo a fresh marker; a page that merely reflects our
input contains the whole directive (and therefore the marker), so the
proof is: marker present AND raw payload absent. A server that parses
the include prints the marker without the directive, which means the
`exec` ran.
"""

from __future__ import annotations

import secrets

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint
from ..runtime import deep


class SsiInjectionCheck(Check):
    check_id = "ssi-injection"
    title = "Server-side includes injection (command execution)"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        marker = "summit" + secrets.token_hex(6)
        payloads = [f'<!--#exec cmd="echo {marker}"-->']
        if deep():
            payloads += [
                f'<!--#exec cmd="printf {marker}"-->',
                f'<!--#echo var="{marker}"-->',
            ]
        for payload in payloads:
            try:
                body = client.send(point.with_value(payload)).text[:100_000]
            except Exception:
                continue
            if marker in body and payload not in body:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=(
                            f"Parameter '{point.param}' ended up inside a server-parsed include. "
                            "The SSI `exec` directive ran and printed our marker - arbitrary "
                            "command execution on the web server, unless the whole site is sandboxed."
                        ),
                        evidence=f"exec marker {marker!r} printed without the raw directive",
                        remediation=(
                            "Do not render user input into SSI-parsed pages; disable mod_include "
                            "exec, and HTML-encode '<' and '#' on output."
                        ),
                    )
                ]
        return []
