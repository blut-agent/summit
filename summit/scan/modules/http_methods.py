"""HTTP method hygiene (CWE-650, CWE-693) - OPTIONS/TRACE probe.

TRACE hands the request back to the caller, which is the engine behind
Cross-Site Tracing; combined with a weak HttpOnly story it re-exposes
cookies to script. We confirm TRACE only when our own marker header
comes back (an observed fact), and merely *advertise* PUT/DELETE/PATCH
when the server's Allow header lists them - we never send a write
request to a production host.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding

_TRACE_MARKER = "summit-trace-probe-9f3c2a"


def run_http_methods(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []

    allowed: set[str] = set()
    try:
        options = client.send(HttpRequest(method="OPTIONS", url=base_url))
        allow_header = options.header("allow")
        allowed = {method.strip().upper() for method in allow_header.split(",") if method.strip()}
    except Exception:
        pass

    # TRACE: send it directly - if the server echoes our marker, it is on.
    try:
        trace = client.send(
            HttpRequest(method="TRACE", url=base_url, headers={"X-Summit-Trace": _TRACE_MARKER})
        )
        echoed = _TRACE_MARKER in trace.text or trace.header("x-summit-trace") == _TRACE_MARKER
        if echoed:
            findings.append(
                Finding(
                    check_id="trace-enabled",
                    title="TRACE method enabled (Cross-Site Tracing surface)",
                    severity="high",
                    url=base_url,
                    confidence="confirmed",
                    detail=(
                        "The server answers TRACE and echoes the request - including our probe header - "
                        "straight back. In older browsers this re-exposes HttpOnly cookies to "
                        "cross-site scripting; modern browsers block TRACE via fetch/XHR, so treat this "
                        "as a hardening gap with a clear fix."
                    ),
                    evidence=f"TRACE {base_url} echoed X-Summit-Trace: {_TRACE_MARKER}",
                    remediation="Disable the TRACE method at the web server or reverse proxy.",
                )
            )
        elif "TRACE" in allowed:
            findings.append(
                Finding(
                    check_id="http-methods-advertised",
                    title="TRACE advertised in Allow header",
                    severity="medium",
                    url=base_url,
                    confidence="likely",
                    detail=(
                        "OPTIONS reports TRACE in the Allow header, but our marker was not echoed back. "
                        "The method may still be accepted in other shapes - review the server config."
                    ),
                    evidence=f"Allow: {', '.join(sorted(allowed))}",
                    remediation="Disable TRACE at the web server or reverse proxy.",
                )
            )
    except Exception:
        pass

    dangerous = sorted(allowed & {"PUT", "DELETE", "PATCH"})
    if dangerous:
        findings.append(
            Finding(
                check_id="http-methods-advertised",
                title=f"Write HTTP methods advertised: {', '.join(dangerous)}",
                severity="medium",
                url=base_url,
                confidence="likely",
                detail=(
                    f"OPTIONS lists write-capable methods ({', '.join(dangerous)}). We did not send a "
                    "write request - this is the server's own advertisement - but if those endpoints "
                    "lack authentication, they are a direct path to data tampering."
                ),
                evidence=f"Allow: {', '.join(sorted(allowed))}",
                remediation="Disable unused write methods at the server; require authentication and CSRF protection on the rest.",
            )
        )
    return findings
