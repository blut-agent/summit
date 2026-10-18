"""LDAP injection (CWE-90) - differential detection.

LDAP filters built from user input can be manipulated with metacharacters
(`*`, `)(`, `|`, `&`). The check sends LDAP metacharacter payloads and
looks for a response change that suggests the filter was altered.

Detection is differential (baseline vs probe), with an FP guard: the
probe values contain no injection-specific keywords, so a page that
merely echoes input will show identical responses and stay quiet.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

# (payload, what it proves)
LDAP_PAYLOADS = [
    ("*", "wildcard - matches all entries"),
    (")(|(", "filter closure - breaks out and ORs a new condition"),
    ("*)(objectClass=*", "objectClass injection - reveals directory structure"),
    ("*))%00", "null byte - truncates the filter and bypasses remaining conditions"),
]


class LdapInjectionCheck(Check):
    check_id = "ldap-injection"
    title = "LDAP injection"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request)
        base_sig = (baseline.status, len(baseline.body))

        for payload, description in LDAP_PAYLOADS:
            request = point.with_value(point.original_value + payload)
            response = client.send(request)
            new_sig = (response.status, len(response.body))

            if new_sig == base_sig:
                continue

            # Response changed - the LDAP filter was likely altered.
            # Double-check: the response should NOT simply be a reflection
            # of the payload (that would be XSS, not LDAP injection).
            if payload in response.text and new_sig[1] > base_sig[1]:
                continue  # pure reflection, not filter manipulation

            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="likely",
                    detail=(
                        f"Injecting LDAP metacharacters ({payload!r}) into parameter '{point.param}' "
                        f"changed the response (HTTP {baseline.status}/{len(baseline.body)}B -> "
                        f"{response.status}/{len(response.body)}B). {description}."
                    ),
                    evidence=f"{point.original_value + payload!r} -> response changed",
                    remediation="Escape LDAP metacharacters (*, (, ), \\, NUL) before building filters; use parameterized LDAP queries.",
                )
            ]
        return []
