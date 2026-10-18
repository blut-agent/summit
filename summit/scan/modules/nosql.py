"""NoSQL injection detection (CWE-943).

MongoDB, CouchDB and Redis-backed applications that accept JSON-like
parameters can be manipulated with operators such as `$ne`, `$gt`,
`$regex` and `$where`. The check sends operator payloads and looks for
a meaningful response change - not just a reflection.

Detection is differential: baseline vs operator-injected. The response
must change in a way that suggests the operator was processed (different
data set returned, different error, different status).
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

# (operator payload, what it proves)
NOSQL_PAYLOADS = [
    ("[$ne]=invalid", "$ne operator - bypasses equality checks"),
    ("[$gt]=", "$gt operator - returns records beyond the target"),
    ("[$regex]=.*", "$regex operator - matches everything"),
    ("[$exists]=true", "$exists operator - reveals internal field structure"),
    ("[$where]=1==1", "$where operator - JavaScript execution in MongoDB"),
]


class NosqlInjectionCheck(Check):
    check_id = "nosql-injection"
    title = "NoSQL injection"
    severity = "critical"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request)
        base_sig = (baseline.status, len(baseline.body))

        for payload_suffix, description in NOSQL_PAYLOADS:
            # Build the operator-injected value: `value[$ne]=invalid`
            injected_param = f"{point.param}{payload_suffix.split('=')[0]}]"
            injected_value = payload_suffix.split("=", 1)[1] if "=" in payload_suffix else ""
            request = point.request.with_query_param(injected_param, injected_value)
            response = client.send(request)

            new_sig = (response.status, len(response.body))
            if new_sig == base_sig:
                continue

            # The response changed meaningfully - the operator was processed.
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=injected_param,
                    confidence="likely",
                    detail=(
                        f"Injecting {payload_suffix} on parameter '{point.param}' changed the "
                        f"response (HTTP {baseline.status}/{len(baseline.body)}B -> "
                        f"{response.status}/{len(response.body)}B). The application may be "
                        "passing user input directly into a NoSQL query. {description}."
                    ),
                    evidence=f"{injected_param}={injected_value} -> response changed",
                    remediation="Sanitize input types; reject non-string values for query parameters; use ODM/library-level parameterized queries.",
                )
            ]
        return []
