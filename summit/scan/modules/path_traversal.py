from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

INDICATORS = [
    "root:x:0:0:",
    "[fonts]",
    "; for 16-bit app support",
    "extensions=none",
]


class PathTraversalCheck(Check):
    check_id = "path-traversal"
    title = "Path traversal (potential)"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in PAYLOADS:
            request = point.request.with_query_param(point.param, payload)
            response = client.send(request)
            for indicator in INDICATORS:
                if indicator in response.text:
                    return [
                        Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=self.severity,
                            url=point.request.url,
                            param=point.param,
                            detail=f"Parameter '{point.param}' returned file contents when given {payload!r}.",
                            evidence=indicator,
                            remediation="Canonicalize and whitelist allowed file paths; never pass user input to filesystem APIs.",
                        )
                    ]
        return []
