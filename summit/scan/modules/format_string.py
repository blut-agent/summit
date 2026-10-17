"""Format string injection (CWE-134).

Format string vulnerabilities occur when user input is passed as a
format string to printf-style functions. Injecting `%s`, `%x`, `%n`
sequences can leak stack memory (%x), crash the process (%n writes),
or read arbitrary memory (%s).

Detection: if the response contains hex values (from %x) or repeated
content (from %s) that wasn't in the baseline, the format string was
processed by a vulnerable function.
"""

from __future__ import annotations

import re

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

PROBES = [
    ("%x" * 8, "stack leak via %x - 8 consecutive hex words"),
    ("%s" * 4, "memory read via %s - 4 consecutive string dereferences"),
    ("%n", "arbitrary memory write via %n - dangerous, may crash the process"),
]


class FormatStringCheck(Check):
    check_id = "format-string"
    title = "Format string injection (potential)"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request)
        baseline_hex = set(re.findall(r"[0-9a-f]{4,8}", baseline.text))

        for payload, description in PROBES:
            request = point.request.with_query_param(point.param, point.original_value + payload)
            response = client.send(request)

            if payload not in response.text:
                continue  # payload was encoded or stripped - not a format string issue

            # Look for new hex values that appeared after the payload
            # (evidence that %x actually read stack memory)
            response_hex = set(re.findall(r"[0-9a-f]{4,8}", response.text))
            new_hex = response_hex - baseline_hex - {f"{ord(c):04x}" for c in payload}

            if payload.startswith("%x") and len(new_hex) >= 3:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=(
                            f"Parameter '{point.param}' was processed as a format string: "
                            f"injecting {'%x' * 8} produced {len(new_hex)} new hex values in the "
                            "response, indicating stack memory was read. Format string "
                            "vulnerabilities can leak memory (%x), read arbitrary addresses (%s), "
                            "and write to memory (%n)."
                        ),
                        evidence=f"payload: {payload!r} -> {len(new_hex)} new hex values: {sorted(new_hex)[:5]}",
                        remediation="Never pass user input as a format string. Use `printf('%s', input)` instead of `printf(input)`.",
                    )
                ]
        return []
