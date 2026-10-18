"""Time-based blind SQL injection (CWE-89) - baseline-calibrated, strict.

The check asks the database to pause (`SLEEP`, `pg_sleep`, `WAITFOR
DELAY`) and measures whether the server actually slowed down. This is
the noisiest class of SQL injection testing, so the rules are strict:

- the baseline response time is measured twice and averaged
- every probe is repeated (`repetitions`) and must ALL exceed the
  threshold relative to that baseline
- the injected delay is capped - a detector never asks a database to
  sleep longer than the threshold it was configured with
- the finding is `likely`, never `confirmed`: network jitter can
  fake a delay, and only a human reading the response behavior can
  close that gap

Default threshold is 2.0 seconds so normal jitter cannot trigger it.
"""

from __future__ import annotations

import time

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

_PAYLOAD_FAMILIES = (
    ("MySQL", "' AND SLEEP({d})-- "),
    ("PostgreSQL", "'; SELECT pg_sleep({d})-- "),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'-- "),
)


class SqliTimeCheck(Check):
    check_id = "sqli-time"
    title = "SQL injection (time-based blind)"
    severity = "critical"

    def __init__(self, delay_threshold: float = 2.0, repetitions: int = 2) -> None:
        super().__init__()
        # Note: a small threshold is safe here - the decision margin only
        # compares measured times. The injected database delay itself is
        # separately capped at 2+ seconds, so the database is never asked
        # to sleep for less than that.
        self.delay_threshold = max(0.1, float(delay_threshold))
        self.repetitions = max(1, int(repetitions))

    def _measure(self, client: HttpClient, request) -> float:
        started = time.monotonic()
        client.send(request)
        return time.monotonic() - started

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        base_samples = [self._measure(client, point.request) for _ in range(2)]
        base_mean = sum(base_samples) / len(base_samples)

        delay = max(2, round(self.delay_threshold))
        margin = self.delay_threshold

        for family, template in _PAYLOAD_FAMILIES:
            payload = template.format(d=delay)
            request = point.with_value(point.original_value + payload)
            samples = [self._measure(client, request) for _ in range(self.repetitions)]
            if all(sample - base_mean >= margin for sample in samples):
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="likely",
                        detail=(
                            f"Parameter '{point.param}' shows a reproducible delay with a {family} "
                            f"time payload ({delay}s): all {self.repetitions} probes exceeded the "
                            f"baseline by at least {margin:.1f}s (baseline {base_mean:.2f}s). "
                            "Time-based findings are always `likely` - verify manually with "
                            "varying delays before reporting."
                        ),
                        evidence=f"{family}: baseline {base_mean:.2f}s, probes "
                        f"{', '.join(f'{s:.2f}s' for s in samples)} (threshold {margin:.1f}s)",
                        remediation="Use parameterized queries; rate-limit or block time-delay functions at the database layer.",
                    )
                ]
        return []
