"""Race condition detection - concurrent state manipulation.

Race conditions exist when concurrent requests produce a state that
sequential requests cannot. The classic examples: double-spending a
gift card, withdrawing more than the balance, creating duplicate
accounts, bypassing rate limits.

Detection strategy:

1. send one request sequentially to establish the baseline response
2. send N identical requests concurrently
3. compare: if concurrent responses differ from the baseline in a
   meaningful way (different body, different status, different side
   effects visible in the response), the server has a concurrency bug

This is always `potential` - only a human who understands the business
logic can confirm that the differing responses represent an exploit
rather than expected variation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ...http.client import HttpClient
from ...http.models import HttpRequest, HttpResponse
from ..scan.core import Finding


@dataclass
class RaceResult:
    url: str
    baseline: HttpResponse
    concurrent: list[HttpResponse]
    unique_responses: int
    verdict: str  # no-race | possible-race


def _fingerprint(response: HttpResponse) -> tuple:
    return (response.status, len(response.body))


def run_race_test(
    client: HttpClient,
    url: str,
    concurrency: int = 10,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> RaceResult:
    """Send one sequential request, then N concurrent identical requests."""
    request = HttpRequest(method=method, url=url, headers=headers or {}, body=body)

    baseline = client.send(request)
    base_fp = _fingerprint(baseline)

    concurrent_responses: list[HttpResponse] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(client.send, request) for _ in range(concurrency)]
        for future in as_completed(futures):
            concurrent_responses.append(future.result())

    unique_fps = {_fingerprint(r) for r in concurrent_responses}
    all_fps = unique_fps | {base_fp}

    if len(all_fps) == 1:
        verdict = "no-race"
    elif len(unique_fps) > 1 or (len(all_fps) > 1 and base_fp not in unique_fps):
        verdict = "possible-race"
    else:
        verdict = "possible-race"

    return RaceResult(
        url=url,
        baseline=baseline,
        concurrent=concurrent_responses,
        unique_responses=len(unique_fps),
        verdict=verdict,
    )


def findings_from(results: list[RaceResult]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        if result.verdict != "possible-race":
            continue
        statuses = sorted({r.status for r in result.concurrent})
        sizes = sorted({len(r.body) for r in result.concurrent})
        findings.append(
            Finding(
                check_id="race-condition",
                title="Race condition (concurrent requests produce different responses)",
                severity="high",
                url=result.url,
                confidence="potential",
                detail=(
                    f"{len(result.concurrent)} concurrent requests produced "
                    f"{result.unique_responses} unique response(s) that differ from the "
                    f"sequential baseline (HTTP {result.baseline.status}/{len(result.baseline.body)}B). "
                    "If this endpoint performs a state change (balance transfer, voucher redemption, "
                    "rate limit), concurrent requests may bypass the check. Verify manually by "
                    "inspecting server-side state after the race."
                ),
                evidence=f"statuses: {statuses}, sizes: {sizes}, unique: {result.unique_responses}",
                remediation="Use atomic operations, database-level locks, or idempotency keys for state-changing endpoints.",
            )
        )
    return findings
