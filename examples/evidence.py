"""Reproduce every claim in the README against the local demo target.

This is the evidence runner: each claim is measured live and printed as
PASS or FAIL with the actual numbers. It runs the demo app in-process,
so nothing outside 127.0.0.1 is touched (the link health check resolves
DNS for the seeded dead domain, which never connects anywhere).

    python examples/evidence.py

Exit code 0 means every claim held. CI runs this on every push.
"""

from __future__ import annotations

import sys
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import quote
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.vuln_app import DemoHandler  # noqa: E402
from summit.http.client import HttpClient  # noqa: E402
from summit.http.models import HttpRequest  # noqa: E402
from summit.scan.engine import ScanEngine  # noqa: E402
from summit.scan.modules.waf_bypass import PAYLOAD  # noqa: E402
from summit.captcha import detect_challenge  # noqa: E402
from summit.toolkit import jwt_decode  # noqa: E402
from summit.updates import is_outdated  # noqa: E402
from summit.crawl.spider import Spider  # noqa: E402

PORT = 8777
BASE = f"http://127.0.0.1:{PORT}"
results: list[tuple[str, bool, str]] = []


def claim(name: str, ok: bool, evidence: str) -> None:
    results.append((name, ok, evidence))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n       {evidence}")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        client = HttpClient(timeout=10)

        # --- 1. full scan: every seeded check fires, negative control stays quiet
        spider = Spider(client, max_depth=1, max_pages=10)
        spider_result = spider.crawl(BASE)
        engine = ScanEngine(client, workers=8)
        findings = engine.scan(spider_result)
        check_ids = {f.check_id for f in findings}
        expected = {
            "sqli-error", "sqli-boolean", "xss-reflection", "open-redirect",
            "path-traversal", "linkcheck-dead-domain", "waf-bypass", "waf-detected", "captcha-challenge",
        }
        missing = expected - check_ids
        control_fp = [f.url for f in findings if f.url.startswith("https://example.com")]
        confirmed = sum(1 for f in findings if f.confidence == "confirmed")
        claim(
            "full scan: 9 seeded check families detected, zero false positives",
            not missing and not control_fp,
            f"{len(findings)} findings in {engine.elapsed:.1f}s ({client.request_count} requests), "
            f"missing={sorted(missing) if missing else 'none'}, control link flagged={control_fp or 'no'}, "
            f"{confirmed} finding(s) carry confidence=confirmed",
        )

        # --- 2. WAF bypass, shown at the HTTP level (same code path the check uses)
        base = HttpRequest(method="GET", url=f"{BASE}/protected?token=demo")
        blocked = client.send(base.with_query_param("token", PAYLOAD))
        tampered = client.send(base.with_query_param("token", quote(PAYLOAD)))
        claim(
            "WAF bypass: naive filter blocks, tampered payload lands decoded",
            blocked.status == 403 and tampered.status == 200 and PAYLOAD in tampered.text,
            f"raw payload -> HTTP {blocked.status} (blocked); "
            f"URL-encoded once -> HTTP {tampered.status}, payload reflected decoded: {PAYLOAD in tampered.text}",
        )

        # --- 3. CAPTCHA is detected, not hammered
        login = client.send(HttpRequest(method="GET", url=f"{BASE}/login"))
        detected = detect_challenge(login)
        claim(
            "CAPTCHA challenge detected (reported, not solved)",
            detected is not None and detected[0] == "reCAPTCHA",
            f"/login -> {detected[0]} via marker {detected[1]!r}" if detected else "no challenge found",
        )

        # --- 4. rate limiter is real: measure 12 requests at 5 rps vs unlimited
        paced = HttpClient(rate=5)
        started = time.monotonic()
        for _ in range(12):
            paced.send(HttpRequest(method="GET", url=BASE))
        paced_elapsed = time.monotonic() - started
        fast = HttpClient()
        started = time.monotonic()
        for _ in range(12):
            fast.send(HttpRequest(method="GET", url=BASE))
        fast_elapsed = time.monotonic() - started
        claim(
            "rate limiting: --rate 5 paces 12 requests to ~2.2s; unlimited runs free",
            paced_elapsed >= 2.1 and fast_elapsed < paced_elapsed,
            f"12 requests at rate 5 -> {paced_elapsed:.2f}s (theoretical floor: 2.2s); "
            f"12 requests unlimited -> {fast_elapsed:.2f}s",
        )

        # --- 5. concurrency: same scan, best of 3 runs each, 1 worker vs 8 workers
        def best_of(workers: int, runs: int = 3) -> float:
            best = float("inf")
            for _ in range(runs):
                engine = ScanEngine(client, workers=workers, linkcheck_enabled=False)
                started = time.monotonic()
                engine.scan(spider_result)
                best = min(best, time.monotonic() - started)
            return best

        solo_elapsed = best_of(1)
        crew_elapsed = best_of(8)
        claim(
            "concurrent engine: 8 workers finish faster than 1 (best of 3 each)",
            crew_elapsed < solo_elapsed,
            f"workers=1 -> {solo_elapsed:.2f}s; workers=8 -> {crew_elapsed:.2f}s "
            f"({solo_elapsed / max(crew_elapsed, 0.001):.1f}x on the demo target)",
        )

        # --- 6. smart prioritizer puts known-injectable names first
        from summit.smart import prioritize  # noqa: E402
        from summit.scan.engine import build_targets  # noqa: E402
        targets = prioritize(build_targets(spider_result))
        first = targets[0]
        claim(
            "smart prioritizer ranks known-injectable parameters first",
            first.param in {"query", "id", "url", "name", "file", "token"},
            f"probing starts with: {[(p.param, p.request.url.rsplit('/', 1)[-1]) for p in targets[:3]]}",
        )

        # --- 7. toolkit decodes a JWT honestly
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0"
        decoded = jwt_decode(f"{header}.{payload}.c2ln")
        claim(
            "toolkit decodes JWT header/payload and states the signature is unverified",
            '"role": "admin"' in decoded and "NOT verified" in decoded,
            decoded.splitlines()[-1].strip("()"),
        )

        # --- 8. version comparison is numeric, not lexicographic
        claim(
            "update check compares versions numerically (0.3 < 0.10)",
            is_outdated("0.3.0", "0.10.0") and not is_outdated("1.0.0", "0.9.9"),
            "is_outdated('0.3.0', '0.10.0') -> True; is_outdated('1.0.0', '0.9.9') -> False",
        )
    finally:
        server.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\nevidence summary: {passed}/{len(results)} claims verified")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
