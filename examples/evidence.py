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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
            "takeover-signature", "host-header-injection", "cors-reflection",
        }
        missing = expected - check_ids
        control_fp = [f.url for f in findings if f.url.startswith("https://example.com")]
        confirmed = sum(1 for f in findings if f.confidence == "confirmed")
        claim(
            "full scan: 12 seeded check families detected, zero false positives",
            not missing and not control_fp,
            f"{len(findings)} findings in {engine.elapsed:.1f}s ({client.request_count} requests), "
            f"missing={sorted(missing) if missing else 'none'}, control link flagged={control_fp or 'no'}, "
            f"{confirmed} finding(s) carry confidence=confirmed",
        )

        # --- 1b. the new v0.4 checks, each shown with its own evidence
        takeover = next((f for f in findings if f.check_id == "takeover-signature"), None)
        claim(
            "resource takeover fingerprint detected on the target's own 404",
            takeover is not None and takeover.confidence == "confirmed",
            f"{takeover.title} | {takeover.evidence}" if takeover else "not found",
        )
        host_header = next((f for f in findings if f.check_id == "host-header-injection"), None)
        claim(
            "host header injection: marker domain echoed back by the app",
            host_header is not None and host_header.confidence == "confirmed",
            f"{host_header.evidence} (reset-link poisoning surface)" if host_header else "not found",
        )
        cors = next((f for f in findings if f.check_id == "cors-reflection"), None)
        claim(
            "CORS reflects an arbitrary origin with credentials allowed",
            cors is not None and cors.confidence == "confirmed",
            cors.evidence if cors else "not found",
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

        # --- 5. concurrency measured where it matters: a target with latency.
        # Loopback answers in microseconds, which hides what parallelism buys.
        # This endpoint sleeps 25ms per request, like a real server over the wire.
        from concurrent.futures import ThreadPoolExecutor

        class SlowHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(0.025)
                body = b"slow but steady"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        slow_server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        slow_port = slow_server.server_address[1]
        threading.Thread(target=slow_server.serve_forever, daemon=True).start()
        try:
            urls = [f"http://127.0.0.1:{slow_port}/slow?i={index}" for index in range(40)]
            started = time.monotonic()
            for url in urls:
                client.send(HttpRequest(method="GET", url=url))
            serial_elapsed = time.monotonic() - started
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda url: client.send(HttpRequest(method="GET", url=url)), urls))
            parallel_elapsed = time.monotonic() - started
            speedup = serial_elapsed / max(parallel_elapsed, 0.001)
            claim(
                "concurrency on a latency-bearing target: 8 workers vs serial",
                speedup >= 3.0,
                f"40 requests x 25ms latency: serial {serial_elapsed:.2f}s -> parallel {parallel_elapsed:.2f}s "
                f"({speedup:.1f}x speedup)",
            )
        finally:
            slow_server.shutdown()

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

        # --- 9. authorize: the admin panel must be caught serving a low-privilege role
        from summit.authorize import Role, findings_from, run_authorize  # noqa: E402
        auth_results = run_authorize(
            client,
            [f"{BASE}/admin?user=1"],
            Role("admin", {"Cookie": "session=admin-token"}),
            Role("user", {"Cookie": "session=user-token"}),
        )
        auth_findings = findings_from(auth_results)
        claim(
            "broken access control: admin panel served identically to a low-privilege role",
            auth_results and auth_results[0].verdict == "broken" and auth_findings
            and auth_findings[0].severity == "critical",
            f"verdict={auth_results[0].verdict if auth_results else 'none'}; "
            f"finding={auth_findings[0].title if auth_findings else 'none'}",
        )

        # --- 10. param miner: the undocumented debug parameter must be discovered,
        #         and the ~70 other candidates must stay quiet
        from summit.paramminer import mine  # noqa: E402
        mined = mine(client, f"{BASE}/debug")
        reflected = [f for f in mined if f.check_id == "paramminer-reflected" and f.param == "debug"]
        claim(
            "hidden parameter mining finds the undocumented debug parameter, zero noise",
            len(reflected) == 1 and all(f.param == "debug" for f in mined),
            f"{len(mined)} finding(s): {sorted(f.param for f in mined)} (all confirmed reflections)",
        )

        # --- 11. openapi-driven scan finds seeded SQLi without any crawling
        from summit.openapi import load_spec, spec_pages  # noqa: E402
        spec = load_spec(str(Path(__file__).resolve().parent / "openapi.json"))
        # the spec's declared server points at the standard demo port; this
        # runner uses its own port, which is exactly what base_url is for
        api_result = spec_pages(client, spec, base_url=BASE)
        api_engine = ScanEngine(client, workers=8, linkcheck_enabled=False)
        api_findings = api_engine.scan(api_result)
        api_ids = {f.check_id for f in api_findings}
        claim(
            "openapi-driven scan: spec alone leads the engine to seeded SQLi and XSS",
            "sqli-error" in api_ids and "xss-reflection" in api_ids,
            f"{len(api_result['pages'])} spec target(s) scanned -> {len(api_findings)} findings, "
            f"sqli-error={'yes' if 'sqli-error' in api_ids else 'NO'}, "
            f"xss-reflection={'yes' if 'xss-reflection' in api_ids else 'NO'}",
        )
    finally:
        server.shutdown()

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\nevidence summary: {passed}/{len(results)} claims verified")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
