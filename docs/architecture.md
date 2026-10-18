# Architecture

Summit is deliberately small (~7.5k lines). This page is the map so you can fix or extend things without archaeology.

## Layout

```text
summit/
├── http/            models (raw request parsing, response) + client (rate limit, retries, TLS controls)
├── crawl/           breadth-first spider with same-host scope + external-link collection
│                    js_endpoints.py extracts AJAX routes; render.py = optional headless JS rendering
├── scan/
│   ├── core.py      Finding (confidence labels + severity caps), InjectionPoint, Check base class
│   ├── passive.py   header/cookie/body checks, WAF + CAPTCHA + takeover wiring
│   ├── engine.py    orchestration: passive pass, prioritized active pass (ThreadPool), link health
│   ├── phases.py    RECON -> FINGERPRINT -> VULNERABILITY phases over one engine run
│   ├── runtime.py   scan-wide runtime flags (e.g. --deep)
│   ├── linkcheck.py broken-link hijacking: DNS double-check, parking fingerprints, SSRF guard
│   ├── smart.py     adaptive probe prioritizer (transparent scoring)
│   └── modules/     one file per active check - the pattern to copy
├── waf.py           WAF fingerprint database
├── captcha.py       challenge detection (report, never solve)
├── takeover.py      provider unclaimed-resource fingerprints
├── ratelimit.py     thread-safe client-side rate limiter (injectable clock)
├── oob.py           out-of-band HTTP callback listener (blind SSRF / XXE proof)
├── recon.py         subfinder / httpx / nmap orchestration with defensive parsing
├── proxy/           intercepting HTTP proxy + SQLite site map
├── diff.py          compare two scan JSON reports (new / resolved / regressed)
├── race.py          concurrent-request race condition probing
├── report/          console, JSON, HTML and SARIF writers
├── templates/       YAML check templates (list / validate via `summit templates`)
├── toolkit.py       JWT / base64 / URL / hex
├── config.py        persisted defaults (~/.summit/config.json)
├── banner.py        ASCII banner + colour handling (NO_COLOR aware)
├── updates.py       version check, self-update, tool installer
└── cli.py           argparse wiring and command implementations
```

## Data flow of a scan

```text
summit scan <url>
    │
    ├── Spider.crawl()          same-host BFS; GET forms are requeued as query URLs;
    │                           external links are recorded, not followed
    │
    ├── passive checks          per page: headers, cookies, error leaks, WAF,
    │                           CAPTCHA, takeover fingerprints
    │
    ├── build_targets()         query params -> InjectionPoints; trackers and
    │   + smart.prioritize()    opaque tokens skipped; high-signal names first
    │
    ├── active checks           ThreadPool(workers): SQLi, XSS, WAF bypass,
    │                           host header, CORS, redirect, traversal
    │
    ├── linkcheck               each unique outbound URL once: DNS (twice on
    │                           failure) -> private-range guard -> streaming GET
    │
    └── report                  console / JSON / HTML, sorted by severity
```

## The rules every module obeys

1. **Findings are facts first.** If the check cannot show the evidence, it stays `needs-manual` or stays quiet.
2. **Baseline diffing.** Compare against an unmodified request; static content is not a finding.
3. **Safe defaults.** Probe hosts that cannot resolve (`.example`), localhost-only demo targets, never fetch private ranges, never solve challenges.
4. **A broken check must not kill the scan.** Exceptions are captured into `engine.errors` and printed.

The full reasoning lives in [the README's anti-FP section](https://github.com/pennacle-security/summit#anti-false-positives-and-false-negatives); the enforcement lives in CI (smoke test + evidence runner).
