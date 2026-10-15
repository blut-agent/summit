<p align="center">
  <img src="docs/assets/banner.png" alt="summit" width="760">
</p>

<p align="center">
  <a href="https://github.com/pennacle-security/summit/actions/workflows/tests.yml"><img src="https://github.com/pennacle-security/summit/actions/workflows/tests.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/pennacle-security/summit/releases"><img src="https://img.shields.io/github/v/tag/pennacle-security/summit?label=release&color=2ea44f" alt="release"></a>
  <a href="https://api.scorecard.dev/projects/github.com/pennacle-security/summit/badge"><img src="https://api.scorecard.dev/projects/github.com/pennacle-security/summit/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://pennacle-security.github.io/summit/"><img src="https://img.shields.io/badge/docs-live-2ea44f" alt="docs"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab" alt="python 3.10+">
  <img src="https://img.shields.io/github/license/pennacle-security/summit?color=8b949e" alt="MIT license">
  <img src="https://img.shields.io/badge/dependencies-requests%20only-8b949e" alt="one dependency">
</p>

<p align="center">Proxy, scanner, fuzzer, link-hijack detection, WAF analysis, takeover fingerprints and recon orchestration in one scriptable CLI.<br>A small, honest cousin of ZAP and Burp - by <a href="https://github.com/pennacle-security">Pennacle Security</a>.</p>

---

We use Burp and ZAP every day. We also kept wanting three things they are not: a scanner we can script against in CI, findings that tell us how sure they are, and a codebase small enough to read in one sitting. Summit is that tool. It is young (v0.4) and built in the open.

**Every claim on this page is reproduced by [`examples/evidence.py`](examples/evidence.py)** - it runs the demo target live, measures each feature, and prints PASS/FAIL with the real numbers. CI executes it on every push; a claim that stops holding fails the build.

**Full documentation:** [pennacle-security.github.io/summit](https://pennacle-security.github.io/summit/)

## Contents

- [Proof, not promises](#proof-not-promises)
- [Install](#install)
- [Quickstart](#quickstart)
- [WAF detection and bypass](#waf-detection-and-bypass)
- [CAPTCHA: detect, do not solve](#captcha-detect-do-not-solve)
- [Rate limiting, timeouts and retries](#rate-limiting-timeouts-and-retries)
- [Smart probe prioritization](#smart-probe-prioritization)
- [Recon orchestration: subfinder, httpx, nmap](#recon-orchestration-subfinder-httpx-nmap)
- [Toolkit: the Decoder bits you actually use](#toolkit-the-decoder-bits-you-actually-use)
- [Updates](#updates)
- [Broken link hijacking](#broken-link-hijacking)
- [Anti false positives and false negatives](#anti-false-positives-and-false-negatives)
- [Check catalog](#check-catalog)
- [How summit compares](#how-summit-compares)
- [Roadmap](#roadmap)
- [Contributing and security](#contributing-and-security)
- [Legal](#legal)

## Proof, not promises

Every feature is verified against [examples/vuln_app.py](examples/vuln_app.py) - a deliberately vulnerable local app with thirteen seeded issue classes, bound to 127.0.0.1 only. Below is a real v0.4.0 scan against it:

<p align="center">
  <img src="docs/assets/demo.png" alt="real summit v0.4.0 scan output against the local demo target" width="760">
</p>

<details>
<summary>Measured evidence (from <code>python examples/evidence.py</code>, not a mockup)</summary>

```text
[PASS] full scan: 12 seeded check families detected, zero false positives
       37 findings in 0.7s (126 requests), missing=none, control link flagged=no,
       11 finding(s) carry confidence=confirmed
[PASS] resource takeover fingerprint detected on the target's own 404
       Possible AWS S3 resource takeover | AWS S3: 'nosuchbucket'
[PASS] host header injection: marker domain echoed back by the app
       Host: summit-host-probe.example -> reflected (reset-link poisoning surface)
[PASS] CORS reflects an arbitrary origin with credentials allowed
       ACAO: https://summit-cors-probe.example; ACAC: true
[PASS] WAF bypass: naive filter blocks, tampered payload lands decoded
       raw payload -> HTTP 403 (blocked); URL-encoded once -> HTTP 200,
       payload reflected decoded: True
[PASS] CAPTCHA challenge detected (reported, not solved)
       /login -> reCAPTCHA via marker 'recaptcha/api.js'
[PASS] rate limiting: --rate 5 paces 12 requests to ~2.2s; unlimited runs free
       12 requests at rate 5 -> 2.20s (theoretical floor: 2.2s);
       12 requests unlimited -> 0.02s
[PASS] concurrency on a latency-bearing target: 8 workers vs serial
       40 requests x 25ms latency: serial 1.46s -> parallel 0.18s (8.1x speedup)
[PASS] smart prioritizer ranks known-injectable parameters first
       probing starts with: [('query', 'search?query=laptop'), ('id', 'user?id=1'), ...]
[PASS] toolkit decodes JWT header/payload and states the signature is unverified
[PASS] update check compares versions numerically (0.3 < 0.10)

evidence summary: 11/11 claims verified
```

</details>

Run it yourself:

    python examples/vuln_app.py             # terminal 1 - the target
    summit scan http://127.0.0.1:8765       # terminal 2 - the scan
    python examples/evidence.py             # reproduce every claim above

The demo seeds a *healthy* outbound link (`https://example.com`) as a negative control - it must never be reported, and CI asserts that alongside the seeded detections. If a claim ever stops holding, CI fails. Found something wrong anyway? [Report it](https://github.com/pennacle-security/summit/issues/new?template=bug_report.yml).

## Install

    git clone https://github.com/pennacle-security/summit.git
    cd summit
    pip install -e .

Python 3.10+. The only dependency is `requests`.

## Quickstart

    # full scan: crawl, passive + active checks, link health, WAF analysis
    summit scan https://testsite.local --depth 2 --workers 8 --rate 10

    # polite mode: hard rate limit, retries with Retry-After support
    summit scan https://testsite.local --rate 5 --retries 2 --timeout 15

    # passive only - no attack traffic at all
    summit scan https://testsite.local --no-active

    # write reports
    summit scan https://testsite.local --json report.json --html report.html

    # directory brute force
    summit fuzz https://testsite.local -w my-wordlist.txt -e php,bak -t 20

    # recon chain: subfinder -> httpx -> nmap (whichever are installed)
    summit recon testsite.local --json recon.json

    # local proxy, logs plain HTTP into a sqlite site map
    summit proxy --port 8080

    # repeater: send a raw request file (Burp-style)
    summit repeater examples/request.txt

    # decoder toolkit
    summit decode -f jwt "eyJhbGciOi..."
    summit encode -f b64 "admin' OR 1=1--"

    # stay current
    summit --check-update
    summit --auto-update
    summit --install-tools

## WAF detection and bypass

Summit fingerprints the WAF from tight signatures (Cloudflare, AWS WAF, Akamai, Imperva Incapsula, ModSecurity, Sucuri, F5 BIG-IP, Wordfence) and adapts:

- **Detection** is passive and factual: a specific header or the vendor's own block-page text, never "the page mentions GoDaddy".
- **Bypass probing** runs when a filter blocks the standard payloads. The check tries tamper variants - single/double URL-encoding, comment splitting, case alternation - and reports a bypass **only when the original payload lands decoded in the response**. Encoded-but-inert reflections do not count. Measured on the demo target: raw payload -> HTTP 403; single URL-encoded -> HTTP 200 with the payload decoded.

## CAPTCHA: detect, do not solve

Summit detects reCAPTCHA, hCaptcha, Cloudflare Turnstile and challenge pages, reports exactly which one is in the way, and stops burning requests. Solving CAPTCHAs automatically is out of scope by design - that line does not move.

## Resource takeover fingerprints

New in v0.4. A 404 that answers with a provider's unclaimed-resource page is a takeover setup: the URL still works, the backing resource is gone. Summit fingerprints the classic ones - AWS S3 (`NoSuchBucket`), GitHub Pages, Heroku, Azure, Shopify, Fastly, Pantheon, Tumblr, Surge, Bitbucket - and reports **confirmed** findings with the reclaim instruction. Fingerprint-only by design: no DNS tricks, no active claiming, ever.

## Host header injection

New in v0.4. Applications that build absolute URLs from the Host header (password reset links, redirects) can be poisoned. The probe sets a marker domain as Host and reports only when it comes back - and only when it is absent from the baseline, so pre-existing content can never trigger it. Measured on the demo target: `Host: summit-host-probe.example -> reflected` in a reset link, `confirmed`.

## CORS origin reflection

New in v0.4. Beyond the wildcard+credentials pattern, the active probe sends `Origin: https://summit-cors-probe.example` and reports when the server reflects it into `Access-Control-Allow-Origin` with credentials allowed - the configuration that lets any website read authenticated responses. Measured: reflected, `confirmed`.

## Rate limiting, timeouts and retries

- `--rate 5` - hard ceiling of 5 requests/second across all worker threads (thread-safe slot queue; measured: 12 requests paced to 2.20s, unlimited runs the same 12 in 0.02s).
- `--timeout 15` - per-request timeout.
- `--retries 2` - retries on connection errors and 429/503, honoring `Retry-After` (capped at 30s). A server that always fails gets exactly `1 + retries` attempts and the final state is reported honestly - proven by a live test that counts the hits.

## Smart probe prioritization

The engine orders injection points by a transparent scoring model (weights are readable in `summit/smart.py`): parameters whose names map to injection families (id, q, url, file...) and values that look numeric or URL-shaped go first, so the interesting findings surface early and a Ctrl+C mid-scan leaves the good half done. Scan output shows the count: `smart order: 4 high-signal injection point(s) probed first`. It is deterministic and auditable - deliberately not a "neural network" claim.

## Recon orchestration: subfinder, httpx, nmap

    summit recon testsite.local

Chains the tools you already have installed: subdomains -> live hosts -> open ports, printed as one report. Missing tools are listed with exact install commands; `summit --install-tools` attempts the install (go for subfinder/httpx, winget/apt/brew for nmap). Defensive parsing throughout: subfinder noise on common domains is capped, per-tool timeouts degrade gracefully into notes instead of killing the run, and an nmap that crashes is reported as *failed*, never as "no open ports".

## Toolkit: the Decoder bits you actually use

    summit decode -f jwt "eyJhbGci..."   # header + payload JSON, honest "signature NOT verified" note
    summit decode -f b64 c3VtbWl0
    summit encode -f url "admin' OR 1=1--"

## Updates

    summit --check-update     # compares against the latest GitHub release, numerically (0.3 < 0.10)
    summit --auto-update      # git pull when running from a checkout; exact steps otherwise
    summit --install-tools    # best-effort installer for the recon integrations

## Broken link hijacking

New in v0.2, kept in v0.3. The spider records every outbound link; the engine checks each unique one:

- **dead domain** - DNS failure verified twice (high, `confirmed`)
- **parked domain** - tight parking fingerprints (high, `confirmed`)
- **broken link** - HTTP 404/410 (medium, `confirmed`)
- **unreachable** - timeouts, 5xx after retry (low, `potential`)
- **private-target link** - resolves into private/link-local space; recorded, never fetched, so a hostile page cannot use your scanner as a blind SSRF probe (info, `confirmed`)

## Anti false positives and false negatives

False positives waste your triage time. False negatives get clients breached. Summit engineers against both, and the evidence runner proves it:

| Mechanism | What it kills |
|---|---|
| **Two-stage XSS check** - a unique canary goes first; attack payloads only fire on parameters that actually reflect input | payload noise on the thousands of parameters that never reflect |
| **Baseline diffing** - every probe is compared against an unmodified request of the same parameter | error strings that were already sitting in the page |
| **Divergence + baseline match** (boolean SQLi) - `AND 1=1` must look like the baseline, `AND 1=2` must differ | pages that simply vary per request |
| **Wildcard baseline in the fuzzer** - a random nonexistent path is measured first; identical answers get filtered | "everything returns 200" servers flooding your report |
| **DNS double-check** (linkcheck) - a host must fail to resolve twice before a hijack finding fires | transient resolver hiccups becoming fake "dead domain" reports |
| **SSRF guard** (linkcheck) - private/link-local/metadata ranges are recorded, never fetched | your scanner being weaponized against internal networks |
| **Tamper honesty** (WAF bypass) - a bypass finding requires the original payload decoded in the response; encoded-but-inert reflections are not bypasses | "we bypassed the WAF" reports that would not survive a browser |
| **Tracker/opaque param filter** - `utm_*`, `fbclid`, `gclid` and 40+ char opaque tokens are never probed | wasted requests and padded reports |
| **Negative control in CI** - the demo seeds a healthy link that must stay unreported, asserted on every push | silent regressions into false-positive territory |
| **Scope lock** - the spider never leaves the target host | crawling half the internet, and legal exposure |
| **Confidence labels** - `confirmed` = observed fact; `potential` = heuristic | one flat "everything is critical" triage queue |
| **Unbreakable probe hosts** - redirect probes use `.example`, which cannot resolve | third-party callbacks and accidental DoS |

## Check catalog

| Check | Type | Severity | Confirmation basis |
|---|---|---|---|
| Missing security headers | passive | low | header absence |
| Cookie flags (Secure / HttpOnly / SameSite) | passive | low-medium | header parse |
| SQL error / stack-trace disclosure | passive | medium | baseline-diffed signatures |
| Server and tech version disclosure | passive | info | header parse |
| CORS wildcard with credentials | passive | low | header parse |
| Email exposure | passive | info | regex |
| WAF fingerprint | passive | info | tight vendor signatures |
| CAPTCHA / anti-bot challenge | passive | info | challenge markers, reported not solved |
| Resource takeover signature | passive | high | provider unclaimed-resource page on 404 -> `confirmed` |
| SQL injection, error-based | active | critical | fresh DB error vs baseline -> `confirmed` |
| SQL injection, boolean-based | active | critical | response divergence -> `potential` |
| Reflected XSS | active | high | canary + raw payload reflection -> `confirmed` |
| WAF filter bypass | active | high | tampered payload lands decoded -> `confirmed` |
| Host header injection | active | high | marker domain echoed vs baseline -> `confirmed` |
| CORS origin reflection | active | high | arbitrary origin reflected + credentials -> `confirmed` |
| Open redirect | active | medium | 3xx Location to probe host -> `confirmed` |
| Path traversal | active | high | OS file indicators -> `confirmed` |
| Link to dead domain (hijack) | linkcheck | high | DNS failure, verified twice -> `confirmed` |
| Link to parked domain (hijack) | linkcheck | high | tight parking fingerprints -> `confirmed` |
| Broken outbound link | linkcheck | medium | HTTP 404/410 -> `confirmed` |
| Unreachable outbound link | linkcheck | low | fails after retry -> `potential` |
| Outbound link to private IP | linkcheck | info | DNS resolution -> `confirmed`, never fetched |
| Directory fuzz | fuzz | info | status + wildcard baseline |

## How summit compares

| | summit | ZAP | Burp Suite |
|---|---|---|---|
| Price | free, MIT | free | paid core |
| UI | CLI + HTML/JSON reports | full GUI | full GUI |
| Scriptable in CI | yes, that is the point | add-ons | paid automation |
| Findings carry confidence labels | yes | partial | partial |
| Broken link hijacking built in | yes | add-on | paid extension |
| WAF detection + bypass probing | built in | partial | partial |
| Rate limiting | built in, thread-safe | add-on | paid |
| JWT/encoder toolkit | built in | add-on | built in |
| Takeover fingerprints, host header, CORS | built in | add-ons | add-ons |
| Codebase you can audit in an afternoon | ~3.1k lines | large | closed source |
| TLS-intercepting proxy | on the roadmap | yes | yes |

We are not trying to replace either of them. Summit is the small tool you drop into a pipeline or onto a VPS box, and the codebase you can actually read line by line.

## Roadmap

- [ ] TLS interception in the proxy (generated CA)
- [ ] POST form and JSON body injection points
- [ ] Authenticated scanning (cookies, headers)
- [ ] CNAME-level subdomain takeover (DNS resolution + service verification)
- [ ] Plugin API for custom checks
- [ ] Request interception UI

## Community & contributors

A repository that helps people back grows through word-of-mouth. So we put our money where our issues are:

- **Questions** -> [Q&A discussion](https://github.com/pennacle-security/summit/discussions/categories/q-a) - beginner questions welcome, answered gladly
- **Ideas & roadmap votes** -> [Ideas](https://github.com/pennacle-security/summit/discussions/categories/ideas)
- **Show what you scanned** -> [Show and tell](https://github.com/pennacle-security/summit/discussions/categories/show-and-tell)
- **Your first contribution** -> issues labeled [good first issue](https://github.com/pennacle-security/summit/labels/good%20first%20issue) come with step-by-step instructions, tests included
- First issue or PR gets an automatic hello from our welcome bot, and every merged PR earns a spot below

If summit saved you time on an engagement, a star helps the next person find it.

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

_No contributors yet - your avatar goes here. Comment `@all-contributors add @yourname code` on any issue to claim a spot._

<!-- markdownlint-enable -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

## Contributing and security

PRs welcome - read the [contributing guide](https://github.com/pennacle-security/.github/blob/main/CONTRIBUTING.md). Adding a scan check is roughly thirty lines if you follow the pattern, and [examples/vuln_app.py](examples/vuln_app.py) gives you a live target to test against.

Security issues go through private disclosure only. Details in the [security policy](https://github.com/pennacle-security/.github/blob/main/SECURITY.md).

## Legal

Summit is built for authorized security testing: your own systems, or systems you have written permission to test. We are not responsible for misuse.

## License

MIT
