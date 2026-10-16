# Changelog

All notable changes to summit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [v0.6.0] - 2026-10-16

### Added

- OS command injection check (CWE-78): echo-based probes across seven shell
  separators with a control probe - a server that merely reflects input shows
  both markers, a server that executes shows the exec marker more often. Only
  that asymmetry produces a finding. No time-based `sleep` payloads, ever.
- Server-side template injection check (CWE-1336, an RCE class): `{{7*7}}`,
  `${7*7}`, `<%= 7*7 %>`, `{7*7}` - confirmed only when the computed value
  (49) is present and absent from the baseline.
- CRLF injection / HTTP response splitting check (CWE-113): an injected header
  must materialize in the response.
- Sensitive file exposure check (CWE-538): `.env`, `.git/config`, database
  dumps and config backups - confirmed by content signature, never by status
  code alone. Runs once per scan against the target origin.
- CWE tagging on every finding (central map, 30+ check ids) and CVE detection
  from version banners (offline curated database: Apache, nginx, OpenSSH, PHP,
  Tomcat). CVE findings stay `potential` - banners are trivially spoofed.
- Reports (console, JSON, HTML) now include CWE and CVE references.
- Demo app gained `/ping` (simulated shell, deterministic - no real
  subprocess), `/greet` (naive template engine), `/goto` (CRLF-reflecting
  redirect) and `/.env`.
- Evidence runner grew to 19 claims.

## [v0.5.0] - 2026-10-16

### Added

- `summit authorize` - broken access control testing (the Autorize workflow):
  request every URL as a privileged and a low-privilege role, compare responses,
  report BOLA/IDOR candidates (`confirmed`) and partial enforcements
  (`potential`). Proven on the demo admin panel.
- `summit mine` - hidden parameter discovery (the Param Miner approach): ~70
  undocumented parameter names probed with unique markers; reflection findings
  are `confirmed`, behavior changes are `potential`. Proven on the demo app's
  hidden `debug` switch, with zero noise on the other candidates.
- OpenAPI-driven scanning: `summit scan --openapi spec.json` turns a JSON
  OpenAPI document into scan targets (path params filled from examples and
  defaults) - the seeded SQLi is found from the spec alone, without crawling.
- Demo app gained `/admin` (BOLA demo) and `/debug` (hidden parameter demo)
  plus an OpenAPI view of itself (`examples/openapi.json`).
- Evidence runner grew to 14 claims, one per feature.

## [v0.4.1] - 2026-10-15

### Added

- CII Best Practices badge (project #15532) and entry.

### Changed

- CI quality gates are now blocking: ruff lint (pycodestyle errors/warnings +
  pyflakes) before tests; CodeQL (Python) on every push, PR and weekly;
  OpenSSF Scorecard weekly; Dependabot for pip and action dependencies.
- All GitHub Actions pinned to full commit SHAs.
- First external contributions merged: GoDaddy parked-page signature
  (@SakarPaisen), SiteLock WAF fingerprint (@mrvi0) - contributors wall added.
- GitHub Pages documentation site (mkdocs Material).

### Fixed

- `import sys` and an unused `HttpResponse` import flagged by ruff 0.17.
- codeql-action version mismatch after the Dependabot bump (mixed 3.39.0 /
  4.38.3 steps broke the analysis) - all steps aligned.

## [v0.4.0] - 2026-10-15

### Added

- Resource takeover fingerprints (passive): AWS S3 (`NoSuchBucket`), GitHub Pages,
  Heroku, Azure, Shopify, Fastly, Pantheon, Tumblr, Surge, Bitbucket - reported
  `confirmed` with reclaim instructions. Fingerprint-only by design: no DNS
  tricks, no active claiming.
- Host header injection check (active): marker-domain probe, reported only when
  echoed back and absent from the baseline.
- CORS origin-reflection check (active): detects servers that reflect an
  arbitrary `Origin` into `Access-Control-Allow-Origin` with credentials allowed.
- OpenSSF Security Insights file, CITATION.cff, and a MkDocs documentation site
  (https://pennacle-security.github.io/summit/).

### Changed

- Finding dedupe inside the engine is now explicitly locked instead of relying
  on GIL behavior.
- The concurrency claim is measured against a latency-bearing target
  (25 ms/request): serial 1.46s -> parallel 0.18s, 8.1x.
- Host headers from repeater request files are honored instead of stripped.

### Security

- All GitHub Actions are pinned to full commit SHAs; CodeQL (Python) and
  OpenSSF Scorecard run in CI; Dependabot watches pip and action dependencies.

## [v0.3.0] - 2026-10-15

### Added

- WAF fingerprinting (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri,
  F5, Wordfence) with bypass probing: tamper variants (single/double URL-encoding,
  comment splitting, case alternation) - a bypass is reported only when the
  original payload lands decoded in the response.
- CAPTCHA / anti-bot challenge detection (reCAPTCHA, hCaptcha, Turnstile).
  Summit reports the challenge; it does not solve it.
- `--rate` (thread-safe requests-per-second ceiling), `--timeout`, `--retries`
  with `Retry-After` support.
- `summit recon`: chains subfinder -> httpx -> nmap with defensive parsing,
  caps against passive-DNS noise, and honest failure notes.
- `summit encode` / `summit decode`: base64, URL, hex and JWT (decoding only,
  with an explicit "signature NOT verified" note).
- `--check-update`, `--auto-update`, `--install-tools`.
- Smart probe prioritizer: transparent scoring model orders high-signal
  parameters first.
- `examples/evidence.py`: reproduces every README claim with measured numbers;
  runs in CI.

## [v0.2.0] - 2026-10-15

### Added

- Broken link hijacking check: the spider records every outbound link, the
  engine verifies each unique one. Dead domains (DNS verified twice), parked
  domains (tight fingerprints), broken links (404/410), unreachable hosts, and
  private-target links (recorded, never fetched - SSRF guard).
- Confidence labels on every finding: `confirmed` (observed fact) vs
  `potential` (heuristic).
- Concurrent scan engine (`--workers`), tracker/opaque parameter filter, and
  honest request-count/wall-clock output.
- Local deliberately-vulnerable demo target (`examples/vuln_app.py`) with a
  healthy negative control link.
- CI smoke test: seeded detections must fire and the control link must stay
  unreported on every push.

## [v0.1.0] - 2026-10-15

### Added

- First public release.
- CLI: `scan` / `fuzz` / `proxy` / `repeater`.
- Passive checks: security headers, cookie flags, error and stack-trace leaks,
  CORS, version disclosure, email exposure.
- Active checks: SQL injection (error-based + boolean-based), reflected XSS
  (two-stage canary), open redirect, path traversal.
- JSON and HTML reports.
