# Changelog

All notable changes to summit are documented here.

# Changelog

All notable changes to summit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [v0.7.1] - 2026-10-16

### Fixed

- `build_requests` crashed with `AttributeError` when an OpenAPI spec contained
  a `null` path entry (e.g. `"/x": null`). Non-dict path values are now skipped
  instead of crashing the entire scan. Found by stability testing, covered by a
  regression test.
- `__init__.py` and `pyproject.toml` now carry the correct version (0.7.1,
  not the stale 0.6.0 they were carrying from a missed version bump).

### Changed

- Stability audit: 30+ edge-case tests run against the full codebase - empty
  findings, malformed specs, unreachable targets, dirty severity filters,
  duplicate links, None banners, negative rate-limiter intervals, concurrent
  proxy port binding. All pass.

## [v0.7.0] - 2026-10-16

### Added

- Impact-first reporting: 30+ impact statements per check, shown in every
  console, JSON and HTML report next to the finding.

## [v0.6.9] - 2026-10-16

### Added

- Body-based CVE detection: jQuery < 3.5.0 (CVE-2020-11023), lodash < 4.17.19
  (CVE-2020-8203), WordPress 5.7.0/5.7.1 (CVE-2021-29447) - detected from
  script URLs and meta generator tags.

## [v0.6.8] - 2026-10-16

### Added

- JS endpoint extraction (AJAX-spider pass): fetch/axios/XHR targets hidden
  in JavaScript are now crawled and scanned - a major FN killer.
- CSRF form check (CWE-352): state-changing forms without CSRF tokens.

## [v0.6.7] - 2026-10-16

### Added

- Email enumeration (CWE-204): differential responses on identity-shaped params.
- Directory listing (CWE-548): content-signature detection on autoindex pages.
- Cacheable sensitive response (CWE-524): sensitive content without Cache-Control.
- Security headers grade: deterministic A..F roll-up.

## [v0.6.6] - 2026-10-16

### Added

- Severity filtering: `--severity high,critical` and `--min-severity medium`.
- Per-severity breakdown in console and HTML reports.

## [v0.6.5] - 2026-10-16

### Added

- Documentation site (MkDocs Material) and complete usage reference.

## [v0.6.4] - 2026-10-16

### Added

- `summit tls` certificate and protocol audit command.
- Spider follows redirects (FN reduction).

## [v0.6.3] - 2026-10-16

### Added

- Range-based CVE matching with `packaging`; Heartbleed and Ghostcat entries.
- YAML OpenAPI spec support (PyYAML).

### Changed

- New dependencies: `pyyaml>=6.0`, `packaging>=23.0`.

## [v0.6.2] - 2026-10-16

### Added

- Time-based blind SQL injection (CWE-89): baseline-calibrated, reproducible.
- GraphQL introspection detection (CWE-200).
- Param miner expanded to ~120 candidates.
- Sensitive paths: /.git/HEAD, /.aws/credentials.

## [v0.6.1] - 2026-10-16

### Fixed

- authorize guard: login-redirect wall suppressed (not reported as BOLA).
- SSTI guard: echoed template + incidental "49" suppressed (not reported as injection).
- Evidence is no longer truncated in any report output.

## [v0.6.0] - 2026-10-16

### Added

- OS command injection (CWE-78) with anti-FP control probe.
- SSTI (CWE-1336) with math-canary detection.
- CRLF injection (CWE-113) with injected-header materialization.
- Sensitive file exposure (CWE-538) with content signatures.
- CWE tagging on every finding (central map, 30+ check ids).
- CVE detection from version banners (offline curated database).

## [v0.5.0] - 2026-10-16

### Added

- `summit authorize` (Autorize workflow) - broken access control testing.
- `summit mine` (Param Miner approach) - hidden parameter discovery.
- OpenAPI-driven scanning - spec becomes targets, no crawling.
- Demo app: /admin, /debug, examples/openapi.json.

## [v0.4.0] - 2026-10-16

### Added

- Resource takeover fingerprints (S3, GitHub Pages, Heroku, Azure, etc.).
- Host header injection, CORS origin reflection checks.
- Thread-safe engine, latency-based concurrency benchmark.

## [v0.3.0] - 2026-10-16

### Added

- WAF fingerprinting and bypass probing.
- CAPTCHA detection (reported, not solved).
- Rate limiting, retries, smart prioritization.
- Recon orchestration (subfinder/httpx/nmap).
- Toolkit (JWT, base64, URL, hex).
- Evidence runner.

## [v0.2.0] - 2026-10-16

### Added

- Broken link hijacking with confidence labels.
- Concurrent engine, tracker/opaque param filter.
- Demo target with negative control.

## [v0.1.0] - 2026-10-16

### Added

- First public release.
- CLI: scan / fuzz / proxy / repeater.
- Passive and active checks, JSON and HTML reports.


