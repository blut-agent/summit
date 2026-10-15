# Check catalog

Every check states its confirmation basis. `confirmed` = an observed fact; `potential` = a heuristic that needs a human eye. That column is not decoration - it is the contract.

## Passive (no attack traffic)

| Check | Severity | Confirmation basis |
|---|---|---|
| Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) | low | header absence |
| Cookie flags (Secure / HttpOnly / SameSite) | low-medium | header parse |
| SQL error / stack-trace disclosure (MySQL, PostgreSQL, MSSQL, SQLite, Oracle) | medium | baseline-diffed signatures |
| Server and tech version disclosure | info | header parse |
| CORS wildcard with credentials | low | header parse |
| Email exposure | info | regex |
| WAF fingerprint (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, F5, Wordfence) | info | tight vendor signatures |
| CAPTCHA / anti-bot challenge (reCAPTCHA, hCaptcha, Turnstile) | info | challenge markers - reported, never solved |
| Resource takeover signature (S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Pantheon, Tumblr, Surge, Bitbucket) | high | provider unclaimed-resource page on a 404/410 -> `confirmed` |

## Active

| Check | Severity | Confirmation basis |
|---|---|---|
| SQL injection, error-based | critical | fresh DB error vs baseline -> `confirmed` |
| SQL injection, boolean-based | critical | response divergence + baseline match -> `potential` |
| Reflected XSS | high | two-stage canary + raw payload reflection -> `confirmed` |
| WAF filter bypass | high | tampered payload lands **decoded** -> `confirmed` |
| Host header injection | high | marker domain echoed vs baseline -> `confirmed` |
| CORS origin reflection | high | arbitrary origin reflected + credentials allowed -> `confirmed` |
| Open redirect | medium | 3xx Location to a `.example` probe host -> `confirmed` |
| Path traversal | high | OS file indicators -> `confirmed` |

## Link health

| Check | Severity | Confirmation basis |
|---|---|---|
| Link to dead domain (hijack candidate) | high | DNS failure verified twice -> `confirmed` |
| Link to parked domain (hijack candidate) | high | tight parking fingerprints -> `confirmed` |
| Broken outbound link | medium | HTTP 404/410 -> `confirmed` |
| Unreachable outbound link | low | fails after retry -> `potential` |
| Outbound link to private IP | info | DNS resolution -> `confirmed`, never fetched |

## Fuzz

| Check | Severity | Confirmation basis |
|---|---|---|
| Found path | info | status + wildcard baseline comparison |

## Adding your own

A check is a class with `check_id`, `title`, `severity` and a `run(point, client)` method - see [contributing](contributing.md). The demo target gives you a live place to test it.
