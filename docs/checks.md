---
title: Check Catalog
description: Every check in summit, with severity, confirmation basis, CWE and impact.
---

# Check Catalog

Every check states its **confirmation basis**. `confirmed` = an observed fact. `potential` = a heuristic that needs a human eye. That column is not decoration - it is the contract.

## Passive checks (no attack traffic)

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Missing security headers | low | CWE-693 | header absence |
| Cookie flags (Secure / HttpOnly / SameSite) | low-medium | CWE-614 | header parse |
| SQL error / stack-trace disclosure | medium | CWE-209 | baseline-diffed signatures |
| Server and tech version disclosure | info | CWE-200 | header parse |
| CORS wildcard with credentials | low | CWE-942 | header parse |
| Email exposure | info | CWE-359 | regex |
| WAF fingerprint | info | CWE-693 | tight vendor signatures |
| CAPTCHA / anti-bot challenge | info | CWE-807 | challenge markers, reported not solved |
| Resource takeover signature | high | CWE-350 | provider unclaimed-resource page on 404 -> `confirmed` |
| Security headers grade | info | CWE-693 | deterministic A..F roll-up |
| Cacheable sensitive response | medium | CWE-524 | sensitive marker + no Cache-Control -> `potential` |
| Known CVE in version banner | high | CWE-1104 | offline CVE database range match -> `potential` |
| Known CVE in frontend library | medium | CWE-1104 | body signature (jQuery, lodash, WordPress) -> `potential` |

## Active checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| SQL injection, error-based | critical | CWE-89 | fresh DB error vs baseline -> `confirmed` |
| SQL injection, boolean-based | critical | CWE-89 | response divergence + baseline match -> `potential` |
| SQL injection, time-based blind | critical | CWE-89 | calibrated delay reproduced on all probes -> `potential` |
| Reflected XSS | high | CWE-79 | canary + raw payload reflection -> `confirmed` |
| WAF filter bypass | high | CWE-693 | tampered payload lands decoded -> `confirmed` |
| OS command injection | critical | CWE-78 | exec marker outruns control marker -> `confirmed` |
| Server-side template injection | critical | CWE-1336 | `{{7*7}}` evaluates to 49 -> `confirmed` |
| CRLF injection / response splitting | high | CWE-113 | injected header materializes -> `confirmed` |
| Host header injection | high | CWE-640 | marker domain echoed vs baseline -> `confirmed` |
| CORS origin reflection | high | CWE-942 | arbitrary origin reflected + credentials -> `confirmed` |
| LDAP injection | high | CWE-90 | differential response to LDAP metacharacters -> `potential` |
| NoSQL injection | critical | CWE-943 | MongoDB operators change response -> `potential` |
| Format string injection | high | CWE-134 | new hex values after `%x` -> `confirmed` |
| Email/user enumeration | medium | CWE-204 | differential response for unknown identities -> `potential` |
| Open redirect | medium | CWE-601 | 3xx Location to probe host -> `confirmed` |
| Path traversal | high | CWE-22 | OS file indicators -> `confirmed` |

## Authorization checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Broken access control (BOLA/IDOR) | critical | CWE-639 | identical response for low-privilege role -> `confirmed` |
| Authorization response differs | medium | CWE-639 | same status, different body -> `potential` |
| Session fixation | medium | CWE-384 | session cookie not regenerated -> `potential` |
| JWT uses alg:none | critical | CWE-347 | JWT header analysis -> `confirmed` |
| JWT alg:none attack accepted | critical | CWE-347 | forged token accepted by server -> `confirmed` |
| JWT uses HMAC | medium | CWE-326 | JWT header analysis -> `potential` |
| Form missing CSRF token | medium | CWE-352 | POST/password form without CSRF field -> `potential` |

## Link health checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Link to dead domain (hijack) | high | CWE-350 | DNS failure, verified twice -> `confirmed` |
| Link to parked domain (hijack) | high | CWE-350 | tight parking fingerprints -> `confirmed` |
| Broken outbound link | medium | CWE-350 | HTTP 404/410 -> `confirmed` |
| Unreachable outbound link | low | CWE-350 | fails after retry -> `potential` |
| Outbound link to private IP | info | CWE-918 | DNS resolution -> `confirmed`, never fetched |

## Fuzz and origin checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Directory fuzz | info | CWE-538 | status + wildcard baseline |
| Sensitive file exposure (.env, .git, backups) | high | CWE-538 | content signature, not just 200 -> `confirmed` |
| Directory listing enabled | medium | CWE-548 | listing content signature -> `confirmed` |
| GraphQL introspection enabled | low | CWE-200 | real `__schema` payload -> `confirmed` |
| Subdomain takeover via CNAME | critical | CWE-350 | CNAME + unclaimed service page -> `confirmed` |
