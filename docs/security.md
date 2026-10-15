# Security policy

Full policy: [SECURITY.md](https://github.com/pennacle-security/.github/blob/main/SECURITY.md). Short version:

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | yes |
| < 0.4 | no |

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub's private vulnerability reporting (Security tab -> Report a vulnerability) on the affected repo.

What to include: affected repo and version or commit, reproduction steps or a proof of concept, and the impact as you see it.

What to expect: acknowledgment within 72 hours, a fix or mitigation plan within 14 days for confirmed issues, and public credit once the fix ships unless you prefer to stay anonymous.

## Scope note

The `examples/` directory is deliberately insecure - it exists so the scanner can be verified without touching real targets. Issues in demo code only count if they break out of the demo.

## What summit refuses to do, by design

- fetch links that resolve to private, loopback, or link-local ranges (including cloud metadata)
- solve CAPTCHAs or bypass challenges automatically
- probe hosts that cannot resolve (`.example` probe hosts)
- leave the target host while crawling
