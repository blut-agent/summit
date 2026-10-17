---
title: Quick Start
description: Get summit running in under two minutes.
---

# Quick Start

## 30-second demo

Two terminals. No internet needed. The target binds to `127.0.0.1` only.

**Terminal 1** - start the deliberately vulnerable target:

```bash
python examples/vuln_app.py
```

**Terminal 2** - run the full scan:

```bash
summit scan http://127.0.0.1:8765
```

You should see output like this (abbreviated):

```
[*] crawling http://127.0.0.1:8765 ...
[*] visited 30 page(s), 5 outbound link(s), 0 request error(s)
[*] 706 request(s) in 30.1s (workers=8, rate=50.0, retries=1)
[*] smart order: 9 high-signal injection point(s) probed first

Summit report - http://127.0.0.1:8765
============================================================
Total findings: 113  (critical 4, high 18, medium 14, low 24, info 53)

[CRITICAL]
  SQL injection (error-based)  (sqli-error)  [confirmed]  CWE-89
    Evidence: unrecognized token

  Broken access control  (authorize-bypass)  [confirmed]  CWE-639
    Evidence: both roles: HTTP 200, 145 bytes

[HIGH]
  Reflected XSS  (xss-reflection)  [confirmed]  CWE-79
    Evidence: "><svg/onload=alert(1)>

  OS command injection  (os-command-injection)  [confirmed]  CWE-78
    Evidence: semicolon: exec marker x2, control marker x1
```

## Reproduce every claim

```bash
python examples/evidence.py
```

This runs the demo target, measures each feature, and prints PASS/FAIL with real numbers. 22 claims, all verified. CI runs this on every push.

## What just happened

1. **RECON** - the spider crawled the target, following `<a href>` tags, extracting forms, and discovering endpoints hidden inside JavaScript files (`fetch()`, `axios`, `XMLHttpRequest`)
2. **FINGERPRINT** - the scanner identified the backend technology from response headers and body patterns
3. **VULNERABILITY** - passive checks ran on every page, active checks ran on every injectable parameter (prioritized by the smart model), and link health was checked for every outbound link

Each phase produced structured output that the next phase consumed. That's the phase-based engine.
