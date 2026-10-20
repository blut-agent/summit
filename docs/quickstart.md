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
summit scan http://127.0.0.1:8765 --json scan.json --fail-on high
```

You should see output like this (abbreviated):

```
▲ SUMMIT v1.3.0 · pennacle security
│ ▸ RECON crawling http://127.0.0.1:8765 (depth=3, max_pages=50) ...
│ ▸ RECON visited 26 page(s), 1 form(s), 4 outbound link(s), 0 request error(s)
│ ▸ RECON completed in 0.4s
│ ▸ SCAN running passive + active checks (workers=8) ...
│ ▸ SCAN completed in 2.7s - 127 raw finding(s)
│ ▸ TEMPLATES ran 25 template(s) - 0 finding(s)
│ ▸ DONE 1061 request(s) in 3.4s (workers=8, rate=unlimited, retries=1)
│ ▸ DONE smart order: 12 high-signal injection point(s) probed first

── Summit report · http://127.0.0.1:8765 ───────────────────────────

  Total findings: 127
  ███████████████████████████████████████████
  [CRITICAL] 3 [HIGH] 17 [MEDIUM] 10 [LOW] 38 [INFO] 59


  [CRITICAL]

    Server-side template injection (RCE candidate)
      ssti  ·  confirmed  ·  CWE-1336
      URL: http://127.0.0.1:8765/greet?name=world  param: name
      Evidence: `Jinja2/Twig: {{7*7}} -> 49`

    OS command injection
      os-command-injection  ·  confirmed  ·  CWE-78
      URL: http://127.0.0.1:8765/ping?host=demo.local  param: host
      Evidence: `semicolon: exec marker x2, control marker x1`

    SQL injection (error-based)
      sqli-error  ·  confirmed  ·  CWE-89
      URL: http://127.0.0.1:8765/user?id=1  param: id
      Evidence: `unrecognized token`


  [HIGH]

    TRACE method enabled (Cross-Site Tracing surface)
      trace-enabled  ·  confirmed  ·  CWE-693
      URL: http://127.0.0.1:8765
      Evidence: `TRACE http://127.0.0.1:8765 echoed X-Summit-Trace: summit-trace-probe-9f3c2a`

    Sensitive file exposed: /.env
      sensitive-file  ·  confirmed  ·  CWE-538
      URL: http://127.0.0.1:8765/.env
      Evidence: `content signature: 'APP_KEY='`
```

## Reproduce every claim

```bash
python examples/evidence.py
```

This runs the demo target, measures each feature, and prints PASS/FAIL with real numbers. 27 claims, all verified. CI runs this on every push.

## What just happened

1. **RECON** - the spider crawled the target, following `<a href>` tags, extracting forms, and discovering endpoints hidden inside JavaScript files (`fetch()`, `axios`, `XMLHttpRequest`)
2. **FINGERPRINT** - the scanner identified the backend technology from response headers and body patterns
3. **VULNERABILITY** - passive checks ran on every page, active checks ran on every injectable parameter (prioritized by the smart model), and link health was checked for every outbound link

Each phase produced structured output that the next phase consumed. That's the phase-based engine.
