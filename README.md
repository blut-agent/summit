# summit

Open-source web security testing platform by [Pennacle Security](https://github.com/pennacle-security). Proxy, scanner and fuzzer in one CLI.

Think of it as a small, scriptable cousin of ZAP and Burp. It is young (v0.1) and we are building it in the open. Expect rough edges, expect fast movement.

## Install

    git clone https://github.com/pennacle-security/summit.git
    cd summit
    pip install -e .

Python 3.10+. The only hard dependency is `requests`.

## Quickstart

    # crawl + passive + active checks, console report
    summit scan https://testsite.local --depth 2 --max-pages 30

    # same, but passive only (no attack traffic)
    summit scan https://testsite.local --no-active

    # write reports
    summit scan https://testsite.local --json report.json --html report.html

    # directory brute force
    summit fuzz https://testsite.local -w my-wordlist.txt -e php,bak -t 20

    # local proxy, logs plain HTTP into a sqlite site map
    summit proxy --port 8080

    # repeater: send a raw request file (Burp-style)
    summit repeater examples/request.txt

## What scan checks

Passive (no attack traffic):

- missing security headers (CSP, HSTS, X-Frame-Options, and friends)
- cookies without Secure / HttpOnly / SameSite
- SQL error strings and stack traces leaking in responses
- server and technology version disclosure
- CORS wildcard with credentials
- exposed email addresses

Active:

- SQL injection: error-based and boolean-based (numeric params)
- reflected XSS (unencoded reflection of probe payloads)
- open redirect (url-ish params, safe `.example` probe host)
- path traversal (`/etc/passwd` and `win.ini` indicators)
- cloud metadata endpoint probing

## Roadmap

- TLS interception in the proxy (generated CA, MITM HTTPS)
- POST form and JSON body injection points
- authenticated scanning (cookies, headers)
- request interception UI
- more checks: SSRF, IDOR heuristics, host header injection
- plugin API

## Legal

Summit is built for authorized security testing: your own systems, or systems you have written permission to test. We are not responsible for misuse. Do not point it at systems you do not own.

## License

MIT
