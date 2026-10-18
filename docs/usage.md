# Usage

Every command follows the same shape: plain flags, honest output, `--json` where a report makes sense.

## scan - the main event

```bash
summit scan https://testsite.local --depth 2 --workers 8 --rate 10
```

Crawls the target (same-host only), then runs passive checks on every page, active checks on every injectable parameter, and link-health checks on every outbound link.

| Flag | Meaning |
|---|---|
| `--depth N` / `--max-pages N` | crawl limits (default 3 / 50) |
| `--workers N` | parallel check workers (default 8) |
| `--rate R` | hard requests-per-second ceiling across all threads |
| `--timeout S` / `--retries N` | per-request timeout; retries on connection errors and 429/503 with `Retry-After` support |
| `--no-active` | passive only - zero attack traffic |
| `--skip-linkcheck` | skip outbound-link health checks |
| `--json` / `--html` | write reports |
| `--auto-html` | write an HTML report automatically after the scan, into `summit-reports/` (`--no-auto-html` to disable) |
| `--render` | render JavaScript pages with headless Chromium (needs `pip install playwright`) |
| `--oob-listen PORT` | run the OOB listener and confirm blind SSRF / XXE callbacks |
| `--templates FILE_OR_DIR` | run YAML check templates during this scan |

Output includes an honest count: `937 request(s) in 2.9s (workers=8, rate=unlimited, retries=1)` (`rate=10.0` when you pass `--rate 10`) plus the prioritizer's note (`smart order: N high-signal injection point(s) probed first`).

## fuzz - directory brute force

```bash
summit fuzz https://testsite.local -w wordlist.txt -e php,bak -t 20
```

Measures a wildcard baseline first (a random nonexistent path) and filters everything that answers identically - "everything returns 200" servers cannot flood the report.

## proxy - local intercepting proxy

```bash
summit proxy --port 8080
```

Plain HTTP is forwarded and logged into a SQLite site map. HTTPS CONNECT tunnels are logged and passed through; TLS interception needs a generated CA and is on the roadmap.

## repeater - raw request sender

```bash
summit repeater examples/request.txt
```

Burp-style raw request files. Host headers in the file are honored.

## authorize - broken access control testing

```bash
summit authorize https://app.local/admin?user=1 \
  --role 'admin=Cookie: session=admintoken' \
  --role 'user=Cookie: session=usertoken'
```

First `--role` is the privileged baseline; the second is what an attacker would have. Verdicts: `enforced`, `broken` (identical response for the low-privilege role - critical), `partial` (same status, different body).

## mine - hidden parameter discovery

```bash
summit mine https://app.local/debug --workers 8
```

Probes ~120 undocumented parameter names with unique markers. Reflection findings are `confirmed`; behavior changes are `needs-manual`.

## race - concurrent-request probing

```bash
summit race https://app.local/api/claim -n 10 --json race.json
```

Fires a burst of identical concurrent requests (`-n` / `--concurrency`, default 10) and reports response divergence inside the window as a `needs-manual` candidate - evidence for a human to confirm, not a verdict. `--method`, `--data` and `--cookie` shape the request; `--json` writes the report.

## diff - compare two scans

```bash
summit diff before.json after.json --fail-on regressed
```

Matches findings between two scan JSON reports and classifies them as new, resolved or regressed. `--fail-on new|regressed|any` turns it into a CI gate.

## oob - out-of-band callback listener

```bash
summit oob --port 9999                               # terminal 1: the listener
summit scan https://target.local --oob-listen 9999   # terminal 2: scan with OOB
```

A local HTTP listener that proves blind SSRF / XXE with a real callback hit: findings fire only when the target actually fetches our URL, so nothing is reported on speculation.

## templates - YAML check templates

```bash
summit templates                        # list the built-in templates
summit templates path/to/template.yaml  # validate one file or directory
summit scan https://target.local --templates path/to/dir
```

Custom checks described in YAML; scans run them alongside the built-in checks. `summit setup --template-dir` persists a template directory as the default.

## setup - persist your defaults

```bash
summit setup
```

Interactive wizard that saves your defaults to `~/.summit/config.json`; later scans pick them up without repeating flags.

## tls - certificate and protocol audit

```bash
summit tls target.com --port 443 --json tls.json
```

Checks certificate expiry, self-signing and whether legacy TLS versions (v1.0/1.1) still complete handshakes. Standalone command - it talks to the network by definition.

## OpenAPI-driven scanning

```bash
summit scan https://api.local --openapi api-spec.json
```

Every documented path becomes a target (path params filled from examples and defaults). JSON and YAML specs both supported (PyYAML ships as a dependency).

## recon - chain your tools

```bash
summit recon testsite.local --json recon.json
```

subfinder -> httpx -> nmap, whichever are installed. Subfinder noise on common domains is capped, per-tool timeouts degrade into notes, and a crashed nmap is reported as *failed* - never as "no open ports".

## encode / decode - the toolkit

```bash
summit decode -f jwt "eyJhbGci..."   # header + payload, honest "signature NOT verified" note
summit decode -f b64 c3VtbWl0
summit encode -f url "admin' OR 1=1--"
summit encode -f hex "ping"
```

## housekeeping

```bash
summit --check-update   # numeric comparison against the latest GitHub release
summit --auto-update    # git pull when running from a checkout
summit --install-tools  # best-effort installer for recon integrations
```
