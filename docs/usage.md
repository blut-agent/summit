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

Output includes an honest count: `78 request(s) in 1.9s (workers=8, rate=50.0, retries=1)` plus the prioritizer's note (`smart order: N high-signal injection point(s) probed first`).

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

Probes ~70 undocumented parameter names with unique markers. Reflection findings are `confirmed`; behavior changes are `potential`.

## OpenAPI-driven scanning

```bash
summit scan https://api.local --openapi api-spec.json
```

Every documented path becomes a target (path params filled from examples and defaults). JSON specs natively; convert YAML to JSON first.

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
