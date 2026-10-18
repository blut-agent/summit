# Phase Engine

Summit v0.9.0 introduced a phase-based scanning engine. Each scan runs through sequential phases that mirror how a human pentester works. Each phase produces structured output consumed by the next.

## The three phases

```
┌─────────────────────────────────────────────────────┐
│  Phase 1: RECON                                     │
│  Crawl the target. Map the attack surface.          │
│  Collect pages, forms, JS endpoints, outbound links.│
│  Follow redirects to reach hidden endpoints.        │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Phase 2: FINGERPRINT                               │
│  Identify server, CMS, framework, language,         │
│  libraries, analytics, CDN from headers and body.   │
│  35+ fingerprints across 7 categories.              │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Phase 3: VULNERABILITY                             │
│  Passive checks on every page.                      │
│  Active checks on every injection point             │
│    (prioritized by tech-aware smart model).         │
│  Link health on every outbound link.                │
│  Origin checks (sensitive files, listing, GraphQL). │
└─────────────────────────────────────────────────────┘
```

## How phases connect

- Phase 1 produces `pages` (with full response data), `forms`, `external_links`, and `errors`
- Phase 2 consumes `pages` to fingerprint technologies
- Phase 3 consumes `pages` for passive checks, builds injection points from `pages` for active checks, and uses `external_links` for link health

## Phase-aware smart model

Phase 2 detected technologies feed into the prioritizer in Phase 3:

- PHP detected → path traversal and command injection parameters boosted
- Python detected → SSTI and NoSQL parameters boosted
- Node.js detected → NoSQL parameters boosted

The model is deterministic: every weight is readable in `summit/smart.py`.

## Verifying the phases

```python
from summit.scan.phases import PhaseEngine
from summit.http.client import HttpClient

client = HttpClient(timeout=10)
engine = PhaseEngine(client, workers=8)
findings = engine.run_full_scan("http://target.local")

# Inspect phase results
for phase in engine.phases:
    print(f"{phase.name}: {phase.duration:.1f}s, {len(phase.errors)} errors")

# Inspect detected technologies
for tech in engine.technologies:
    print(f"  {tech['category']}: {tech['name']} {tech['version']}")
```

Against the bundled demo target (`python examples/vuln_app.py`), all three phases report `OK` with zero errors.
