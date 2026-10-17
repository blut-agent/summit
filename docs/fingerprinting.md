# Technology Fingerprinting

Summit identifies the technologies running on a target using the same approach as Wappalyzer: pattern matching against response headers, body HTML, and meta tags.

## How it works

The fingerprint database (`summit/fingerprint.py`) contains 35+ fingerprints across 7 categories. Each fingerprint is a regex matched against the response headers and body. Version strings are extracted when available.

## Categories

| Category | Examples | What it enables |
|---|---|---|
| **Server** | Nginx, Apache, IIS, LiteSpeed, Caddy | CVE matching, version-specific exploits |
| **CMS** | WordPress, Drupal, Joomla, Ghost, Shopify | CMS-specific checks, plugin enumeration |
| **Framework** | Django, Flask, Express, Spring, Next.js, React, Vue | Framework-specific injection patterns |
| **Language** | PHP, Python, Node.js, Java, ASP.NET, Ruby, Go | Language-specific payload selection |
| **Library** | jQuery, Bootstrap, Lodash | Client-side CVE matching |
| **Analytics** | Google Analytics, Hotjar, Meta Pixel | Attack surface mapping |
| **CDN** | Cloudflare, CloudFront, Fastly, Akamai | Cache behavior, WAF detection |

## Detection examples

```python
from summit.http.client import HttpClient
from summit.http.models import HttpRequest
from summit.fingerprint import fingerprint

client = HttpClient()
response = client.send(HttpRequest(method="GET", url="https://target.com"))

for tech in fingerprint(response):
    print(f"{tech['category']:12} {tech['name']:20} {tech['version']}")
    print(f"  evidence: {tech['evidence']}")
```

## How it feeds the smart model

Detected technologies are passed to the prioritizer:

```python
from summit.smart import prioritize

# If PHP was detected, traversal and command injection params get boosted
ordered = prioritize(targets, detected_tech="PHP 8.1.5")
```

## How it feeds CVE detection

Detected versions are matched against the CVE database:

```python
from summit.cve import detect_cves

# If "Apache/2.4.49" was detected in the Server header
hits = detect_cves("Apache/2.4.49")
# -> [{"cve": "CVE-2021-41773", ...}, {"cve": "CVE-2021-42013", ...}]
```

## Adding fingerprints

Add an entry to `FINGERPRINTS` in `summit/fingerprint.py`:

```python
("cms", "MyNewCMS", r"mynewcms[-.]?(\d+\.\d+)", 1),
```

The regex must be defensible: it should match only the vendor's own markers, not pages that merely discuss the product.
