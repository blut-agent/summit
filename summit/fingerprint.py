"""Technology fingerprinting - the Wappalyzer approach, stdlib edition.

Fingerprints are matched against response headers, body HTML patterns,
and meta tags. Each fingerprint produces a technology name and version
string that downstream phases use to select targeted checks.

This is not a neural network - it is a transparent pattern-matching
database where every rule is readable and auditable.
"""

from __future__ import annotations

import re

from ..http.models import HttpResponse

# Each fingerprint: (category, name, regex against response, version_group)
# Categories: server, framework, cms, library, analytics, cdn
FINGERPRINTS = [
    # --- Servers ---
    ("server", "Nginx", r"nginx/(\d+\.\d+(?:\.\d+)?)", 1),
    ("server", "Apache", r"Apache/(\d+\.\d+(?:\.\d+)?)", 1),
    ("server", "IIS", r"Microsoft-IIS/(\d+(?:\.\d+)?)", 1),
    ("server", "LiteSpeed", r"LiteSpeed/(\S+)", 1),
    ("server", "Caddy", r"Caddy/(\S+)", 1),
    ("server", "Cloudflare", r"cloudflare", None),
    # --- Languages / runtimes ---
    ("language", "PHP", r"PHP/(\d+\.\d+(?:\.\d+)?)", 1),
    ("language", "PHP (X-Powered-By)", r"PHP/(\d+\.\d+(?:\.\d+)?)", 1),
    ("language", "Python", r"Python/(\d+\.\d+(?:\.\d+)?)", 1),
    ("language", "Node.js", r"node|express", None),
    ("language", "Java", r"Java/(\d+(?:\.\d+)?)", 1),
    ("language", "ASP.NET", r"ASP\.NET|X-AspNet-Version", None),
    ("language", "Ruby", r"Ruby|Rails|Puma", None),
    ("language", "Go", r"Go/(\d+(?:\.\d+)?)|Golang", 1),
    # --- Frameworks ---
    ("framework", "Django", r"Django/(\d+\.\d+)", 1),
    ("framework", "Flask", r"flask|Werkzeug/(\d+\.\d+)", 1),
    ("framework", "Express", r"Express|x-powered-by: *Express", None),
    ("framework", "Spring", r"Spring|Spring-Boot", None),
    ("framework", "Laravel", r"Laravel|laravel_session", None),
    ("framework", "Next.js", r"__NEXT_DATA__|next\.js|/_next/", None),
    ("framework", "Nuxt", r"__NUXT__|nuxt", None),
    ("framework", "React", r"react-dom|__REACT_DEVTOOLS__|data-reactroot", None),
    ("framework", "Vue.js", r"vue\.js|data-v-|__VUE__", None),
    ("framework", "Angular", r"ng-version=|angular\.min\.js", None),
    ("framework", "Gunicorn", r"gunicorn/(\d+\.\d+)", 1),
    ("framework", "FastAPI", r"FastAPI|fastapi", None),
    ("framework", "Gatsby", r"___gatsby", None),
    # --- CMS ---
    ("cms", "WordPress", r"wp-content|wp-includes|WordPress (\d+\.\d+(?:\.\d+)?)", 1),
    ("cms", "Drupal", r"Drupal (\d+(?:\.\d+)?)|drupal\.js|drupal-settings-json", 1),
    ("cms", "Joomla", r"Joomla!|/media/jui/|joomla\.js", None),
    ("cms", "Ghost", r"ghost-sdk|content_api_key", None),
    ("cms", "Shopify", r"cdn\.shopify\.com|Shopify\.theme", None),
    ("cms", "Wix", r"wix\.com|wix-static", None),
    ("cms", "Squarespace", r"squarespace\.com|Static\.SQUARESPACE", None),
    ("cms", "Webflow", r"webflow\.js|w\-webflow", None),
    # --- Frontend libraries (for CVE matching) ---
    ("library", "jQuery", r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)", 1),
    ("library", "Bootstrap", r"bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)", 1),
    ("library", "Lodash", r"lodash[-.@]?(\d+\.\d+\.\d+)", 1),
    # --- Analytics / trackers ---
    ("analytics", "Google Analytics", r"google-analytics\.com|googletagmanager|gtag\(", None),
    ("analytics", "Hotjar", r"hotjar\.com", None),
    ("analytics", "Meta Pixel", r"facebook\.net/en_US/fbevents|connect\.facebook\.net", None),
    # --- CDN ---
    ("cdn", "Cloudflare CDN", r"cdn-cgi/|cloudflare", None),
    ("cdn", "CloudFront", r"cloudfront\.net|X-Amz-Cf-Id", None),
    ("cdn", "Fastly", r"fastly\.net|x-served-by: *cache-", None),
    ("cdn", "Akamai", r"akamai|akamaiedge", None),
    ("cdn", "KeyCDN", r"keycdn", None),
]


def _extract_header_value(response: HttpResponse, header: str) -> str:
    return response.header(header).strip()


def _match_fingerprints(response: HttpResponse) -> list[dict]:
    """Match all fingerprints against headers and body. Returns unique tech."""
    text = response.text[:100_000]
    headers = " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
    combined = headers + "\n" + text[:50_000]
    seen = set()
    results = []
    for category, name, pattern, version_group in FINGERPRINTS:
        match = re.search(pattern, combined, re.IGNORECASE)
        if not match:
            continue
        key = f"{category}:{name}"
        if key in seen:
            continue
        seen.add(key)
        version = ""
        if version_group is not None:
            try:
                version = match.group(version_group)
            except (IndexError, re.error):
                version = ""
        results.append({
            "category": category,
            "name": name,
            "version": version,
            "evidence": match.group(0)[:100],
        })
    return results


def fingerprint(response: HttpResponse) -> list[dict]:
    """Full fingerprint of a response - headers + body + meta tags."""
    return _match_fingerprints(response)


def summarize_technologies(technologies: list[dict]) -> str:
    """Human-readable summary string for console output."""
    by_cat: dict[str, list[str]] = {}
    for tech in technologies:
        label = tech["name"]
        if tech["version"]:
            label += f" {tech['version']}"
        by_cat.setdefault(tech["category"], []).append(label)
    parts = []
    for cat in ("server", "cms", "framework", "language", "library", "analytics", "cdn"):
        if cat in by_cat:
            parts.append(f"{cat}: {', '.join(by_cat[cat])}")
    return " | ".join(parts)
