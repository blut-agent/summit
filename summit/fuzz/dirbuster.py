from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..http.client import HttpClient
from ..http.models import HttpRequest
from ..scan.core import Finding

DEFAULT_WORDLIST = [
    "admin", "administrator", "backup", "config", "db", ".git", ".env", "robots.txt",
    "sitemap.xml", "login", "logout", "register", "uploads", "wp-admin", "wp-login.php",
    "api", "actuator", "swagger", "swagger-ui", "phpmyadmin", "console", "dashboard",
    "server-status", ".htaccess", "composer.json", "package.json", "web.config",
    "crossdomain.xml", "debug", "test", "old", "dev", "staging", "tmp", "temp",
    "log", "logs", "shell", "cmd", "cpanel", "manager", "panel", "user", "users",
    "account", "settings", "setup", "install", "install.php", "info.php",
    "phpinfo.php", "server-info", "status", "metrics", "health", ".svn", ".DS_Store",
    "id_rsa", "database.sql", "dump.sql", "db.sql", "backup.sql", "README.md",
    "CHANGELOG.md", "docker-compose.yml", "Dockerfile", "Jenkinsfile", "Makefile",
    "app.py", "main.py", "wsgi.py", "manage.py", "settings.py", ".gitignore", ".npmrc",
]

_WILDCARD_MARKER = "summit-wildcard-probe-9f3ac"


def fuzz(
    client: HttpClient,
    base_url: str,
    wordlist: list[str] | None = None,
    threads: int = 10,
    extensions: list[str] | None = None,
) -> list[Finding]:
    """Brute-force paths under base_url. Returns one info Finding per hit."""
    wordlist = wordlist or DEFAULT_WORDLIST
    extensions = extensions or []
    base = base_url if base_url.endswith("/") else base_url + "/"

    # Wildcard baseline: a server that answers 200 for everything would flood
    # the report with false positives, so measure it first and filter on it.
    wildcard_status: int | None = None
    wildcard_len: int | None = None
    try:
        wildcard = client.send(HttpRequest(method="GET", url=base + _WILDCARD_MARKER))
        wildcard_status = wildcard.status
        wildcard_len = len(wildcard.body)
    except Exception:
        pass

    candidates = [base + word for word in wordlist]
    candidates += [base + word + ext for word in wordlist for ext in extensions]

    def probe(url: str):
        # HttpClient wraps a shared requests.Session, which handles concurrent
        # use fine for plain requests of this size.
        try:
            return url, client.send(HttpRequest(method="GET", url=url))
        except Exception:
            return url, None

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe, url) for url in candidates]
        for future in as_completed(futures):
            url, response = future.result()
            if response is None:
                continue
            if response.status == 404:
                continue
            if wildcard_status is not None and response.status == wildcard_status and wildcard_len is not None and abs(len(response.body) - wildcard_len) < 20:
                continue
            name = url[len(base):]
            findings.append(
                Finding(
                    check_id="fuzz-dir",
                    title=f"Found path: /{name}",
                    severity="info",
                    url=url,
                    detail=f"HTTP {response.status} ({len(response.body)} bytes)",
                )
            )
    return findings
