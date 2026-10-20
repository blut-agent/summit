"""Sensitive file exposure (CWE-538) - signatures, not just status codes.

A 200 response for /.env proves nothing on wildcard-routing servers
(that is why the fuzzer has a wildcard baseline). This check requires
the body to match the file's real content, which makes false positives
practically impossible. Depth follows Nuclei's exposure templates:
credentials, VCS metadata, cloud configs, framework settings, build
and infrastructure state.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding
from ..runtime import deep

# (path, content signatures - any one match confirms, name, severity)
PATH_SIGNATURES = [
    ("/.env", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.git/config", ["[core]", "repositoryformatversion"], "git repository metadata", "high"),
    ("/.git/HEAD", ["ref: refs/"], "git repository head", "medium"),
    ("/.aws/credentials", ["aws_access_key_id", "[default]"], "AWS credentials file", "high"),
    ("/backup.sql", ["CREATE TABLE", "INSERT INTO"], "database dump", "high"),
    ("/wp-config.php", ["DB_NAME", "DB_PASSWORD"], "WordPress configuration", "high"),
    ("/web.config.bak", ["connectionString", "system.web"], "IIS configuration backup", "high"),
    ("/.DS_Store", ["Bud1"], "macOS directory listing", "low"),
    ("/.htaccess", ["<IfModule", "RewriteEngine"], "Apache configuration", "medium"),
    ("/.htpasswd", [":$apr1$", ":$2y$", ":$2a$", ":$6$", ":$argon2"], "htpasswd credential file", "high"),
    ("/web.config", ["<system.webServer>", "<system.web>"], "IIS configuration", "high"),
    ("/phpinfo.php", ["PHP Version", "phpinfo()"], "PHP info page", "medium"),
    ("/server-status", ["Apache Server Status", "Server uptime"], "Apache status page", "medium"),
    ("/server-info", ["Apache Server Information", "Server Settings"], "Apache server information", "medium"),
    ("/metrics", ["# HELP ", "# TYPE "], "metrics endpoint", "low"),
    ("/_cluster/health", ['"cluster_name"', '"active_primary_shards"'], "Elasticsearch cluster health", "medium"),
    ("/v2/_catalog", ['"repositories"'], "Docker registry catalog", "high"),
    ("/actuator/env", ['"propertySources"'], "Spring Boot environment endpoint", "high"),
    ("/actuator/gateway/routes", ['"route_id"'], "Spring Cloud Gateway routes", "medium"),
    ("/swagger.json", ['"swagger":', '"openapi":'], "Swagger definition", "low"),
    ("/openapi.json", ['"openapi":', '"paths":'], "OpenAPI definition", "low"),
    ("/.npmrc", ["_authToken", "registry="], "npm credentials file", "high"),
    ("/.docker/config.json", ['"auths"'], "Docker registry credentials", "high"),
    ("/.kube/config", ["apiVersion:", "clusters:"], "Kubernetes credentials", "high"),
    ("/terraform.tfstate", ['"terraform_version"', '"resources"'], "Terraform state (secrets)", "high"),
    ("/secrets.json", ['"password"', '"secret"', '"api_key"'], "application secrets file", "medium"),
]

# Deep mode: more high-value paths, same content-signature rule.
DEEP_PATH_SIGNATURES = [
    ("/.env.local", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.production", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.development", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.staging", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.bak", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.old", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/.env.dev", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file", "high"),
    ("/id_rsa", ["PRIVATE KEY"], "SSH private key", "high"),
    ("/id_ed25519", ["PRIVATE KEY"], "SSH private key", "high"),
    ("/id_ecdsa", ["PRIVATE KEY"], "SSH private key", "high"),
    ("/.ssh/id_rsa", ["PRIVATE KEY"], "SSH private key", "high"),
    ("/server.key", ["PRIVATE KEY"], "TLS private key", "high"),
    ("/private.key", ["PRIVATE KEY"], "private key", "high"),
    ("/docker-compose.yml", ["services:", "image:"], "docker compose manifest", "high"),
    ("/docker-compose.yaml", ["services:", "image:"], "docker compose manifest", "high"),
    ("/db.sqlite3", ["SQLite format 3"], "SQLite database", "high"),
    ("/dump.sql", ["CREATE TABLE", "INSERT INTO"], "database dump", "high"),
    ("/database.sql", ["CREATE TABLE", "INSERT INTO"], "database dump", "high"),
    ("/db.sql", ["CREATE TABLE", "INSERT INTO"], "database dump", "high"),
    ("/db_backup.sql", ["CREATE TABLE", "INSERT INTO"], "database dump", "high"),
    ("/config.php.bak", ["DB_PASSWORD", "DB_NAME"], "PHP configuration backup", "high"),
    ("/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD"], "WordPress configuration backup", "high"),
    ("/error.log", ["PHP Fatal error", "Traceback (most recent call last)", "Exception in thread"], "application error log", "medium"),
    ("/debug.log", ["PHP Fatal error", "Traceback (most recent call last)", "Exception in thread"], "application debug log", "medium"),
    ("/.aws/config", ["[default]", "region ="], "AWS CLI configuration", "medium"),
    ("/.idea/workspace.xml", ["<project version=", "<component name="], "IDE workspace metadata", "medium"),
]


def run_sensitive_files(client: HttpClient, base_url: str) -> list[Finding]:
    """Check a handful of high-value paths once per scan. Content decides."""
    findings: list[Finding] = []
    split = urlsplit(base_url)
    origin = f"{split.scheme}://{split.netloc}"
    checks = (PATH_SIGNATURES + DEEP_PATH_SIGNATURES) if deep() else PATH_SIGNATURES
    for path, signatures, name, severity in checks:
        try:
            response = client.send(HttpRequest(method="GET", url=origin + path))
        except Exception:
            continue
        if response.status != 200:
            continue
        body = response.text[:50_000].lower()
        hit = next((signature for signature in signatures if signature.lower() in body), None)
        if hit is None:
            continue
        findings.append(
            Finding(
                check_id="sensitive-file",
                title=f"Sensitive file exposed: {path}",
                severity=severity,
                url=origin + path,
                confidence="confirmed",
                detail=f"The server returns a 200 with content that matches a real {name}. "
                "Status-code-only scanners flood this check with false positives; the content signature is what makes it certain.",
                evidence=f"content signature: {hit!r}",
                remediation="Remove the file from the web root, revoke any credentials it contains, "
                "and block access to dotfiles and backups at the server level.",
            )
        )
    return findings
