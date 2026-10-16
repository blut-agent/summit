import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import re

from summit.cve import detect_cves
from summit.http.client import HttpClient
from summit.http.models import HttpRequest
from summit.scan.core import InjectionPoint
from summit.scan.modules.crlf import CrlfInjectionCheck
from summit.scan.modules.os_command import OsCommandInjectionCheck
from summit.scan.modules.sensitive_files import run_sensitive_files
from summit.scan.modules.ssti import SstiCheck


# --- CVE database (pure, offline) ---

def test_apache_2_4_49_maps_to_cves():
    hits = detect_cves("Apache/2.4.49 (Unix)")
    ids = {h["cve"] for h in hits}
    assert "CVE-2021-41773" in ids
    assert "CVE-2021-42013" in ids


def test_nginx_1_20_0_maps_to_cve():
    hits = detect_cves("nginx/1.20.0")
    assert any(h["cve"] == "CVE-2021-23017" for h in hits)


def test_unknown_version_stays_quiet():
    assert detect_cves("DemoShop/1.0 Python/3.13.2") == []
    assert detect_cves("") == []


# --- live mini server: the four new checks ---

class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        split = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(split.query, keep_blank_values=True).items()}
        if split.path == "/ping":
            host = query.get("host", "")
            lines = [f"Pinging {host}..."]
            match = re.search(r"(?:;|\||&&|&|`|\$\()\s*echo\s+([A-Za-z0-9\-]+)", host)
            if match:
                lines.append(match.group(1))
            body = f"<pre>{chr(10).join(lines)}</pre>".encode()
            self._ok(body)
        elif split.path == "/greet":
            name = query.get("name", "")
            name = re.sub(r"\{\{(\d+\s*[\+\-\*/]\s*\d+)\}\}", lambda m: str(eval(m.group(1))), name)
            self._ok(f"<h1>Hello {name}</h1>".encode())
        elif split.path == "/goto":
            self.send_response(302)
            self.send_header("Location", query.get("to", "/"))
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif split.path == "/.env":
            self._ok(b"APP_KEY=base64:demo\nDB_PASSWORD=demo\n")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _ok(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def make_point(url: str, param: str, value: str):
    request = HttpRequest(method="GET", url=url)
    return InjectionPoint(request=request, param=param, original_value=value)


def test_os_command_injection_detected_live():
    server, port = start_server()
    try:
        client = HttpClient()
        point = make_point(f"http://127.0.0.1:{port}/ping?host=demo.local", "host", "demo.local")
        findings = OsCommandInjectionCheck().run(point, client)
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
        assert findings[0].severity == "critical"
    finally:
        server.shutdown()


def test_ssti_detected_live():
    server, port = start_server()
    try:
        client = HttpClient()
        point = make_point(f"http://127.0.0.1:{port}/greet?name=world", "name", "world")
        findings = SstiCheck().run(point, client)
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
        assert "49" in findings[0].evidence or "Jinja2" in findings[0].evidence
    finally:
        server.shutdown()


def test_crlf_injection_detected_live():
    server, port = start_server()
    try:
        client = HttpClient()
        point = make_point(f"http://127.0.0.1:{port}/goto?to=/", "to", "/")
        findings = CrlfInjectionCheck().run(point, client)
        assert len(findings) == 1
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


def test_sensitive_env_file_detected_live():
    server, port = start_server()
    try:
        client = HttpClient()
        findings = run_sensitive_files(client, f"http://127.0.0.1:{port}/")
        assert len(findings) == 1
        assert findings[0].url.endswith("/.env")
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


# --- CVE range matching (packaging-backed, offline) ---

def test_cve_ranges_match_boundaries():
    hits_49 = {h["cve"] for h in detect_cves("Apache/2.4.49")}
    hits_50 = {h["cve"] for h in detect_cves("Apache/2.4.50")}
    hits_48 = {h["cve"] for h in detect_cves("Apache/2.4.48")}
    hits_51 = {h["cve"] for h in detect_cves("Apache/2.4.51")}
    assert hits_49 == {"CVE-2021-41773", "CVE-2021-42013"}
    assert hits_50 == {"CVE-2021-42013"}
    assert hits_48 == set()   # below the affected range
    assert hits_51 == set()   # above the affected range


def test_cve_non_pep440_versions_use_exact_lists():
    assert any(h["cve"] == "CVE-2014-0160" for h in detect_cves("OpenSSL/1.0.1f"))
    assert any(h["cve"] == "CVE-2014-0160" for h in detect_cves("OpenSSL/1.0.1"))
    assert not any(h["cve"] == "CVE-2014-0160" for h in detect_cves("OpenSSL/1.0.2a"))


def test_tomcat_multi_range_ghostcat():
    assert any(h["cve"] == "CVE-2020-1938" for h in detect_cves("Apache Tomcat/9.0.30"))
    assert not any(h["cve"] == "CVE-2020-1938" for h in detect_cves("Apache Tomcat/9.0.31"))


# --- YAML OpenAPI specs ---

def test_yaml_spec_loads_and_builds_targets():
    from summit.openapi import build_requests, load_spec

    spec = load_spec("examples/openapi.yaml")
    requests = build_requests(spec)
    urls = {r.url for r in requests}
    assert "http://127.0.0.1:8765/user?id=1" in urls
