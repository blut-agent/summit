import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from summit.authorize import Role, findings_from, parse_role, run_authorize
from summit.http.client import HttpClient
from summit.openapi import build_requests, load_spec
from summit.paramminer import mine


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        split = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(split.query, keep_blank_values=True).items()}
        if split.path == "/admin":
            body = (
                b"<html><body><h1>Admin panel</h1>"
                b"<p>Salary report: admin 9500, users 3200/3100.</p>"
                b"<p>Internal notes: acquisition planned Q3.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif split.path == "/debug":
            debug_value = query.get("debug", "")
            suffix = f"<!-- debug mode enabled by request: {debug_value} -->" if debug_value else ""
            body = f"<html><body><p>Normal page</p>{suffix}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --- authorize (Autorize workflow) ---

def test_parse_role_spec():
    role = parse_role("admin=Cookie: session=abc123")
    assert role.name == "admin"
    assert role.headers == {"Cookie": "session=abc123"}


def test_broken_access_control_detected_live():
    server, port = start_server()
    try:
        client = HttpClient()
        results = run_authorize(
            client,
            [f"http://127.0.0.1:{port}/admin?user=1"],
            Role("admin", {"Cookie": "session=admin-token"}),
            Role("user", {"Cookie": "session=user-token"}),
        )
        assert results[0].verdict == "broken"
        findings = findings_from(results)
        assert len(findings) == 1
        assert findings[0].check_id == "authorize-bypass"
        assert findings[0].severity == "critical"
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


# --- param miner (hidden parameter discovery) ---

def test_hidden_parameter_mined_live():
    server, port = start_server()
    try:
        client = HttpClient()
        findings = mine(client, f"http://127.0.0.1:{port}/debug")
        reflected = [f for f in findings if f.check_id == "paramminer-reflected" and f.param == "debug"]
        assert len(reflected) == 1
        assert reflected[0].confidence == "confirmed"
        # the other ~120 candidates must stay quiet - no false positives
        assert all(f.param == "debug" for f in findings)
    finally:
        server.shutdown()


# --- openapi spec-driven targets ---

def test_build_requests_from_spec():
    spec = load_spec("examples/openapi.json")
    requests = build_requests(spec)
    urls = {r.url for r in requests}
    assert "http://127.0.0.1:8765/user?id=1" in urls
    assert "http://127.0.0.1:8765/search?query=laptop" in urls
    assert all(r.method == "GET" for r in requests)
