import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from summit.crawl.js_endpoints import extract_from_page
from summit.http.client import HttpClient
from summit.http.models import HttpRequest
from summit.scan.modules.csrf import check_csrf_forms


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        split = urlsplit(self.path)
        if split.path == "/":
            body = b"<html><body><script src='/app.js'></script></body></html>"
            self._send(body)
        elif split.path == "/app.js":
            body = b"fetch('/api/secret?token=abc123');\n"
            self._send(body, "application/javascript")
        elif split.path == "/api/secret":
            body = b'{"token": "summit-demo-secret-token-9f3", "role": "internal"}'
            self._send(body, "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _send(self, body: bytes, content_type: str = "text/html"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server(handler_class=None):
    handler = handler_class or AppHandler
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_js_endpoint_extraction():
    endpoints, js_files = extract_from_page(
        "<script src='/app.js'></script>",
        "http://127.0.0.1:9000/",
        {"127.0.0.1"},
    )
    assert js_files == ["http://127.0.0.1:9000/app.js"]


def test_js_hidden_endpoint_reached_through_crawl():
    """The FN killer: /api/secret is only referenced from JavaScript.
    A crawl that reads JS must reach it; its findings must include the
    sensitive-token cacheable-response finding."""
    server, port = start_server()
    try:
        client = HttpClient(timeout=10)
        from summit.crawl.spider import Spider
        from summit.scan.engine import ScanEngine

        spider = Spider(client, max_depth=2, max_pages=20)
        result = spider.crawl(f"http://127.0.0.1:{port}/")
        assert any("/api/secret" in url for url in result["visited"]), (
            "the JS-only endpoint was never crawled"
        )
        engine = ScanEngine(client, workers=4, linkcheck_enabled=False)
        findings = engine.scan(result)
        secret_findings = [f for f in findings if "/api/secret" in f.url]
        assert secret_findings, "the JS-only endpoint was never scanned"
        assert any(f.check_id == "cacheable-sensitive" for f in secret_findings), (
            "the leaked token behind the JS endpoint was never detected"
        )
    finally:
        server.shutdown()


# --- CSRF form check ---

class FormHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/login":
            body = (
                b"<html><body><form method='POST' action='/login'>"
                b"<input name='user'><input type='password' name='pass'>"
                b"<button>Login</button></form></body></html>"
            )
            self._send(body)
        elif self.path == "/safe":
            body = (
                b"<html><body><form method='POST' action='/safe'>"
                b"<input name='user'><input type='hidden' name='csrf_token' value='x'>"
                b"<button>Go</button></form></body></html>"
            )
            self._send(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_csrf_missing_token_flagged():
    server, port = start_server(FormHandler)
    try:
        client = HttpClient()
        response = client.send(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/login"))

        findings = check_csrf_forms(
            response,
            forms=[{"action": f"http://127.0.0.1:{port}/login", "method": "POST", "fields": {"user": "", "pass": ""}}],
        )
        assert len(findings) == 1
        assert findings[0].check_id == "csrf-missing"
        assert findings[0].severity == "medium"
    finally:
        server.shutdown()


def test_csrf_check_quiet_when_token_present():
    server, port = start_server(FormHandler)
    try:
        client = HttpClient()
        response = client.send(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/safe"))
        findings = check_csrf_forms(
            response,
            forms=[{"action": f"http://127.0.0.1:{port}/safe", "method": "POST", "fields": {"user": "", "csrf_token": "x"}}],
        )
        assert findings == []
    finally:
        server.shutdown()
