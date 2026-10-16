"""False-positive regression tests: every guard here exists because a
FP class was observed or predicted. If any of these start failing, a
check has regressed into noise.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from summit.authorize import Role, findings_from, run_authorize
from summit.http.client import HttpClient
from summit.http.models import HttpRequest, HttpResponse
from summit.scan.core import InjectionPoint
from summit.scan.modules.ssti import SstiCheck


class LoginWallHandler(BaseHTTPRequestHandler):
    """Mimics an app where EVERY request (any role) bounces to the same
    login redirect. The old authorize logic called this 'broken access
    control' because responses matched - it is nothing of the sort."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Content-Length", "0")
        self.end_headers()


class EchoPlusFortyNineHandler(BaseHTTPRequestHandler):
    """Reflects the raw parameter AND happens to render '49' elsewhere
    (e.g. a page number). Old SSTI logic called this template injection."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        split = self.path.split("?", 1)
        query = split[1] if len(split) > 1 else ""
        body = f"<html><body>input: {query}</body><footer>page 49 of 120</footer></html>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_authorize_ignores_login_redirect_wall():
    """Both roles get the same 302 login redirect -> NOT broken access control."""
    server, port = start_server(LoginWallHandler)
    try:
        client = HttpClient()
        results = run_authorize(
            client,
            [f"http://127.0.0.1:{port}/admin?user=1"],
            Role("admin", {"Cookie": "session=admin-token"}),
            Role("user", {"Cookie": "session=user-token"}),
        )
        assert results[0].verdict == "broken"  # responses do match...
        assert findings_from(results) == []   # ...but the guard suppresses it
    finally:
        server.shutdown()


def test_authorize_still_flags_real_privileged_content():
    """The guard must not suppress genuine privileged content."""
    class AdminHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            body = (
                b"<html><body><h1>Admin panel</h1>"
                b"<p>Salary report: admin 9500, users 3200/3100.</p>"
                b"<p>Internal notes: acquisition planned Q3.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, port = start_server(AdminHandler)
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
        assert len(findings) == 1 and findings[0].severity == "critical"
    finally:
        server.shutdown()


def test_ssti_ignores_reflection_with_incidental_49():
    server, port = start_server(EchoPlusFortyNineHandler)
    try:
        client = HttpClient()
        point = InjectionPoint(
            request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/page?name=world"),
            param="name",
            original_value="world",
        )
        # The page echoes {{7*7}} literally AND contains "49" (page footer).
        # Evaluation requires the raw template to disappear - it did not.
        assert SstiCheck().run(point, client) == []
    finally:
        server.shutdown()


def test_evidence_is_not_truncated():
    """The 'complete evidence' requirement: long proof strings survive
    as_dict and the console writer untouched."""
    from summit.report.writer import write_console

    long_evidence = "x" * 900 + "END-MARKER"
    finding = HttpResponse  # placeholder to keep imports honest
    from summit.scan.core import Finding

    finding = Finding(
        check_id="test",
        title="long evidence",
        severity="info",
        url="http://test.local/",
        evidence=long_evidence,
    )
    dumped = finding.as_dict()["evidence"]
    assert dumped.endswith("END-MARKER") and len(dumped) == len(long_evidence)
    console = write_console([finding], "http://test.local/")
    assert "END-MARKER" in console
