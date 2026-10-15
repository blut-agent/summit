import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from summit.http.client import HttpClient
from summit.http.models import HttpRequest


def test_retry_on_429_recovers_and_counts_hits():
    """Live proof of the retry logic: first response is 429, the client backs
    off, retries, and the caller sees the 200. The server counts exactly one
    retry - no more, no less."""
    state = {"hits": 0}

    class FlakyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["hits"] += 1
            if state["hits"] == 1:
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b"recovered"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), FlakyHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = HttpClient(retries=1)
        response = client.send(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/flaky"))
        assert response.status == 200, f"expected the retried 200, got {response.status}"
        assert state["hits"] == 2, f"expected exactly one retry (2 hits), got {state['hits']}"
        assert client.request_count == 2
    finally:
        server.shutdown()


def test_retry_budget_is_respected():
    """A server that always answers 503 must exhaust the retry budget, not loop."""
    class DownHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503)
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), DownHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = HttpClient(retries=2)
        response = client.send(HttpRequest(method="GET", url=f"http://127.0.0.1:{port}/down"))
        assert response.status == 503  # budget exhausted, final state returned honestly
        assert client.request_count == 3  # 1 initial + 2 retries, then it stopped
    finally:
        server.shutdown()
