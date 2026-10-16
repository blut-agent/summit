"""Deliberately vulnerable demo app for verifying Summit's detection.

This app exists so you (and our CI) can prove the scanner works without
touching any real target. Everything is simulated and local:

- the "database" is an in-memory SQLite behind a lock
- the "filesystem" is a virtual dict (no real files are ever read)
- the server binds to 127.0.0.1 only

Run it, then run Summit against it:

    python examples/vuln_app.py            # terminal 1
    summit scan http://127.0.0.1:8765      # terminal 2

Seeded vulnerabilities:
    - reflected XSS       /search?query=   (raw reflection in HTML body)
    - SQLi, error-based   /user?id=        (unquoted string concatenation)
    - SQLi, boolean-based /user?id=        (true/false response divergence)
    - open redirect       /redirect?url=   (unvalidated 302)
    - path traversal      /file?name=      (virtual filesystem read)
    - broken link         summer-promo     (dead external domain, NXDOMAIN)
    - WAF, bypassable     /protected?token= (naive filter + double decoding)
    - CAPTCHA challenge   /login           (reCAPTCHA marker, reported not solved)
    - resource takeover   /old-bucket      (404 + S3 NoSuchBucket signature)
    - host header inject  /reset?user=     (reflects the Host header into a reset link)
    - CORS reflection     /api?user=1      (reflects any Origin, credentials allowed)
    - broken authz        /admin?user=1    (admin panel served to any role - BOLA demo)
    - hidden parameter    /debug           (undocumented debug param, reflected)
    - OS command inject   /ping?host=      (simulated shell - deterministic, no real subprocess)
    - SSTI / RCE          /greet?name=     (naive template evaluates {{7*7}})
    - CRLF injection      /goto?to=        (Location header accepts CRLF)
    - sensitive file      /.env            (200 with APP_KEY/DB_PASSWORD content)
    - time-based SQLi     /user?id=        (SLEEP marker pauses the handler 0.25s)
    - GraphQL leak        /graphql         (introspection enabled in production)
    - missing security headers + version disclosure on every response

The "partner" link (https://example.com) is a live negative control: a
healthy outbound link (HTTP 200) must NOT be reported.
"""

import json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

PORT = 8765

PAGE = """<!doctype html>
<html><head><title>Summit demo shop</title></head>
<body>
<h1>Summit demo shop</h1>
<p>Deliberately vulnerable on purpose. Local only.</p>
<ul>
  <li><a href="/search?query=laptop">search</a></li>
  <li><a href="/user?id=1">user</a></li>
  <li><a href="/redirect?url=https://example.com">redirect</a></li>
  <li><a href="/file?name=notes.txt">file</a></li>
  <li><a href="/protected?token=demo">protected</a></li>
  <li><a href="/login">login</a></li>
  <li><a href="/old-bucket">old-bucket</a></li>
  <li><a href="/reset?user=demo">reset</a></li>
  <li><a href="/api?user=1">api</a></li>
  <li><a href="/ping?host=demo.local">ping</a></li>
  <li><a href="/greet?name=world">greet</a></li>
  <li><a href="/goto?to=/">goto</a></li>
  <li><a href="/.env">env</a></li>
  <li><a href="/graphql">graphql</a></li>
  <li><a href="https://summit-demo-dead.example/old-promo">summer promo</a></li>
  <li><a href="https://example.com/">partner</a></li>
</ul>
</body></html>"""

# Virtual filesystem for the traversal demo. No real file is ever opened.
VFS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
    ),
    "/windows/win.ini": "[fonts]\n[extensions]\n; for 16-bit app support\n[MCI Extensions.BAK]",
}

USERS = {
    1: ("admin", "admin@demo.local", "198.51.100.10"),
    2: ("kevin", "kevin@demo.local", "198.51.100.11"),
    3: ("sarah", "sarah@demo.local", "198.51.100.12"),
}


def seed_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT, last_ip TEXT)")
    for uid, (name, email, ip) in USERS.items():
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (uid, name, email, ip))
    conn.commit()
    return conn


DB = seed_db()
DB_LOCK = threading.Lock()


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "DemoShop/1.0"  # chatty Server header on purpose
    protocol_version = "HTTP/1.1"

    def _html(self, body: str, status: int = 200, extra_headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args) -> None:  # keep the demo output clean
        pass

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        query = {key: values[0] for key, values in parse_qs(split.query, keep_blank_values=True).items()}
        path = split.path

        if path == "/":
            self._html(PAGE)

        elif path == "/search":
            # Vulnerable: raw reflection into the HTML body.
            term = query.get("query", "")
            self._html(f"<html><body><h1>Results for {term}</h1><p>No products matched.</p></body></html>")

        elif path == "/user":
            uid = query.get("id", "")
            # Vulnerable (time-based demo): a SLEEP marker in the input makes
            # the handler pause briefly - deterministic, capped at 0.25s, so
            # the time-based check can be demonstrated without hurting anyone.
            if "SLEEP" in uid:
                time.sleep(0.25)
            # Vulnerable: user input concatenated straight into SQL.
            sql = f"SELECT id, name, email, last_ip FROM users WHERE id = {uid}"
            try:
                with DB_LOCK:
                    rows = DB.execute(sql).fetchall()
            except sqlite3.Error as exc:
                # Vulnerable: verbose database error surfaced to the client.
                self._html(f"<html><body><p class='error'>Database error: {exc}</p></body></html>")
                return
            if not rows:
                self._html("<html><body><p>No user found.</p></body></html>")
                return
            blocks = "".join(
                f"<div class='user'><h2>{row[1]}</h2>"
                f"<p>Email: {row[2]}</p>"
                f"<p>Last login from: {row[3]}</p>"
                f"<p>Account created 2026-01-0{row[0]}, status: active, plan: pro. "
                f"Demo user record number {row[0]} with plenty of filler text so response "
                f"sizes differ meaningfully between hits and misses.</p></div>"
                for row in rows
            )
            self._html(f"<html><body>{blocks}</body></html>")

        elif path == "/protected":
            token = query.get("token", "")
            # Simulated WAF: it inspects the parameter as the request carries it
            # (no extra decoding - real WAFs sit in front of the app) and blocks
            # tag / quote injection markers. Note the app behind it decodes one
            # layer more than the filter ever looks at - that mismatch is the
            # whole vulnerability.
            inspected = token.lower()
            if "<svg" in inspected or "<script" in inspected or "'" in inspected:
                body = "<html><body><h1>403 Forbidden</h1><p>Request blocked. ModSecurity.</p></body></html>"
                data = body.encode("utf-8")
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Server", "DemoShop/1.0 Mod_Security/2.9")
                self.end_headers()
                self.wfile.write(data)
                return
            # The layer behind the WAF decodes one more time than the filter
            # does - exactly that mismatch is the vulnerability.
            decoded = unquote(token)
            self._html(
                f"<html><body><p>Access for {decoded} granted.</p></body></html>",
                extra_headers={"Server": "DemoShop/1.0 Mod_Security/2.9"},
            )

        elif path == "/login":
            # Simulated login page behind a CAPTCHA. Summit reports the
            # challenge; solving it is a human's job.
            body = (
                "<html><head>"
                "<script src=\"https://www.google.com/recaptcha/api.js\"></script>"
                "</head><body><h1>Sign in</h1>"
                "<form method=\"POST\" action=\"/login\">"
                "<input type=\"text\" name=\"user\"><input type=\"password\" name=\"pass\">"
                "<div class=\"g-recaptcha\" data-sitekey=\"demo\"></div>"
                "<button type=\"submit\">Sign in</button></form></body></html>"
            )
            self._html(body)

        elif path == "/old-bucket":
            # Simulated decommissioned S3 bucket: the DNS still points here,
            # the bucket behind it is gone. The classic takeover setup.
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<Error><Code>NoSuchBucket</Code>"
                "<Message>The specified bucket does not exist</Message></Error>"
            )
            self._html(body, status=404, extra_headers={"Content-Type": "application/xml"})

        elif path == "/reset":
            # Vulnerable: the reset link is built from the Host header, so
            # whoever controls the header controls where the link points.
            host_header = self.headers.get("Host", "localhost")
            user = query.get("user", "")
            self._html(
                f"<html><body><p>Password reset for {user} sent: "
                f"http://{host_header}/reset?token=abc123</p></body></html>"
            )

        elif path == "/api":
            # Vulnerable: reflects an arbitrary Origin back into
            # Access-Control-Allow-Origin, with credentials allowed.
            origin = self.headers.get("Origin", "")
            data = '{"user":"demo","email":"admin@demo.local"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(data.encode())))
            self.end_headers()
            self.wfile.write(data.encode())

        elif path == "/admin":
            # Vulnerable: the admin panel is served to ANY role. The session
            # cookie is decorative - nothing is checked. This is the endpoint
            # `summit authorize` exists to catch.
            self._html(
                "<html><body><h1>Admin panel</h1>"
                "<p>Salary report: admin 9500, users 3200/3100/3000.</p>"
                "<p>Internal notes: acquisition planned Q3.</p></body></html>"
            )

        elif path == "/debug":
            # Vulnerable: an undocumented parameter flips the page into debug
            # mode and echoes its value. Nothing in the HTML advertises it -
            # exactly what `summit mine` is for.
            debug_value = query.get("debug", "")
            if debug_value:
                self._html(
                    f"<html><body><p>Normal page</p>"
                    f"<!-- debug mode enabled by request: {debug_value} --></body></html>"
                )
            else:
                self._html("<html><body><p>Normal page</p></body></html>")

        elif path == "/ping":
            # Vulnerable: simulates a shell wrapper. Everything after a shell
            # separator is treated as a second command - but only `echo <token>`
            # is implemented, so the demo is deterministic and never spawns a
            # real process.
            host = query.get("host", "")
            lines = [f"Pinging {host}..."]
            match = re.search(r"(?:;|\||&&|&|`|\$\()\s*echo\s+([A-Za-z0-9\-]+)", host)
            if match:
                lines.append(match.group(1))
            self._html("<html><body><pre>" + "\n".join(lines) + "</pre></body></html>")

        elif path == "/greet":
            # Vulnerable: a naive template engine that evaluates simple
            # arithmetic inside {{ }} - the classic SSTI canary condition.
            name = query.get("name", "")
            name = re.sub(r"\{\{(\d+\s*[\+\-\*/]\s*\d+)\}\}", lambda m: str(eval(m.group(1))), name)
            self._html(f"<html><body><h1>Hello {name}</h1><p>Welcome back.</p></body></html>")

        elif path == "/goto":
            # Vulnerable: redirects to a user-supplied target without
            # stripping CRLF - response splitting demo.
            target = query.get("to", "/")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/.env":
            # Vulnerable: environment file left in the web root, served with
            # its real content (status-code-only scanners miss the difference).
            body = (
                "APP_KEY=base64:summitDemoKeyOnPurpose\n"
                "DB_PASSWORD=summit-demo-password\n"
                "DB_HOST=127.0.0.1\n"
            )
            self._html(body)

        elif path == "/graphql":
            # Vulnerable: introspection is enabled in production.
            body = json.dumps({
                "data": {"__schema": {"queryType": {"name": "Query"}, "types": [
                    {"name": "Query"}, {"name": "User"}, {"name": "Secret"},
                ]}}
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())

        elif path == "/redirect":
            # Vulnerable: unvalidated redirect target.
            target = query.get("url", "/")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif path == "/file":
            # Vulnerable: user-controlled path, resolved against a virtual
            # filesystem root (stand-in for a real file read).
            name = query.get("name", "")
            resolved = name if name.startswith("/") else "/" + name
            normalized = resolved.replace("\\", "/")
            while "/../" in normalized:
                normalized = normalized.replace("/../", "/")
            content = VFS.get(normalized)
            if content is None:
                self._html("<html><body><p>File not found.</p></body></html>", status=404)
            else:
                self._html(f"<html><body><pre>{content}</pre></body></html>")

        else:
            self._html("<html><body><p>Not found.</p></body></html>", status=404)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"[*] demo shop listening on http://127.0.0.1:{PORT} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye")


if __name__ == "__main__":
    main()
