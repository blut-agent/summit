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
    - missing security headers + version disclosure on every response
"""

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

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

    def _html(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
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
