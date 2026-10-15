from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .crawl.spider import Spider
from .fuzz.dirbuster import fuzz
from .http.client import HttpClient
from .http.models import HttpRequest
from .proxy.server import ProxyServer
from .report.writer import write_console, write_html, write_json
from .scan.engine import ScanEngine

BANNER = r"""
          _
 ___ _ _| |_ ___ _ _ ___  _ _ ___ ___
|  _| ' \  _/ -_) '_/ -_) '_\ \ / / -_)   summit v{version}
|___|_||_\__\___|_| \___|_| /_\_\ \___|   by Pennacle Security
                                          authorized testing only
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="summit",
        description="Summit - open-source web security testing platform (proxy, scanner, fuzzer).",
    )
    parser.add_argument("--version", action="version", version=f"summit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="crawl a target and run passive + active checks")
    scan.add_argument("url", help="target URL, e.g. https://testsite.local")
    scan.add_argument("--depth", type=int, default=3, help="max crawl depth (default 3)")
    scan.add_argument("--max-pages", type=int, default=50, help="max pages to visit (default 50)")
    scan.add_argument("--no-active", action="store_true", help="skip active checks (passive only)")
    scan.add_argument("--delay", type=float, default=0.0, help="seconds between requests (be nice)")
    scan.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
    scan.add_argument("--json", dest="json_path", help="write a JSON report to this path")
    scan.add_argument("--html", dest="html_path", help="write an HTML report to this path")

    fuzz_p = sub.add_parser("fuzz", help="brute-force paths on a target")
    fuzz_p.add_argument("url")
    fuzz_p.add_argument("-w", "--wordlist", help="wordlist file, one entry per line")
    fuzz_p.add_argument("-t", "--threads", type=int, default=10, help="concurrent requests (default 10)")
    fuzz_p.add_argument("-e", "--extensions", default="", help="comma separated, e.g. php,html,bak")

    proxy_p = sub.add_parser("proxy", help="run the local intercepting proxy")
    proxy_p.add_argument("--bind", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8080)
    proxy_p.add_argument("--db", default="summit_sitemap.db", help="sqlite site map path")

    rep = sub.add_parser("repeater", help="send a raw HTTP request from a file (Burp-style)")
    rep.add_argument("file")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    print(BANNER.format(version=__version__))
    client = HttpClient(timeout=args.timeout, delay=args.delay)
    spider = Spider(client, max_depth=args.depth, max_pages=args.max_pages, delay=args.delay)
    print(f"[*] crawling {args.url} ...")
    result = spider.crawl(args.url)
    print(
        f"[*] visited {len(result['visited'])} page(s), "
        f"{len(result['forms'])} form(s), {len(result['errors'])} request error(s)"
    )
    for error in result["errors"][:5]:
        print(f"[!] {error}")

    engine = ScanEngine(client, active=not args.no_active)
    findings = engine.scan(result)
    for error in engine.errors[:5]:
        print(f"[!] check error: {error}")
    print(write_console(findings, args.url))
    if args.json_path:
        write_json(findings, args.json_path)
        print(f"[*] JSON report written to {args.json_path}")
    if args.html_path:
        write_html(findings, args.html_path, args.url)
        print(f"[*] HTML report written to {args.html_path}")
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    wordlist = None
    if args.wordlist:
        wordlist = [line.strip() for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines() if line.strip()]
    extensions = [ext.strip().lstrip(".") for ext in args.extensions.split(",") if ext.strip()]
    client = HttpClient()
    findings = fuzz(client, args.url, wordlist=wordlist, threads=args.threads, extensions=extensions)
    print(write_console(findings, args.url))
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    server = ProxyServer(host=args.bind, port=args.port, db_path=args.db)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] shutting down")
        server.stop()
    return 0


def _cmd_repeater(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_text(encoding="utf-8")
    request = HttpRequest.from_raw(raw)
    client = HttpClient()
    print(f"[*] sending {request.method} {request.url}")
    response = client.send(request)
    print(f"HTTP {response.status} ({response.elapsed:.2f}s)")
    for key, value in response.headers.items():
        print(f"{key}: {value}")
    print()
    print(response.text[:5000])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "fuzz":
            return _cmd_fuzz(args)
        if args.command == "proxy":
            return _cmd_proxy(args)
        if args.command == "repeater":
            return _cmd_repeater(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130
    return 0
