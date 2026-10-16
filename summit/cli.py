from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .authorize import findings_from, parse_role, run_authorize
from .crawl.spider import Spider
from .fuzz.dirbuster import fuzz
from .http.client import HttpClient
from .http.models import HttpRequest
from .openapi import load_spec, spec_pages
from .paramminer import mine
from .proxy.server import ProxyServer
from .recon import missing_tools, render_report, run_recon
from .report.writer import write_console, write_html, write_json
from .scan.engine import ScanEngine
from .toolkit import decode_text, encode_text
from .updates import fetch_latest_version, install_tools, is_outdated, self_update

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
        description="Summit - open-source web security testing platform (proxy, scanner, fuzzer, link hijack detection).",
    )
    parser.add_argument("--version", action="version", version=f"summit {__version__}")
    parser.add_argument("--check-update", action="store_true", help="compare the installed version against the latest GitHub release")
    parser.add_argument("--auto-update", action="store_true", help="update summit in place (git checkout) or print exact install steps")
    parser.add_argument("--install-tools", action="store_true", help="install recon tools (nmap, httpx, subfinder) via the available package manager")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="crawl a target and run passive + active checks")
    scan.add_argument("url", help="target URL, e.g. https://testsite.local")
    scan.add_argument("--openapi", dest="openapi_path", help="scan an OpenAPI/JSON spec instead of crawling (paths become targets)")
    scan.add_argument("--depth", type=int, default=3, help="max crawl depth (default 3)")
    scan.add_argument("--max-pages", type=int, default=50, help="max pages to visit (default 50)")
    scan.add_argument("--no-active", action="store_true", help="skip active checks (passive only)")
    scan.add_argument("--skip-linkcheck", action="store_true", help="skip broken link / hijack check")
    scan.add_argument("--workers", type=int, default=8, help="parallel check workers (default 8)")
    scan.add_argument("--rate", type=float, default=None, help="max requests per second across all workers, e.g. --rate 5")
    scan.add_argument("--retries", type=int, default=1, help="retries on connection errors and 429/503 (default 1)")
    scan.add_argument("--delay", type=float, default=0.0, help="seconds between requests (be nice)")
    scan.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
    scan.add_argument("--json", dest="json_path", help="write a JSON report to this path")
    scan.add_argument("--html", dest="html_path", help="write an HTML report to this path")

    mine_p = sub.add_parser("mine", help="discover hidden parameters on one URL (Param Miner approach)")
    mine_p.add_argument("url")
    mine_p.add_argument("--workers", type=int, default=8)
    mine_p.add_argument("--timeout", type=float, default=10.0)
    mine_p.add_argument("--json", dest="json_path", help="write findings as JSON")

    auth = sub.add_parser("authorize", help="compare two roles per URL - broken access control (Autorize workflow)")
    auth.add_argument("urls", nargs="+", help="URLs to test (test each with both roles)")
    auth.add_argument("--role", dest="roles", action="append", required=True,
                      help="role spec 'name=Header: value', repeatable; first role = privileged baseline, e.g. --role 'admin=Cookie: session=abc'")
    auth.add_argument("--timeout", type=float, default=10.0)
    auth.add_argument("--json", dest="json_path", help="write findings as JSON")

    fuzz_p = sub.add_parser("fuzz", help="brute-force paths on a target")
    fuzz_p.add_argument("url")
    fuzz_p.add_argument("-w", "--wordlist", help="wordlist file, one entry per line")
    fuzz_p.add_argument("-t", "--threads", type=int, default=10, help="concurrent requests (default 10)")
    fuzz_p.add_argument("-e", "--extensions", default="", help="comma separated, e.g. php,html,bak")
    fuzz_p.add_argument("--rate", type=float, default=None, help="max requests per second")
    fuzz_p.add_argument("--timeout", type=float, default=10.0)

    proxy_p = sub.add_parser("proxy", help="run the local intercepting proxy")
    proxy_p.add_argument("--bind", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8080)
    proxy_p.add_argument("--db", default="summit_sitemap.db", help="sqlite site map path")

    rep = sub.add_parser("repeater", help="send a raw HTTP request from a file (Burp-style)")
    rep.add_argument("file")
    rep.add_argument("--timeout", type=float, default=10.0)

    rec = sub.add_parser("recon", help="chain subfinder -> httpx -> nmap on a target")
    rec.add_argument("target", help="domain or URL, e.g. testsite.local")
    rec.add_argument("--timeout", type=float, default=120.0, help="per-tool timeout in seconds")
    rec.add_argument("--json", dest="json_path", help="write the recon report as JSON")

    enc = sub.add_parser("encode", help="encode text (b64, url, hex)")
    enc.add_argument("value")
    enc.add_argument("-f", "--format", dest="encoding", default="b64", choices=["b64", "url", "hex"])

    dec = sub.add_parser("decode", help="decode text (b64, url, hex, jwt)")
    dec.add_argument("value")
    dec.add_argument("-f", "--format", dest="encoding", default="b64", choices=["b64", "url", "hex", "jwt"])

    return parser


def _cmd_check_update() -> int:
    print(BANNER.format(version=__version__))
    latest = fetch_latest_version()
    if latest is None:
        print("[!] could not reach the GitHub release API (offline or rate-limited)")
        return 1
    if is_outdated(__version__, latest):
        print(f"[*] update available: {__version__} -> {latest}")
        print("[*] run: summit --auto-update")
    else:
        print(f"[*] summit {__version__} is up to date (latest release: {latest})")
    return 0


def _cmd_auto_update() -> int:
    print(BANNER.format(version=__version__))
    ok, message = self_update()
    print(f"[*] {message}" if ok else f"[!] {message}")
    return 0 if ok else 1


def _cmd_install_tools() -> int:
    print(BANNER.format(version=__version__))
    install_tools()
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    print(BANNER.format(version=__version__))
    client = HttpClient(timeout=args.timeout, delay=args.delay, rate=args.rate, retries=args.retries)
    if args.openapi_path:
        spec = load_spec(args.openapi_path)
        result = spec_pages(client, spec)
        print(f"[*] openapi spec loaded: {len(result['pages'])} target(s), {len(result['errors'])} error(s)")
    else:
        spider = Spider(client, max_depth=args.depth, max_pages=args.max_pages, delay=args.delay)
        print(f"[*] crawling {args.url} ...")
        result = spider.crawl(args.url)
        print(
            f"[*] visited {len(result['visited'])} page(s), "
            f"{len(result['forms'])} form(s), {len(result['external_links'])} outbound link(s), "
            f"{len(result['errors'])} request error(s)"
        )
    for error in result["errors"][:5]:
        print(f"[!] {error}")

    engine = ScanEngine(
        client,
        active=not args.no_active,
        workers=args.workers,
        linkcheck_enabled=not args.skip_linkcheck,
    )
    findings = engine.scan(result)
    print(
        f"[*] {client.request_count} request(s) in {engine.elapsed:.1f}s "
        f"(workers={args.workers}, rate={args.rate or 'unlimited'}, retries={args.retries})"
    )
    print(f"[*] smart order: {engine.high_signal} high-signal injection point(s) probed first")
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
    client = HttpClient(timeout=args.timeout, rate=args.rate)
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
    client = HttpClient(timeout=args.timeout)
    print(f"[*] sending {request.method} {request.url}")
    response = client.send(request)
    print(f"HTTP {response.status} ({response.elapsed:.2f}s)")
    for key, value in response.headers.items():
        print(f"{key}: {value}")
    print()
    print(response.text[:5000])
    return 0


def _cmd_mine(args: argparse.Namespace) -> int:
    print(BANNER.format(version=__version__))
    client = HttpClient(timeout=args.timeout)
    print(f"[*] mining hidden parameters on {args.url} ...")
    findings = mine(client, args.url, workers=args.workers)
    print(write_console(findings, args.url))
    if args.json_path:
        write_json(findings, args.json_path)
        print(f"[*] JSON report written to {args.json_path}")
    return 0


def _cmd_authorize(args: argparse.Namespace) -> int:
    print(BANNER.format(version=__version__))
    client = HttpClient(timeout=args.timeout)
    try:
        roles = [parse_role(spec) for spec in args.roles]
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    if len(roles) < 2:
        print("[!] authorize needs at least two roles - first is the privileged baseline")
        return 1
    privileged, other = roles[0], roles[1]
    print(f"[*] testing {len(args.urls)} URL(s): '{privileged.name}' vs '{other.name}'")
    results = run_authorize(client, args.urls, privileged, other)
    for result in results:
        print(f"  [{result.verdict.upper()}] {result.url}")
        if result.verdict == "broken":
            print(f"      {other.name} sees exactly what {privileged.name} sees (HTTP {result.privileged.status}, {len(result.privileged.body)}B)")
    findings = findings_from(results)
    print(write_console(findings, f"{len(args.urls)} URL(s), {privileged.name} vs {other.name}"))
    if args.json_path:
        write_json(findings, args.json_path)
        print(f"[*] JSON report written to {args.json_path}")
    return 0


def _cmd_recon(args: argparse.Namespace) -> int:
    print(BANNER.format(version=__version__))
    missing = missing_tools()
    if missing:
        print(f"[!] tools not on PATH: {', '.join(missing)} - install them with: summit --install-tools")
        print("[*] continuing with the tools that ARE available ...\n")
    try:
        report = run_recon(args.target, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] recon failed: {exc}")
        return 1
    print(render_report(report))
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[*] JSON report written to {args.json_path}")
    return 0


def _cmd_encode(args: argparse.Namespace) -> int:
    try:
        print(encode_text(args.value, args.encoding))
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    try:
        print(decode_text(args.value, args.encoding))
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.check_update:
            return _cmd_check_update()
        if args.auto_update:
            return _cmd_auto_update()
        if args.install_tools:
            return _cmd_install_tools()
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "fuzz":
            return _cmd_fuzz(args)
        if args.command == "proxy":
            return _cmd_proxy(args)
        if args.command == "repeater":
            return _cmd_repeater(args)
        if args.command == "mine":
            return _cmd_mine(args)
        if args.command == "authorize":
            return _cmd_authorize(args)
        if args.command == "recon":
            return _cmd_recon(args)
        if args.command == "encode":
            return _cmd_encode(args)
        if args.command == "decode":
            return _cmd_decode(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        return 130
    print(f"summit {__version__}")
    parser.print_help()
    return 0
