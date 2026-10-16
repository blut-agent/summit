"""Recon orchestration - wraps the tools you already trust.

If subfinder, httpx and nmap are on PATH, `summit recon` chains them:
subdomains -> live hosts -> open ports, then prints one report. Tools that
are missing are listed with exact install commands (`--install-tools`
attempts the install). Summit only *orchestrates* here; every finding
still comes from the named tool's own output, parsed defensively.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from urllib.parse import urlsplit

TOOLS = ("subfinder", "httpx", "nmap")


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def missing_tools() -> list[str]:
    return [name for name in TOOLS if find_tool(name) is None]


def _run(cmd: list[str], timeout: float, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)


def _hostname(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    return urlsplit(target).hostname or target


def enumerate_subdomains(domain: str, timeout: float) -> list[str] | None:
    exe = find_tool("subfinder")
    if exe is None:
        return None
    result = _run([exe, "-d", domain, "-silent"], timeout)
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def probe_hosts(hosts: list[str], timeout: float) -> list[dict] | None:
    exe = find_tool("httpx")
    if exe is None:
        return None
    # Passive DNS sources return thousands of entries on common domains;
    # probing them all would run for hours. A cap keeps recon useful and fast.
    capped = hosts[:101]
    result = _run([exe, "-silent", "-status-code", "-no-color", "-timeout", "10"], timeout, stdin="\n".join(capped))
    alive: list[dict] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(.*?)\s*\[(\d{3})\]", line.strip())
        if match:
            alive.append({"url": match.group(1).strip(), "status": int(match.group(2))})
    return alive


def scan_ports(host: str, timeout: float) -> list[dict] | None:
    exe = find_tool("nmap")
    if exe is None:
        return None
    result = _run([exe, "-Pn", "--top-ports", "100", "-T4", "--open", host], timeout)
    ports: list[dict] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line.strip())
        if match:
            ports.append({"port": int(match.group(1)), "service": match.group(2)})
    if not ports and result.returncode != 0:
        # nmap crashed or could not run (missing Npcap, no privileges, ...).
        # Saying "no open ports" here would be a lie.
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(f"nmap exited with code {result.returncode}" + (f": {detail[-1]}" if detail else ""))
    return ports


def run_recon(target: str, timeout: float = 120.0) -> dict:
    domain = _hostname(target)
    report: dict = {"target": domain, "subdomains": [], "alive": [], "open_ports": {}, "missing_tools": [], "notes": []}

    try:
        subs = enumerate_subdomains(domain, timeout)
    except subprocess.TimeoutExpired:
        subs = []
        report["notes"].append("subfinder hit its timeout - results may be partial")
    if subs is None:
        report["missing_tools"].append("subfinder")
    else:
        report["subdomains"] = subs[:500]

    hosts = [domain] + [s for s in subs if s != domain]
    try:
        alive = probe_hosts(hosts, timeout)
    except subprocess.TimeoutExpired:
        alive = []
        report["notes"].append("httpx hit its timeout - showing the hosts it finished")
    if alive is None:
        report["missing_tools"].append("httpx")
        return report
    report["alive"] = alive

    nmap_missing = False
    for entry in alive[:10]:  # cap port scans so the report stays quick
        host = _hostname(entry["url"])
        try:
            ports = scan_ports(host, timeout)
        except subprocess.TimeoutExpired:
            report["notes"].append(f"nmap timed out for {host}")
            continue
        except RuntimeError as exc:
            report["notes"].append(f"nmap failed for {host} - {exc}")
            nmap_missing = True
            continue
        if ports is None:
            nmap_missing = True
            continue
        report["open_ports"][host] = ports
    if nmap_missing and "nmap" not in report["missing_tools"]:
        report["missing_tools"].append("nmap")
    return report


def render_report(report: dict) -> str:
    lines = [f"recon report - {report['target']}", "=" * 60]
    if report["missing_tools"]:
        lines.append(f"[!] tools not on PATH: {', '.join(report['missing_tools'])} (run summit --install-tools)")
    for note in report.get("notes", []):
        lines.append(f"[!] {note}")
    lines.append(f"subdomains ({len(report['subdomains'])}):")
    lines.extend(f"  - {sub}" for sub in report["subdomains"][:25] or ["  (none found)"])
    if len(report["subdomains"]) > 25:
        lines.append(f"  ... and {len(report['subdomains']) - 25} more")
    lines.append(f"alive hosts ({len(report['alive'])}):")
    lines.extend(f"  - {entry['url']} [{entry['status']}]" for entry in report["alive"][:50] or ["  (none)"])
    if report["open_ports"]:
        lines.append("open ports (top 100):")
        for host, ports in report["open_ports"].items():
            rendered = ", ".join(f"{p['port']}/tcp {p['service']}" for p in ports) or "(none open)"
            lines.append(f"  - {host}: {rendered}")
    return "\n".join(lines)
