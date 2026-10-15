"""Version checking, self-update, and recon tool installation.

`--check-update` compares the installed version against the latest GitHub
release (public API, no token, no telemetry). `--auto-update` pulls the
newest main when summit runs from a git checkout and says exactly what to
do otherwise - it never installs code from anywhere but the repository.
`--install-tools` is a best-effort installer for the recon integrations;
whatever it cannot install automatically, it prints the exact command for.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import requests

from .recon import TOOLS

RELEASES_API = "https://api.github.com/repos/pennacle-security/summit/releases/latest"

# Tool name -> install spec per channel. Keep these current; they are printed
# verbatim when automatic installation is not possible.
_GO_PACKAGES = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
}
_WINGET_IDS = {"nmap": "Insecure.Nmap"}
_PACKAGE_MANAGER_COMMANDS = {
    "apt": {"nmap": "sudo apt install -y nmap"},
    "dnf": {"nmap": "sudo dnf install -y nmap"},
    "pacman": {"nmap": "sudo pacman -S nmap"},
    "brew": {"nmap": "brew install nmap"},
    "choco": {"nmap": "choco install nmap -y"},
    "winget": {"nmap": "winget install --id Insecure.Nmap"},
}


def fetch_latest_version(timeout: float = 10.0) -> str | None:
    """Return the latest release version as 'X.Y.Z', or None when unreachable."""
    try:
        response = requests.get(RELEASES_API, timeout=timeout, headers={"Accept": "application/vnd.github+json"})
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    match = re.match(r"v?(\d+\.\d+\.\d+)$", response.json().get("tag_name", ""))
    return match.group(1) if match else None


def is_outdated(local: str, latest: str) -> bool:
    def parts(version: str) -> tuple[int, ...]:
        return tuple(int(piece) for piece in version.split("."))

    return parts(local) < parts(latest)


def install_root() -> Path:
    """Directory that contains the summit package (the repo root on a checkout)."""
    return Path(__file__).resolve().parent.parent


def in_git_checkout() -> bool:
    return (install_root() / ".git").exists()


def self_update() -> tuple[bool, str]:
    """git pull when running from a checkout; instructions otherwise."""
    if not in_git_checkout():
        return False, (
            "summit was not installed from a git checkout, so it cannot self-update. "
            "Re-run the installer: git clone https://github.com/pennacle-security/summit.git "
            "&& cd summit && pip install -e ."
        )
    try:
        result = subprocess.run(
            ["git", "-C", str(install_root()), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"git pull failed: {exc}"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "git pull failed").strip()
    return True, (result.stdout or "already up to date").strip()


def _run_quiet(cmd: list[str], timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def install_tools() -> None:
    """Best-effort install of nmap / httpx / subfinder. Nothing is silent:
    each tool ends up either installed or with the exact command printed."""
    for name in TOOLS:
        where = shutil.which(name)
        if where:
            print(f"[*] {name}: already installed ({where})")
            continue

        installed = False

        # subfinder and httpx ship as Go binaries - the projectdiscovery way.
        if name in _GO_PACKAGES and shutil.which("go"):
            print(f"[*] installing {name} via go install (this can take a minute) ...")
            try:
                result = _run_quiet(["go", "install", "-v", _GO_PACKAGES[name]])
                installed = result.returncode == 0 and shutil.which(name) is not None
                if not installed and result.stderr.strip():
                    print(f"    go said: {result.stderr.strip().splitlines()[-1]}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"    go install failed: {exc}")
        elif name in _GO_PACKAGES:
            print(f"[!] {name}: install with -> go install {_GO_PACKAGES[name]}")

        # nmap comes from the platform package manager.
        if name == "nmap" and not installed:
            for manager, packages in _PACKAGE_MANAGER_COMMANDS.items():
                if not shutil.which(manager):
                    continue
                if sys.platform == "win32" and manager == "winget":
                    print("[*] installing nmap via winget ...")
                    try:
                        result = _run_quiet([
                            manager, "install", "--id", _WINGET_IDS["nmap"],
                            "--accept-source-agreements", "--accept-package-agreements", "--silent",
                        ])
                        installed = result.returncode == 0
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        print(f"    winget failed: {exc}")
                else:
                    print(f"[*] trying: {packages['nmap']}")
                    try:
                        if manager == "choco":
                            command = manager.split() + ["install", "-y", "nmap"]
                        elif manager == "apt":
                            command = ["sudo", "-n"] + packages["nmap"].split()
                        else:
                            command = packages["nmap"].split()
                        result = _run_quiet(command)
                        installed = result.returncode == 0
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        print(f"    {manager} failed: {exc}")
                if installed:
                    break

        if installed and shutil.which(name):
            print(f"[*] {name}: installed -> {shutil.which(name)}")
        elif name == "nmap":
            print("[!] nmap: install it with e.g. winget install --id Insecure.Nmap (Windows) or sudo apt install -y nmap (Linux)")
        # Go-tool hints were already printed above when go was unavailable.
