# Installation

## From source (recommended)

```bash
git clone https://github.com/pennacle-security/summit.git
cd summit
pip install -e .
```

Python 3.10 or newer. The only hard dependency is `requests` - every DNS, threading and parsing feature is stdlib.

## Verify the install

```bash
summit --version
pytest -q                       # 45 tests
python examples/evidence.py     # 11/11 claims should pass
```

## Optional recon tools

`summit recon` chains external tools when they are on your PATH. Install them any way you like, or let summit try:

```bash
summit --install-tools
```

- [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) ship as Go binaries (`go install ...` commands are printed if go is unavailable)
- [nmap](https://nmap.org) comes from your platform package manager (winget/choco on Windows, apt/dnf/pacman on Linux, brew on macOS)

Missing tools never crash a recon run - they are listed with exact install commands instead.

## Updating

```bash
summit --check-update   # compares your version against the latest release
summit --auto-update    # git pull when running from a checkout
```

Versions are compared numerically, so 0.3 < 0.10 the way you expect.
