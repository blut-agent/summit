# Cross-platform binary releases

Summit ships pre-built binaries for three platforms on every GitHub release. The build workflow (`build-binaries.yml`) uses PyInstaller to produce standalone executables that require no Python installation.

## Supported platforms

| Platform | Binary name | Runtime |
|---|---|---|
| Linux amd64 | `summit-linux-amd64` | Any glibc 2.31+ system |
| Linux arm64 | `summit-linux-arm64` | AWS Graviton, Raspberry Pi 4+, Apple Silicon (via Rosetta) |
| Windows amd64 | `summit-windows-amd64.exe` | Windows 10+ |

## Building locally

```bash
pip install pyinstaller
pyinstaller --onefile --name summit \
  --hidden-import=summit.scan.modules \
  --hidden-import=summit.report \
  summit/cli.py
```

The binary is self-contained: all Python code, the `requests` library, and all check modules are bundled. No virtual environment, no `pip install`, no Python version management.

## Version compatibility

The Python source requires 3.10+. The pre-built binaries bundle Python 3.12 internally and run on:

- **Linux**: glibc 2.31+ (Ubuntu 20.04+, Debian 11+, RHEL 8+, Alpine with glibc)
- **Windows**: Windows 10 build 1709+ (including Windows Server 2019+)
- **macOS**: Not currently built (use `pip install -e .` instead)

## ARM64 notes

The linux-arm64 binary is built on `ubuntu-24.04-arm` runners and targets the ARMv8-A architecture (aarch64). It runs on:

- AWS Graviton / Graviton2 / Graviton3
- Oracle Cloud Ampere A1
- Raspberry Pi 4 and 5 (64-bit OS)
- Apple Silicon Macs via Docker or Rosetta
