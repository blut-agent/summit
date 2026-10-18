"""Colored CLI output helpers.

Uses ANSI escape codes for severity-tagged colored output. Falls back
to plain text when the output is not a TTY (e.g., piped to a file).
"""

from __future__ import annotations

import sys

# ANSI codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
}

_SEVERITY_COLORS = {
    "critical": "bright_red",
    "high": "bright_yellow",
    "medium": "bright_magenta",
    "low": "bright_green",
    "info": "white",
}

_STATUS_COLORS = {
    "RECON": "bright_blue",
    "SCAN": "bright_cyan",
    "DONE": "bright_green",
    "FINGERPRINT": "bright_magenta",
}

_is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _colorize(text: str, color: str) -> str:
    if not _is_tty:
        return text
    code = _COLORS.get(color, "")
    return f"{code}{text}{_RESET}" if code else text


def color_severity(severity: str) -> str:
    return _colorize(severity.upper(), _SEVERITY_COLORS.get(severity, "white"))


def color_phase(phase: str) -> str:
    return _colorize(f"[{phase}]", _STATUS_COLORS.get(phase, "cyan"))


def color_finding_title(title: str, severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "white")
    return _colorize(title, color)


def color_url(url: str) -> str:
    return _colorize(url, "blue")


def color_evidence(text: str) -> str:
    return _colorize(text, "white")


def color_progress(text: str) -> str:
    return _colorize(text, "bright_green")


def color_warning(text: str) -> str:
    return _colorize(text, "bright_yellow")


def color_error(text: str) -> str:
    return _colorize(text, "bright_red")
