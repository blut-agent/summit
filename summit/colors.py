"""Terminal UI toolkit - color, layout and identity for the summit CLI.

Everything visual lives here so the rest of the codebase never has to
think about ANSI codes. Three rules shape this module:

- Colour is opt-out, never opt-in by accident: NO_COLOR, TERM=dumb and
  non-TTY output all degrade to plain text. Windows gets VT processing
  switched on explicitly so ANSI works on 10+ without a wrapper.
- True colour when the terminal admits it (`COLORTERM=truecolor`),
  xterm-256 as the middle ground, plain 16-colour ANSI otherwise.
- The helpers return strings, they never print. Callers decide where
  output goes, which keeps the functions testable and pipe-safe.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# terminal capability detection
# ---------------------------------------------------------------------------

RESET = "\033[0m"


def enable_windows_ansi() -> None:
    """Turn on VT sequence processing for classic Windows consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        # A terminal that refuses ANSI simply gets no colour below.
        pass


def _stream_supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") not in (None, "", "0"):
        return True
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _detect_truecolor() -> bool:
    colorterm = os.environ.get("COLORTERM", "").lower()
    return colorterm in ("truecolor", "24bit") or os.environ.get("TERM_PROGRAM") in (
        "iTerm.app",
        "WezTerm",
        "vscode",
    )


enable_windows_ansi()

_enabled = _stream_supports_color(sys.stdout)
_truecolor = _detect_truecolor()


def set_enabled(value: bool) -> None:
    """Force colour on/off (used by --no-color and inside tests)."""
    global _enabled
    _enabled = bool(value)


def enabled() -> bool:
    return _enabled


def set_truecolor(value: bool) -> None:
    global _truecolor
    _truecolor = bool(value)


# ---------------------------------------------------------------------------
# palette
# ---------------------------------------------------------------------------

# RGB triplets used for gradients and true-colour accents.
RGB = {
    "aurora_green": (74, 222, 128),
    "aurora_cyan": (34, 211, 238),
    "aurora_blue": (59, 130, 246),
    "aurora_violet": (167, 139, 250),
    "aurora_pink": (244, 114, 182),
    "summit_gold": (250, 204, 21),
    "ember": (251, 146, 60),
    "crimson": (248, 113, 113),
    "slate": (148, 163, 184),
    "fog": (203, 213, 225),
    "ink": (15, 23, 42),
}

# 16-colour fallbacks keyed by semantic name.
_CODES = {
    "black": "30",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "gray": "90",
    "bright_red": "91",
    "bright_green": "92",
    "bright_yellow": "93",
    "bright_blue": "94",
    "bright_magenta": "95",
    "bright_cyan": "96",
    "bright_white": "97",
}

# severity -> (16-colour name, RGB)
SEVERITY_STYLE = {
    "critical": ("bright_red", RGB["crimson"]),
    "high": ("bright_yellow", RGB["ember"]),
    "medium": ("bright_magenta", RGB["aurora_pink"]),
    "low": ("bright_green", RGB["aurora_green"]),
    "info": ("cyan", RGB["aurora_cyan"]),
}

PHASE_STYLE = {
    "INIT": ("cyan", RGB["aurora_cyan"]),
    "RECON": ("bright_blue", RGB["aurora_blue"]),
    "FINGERPRINT": ("bright_magenta", RGB["aurora_violet"]),
    "SCAN": ("bright_cyan", RGB["aurora_cyan"]),
    "ACTIVE": ("bright_yellow", RGB["summit_gold"]),
    "TEMPLATES": ("bright_magenta", RGB["aurora_violet"]),
    "REPORT": ("bright_green", RGB["aurora_green"]),
    "DONE": ("bright_green", RGB["aurora_green"]),
    "WARN": ("bright_yellow", RGB["summit_gold"]),
    "ERROR": ("bright_red", RGB["crimson"]),
}


def _ansi(code: str) -> str:
    return f"\033[{code}m"


def _fg_16(name: str) -> str:
    return _ansi(_CODES.get(name, "37"))


def _fg_rgb(rgb: tuple[int, int, int]) -> str:
    return _ansi(f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}")


def _fg_256(rgb: tuple[int, int, int]) -> str:
    # Map an RGB triplet onto the xterm-256 cube when true colour is absent.
    r, g, b = (channel // 51 for channel in rgb)
    index = 16 + (36 * r) + (6 * g) + b
    return _ansi(f"38;5;{index}")


def _paint(
    text: str,
    color: str | tuple[int, int, int] | None,
    *,
    bold: bool = False,
    dim: bool = False,
    italic: bool = False,
    underline: bool = False,
) -> str:
    if not _enabled or not text:
        return text
    prefix = ""
    if bold:
        prefix += _ansi("1")
    if dim:
        prefix += _ansi("2")
    if italic:
        prefix += _ansi("3")
    if underline:
        prefix += _ansi("4")
    if color:
        if isinstance(color, tuple):
            prefix += _fg_rgb(color) if _truecolor else _fg_256(color)
        else:
            prefix += _fg_16(color)
    return f"{prefix}{text}{RESET}"


# ---------------------------------------------------------------------------
# basic styles
# ---------------------------------------------------------------------------


def style(
    text: str,
    color: str | tuple[int, int, int] | None = None,
    *,
    bold: bool = False,
    dim: bool = False,
    italic: bool = False,
    underline: bool = False,
) -> str:
    return _paint(text, color, bold=bold, dim=dim, italic=italic, underline=underline)


def bold(text: str) -> str:
    return _paint(text, None, bold=True)


def dim_text(text: str) -> str:
    return _paint(text, None, dim=True)


def red(text: str) -> str:
    return _paint(text, "bright_red")


def green(text: str) -> str:
    return _paint(text, "bright_green")


def yellow(text: str) -> str:
    return _paint(text, "bright_yellow")


def blue(text: str) -> str:
    return _paint(text, "bright_blue")


def magenta(text: str) -> str:
    return _paint(text, "bright_magenta")


def cyan(text: str) -> str:
    return _paint(text, "bright_cyan")


def white(text: str) -> str:
    return _paint(text, "white")


def gray(text: str) -> str:
    return _paint(text, "gray")


def gold(text: str) -> str:
    return _paint(text, "bright_yellow", bold=True)


# ---------------------------------------------------------------------------
# semantic helpers
# ---------------------------------------------------------------------------


def severity_color(severity: str) -> str:
    name = SEVERITY_STYLE.get(severity.lower(), ("white", RGB["fog"]))[0]
    return name


def _bg_16(name: str) -> str:
    # Background codes are the foreground codes + 10
    # (30-37 -> 40-47, 90-97 -> 100-107).
    code = int(_CODES.get(name, "37"))
    return _ansi(str(code + 10))


def severity_badge(severity: str, *, width: int = 0) -> str:
    """A filled, readable badge: `` CRITICAL `` in the severity colour."""
    label = severity.upper()
    if width:
        label = label.center(width)
    name, rgb = SEVERITY_STYLE.get(severity.lower(), ("white", RGB["fog"]))
    if not _enabled:
        return f"[{label.strip()}]"
    if _truecolor:
        bg_code = _fg_rgb(rgb).replace("\033[38;", "\033[48;")
    else:
        bg_code = _bg_16(name)
    # Colour background + black text reads well on every severity colour.
    return f"{bg_code}{_ansi('30')}{_ansi('1')} {label} {RESET}"


def confidence_tag(confidence: str) -> str:
    mapping = {
        "confirmed": ("bright_green", RGB["aurora_green"]),
        "likely": ("bright_yellow", RGB["summit_gold"]),
        "needs-manual": ("bright_magenta", RGB["aurora_pink"]),
        "info": ("gray", RGB["slate"]),
    }
    name, rgb = mapping.get(confidence, ("white", RGB["fog"]))
    return _paint(confidence, rgb if _truecolor else name, dim=True)


def phase_tag(phase: str) -> str:
    name, rgb = PHASE_STYLE.get(phase.upper(), ("cyan", RGB["aurora_cyan"]))
    tag = _paint(f"▸ {phase.upper()}", rgb if _truecolor else name, bold=True)
    return f"{gray('│')} {tag}"


def check_tag(check_id: str) -> str:
    return _paint(check_id, RGB["slate"] if _truecolor else "gray", dim=True)


def url_text(url: str) -> str:
    return _paint(url, RGB["aurora_blue"] if _truecolor else "bright_blue", underline=True)


def evidence_text(value: str) -> str:
    return _paint(f"`{value}`", RGB["summit_gold"] if _truecolor else "bright_yellow")


def ok(text: str) -> str:
    return f"{_paint('✔', RGB['aurora_green'] if _truecolor else 'bright_green', bold=True)} {text}"


def warn(text: str) -> str:
    return f"{_paint('▲', RGB['summit_gold'] if _truecolor else 'bright_yellow', bold=True)} {text}"


def fail(text: str) -> str:
    return f"{_paint('✖', RGB['crimson'] if _truecolor else 'bright_red', bold=True)} {text}"


def bullet(text: str) -> str:
    return f"{gray('•')} {text}"


# ---------------------------------------------------------------------------
# gradients & decoration
# ---------------------------------------------------------------------------


def _lerp(start: tuple[int, int, int], end: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (
        round(start[0] + (end[0] - start[0]) * t),
        round(start[1] + (end[1] - start[1]) * t),
        round(start[2] + (end[2] - start[2]) * t),
    )


def gradient(
    text: str,
    start: tuple[int, int, int] = RGB["aurora_cyan"],
    end: tuple[int, int, int] = RGB["aurora_pink"],
) -> str:
    """Character-by-character gradient. Falls back to a solid accent."""
    if not _enabled:
        return text
    if not _truecolor:
        return _paint(text, "bright_cyan", bold=True)
    if not text:
        return text
    span = max(len(text) - 1, 1)
    out = []
    for index, char in enumerate(text):
        if char == " ":
            out.append(char)
            continue
        color = _lerp(start, end, index / span)
        out.append(f"{_fg_rgb(color)}{char}")
    return "".join(out) + RESET


def rule(width: int = 68, char: str = "─", color: str | tuple[int, int, int] = RGB["aurora_blue"]) -> str:
    return _paint(char * width, color if _truecolor else "blue", dim=True)


def header(text: str, width: int = 68) -> str:
    """`── title ─────────────` used between scan phases."""
    title = f" {text} "
    if len(title) >= width:
        return _paint(title, RGB["fog"] if _truecolor else "white", bold=True)
    left = 2
    right = width - left - len(title) - 2
    line = "─" * left + title + "─" * max(right, 0)
    return _paint(line, RGB["aurora_blue"] if _truecolor else "blue", dim=True)


def box(title: str, lines: list[str], width: int = 68, color: tuple[int, int, int] = RGB["aurora_cyan"]) -> str:
    """A rounded box with a title. Lines may already carry ANSI colour."""
    if not _enabled:
        out = [f"+- {title} " + "-" * max(width - len(title) - 6, 0) + "+"]
        out += [f"| {line}" for line in lines]
        out.append("+" + "-" * (width - 2) + "+")
        return "\n".join(out)

    accent = _fg_rgb(color) if _truecolor else _fg_16("bright_cyan")
    reset = RESET
    top = f"{accent}╭─ {title} " + "─" * max(width - len(title) - 5, 0) + f"╮{reset}"
    body = [f"{accent}│{reset} {line}" for line in lines]
    bottom = f"{accent}╰" + "─" * (width - 2) + f"╯{reset}"
    return "\n".join([top, *body, bottom])


def kv_table(rows: list[tuple[str, str]], *, separator: str = "  ", color: tuple[int, int, int] = RGB["slate"]) -> str:
    if not rows:
        return ""
    width = max(len(key) for key, _ in rows)
    key_color = color if _truecolor else "gray"
    return "\n".join(f"{_paint(key.ljust(width), key_color)} {gray(separator.strip())} {value}" for key, value in rows)


def summary_bar(counts: dict[str, int], *, width: int = 44) -> str:
    """A compact severity histogram: coloured blocks plus counts."""
    total = sum(counts.get(severity, 0) for severity in SEVERITY_STYLE)
    if total == 0:
        return gray("no findings")
    segments = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts.get(severity, 0)
        if not count:
            continue
        blocks = max(1, round(width * count / total))
        segments.append(_paint("█" * blocks, SEVERITY_STYLE[severity][1] if _truecolor else SEVERITY_STYLE[severity][0]))
    legend = " ".join(
        f"{severity_badge(severity)} {counts.get(severity, 0)}"
        for severity in ("critical", "high", "medium", "low", "info")
        if counts.get(severity, 0)
    )
    return "".join(segments) + "\n" + legend


def strip_ansi(text: str) -> str:
    """Remove ANSI sequences (tests and log files)."""
    import re

    return re.sub(r"\033\[[0-9;]*m", "", text)


@dataclass(frozen=True)
class Glyphs:
    """Unicode glyph set with ASCII fallback for limited terminals."""

    arrow: str = "▸"
    dot: str = "•"
    check: str = "✔"
    cross: str = "✖"
    warning: str = "▲"
    bar: str = "│"
    rule: str = "─"
    spark: str = "◆"


GLYPHS = Glyphs()
