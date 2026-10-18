"""ASCII identity for summit - detailed mountain art with a gradient.

The banner is deliberately hand-drawn instead of generated: block
characters render identically in every modern terminal, the wordmark
stays readable when colours are stripped, and the whole thing fits in
76 columns. Two variants exist:

- full: mountain range + SUMMIT wordmark + version line, for interactive
  scans and `summit setup`
- compact: one line, for subcommands and CI logs
"""

from __future__ import annotations

from . import colors

_MOUNTAIN = [
    "                            ▂▄▆█▆▄▂",
    "                       ▂▄▆██████████▆▄▂",
    "                   ▂▄▆██████████████████▆▄▂",
    "               ▂▄▆██████████████████████████▆▄▂",
    "           ▂▄▆██████████████████████████████████▆▄▂",
    "       ▂▄▆██████████████████████████████████████████▆▄▂",
    "   ▂▄▆██████████████████████████████████████████████████▆▄▂",
    "▄██████████████████████████████████████████████████████████████▄",
]

_WORDMARK = [
    "███████╗██╗   ██╗███╗   ███╗███╗   ███╗██╗████████╗",
    "██╔════╝██║   ██║████╗ ████║████╗ ████║██║╚══██╔══╝",
    "███████╗██║   ██║██╔████╔██║██╔████╔██║██║   ██║   ",
    "╚════██║██║   ██║██║╚██╔╝██║██║╚██╔╝██║██║   ██║   ",
    "███████║╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║   ██║   ",
    "╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝   ╚═╝   ",
]

_TAGLINE = "web security platform · scanner · proxy · fuzzer · oob"


def render_banner(version: str, *, compact: bool = False) -> str:
    """Return the banner as a string; colour follows terminal capability."""
    if compact:
        mark = colors.gradient("▲ SUMMIT", colors.RGB["aurora_cyan"], colors.RGB["aurora_pink"])
        version_tag = colors.gray(f"v{version}")
        byline = colors.gray("pennacle security")
        return f"{mark} {version_tag} {colors.gray('·')} {byline}"

    lines: list[str] = [""]
    # Cool-to-warm gradient down the mountain: snow at the top, ember base.
    top = colors.RGB["aurora_cyan"]
    bottom = colors.RGB["aurora_violet"]
    for index, row in enumerate(_MOUNTAIN):
        lines.append(colors.gradient(row, top, bottom))
    lines.append("")
    for row in _WORDMARK:
        lines.append(colors.gradient(row, colors.RGB["aurora_cyan"], colors.RGB["aurora_pink"]))
    lines.append("")
    tagline = colors.gradient(_TAGLINE, colors.RGB["aurora_green"], colors.RGB["aurora_cyan"])
    version_tag = colors.gold(f"v{version}")
    byline = colors.gray("by Pennacle Security")
    lines.append(f"  {tagline}")
    lines.append(f"  {version_tag}  {colors.gray('·')}  {byline}  {colors.gray('·')}  {colors.warn('authorized testing only')}")
    lines.append(colors.rule(66))
    lines.append("")
    return "\n".join(lines)


def print_banner(version: str, *, compact: bool = False, silent: bool = False) -> None:
    if not silent:
        print(render_banner(version, compact=compact))
