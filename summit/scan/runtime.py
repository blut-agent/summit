"""Scan-wide runtime flags.

Modules need to know whether `--deep` is active to extend their payload
sets. Passing that through every Check signature would touch every call
site, so it lives here as a process flag set once per scan by the engine.
Threads only read it, and the engine sets it before workers start.
"""

from __future__ import annotations

_DEEP = False


def set_deep(value: bool) -> None:
    global _DEEP
    _DEEP = bool(value)


def deep() -> bool:
    return _DEEP
