"""Live scan progress for the CLI.

The reporter is deliberately small and dependency-free. It answers one
question a scanner user actually has while a scan is running: *what is
being requested right now?*

- On an interactive terminal the current request overwrites one line, so
  a 5,000-request scan does not scroll the findings off screen.
- When output is piped (CI logs, files) every event becomes its own line.
  That keeps the log complete and greppable instead of losing updates.
- Writes are serialized because active checks and template runners use
  worker threads.

The reporter never owns scan state. It only formats events; callers can
disable it with ``--no-progress`` or ``--silent`` without changing how
the scan itself behaves.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
from typing import TextIO


def _clean(value: str) -> str:
    """Keep one progress event on one line, even for hostile URLs."""
    return " ".join(str(value).replace("\x00", "").split())


class ProgressReporter:
    """Thread-safe, terminal-aware progress output."""

    def __init__(
        self,
        enabled: bool = True,
        stream: TextIO | None = None,
        *,
        tty: bool | None = None,
        width: int | None = None,
        min_interval: float = 0.0,
    ) -> None:
        self.enabled = bool(enabled)
        self.stream = stream if stream is not None else sys.stderr
        if tty is None:
            try:
                tty = bool(self.stream.isatty())
            except (AttributeError, OSError):
                tty = False
        self.tty = bool(tty)
        self.width = max(40, width or shutil.get_terminal_size((100, 24)).columns)
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._phase = ""
        self._total = 0
        self._index = 0
        self._hits = 0
        self._started = 0.0
        self._last_emit = 0.0
        self._line_visible = False
        self._last_len = 0

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def phase(self, name: str, total: int = 0) -> None:
        """Start a new phase and print its header."""
        if not self.enabled:
            return
        with self._lock:
            self._clear_locked()
            self._phase = name.upper()
            self._total = max(0, int(total))
            self._index = 0
            self._hits = 0
            self._started = time.monotonic()
            self._last_emit = 0.0
            label = f"[{self._phase}]"
            if self._total:
                label += f" 0/{self._total}"
            self._write_line_locked(label)
            self._newline_locked()

    def task(self, label: str, method: str, url: str, note: str = "") -> None:
        """Report the start of a discrete task and advance the counter."""
        if not self.enabled:
            return
        with self._lock:
            self._index += 1
            self._render_locked(label, method, url, note)

    def event(self, label: str, method: str, url: str, note: str = "") -> None:
        """Report a request without advancing the phase task counter.

        Used for crawl pages and template requests, where the phase total
        is measured in tasks, not in individual HTTP calls.
        """
        if not self.enabled:
            return
        with self._lock:
            self._render_locked(label, method, url, note)

    def hit(self, count: int = 1) -> None:
        """Record findings produced by the task that just finished."""
        if not self.enabled or count <= 0:
            return
        with self._lock:
            self._hits += int(count)

    def finish(self, summary: str = "") -> None:
        """End the phase, clearing the transient line."""
        if not self.enabled:
            return
        with self._lock:
            self._clear_locked()
            if summary:
                self.stream.write(summary.rstrip() + "\n")
                self.stream.flush()
            self._phase = ""
            self._total = 0
            self._index = 0
            self._hits = 0
            self._started = 0.0

    def clear(self) -> None:
        """Clear the transient line before a normal log line is printed."""
        if not self.enabled or not self.tty:
            return
        with self._lock:
            self._clear_locked()

    def close(self) -> None:
        self.finish()

    # ------------------------------------------------------------------
    # rendering
    # ------------------------------------------------------------------
    def _render_locked(self, label: str, method: str, url: str, note: str) -> None:
        now = time.monotonic()
        if self.min_interval and self._last_emit and now - self._last_emit < self.min_interval:
            return
        self._last_emit = now
        bits: list[str] = [f"[{self._phase or 'SCAN'}]"]
        if self._total:
            pct = (self._index / self._total * 100.0) if self._total else 0.0
            bits.append(f"{self._index:>4}/{self._total:<4} {pct:5.1f}%")
        elif self._index:
            bits.append(f"{self._index:>5}")
        if label:
            bits.append(_clean(label))
        bits.append(_clean(method).upper())
        bits.append(_clean(url))
        if note:
            bits.append(f"[{_clean(note)}]")
        if self._hits:
            bits.append(f"+{self._hits}")
        line = " ".join(bits)
        if self.tty:
            line = line[: max(1, self.width - 1)]
            padding = " " * max(0, self._last_len - len(line))
            self.stream.write("\r" + line + padding)
            self._last_len = len(line)
            self._line_visible = True
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    def _write_line_locked(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    def _newline_locked(self) -> None:
        self.stream.write("\n")
        self.stream.flush()

    def _clear_locked(self) -> None:
        if not self.tty or not self._line_visible:
            return
        self.stream.write("\r" + (" " * self._last_len) + "\r")
        self.stream.flush()
        self._line_visible = False
        self._last_len = 0
