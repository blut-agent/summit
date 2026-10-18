"""Persistent CLI settings - written by `summit setup`, read by every command.

One JSON file, one dataclass, no surprises. Missing files, corrupt files
and unknown keys all degrade to defaults instead of crashing: a scanner
should never fail to start because a config file was edited by hand.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

CONFIG_ENV = "SUMMIT_CONFIG"


def default_config_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".summit" / "config.json"


@dataclass
class Settings:
    """Everything the wizard can persist. Values mirror CLI flags."""

    output_dir: str = "summit-reports"
    workers: int = 8
    rate: float | None = None
    timeout: float = 10.0
    retries: int = 1
    delay: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    cookie: str = ""
    user_agent: str = ""
    auto_html: bool = False
    deep: bool = False
    oob_url: str = ""
    template_dir: str = ""
    no_color: bool = False

    def effective_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.cookie and "cookie" not in {key.lower() for key in headers}:
            headers["Cookie"] = self.cookie
        return headers

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {item.name for item in fields(cls)}
        clean = {key: value for key, value in data.items() if key in known}
        # Coerce numeric fields so a string in the JSON cannot explode later;
        # null and unparseable values degrade to the dataclass default.
        for numeric, cast in (("workers", int), ("timeout", float), ("retries", int), ("delay", float)):
            if numeric in clean:
                if clean[numeric] is None:
                    clean.pop(numeric)
                    continue
                try:
                    clean[numeric] = cast(clean[numeric])
                except (TypeError, ValueError):
                    clean.pop(numeric)
        if "rate" in clean and clean["rate"] is not None:
            try:
                clean["rate"] = float(clean["rate"])
            except (TypeError, ValueError):
                clean.pop("rate")
        if "headers" in clean and not isinstance(clean["headers"], dict):
            clean.pop("headers")
        return cls(**clean)


def load_settings(path: Path | str | None = None) -> Settings:
    target = Path(path).expanduser() if path else default_config_path()
    try:
        raw = target.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError, TypeError):
        return Settings()
    if not isinstance(data, dict):
        return Settings()
    return Settings.from_dict(data)


def save_settings(settings: Settings, path: Path | str | None = None) -> Path:
    target = Path(path).expanduser() if path else default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(settings.to_dict(), indent=2) + "\n", encoding="utf-8")
    return target


def resolve_paths(settings: Settings) -> Settings:
    """Expand ~ in any path-like setting so callers get usable values."""
    if settings.output_dir:
        settings.output_dir = str(Path(settings.output_dir).expanduser())
    if settings.template_dir:
        settings.template_dir = str(Path(settings.template_dir).expanduser())
    return settings
