"""Scan history persistence for dashboard workflows."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_HISTORY_FILE = Path.home() / ".codeguard_cli_history.json"
MAX_HISTORY_ENTRIES = 25


def get_history_file() -> Path:
    """Return the configured history file location."""
    override = os.getenv("CODEGUARD_HISTORY_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    return DEFAULT_HISTORY_FILE


def _load_raw(history_path: Path | None = None) -> list[dict]:
    if history_path is None:
        history_path = get_history_file()
    if not history_path.exists():
        return []
    try:
        payload = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _save_raw(entries: list[dict], history_path: Path | None = None) -> None:
    if history_path is None:
        history_path = get_history_file()
    try:
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except OSError:
        return


def append_scan_history(entry: dict, history_path: Path | None = None) -> None:
    """Append a new history entry and keep newest entries first."""
    entries = _load_raw(history_path)
    entry = dict(entry)
    entry["saved_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entries.insert(0, entry)
    _save_raw(entries[:MAX_HISTORY_ENTRIES], history_path)


def list_scan_history(limit: int = 5, history_path: Path | None = None) -> list[dict]:
    """Return most recent scan history items."""
    entries = _load_raw(history_path)
    return entries[: max(0, limit)]


def get_last_scan(history_path: Path | None = None) -> dict | None:
    """Return the latest scan entry, if any."""
    entries = list_scan_history(limit=1, history_path=history_path)
    return entries[0] if entries else None
