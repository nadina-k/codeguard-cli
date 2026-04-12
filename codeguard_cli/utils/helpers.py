"""Shared helper functions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def read_text_file(path: Path) -> str:
    """Read file content as UTF-8 text while tolerating encoding issues."""
    return path.read_text(encoding="utf-8", errors="ignore")


def normalize_extensions(raw_extensions: list[str] | None) -> set[str] | None:
    """Normalize extension values to lowercase with leading dots."""
    if not raw_extensions:
        return None
    normalized = set()
    for ext in raw_extensions:
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        normalized.add(ext)
    return normalized or None


def is_severity_allowed(candidate: str, minimum: str) -> bool:
    """Return True if candidate severity is >= minimum severity."""
    return SEVERITY_ORDER.get(candidate.lower(), 0) >= SEVERITY_ORDER.get(minimum.lower(), 1)


def utc_now_iso() -> str:
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clamp_text(text: str, length: int = 120) -> str:
    """Trim text for display while preserving readability."""
    if len(text) <= length:
        return text
    return text[: max(0, length - 3)] + "..."
