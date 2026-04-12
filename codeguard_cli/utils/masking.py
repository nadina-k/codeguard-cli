"""Masking helpers for sensitive previews."""

from __future__ import annotations


def mask_value(value: str, keep_start: int = 4, keep_end: int = 2) -> str:
    """Mask a secret-like value while keeping limited context."""
    compact = value.strip()
    if len(compact) <= keep_start + keep_end:
        return "*" * max(4, len(compact))
    return f"{compact[:keep_start]}{'*' * (len(compact) - keep_start - keep_end)}{compact[-keep_end:]}"


def masked_line_preview(line: str, start: int, end: int) -> str:
    """Mask a specific segment inside a source line."""
    segment = line[start:end]
    masked = mask_value(segment)
    return f"{line[:start]}{masked}{line[end:]}".strip()
