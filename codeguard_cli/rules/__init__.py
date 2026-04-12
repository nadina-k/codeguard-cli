"""Rule loading functions."""

from __future__ import annotations

import json
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent / "rules.json"


def load_rules() -> dict[str, dict]:
    """Load detection rules from the bundled JSON file."""
    with RULES_PATH.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    rules = payload.get("rules", [])
    return {rule["id"]: rule for rule in rules}


def list_rules() -> list[dict]:
    """Return all rule dictionaries sorted by id."""
    return sorted(load_rules().values(), key=lambda item: item["id"])


def get_rule(rule_id: str) -> dict | None:
    """Return a single rule by ID."""
    return load_rules().get(rule_id)
