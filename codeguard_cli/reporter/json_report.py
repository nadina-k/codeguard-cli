"""JSON reporting utilities."""

from __future__ import annotations

import json
from pathlib import Path

from codeguard_cli.models import ScanResult


def write_json_report(scan_result: ScanResult, output_path: Path) -> Path:
    """Write scan result to JSON file and return output path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(scan_result.to_dict(), file, indent=2)
    return output_path


def load_json_report(input_path: Path) -> ScanResult:
    """Load a ScanResult from a JSON report file."""
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    return ScanResult.from_dict(payload)
