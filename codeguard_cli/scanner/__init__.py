"""Scanner orchestration."""

from __future__ import annotations

from pathlib import Path
from time import perf_counter

from codeguard_cli.models import ScanResult
from codeguard_cli.utils.helpers import is_severity_allowed, normalize_extensions, utc_now_iso

from .dependencies import scan_dependency_files
from .file_walker import walk_files
from .ignore_config import load_ignore_config
from .patterns import scan_python_file
from .secrets import scan_file_for_secrets

DEFAULT_SCAN_EXTENSIONS = {
    ".py",
    ".txt",
    ".env",
    ".ini",
    ".cfg",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
}


def scan_target(
    target_path: Path,
    rules: dict[str, dict],
    severity: str = "low",
    extensions: list[str] | None = None,
) -> ScanResult:
    """Run all scanners for a target folder and return ScanResult."""
    started_at = utc_now_iso()
    start = perf_counter()

    extension_filter = normalize_extensions(extensions)
    selected_extensions = extension_filter or DEFAULT_SCAN_EXTENSIONS

    ignore_config = load_ignore_config(target_path)

    total_discovered, files_to_scan = walk_files(
        target_path,
        selected_extensions,
        ignore_matcher=ignore_config.should_ignore_path,
    )

    findings = []
    for file_path in files_to_scan:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        findings.extend(scan_file_for_secrets(file_path, text, rules))

        if file_path.suffix.lower() == ".py":
            findings.extend(scan_python_file(file_path, text, rules))

    findings.extend(scan_dependency_files(target_path, rules))

    filtered = [
        finding
        for finding in findings
        if not ignore_config.should_ignore_path(Path(finding.file_path), False)
        and finding.rule_id not in ignore_config.rule_ids
        and is_severity_allowed(finding.severity, severity)
    ]

    duration = perf_counter() - start
    finished_at = utc_now_iso()

    return ScanResult(
        target_path=str(target_path.resolve()),
        findings=sorted(filtered, key=lambda item: (item.file_path, item.line_number, item.rule_id)),
        total_files_discovered=total_discovered,
        total_files_scanned=len(files_to_scan),
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration,
    )
