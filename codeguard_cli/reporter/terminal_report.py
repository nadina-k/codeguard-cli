"""Terminal report rendering."""

from __future__ import annotations

from collections import Counter

from codeguard_cli.models import ScanResult
from codeguard_cli.utils.helpers import clamp_text


def _format_counts(counts: dict[str, int]) -> str:
    ordered = ["Critical", "High", "Medium", "Low"]
    return " | ".join(f"{key}: {counts.get(key, 0)}" for key in ordered)


def render_terminal_report(scan_result: ScanResult, quiet: bool = False, top_n_rules: int = 5) -> str:
    """Build a polished terminal report string."""
    lines: list[str] = []
    lines.append("CodeGuard CLI Scan Report")
    lines.append("=" * 60)
    lines.append(f"Target: {scan_result.target_path}")
    lines.append(f"Files discovered: {scan_result.total_files_discovered}")
    lines.append(f"Files scanned: {scan_result.total_files_scanned}")
    lines.append(f"Findings: {len(scan_result.findings)}")
    lines.append(f"Severity: {_format_counts(scan_result.severity_counts())}")
    lines.append(f"Duration: {scan_result.duration_seconds:.3f}s")
    lines.append("")

    rule_counts = Counter(scan_result.rule_counts())
    if rule_counts:
        lines.append("Top Rule Matches:")
        for rule_id, count in rule_counts.most_common(top_n_rules):
            lines.append(f"- {rule_id}: {count}")
        lines.append("")

    if not quiet and scan_result.findings:
        lines.append("Detailed Findings:")
        for finding in scan_result.findings:
            location = f"{finding.file_path}:{finding.line_number}" if finding.line_number else finding.file_path
            lines.append(
                f"- [{finding.severity}] {finding.rule_id} at {location} | "
                f"confidence={finding.confidence:.2f} | {clamp_text(finding.match_preview, 140)}"
            )

    if not scan_result.findings:
        lines.append("No findings detected.")

    return "\n".join(lines)
