"""HTML report rendering."""

from __future__ import annotations

from html import escape
from pathlib import Path

from codeguard_cli.models import ScanResult


_BADGE_CLASS = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
}


def _severity_badge(severity: str) -> str:
    css = _BADGE_CLASS.get(severity, "low")
    return f'<span class="badge {css}">{escape(severity)}</span>'


def render_html(scan_result: ScanResult) -> str:
    """Render a clean HTML report."""
    rows = []
    for finding in scan_result.findings:
        location = f"{escape(finding.file_path)}:{finding.line_number}" if finding.line_number else escape(finding.file_path)
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(finding.severity)}</td>"
            f"<td>{escape(finding.rule_id)}</td>"
            f"<td>{escape(finding.rule_name)}</td>"
            f"<td>{location}</td>"
            f"<td>{escape(finding.match_preview)}</td>"
            f"<td>{finding.confidence:.2f}</td>"
            "</tr>"
        )

    severity = scan_result.severity_counts()
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='6'>No findings detected.</td></tr>"

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>CodeGuard CLI Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 24px; color: #1f2937; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .meta {{ margin-bottom: 1.2rem; color: #4b5563; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin-bottom: 1.2rem; }}
    .card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .badge {{ border-radius: 999px; padding: 4px 9px; color: #fff; font-weight: 600; font-size: 0.75rem; display: inline-block; }}
    .critical {{ background: #991b1b; }}
    .high {{ background: #b45309; }}
    .medium {{ background: #2563eb; }}
    .low {{ background: #6b7280; }}
  </style>
</head>
<body>
  <h1>CodeGuard CLI Security Report</h1>
  <div class=\"meta\">Target: {escape(scan_result.target_path)} | Files scanned: {scan_result.total_files_scanned} / {scan_result.total_files_discovered} | Duration: {scan_result.duration_seconds:.3f}s</div>
  <div class=\"grid\">
    <div class=\"card\"><strong>Total Findings</strong><div>{len(scan_result.findings)}</div></div>
    <div class=\"card\"><strong>Critical</strong><div>{severity.get('Critical', 0)}</div></div>
    <div class=\"card\"><strong>High</strong><div>{severity.get('High', 0)}</div></div>
    <div class=\"card\"><strong>Medium+Low</strong><div>{severity.get('Medium', 0) + severity.get('Low', 0)}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule ID</th>
        <th>Rule Name</th>
        <th>Location</th>
        <th>Preview</th>
        <th>Confidence</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>
"""


def write_html_report(scan_result: ScanResult, output_path: Path) -> Path:
    """Write HTML report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(scan_result), encoding="utf-8")
    return output_path
