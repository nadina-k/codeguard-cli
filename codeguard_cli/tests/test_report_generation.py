from pathlib import Path

from codeguard_cli.models import Finding, ScanResult
from codeguard_cli.reporter.html_report import render_html
from codeguard_cli.reporter.json_report import write_json_report


def test_json_report_writer(tmp_path: Path) -> None:
    result = ScanResult(target_path="demo", findings=[])
    output = tmp_path / "report.json"
    write_json_report(result, output)
    assert output.exists()


def test_html_renderer_contains_table() -> None:
    finding = Finding(
        rule_id="PY-EVAL-001",
        rule_name="Use of eval()",
        description="desc",
        category="Dangerous Patterns",
        severity="High",
        confidence=0.9,
        file_path="demo/app.py",
        line_number=1,
        match_preview="eval(user_input)",
    )
    result = ScanResult(target_path="demo", findings=[finding], total_files_scanned=1, total_files_discovered=1)
    html = render_html(result)
    assert "<table>" in html
    assert "PY-EVAL-001" in html
