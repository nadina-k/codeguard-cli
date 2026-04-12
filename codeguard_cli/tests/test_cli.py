import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )


def test_rules_list_command() -> None:
    result = run_cli("rules", "list")
    assert result.returncode == 0
    assert "SEC-AWS-001" in result.stdout


def test_scan_exports_json_and_html(tmp_path: Path) -> None:
    sample_dir = tmp_path / "sample"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text('password = "secret123"\nprint(eval("1+1"))\n', encoding="utf-8")

    out_base = tmp_path / "report"
    result = run_cli("scan", str(sample_dir), "--json", "--html", "--output", str(out_base))

    assert result.returncode == 0
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()

    payload = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert payload["metadata"]["total_findings"] >= 1


def test_report_command_from_json(tmp_path: Path) -> None:
    payload = {
        "target_path": "demo",
        "metadata": {
            "total_files_discovered": 1,
            "total_files_scanned": 1,
            "total_findings": 1,
            "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0},
            "rule_counts": {"PY-EVAL-001": 1},
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "duration_seconds": 1.0,
            "generated_at": "2026-01-01T00:00:01Z",
        },
        "findings": [
            {
                "rule_id": "PY-EVAL-001",
                "rule_name": "Use of eval()",
                "description": "eval usage",
                "category": "Dangerous Patterns",
                "severity": "High",
                "confidence": 0.9,
                "file_path": "demo/app.py",
                "line_number": 1,
                "match_preview": "eval(user_input)",
                "remediation": "avoid eval",
                "cwe": "CWE-95",
            }
        ],
    }
    report_file = tmp_path / "input.json"
    report_file.write_text(json.dumps(payload), encoding="utf-8")

    result = run_cli("report", str(report_file))

    assert result.returncode == 0
    assert "CodeGuard CLI Scan Report" in result.stdout
