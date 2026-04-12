from pathlib import Path

from codeguard_cli.rules import load_rules
from codeguard_cli.scanner.dependencies import parse_requirements_file, scan_dependency_files


def test_parse_requirements_file(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask\ndjango==2.2\n", encoding="utf-8")

    deps = parse_requirements_file(req)
    assert len(deps) == 2
    assert deps[0].name == "flask"
    assert deps[1].version == "2.2"


def test_dependency_scanner_reports_unpinned_and_risky(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask\ndjango==2.2\n", encoding="utf-8")

    findings = scan_dependency_files(tmp_path, load_rules())
    rule_ids = {finding.rule_id for finding in findings}

    assert "DEP-UNPINNED-001" in rule_ids
    assert "DEP-RISKY-001" in rule_ids
