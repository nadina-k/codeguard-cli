from pathlib import Path

from codeguard_cli.rules import load_rules
from codeguard_cli.scanner import scan_target


def test_codeguardignore_excludes_paths_and_rules(tmp_path: Path) -> None:
    (tmp_path / ".codeguardignore").write_text(
        "\n".join(
            [
                "# ignore one file entirely",
                "skip.py",
                "rule:PY-EVAL-001",
            ]
        ),
        encoding="utf-8",
    )

    (tmp_path / "keep.py").write_text('password = "abc12345"\nprint(eval("1+1"))\n', encoding="utf-8")
    (tmp_path / "skip.py").write_text('password = "should_not_show"\n', encoding="utf-8")

    result = scan_target(tmp_path, load_rules(), severity="low")
    rule_ids = {finding.rule_id for finding in result.findings}
    finding_paths = {Path(finding.file_path).name for finding in result.findings}

    assert "PY-EVAL-001" not in rule_ids
    assert "skip.py" not in finding_paths
    assert "SEC-PASSWORD-001" in rule_ids
