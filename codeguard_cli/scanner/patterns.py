"""Dangerous pattern scanning for Python files."""

from __future__ import annotations

from pathlib import Path

from codeguard_cli.models import Finding

from .ast_checks import analyze_python_ast


def scan_python_file(file_path: Path, content: str, rules: dict[str, dict]) -> list[Finding]:
    """Scan Python source text for AST-detected dangerous patterns."""
    findings: list[Finding] = []

    for hit in analyze_python_ast(content):
        rule = rules.get(hit.rule_id)
        if not rule:
            continue
        findings.append(
            Finding(
                rule_id=rule["id"],
                rule_name=rule["name"],
                description=rule["description"],
                category=rule["category"],
                severity=rule["severity"],
                confidence=hit.confidence,
                file_path=str(file_path),
                line_number=hit.line_number,
                match_preview=hit.preview,
                remediation=rule.get("remediation", ""),
                cwe=rule.get("cwe", ""),
            )
        )

    return findings
