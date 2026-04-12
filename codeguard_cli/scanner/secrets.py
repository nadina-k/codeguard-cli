"""Secret detection scanner."""

from __future__ import annotations

import re
from pathlib import Path

from codeguard_cli.models import Finding
from codeguard_cli.utils.masking import masked_line_preview


def _secret_rules(rules: dict[str, dict]) -> list[tuple[dict, re.Pattern[str]]]:
    compiled: list[tuple[dict, re.Pattern[str]]] = []
    for rule in rules.values():
        if rule.get("category") != "Secrets":
            continue
        pattern = rule.get("pattern")
        if not pattern:
            continue
        compiled.append((rule, re.compile(pattern)))
    return compiled


def scan_file_for_secrets(file_path: Path, content: str, rules: dict[str, dict]) -> list[Finding]:
    """Scan a single file for potential hardcoded secrets."""
    findings: list[Finding] = []
    secret_rules = _secret_rules(rules)

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule, regex in secret_rules:
            for match in regex.finditer(line):
                preview = masked_line_preview(line, match.start(), match.end())
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        description=rule["description"],
                        category=rule["category"],
                        severity=rule["severity"],
                        confidence=float(rule.get("confidence", 0.7)),
                        file_path=str(file_path),
                        line_number=line_number,
                        match_preview=preview,
                        remediation=rule.get("remediation", ""),
                        cwe=rule.get("cwe", ""),
                    )
                )
    return findings
