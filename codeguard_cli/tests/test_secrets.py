from pathlib import Path

from codeguard_cli.rules import load_rules
from codeguard_cli.scanner.secrets import scan_file_for_secrets


def test_detects_aws_key_and_password() -> None:
    rules = load_rules()
    content = """
API_KEY = "AKIA1234567890ABCDEF"
password = "super-secret-pass"
"""
    findings = scan_file_for_secrets(Path("sample.py"), content, rules)
    rule_ids = {finding.rule_id for finding in findings}

    assert "SEC-AWS-001" in rule_ids
    assert "SEC-PASSWORD-001" in rule_ids
