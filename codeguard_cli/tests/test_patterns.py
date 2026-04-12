from pathlib import Path

from codeguard_cli.rules import load_rules
from codeguard_cli.scanner.patterns import scan_python_file


def test_detects_eval_and_broad_except() -> None:
    rules = load_rules()
    content = """
def run(user_input):
    try:
        value = eval(user_input)
        return value
    except Exception:
        return None
"""
    findings = scan_python_file(Path("vuln.py"), content, rules)
    rule_ids = {finding.rule_id for finding in findings}

    assert "PY-EVAL-001" in rule_ids
    assert "PY-BROAD-EXCEPT-001" in rule_ids


def test_detects_sql_injection_pattern() -> None:
    rules = load_rules()
    content = """
def lookup(cursor, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
"""
    findings = scan_python_file(Path("sql.py"), content, rules)
    rule_ids = {finding.rule_id for finding in findings}
    assert "PY-SQL-INJECT-001" in rule_ids
