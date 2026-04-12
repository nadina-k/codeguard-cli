"""AST-based Python security checks."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(slots=True)
class AstHit:
    """Intermediate AST finding before model conversion."""

    rule_id: str
    line_number: int
    confidence: float
    preview: str


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        called = _call_name(node.func)
        if called.endswith(".format"):
            return True
    return False


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class DangerousPatternVisitor(ast.NodeVisitor):
    """AST visitor that detects dangerous Python code patterns."""

    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.hits: list[AstHit] = []
        self.dynamic_sql_vars: set[str] = set()

    def _add_hit(self, rule_id: str, node: ast.AST, confidence: float = 0.8) -> None:
        line_no = getattr(node, "lineno", 0)
        preview = self.source_lines[line_no - 1].strip() if line_no and line_no <= len(self.source_lines) else ""
        self.hits.append(AstHit(rule_id=rule_id, line_number=line_no, confidence=confidence, preview=preview))

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)

        if name == "eval":
            self._add_hit("PY-EVAL-001", node, 0.95)
        if name == "exec":
            self._add_hit("PY-EXEC-001", node, 0.95)
        if name == "os.system":
            self._add_hit("PY-OS-SYSTEM-001", node, 0.9)
            if node.args and _is_dynamic_string(node.args[0]):
                self._add_hit("PY-CMD-INJECT-001", node, 0.78)

        if name in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }:
            shell_true = any(
                isinstance(keyword.value, ast.Constant)
                and keyword.arg == "shell"
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true:
                self._add_hit("PY-SUBPROCESS-SHELL-001", node, 0.9)
                if node.args and _is_dynamic_string(node.args[0]):
                    self._add_hit("PY-CMD-INJECT-001", node, 0.8)

        if name in {"pickle.loads", "pickle.load"}:
            self._add_hit("PY-PICKLE-LOADS-001", node, 0.88)

        if name == "yaml.load":
            has_safe_loader = any(
                keyword.arg == "Loader"
                and isinstance(keyword.value, ast.Attribute)
                and keyword.value.attr in {"SafeLoader", "CSafeLoader"}
                for keyword in node.keywords
            )
            if not has_safe_loader:
                self._add_hit("PY-YAML-UNSAFE-001", node, 0.85)

        if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self._add_hit("PY-WEAK-HASH-001", node, 0.86)

        if name.endswith(".execute") or name == "execute":
            if node.args and _is_dynamic_string(node.args[0]):
                self._add_hit("PY-SQL-INJECT-001", node, 0.82)
            elif node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in self.dynamic_sql_vars:
                self._add_hit("PY-SQL-INJECT-001", node, 0.8)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names: list[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id.lower())

        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = node.value
            if _is_dynamic_string(value):
                source_text = ast.unparse(value).lower() if hasattr(ast, "unparse") else ""
                if any(keyword in source_text for keyword in ("select", "insert", "update", "delete", "where")):
                    self.dynamic_sql_vars.add(node.targets[0].id)

        keywords = {"password", "passwd", "pwd", "token", "secret", "api_key", "apikey"}
        if target_names and any(any(keyword in name for keyword in keywords) for name in target_names):
            if _is_string_literal(node.value):
                self._add_hit("PY-HARDCODED-CREDS-001", node, 0.8)

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add_hit("PY-BROAD-EXCEPT-001", node, 0.7)
        elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
            self._add_hit("PY-BROAD-EXCEPT-001", node, 0.72)
        self.generic_visit(node)


def analyze_python_ast(source: str) -> list[AstHit]:
    """Parse source with AST and return dangerous pattern hits."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    visitor = DangerousPatternVisitor(source.splitlines())
    visitor.visit(tree)
    return visitor.hits
