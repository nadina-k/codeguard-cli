"""Dependency parsing and risk checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from codeguard_cli.models import Finding

RISK_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "dependency_risks.json"


@dataclass(slots=True)
class DependencyEntry:
    """Parsed dependency line from requirements or pyproject."""

    name: str
    specifier: str
    version: str
    source_file: str
    line_number: int


_DEP_LINE_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*([<>=!~]{1,2}.*)?$")
_PEP508_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~].+)?$")


def _normalize_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _clean_version(value: str) -> str:
    return value.strip().strip('"').strip("'")


def parse_requirements_file(path: Path) -> list[DependencyEntry]:
    """Parse dependencies from requirements.txt style files."""
    dependencies: list[DependencyEntry] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--", "git+", "http://", "https://")):
            continue

        no_comment = line.split("#", 1)[0].strip()
        match = _DEP_LINE_RE.match(no_comment)
        if not match:
            continue

        name = _normalize_name(match.group(1))
        specifier = (match.group(2) or "").strip()
        version = ""
        if "==" in specifier:
            version = _clean_version(specifier.split("==", 1)[1].split(",", 1)[0])

        dependencies.append(
            DependencyEntry(
                name=name,
                specifier=specifier,
                version=version,
                source_file=str(path),
                line_number=line_number,
            )
        )
    return dependencies


def parse_pyproject_file(path: Path) -> list[DependencyEntry]:
    """Parse dependencies from pyproject.toml with tomllib."""
    import tomllib

    dependencies: list[DependencyEntry] = []
    payload = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))

    project = payload.get("project", {})
    for item in project.get("dependencies", []):
        match = _PEP508_RE.match(str(item))
        if not match:
            continue
        name = _normalize_name(match.group(1))
        specifier = (match.group(2) or "").strip()
        version = ""
        if "==" in specifier:
            version = _clean_version(specifier.split("==", 1)[1].split(",", 1)[0])
        dependencies.append(DependencyEntry(name, specifier, version, str(path), 0))

    poetry = payload.get("tool", {}).get("poetry", {})
    poetry_deps = poetry.get("dependencies", {})
    for name, raw_spec in poetry_deps.items():
        if str(name).lower() == "python":
            continue
        normalized = _normalize_name(str(name))
        if isinstance(raw_spec, str):
            specifier = raw_spec.strip()
        elif isinstance(raw_spec, dict):
            specifier = str(raw_spec.get("version", "")).strip()
        else:
            specifier = ""
        version = ""
        if "==" in specifier:
            version = _clean_version(specifier.split("==", 1)[1].split(",", 1)[0])
        dependencies.append(DependencyEntry(normalized, specifier, version, str(path), 0))

    return dependencies


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts[:4]) if parts else ()


def _compare_versions(left: str, right: str) -> int:
    """Return -1 if left<right, 0 if equal, 1 if left>right."""
    left_parts = list(_parse_version_tuple(left))
    right_parts = list(_parse_version_tuple(right))

    length = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (length - len(left_parts)))
    right_parts.extend([0] * (length - len(right_parts)))

    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def _version_matches_affected(version: str, affected_spec: str) -> bool:
    if not version:
        return True

    conditions = [part.strip() for part in affected_spec.split(",") if part.strip()]
    if not conditions:
        return False

    for condition in conditions:
        operator = ""
        operand = condition
        for candidate in (">=", "<=", "==", "!=", ">", "<"):
            if condition.startswith(candidate):
                operator = candidate
                operand = condition[len(candidate) :].strip()
                break

        if not operator:
            continue

        comparison = _compare_versions(version, operand)
        if operator == "<" and not (comparison < 0):
            return False
        if operator == "<=" and not (comparison <= 0):
            return False
        if operator == ">" and not (comparison > 0):
            return False
        if operator == ">=" and not (comparison >= 0):
            return False
        if operator == "==" and not (comparison == 0):
            return False
        if operator == "!=" and not (comparison != 0):
            return False

    return True


def _load_risk_database(path: Path = RISK_DB_PATH) -> dict:
    if not path.exists():
        return {"packages": {}}
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _is_unpinned(specifier: str) -> bool:
    if not specifier:
        return True
    return "==" not in specifier


def scan_dependency_files(root_path: Path, rules: dict[str, dict]) -> list[Finding]:
    """Scan requirements and pyproject files for dependency risks."""
    findings: list[Finding] = []
    dependencies: list[DependencyEntry] = []

    requirements_file = root_path / "requirements.txt"
    if requirements_file.exists():
        dependencies.extend(parse_requirements_file(requirements_file))

    pyproject_file = root_path / "pyproject.toml"
    if pyproject_file.exists():
        try:
            dependencies.extend(parse_pyproject_file(pyproject_file))
        except Exception:
            pass

    if not dependencies:
        return findings

    risk_db = _load_risk_database()
    risk_packages = risk_db.get("packages", {})

    unpinned_rule = rules.get("DEP-UNPINNED-001", {})
    risky_rule = rules.get("DEP-RISKY-001", {})

    for dep in dependencies:
        if _is_unpinned(dep.specifier):
            findings.append(
                Finding(
                    rule_id=unpinned_rule.get("id", "DEP-UNPINNED-001"),
                    rule_name=unpinned_rule.get("name", "Unpinned Dependency"),
                    description=unpinned_rule.get("description", "Dependency is not pinned to exact version."),
                    category=unpinned_rule.get("category", "Dependencies"),
                    severity=unpinned_rule.get("severity", "Medium"),
                    confidence=0.78,
                    file_path=dep.source_file,
                    line_number=dep.line_number,
                    match_preview=f"{dep.name}{dep.specifier}",
                    remediation=unpinned_rule.get("remediation", ""),
                    cwe=unpinned_rule.get("cwe", ""),
                )
            )

        risk = risk_packages.get(dep.name)
        if not risk:
            continue

        affected_spec = str(risk.get("affected", "")).strip()
        if affected_spec and not _version_matches_affected(dep.version, affected_spec):
            continue

        findings.append(
            Finding(
                rule_id=risky_rule.get("id", "DEP-RISKY-001"),
                rule_name=risky_rule.get("name", "Known Risky Dependency"),
                description=risk.get("summary", risky_rule.get("description", "Dependency flagged by local risk database.")),
                category=risky_rule.get("category", "Dependencies"),
                severity=risk.get("severity", risky_rule.get("severity", "High")),
                confidence=0.8,
                file_path=dep.source_file,
                line_number=dep.line_number,
                match_preview=f"{dep.name}{dep.specifier} (recommended {risk.get('recommended', 'upgrade')})",
                remediation=risky_rule.get("remediation", ""),
                cwe=risky_rule.get("cwe", ""),
            )
        )

    return findings
