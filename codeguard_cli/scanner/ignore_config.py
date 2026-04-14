"""Ignore configuration parsing for .codeguardignore."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path


IGNORE_FILE_NAME = ".codeguardignore"


@dataclass(slots=True)
class IgnoreConfig:
    """Represents parsed path and rule exclusions."""

    root_path: Path
    path_patterns: list[str] = field(default_factory=list)
    rule_ids: set[str] = field(default_factory=set)

    def should_ignore_path(self, path: Path, is_dir: bool = False) -> bool:
        """Return True when path matches any configured ignore pattern."""
        normalized = path
        if not normalized.is_absolute():
            normalized = (self.root_path / normalized).resolve()

        try:
            rel = normalized.relative_to(self.root_path.resolve()).as_posix()
        except ValueError:
            rel = normalized.as_posix()

        rel_for_dir = rel if not is_dir else (rel if rel.endswith("/") else f"{rel}/")

        for raw_pattern in self.path_patterns:
            pattern = raw_pattern.strip().replace("\\", "/")
            if not pattern:
                continue

            if pattern.startswith("./"):
                pattern = pattern[2:]
            if pattern.startswith("/"):
                pattern = pattern[1:]

            direct_pattern = pattern.rstrip("/")
            dir_pattern = direct_pattern + "/"

            if fnmatch(rel, direct_pattern):
                return True
            if fnmatch(rel_for_dir, dir_pattern):
                return True
            if "/" not in direct_pattern and fnmatch(normalized.name, direct_pattern):
                return True

            if pattern.endswith("/") and (rel == direct_pattern or rel.startswith(dir_pattern)):
                return True

        return False


def load_ignore_config(root_path: Path) -> IgnoreConfig:
    """Load .codeguardignore rules from target root."""
    ignore_path = root_path / IGNORE_FILE_NAME
    config = IgnoreConfig(root_path=root_path)

    if not ignore_path.exists():
        return config

    for raw_line in ignore_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("rule:"):
            rule_id = line.split(":", 1)[1].strip()
            if rule_id:
                config.rule_ids.add(rule_id)
            continue
        config.path_patterns.append(line)

    return config
