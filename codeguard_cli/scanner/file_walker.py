"""Filesystem walking utilities."""

from __future__ import annotations

import os
from pathlib import Path

IGNORED_DIRS = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}

ALWAYS_INCLUDED_FILES = {"requirements.txt", "pyproject.toml"}


def walk_files(root: Path, extensions: set[str] | None = None) -> tuple[int, list[Path]]:
    """Recursively walk root and return (total_discovered, selected_files)."""
    total_discovered = 0
    selected_files: list[Path] = []

    for current_root, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in IGNORED_DIRS]
        for file_name in files:
            total_discovered += 1
            path = Path(current_root) / file_name
            suffix = path.suffix.lower()

            if file_name in ALWAYS_INCLUDED_FILES:
                selected_files.append(path)
                continue

            if extensions is None or suffix in extensions:
                selected_files.append(path)

    return total_discovered, selected_files
