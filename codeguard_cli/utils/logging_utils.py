"""Logging setup utilities."""

from __future__ import annotations

import logging


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the root logger for CLI usage."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )
