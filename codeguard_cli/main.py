"""Application entrypoint wiring."""

from codeguard_cli.cli.commands import run


def main() -> int:
    """Run the CLI and return exit code."""
    return run()
