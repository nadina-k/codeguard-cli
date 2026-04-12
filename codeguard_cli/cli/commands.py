"""Command-line interface for CodeGuard CLI."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import shutil
import sys
from pathlib import Path

from codeguard_cli import __version__
from codeguard_cli.models import ScanResult
from codeguard_cli.reporter.html_report import write_html_report
from codeguard_cli.reporter.json_report import load_json_report, write_json_report
from codeguard_cli.reporter.terminal_report import render_terminal_report
from codeguard_cli.rules import get_rule, list_rules, load_rules
from codeguard_cli.scanner import scan_target
from codeguard_cli.utils.logging_utils import configure_logging

logger = logging.getLogger(__name__)


def _parse_extensions(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def _severity_choices() -> list[str]:
    return ["low", "medium", "high", "critical"]


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def _style(text: str, color_code: str) -> str:
    if not _supports_color():
        return text
    return f"\033[{color_code}m{text}\033[0m"


def _terminal_width() -> int:
    return max(80, min(shutil.get_terminal_size((100, 30)).columns, 110))


def _dashboard_separator(char: str = "=") -> str:
    return char * _terminal_width()


def _center_line(text: str, width: int) -> str:
    return text.center(width)


def _boxed_block(lines: list[str], title: str = "") -> str:
    inner_width = _terminal_width() - 4
    top = f"+{'-' * (inner_width + 2)}+"

    title_line = ""
    if title:
        label = f" {title} "
        title_line = f"|{label:<{inner_width + 2}}|"

    body = "\n".join(f"| {line[:inner_width]:<{inner_width}} |" for line in lines)
    if title_line:
        return "\n".join([top, title_line, body, top])
    return "\n".join([top, body, top])


def _dashboard_logo() -> str:
    logo_lines = [
        "  ____          _      ____                     _    ____ _     ___ ",
        " / ___|___   __| | ___/ ___|_   _  __ _ _ __ __| |  / ___| |   |_ _|",
        "| |   / _ \\ / _` |/ _ \\ |  _| | | |/ _` | '__/ _` | | |   | |    | | ",
        "| |__| (_) | (_| |  __/ |_| | |_| | (_| | | | (_| | | |___| |___ | | ",
        " \\____\\___/ \\__,_|\\___|\\____|\\__,_|\\__,_|_|  \\__,_|  \\____|_____|___|",
    ]
    return "\n".join(_style(_center_line(line, _terminal_width()), "1;36") for line in logo_lines)


def _dashboard_header() -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta = f"Security Dashboard | v{__version__} | Python {sys.version_info.major}.{sys.version_info.minor} | {now}"
    subtitle = "Analyze code, surface risky patterns, and export reports from this terminal home."
    return "\n".join(
        [
            _dashboard_logo(),
            _style(_center_line(meta, _terminal_width()), "2;37"),
            _style(_center_line(subtitle, _terminal_width()), "0;37"),
        ]
    )


def _dashboard_menu() -> str:
    menu_items = [
        "[1] Quick Scan Current Directory",
        "[2] Scan Custom Path",
        "[3] Scan Demo Samples",
        "[4] List Security Rules",
        "[5] Show Rule Details",
        "[6] Version",
        "[7] Help",
        "[0] Exit",
    ]
    return _boxed_block(menu_items, title="AVAILABLE TOOLS")


def _dashboard_info_panel() -> str:
    cwd = str(Path.cwd())
    info_lines = [
        "Welcome to CodeGuard CLI home.",
        f"Current working directory: {cwd}",
        "Tip: start with option [3] to run an immediate demo scan.",
    ]
    return _boxed_block(info_lines, title="HOME")


def _prompt(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    if raw:
        return raw
    return default


def _build_scan_args_from_prompt(path: str) -> argparse.Namespace:
    severity = _prompt("Minimum severity (low|medium|high|critical)", "low").lower()
    if severity not in _severity_choices():
        print("Invalid severity, defaulting to low.")
        severity = "low"

    extensions = _prompt("File extensions filter (comma-separated, blank for defaults)", "")

    export_format = _prompt("Export format (none|json|html|both)", "none").lower()
    output = ""
    json_export = export_format in {"json", "both"}
    html_export = export_format in {"html", "both"}
    if json_export or html_export:
        output = _prompt("Output file base/path (optional)", "")

    return argparse.Namespace(
        path=path,
        json=json_export,
        html=html_export,
        print_json=False,
        output=output or None,
        severity=severity,
        extensions=extensions or None,
        quiet=False,
        verbose=False,
    )


def _run_dashboard() -> int:
    while True:
        print()
        print(_style(_dashboard_separator("="), "1;34"))
        print(_dashboard_header())
        print(_style(_dashboard_separator("="), "1;34"))
        print(_dashboard_info_panel())
        print(_dashboard_menu())
        choice = _prompt("Select an option", "")

        if choice == "1":
            _cmd_scan(_build_scan_args_from_prompt("."))
            _prompt("Press Enter to continue", "")
        elif choice == "2":
            custom_path = _prompt("Path to scan", ".")
            _cmd_scan(_build_scan_args_from_prompt(custom_path))
            _prompt("Press Enter to continue", "")
        elif choice == "3":
            _cmd_scan(_build_scan_args_from_prompt("demo_samples"))
            _prompt("Press Enter to continue", "")
        elif choice == "4":
            _cmd_rules_list(argparse.Namespace())
            _prompt("Press Enter to continue", "")
        elif choice == "5":
            rule_id = _prompt("Rule ID", "PY-EVAL-001")
            _cmd_rules_show(argparse.Namespace(rule_id=rule_id))
            _prompt("Press Enter to continue", "")
        elif choice == "6":
            _cmd_version(argparse.Namespace())
            _prompt("Press Enter to continue", "")
        elif choice == "7":
            parser = build_parser()
            parser.print_help()
            _prompt("Press Enter to continue", "")
        elif choice == "0":
            print("Exiting CodeGuard dashboard.")
            return 0
        else:
            print("Invalid option. Please choose one of the listed menu numbers.")


def _resolve_output_paths(output: str | None, export_json: bool, export_html: bool) -> tuple[Path | None, Path | None]:
    if not export_json and not export_html:
        return None, None

    provided = Path(output) if output else None

    if export_json and export_html:
        if provided:
            if provided.exists() and provided.is_dir():
                provided.mkdir(parents=True, exist_ok=True)
                return provided / "codeguard_report.json", provided / "codeguard_report.html"
            base = provided.with_suffix("") if provided.suffix else provided
            return base.with_suffix(".json"), base.with_suffix(".html")

        target_dir = Path.cwd()
        return target_dir / "codeguard_report.json", target_dir / "codeguard_report.html"

    if export_json:
        if provided:
            if provided.suffix:
                return provided, None
            provided.mkdir(parents=True, exist_ok=True)
            return provided / "codeguard_report.json", None
        return Path("codeguard_report.json"), None

    if provided:
        if provided.suffix:
            return None, provided
        provided.mkdir(parents=True, exist_ok=True)
        return None, provided / "codeguard_report.html"
    return None, Path("codeguard_report.html")


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Error: target path does not exist: {target}")
        return 2
    if not target.is_dir():
        print(f"Error: target path is not a directory: {target}")
        return 2

    rules = load_rules()
    result = scan_target(
        target,
        rules,
        severity=args.severity,
        extensions=_parse_extensions(args.extensions),
    )

    if args.quiet and not (args.json or args.html):
        print(f"Findings: {len(result.findings)}")
    else:
        print(render_terminal_report(result, quiet=args.quiet))

    json_path, html_path = _resolve_output_paths(args.output, args.json, args.html)

    if json_path:
        write_json_report(result, json_path)
        print(f"JSON report written to: {json_path}")
    if html_path:
        write_html_report(result, html_path)
        print(f"HTML report written to: {html_path}")

    if args.print_json:
        print(json.dumps(result.to_dict(), indent=2))

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    input_path = Path(args.input_json)
    if not input_path.exists():
        print(f"Error: JSON report not found: {input_path}")
        return 2

    result = load_json_report(input_path)
    print(render_terminal_report(result, quiet=args.quiet))

    if args.html:
        output = Path(args.output) if args.output else Path("codeguard_report_from_json.html")
        if output.exists() and output.is_dir():
            output = output / "codeguard_report_from_json.html"
        write_html_report(result, output)
        print(f"HTML report written to: {output}")

    return 0


def _cmd_rules_list(_: argparse.Namespace) -> int:
    for rule in list_rules():
        print(f"{rule['id']:<24} {rule['severity']:<8} {rule['category']:<20} {rule['name']}")
    return 0


def _cmd_rules_show(args: argparse.Namespace) -> int:
    rule = get_rule(args.rule_id)
    if not rule:
        print(f"Rule not found: {args.rule_id}")
        return 2

    fields = [
        ("ID", rule.get("id", "")),
        ("Name", rule.get("name", "")),
        ("Category", rule.get("category", "")),
        ("Severity", rule.get("severity", "")),
        ("Description", rule.get("description", "")),
        ("Detection", rule.get("detection", "")),
        ("Logic/Pattern", rule.get("logic", rule.get("pattern", ""))),
        ("Remediation", rule.get("remediation", "")),
        ("CWE", rule.get("cwe", "")),
    ]
    for label, value in fields:
        print(f"{label}: {value}")
    return 0


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"CodeGuard CLI v{__version__}")
    return 0


def _cmd_dashboard(_: argparse.Namespace) -> int:
    return _run_dashboard()


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="codeguard", description="CodeGuard CLI - lightweight security scanner")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Reduce terminal output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a local folder or repository")
    scan_parser.add_argument("path", help="Path to project folder")
    scan_parser.add_argument("--json", action="store_true", help="Export JSON report")
    scan_parser.add_argument("--html", action="store_true", help="Export HTML report")
    scan_parser.add_argument("--print-json", action="store_true", help="Print full JSON to terminal")
    scan_parser.add_argument("--output", help="Output file or directory for report exports")
    scan_parser.add_argument("--severity", default="low", choices=_severity_choices(), help="Minimum severity")
    scan_parser.add_argument(
        "--extensions",
        help="Comma-separated file extensions to scan (example: .py,.env,.yaml)",
    )
    scan_parser.set_defaults(func=_cmd_scan)

    report_parser = subparsers.add_parser("report", help="Render a saved JSON report")
    report_parser.add_argument("input_json", help="Path to input JSON report")
    report_parser.add_argument("--html", action="store_true", help="Export an HTML report")
    report_parser.add_argument("--output", help="Output HTML file path")
    report_parser.set_defaults(func=_cmd_report)

    rules_parser = subparsers.add_parser("rules", help="Inspect detection rules")
    rules_sub = rules_parser.add_subparsers(dest="rules_cmd", required=True)

    rules_list = rules_sub.add_parser("list", help="List all rules")
    rules_list.set_defaults(func=_cmd_rules_list)

    rules_show = rules_sub.add_parser("show", help="Show details for a rule")
    rules_show.add_argument("rule_id", help="Rule identifier")
    rules_show.set_defaults(func=_cmd_rules_show)

    dashboard_parser = subparsers.add_parser("dashboard", help="Open interactive terminal dashboard")
    dashboard_parser.set_defaults(func=_cmd_dashboard)

    version_parser = subparsers.add_parser("version", help="Show current version")
    version_parser.set_defaults(func=_cmd_version)

    return parser


def run(argv: list[str] | None = None) -> int:
    """CLI execution entry point."""
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        configure_logging(verbose=False, quiet=False)
        try:
            return _run_dashboard()
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting CodeGuard dashboard.")
            return 130

    parser = build_parser()
    args = parser.parse_args(argv)

    # Propagate global quiet/verbose flags to handlers.
    if not hasattr(args, "quiet"):
        args.quiet = False
    if not hasattr(args, "verbose"):
        args.verbose = False

    configure_logging(verbose=args.verbose, quiet=args.quiet)
    logger.debug("Parsed args: %s", args)

    return int(args.func(args))
