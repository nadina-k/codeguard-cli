# CodeGuard CLI

CodeGuard CLI is a production-style Python command-line security scanner for local projects and Git repositories.
It focuses on practical, interview-friendly static checks for Python-heavy codebases.

## Features

- Recursive project scanning with ignored noisy directories (`.git`, `venv`, `node_modules`, `dist`, `build`, etc.)
- Hardcoded secret detection using regex + masking previews
- AST-based dangerous Python pattern checks (`eval`, `exec`, `os.system`, `subprocess shell=True`, weak hashes, broad except, SQL injection heuristics, command injection heuristics)
- Dependency risk checks from `requirements.txt` and `pyproject.toml`
- Local offline dependency risk intelligence from `codeguard_cli/data/dependency_risks.json`
- Rule catalog with metadata, remediation advice, and CWE mapping
- Terminal, JSON, and HTML reports
- Severity filtering (`Low`, `Medium`, `High`, `Critical`)
- CI mode with non-zero exit on risky findings (`--ci`)
- `.codeguardignore` support for path and rule exclusions
- Dashboard recent scan history and quick rerun of the last scan

## Installation

## Prerequisites

- Python 3.11+

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Quick Start

1. Open the dashboard:
```bash
python main.py
```
2. Select menu option `3` to scan `demo_samples` immediately.
3. Use menu option `2` to scan your own project path.
4. Export JSON/HTML reports from the dashboard prompts or use command mode below.

### Terminal Home Dashboard (Kali-style launcher feel)

```bash
python main.py
```

This opens an interactive dashboard menu where you can launch scans, list/show rules, and run demo scans without typing full subcommands.
It also shows recent scans and includes options to rerun the latest scan.

### Basic scan

```bash
python main.py scan demo_samples
```

### Scan with JSON + HTML export

```bash
python main.py scan demo_samples --json --html --output reports/codeguard_report
```

### CI mode (fail build on High/Critical findings by default)

```bash
python main.py scan demo_samples --ci
```

### CI mode with custom threshold

```bash
python main.py scan demo_samples --ci --ci-threshold medium
```

### Scan only Python and environment files

```bash
python main.py scan . --extensions .py,.env --severity medium
```

### Print JSON payload to terminal

```bash
python main.py scan demo_samples --print-json
```

### Render report from existing JSON

```bash
python main.py report reports/codeguard_report.json --html --output reports/from_json.html
```

### Explore rules

```bash
python main.py rules list
python main.py rules show PY-EVAL-001
```

### Version

```bash
python main.py version
```

## CLI Commands

- `scan <path>`
- `report <input-json>`
- `rules list`
- `rules show <rule_id>`
- `dashboard`
- `version`

### Common Flags

- `--json` export JSON report
- `--html` export HTML report
- `--output <path>` output file or directory
- `--severity <low|medium|high|critical>` minimum severity filter
- `--extensions <comma-separated>` extension filter
- `--ci` return non-zero exit code when findings meet threshold
- `--ci-threshold <low|medium|high|critical>` severity threshold for CI mode
- `--quiet` reduce output
- `--verbose` debug logging

## .codeguardignore

Create a `.codeguardignore` file at the scan target root to suppress paths and rules.

Example:

```text
# Ignore a file
tests/fixtures/insecure_sample.py

# Ignore an entire folder
legacy/

# Ignore a specific rule globally
rule:PY-EVAL-001
```

## Example Terminal Output

```text
CodeGuard CLI Scan Report
============================================================
Target: /path/to/demo_samples
Files discovered: 4
Files scanned: 4
Findings: 17
Severity: Critical: 1 | High: 11 | Medium: 4 | Low: 1
Duration: 0.041s

Top Rule Matches:
- PY-EVAL-001: 1
- PY-EXEC-001: 1
- DEP-UNPINNED-001: 2
```

## Project Structure

```text
codeguard_cli/
  main.py
  cli/
    __init__.py
    commands.py
  scanner/
    __init__.py
    file_walker.py
    secrets.py
    patterns.py
    dependencies.py
    ast_checks.py
  rules/
    rules.json
  reporter/
    __init__.py
    terminal_report.py
    json_report.py
    html_report.py
  models/
    __init__.py
    finding.py
    scan_result.py
  utils/
    __init__.py
    masking.py
    helpers.py
    logging_utils.py
  data/
    dependency_risks.json
  tests/
    test_secrets.py
    test_patterns.py
    test_dependencies.py
    test_cli.py
    test_report_generation.py
demo_samples/
main.py
README.md
requirements.txt
.gitignore
```

## Severity Model

- **Critical**: direct private key exposure and similarly severe credential leaks
- **High**: exploitable dangerous execution patterns and hardcoded credentials
- **Medium**: weak crypto and unpinned dependencies
- **Low**: weaker risk indicators (e.g., broad exception handling depending on context)

## Rules Metadata

Each rule defines:

- `id`
- `name`
- `description`
- `category`
- `severity`
- detection type (`regex`, `ast`, `dependency`)
- `pattern` or `logic`
- `remediation`
- `cwe`

## Running Tests

```bash
pytest -q
```

## Demo Samples

`demo_samples/` contains intentionally insecure files that should trigger multiple findings immediately.

## Limitations

- Static analysis only; no runtime instrumentation
- Heuristic checks may produce false positives
- Dependency risk database is local and intentionally small for offline use
- Version comparison is simplified and not full semantic-versioning coverage

## Future Improvements

- Add suppression support (`.codeguardignore`)
- Add SARIF output for CI integration
- Add more language plugins (JavaScript, Go)
- Rule tuning with confidence calibration and context-aware severity
- Optional integration with external vulnerability feeds
