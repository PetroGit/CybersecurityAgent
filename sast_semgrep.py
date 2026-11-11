"""Run Semgrep static analysis against source code without executing it."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_TIMEOUT_SECONDS = 300


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze source code for security issues with Semgrep."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--config",
        default="p/security-audit",
        help="Semgrep ruleset or rules file to use (default: p/security-audit).",
    )
    parser.add_argument(
        "--metrics",
        choices=("off", "on"),
        default="off",
        help="Whether to allow Semgrep metrics (default: off).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Maximum scan time in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    return parser.parse_args()


def format_finding(finding):
    """Render one Semgrep JSON finding in a compact, readable form."""
    extra = finding.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    start = finding.get("start", {})
    if not isinstance(start, dict):
        start = {}

    severity = extra.get("severity", "UNKNOWN")
    rule_id = finding.get("check_id", "unknown-rule")
    location = f"{finding.get('path', '<unknown file>')}:{start.get('line', '?')}"
    message = extra.get("message", "No finding description provided.")

    lines = [f"[{severity}] {rule_id} - {location}", f"  {message}"]
    metadata = extra.get("metadata", {})
    if isinstance(metadata, dict):
        for key in ("cwe", "owasp", "references"):
            value = metadata.get(key)
            if value:
                lines.append(f"  {key.upper()}: {value}")

    return "\n".join(lines)


def report_errors(errors):
    """Print Semgrep scan errors without hiding an incomplete scan."""
    for error in errors:
        if isinstance(error, dict):
            message = error.get("message", str(error))
        else:
            message = str(error)
        print(f"Semgrep error: {message}", file=sys.stderr)


def main():
    args = parse_args()

    if args.timeout <= 0:
        print("Error: --timeout must be a positive number.", file=sys.stderr)
        return 2

    if args.config.casefold() == "auto" and args.metrics == "off":
        print(
            "Error: Semgrep's 'auto' config requires metrics. Use a specific "
            "config such as 'p/security-audit', or pass --metrics on.",
            file=sys.stderr,
        )
        return 2

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2

    semgrep = shutil.which("semgrep")
    if semgrep is None:
        print(
            "Error: Semgrep CLI was not found on PATH. Install Semgrep and make "
            "the 'semgrep' command available before running this script.",
            file=sys.stderr,
        )
        return 2

    # Semgrep reads and analyzes the target; this script never runs target code.
    command = [
        semgrep,
        "scan",
        "--config",
        args.config,
        f"--metrics={args.metrics}",
        "--error",
        "--json",
        str(target),
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(
            f"Error: Semgrep scan exceeded the {args.timeout}-second timeout.",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"Error: could not start Semgrep: {exc}", file=sys.stderr)
        return 2

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        details = completed.stderr.strip()
        if details:
            print(details, file=sys.stderr)
        print("Error: Semgrep did not return valid JSON.", file=sys.stderr)
        return 2

    if not isinstance(report, dict):
        print("Error: Semgrep returned an unexpected JSON format.", file=sys.stderr)
        return 2

    findings = report.get("results", [])
    errors = report.get("errors", [])
    if not isinstance(findings, list) or not isinstance(errors, list):
        print("Error: Semgrep returned an unexpected JSON format.", file=sys.stderr)
        return 2
    if any(not isinstance(finding, dict) for finding in findings):
        print("Error: Semgrep returned a malformed finding.", file=sys.stderr)
        return 2

    for finding in findings:
        print(format_finding(finding))

    if errors:
        report_errors(errors)

    finding_count = len(findings)
    error_count = len(errors)
    print(f"\nSemgrep scan complete: {finding_count} finding(s), {error_count} error(s).")

    expected_returncode = 1 if finding_count else 0
    if error_count or completed.returncode != expected_returncode:
        if completed.stderr.strip():
            print(completed.stderr.strip(), file=sys.stderr)
        return 2

    return expected_returncode


if __name__ == "__main__":
    raise SystemExit(main())
