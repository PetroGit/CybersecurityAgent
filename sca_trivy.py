"""Find vulnerable dependencies with Trivy without executing project code."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_TIMEOUT_SECONDS = 600
ALL_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan dependency manifests for known vulnerabilities with Trivy."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=ALL_SEVERITIES,
        default=list(ALL_SEVERITIES),
        help="Severity levels to include (default: all levels).",
    )
    parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="Hide vulnerabilities for which Trivy reports no fixed version.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Maximum scan time in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    return parser.parse_args()


def get_vulnerabilities(report):
    results = report.get("Results", [])
    if results is None:
        return []
    if not isinstance(results, list):
        raise ValueError("Trivy returned an unexpected Results field.")

    vulnerabilities = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy returned a malformed scan result.")
        findings = result.get("Vulnerabilities") or []
        if not isinstance(findings, list):
            raise ValueError("Trivy returned an unexpected Vulnerabilities field.")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Trivy returned a malformed vulnerability finding.")
            vulnerabilities.append((result, finding))

    return vulnerabilities


def finding_url(finding):
    primary_url = finding.get("PrimaryURL")
    if isinstance(primary_url, str) and primary_url:
        return primary_url

    references = finding.get("References", [])
    if isinstance(references, list):
        for reference in references:
            if isinstance(reference, str) and reference:
                return reference
    return "Not provided by Trivy"


def format_finding(result, finding):
    vulnerability_id = finding.get("VulnerabilityID", "Unknown ID")
    package_name = finding.get("PkgName", "Unknown package")
    installed = finding.get("InstalledVersion", "Unknown")
    fixed = finding.get("FixedVersion") or "No fixed version listed"
    severity = finding.get("Severity", "UNKNOWN")
    title = finding.get("Title") or finding.get("Description") or "No title provided."
    target = result.get("Target", "Unknown target")
    package_path = finding.get("PkgPath")

    lines = [
        f"[{severity}] {vulnerability_id} - {package_name}",
        f"  Target: {target}",
        f"  Installed: {installed}",
        f"  Fixed version: {fixed}",
        f"  Details: {title}",
        f"  Advisory: {finding_url(finding)}",
    ]
    if package_path:
        lines.append(f"  Dependency path: {package_path}")
    return "\n".join(lines)


def main():
    args = parse_args()
    if args.timeout <= 0:
        print("Error: --timeout must be a positive number.", file=sys.stderr)
        return 2

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2

    trivy = shutil.which("trivy")
    if trivy is None:
        print(
            "Error: Trivy CLI was not found on PATH. Install Trivy and make "
            "the 'trivy' command available before running this script.",
            file=sys.stderr,
        )
        return 2

    # Trivy reads dependency metadata and vulnerability databases; it does not
    # execute the analyzed application or its dependencies.
    command = [
        trivy,
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--exit-code",
        "1",
        "--severity",
        ",".join(args.severity),
    ]
    if args.ignore_unfixed:
        command.append("--ignore-unfixed")
    command.append(str(target))

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
            f"Error: Trivy scan exceeded the {args.timeout}-second timeout.",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"Error: could not start Trivy: {exc}", file=sys.stderr)
        return 2

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        details = completed.stderr.strip()
        if details:
            print(details, file=sys.stderr)
        print("Error: Trivy did not return valid JSON.", file=sys.stderr)
        return 2

    if not isinstance(report, dict):
        print("Error: Trivy returned an unexpected JSON format.", file=sys.stderr)
        return 2

    try:
        vulnerabilities = get_vulnerabilities(report)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for result, finding in vulnerabilities:
        print(format_finding(result, finding))

    if not vulnerabilities:
        print("No dependency vulnerabilities were reported by Trivy.")

    print(f"\nTrivy SCA complete: {len(vulnerabilities)} finding(s).")

    expected_returncode = 1 if vulnerabilities else 0
    if completed.returncode != expected_returncode:
        if completed.stderr.strip():
            print(completed.stderr.strip(), file=sys.stderr)
        print(
            f"Error: Trivy returned unexpected exit code {completed.returncode}.",
            file=sys.stderr,
        )
        return 2

    return expected_returncode


if __name__ == "__main__":
    raise SystemExit(main())
