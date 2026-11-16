"""Combine existing Mistral triage with local-only Ollama remediation.

Does not call an external API, execute generated tests, or apply patches.
Requires the previously described local_remediation.py in the repository root.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {"sast_mistral.py", "test_mistral.py"}


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        obj = json.load(handle)
    if not isinstance(obj, dict):
        raise ValueError(f"Expected JSON object in {path.name}")
    return obj


def assert_local_path(root: Path, name: str) -> Path:
    if name not in SOURCES:
        raise ValueError(f"Source not explicitly approved: {name}")
    candidate = root / name
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"Missing or symlinked source: {name}")
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("Source outside repository")
    return candidate


def run_pipeline(args: argparse.Namespace) -> int:
    root = Path(args.repo).resolve(strict=True)
    scan = read_json(root / args.semgrep)
    evidence = read_json(root / args.evidence)
    triage = read_json(root / args.triage)

    if evidence.get("policy", {}).get("source_code_included") is not False:
        raise ValueError("Evidence report does not assert source_code_included=false")
    if triage.get("source_code_sent_to_model") is not False:
        raise ValueError("Triage report does not assert source_code_sent_to_model=false")

    findings = scan.get("results", [])
    ev = {f["finding_id"]: f for f in evidence.get("findings", [])}
    tr = {f["evidence"]["finding_id"]: f for f in triage.get("findings", [])}
    if not isinstance(findings, list):
        raise ValueError("Invalid Semgrep results")

    output_dir = root / "remediation" / "proposals"
    if output_dir.is_symlink():
        raise ValueError("Output directory cannot be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.resolve().is_relative_to(root):
        raise ValueError("Output directory outside repository")

    results = []
    for index, finding in enumerate(findings):
        fid = f"SAST-{index + 1:04d}"
        source_name = Path(finding["path"]).name
        entry = {
            "finding_id": fid,
            "source_file": source_name,
            "line": finding["start"]["line"],
            "rule_id": finding["check_id"],
            "triage_classification": None,
            "local_remediation_status": "not_run",
            "proposal_file": None,
            "tests_executed": False,
            "patch_applied": False,
            "human_review_required": True,
        }
        evidence_item = ev.get(fid)
        triage_item = tr.get(fid)
        if not evidence_item or not triage_item:
            entry["local_remediation_status"] = "missing_correlated_report"
            results.append(entry)
            continue
        if (evidence_item.get("rule_id") != finding["check_id"]
                or triage_item.get("evidence", {}).get("rule_id") != finding["check_id"]):
            entry["local_remediation_status"] = "rule_mismatch"
            results.append(entry)
            continue
        entry["triage_classification"] = triage_item.get("triage", {}).get("classification")
        try:
            assert_local_path(root, source_name)
            if args.dry_run:
                entry["local_remediation_status"] = "ready"
            else:
                # No shell, no external-model API calls. The child script must
                # itself use a hardcoded loopback-only Ollama endpoint.
                command = [
                    sys.executable, str(root / "local_remediation.py"),
                    "--repo", str(root),
                    "--results", str(root / args.semgrep),
                    "--finding", str(index),
                    "--source", source_name,
                ]
                completed = subprocess.run(
                    command, cwd=root, capture_output=True, text=True,
                    timeout=args.timeout, check=False,
                )
                proposal = output_dir / f"finding-{index + 1:04d}.md"
                if completed.returncode == 0 and proposal.is_file() and not proposal.is_symlink():
                    entry["local_remediation_status"] = "proposal_generated"
                    entry["proposal_file"] = str(proposal.relative_to(root))
                else:
                    # Avoid copying subprocess stderr/stdout into reports: they
                    # may contain source code or sensitive local paths.
                    entry["local_remediation_status"] = "generation_failed"
        except (ValueError, OSError, subprocess.TimeoutExpired):
            entry["local_remediation_status"] = "generation_failed"
        results.append(entry)

    report = {
        "schema_version": 1,
        "report_type": "hybrid_remediation_summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_api_invoked_by_orchestrator": False,
        "source_code_sent_to_external_api_by_orchestrator": False,
        "tests_executed": False,
        "patches_applied": False,
        "findings": results,
    }
    destination = root / "remediation" / "hybrid-report.json"
    if destination.is_symlink():
        raise ValueError("Report destination cannot be a symlink")
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {destination}")
    for item in results:
        print(f"{item['finding_id']}: {item['local_remediation_status']}")
    return 0 if all(x["local_remediation_status"] in ("ready", "proposal_generated") for x in results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--semgrep", default="semgrep-results.json")
    parser.add_argument("--evidence", default="mistral-evidence.json")
    parser.add_argument("--triage", default="mistral-triage.json")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--dry-run", action="store_true")
    return run_pipeline(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
