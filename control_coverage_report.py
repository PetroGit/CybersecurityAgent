#!/usr/bin/env python3
"""Offline CybersecurityAgent coverage summary; no test execution or hardening."""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output-prefix", required=True)
    args = parser.parse_args()
    catalog, requirements, plan, evidence = (load(getattr(args, k)) for k in ("catalog", "requirements", "plan", "evidence"))
    tests = catalog.get("tests", [])
    reqs = requirements.get("requirements", [])
    entries = plan.get("entries", [])
    if not all(isinstance(x, list) for x in (tests, reqs, entries)):
        raise ValueError("Invalid catalog, requirements or plan structure")
    if evidence.get("artifact_type") != "local_threat_control_regression_evidence":
        raise ValueError("Expected locally registered evidence")
    if evidence.get("plan_sha256") != __import__("hashlib").sha256(Path(args.plan).read_bytes()).hexdigest():
        raise ValueError("Evidence does not match plan content")
    known = {x["test_id"] for x in tests}
    selected = set(evidence.get("selected_test_ids", []))
    if not selected.issubset(known):
        raise ValueError("Evidence references unknown catalog tests")
    plan_ids = {x["test_id"] for x in entries}
    if not selected.issubset(plan_ids):
        raise ValueError("Evidence references tests absent from plan")
    observed = evidence.get("observed_cases_per_test_id", {})
    passed = evidence.get("status") == "LOCAL_REGRESSION_PASSED_REVIEW_REQUIRED"
    rows = []
    for test in tests:
        tid = test["test_id"]
        cases = int(observed.get(tid, 0)) if tid in selected else 0
        status = ("LOCAL_PASSED_REVIEW_REQUIRED" if passed and cases > 0 else
                  "LOCAL_FAILED_OR_INCONCLUSIVE" if tid in selected else "NOT_EXECUTED")
        rows.append({"test_id": tid, "scenario_id": test.get("scenario_id", ""),
                     "domain": test.get("domain", ""), "stride": test.get("stride", ""),
                     "status": status, "observed_pytest_cases": cases,
                     "control_effectiveness": "NOT_VERIFIED"})
    counts = Counter(row["status"] for row in rows)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_type": "threat_control_coverage_summary",
        "proposed_scenarios": len({x.get("scenario_id") for x in tests if x.get("scenario_id")}),
        "proposed_requirements": len(reqs),
        "proposed_test_specifications": len(tests),
        "locally_passed_test_specifications": counts["LOCAL_PASSED_REVIEW_REQUIRED"],
        "local_failed_or_inconclusive": counts["LOCAL_FAILED_OR_INCONCLUSIVE"],
        "not_executed": counts["NOT_EXECUTED"],
        "observed_pytest_cases": sum(r["observed_pytest_cases"] for r in rows),
        "verified_security_controls": 0,
        "caveat": "Scenario-level requirement mappings are candidates, not verified traceability. Local regression success is not certification.",
        "evidence_path": args.evidence,
    }
    prefix = Path(args.output_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix(".json")
    csv_path = prefix.with_suffix(".csv")
    if json_path.exists() or csv_path.exists():
        raise FileExistsError("Use a new output prefix; reports are not overwritten")
    with json_path.open("x", encoding="utf-8") as f:
        json.dump({"summary": summary, "tests": rows}, f, indent=2)
    with csv_path.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else
                                ["test_id", "scenario_id", "domain", "stride", "status",
                                 "observed_pytest_cases", "control_effectiveness"])
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(summary, indent=2))
    print("Reports:", json_path, csv_path)

if __name__ == "__main__":
    main()
