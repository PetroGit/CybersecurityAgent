"""Build local source context and a strictly allowlisted Mistral evidence report."""

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote


RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
CWE_ID_PATTERN = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}
CONFIDENCES = {"LOW", "MEDIUM", "HIGH"}
SKIP_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", "node_modules"}
MAX_CONTEXT_LINES = 12
MAX_CALLER_SITES = 20
MAX_PROJECT_FILES = 2000

URL_SINK_PATTERNS = (
    (re.compile(r"\b(?:urllib\.request\.)?urlopen\s*\("), "urllib.request.urlopen"),
    (re.compile(r"\brequests\.(?:get|post|put|patch|delete|request)\s*\("), "requests"),
    (re.compile(r"\bhttpx\.(?:get|post|put|patch|delete|request)\s*\("), "httpx"),
    (re.compile(r"\baiohttp\.(?:get|post|put|patch|delete|request)\s*\("), "aiohttp"),
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build local-only source context and sanitized SAST evidence."
    )
    parser.add_argument("--semgrep-report", required=True, help="Semgrep JSON report.")
    parser.add_argument("--root", default=".", help="Repository root for local source lookup.")
    parser.add_argument("--sarif-report", help="Optional Semgrep SARIF report with data-flow traces.")
    parser.add_argument(
        "--local-report",
        default="local-evidence.json",
        help="Local report path; this may contain source excerpts and must not be uploaded.",
    )
    parser.add_argument(
        "--sanitized-report",
        default="mistral-evidence.json",
        help="Allowlisted evidence report suitable for Mistral.",
    )
    return parser.parse_args()


def load_json(path, description):
    try:
        with Path(path).open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read {description}: {exc}") from exc


def write_json(path, data):
    try:
        Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Could not write JSON report {path}: {exc}") from exc


def load_findings(report_path):
    report = load_json(report_path, "Semgrep report")
    if not isinstance(report, dict):
        raise RuntimeError("Semgrep report has an unexpected JSON format.")
    findings = report.get("results")
    errors = report.get("errors")
    if not isinstance(findings, list) or not isinstance(errors, list):
        raise RuntimeError("Semgrep report must contain results and errors arrays.")
    if errors:
        messages = "; ".join(
            error.get("message", str(error)) if isinstance(error, dict) else str(error)
            for error in errors
        )
        raise RuntimeError(f"Semgrep report contains scan errors: {messages}")
    if any(not isinstance(finding, dict) for finding in findings):
        raise RuntimeError("Semgrep report contains a malformed finding.")
    return findings


def _is_within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_source_path(raw_path, root):
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        resolved = None

    if resolved is not None and _is_within(resolved, root) and resolved.is_file():
        return resolved

    if Path(raw_path).is_absolute():
        parts = Path(raw_path).parts
        root_name = root.name
        matching_indexes = [
            index for index, part in enumerate(parts) if part.casefold() == root_name.casefold()
        ]
        if matching_indexes:
            relative_parts = parts[matching_indexes[-1] + 1 :]
            if relative_parts:
                try:
                    resolved = root.joinpath(*relative_parts).resolve(strict=True)
                except OSError:
                    return None
                if _is_within(resolved, root) and resolved.is_file():
                    return resolved
    return None


def _safe_line(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _enclosing_symbol(tree, line):
    candidates = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end_line = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end_line:
                candidates.append((end_line - node.lineno, node.name, node.lineno, end_line))
    if not candidates:
        return None
    _, name, start_line, end_line = min(candidates)
    return {"name": name, "start_line": start_line, "end_line": end_line}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _caller_sites(root, function_name):
    if not function_name:
        return {"sites": [], "complete": True, "files_scanned": 0}

    sites = []
    files_scanned = 0
    complete = True
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRECTORIES]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            files_scanned += 1
            if files_scanned > MAX_PROJECT_FILES:
                complete = False
                break
            try:
                source_path = (Path(directory) / filename).resolve()
            except (OSError, RuntimeError):
                continue
            if not _is_within(source_path, root):
                continue
            try:
                source = source_path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(source_path))
            except (OSError, SyntaxError):
                continue

            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and _call_name(node.func) == function_name
                    and len(sites) < MAX_CALLER_SITES
                ):
                    relative = source_path.relative_to(root).as_posix()
                    line = node.lineno
                    source_lines = source.splitlines()
                    excerpt = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    sites.append(
                        {
                            "path": relative,
                            "line": line,
                            "code": excerpt,
                        }
                    )
        if not complete:
            break
    return {"sites": sites, "complete": complete, "files_scanned": min(files_scanned, MAX_PROJECT_FILES)}


def _line_context(source, line):
    lines = source.splitlines()
    first = max(1, line - MAX_CONTEXT_LINES)
    last = min(len(lines), line + MAX_CONTEXT_LINES)
    excerpt = "\n".join(
        f"{number:5}: {lines[number - 1]}"
        for number in range(first, last + 1)
    )
    return {"start_line": first, "end_line": last, "code": excerpt}


def _contains_raise(statements):
    def contains_raise(node):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return False
        return any(contains_raise(child) for child in ast.iter_child_nodes(node))

    return any(contains_raise(statement) for statement in statements)


def _compare_attribute(condition, variable, attribute, expected):
    return (
        isinstance(condition, ast.Compare)
        and isinstance(condition.left, ast.Attribute)
        and isinstance(condition.left.value, ast.Name)
        and condition.left.value.id == variable
        and condition.left.attr == attribute
        and any(
            isinstance(operator, ast.NotEq)
            and isinstance(value, ast.Constant)
            and value.value == expected
            for operator, value in zip(condition.ops, condition.comparators)
        )
    )


def _condition_comparisons(condition):
    if isinstance(condition, ast.Compare):
        return [condition]
    return [node for node in ast.walk(condition) if isinstance(node, ast.Compare)]


def _url_control_checks(tree, line):
    if tree is None:
        return {
            "scheme_check_in_sink_function": "unknown",
            "host_allowlist_in_sink_function": "unknown",
            "path_check_in_sink_function": "unknown",
            "redirect_restriction": "unknown",
        }

    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= getattr(node, "end_lineno", node.lineno)
    ]
    if not functions:
        return {
            "scheme_check_in_sink_function": "unknown",
            "host_allowlist_in_sink_function": "unknown",
            "path_check_in_sink_function": "unknown",
            "redirect_restriction": "unknown",
        }
    function = min(
        functions,
        key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno,
    )

    sink_call = next(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and node.lineno == line
            and _call_name(node.func)
            in {"urlopen", "get", "post", "put", "patch", "delete", "request"}
        ),
        None,
    )
    if sink_call is None:
        return {
            "scheme_check_in_sink_function": "unknown",
            "host_allowlist_in_sink_function": "unknown",
            "path_check_in_sink_function": "unknown",
            "redirect_restriction": "unknown",
        }

    url_expression = sink_call.args[0] if sink_call.args else None
    if isinstance(url_expression, ast.Name) and _call_name(sink_call.func) == "urlopen":
        request_name = url_expression.id
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == request_name
                    for target in node.targets
                )
                and isinstance(node.value, ast.Call)
                and _call_name(node.value.func) == "Request"
                and node.value.args
            ):
                url_expression = node.value.args[0]
                break

    parsed_url_names = set()
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _call_name(node.value.func) == "urlsplit"
            and node.value.args
            and isinstance(url_expression, ast.Name)
            and isinstance(node.value.args[0], ast.Name)
            and node.value.args[0].id == url_expression.id
        ):
            parsed_url_names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )

    guard_ifs = [
        node for node in ast.walk(function)
        if isinstance(node, ast.If) and _contains_raise(node.body)
    ]
    scheme = any(
        _compare_attribute(condition, name, "scheme", "https")
        for node in guard_ifs
        for name in parsed_url_names
        for condition in _condition_comparisons(node.test)
    )
    host_allowlist = any(
        _compare_attribute(condition, name, "hostname", hostname)
        for node in guard_ifs
        for name in parsed_url_names
        for hostname in ("cwe.mitre.org", "app.opencve.io")
        for condition in _condition_comparisons(node.test)
    )

    path_match_names = set()
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _call_name(node.value.func) in {"fullmatch", "match"}
            and len(node.value.args) >= 2
            and isinstance(node.value.args[0], ast.Constant)
            and isinstance(node.value.args[0].value, str)
            and isinstance(node.value.args[1], ast.Attribute)
            and isinstance(node.value.args[1].value, ast.Name)
            and node.value.args[1].value.id in parsed_url_names
            and node.value.args[1].attr == "path"
        ):
            path_match_names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
    path_check = any(
        isinstance(condition.left, ast.Name)
        and condition.left.id in path_match_names
        and any(
            isinstance(operator, ast.Is)
            and isinstance(value, ast.Constant)
            and value.value is None
            for operator, value in zip(condition.ops, condition.comparators)
        )
        and _contains_raise(node.body)
        for node in ast.walk(function)
        if isinstance(node, ast.If)
        for condition in _condition_comparisons(node.test)
    )

    return {
        "scheme_check_in_sink_function": "detected" if scheme else "not_detected",
        "host_allowlist_in_sink_function": "detected" if host_allowlist else "not_detected",
        "path_check_in_sink_function": "detected" if path_check else "not_detected",
        "redirect_restriction": "unknown",
    }


def _parse_cwes(finding):
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
    if not isinstance(metadata, dict):
        return []
    raw_cwes = metadata.get("cwe", [])
    if isinstance(raw_cwes, str):
        raw_cwes = [raw_cwes]
    if not isinstance(raw_cwes, list):
        return []
    cwes = []
    for value in raw_cwes:
        if not isinstance(value, str):
            continue
        match = CWE_ID_PATTERN.search(value)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            if cwe_id not in cwes:
                cwes.append(cwe_id)
    return cwes


def _safe_enum(value, allowed):
    if not isinstance(value, str):
        return "UNKNOWN"
    normalized = value.upper()
    return normalized if normalized in allowed else "UNKNOWN"


def _safe_rule_id(value):
    return value if isinstance(value, str) and RULE_ID_PATTERN.fullmatch(value) else "unknown"


def _sink_type(finding, source_excerpt):
    extra = finding.get("extra", {})
    matched_line = extra.get("lines", "") if isinstance(extra, dict) else ""
    text = f"{matched_line}\n{source_excerpt}"
    for pattern, sink in URL_SINK_PATTERNS:
        if pattern.search(text):
            return sink
    return "unknown"


def _sarif_trace_index(sarif_path):
    if not sarif_path:
        return {}
    sarif = load_json(sarif_path, "Semgrep SARIF report")
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise RuntimeError("Semgrep SARIF report has an unexpected JSON format.")
    index = {}
    for run in sarif["runs"]:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            locations = result.get("locations", [])
            if (
                not isinstance(rule_id, str)
                or not isinstance(locations, list)
                or not locations
                or not isinstance(locations[0], dict)
            ):
                continue
            physical = locations[0].get("physicalLocation", {})
            if not isinstance(physical, dict):
                continue
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            if not isinstance(artifact, dict) or not isinstance(region, dict):
                continue
            uri = artifact.get("uri")
            line = _safe_line(region.get("startLine"))
            if isinstance(uri, str) and line is not None:
                key = (rule_id, Path(unquote(uri)).as_posix().casefold(), line)
                flows = result.get("codeFlows", [])
                index[key] = flows if isinstance(flows, list) else []
    return index


def _trace_for_finding(finding, root, source_path, trace_index):
    rule_id = finding.get("check_id")
    start = finding.get("start", {})
    line = _safe_line(start.get("line")) if isinstance(start, dict) else None
    relative = source_path.relative_to(root).as_posix()
    possible_paths = {relative.casefold(), Path(relative).as_posix().casefold()}
    for (trace_rule, trace_path, trace_line), flows in trace_index.items():
        if trace_rule == rule_id and trace_line == line and trace_path in possible_paths:
            return flows
    return []


def _flow_steps(code_flows):
    steps = []
    has_source = False
    has_sink = False
    for code_flow in code_flows:
        thread_flows = code_flow.get("threadFlows", []) if isinstance(code_flow, dict) else []
        for thread_flow in thread_flows:
            locations = thread_flow.get("locations", []) if isinstance(thread_flow, dict) else []
            for item in locations:
                location = item.get("location", {}) if isinstance(item, dict) else {}
                physical = location.get("physicalLocation", {})
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                kinds = location.get("kinds", [])
                if not isinstance(artifact, dict):
                    artifact = {}
                if not isinstance(region, dict):
                    region = {}
                if isinstance(kinds, list):
                    has_source |= "source" in kinds
                    has_sink |= "sink" in kinds
                snippet = region.get("snippet", {})
                message = location.get("message", {})
                steps.append(
                    {
                        "path": artifact.get("uri"),
                        "line": _safe_line(region.get("startLine")),
                        "kind": kinds if isinstance(kinds, list) else [],
                        "message": message.get("text") if isinstance(message, dict) else None,
                        "code": snippet.get("text") if isinstance(snippet, dict) else None,
                    }
                )
    return steps, has_source, has_sink


def build_reports(findings, root_path, sarif_path=None):
    root = Path(root_path).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"Source root is not a directory: {root}")
    trace_index = _sarif_trace_index(sarif_path)
    local_findings = []
    sanitized_findings = []

    for index, finding in enumerate(findings, start=1):
        raw_path = finding.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise RuntimeError(f"Finding {index} has no valid source path.")
        source_path = resolve_source_path(raw_path, root)
        if source_path is None:
            raise RuntimeError(
                f"Finding {index} source path could not be resolved inside the repository."
            )
        start = finding.get("start", {})
        line = _safe_line(start.get("line")) if isinstance(start, dict) else None
        if line is None:
            raise RuntimeError(f"Finding {index} has no valid source line.")

        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RuntimeError(f"Could not read finding source file: {exc}") from exc
        try:
            tree = ast.parse(source, filename=str(source_path))
        except SyntaxError:
            tree = None

        symbol = _enclosing_symbol(tree, line) if tree is not None else None
        symbol_source = ""
        if symbol:
            symbol_source = "\n".join(
                source.splitlines()[symbol["start_line"] - 1 : symbol["end_line"]]
            )
        context = _line_context(source, line)
        relative_path = source_path.relative_to(root).as_posix()
        callers = _caller_sites(root, symbol["name"] if symbol else None)
        code_flows = _trace_for_finding(finding, root, source_path, trace_index)
        steps, has_source, has_sink = _flow_steps(code_flows)
        trace_confirmed = bool(code_flows) and has_source and has_sink
        trace_status = "confirmed" if trace_confirmed else (
            "present_roles_unknown" if code_flows else "not_available"
        )

        extra = finding.get("extra", {})
        metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        local_finding = {
            "finding_id": f"SAST-{index:04d}",
            "source": {
                "path": relative_path,
                "line": line,
                "context": context,
                "enclosing_symbol": symbol,
                "enclosing_function_code": symbol_source,
                "caller_sites": callers,
                "python_parse": "ok" if tree is not None else "syntax_error",
            },
            "semgrep": {
                "rule_id": finding.get("check_id"),
                "severity": extra.get("severity") if isinstance(extra, dict) else None,
                "message": extra.get("message") if isinstance(extra, dict) else None,
                "matched_line": extra.get("lines") if isinstance(extra, dict) else None,
                "cwe_ids": _parse_cwes(finding),
                "confidence": metadata.get("confidence"),
            },
            "dataflow": {
                "status": trace_status,
                "source_to_sink_confirmed": True if trace_confirmed else "unknown",
                "input_origin": "semgrep_source" if has_source else "unknown",
                "steps": steps,
            },
            "url_controls": _url_control_checks(tree, line),
            "classification": "requires_further_investigation",
        }
        local_findings.append(local_finding)

        sink = _sink_type(finding, context["code"])
        severity = _safe_enum(extra.get("severity") if isinstance(extra, dict) else None, SEVERITIES)
        confidence = _safe_enum(metadata.get("confidence"), CONFIDENCES)
        sanitized_findings.append(
            {
                "finding_id": local_finding["finding_id"],
                "rule_id": _safe_rule_id(finding.get("check_id")),
                "severity": severity,
                "confidence": confidence,
                "cwe_ids": local_finding["semgrep"]["cwe_ids"],
                "sink_type": sink,
                "input_origin": local_finding["dataflow"]["input_origin"],
                "taint_path_confirmed": local_finding["dataflow"]["source_to_sink_confirmed"],
                "url_controls": local_finding["url_controls"],
                "local_validation": local_finding["classification"],
                "evidence_type": "local_static_analysis",
            }
        )

    local_report = {
        "schema_version": 1,
        "report_type": "local_source_evidence",
        "source_code_included": True,
        "findings": local_findings,
    }
    sanitized_report = {
        "schema_version": 1,
        "report_type": "mistral_allowlisted_evidence",
        "policy": {
            "source_code_included": False,
            "repository_paths_included": False,
            "secrets_included": False,
            "allowlist_enforced": True,
        },
        "findings": sanitized_findings,
    }
    return local_report, sanitized_report


def main():
    args = parse_args()
    try:
        findings = load_findings(args.semgrep_report)
        local_report, sanitized_report = build_reports(
            findings,
            args.root,
            args.sarif_report,
        )
        write_json(args.local_report, local_report)
        write_json(args.sanitized_report, sanitized_report)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Built local evidence for {len(findings)} finding(s); "
        "only allowlisted fields are present in the Mistral evidence report."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
