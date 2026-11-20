#!/usr/bin/env python3
"""CI adapter for existing CybersecurityAgent remote remediation and validator.

Explicit allowlist only; review-only; no source changes or PR creation.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def run(command, timeout):
    print('Executing:', ' '.join(command), flush=True)
    try:
        result = subprocess.run(command, timeout=timeout, check=False)
        return result.returncode
    except subprocess.TimeoutExpired:
        print('Step timed out', file=sys.stderr)
        return 124


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results', default='semgrep-results.json')
    p.add_argument('--allow-file', action='append', required=True)
    p.add_argument('--max-findings', type=int, default=3)
    p.add_argument('--validate', action='store_true')
    p.add_argument('--validator', default='remediation/remote-proposals/remediation_validator.py')
    p.add_argument('--image', default='cybersecurityagent-validator:local')
    p.add_argument('--summary', default='remediation/ci-remote-summary.json')
    args = p.parse_args()
    if not 1 <= args.max_findings <= 20:
        p.error('--max-findings must be 1..20')
    root = Path.cwd().resolve()
    data = json.loads(Path(args.results).read_text(encoding='utf-8'))
    findings = data.get('results')
    if not isinstance(findings, list):
        raise ValueError('Semgrep JSON must contain results list')
    allow = set()
    for item in args.allow_file:
        path = Path(item)
        resolved = (root / path).resolve()
        if not resolved.is_file() or not resolved.is_relative_to(root):
            raise ValueError(f'Allowlisted file missing or outside repository: {item}')
        allow.add(resolved.relative_to(root).as_posix())
    selected = []
    for index, finding in enumerate(findings):
        rel = finding.get('path', '').replace('\\', '/')
        if rel.startswith('./'):
            rel = rel[2:]
        if rel in allow:
            selected.append((index, rel))
        if len(selected) >= args.max_findings:
            break
    summary = {'selected': len(selected), 'total_findings': len(findings), 'results': []}
    Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
    for index, rel in selected:
        proposal = Path(f'remediation/remote-proposals/finding-{index+1:04d}.md')
        command = [sys.executable, 'mistral_remote_remediation.py', '--mode', 'remediation',
                   '--repo', '.', '--results', args.results, '--finding', str(index),
                   '--source', rel, '--allow-file', rel, '--approve-external-source']
        rc = run(command, 420)
        record = {'finding_index': index, 'source': rel, 'remediation_exit': rc,
                  'proposal': str(proposal) if proposal.is_file() and rc == 0 else None}
        if args.validate and rc == 0 and proposal.is_file():
            report = f'remediation/ci-validation-{index+1:04d}.json'
            validation = [sys.executable, args.validator, '--repo', '.', '--proposal',
                          str(proposal), '--report', report, '--image', args.image]
            record['validation_exit'] = run(validation, 900)
            record['validation_report'] = report
        summary['results'].append(record)
        Path(args.summary).write_text(json.dumps(summary, indent=2), encoding='utf-8')
    if not selected:
        print('No Semgrep findings matched the explicit source allowlist.')
    print(json.dumps(summary, indent=2))
    return 1 if any(x['remediation_exit'] != 0 for x in summary['results']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
