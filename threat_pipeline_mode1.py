#!/usr/bin/env python3
"""Mode 1: orchestrate review-only threat modeling, catalog generation and planning.

No test execution, Docker, patch application or control verification.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

NAME = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

def run(repo, args):
    print('+', sys.executable, *args, flush=True)
    subprocess.run([sys.executable, *args], cwd=repo, check=True)

def relpath(root, path):
    path = Path(path)
    if path.is_absolute() or '..' in path.parts or '\\' in str(path):
        raise ValueError('Expected safe repository-relative path')
    full = root / path
    if not full.is_file() or full.is_symlink() or not full.resolve().is_relative_to(root):
        raise ValueError(f'Missing or unsafe file: {path}')
    return path.as_posix()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', default='.')
    ap.add_argument('--design-context', default='design_context.md')
    ap.add_argument('--output-name', required=True)
    ap.add_argument('--source-model', help='Existing threat model JSON; skips external API call')
    ap.add_argument('--approve-external-design', action='store_true',
                    help='Explicit authorization to transmit the approved design context')
    ap.add_argument('--max-scenarios', type=int, default=12)
    ap.add_argument('--plan-tests', type=int, default=3,
                    help='Number of test specifications to include in review-only plan (1-20)')
    ap.add_argument('--focus-stride', default=None)
    args = ap.parse_args()
    root = Path(args.repo).resolve(strict=True)
    if not root.is_dir() or not NAME.fullmatch(args.output_name):
        ap.error('Invalid repository or output name')
    if not 1 <= args.plan_tests <= 20:
        ap.error('--plan-tests must be 1..20')
    if not 1 <= args.max_scenarios <= 30:
        ap.error('--max-scenarios must be 1..30')
    if args.source_model and args.approve_external_design:
        ap.error('Do not specify external disclosure approval in offline source-model mode')
    if not args.source_model and not args.approve_external_design:
        ap.error('Fresh Mistral modeling requires --approve-external-design')
    if not args.source_model and not os.getenv('MISTRAL_API_KEY'):
        ap.error('MISTRAL_API_KEY is required for fresh Mistral modeling')

    model_dir = root / 'remediation' / 'threat-models'
    validation_dir = root / 'remediation' / 'control-validation'
    name = args.output_name
    plan_name = name + '-plan'
    summary_path = validation_dir / (name + '-mode1-summary.json')
    if summary_path.exists() or summary_path.is_symlink():
        raise FileExistsError(f'Summary exists: {summary_path}')

    if args.source_model:
        source = relpath(root, args.source_model)
        # Offline: retain the original model JSON, generate a fresh catalog named by this run.
        model = json.loads((root / source).read_text(encoding='utf-8-sig'))
        if model.get('artifact_type') != 'design_time_threat_model':
            raise ValueError('Source must be a design_time_threat_model JSON')
        domains = model.get('requested_domains')
        if not isinstance(domains, list) or not domains:
            raise ValueError('Source model has no requested_domains')
        run(root, ['threat_artifacts.py',
                   '--input', source, '--output-dir', 'remediation/threat-models',
                   '--output-name', name, '--domains', ','.join(domains)])
        model_path = source
    else:
        design = relpath(root, args.design_context)
        cmd = ['mistral_remote_remediation.py', '--mode', 'threat-model', '--repo', '.',
               '--design-context', design, '--approve-external-design',
               '--max-scenarios', str(args.max_scenarios), '--output-name', name]
        if args.focus_stride:
            cmd += ['--focus-stride', args.focus_stride]
        run(root, cmd)
        model_path = f'remediation/threat-models/{name}.json'

    catalog_path = f'remediation/threat-models/{name}-test-catalog.json'
    requirements_path = f'remediation/threat-models/{name}-requirements.json'
    catalog = json.loads((root / catalog_path).read_text(encoding='utf-8-sig'))
    requirements = json.loads((root / requirements_path).read_text(encoding='utf-8-sig'))
    tests = catalog.get('tests')
    reqs = requirements.get('requirements')
    if not isinstance(tests, list) or not isinstance(reqs, list):
        raise ValueError('Unexpected generated catalog schema')
    selected = [x['test_id'] for x in tests[:args.plan_tests]]
    if len(set(selected)) != len(selected):
        raise ValueError('Duplicate selected test IDs')
    plan_path = None
    if selected:
        cmd = ['validate_threat_controls.py',
               '--action', 'plan', '--repo', '.', '--catalog', catalog_path,
               '--requirements', requirements_path, '--output-name', plan_name]
        for tid in selected:
            cmd += ['--test-id', tid]
        run(root, cmd)
        plan_path = f'remediation/control-validation/{plan_name}-plan.json'
    model_doc = json.loads((root / model_path).read_text(encoding='utf-8-sig'))
    summary = {
        'artifact_type': 'mode1_threat_pipeline_summary',
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'mode': 'offline-existing-model' if args.source_model else 'remote-mistral',
        'source_model': model_path,
        'source_model_sha256': hashlib.sha256((root / model_path).read_bytes()).hexdigest(),
        'test_catalog': catalog_path,
        'requirements': requirements_path,
        'validation_plan': plan_path,
        'scenario_count': len(model_doc.get('threat_model', {}).get('scenarios', [])),
        'requirement_count': len(reqs),
        'test_specification_count': len(tests),
        'planned_test_specifications': selected,
        'tests_executed': 0,
        'verified_controls': 0,
        'review_required': True,
        'notes': 'Candidate specifications and skip-only scaffolds; no runtime tests or control verification.'
    }
    validation_dir.mkdir(parents=True, exist_ok=True)
    with summary_path.open('x', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
        f.write('\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
