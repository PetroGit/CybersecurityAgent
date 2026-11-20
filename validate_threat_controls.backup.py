"""Offline threat-control planning and explicitly approved, isolated pytest execution.

No LLM calls. No generated test candidates are automatically executable. Docker must
be installed separately; use a trusted, digest-pinned image with pytest available.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import uuid
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

NAME = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
TEST_ID = re.compile(r'^TM-\d{3,5}-TEST-\d{2,3}$')
SHA = re.compile(r'^[0-9a-f]{64}$')
IMAGE = re.compile(r'^[a-zA-Z0-9._:/-]+@sha256:[0-9a-f]{64}$')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_file(root, value, suffixes=('.json',), max_bytes=5_000_000):
    rel = Path(value)
    if not value or rel.is_absolute() or '..' in rel.parts or '\\' in value:
        raise ValueError('Use a repository-relative path without .. or backslashes')
    path = root / rel
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError('Unsafe or missing input: ' + value)
    if path.suffix not in suffixes or path.stat().st_size > max_bytes:
        raise ValueError('Invalid input type/size: ' + value)
    return path


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def selected_tests(catalog, ids):
    tests = catalog.get('tests')
    if not isinstance(tests, list):
        raise ValueError('Expected generated test catalog with tests array')
    found = {}
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get('test_id'), str):
            raise ValueError('Malformed test catalog entry')
        tid = test['test_id']
        if tid in found:
            raise ValueError('Duplicate test ID in catalog: ' + tid)
        found[tid] = test
    if not ids or len(ids) != len(set(ids)) or any(not TEST_ID.fullmatch(x) for x in ids):
        raise ValueError('Supply distinct valid --test-id values')
    if any(x not in found for x in ids):
        raise ValueError('Unknown test ID(s): ' + ', '.join(x for x in ids if x not in found))
    return [found[x] for x in ids]


def mapped_requirements(requirements, scenario_id):
    # Conservative scenario-level candidate mapping, NOT proof that a control implements the objective.
    return [r for r in requirements if r.get('scenario_id') == scenario_id]


def safe_output(root, name):
    if not NAME.fullmatch(name):
        raise ValueError('Invalid output name')
    parent = root / 'remediation'
    out = parent / 'control-validation'
    if parent.is_symlink() or out.is_symlink():
        raise ValueError('Output path is symlinked')
    out.mkdir(parents=True, exist_ok=True)
    if not out.resolve().is_relative_to(root):
        raise ValueError('Output escaped repository')
    return out


def dump_new(path, data):
    # Exclusive creation prevents accidental overwrite; no executable file contents.
    with path.open('x', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')


def plan(root, args):
    catalog_path = local_file(root, args.catalog)
    requirements_path = local_file(root, args.requirements)
    catalog = load_json(catalog_path)
    req_doc = load_json(requirements_path)
    requirements = req_doc.get('requirements')
    if not isinstance(requirements, list):
        raise ValueError('Expected requirements array')
    # Both must derive from the same original threat-model package.
    if not catalog.get('source_sha256') or catalog['source_sha256'] != req_doc.get('source_sha256'):
        raise ValueError('Catalog and requirements have different or missing source_sha256')
    chosen = selected_tests(catalog, args.test_id)
    out = safe_output(root, args.output_name)
    target = out / (args.output_name + '-plan.json')
    if target.exists() or target.is_symlink():
        raise FileExistsError('Plan already exists; use a fresh output name')
    entries = []
    candidates = out / (args.output_name + '-candidates')
    if candidates.exists() or candidates.is_symlink():
        raise FileExistsError('Candidate directory already exists')
    candidates.mkdir()
    for test in chosen:
        matches = mapped_requirements(requirements, test['scenario_id'])
        candidate = candidates / ('test_' + test['test_id'].lower().replace('-', '_') + '.py')
        objective = str(test.get('test_objective', ''))
        scaffold = ('"""REVIEW-ONLY candidate for ' + test['test_id'] + '.\n'
                    + 'Objective: ' + objective.replace('\n', ' ')[:400].replace('\"', '\u2019') + '\n'
                    + 'Not an implemented verification.\n"""\n'
                    + 'import pytest\n\n'
                    + 'def test_control_requires_implementation():\n'
                    + '    pytest.skip("Candidate only: implement assertions, fixtures and control mapping")\n')
        candidate.write_text(scaffold, encoding='utf-8')
        entries.append({
            'candidate_file': candidate.relative_to(root).as_posix(),
            'test_id': test['test_id'], 'scenario_id': test['scenario_id'],
            'domain': test.get('domain'), 'stride': test.get('stride'),
            'objective': test.get('test_objective'), 'expected_result': test.get('expected_result'),
            'preconditions': test.get('preconditions'),
            'candidate_control_mappings': [
                {'requirement_id': r.get('requirement_id'), 'proposed_control': r.get('security_requirement'),
                 'mapping_status': 'CANDIDATE_REQUIRES_REVIEW'} for r in matches],
            'automation_candidate': 'REQUIRES_FEASIBILITY_REVIEW',
            'procedure': {
                'preparation': 'Identify implemented control, owner, authorized target, and isolated fixture',
                'steps': 'Implement a deterministic offline pytest test; use mocks and controlled fixtures',
                'assertions': 'Assert both denied behavior and authorized behavior where applicable',
                'evidence': 'Collect pytest output, fixture configuration, observed policy decisions and code revision',
                'cleanup': 'Destroy ephemeral test state; preserve sanitized evidence'},
            'candidate_test_status': 'SPECIFICATION_ONLY_NOT_EXECUTABLE',
            'approved_test_file': None,
            'execution_status': 'NOT_EXECUTED',
        })
    data = {'schema_version': 1, 'artifact_type': 'threat_control_validation_plan',
            'created_at_utc': datetime.now(timezone.utc).isoformat(),
            'catalog_path': args.catalog, 'catalog_sha256': sha(catalog_path),
            'requirements_path': args.requirements, 'requirements_sha256': sha(requirements_path),
            'threat_model_source_sha256': catalog['source_sha256'],
            'review_required': True, 'entries': entries,
            'limitations': ['Candidate control mappings are scenario-level hypotheses',
                            'No test code generated, no tests executed, no controls verified']}
    dump_new(target, data)
    print(f'Validation plan: {target}; selected tests: {len(entries)}')
    print('Review-only pytest scaffolds generated (all SKIP); they cannot be approved directly for execution.')


def approved_test(root, value):
    path = local_file(root, value, suffixes=('.py',), max_bytes=200_000)
    rel = path.relative_to(root).as_posix()
    if not rel.startswith('tests/security_validation/') or not re.fullmatch(r'tests/security_validation/test_[A-Za-z0-9_]+\.py', rel):
        raise ValueError('Approved tests must be direct children of tests/security_validation/test_*.py')
    # Reject symlinked parent directories as well.
    if any((root / Path(*path.relative_to(root).parts[:i])).is_symlink()
           for i in range(1, len(path.relative_to(root).parts))):
        raise ValueError('Test path contains a symlink')
    return path, rel


def execute(root, args):
    if not args.approve_execution:
        raise ValueError('Execution requires --approve-execution')
    if not args.approval_file or not args.plan or not args.image:
        raise ValueError('Execution requires --plan, --approval-file, and --image')
    if not IMAGE.fullmatch(args.image):
        raise ValueError('Docker image must be pinned by sha256 digest')
    plan_path = local_file(root, args.plan)
    approval_path = local_file(root, args.approval_file)
    plan_data = load_json(plan_path)
    approval = load_json(approval_path)
    if plan_data.get('artifact_type') != 'threat_control_validation_plan':
        raise ValueError('Not a control validation plan')
    if approval.get('plan_sha256') != sha(plan_path) or approval.get('approved_image') != args.image:
        raise ValueError('Approval does not match exact plan hash or image')
    if approval.get('approved') is not True or not isinstance(approval.get('tests'), list):
        raise ValueError('Approval must explicitly authorize tests')
    selected = {x['test_id']: x for x in plan_data['entries']}
    approvals = {}
    for item in approval['tests']:
        if not isinstance(item, dict) or item.get('test_id') in approvals:
            raise ValueError('Malformed or duplicate approval entry')
        approvals[item['test_id']] = item
    chosen = []
    for tid in args.test_id:
        if tid not in selected or tid not in approvals:
            raise ValueError('Selected test is absent from approved plan: ' + tid)
        item = approvals[tid]
        path, rel = approved_test(root, item.get('file', ''))
        if item.get('sha256') != sha(path) or not SHA.fullmatch(item['sha256']):
            raise ValueError('Approved test hash does not match: ' + tid)
        chosen.append((tid, rel))
    if len(set(args.test_id)) != len(args.test_id):
        raise ValueError('Duplicate selected test ID')
    out = safe_output(root, args.output_name)
    result_path = out / (args.output_name + '-execution.json')
    if result_path.exists() or result_path.is_symlink():
        raise FileExistsError('Execution evidence already exists')
    # Check daemon availability before launching any test.
    probe = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                           capture_output=True, text=True, timeout=15, check=False)
    if probe.returncode != 0:
        raise RuntimeError('Docker daemon unavailable: ' + probe.stderr[:300])
    results = []
    for tid, rel in chosen:
        container_name = 'cyberagent-validation-' + uuid.uuid4().hex[:16]
        command = [
            'docker', 'run', '--rm', '--name', container_name, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '512m', '--cpus', '1',
            '--user', '65534:65534', '--workdir', '/workspace',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
            '--mount', f'type=bind,source={root},target=/workspace,readonly',
            '--entrypoint', 'python', args.image,
            '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', rel,
        ]
        started = datetime.now(timezone.utc).isoformat()
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=args.timeout_seconds, check=False)
            status = ('PASSED_REVIEW_REQUIRED' if proc.returncode == 0 and not re.search(r'\b\d+ skipped\b', proc.stdout)
                      else 'INCONCLUSIVE_SKIPPED' if proc.returncode == 0 else 'FAILED_OR_INCONCLUSIVE')
            record = {'test_id': tid, 'file': rel, 'started_at_utc': started,
                      'status': status, 'returncode': proc.returncode,
                      'stdout': proc.stdout[-12000:], 'stderr': proc.stderr[-6000:]}
        except subprocess.TimeoutExpired:
            # Clean up a container that might remain after a host-side timeout.
            subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=15, check=False)
            record = {'test_id': tid, 'file': rel, 'started_at_utc': started,
                      'status': 'TIMEOUT_CLEANUP_ATTEMPTED', 'returncode': None,
                      'stdout': '', 'stderr': 'Host timeout; inspect and clean up orphan containers'}
        results.append(record)
        if record['status'] != 'PASSED_REVIEW_REQUIRED':
            break
    evidence = {'schema_version': 1, 'artifact_type': 'threat_control_execution_evidence',
                'created_at_utc': datetime.now(timezone.utc).isoformat(),
                'plan_sha256': sha(plan_path), 'approval_sha256': sha(approval_path),
                'image': args.image, 'results': results,
                'limitations': ['pytest exit code does not establish control effectiveness',
                                'Manual review of assertions, environment and evidence is required',
                                'No external network; Docker daemon and trusted image are prerequisites']}
    dump_new(result_path, evidence)
    print('Execution evidence:', result_path)
    for record in results:
        print(record['test_id'], record['status'], record['returncode'])
    if len(results) != len(chosen) or any(r['status'] != 'PASSED_REVIEW_REQUIRED' for r in results):
        raise RuntimeError('One or more tests failed or timed out; inspect execution evidence')


def validation_main(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', default='.')
    p.add_argument('--action', choices=('plan', 'execute'), default='plan')
    p.add_argument('--catalog', help='Generated -test-catalog.json (plan)')
    p.add_argument('--requirements', help='Generated -requirements.json (plan)')
    p.add_argument('--test-id', action='append', required=True, help='Select a test ID; repeat to select more')
    p.add_argument('--output-name', required=True)
    p.add_argument('--plan', help='Approved validation plan (execute)')
    p.add_argument('--approval-file', help='JSON approval manifest (execute)')
    p.add_argument('--approve-execution', action='store_true')
    p.add_argument('--image', help='Trusted Docker image pinned by sha256 digest')
    p.add_argument('--timeout-seconds', type=int, default=120)
    args = p.parse_args(argv)
    if not 10 <= args.timeout_seconds <= 600:
        p.error('Timeout must be 10..600 seconds')
    root = Path(args.repo).resolve(strict=True)
    if not root.is_dir():
        p.error('Repository missing')
    if args.action == 'plan':
        if not args.catalog or not args.requirements:
            p.error('Plan requires --catalog and --requirements')
        plan(root, args)
    else:
        execute(root, args)


if __name__ == '__main__':
    import sys
    validation_main(sys.argv[1:])
