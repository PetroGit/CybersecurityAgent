#!/usr/bin/env python3
"""Fail-closed, Docker-isolated validator for untrusted AI remediation proposals.

Requires Docker, Git, and a prebuilt local validator image. Never applies to the
original repository. A PASS is technical evidence, NOT authorization to merge.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

FENCE = re.compile(r'(?m)^```([\w+.-]*)\s*\n(.*?)^```\s*$', re.S | re.M)
HEAD = re.compile(r'(?m)^#{1,3}\s+(ASSESSMENT|EXISTING CONTROLS|REMEDIATION(?: STRATEGY)?|PATCH|SECURITY TESTS|VALIDATION PLAN|LIMITATIONS|ASSUMPTIONS AND LIMITATIONS)\s*$')
PLACEHOLDER = re.compile(r'<(?:sanitizer_function|function_name|your_\w+)>|\b(?:TODO|FIXME|REPLACE_ME|YOUR_FUNCTION_HERE)\b|path/to/file\.py|\b(?:abc123|def456)\b|\.\.\.\s*(?:#.*)?$', re.I | re.M)
CONFIRMED = re.compile(r'(?im)^\s*(?:\*\*)?(?:classification|status)(?:\*\*)?\s*:\s*(?:\*\*)?CONFIRMED\b')
PROOF = re.compile(r'(?im)^\s*(?:\*\*)?(?:exploitability)(?:\*\*)?\s*:\s*(?:\*\*)?DEMONSTRATED\b')
MAX_OUTPUT = 5000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sections(text):
    hits = list(HEAD.finditer(text))
    result = {}
    for i, hit in enumerate(hits):
        key = hit.group(1).replace(' ', '_')
        if key in result:
            raise ValueError('Duplicate section: ' + key)
        result[key] = text[hit.end():hits[i + 1].start() if i + 1 < len(hits) else len(text)].strip()
    return result


def safe_rel(raw):
    if not raw or '\\' in raw or '\x00' in raw or raw.startswith(('/', './')) or re.match(r'^[A-Za-z]:', raw):
        raise ValueError('Invalid patch/test path: ' + repr(raw))
    path = PurePosixPath(raw)
    if any(part in ('.', '..', '.git', '.venv', '__pycache__') for part in raw.split('/')) or path.is_absolute():
        raise ValueError('Unsafe patch/test path: ' + raw)
    return str(path)


def parse_diff(patch):
    """Accept Git unified diffs only, with ordinary text-file modifications."""
    headers = re.findall(r'(?m)^diff --git a/(\S+) b/(\S+)\s*$', patch)
    if not headers:
        raise ValueError('Missing diff --git headers')
    if patch.count('diff --git ') != len(headers):
        raise ValueError('Malformed diff headers')
    paths = []
    for a, b in headers:
        if a != b:
            raise ValueError('Renames are not permitted')
        paths.append(safe_rel(a))
    if len(paths) != len(set(paths)):
        raise ValueError('Repeated target file')
    if re.search(r'(?m)^(?:new file mode|deleted file mode|rename |copy |old mode|new mode|GIT binary patch|Binary files|Submodule)', patch):
        raise ValueError('File creation/deletion, mode changes, renames and binary patches are forbidden')
    minus = re.findall(r'(?m)^--- a/(\S+)\s*$', patch)
    plus = re.findall(r'(?m)^\+\+\+ b/(\S+)\s*$', patch)
    if minus != paths or plus != paths:
        raise ValueError('Patch file headers do not match diff headers')
    if not re.search(r'(?m)^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@', patch):
        raise ValueError('No valid hunk headers')
    return paths


def extract(proposal):
    text = proposal.read_text(encoding='utf-8')
    parts = sections(text)
    if 'ASSESSMENT' not in parts or 'PATCH' not in parts or 'SECURITY_TESTS' not in parts:
        raise ValueError('Missing required assessment, patch or tests sections')
    if PLACEHOLDER.search(text):
        raise ValueError('Placeholder or invented patch/test marker detected')
    patch_section = parts['PATCH']
    diffs = [(lang, body) for lang, body in FENCE.findall(patch_section) if lang.lower() in ('diff', 'patch')]
    if len(diffs) > 1:
        raise ValueError('Multiple patch blocks not supported')
    patch = diffs[0][1] if diffs else None
    if patch is None and 'PATCH_NOT_GENERATED' not in patch_section:
        raise ValueError('No patch and no PATCH_NOT_GENERATED marker')
    tests = []
    for lang, code in FENCE.findall(parts['SECURITY_TESTS']):
        if lang.lower() not in ('python', 'py'):
            raise ValueError('Only Python regression tests supported by this validator')
        match = re.match(r'\s*#\s*(tests/[\w./-]+\.py)\s*\n', code)
        if not match:
            raise ValueError('Test code block must start with # tests/test_name.py')
        name = safe_rel(match.group(1))
        if not name.startswith('tests/test_') or not name.endswith('.py'):
            raise ValueError('Invalid test path')
        ast.parse(code, filename=name)
        tests.append((name, code))
    if not tests and 'TESTS_NOT_GENERATED' not in parts['SECURITY_TESTS']:
        raise ValueError('No executable tests or TESTS_NOT_GENERATED marker')
    if len({p for p, _ in tests}) != len(tests):
        raise ValueError('Duplicate test file')
    return text, parts, patch, tests


def run(argv, cwd=None, timeout=60, input_data=None, max_output=MAX_OUTPUT):
    try:
        result = subprocess.run(argv, cwd=cwd, input=input_data, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
        return {'exit_code': result.returncode, 'stdout': result.stdout[-max_output:] if max_output else result.stdout,
                'stderr': result.stderr[-MAX_OUTPUT:]}
    except subprocess.TimeoutExpired:
        return {'exit_code': None, 'error': 'TIMEOUT'}
    except OSError as exc:
        return {'exit_code': None, 'error': type(exc).__name__}


def copy_safe(src, dst):
    """Copy ordinary files only. Reject symlinks; never copy git metadata or secrets."""
    excluded = {'.git', '.venv', 'venv', 'node_modules', '.env', '__pycache__',
                'remediation', '.pytest_cache', '.mypy_cache', '.tox', 'dist', 'build'}
    count = total = 0
    for base, dirs, files in os.walk(src, followlinks=False):
        base = Path(base)
        dirs[:] = [d for d in dirs if d not in excluded and not (base / d).is_symlink()]
        for name in files:
            file = base / name
            if name in excluded or name.startswith('.env') or file.is_symlink() or not file.is_file():
                continue
            size = file.stat().st_size
            count += 1
            total += size
            if count > 3000 or total > 40_000_000 or size > 2_000_000:
                raise ValueError('Repository exceeds safe copy limits')
            target = dst / file.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
    return {'files': count, 'bytes': total}


def docker_cmd(image, workspace, command, timeout, max_output=MAX_OUTPUT):
    # Untrusted code executes only in this constrained container, never on host.
    argv = ['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '128',
            '--memory', '768m', '--cpus', '1', '--read-only',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--user', '65534:65534', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
            '--mount', f'type=bind,src={workspace},dst=/workspace',
            '--workdir', '/workspace', image, *command]
    return run(argv, timeout=timeout, max_output=max_output)


def semgrep_result(image, workspace, config, timeout):
    result = docker_cmd(image, workspace, ['semgrep', 'scan', '--config', config,
        '--json', '--metrics', 'off', '--disable-version-check', '--no-git-ignore', '.'], timeout, max_output=0)
    if result.get('exit_code') not in (0, 1):
        return result, None
    try:
        data = json.loads(result['stdout'])
        if data.get('errors'):
            return result, None
        fingerprints = {f"{item.get('check_id')}|{item.get('path')}|{item.get('start',{}).get('line')}" for item in data.get('results', [])}
        return result, fingerprints
    except (ValueError, TypeError):
        return result, None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', default='.')
    p.add_argument('--proposal', required=True)
    p.add_argument('--report', default='remediation/validation-report.json')
    p.add_argument('--image', default='cybersecurityagent-validator:local')
    p.add_argument('--semgrep-config', help='Repository-relative OFFLINE Semgrep YAML config')
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--mode', choices=('auto', 'remediation', 'triage'), default='auto',
                   help='auto validates patches or runs generated triage tests when no patch exists')
    args = p.parse_args()
    report = {'schema_version': 1, 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'INCONCLUSIVE', 'checks': {}, 'warnings': [],
              'original_repository_modified': False, 'human_approval_required': True}
    root = Path(args.repo).resolve()
    report_path = Path(args.report).resolve()
    try:
        if not root.is_dir() or not (root / '.git').exists():
            raise ValueError('Repository must be a local Git working tree root')
        proposal = Path(args.proposal).resolve()
        text, parts, patch, tests = extract(proposal)
        report['proposal_sha256'] = digest(text.encode('utf-8'))
        report['artifacts'] = {'assessment': parts['ASSESSMENT'],
            'patch_sha256': digest(patch.encode('utf-8')) if patch else None,
            'tests': [path for path, _ in tests]}
        if CONFIRMED.search(parts['ASSESSMENT']) or PROOF.search(parts['ASSESSMENT']):
            raise ValueError('Confirmed/demonstrated exploitability requires independent proof; refuse automatic validation')
        triage = not bool(patch)
        report['mode'] = 'triage' if triage else 'remediation'
        if args.mode != 'auto' and args.mode != report['mode']:
            raise ValueError(f'Proposal is {report["mode"]}, but --mode {args.mode} was requested')
        if triage:
            report['checks']['patch'] = 'NOT_GENERATED'
            report['warnings'].append('No patch supplied: only triage evidence can be evaluated')
        if not tests:
            report['checks']['tests'] = 'NOT_GENERATED'
            report['warnings'].append('No executable regression tests supplied')
            return 2
        paths = [] if triage else parse_diff(patch)
        for path in paths:
            src = root / path
            if not src.is_file() or src.is_symlink() or not src.resolve().is_relative_to(root):
                raise ValueError('Patch target missing, symlinked or outside repository: ' + path)
            if src.suffix != '.py':
                raise ValueError('Current validator supports Python patches only: ' + path)
        for name, _ in tests:
            target = root / name
            if target.exists():
                raise ValueError('Generated test would overwrite existing repository file: ' + name)
        if not shutil.which('docker') or not shutil.which('git'):
            raise ValueError('Docker and Git must be installed')
        image_check = run(['docker', 'image', 'inspect', args.image], timeout=15)
        if image_check['exit_code'] != 0:
            report['warnings'].append('Validator image missing; build Dockerfile.validator first')
            return 2
        if args.timeout < 10 or args.timeout > 600:
            raise ValueError('Timeout must be between 10 and 600 seconds')
        with tempfile.TemporaryDirectory(prefix='cybersecurityagent-validation-') as tmp:
            workspace = Path(tmp) / 'workspace'
            workspace.mkdir()
            report['checks']['copy'] = copy_safe(root, workspace)
            for path in paths:
                if not (workspace / path).is_file():
                    raise ValueError('Patch target not present in isolated copy')
            config = None
            if args.semgrep_config:
                config = safe_rel(args.semgrep_config)
                if not (workspace / config).is_file():
                    raise ValueError('Offline Semgrep configuration not present in workspace')
            if triage:
                # Only run the explicitly generated tests. Avoid collecting arbitrary
                # repository tests or importing source modules with import-time effects.
                for name, code in tests:
                    dest = workspace / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(code, encoding='utf-8')
                # Container uses a non-root UID and the workspace is a disposable copy.
                for directory, dirs, files in os.walk(workspace):
                    os.chmod(directory, 0o755)
                    for filename in files:
                        os.chmod(Path(directory) / filename, 0o644)
                syntax = docker_cmd(args.image, workspace,
                    ['python', '-c',
                     'import ast,sys,pathlib; [ast.parse(pathlib.Path(p).read_text(encoding="utf-8"), filename=p) for p in sys.argv[1:]]',
                     *[name for name, _ in tests]], args.timeout)
                report['checks']['triage_test_syntax'] = syntax
                if syntax.get('exit_code') != 0:
                    report['status'] = 'FAIL'
                    return 1
                pytest = docker_cmd(args.image, workspace,
                    ['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                     '--disable-warnings', *[name for name, _ in tests]], args.timeout)
                report['checks']['triage_pytest'] = pytest
                if pytest.get('exit_code') == 5:
                    report['warnings'].append('No triage tests collected')
                    return 2
                if pytest.get('exit_code') is None:
                    report['warnings'].append('Triage tests could not complete')
                    return 2
                if pytest.get('exit_code') != 0:
                    report['status'] = 'FAIL'
                    return 1
                report['status'] = 'TRIAGE_REVIEW_REQUIRED'
                report['warnings'].append('Passing generated tests do not prove a false positive; manually review full call graph and approve disposition')
                return 2
            # Run baseline scanner before applying the candidate, using the same config.
            if config:
                base, before = semgrep_result(args.image, workspace, config, args.timeout)
                report['checks']['semgrep_before'] = {'exit_code': base.get('exit_code'),
                    'finding_count': len(before) if before is not None else None,
                    'error': base.get('error')}
            else:
                before = None
                report['warnings'].append('No offline Semgrep config; scanner comparison unavailable')
            check = run(['git', 'apply', '--check', '--'], cwd=workspace,
                        input_data=patch, timeout=20)
            report['checks']['git_apply_check'] = check
            if check['exit_code'] != 0:
                report['status'] = 'FAIL'
                return 1
            applied = run(['git', 'apply', '--'], cwd=workspace,
                          input_data=patch, timeout=20)
            report['checks']['git_apply'] = applied
            if applied['exit_code'] != 0:
                report['status'] = 'FAIL'
                return 1
            for name, code in tests:
                dest = workspace / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(code, encoding='utf-8')
            # Non-root container user needs write access to copied temp tree.
            for directory, dirs, files in os.walk(workspace):
                os.chmod(directory, 0o777)
                for filename in files:
                    os.chmod(Path(directory) / filename, 0o666)
            syntax = docker_cmd(args.image, workspace,
                ['python', '-m', 'compileall', '-q', *paths, *[x for x, _ in tests]], args.timeout)
            report['checks']['syntax'] = syntax
            if syntax.get('exit_code') != 0:
                report['status'] = 'FAIL'
                return 1
            # Existing tests plus generated tests: pytest discovers all test_*.py files.
            pytest = docker_cmd(args.image, workspace,
                ['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--disable-warnings'], args.timeout)
            report['checks']['pytest'] = pytest
            if pytest.get('exit_code') not in (0, 5):
                report['status'] = 'FAIL'
                return 1
            if pytest.get('exit_code') == 5:
                report['warnings'].append('No tests collected')
                return 2
            if config:
                after_result, after = semgrep_result(args.image, workspace, config, args.timeout)
                report['checks']['semgrep_after'] = {'exit_code': after_result.get('exit_code'),
                    'finding_count': len(after) if after is not None else None,
                    'error': after_result.get('error')}
                if before is None or after is None:
                    report['warnings'].append('Semgrep comparison failed')
                    return 2
                added = sorted(after - before)
                removed = sorted(before - after)
                report['checks']['semgrep_delta'] = {'added': added, 'removed': removed}
                if added:
                    report['status'] = 'FAIL'
                    return 1
                if not removed:
                    report['warnings'].append('No scanner findings removed; may be a valid hardening-only patch')
            else:
                return 2
            report['status'] = 'PASS'
            report['warnings'].append('Technical PASS does not prove security or authorize application')
            return 0
    except (ValueError, SyntaxError, UnicodeError, OSError, KeyError, TypeError) as exc:
        report['status'] = 'FAIL' if isinstance(exc, (ValueError, SyntaxError)) else 'INCONCLUSIVE'
        report['checks']['validation_error'] = {'type': type(exc).__name__, 'message': str(exc)[:500]}
        return 1 if report['status'] == 'FAIL' else 2
    finally:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"Validation status: {report['status']}; report: {report_path}")


if __name__ == '__main__':
    sys.exit(main())
