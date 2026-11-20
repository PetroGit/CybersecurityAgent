# CybersecurityAgent — Operating Procedure

**Source:** inspection of `CybersecurityAgent-main.zip` supplied 20 November 2026.  **Target environment:** Windows PowerShell, Python 3.13, Git, optional Docker Desktop. **Scope:** operating the existing code without changing or hardening the validation engines.

## 1. What is included

The archive contains the root Python scripts, two GitHub Actions workflows, `Dockerfile.validator`, `requirements.txt`, design context, generated threat models, remediation proposals, reports and test evidence. It does **not** include a `.git` directory, a Python virtual environment, Semgrep/Trivy binaries, a local Ollama installation, or a Mistral API credential.

| Component | Main files | Function |
|---|---|---|
| SAST | `sast_semgrep.py`, `sast_evidence.py`, `sast_mistral.py` | Semgrep findings, local evidence extraction, sanitized external Mistral triage |
| SCA | `sca_trivy.py` | Trivy dependency/vulnerability scan |
| Remediation proposals | `mistral_remote_remediation.py`, `local_remediation.py`, `hybrid_pipeline.py` | Review-only source-aware Mistral proposals or local Ollama proposals |
| Remediation validation | **root** `remediation_validator.py`, `Dockerfile.validator` | Evaluate proposal patches and tests in disposable Docker workspace |
| Threat modeling | `design_context.md`, `threat_artifacts.py`, `merge_threat_models.py` | STRIDE scenarios, requirements, test catalogs, consolidated models |
| Control validation | `validate_threat_controls.py`, `test_tm_004_controls.py`, `run_security_validation.py` | Plan, record local JUnit evidence, optional approved Docker execution |
| Reporting | `control_coverage_report.py`, `cybersecurity_dashboard.py` | JSON/CSV coverage report and read-only local web dashboard |
| CI/CD | `.github/workflows/sast-mistral.yml`, `sast-remediation-pr.yml` | GitHub scanning, Mistral triage, human-review remediation PR workflow |

**Important duplicate:** the archive also contains `remediation/remote-proposals/remediation_validator.py`, an older/different copy. The instructions below invoke **root** `remediation_validator.py`; do not assume the two are interchangeable. Backups named `*.backup.py` and `*.before-hardening.py` are historical snapshots, not entry points.

## 2. First-time setup

1. Extract `CybersecurityAgent-main.zip` to a local folder, e.g. `C:\Users\pjnav\PetroGit\CybersecurityAgent-main`. If using the existing Git clone instead, work in that repository root and do not overwrite newer local changes with the ZIP.
2. Open PowerShell in the project root. Install Python 3.13 and Git separately if needed. The archive itself is not a Git checkout; Git operations and `remediation_validator.py` require a real repository with `.git`.
3. Create a virtual environment and install the pinned API SDK:

```powershell
cd C:\Users\pjnav\PetroGit\CybersecurityAgent-main
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install pytest
```

`requirements.txt` pins **`mistralai==3.7.0` only**. `pytest` is an additional dependency for the local test runner. Semgrep and Trivy CLIs are separately required for their respective scans; verify their availability with `semgrep --version` and `trivy --version`. Docker Desktop is required only for Docker validation. The local Ollama path additionally needs an Ollama server, a compatible model and the Python `openai` client used by `local_remediation.py` (install separately if using that path).

4. For Mistral calls, set an API key **only in your local session**:

```powershell
$env:MISTRAL_API_KEY = Read-Host 'Mistral API key'
```

Do not commit credentials or upload source-containing local evidence. The source-aware remote-remediation path deliberately requires explicit approval before sending a selected source excerpt externally.

5. Confirm the command interfaces without contacting external services:

```powershell
python .\sast_semgrep.py --help
python .\mistral_remote_remediation.py --mode threat-model --help
python .\mistral_remote_remediation.py --mode validate-threat-controls --help
python .\cybersecurity_dashboard.py --help
```

## 3. Recommended starting point: inspect the existing results

The ZIP already includes a complete consolidated model and local TM-004 pilot evidence. You can use them without making any external API call or running Docker.

```powershell
python .\control_coverage_report.py `
  --catalog remediation/threat-models/cybersecurityagent-consolidated-v1-test-catalog.json `
  --requirements remediation/threat-models/cybersecurityagent-consolidated-v1-requirements.json `
  --plan remediation/control-validation/control-validation-pilot-v1-plan.json `
  --evidence remediation/control-validation/tm-004-local-evidence-v1-local-evidence.json `
  --output-prefix remediation/control-validation/coverage-report-v2
```

Use a **new** `--output-prefix`; the report generator refuses to overwrite existing files. The ZIP already contains `coverage-report-v1.json` and `.csv`.

Launch the dashboard:

```powershell
python .\cybersecurity_dashboard.py `
  --report remediation/control-validation/coverage-report-v1.json `
  --history-dir remediation/control-validation
```

Open `http://127.0.0.1:8765/` if it does not open automatically. The app listens on loopback, displays summary metrics, STRIDE/domain breakdowns, historical coverage, a filterable test inventory and CSV export. Keep PowerShell open; stop with `Ctrl+C`. For a new report, change `--report` to `coverage-report-v2.json` and restart. History picks up files matching `coverage-report*.json` in the selected folder.

**Current archived baseline:** 15 scenarios, 88 requirements, 69 proposed tests, 2 test specifications with local passing evidence, 9 passed pytest cases, 67 not executed, 0 independently verified controls. The evidence status is `LOCAL_REGRESSION_PASSED_REVIEW_REQUIRED`, **not approval**.

## 4. Workflow A — SAST scan and sanitized Mistral triage

1. Scan the intended target. For the repository root:

```powershell
python .\sast_semgrep.py . `
  --json-file semgrep-results.json `
  --sarif-file semgrep-dataflow.sarif
```

The documented Semgrep return codes are `0` (no findings), `1` (findings), `2` (scan error). A finding is not necessarily an exploitable vulnerability. The default ruleset is `p/security-audit`; it may need network access to retrieve rules. Use `--config` for a local rule file if available.

2. Create local source-aware evidence and a separate allowlisted report:

```powershell
python .\sast_evidence.py `
  --semgrep-report semgrep-results.json `
  --sarif-report semgrep-dataflow.sarif `
  --root . `
  --local-report local-evidence.json `
  --sanitized-report mistral-evidence.json
```

`local-evidence.json` can include source excerpts; keep it local. `mistral-evidence.json` is the intended metadata-only input for external triage.

3. Call Mistral for triage (requires `MISTRAL_API_KEY` and network access):

```powershell
python .\sast_mistral.py `
  --evidence-report mistral-evidence.json `
  --json-report mistral-triage.json
```

Review findings and confidence/limitations. This triage does not prove exploitability or apply patches.

4. Optional correlation with local Ollama:

```powershell
python .\hybrid_pipeline.py --repo . `
  --semgrep semgrep-results.json `
  --evidence mistral-evidence.json `
  --triage mistral-triage.json --dry-run
```

Remove `--dry-run` **only** after installing/configuring local Ollama and its dependencies. The hybrid orchestrator writes `remediation/hybrid-report.json` and may create proposals under `remediation/proposals/`. It does not automatically apply patches.

## 5. Workflow B — Trivy SCA

```powershell
python .\sca_trivy.py .
python .\sca_trivy.py . --severity HIGH CRITICAL
```

Trivy scans dependency metadata and reports known vulnerabilities. The CLI must be installed; its vulnerability database may require a first-time download. Documented exit codes are `0` no findings, `1` findings, `2` scanning error.

## 6. Workflow C — Review-only source-aware Mistral remediation

Inspect `semgrep-results.json` to choose a **zero-based** finding index and the corresponding repository-relative source path. The controller requires an explicit source allowlist and external-disclosure approval:

```powershell
python .\mistral_remote_remediation.py `
  --mode remediation `
  --repo . `
  --results semgrep-results.json `
  --finding 0 `
  --source test_mistral.py `
  --allow-file test_mistral.py `
  --approve-external-source
```

**Example only:** use `test_mistral.py` only when it is actually the file for finding index 0. This mode sends a bounded source excerpt and metadata to the Mistral API. Review the source before approving disclosure. Outputs are proposals under `remediation/remote-proposals/`, not applied patches.

Alternative local generation:

```powershell
python .\local_remediation.py `
  --repo . --results semgrep-results.json `
  --finding 0 --source test_mistral.py
```

The local path requires Ollama and the expected local model; it writes `remediation/proposals/finding-0001.md` for index 0.

## 7. Workflow D — Validate an AI remediation proposal in Docker

The **root** `remediation_validator.py` takes a proposal containing `ASSESSMENT`, `PATCH` and `SECURITY TESTS` sections. Its parser expects correctly formatted Git unified diffs in a fenced `diff` block or an explicit `PATCH_NOT_GENERATED` marker, and Python test blocks beginning with a `# tests/test_*.py` comment (or a `TESTS_NOT_GENERATED` marker, which cannot produce passing test evidence).

1. Use a genuine Git checkout (the ZIP alone has no `.git`).
2. Install/start Docker Desktop.
3. Build the local validator image:

```powershell
docker build -f Dockerfile.validator -t cybersecurityagent-validator:local .
```

4. Select a **reviewed** proposal and a fresh report filename. Example using the existing archived proposal:

```powershell
python .\remediation_validator.py `
  --repo . `
  --proposal remediation/remote-proposals/finding-0002.md `
  --report remediation/validation-0002-next.json `
  --image cybersecurityagent-validator:local `
  --mode auto
```

`--mode auto` selects `triage` if there is no patch, otherwise `remediation`. The validator copies project files to a temporary workspace, runs tests in Docker and, for a patch, attempts `git apply` **on that copy**, not the original working tree. With an optional repository-relative offline Semgrep YAML file passed via `--semgrep-config`, it can compare scanner findings before/after. A patch without that comparison may remain inconclusive.

Interpret the JSON report: `PASS` means technical checks passed but **does not authorize merge**; `TRIAGE_REVIEW_REQUIRED` means triage tests passed but classification still needs review; `FAIL` or `INCONCLUSIVE` requires investigation. The ZIP contains a prior `validation-0002-v4.json` with `TRIAGE_REVIEW_REQUIRED` and three passing triage tests; it is not a remediation approval.

**Important:** `remediation_validator.py` is **different** from `validate_threat_controls.py`. Do not use the remediation validator to certify STRIDE control effectiveness.

## 8. Workflow E — Threat modeling and requirements generation

`design_context.md` is the archived architectural input. Running a fresh model requires external Mistral disclosure approval and API access:

```powershell
python .\mistral_remote_remediation.py `
  --mode threat-model `
  --repo . `
  --design-context design_context.md `
  --approve-external-design `
  --output-name cybersecurityagent-threat-model-new
```

The controller writes JSON/Markdown under `remediation/threat-models/` and invokes `threat_artifacts.py` to produce security requirements, proposed test catalog, coverage-gap and review artifacts. Use a new name to avoid existing outputs. Validate assumptions and standard mappings manually.

Offline regeneration from an **existing** threat-model JSON:

```powershell
python .\mistral_remote_remediation.py `
  --mode threat-artifacts `
  --input remediation/threat-models/cybersecurityagent-threat-model-v3-test.json `
  --output-dir remediation/threat-models `
  --output-name regenerated-v3
```

To merge two existing models offline:

```powershell
python .\mistral_remote_remediation.py `
  --mode merge-threat-models `
  --repo . `
  --input remediation/threat-models/cybersecurityagent-threat-model-v3-test.json `
  --input remediation/threat-models/cybersecurityagent-stride-gaps-v1.json `
  --output-name consolidated-new
```

The ZIP already includes `cybersecurityagent-consolidated-v1.*`, so re-merging is optional. The merger checks design provenance; mismatched design hashes require explicit review and an optional flag documented in its help.

## 9. Workflow F — STRIDE control-test planning and evidence

Generate a **new** pilot plan from the consolidated catalog:

```powershell
python .\mistral_remote_remediation.py `
  --mode validate-threat-controls `
  --action plan --repo . `
  --catalog remediation/threat-models/cybersecurityagent-consolidated-v1-test-catalog.json `
  --requirements remediation/threat-models/cybersecurityagent-consolidated-v1-requirements.json `
  --test-id TM-004-TEST-01 `
  --test-id TM-004-TEST-03 `
  --output-name control-validation-pilot-v2
```

This creates a plan and **SKIP-only candidate scaffolds**, not executable security tests. The ZIP already contains the reviewed local regression file `test_tm_004_controls.py` and a previous plan.

For the archived TM-004 pilot, run the included Windows wrapper (it avoids a Python 3.13 Windows WMI crash encountered during JUnit finalization):

```powershell
python .\run_security_validation.py
Write-Host "Exit code: $LASTEXITCODE"
```

The wrapper runs nine pytest cases and writes `remediation/control-validation/evidence/tm-004-pilot-junit-v2.xml`. Confirm exit code `0` and the XML counts before recording evidence. To **record a new run**, use a new `--output-name`:

```powershell
python .\mistral_remote_remediation.py `
  --mode validate-threat-controls --action record --repo . `
  --plan remediation/control-validation/control-validation-pilot-v1-plan.json `
  --junit remediation/control-validation/evidence/tm-004-pilot-junit-v2.xml `
  --test-file test_tm_004_controls.py `
  --controller mistral_remote_remediation.py `
  --test-id TM-004-TEST-01 `
  --test-id TM-004-TEST-03 `
  --output-name tm-004-local-evidence-v2
```

The record is local, unapproved regression evidence. The separate `--action execute` mode is for **human-approved**, hash-bound test files under `tests/security_validation/`, with an approval JSON and digest-pinned Docker image. The ZIP contains no such approval manifest or ready-to-run approved test directory; do not treat its candidate scaffolds as approved tests.

After a new evidence record, generate a new coverage report by following §3 and changing `--evidence` and `--output-prefix` to the new filenames. The dashboard reads the coverage report, not the JUnit directly.

## 10. GitHub Actions

- **`.github/workflows/sast-mistral.yml`** runs Semgrep on pushes, pull requests and manual dispatch. It uploads Semgrep results and sanitized evidence. The Mistral triage job is limited to `main` push/manual dispatch, uses the `mistral-analysis` environment and its `MISTRAL_API_KEY` secret, and uploads the triage report.
- **`.github/workflows/sast-remediation-pr.yml`** is manually dispatched from `main` with an existing `remediation/<short-name>` branch. It checks changed Python syntax, scans for new Semgrep findings against `main`, and opens a pull request for human review. It does **not** merge automatically.

These workflows require a GitHub repository and appropriate Actions/environment configuration. The archive alone cannot run GitHub Actions. The README's statement that the repository has no safe automated test suite predates the bundled `test_tm_004_controls.py`; do not assume every test file is offline-safe (notably `test_mistral.py` performs external requests).

## 11. Typical operating cadence

**Daily / on code change:** run Semgrep and Trivy; inspect findings; optionally generate sanitized Mistral triage. **For selected findings:** request review-only remediation; independently review proposal; optionally validate in Docker. **On architecture change:** update `design_context.md`, generate/review a new threat model and its requirements. **On completed control tests:** record JUnit evidence, regenerate coverage JSON/CSV and reopen dashboard. **Before merging:** review evidence and use a human-approved PR; do not infer merge authorization from automated PASS.

## 12. Troubleshooting and operational notes

| Symptom | Likely cause / next step |
|---|---|
| `MISTRAL_API_KEY is not set` | Configure session environment variable for external Mistral steps |
| `semgrep` / `trivy` not recognized | Install respective CLI and verify `PATH` |
| `Docker daemon unavailable` | Start Docker Desktop and check `docker info` |
| `Repository must be a local Git working tree root` | ZIP extraction lacks `.git`; use an actual clone |
| `Plan already exists` / output file exists | Choose a new `--output-name` / report prefix |
| JUnit access violation on Windows Python 3.13 | Use the bundled `run_security_validation.py` wrapper for the pilot |
| Dashboard shows old counts | Regenerate coverage report and point dashboard to the new JSON; restart dashboard |
| `TRIAGE_REVIEW_REQUIRED` | Triage evidence is not proof of a false positive or an approved patch |
| Docker validation returns `INCONCLUSIVE` | Review generated JSON report and required offline scanner configuration |

## 13. Evidence and source of truth

The ZIP's `remediation/control-validation/tm-004-local-evidence-v1-local-evidence.json` records the archived pilot's SHA-256 values and selected test IDs. The associated JUnit has **9 tests, 0 failures, 0 errors, 0 skipped**. These are historical local evidence artifacts, not proof that a new machine or fresh checkout will reproduce the same result. The dashboard's `verified_security_controls` value remains **0** by design.

**No source files or validators were changed to prepare this procedure.**
