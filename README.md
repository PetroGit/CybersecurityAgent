# CybersecurityAgent
agent to detect vulnerabilities in the code repository or analyse the vulnerabilities from the devops pipeline via SAST / DAST and SCA tools and identify and test remediation in a sandbox
Mistral Large 4 (Le Chonk) enhances enterprise AI with advanced coding, cybersecurity, and document reasoning, while Mistral Studio provides a flexible platform for deploying agents, workflows, and apps across cloud, VPC, or on-premises environments. New features like managed agents, workflows, and enterprise context streamline business processes, enabling faster development and deployment of AI solutions. Customers like ABANCA and BNP Paribas already use Studio to automate tasks, improve efficiency, and maintain full control over their AI systems
Other possible models:
codestral-2508
codestral-latest
mistral-code-latest
mistral-code-fim-latest
deepseek-v4-1-flash-1017
glm-5-2
zai-glm-5-2
zai-glm-5-3
zai-glm-5
zai-glm-latest
zai-glm-5-3-flash
labs-leanstral-1-5-1
labs-leanstral-1-5
ministral-14b-2512
ministral-14b-latest
ministral-3b-2512
ministral-3b-latest
ministral-8b-2512
ministral-8b-latest
mistral-large-2512
mistral-large-latest
mistral-large-4
mistral-large-4-0
mistral-medium-latest
mistral-medium
mistral-medium-3-5
mistral-medium-3.5
mistral-medium-3
mistral-medium-2604
mistral-vibe-cli-latest
mistral-vibe-cli-with-tools
magistral-medium-latest
mistral-small-2603
mistral-small-latest
mistral-vibe-cli-fast
magistral-small-latest
voxtral-small-2507
voxtral-small-latest
codestral-embed
codestral-embed-2505
mistral-embed-2312
mistral-embed
mistral-moderation-2603
mistral-ocr-2512
mistral-ocr-3-0
mistral-ocr-3
mistral-ocr-latest
mistral-ocr-4
mistral-ocr-4-1
voxtral-mini-2602
voxtral-mini-latest
voxtral-mini-transcribe-3
voxtral-mini-transcribe-3-0
voxtral-mini-transcribe-realtime-2602
voxtral-mini-realtime-2602
voxtral-mini-realtime-latest
voxtral-mini-transcribe-realtime-3
voxtral-mini-transcribe-realtime-3-0
voxtral-small-transcribe-3
voxtral-small-transcribe-3-0
voxtral-mini-tts-2603
voxtral-mini-tts-latest
voxtral-mini-tts-3-0
voxtral-mini-tts-3

## Semgrep SAST

`sast_semgrep.py` runs Semgrep against a file or directory for static security
analysis. It reads the source code but does not execute it. Install the Semgrep
CLI using the supported instructions for your platform and ensure `semgrep` is
available on `PATH`.

Run a scan from PowerShell:

```powershell
python .\sast_semgrep.py .\src
```

By default, the script uses Semgrep's `p/security-audit` ruleset with metrics
disabled. Pass `--config` to use a different Semgrep ruleset or a local rules
file:

```powershell
python .\sast_semgrep.py .\src --config p/default
python .\sast_semgrep.py .\src --config .\semgrep-rules.yml
```

Semgrep's `auto` config requires metrics to be enabled. If you choose it, opt in
explicitly with `--config auto --metrics on`.

The script prints each finding's rule, severity, file, line, and message. In
GitHub Actions it also creates an annotation for each finding. Use
`--json-file report.json` to export findings and scan errors as structured JSON;
`--json-output` continues to write that JSON to standard output. It exits
with status `0` when no findings are reported, `1` when findings are reported,
and `2` when the scan cannot complete reliably.

## Semgrep findings with Mistral

`sast_mistral.py` can run Semgrep or consume an existing Semgrep JSON report. It
fetches MITRE CWE pages for CWE-tagged findings and asks Mistral to triage them
using Semgrep metadata and CWE text. It validates returned evidence quotes
against those sources. Source code is not sent to Mistral; its risk summary and
generic patch guidance are unverified, not source-specific, and require review.
Set `MISTRAL_API_KEY` before running it:

```powershell
python .\sast_mistral.py
python .\sast_mistral.py .\src\module.py
python .\sast_mistral.py . --semgrep-report .\semgrep-results.json --json-report .\mistral-triage.json
```

The default target is `test_mistral.py`. The `--config`, `--metrics`, and
`--timeout` options are passed to `sast_semgrep.py` when it runs a scan.

The GitHub Actions workflow `.github/workflows/sast-mistral.yml` runs Semgrep
on pushes to any branch and on pull requests targeting any branch. It uploads
`semgrep-results.json` as the `semgrep-results` artifact and annotates each
finding. Findings do not fail this reporting job; scan errors do.

Mistral triage runs only for pushes to `main` and manual runs started from
`main`, using the report from that run. To enable it, create a GitHub Actions
environment named `mistral-analysis`, add `MISTRAL_API_KEY` as an environment
secret, and restrict deployments to `main`. The triage job checks out `main`;
feature-branch and pull-request jobs never receive the Mistral secret. When
enabled, it uploads `mistral-triage.json` as the `mistral-triage` artifact.

## Validating and submitting a remediation

Author a remediation on a branch named `remediation/<short-name>` and push it.
Then run the **Validate security remediation PR** workflow from the `main`
branch, providing that branch name. It syntax-checks changed Python files and
rescans against `main`, failing if new Semgrep findings are introduced. This
repository has no safe automated test suite; `test_mistral.py` makes live
external-service calls and is not run as a patch test. A passing run opens a
pull request for human review and never merges it. Review the data flow,
remediation, and test coverage before approving or merging.

## Trivy SCA

`sca_trivy.py` uses Trivy's filesystem vulnerability scanner to inspect
dependency manifests and report the dependency targets and package inventory,
including packages without known vulnerabilities. It also reports severity,
advisory links, and fixed versions when available. It reads dependency metadata
but does not execute the application or its dependencies. Install the Trivy CLI
using the supported instructions for your platform and ensure `trivy` is
available on `PATH`.

Run it against the current directory or a selected project path:

```powershell
python .\sca_trivy.py
python .\sca_trivy.py .\path\to\project
python .\sca_trivy.py .\path\to\project --severity HIGH CRITICAL
```

Trivy may download or update its vulnerability database during the first scan.
The listed files are Trivy-reported dependency targets, not every file read
during filesystem traversal.
The script exits with status `0` when no vulnerabilities are reported, `1` when
findings are reported, and `2` when the scan cannot complete reliably.
