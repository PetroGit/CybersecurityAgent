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

The script prints each finding's rule, severity, file, line, and message. It
exits with status `0` when no findings are reported, `1` when findings are
reported, and `2` when the scan cannot complete reliably.

## Semgrep findings with Mistral

`sast_mistral.py` runs the Semgrep wrapper, fetches MITRE CWE pages for
CWE-tagged findings, and asks Mistral to explain the finding using the
Semgrep metadata and CWE text. It validates each returned evidence quote
against those supplied sources. The scanned source code is not sent to Mistral.
Set `MISTRAL_API_KEY` before running it:

```powershell
python .\sast_mistral.py
python .\sast_mistral.py .\src\module.py
```

The default target is `test_mistral.py`. The `--config`, `--metrics`, and
`--timeout` options are also passed to `sast_semgrep.py`.
