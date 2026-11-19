# CybersecurityAgent — Design-time threat modeling context

## System purpose
A security-assessment platform orchestrating Semgrep, AI-assisted triage, review-only remediation proposals, and independent Docker validation. No automatic merge or production deployment.

## Architecture and data flows
- Developer pushes source to GitHub; GitHub Actions scans with Semgrep.
- Scanner findings are converted to sanitized evidence for external Mistral triage.
- Optional source-aware Mistral remediation requires explicit disclosure approval.
- Optional local Ollama remediation is intended to keep source local.
- Generated tests and patches are validated in a temporary, network-disabled Docker workspace.
- Human reviewers decide whether to accept findings, patches, or pull requests.

## Assets and identities
- Proprietary source code and security findings
- Mistral API key, GitHub Actions token, developer credentials
- CI/CD runners, GitHub repository, local workstation and Ollama endpoint
- Generated remediation artifacts, audit evidence, Docker images

## Trust boundaries
- Developer workstation to GitHub repository
- GitHub Actions runner to external Mistral API
- Untrusted repository files and scanner findings to LLM prompt
- Host filesystem to Docker validation workspace
- Local orchestrator to Ollama HTTP service
- AI-generated proposals to human approval / pull-request process

## Security requirements and constraints
- No unapproved source disclosure to external models
- No automatic patch application, merge, or deployment
- Restrict secrets, network egress, filesystem access, and workflow permissions
- Maintain evidence integrity, traceability and audit records
- Prefer offline, reproducible security regression tests

## Unknowns to investigate
- GitHub organization branch protections and environment approvals
- Actual network controls enforcing loopback-only Ollama
- How source snippets are reviewed and approved for external disclosure
- Key rotation and credential storage arrangements
- Deployment environments and asset criticality

## Requested focus
IAM, PKI, network, data protection, web/API, mobile, MCP and agentic AI.
