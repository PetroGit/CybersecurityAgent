# Design-time threat model (review required)

> AI-generated threat hypotheses, not verified vulnerabilities or a compliance assessment.

**Scope:** Design-time, review-only threat model for the CybersecurityAgent assessment platform. The supplied design description is treated as untrusted data. Focus is limited to STRIDE Repudiation and Denial of Service across the selected domains; no runtime testing, control verification, or framework-page retrieval is claimed.

## Architecture summary
GitHub-hosted source is scanned by GitHub Actions using Semgrep; findings are sanitized for optional external Mistral triage and optional local Ollama remediation; generated tests/patches are validated in a temporary network-disabled Docker workspace; humans decide acceptance of findings, patches, and pull requests. No automatic merge or production deployment is described.

## Assets
- Proprietary source code and security findings
- Sanitized evidence and disclosure-approval records
- Mistral API key, GitHub Actions token, developer credentials
- CI/CD runners, GitHub repository and approval state
- Local workstation and Ollama HTTP endpoint
- Generated remediation artifacts, tests, patches, and audit evidence
- Docker images and temporary validation workspace

## Trust boundaries
- Developer workstation to GitHub repository
- GitHub Actions runner to external Mistral API
- Untrusted repository files and scanner findings to LLM prompt
- Host filesystem to Docker validation workspace
- Local orchestrator to Ollama HTTP service
- AI-generated proposals to human approval / pull-request process

## Assumptions
- The design text is untrusted and no security control is assumed implemented unless explicitly stated, which it is not.
- TLS to external APIs is plausible but not specified; certificate pinning, revocation checking, and PKI details are unknown.
- GitHub Actions permissions, branch protections, and environment approvals are unknown.
- Ollama may be HTTP on loopback, but enforcement of loopback-only access and egress allowlists is unknown.
- Human approval is assumed to occur through pull-request review, but audit-log immutability, commit signing, and identity binding are not specified.
- The mcp domain was requested, so tool/MCP-style orchestration is treated as possible even though no MCP server is explicitly described.
- No mobile application is described in the design.
- No runtime tests were executed and no evidence was collected.

## Open questions
- What GitHub organization branch protections, required reviewers, and environment approvals are configured?
- What network controls enforce loopback-only Ollama and restrict egress from runners and workstations?
- How are source snippets reviewed and approved before external disclosure to Mistral, and are those approvals non-repudiable?
- How are Mistral API keys, Actions tokens, and developer credentials stored, rotated, scoped, and revoked?
- Are approval, prompt, tool-call, model-output, and API-usage events written to append-only, time-synchronized, integrity-protected audit logs?
- What rate limits, quotas, timeouts, retry budgets, and circuit breakers apply to Mistral, GitHub APIs, and Ollama?
- What CPU, memory, disk, network, and time limits apply to the temporary Docker validation workspace?
- Do MCP or other tool endpoints exist, and what authentication, authorization, and call budgets protect them?
- What PKI is used for API/TLS authentication, artifact signing, or commit signing, including pinning and revocation behavior?
- Are there mobile clients or mobile-specific trust boundaries not present in the supplied design?
- What deployment environments exist and what is the criticality of each asset?

## TM-001: Repudiation of privileged review and workflow actions

**Domain:** iam | **STRIDE:** Repudiation | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Compromised developer or approver account, misused GitHub Actions token, or malicious insider
**Asset:** GitHub repository approval state, audit evidence, generated remediation artifacts
**Trust boundary:** AI-generated proposals to human approval / pull-request process; developer workstation to GitHub repository

**Attack hypothesis:** If approval and workflow events are not immutably bound to strongly authenticated identities, an actor could approve or alter remediation artifacts and later credibly deny the action, leaving the review trail unable to establish who decided what.

### Preconditions
- Branch protections, required reviewers, and environment approvals are unknown
- Approval and workflow events may not be append-only or cryptographically bound to authenticated identities
- Short-lived least-privilege tokens, MFA for approvers, and commit/PR signing are not confirmed

### Attack-tree path
- Obtain or misuse an approver identity or Actions token
- Bypass or find absence of branch protection or environment approval
- Approve, reject, or alter review decisions and remediation artifacts
- Later deny the action because audit records do not establish attribution

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Require phishing-resistant MFA and least-privilege, short-lived tokens for approvers and workflow identities.
- Enforce branch protections, required reviews, and environment approvals with separation of duties.
- Write approval, merge, reject, and artifact-creation events to append-only audit logs with synchronized time and integrity protection.
- Bind approvals to signed commits or signed review artifacts where supported.
- Alert on anomalous approval patterns and require re-authentication for high-impact actions.

### Testable acceptance criteria
- A non-approver or token-scoped identity attempting to approve a protected branch is denied and the denial is logged.
- Any attempt to modify or delete an approval audit record outside the audit service is denied and generates an alert.
- A review decision can be cryptographically tied to an authenticated identity and timestamp in the audit export.
- Revocation of an approver credential prevents further approvals after revocation propagation.

### Evidence gaps
- Actual GitHub branch protections and environment approval settings are unknown.
- Audit-log storage, retention, immutability, and clock synchronization are unspecified.
- Commit/PR signing and approval identity binding are not described.

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [ISO_27001](https://www.iso.org/standard/27001)

## TM-002: Repudiation of evidence provenance and external-disclosure approval

**Domain:** data | **STRIDE:** Repudiation | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Pipeline actor with write access to evidence storage, compromised CI runner, or a party disputing whether source was disclosed externally
**Asset:** Sanitized scanner evidence, proprietary source snippets, security findings, disclosure-approval records
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If sanitized evidence, disclosure approvals, and outbound LLM requests are not integrity-protected and correlated, an actor could later deny that a particular source-derived snippet was sent to an external model or who approved it.

### Preconditions
- Evidence sanitization and external-disclosure approval steps may lack signed, append-only records
- Prompt contents, egress requests, and API responses may not be logged with integrity and correlation IDs
- Reviewer identity and approval decision may not be bound to the exact disclosed snippet hash

### Attack-tree path
- Untrusted repository content or scanner finding enters the pipeline
- Sanitization or disclosure-approval step occurs without a signed, append-only record
- Evidence, approval, or egress logs are altered, deleted, or never correlated
- It becomes impossible to prove who approved disclosure of which source-derived data

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Record hashes of inputs, sanitized evidence, prompts, model versions, and approval decisions in an append-only audit trail.
- Require explicit, identity-bound, non-repudiable approval before any source-aware disclosure to an external model.
- Log outbound API requests and responses with redaction, retention, and integrity protection.
- Separate evidence storage from CI runner write access and restrict log mutation to an audit service.
- Include disclosure decisions in reproducible evidence packages reviewed by humans.

### Testable acceptance criteria
- For a sample external-disclosure approval, the audit export shows approver identity, timestamp, input hash, prompt hash, and destination without gaps.
- Modifying or deleting a historical evidence record as a pipeline identity is denied and alerted.
- A disclosure attempt without an approval record fails closed and is logged.
- A replayed or altered approval token cannot authorize a second disclosure.

### Evidence gaps
- The source-snippet review and approval process for external disclosure is listed as unknown.
- No evidence of prompt/egress logging, hashing, or append-only audit storage is supplied.
- Credential storage and key rotation arrangements are unknown.

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [ISO_27001](https://www.iso.org/standard/27001)

## TM-003: Repudiation of model-assisted triage, tool actions, and remediation proposals

**Domain:** agentic-ai | **STRIDE:** Repudiation | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Malicious repository contributor, prompt-injection-driven agent behavior, or compromised orchestrator session
**Asset:** LLM prompts and outputs, tool-call traces, Mistral/Ollama API usage logs, generated patches and tests
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; local orchestrator to Ollama HTTP service; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If agent prompts, tool invocations, model outputs, and resulting proposals are not immutably attributed to a session, input, model version, and actor, a party could deny that the agent disclosed data, selected a finding, or generated a specific patch.

### Preconditions
- LLM sessions may not log prompts, tool calls, model outputs, and decisions with integrity and attribution
- Model version, system prompt, and policy version may not be recorded per action
- Generated proposals may not be bound to the input finding, session ID, or approving human

### Attack-tree path
- Untrusted input reaches an LLM-orchestrated triage or remediation step
- Agent performs tool calls, external API calls, or generates proposals
- Session records are incomplete, mutable, or not tied to an authenticated actor
- The actor or session later denies the model-assisted action or disclosure

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Log every model call with session ID, actor, input hash, system prompt hash, model version, tool calls, outputs, and downstream actions in append-only storage.
- Require human approval records that reference the exact generated artifact hash before any PR or remediation use.
- Bind external API usage and local Ollama calls to an authenticated orchestrator identity and policy decision.
- Apply least privilege to agent tools and separate read-only triage from write-capable remediation tools.
- Establish AI incident governance so model-assisted decisions are reviewable and attributable.

### Testable acceptance criteria
- For a sampled generated patch, the audit trail links finding ID, input hash, prompt/model version, tool calls, artifact hash, and human approval.
- Deleting or editing a model-call log entry as the orchestrator service account is denied and alerted.
- An unapproved generated artifact cannot be referenced by a pull request in the review workflow.
- Changing the model version or system prompt creates a new policy/audit context rather than overwriting history.

### Evidence gaps
- No LLM session logging, prompt hashing, model versioning, or tool-call audit spec is provided.
- No approval-to-artifact binding mechanism is described.
- Whether external Mistral usage and local Ollama usage are logged with the same rigor is unknown.

### Framework references (entry pages; precise mappings not independently verified)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [ISO_42001](https://www.iso.org/standard/42001)
- [OECD_AI_PRINCIPLES](https://www.oecd.org/en/topics/ai-principles.html)

## TM-004: Denial of service through untrusted input resource exhaustion in AI triage

**Domain:** agentic-ai | **STRIDE:** Denial of Service | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** Attacker-controlled repository content, malicious dependency, or crafted scanner finding designed to exhaust model or compute resources
**Asset:** CI/CD runners, Mistral API quota, local Ollama endpoint and workstation, triage pipeline availability
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service

**Attack hypothesis:** Crafted inputs could cause oversized contexts, repeated retries, long generations, or heavy local inference, stalling the triage pipeline or exhausting paid API quota if budgets and timeouts are not enforced.

### Preconditions
- Sanitization may not cap input size, token count, file count, nesting, or repetition
- No per-job token budget, timeout, retry limit, or queue isolation is confirmed
- Local Ollama inference load and external API rate limits are unknown

### Attack-tree path
- Attacker-controlled repository content or finding reaches scanner or LLM prompt
- Sanitizer fails to bound context size, complexity, or number of derived prompts
- Mistral API or local Ollama performs large generations, retries, or long inference
- CI job, queue, API quota, or workstation becomes unavailable to legitimate work

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Enforce maximum input size, token count, file count, and prompt depth before any LLM call.
- Set per-job and per-run budgets for tokens, API calls, wall-clock time, retries, and concurrency.
- Use timeouts, exponential backoff, circuit breakers, and queue isolation for external model calls.
- Prefer local/offline models for untrusted content where feasible and cap local inference CPU, memory, and concurrency.
- Reject or quarantine pathological inputs detected by deterministic checks before model invocation.

### Testable acceptance criteria
- A test repository containing an oversized or highly repetitive finding is rejected before an external LLM call and the rejection is logged.
- A job exceeding configured token/time/API-call budgets is terminated automatically and reported.
- When Mistral is unavailable or rate-limited, the pipeline fails closed or falls back to a queued/offline path without blocking other jobs.
- Local Ollama inference for untrusted content cannot exceed configured CPU/memory/concurrency limits.

### Evidence gaps
- No sanitizer limits, token budgets, retry policies, or queue design are specified.
- Mistral quota/rate-limit handling and Ollama resource limits are unknown.
- Whether untrusted content can reach the external model without deterministic pre-filtering is not evidenced.

### Framework references (entry pages; precise mappings not independently verified)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-005: Denial of service through assumed tool/MCP-style validation loops

**Domain:** mcp | **STRIDE:** Denial of Service | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** Medium
**Threat actor:** Untrusted model output or repository content that reaches assumed tool orchestration and triggers repeated validation work
**Asset:** Docker validation workspace, CI/CD runner time, orchestrator tool endpoints, generated test/patch artifacts
**Trust boundary:** Host filesystem to Docker validation workspace; AI-generated proposals to human approval / pull-request process

**Attack hypothesis:** If tool-style orchestration allows model-influenced repeated Docker validation without resource caps or idempotency, untrusted content could keep the validator busy and deny service to legitimate remediation review.

### Preconditions
- The mcp domain was requested, but no MCP server or tool schema is explicitly described in the design
- Generated tests/patches are executed in temporary Docker, but CPU, memory, disk, network, and time limits are unknown
- No tool-call budget, idempotency key, recursion depth limit, or approval gate for repeated validation is confirmed

### Attack-tree path
- Untrusted repository content influences model-generated tool calls or validation requests
- Tool results or proposed tests lack idempotency and recursion limits
- Repeated or nested Docker validation jobs are spawned
- Runner CPU, memory, disk, or job time is exhausted and validation becomes unavailable

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Treat any MCP/tool endpoint as a trust boundary requiring authentication, authorization, and per-caller call budgets.
- Limit tool recursion depth, concurrency, idempotency-key reuse, and maximum jobs per finding.
- Run validation in network-disabled containers with explicit CPU, memory, disk, pids, and wall-clock limits.
- Require deterministic pre-checks and human approval before expensive validation of generated artifacts.
- Quarantine validation workspaces and prevent host filesystem access beyond the declared mount.

### Testable acceptance criteria
- A tool-call sequence that exceeds configured depth, count, or duplicate idempotency key is rejected and logged.
- A validation container attempting network egress or exceeding resource limits is killed and reported.
- Parallel validation jobs cannot exceed the configured global concurrency limit.
- Re-running the same artifact hash does not spawn unbounded duplicate jobs.

### Evidence gaps
- No MCP server, tool list, protocol, or authentication model is supplied.
- Docker validation resource limits and network-disabled enforcement are asserted in intent but not evidenced.
- Whether tool calls can be initiated directly by model output without human approval is unknown.

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)

## TM-006: Denial of service to local Ollama and egress/network path

**Domain:** network | **STRIDE:** Denial of Service | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** Medium
**Threat actor:** Malicious repository content, compromised workflow, or any local process able to reach the Ollama HTTP service or egress path
**Asset:** Local Ollama HTTP service, developer workstation, CI runner egress, DNS/TLS path to external APIs
**Trust boundary:** Local orchestrator to Ollama HTTP service; GitHub Actions runner to external Mistral API

**Attack hypothesis:** Without verified loopback-only Ollama access and egress controls, untrusted content or a compromised workflow could generate enough local or outbound requests, or malformed DNS/TLS traffic, to degrade the services the pipeline depends on.

### Preconditions
- Loopback-only binding for Ollama is listed as unknown rather than enforced
- Egress allowlists, DNS resolution controls, and TLS validation are not specified
- No rate limiting or request-size caps for local HTTP calls are confirmed

### Attack-tree path
- Untrusted content induces high-volume requests to Ollama or external endpoints
- Loopback-only, egress allowlist, DNS, or TLS validation is absent or misconfigured
- Malformed or repeated requests consume local service, resolver, or egress capacity
- Scanning, triage, or remediation steps that depend on network services stall

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Bind Ollama to loopback or an authenticated local socket and verify with network policy that no other host can reach it.
- Enforce egress allowlists for runners with default-deny and explicit destinations for Mistral and GitHub APIs.
- Cap request rate, concurrency, and payload size for all local and external HTTP calls.
- Validate TLS certificates and use pinned/authorized CA roots; avoid disabling validation for convenience.
- Monitor DNS/TLS failures and request volume as availability signals with alerts.

### Testable acceptance criteria
- From a non-loopback address, a connection to the Ollama port is refused and logged.
- A runner with default-deny egress cannot reach an unapproved external host but can reach approved API endpoints.
- Requests exceeding local rate/size limits are throttled or rejected without crashing the orchestrator.
- TLS validation failure against a test endpoint causes fail-closed behavior rather than silent fallback.

### Evidence gaps
- Actual network controls enforcing loopback-only Ollama are unknown.
- Egress allowlists, DNS filtering, TLS validation, and certificate pinning are not described.
- No rate-limit or availability monitoring evidence is supplied.

### Framework references (entry pages; precise mappings not independently verified)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-007: Denial of service through exhaustion of web/API quotas and rate limits

**Domain:** web-api | **STRIDE:** Denial of Service | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** Medium
**Threat actor:** Crafted findings, retry loops, or a compromised Actions token causing excessive calls to Mistral, GitHub, or local HTTP APIs
**Asset:** Mistral API key quota, GitHub Actions token, CI runner availability, web/API-dependent workflow steps
**Trust boundary:** GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service

**Attack hypothesis:** If outbound API calls are not budgeted or throttled, a small number of crafted findings or a retry storm could exhaust external API quota or rate limits and make the assessment workflow unavailable.

### Preconditions
- API quotas, IP rate limits, and backoff behavior for Mistral and GitHub are unknown
- No per-job request budget, circuit breaker, or concurrency cap is confirmed
- Secrets may be long-lived and usable for repeated API calls until rotated

### Attack-tree path
- Untrusted input or retry logic generates many API requests
- No quota-aware throttling, backoff, or circuit breaker stops the calls
- Mistral quota, GitHub rate limit, or local Ollama concurrency is exhausted
- API-dependent scan, triage, and review steps fail for legitimate jobs

### Kill-chain phases (if applicable)
- None supplied

### Proposed controls
- Set explicit per-job and per-repository request budgets for Mistral, GitHub, and local HTTP APIs.
- Implement timeouts, exponential backoff, jitter, circuit breakers, and concurrency caps for all web/API calls.
- Use short-lived, scoped tokens and rotate API keys; alert on unusual call volume or destination.
- Cache deterministic results and avoid repeated identical LLM/API calls.
- Fail closed with clear audit records when quota or rate limits are reached.

### Testable acceptance criteria
- A test job that exceeds its configured API request budget stops making calls, records the event, and reports failure.
- When an API returns rate-limit responses, the pipeline backs off and does not retry in a tight loop.
- A revoked or expired Mistral key cannot be used by the workflow after revocation propagates.
- Concurrent jobs share a global API budget and cannot collectively exceed it.

### Evidence gaps
- Mistral and GitHub quota/rate-limit configurations are unknown.
- Retry/backoff/circuit-breaker behavior is not specified.
- Key rotation and credential storage arrangements are listed as unknown.

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_CSF](https://www.nist.gov/cyberframework)

## Requested STRIDE focus

- Repudiation
- Denial of Service

All generated scenarios were structurally checked against this focus; threat relevance still requires human review.

## Reference catalog

- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_MASVS](https://mas.owasp.org/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OECD_AI_PRINCIPLES](https://www.oecd.org/en/topics/ai-principles.html)
- [ISO_42001](https://www.iso.org/standard/42001)
- [ISO_27001](https://www.iso.org/standard/27001)

## Review requirements

- Verify architecture assumptions, attack paths and exact standard mappings with authoritative publications.
- Obtain security architect approval before accepting requirements or creating work items.
- No generated code or tests were executed; no patches were applied.
