# Design-time threat model (review required)

> AI-generated threat hypotheses, not verified vulnerabilities or a compliance assessment.

**Scope:** Design-time, review-only threat model for the CybersecurityAgent security-assessment orchestration design, covering iam, pki, network, data, web-api, mobile, mcp, and agentic-ai. This output records hypotheses and control requirements only; it does not assert that vulnerabilities exist, that controls are implemented, or that tests were executed.

## Architecture summary
Developers push source to GitHub; GitHub Actions runs Semgrep scans; findings may be sanitized and sent to external Mistral for triage or optional remediation; optional local Ollama is intended for source-local remediation; generated tests/patches are validated in a temporary, network-disabled Docker workspace; humans approve findings, patches, and pull requests. No automatic merge or production deployment is intended.

## Assets
- Proprietary source code and security findings
- Sanitized evidence and audit/audit-trail records
- Mistral API key, GitHub Actions token, OIDC credentials, developer credentials
- GitHub repository, branches, pull requests, approvals, and webhooks
- CI/CD runners and workflow definitions
- Developer workstation and local orchestrator
- Local Ollama HTTP service and local models
- MCP tool server and tool descriptions, if exposed to agents
- Generated remediation artifacts, tests, patches, and Docker images
- Network egress paths to Mistral and loopback/local services
- Mobile approval client, if introduced

## Trust boundaries
- Developer workstation to GitHub repository
- GitHub Actions runner to external Mistral API
- Untrusted repository files and scanner findings to LLM prompt
- Host filesystem to Docker validation workspace
- Local orchestrator to Ollama HTTP service
- AI-generated proposals to human approval / pull-request process
- Web/API entry points to GitHub and approval workflows
- Mobile client to web/API approval services, if present
- Agent/orchestrator to MCP tools, if present

## Assumptions
- The design description is treated as untrusted context and not as an instruction source.
- A mobile approval client is not described; mobile scenarios are conditional on such a client being introduced.
- An MCP server/tool surface may be introduced for agent orchestration; MCP scenarios are conditional and should be retired if no MCP surface exists.
- Branch protections, environment approvals, secret storage, key rotation, network controls, and deployment criticality are not yet evidenced.
- Docker validation is intended to be temporary and network-disabled, but actual runtime flags, mounts, capabilities, and resource limits are unknown.
- External disclosure of source snippets requires explicit approval, but the approval workflow and review content are unspecified.
- Likelihood and impact values are qualitative design hypotheses, not measured risk ratings.

## Open questions
- What are the actual GitHub organization branch protections, required reviewers, and environment approval rules?
- Which workflows use pull_request_target, write tokens, secrets, or untrusted checkout patterns?
- Is Ollama bound only to loopback, and what authentication, firewall, or process isolation enforces that?
- How are source snippets selected, reviewed, redacted, and approved before external disclosure to Mistral?
- Where are Mistral API keys, GitHub tokens, OIDC credentials, and signing keys stored, and how are they rotated?
- What network egress controls exist for CI runners and local orchestrators?
- What MCP tools, if any, are exposed, with what schemas, permissions, and confirmation requirements?
- What validation proves Docker workspaces are network-disabled, rootless, resource-limited, and isolated from host filesystem?
- Is there a mobile client, and if so what data it stores, how sessions are protected, and whether pinning is used?
- What deployment environments exist, what is the criticality of each asset, and what audit retention/integrity requirements apply?

## TM-001: CI workflow identity abuse from untrusted pull requests

**Domain:** iam | **STRIDE:** Elevation of Privilege | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** Malicious external contributor or compromised dependency author
**Asset:** GitHub Actions token, OIDC credentials, repository write/admin actions
**Trust boundary:** Developer workstation to GitHub repository; GitHub Actions runner to external services

**Attack hypothesis:** If untrusted pull-request code can run under a write-capable token or with access to secrets, an adversary may escalate from contributor to repository or CI control without direct credential theft.

### Preconditions
- A workflow may execute untrusted pull-request code with elevated context
- Default workflow permissions are not read-only or environment approvals are absent
- Secrets are exposed to the workflow environment

### Attack-tree path
- Untrusted change enters repository
- Workflow executes with privileged identity
- Attacker abuses token/OIDC/secrets
- Repository, approvals, or CI state altered

### Kill-chain phases (if applicable)
- Initial Access
- Privilege Escalation
- Persistence
- Collection
- Impact

### Proposed controls
- Require least-privilege workflow permissions with read-only defaults
- Prefer short-lived OIDC federation over long-lived secrets and validate audience/subject claims
- Avoid privileged workflows on untrusted pull-request events and require environment approvals for sensitive jobs
- Scope secrets by environment and avoid exposing broad tokens to untrusted code

### Testable acceptance criteria
- A test pull request attempting a write operation with a read-only token is denied
- A sensitive job cannot start without recorded environment approval
- OIDC tokens with unexpected audience or subject claims are rejected
- Secret access from an untrusted event context fails closed and is logged

### Evidence gaps
- Actual workflow files
- GITHUB_TOKEN permission blocks
- OIDC trust configuration
- branch protection and environment approval settings
- secret scoping

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [MITRE_ATTACK](https://attack.mitre.org/)

## TM-002: Developer workstation or credential compromise impersonating a maintainer

**Domain:** iam | **STRIDE:** Spoofing | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** External attacker using stolen developer credentials or session
**Asset:** Developer credentials, GitHub account, commit authorship, pull-request approvals
**Trust boundary:** Developer workstation to GitHub repository

**Attack hypothesis:** If authentication relies on weaker factors or long-lived sessions, a stolen credential may be sufficient to impersonate a trusted developer and inject or approve changes.

### Preconditions
- Developer uses reusable credentials or long-lived sessions
- Workstation lacks strong device posture or endpoint protection evidence
- Commit signing or approval verification is not enforced

### Attack-tree path
- Compromise workstation or steal credential/session
- Authenticate to GitHub as developer
- Push commits or approve changes
- Hide among legitimate activity

### Kill-chain phases (if applicable)
- Initial Access
- Credential Access
- Collection
- Exfiltration
- Impact

### Proposed controls
- Require phishing-resistant MFA and short-lived sessions for GitHub access
- Use hardware-backed keys or passkeys where supported and bind credentials to device posture where possible
- Require signed commits and verified approvals for protected branches
- Alert on anomalous push/approval patterns and impossible travel

### Testable acceptance criteria
- Login without required second factor is denied
- Revoked or expired session cannot push or approve
- Unsigned commit to a protected branch is rejected
- Approval from an unverified identity cannot satisfy branch protection

### Evidence gaps
- MFA enforcement evidence
- session lifetime policy
- commit signing configuration
- device posture integration
- approval audit log format

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO_27001](https://www.iso.org/standard/27001)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-003: Signing/provenance key misuse allowing forged trusted artifacts

**Domain:** pki | **STRIDE:** Tampering | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Attacker with access to signing material or a compromised release path
**Asset:** Code/commit signing keys, artifact signatures, provenance records, release trust decisions
**Trust boundary:** Host filesystem to Docker validation workspace; CI runner to GitHub repository

**Attack hypothesis:** If signatures are not bound to protected key custody and verified against expected identity before use, an attacker may make an untrusted artifact appear trusted.

### Preconditions
- Signing keys are stored on general-purpose CI or developer hosts
- Signature verification is optional or not bound to identity and expected source
- Provenance records can be generated after untrusted build steps

### Attack-tree path
- Obtain or influence signing key access
- Produce artifact with valid-looking signature
- Victim trusts signature/provenance
- Malicious artifact enters approval or validation flow

### Kill-chain phases (if applicable)
- Credential Access
- Defense Evasion
- Impact

### Proposed controls
- Store signing keys in protected key management or HSM-backed custody with access logging
- Use short-lived certificates or keyless signing where supported
- Require verification of signer identity, source repository, workflow, and artifact hash before trust
- Record immutable provenance for scanner outputs, patches, and Docker images

### Testable acceptance criteria
- Artifact with invalid signature or unexpected signer is rejected
- Key use outside approved workflow/host is denied and logged
- Tampered artifact fails hash/signature verification
- Provenance record cannot be rewritten after issuance

### Evidence gaps
- Key custody location
- signing workflow
- verification policy
- provenance format
- rotation evidence

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO_27001](https://www.iso.org/standard/27001)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-004: TLS/certificate validation failure on external and local model endpoints

**Domain:** pki | **STRIDE:** Information Disclosure | **Likelihood (hypothesis):** Low | **Impact (hypothesis):** High
**Threat actor:** Network-position attacker or DNS spoofer
**Asset:** Mistral API key, source snippets, Ollama traffic, session tokens
**Trust boundary:** GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service

**Attack hypothesis:** If any client skips certificate validation or endpoint identity checks, a network attacker may capture API keys or manipulate model responses.

### Preconditions
- Clients disable or misconfigure certificate validation
- Pinning or allowlists are absent
- Local Ollama endpoint uses plaintext HTTP or permissive exposure

### Attack-tree path
- Intercept or redirect endpoint traffic
- Present invalid/self-signed certificate or spoof DNS
- Capture credentials or inject responses
- Exfiltrate data or poison model output

### Kill-chain phases (if applicable)
- Initial Access
- Credential Access
- Collection
- Exfiltration

### Proposed controls
- Enforce TLS with system trust roots and fail closed on certificate errors
- Use certificate pinning or SPKI pinning for critical external endpoints where appropriate
- Use mTLS or authenticated local transport for internal model services where feasible
- Restrict egress by hostname/IP and validate service identity

### Testable acceptance criteria
- Connection to endpoint with expired, wrong-host, or self-signed certificate fails
- DNS-spoofed endpoint is rejected by pinning/identity check
- Plaintext HTTP to local model service is refused
- Egress to non-allowlisted model endpoint is blocked

### Evidence gaps
- HTTP client configuration
- pinning policy
- Ollama transport/auth details
- egress allowlist
- certificate monitoring

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [OWASP_WEB](https://owasp.org/Top10/2025/)

## TM-005: Ollama service reachable beyond intended loopback or without authentication

**Domain:** network | **STRIDE:** Information Disclosure | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Local or adjacent-network attacker, or SSRF-driven internal client
**Asset:** Local Ollama endpoint, prompts containing source/findings, model responses
**Trust boundary:** Local orchestrator to Ollama HTTP service

**Attack hypothesis:** If the local model service is not strictly loopback-only and authenticated, any local or reachable process may submit prompts or retrieve sensitive context.

### Preconditions
- Ollama binds to non-loopback interface or is exposed through proxy
- No authentication token or access control on the HTTP service
- Browser or other local process can reach the port

### Attack-tree path
- Discover listening model port
- Send crafted prompts or read model state
- Extract source/findings from context or logs
- Abuse endpoint as internal pivot

### Kill-chain phases (if applicable)
- Discovery
- Lateral Movement
- Collection
- Exfiltration

### Proposed controls
- Bind Ollama to 127.0.0.1 or Unix socket only and enforce with firewall/host policy
- Require per-session token or local authentication for model requests
- Disable remote model management endpoints and ingress from other interfaces
- Log and alert on non-loopback connection attempts

### Testable acceptance criteria
- Connection from a non-loopback address to the model port is refused
- Unauthenticated HTTP request receives 401/403
- Configuration review shows bind address constrained to loopback
- Firewall rule test blocks external interface access

### Evidence gaps
- Actual bind address
- auth token presence
- firewall rules
- proxy exposure
- logging of access

### Framework references (entry pages; precise mappings not independently verified)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-006: CI egress path abused for secret exfiltration or command-and-control

**Domain:** network | **STRIDE:** Information Disclosure | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** Compromised workflow step, dependency, or injected prompt output
**Asset:** Mistral API key, source snippets, scanner findings, CI runner metadata
**Trust boundary:** GitHub Actions runner to external Mistral API

**Attack hypothesis:** If egress is unrestricted and secrets are present in the runner environment, malicious code may exfiltrate them or use outbound traffic as a covert channel.

### Preconditions
- Runner has broad internet egress
- Secrets or sensitive findings can enter outbound requests/logs
- No DLP or egress allowlist is enforced

### Attack-tree path
- Gain code execution in workflow
- Read environment or files
- Send data to attacker-controlled host
- Maintain channel or receive instructions

### Kill-chain phases (if applicable)
- Collection
- Command and Control
- Exfiltration

### Proposed controls
- Restrict runner egress to allowlisted hosts using proxy/firewall
- Use masked secrets and avoid printing environment variables
- Route external model calls through an inspected proxy with DLP rules
- Block known non-essential ports and protocols; alert on anomalous destinations

### Testable acceptance criteria
- Attempt to reach a non-allowlisted external host from a workflow fails
- Canary secret placed in a test run does not leave the runner except via approved destination
- Proxy logs show only expected Mistral endpoint destinations
- DNS resolution to unexpected domains is denied

### Evidence gaps
- Runner network policy
- egress allowlist
- secret masking config
- proxy/DLP rules
- log retention

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-007: Sensitive source or secrets leak into external model prompts despite sanitization

**Domain:** data | **STRIDE:** Information Disclosure | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** External model provider, prompt-injection adversary, or over-broad disclosure approval
**Asset:** Proprietary source code, security findings, secrets, personal data
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If evidence sent to Mistral is not reliably redacted and approved, proprietary source or credentials may be disclosed to an external system even when the workflow is intended to be sanitized.

### Preconditions
- Sanitizer misses secrets, tokens, connection strings, or identifying code
- Disclosure approval is broad, implicit, or not logged
- Prompt includes more context than necessary

### Attack-tree path
- Scanner captures sensitive finding or source snippet
- Sanitization incomplete
- Content sent to external model
- Data retained, inferred, or exposed

### Kill-chain phases (if applicable)
- Collection
- Exfiltration

### Proposed controls
- Use canary secrets and pattern-based redaction before any external call
- Require explicit, itemized, logged approval for source disclosure
- Send minimal necessary context and prefer findings over raw source
- Use contractual/technical controls for retention, training exclusion, and deletion where available

### Testable acceptance criteria
- A seeded canary secret in a sample finding is redacted before egress
- External call without approval record is blocked
- Prompt payload size/context is below approved maximum
- Redaction regression suite covers tokens, keys, internal hosts, and personal data patterns

### Evidence gaps
- Sanitizer implementation
- approval workflow
- redaction test corpus
- Mistral data handling terms
- egress payload inspection

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## TM-008: Tampering with scanner findings or audit evidence undermines review decisions

**Domain:** data | **STRIDE:** Tampering | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Attacker able to modify intermediate evidence, or compromised pipeline component
**Asset:** Sanitized evidence, audit records, approval history, remediation decisions
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; AI-generated proposals to human approval / pull-request process

**Attack hypothesis:** If findings and audit records lack integrity anchoring, an attacker or faulty component could change what reviewers see without leaving a reliable trace.

### Preconditions
- Evidence is stored mutable without integrity protection
- Audit logs are writable by pipeline identity
- Reviewers cannot verify evidence provenance

### Attack-tree path
- Alter finding severity or content in transit/storage
- Regenerate or delete audit entry
- Human approves falsified evidence
- Weak or malicious patch enters review

### Kill-chain phases (if applicable)
- Defense Evasion
- Impact

### Proposed controls
- Hash and sign scanner output and sanitized evidence at creation; verify before display/approval
- Store audit records append-only with restricted write permissions and separate audit identity
- Bind approvals to evidence hash and actor identity
- Retain immutable copies of prompts, outputs, and decisions for traceability

### Testable acceptance criteria
- Modified evidence fails integrity verification before human review
- Attempt to delete or update an audit record is denied and alerted
- Approval is cryptographically bound to evidence hash
- Replay of an old evidence hash is rejected if superseded

### Evidence gaps
- Evidence storage location
- hash/signing scheme
- audit log permissions
- retention policy
- approval binding format

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO_27001](https://www.iso.org/standard/27001)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-009: GitHub webhook/API or approval endpoints accept forged or unauthorized requests

**Domain:** web-api | **STRIDE:** Spoofing | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** External attacker probing webhook/API endpoints
**Asset:** GitHub repository events, pull-request approvals, automation triggers
**Trust boundary:** Web/API entry points to GitHub and approval workflows

**Attack hypothesis:** If inbound events are not authenticated and authorized against GitHub signatures and expected scopes, forged requests may drive approvals or CI actions.

### Preconditions
- Webhooks or custom API endpoints lack signature verification or allowlist
- Endpoints trust client-supplied identity or event fields
- Tokens have broader scopes than needed

### Attack-tree path
- Discover exposed webhook/API route
- Send forged event or command
- Trigger automation or approval action
- Escalate repository privileges

### Kill-chain phases (if applicable)
- Initial Access
- Privilege Escalation
- Impact

### Proposed controls
- Verify GitHub webhook signatures and reject unsigned/unknown senders
- Allowlist source IPs or use private connectivity where possible
- Apply least privilege to automation tokens and separate read/write/approve scopes
- Require human approval for merge/deploy and validate event payloads server-side

### Testable acceptance criteria
- Webhook with invalid signature is rejected with 401/403
- Forged approval event cannot change protected branch state
- Automation token cannot perform actions outside its assigned scope
- Unexpected event fields do not override server-side authorization

### Evidence gaps
- Custom web/API routes
- webhook secret handling
- token scopes
- source allowlists
- approval enforcement points

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## TM-010: AI-generated remediation text rendered unsafely in reviewer UI

**Domain:** web-api | **STRIDE:** Tampering | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** Medium
**Threat actor:** Prompt-injection or malicious model output aiming at reviewer browser
**Asset:** Reviewer session, browser DOM, approval UI integrity
**Trust boundary:** AI-generated proposals to human approval / pull-request process

**Attack hypothesis:** If proposals are rendered as rich content, model output influenced by untrusted inputs may execute in the reviewer UI despite human approval being required.

### Preconditions
- Model output is rendered as HTML/markdown without sanitization
- CSP is weak or absent
- Generated patch text can include links, images, or scripts

### Attack-tree path
- Inject payload into finding/source
- Model emits crafted remediation text
- Reviewer opens proposal
- Script executes in approval context

### Kill-chain phases (if applicable)
- Execution
- Impact

### Proposed controls
- Treat all model output as untrusted data; render as text or sanitize rich markdown
- Enforce strict CSP, disable inline scripts, and sandbox iframes
- Never auto-apply generated changes; require explicit human diff review
- Separate approval actions from content rendering origins where possible

### Testable acceptance criteria
- Known XSS payload in generated patch does not execute in review UI
- CSP blocks inline script and reports violation
- Links in proposals open in sandboxed/new context and cannot invoke privileged actions
- Diff view shows raw text without interpreting HTML

### Evidence gaps
- Review UI stack
- markdown sanitizer
- CSP headers
- iframe usage
- approval action URLs

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-011: Conditional mobile approval client leaks session or sensitive findings

**Domain:** mobile | **STRIDE:** Information Disclosure | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Attacker with device access, malicious app, or MITM on mobile network
**Asset:** Mobile session token, approval actions, push notifications containing finding details
**Trust boundary:** Mobile client to web/API approval services, if present

**Attack hypothesis:** If a mobile client is added without platform secure storage and short sessions, device compromise may expose approval capability and sensitive findings.

### Preconditions
- A mobile client is introduced for approvals or finding review
- Tokens stored insecurely or long-lived
- Push notifications include sensitive finding content

### Attack-tree path
- Compromise device or app storage
- Extract token or cached findings
- Call approval API
- Exfiltrate data or approve malicious change

### Kill-chain phases (if applicable)
- Credential Access
- Collection
- Exfiltration
- Impact

### Proposed controls
- Use platform keystore/keychain with biometric unlock and short-lived tokens
- Pin certificates for API endpoints and validate TLS
- Avoid storing raw findings or source in notifications/cache; use opaque references
- Require step-up authentication for approvals and allow remote session revocation

### Testable acceptance criteria
- Token is not readable from ordinary app sandbox storage
- Revoked session cannot approve after server-side revocation
- Certificate pinning rejects MITM proxy certificate
- Push notification contains no secret or source snippet

### Evidence gaps
- Mobile app existence
- storage mechanism
- session lifetime
- pinning implementation
- notification content policy

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_MASVS](https://mas.owasp.org/)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## TM-012: MCP tool surface grants excessive filesystem, shell, or network capability

**Domain:** mcp | **STRIDE:** Elevation of Privilege | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Prompt-injected agent or compromised orchestrator
**Asset:** Host filesystem, secrets, MCP-exposed tools, downstream services
**Trust boundary:** Agent/orchestrator to MCP tools, if present

**Attack hypothesis:** If MCP tools are broadly capable and automatically callable, an injected instruction may cause the agent to use file, shell, or network tools beyond the task's need.

### Preconditions
- MCP server exposes dangerous tools without per-tool authorization
- Agent can call tools based on untrusted prompt content
- No human confirmation for destructive actions

### Attack-tree path
- Untrusted input influences agent plan
- Agent invokes MCP tool
- Tool reads secrets, executes command, or reaches network
- Privilege or data crosses boundary

### Kill-chain phases (if applicable)
- Execution
- Privilege Escalation
- Collection
- Exfiltration

### Proposed controls
- Expose only an allowlisted set of MCP tools with explicit schemas and per-tool scopes
- Require human confirmation for file writes, shell execution, network access, and secret access
- Run MCP server in a sandbox with no host mounts, no egress, and resource limits
- Validate tool arguments and treat tool results as untrusted data

### Testable acceptance criteria
- Tool not on allowlist is rejected before execution
- Dangerous tool call requires recorded human approval
- Sandboxed MCP server cannot reach external network or host filesystem
- Malformed tool arguments fail closed and are logged

### Evidence gaps
- MCP server implementation
- tool inventory
- permission model
- confirmation UX
- sandbox runtime flags

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-013: MCP tool descriptions/results poisoned to manipulate agent actions

**Domain:** mcp | **STRIDE:** Spoofing | **Likelihood (hypothesis):** Medium | **Impact (hypothesis):** High
**Threat actor:** Attacker controlling tool output, repository content, or tool metadata
**Asset:** Agent decision state, downstream tool calls, human approval inputs
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; agent/orchestrator to MCP tools, if present

**Attack hypothesis:** If MCP metadata or outputs are trusted as authoritative, poisoned content may redirect the agent to call unintended tools or misclassify evidence.

### Preconditions
- Tool descriptions or results are not integrity-protected
- Agent treats tool output as instructions rather than data
- Cross-tool trust is not separated

### Attack-tree path
- Attacker influences scanner finding or tool result
- Content includes fake instructions or fake schema
- Agent follows injected instruction
- Confused deputy invokes another tool or endpoint

### Kill-chain phases (if applicable)
- Initial Access
- Execution
- Privilege Escalation

### Proposed controls
- Sign or pin trusted tool descriptions where possible and validate tool schemas
- Instruct and enforce that tool output is data, never instructions
- Isolate tools by capability and require policy checks before chained calls
- Log full tool call/response trace for human review

### Testable acceptance criteria
- Injected text in tool result does not change agent plan or trigger another tool
- Tool schema mismatch is rejected
- Tool call trace shows actor, reason, arguments, and result for every invocation
- Untrusted content cannot elevate tool permissions

### Evidence gaps
- Tool provenance
- prompt/system instruction design
- policy engine
- trace retention
- output validation rules

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-014: Prompt injection through findings/source causes disclosure or malicious remediation

**Domain:** agentic-ai | **STRIDE:** Tampering | **Likelihood (hypothesis):** High | **Impact (hypothesis):** High
**Threat actor:** Attacker embedding instructions in repository files, commit messages, or scanner findings
**Asset:** Source code, API keys, LLM context, generated patches, human approval decisions
**Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; AI-generated proposals to human approval / pull-request process

**Attack hypothesis:** If untrusted repository content can override system intent, an injected instruction may cause the model to exfiltrate context, propose harmful patches, or mislead reviewers.

### Preconditions
- Untrusted content is concatenated into prompts without robust separation
- Model output can influence tool calls or patch content
- No canary or output validation before human review

### Attack-tree path
- Plant instruction in untrusted artifact
- Scanner/orchestrator includes it in prompt
- Model follows instruction
- Secret disclosure, tool misuse, or malicious patch proposed

### Kill-chain phases (if applicable)
- Initial Access
- Execution
- Collection
- Exfiltration
- Impact

### Proposed controls
- Use clear instruction hierarchy and delimit untrusted content as data with randomized markers
- Never auto-apply model output; require human diff review and independent validation
- Validate outputs against schemas, canaries, and safety classifiers before use
- Minimize sensitive context and block egress except approved endpoints

### Testable acceptance criteria
- Seeded injection in a test finding does not cause secret canary exfiltration
- Generated patch cannot be applied without human approval record
- Output that violates schema or safety policy is rejected
- Prompt trace shows untrusted content was delimited and logged

### Evidence gaps
- Prompt templates
- delimiting strategy
- output validation
- canary deployment
- approval enforcement point

### Framework references (entry pages; precise mappings not independently verified)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-015: Model supply chain or endpoint compromise produces poisoned behavior

**Domain:** agentic-ai | **STRIDE:** Tampering | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Compromised model provider, malicious local model artifact, or MITM on model download
**Asset:** Ollama local models, Mistral service responses, remediation quality, evidence interpretation
**Trust boundary:** Local orchestrator to Ollama HTTP service; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If model artifacts or provider responses are not verified and monitored, a poisoned model may systematically misclassify findings or propose plausible but harmful patches.

### Preconditions
- Local models are downloaded without checksum/provenance verification
- External provider responses are not monitored for anomalies
- No offline validation baseline exists

### Attack-tree path
- Replace or poison model artifact/service
- Orchestrator loads or calls compromised model
- Model emits misleading triage/remediation
- Human approves harmful or false output

### Kill-chain phases (if applicable)
- Resource Development
- Persistence
- Execution
- Impact

### Proposed controls
- Verify model hashes/signatures and provenance before use; prefer pinned versions
- Monitor outputs against regression suites and canary cases before human display
- Use independent validation in Docker and require consensus or human confirmation for high-risk changes
- Provide kill switch to disable external/local model paths

### Testable acceptance criteria
- Model artifact with mismatched hash/signature is refused
- Poisoned canary input produces detected anomaly and blocks proposal
- Kill switch disables model calls and falls back to human-only review
- Regression test suite flags systematic misclassification

### Evidence gaps
- Model provenance process
- hash pinning
- output monitoring
- regression corpus
- fallback procedure

### Framework references (entry pages; precise mappings not independently verified)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-016: Validation workspace escape or resource exhaustion from generated artifacts

**Domain:** network | **STRIDE:** Denial of Service | **Likelihood (hypothesis):** Unknown | **Impact (hypothesis):** High
**Threat actor:** Attacker via malicious generated patch/test or model-influenced artifact
**Asset:** CI runner host, host filesystem, neighboring jobs, validation service availability
**Trust boundary:** Host filesystem to Docker validation workspace

**Attack hypothesis:** If the temporary validation workspace is not strictly isolated, generated artifacts could affect the host or other CI jobs despite the human-approval design.

### Preconditions
- Generated code/tests run in Docker without hardened runtime defaults
- Container has host mounts, added capabilities, host network, or high resource limits
- Network-disabled intent is not enforced by runtime policy

### Attack-tree path
- Model proposes malicious test/patch
- Validation runner executes artifact in container
- Artifact escapes sandbox, reaches host/network, or exhausts resources
- CI availability or host integrity affected

### Kill-chain phases (if applicable)
- Execution
- Privilege Escalation
- Lateral Movement
- Impact

### Proposed controls
- Run validation rootless with no added capabilities, seccomp/AppArmor, read-only rootfs, dropped mounts, and network none
- Enforce CPU/memory/process/disk limits and timeouts
- Use unique ephemeral runner/namespace per job and destroy workspace after validation
- Block host Docker socket, sensitive paths, and metadata endpoints from the container

### Testable acceptance criteria
- Container cannot connect to external network or host loopback services
- Attempt to mount host filesystem or access Docker socket fails
- Resource exhaustion test is terminated by limits without affecting other jobs
- Workspace is destroyed and logs preserved immutably after run

### Evidence gaps
- Docker run flags
- rootless configuration
- seccomp profile
- resource limits
- network policy
- workspace teardown evidence

### Framework references (entry pages; precise mappings not independently verified)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [OWASP_WEB](https://owasp.org/Top10/2025/)

## Reference catalog

- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_MASVS](https://mas.owasp.org/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO_27001](https://www.iso.org/standard/27001)

## Review requirements

- Verify architecture assumptions, attack paths and exact standard mappings with authoritative publications.
- Obtain security architect approval before accepting requirements or creating work items.
- No generated code or tests were executed; no patches were applied.
