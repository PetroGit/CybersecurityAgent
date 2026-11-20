# Consolidated design-time threat model (review required)

> Offline merge of AI-generated hypotheses. Not verified vulnerabilities, test results, or compliance evidence.

## Source models

- `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` (SHA-256 `37cc3cac1c0674d9cdfe5c13fb4ee8a515f7146087f25f727ff4a4e53f124f53`, 8 scenarios)
- `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` (SHA-256 `35cdf2f65c7df6f8ddfcf8767ac2ca70a54c8c90eb26ea49f092a2b1b33af386`, 7 scenarios)

## Scope
Consolidation of: Design-time, review-only threat model for the CybersecurityAgent security-assessment orchestration flow: GitHub source push, GitHub Actions Semgrep scanning, sanitized evidence to external Mistral triage, optional approval-gated source disclosure, optional local Ollama remediation, temporary network-disabled Docker validation, and human approval before any pull request. Requested domains covered: iam, pki, network, data, web-api, mobile, mcp, agentic-ai. No runtime testing, control verification, or vulnerability confirmation is performed.; Design-time, review-only threat model for the CybersecurityAgent assessment platform. The supplied design description is treated as untrusted data. Focus is limited to STRIDE Repudiation and Denial of Service across the selected domains; no runtime testing, control verification, or framework-page retrieval is claimed.

## Architecture summary
Developers push source to GitHub; GitHub Actions runs Semgrep and converts findings into sanitized evidence. External Mistral triage may be used after disclosure approval, while optional Ollama remediation is intended to remain local. Generated tests and patches are validated in a temporary Docker workspace described as network-disabled. Human reviewers decide acceptance of findings, patches, and pull requests. No automatic merge or production deployment is intended, but enforcement mechanisms are not specified in the untrusted design context.

GitHub-hosted source is scanned by GitHub Actions using Semgrep; findings are sanitized for optional external Mistral triage and optional local Ollama remediation; generated tests/patches are validated in a temporary network-disabled Docker workspace; humans decide acceptance of findings, patches, and pull requests. No automatic merge or production deployment is described.

## Assets

- Proprietary source code and security findings
- Mistral API key and external model endpoint
- GitHub Actions token, OIDC identity, repository write access, and workflow secrets
- Developer credentials and approval identities
- CI/CD runners and GitHub repository configuration
- Local workstation and local Ollama HTTP endpoint
- Untrusted repository files and scanner findings used as LLM input
- Generated remediation artifacts, tests, patches, and audit evidence
- Temporary Docker validation workspace and Docker images
- Assumed web/API approval or triage surface, if introduced
- Assumed mobile approval client, if introduced
- Assumed MCP server and tool surface, if introduced
- Sanitized evidence and disclosure-approval records
- Mistral API key, GitHub Actions token, developer credentials
- CI/CD runners, GitHub repository and approval state
- Local workstation and Ollama HTTP endpoint
- Docker images and temporary validation workspace

## Trust boundaries

- Developer workstation to GitHub repository
- GitHub Actions runner to external Mistral API
- Untrusted repository files and scanner findings to LLM prompt
- Host filesystem to Docker validation workspace
- Local orchestrator to Ollama HTTP service
- AI-generated proposals to human approval and pull-request process
- Assumed external clients to web/API approval surface
- Assumed mobile client to approval or notification service
- Assumed MCP client/server/tool boundary around LLM access
- AI-generated proposals to human approval / pull-request process

## Assumptions

- A web/API approval surface and mobile approval clients may exist or be introduced, but their design is not supplied.
- An MCP server may front LLM/tool access for Mistral or Ollama, but its deployment and tool scopes are not supplied.
- TLS is intended for external API calls, but certificate validation, pinning, and internal PKI behavior are unknown.
- Ollama is intended to be loopback-only, but actual binding, authentication, and network enforcement are unknown.
- Branch protections, environment approvals, token scopes, OIDC versus long-lived secrets, and key rotation are not specified.
- Semgrep findings and repository content may contain attacker-influenced text that enters prompts or tool inputs.
- The Docker validation workspace is described as network-disabled, but mounts, capabilities, user context, rootless mode, and image provenance are unknown.
- Sanitization of evidence sent to Mistral is intended, but the exact redaction rules and approval workflow are unknown.
- Human review is a required gate, but approval UX, step-up authentication, and audit integrity are not specified.
- No automatic merge or deployment is a stated constraint, but the technical enforcement of that constraint is not described.
- The design text is untrusted and no security control is assumed implemented unless explicitly stated, which it is not.
- TLS to external APIs is plausible but not specified; certificate pinning, revocation checking, and PKI details are unknown.
- GitHub Actions permissions, branch protections, and environment approvals are unknown.
- Ollama may be HTTP on loopback, but enforcement of loopback-only access and egress allowlists is unknown.
- Human approval is assumed to occur through pull-request review, but audit-log immutability, commit signing, and identity binding are not specified.
- The mcp domain was requested, so tool/MCP-style orchestration is treated as possible even though no MCP server is explicitly described.
- No mobile application is described in the design.
- No runtime tests were executed and no evidence was collected.

## Open questions

- What GitHub Actions permissions are set per workflow, and are fork pull requests blocked from secrets and write tokens?
- Is OIDC federation used instead of long-lived cloud or API secrets, and what are token lifetimes and audiences?
- What branch protection and environment approval rules exist for the repository and deployment environments?
- How are Mistral API keys stored, rotated, scoped, and monitored, and what is Mistral's retention or training-use policy for submitted prompts?
- What exact fields are included in sanitized evidence, and how are secrets, canaries, and prompt-injection strings detected and redacted before egress?
- How is explicit source-disclosure approval recorded, enforced, and revocable?
- Is Ollama bound only to loopback with authentication, and are there host or container network controls proving this?
- What egress allowlists, DNS restrictions, and proxy inspection apply to CI runners and workstations?
- What TLS certificate validation and pinning are used for Mistral, Ollama if remote, webhooks, and any internal PKI?
- How are Docker images and remediation artifacts signed, provenance-checked, and admitted to the validation workspace?
- What filesystem paths, capabilities, seccomp profile, user, and network settings define the Docker validation sandbox?
- Does a web API exist for triage, approvals, or artifact retrieval, and what authentication, authorization, rate limiting, and audit logging apply?
- Are mobile devices used for approvals, and what MDM, biometric, token storage, and revocation controls apply?
- Is an MCP server used, what tools and resources does it expose, and which tool calls require human confirmation?
- What audit log storage, integrity protection, retention, and access controls cover findings, approvals, tool calls, and merges?
- What is the criticality and deployment context of each asset, and which environments are production versus test?
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

## Potential duplicates (retained for review)

- No exact normalized title/hypothesis matches found; semantic duplicates may still exist.

## TM-001: CI identity or developer credential could be abused to escalate from scan execution to repository or secret access

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-001`

**Domain:** iam | **STRIDE:** Elevation of Privilege | **Likelihood:** Medium | **Impact:** High

**Threat actor:** External attacker submitting a malicious pull request, a compromised dependency in a scanned repository, or an attacker holding a stolen developer session | **Asset:** GitHub Actions token, repository write access, workflow secrets, developer credentials, audit records | **Trust boundary:** Developer workstation to GitHub repository; GitHub Actions runner to external services

**Attack hypothesis:** If the Actions token or developer credential has more privilege than the Semgrep scan requires, an attacker who influences a workflow run could hypothesized to use that identity to read secrets, alter workflow files, or push unauthorized changes, subject to unverified branch-protection and secret-access settings.

### Preconditions

- Workflow token scopes are broader than read-only scanning needs
- Fork pull requests can access secrets or obtain write-capable tokens
- Branch protection or environment approval rules are absent or unverified
- Developer accounts lack phishing-resistant MFA or session binding
- Secrets are present in workflow environment or logs

### Attack tree

- Obtain a CI or developer identity through malicious workflow, dependency, or stolen session
- Use token or session beyond intended scan-only scope
- Read secrets, modify workflows, or push commits to protected paths
- Persist through malicious workflow, repository setting, or deploy key
- Tamper with findings, evidence, or remediation artifacts

### Kill chain (if applicable)

- Delivery
- Exploitation
- Installation
- Actions on Objectives

### Proposed controls

- Set explicit least-privilege workflow permissions such as read-only contents and no secrets for scan jobs
- Prefer short-lived OIDC federation over long-lived tokens and bind tokens to repository, branch, and workflow conditions
- Require environment approvals for any job that handles secrets or remediation artifacts
- Block fork pull requests from accessing secrets and write tokens where possible
- Enforce phishing-resistant MFA and session protection for developer and organization admin accounts
- Rotate all API keys and tokens on suspicion and store them in a managed secret store with access logging
- Enable secret scanning and audit logging for the repository and Actions runs

### Proposed acceptance tests

- A pull request from a fork cannot read any repository secret and cannot obtain a write-capable token
- A scan workflow token cannot push to a protected branch or modify workflow files
- Revoking an OIDC token or developer session invalidates subsequent API and Actions access
- An account without phishing-resistant MFA cannot be enrolled as an organization admin
- A simulated secret in workflow output is detected, redacted, and logged

### Evidence gaps

- Actual workflow permissions blocks, OIDC configuration, branch protection rules, and secret scopes are not provided
- Developer MFA method and session-binding controls are unknown
- Audit log retention and tamper-evidence for Actions and repository events are unknown

### Framework references

- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-002: PKI/TLS trust for external model endpoints or artifact signing could be spoofed if endpoint validation is weak

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-002`

**Domain:** pki | **STRIDE:** Spoofing | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Network-path attacker, malicious or compromised endpoint, or attacker with access to an internal CA or signing key | **Asset:** Mistral API TLS endpoint, Ollama HTTP endpoint if not loopback-only, Docker image or remediation artifact signing key, internal service certificates | **Trust boundary:** GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service; host filesystem to Docker validation workspace

**Attack hypothesis:** If external calls rely on default TLS without pinning or if internal signing keys are broadly readable, an attacker on a network path or with key access could hypothesized to impersonate the Mistral or Ollama endpoint, capture submitted data, or produce artifacts that appear legitimately signed.

### Preconditions

- TLS hostname or certificate validation is absent, disabled, or not pinned for external calls
- DNS or routing can be influenced on the runner or workstation
- Ollama is reachable beyond loopback or uses plaintext HTTP
- Image or artifact signing keys are stored in CI secrets, workstation files, or a broadly accessible key store
- Internal PKI issuance, certificate lifetimes, and revocation behavior are unspecified

### Attack tree

- Influence network path, DNS, or endpoint configuration
- Present a forged or misissued certificate for the model endpoint or internal service
- Have the orchestrator trust the endpoint because validation is not enforced
- Send source snippets, findings, or secrets to the attacker-controlled endpoint
- Or sign malicious Docker images/artifacts that are later admitted for validation or review

### Kill chain (if applicable)

- Reconnaissance
- Delivery
- Exploitation
- Actions on Objectives

### Proposed controls

- Enforce certificate and hostname validation for all external calls and consider pinning for the Mistral API endpoint
- Use mutual TLS or authenticated loopback-only access for any local model service
- Keep Ollama bound to loopback with a separate auth token and verify the address before connection
- Store signing and API keys in hardware-backed or managed key storage with least privilege and rotation
- Sign Docker images and remediation artifacts and verify signatures and provenance before validation or human review
- Use short-lived certificates with revocation checking for internal services and webhooks
- Restrict egress by allowlist so only the approved model endpoint and package sources are reachable

### Proposed acceptance tests

- A connection to a model endpoint with an invalid certificate, wrong hostname, or untrusted CA fails closed
- A self-signed or non-loopback Ollama endpoint is rejected unless explicitly approved and authenticated
- An unsigned or incorrectly signed Docker image or patch artifact is not admitted to the validation workspace
- A revoked signing key or certificate cannot produce artifacts accepted by the verification step
- CI egress to non-allowlisted TLS destinations fails

### Evidence gaps

- Actual TLS validation, pinning, and CA trust configuration are not provided
- Ollama binding and authentication details are unknown
- Whether artifacts or images are signed, and where keys are stored, is not specified
- Internal PKI policy, certificate lifetimes, and revocation mechanisms are unknown

### Framework references

- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [ISO_27001](https://www.iso.org/standard/27001)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-003: CI runner or workstation egress could be used to exfiltrate secrets, source, or findings despite review-only intent

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-003`

**Domain:** network | **STRIDE:** Information Disclosure | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Attacker with code execution in a workflow or dependency, compromised workstation, or prompt-injection-driven tool that attempts network egress | **Asset:** Source code, security findings, environment secrets, Mistral API key, CI runner, local workstation | **Trust boundary:** GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service; host filesystem to Docker validation workspace

**Attack hypothesis:** If egress is not tightly restricted, an attacker with workflow or tool code execution could hypothesized to exfiltrate secrets, proprietary source, or findings through allowed HTTPS, DNS, or an exposed local service, even if the intended flow is review-only.

### Preconditions

- Egress allowlist is absent or broad on runners and workstations
- DNS is unrestricted or can be used for encoding data
- Secrets or source snippets are available in process memory or files reachable by the malicious code
- Ollama or other local services are exposed beyond loopback
- Docker validation workspace network isolation is assumed but not verified

### Attack tree

- Achieve code execution in a scan workflow, dependency, workstation tool, or LLM-driven tool
- Read secrets, repository files, findings, or environment variables
- Encode the data in HTTPS requests to an allowlisted service, DNS queries, or logs
- Transmit the data before Docker validation or human review
- Use the same channel for command-and-control or further payload retrieval

### Kill chain (if applicable)

- Reconnaissance
- Command and Control
- Actions on Objectives

### Proposed controls

- Apply an egress allowlist permitting only the approved Mistral endpoint, package registries, and required GitHub endpoints
- Restrict DNS to an approved resolver and block direct IP or DNS-based exfiltration patterns where feasible
- Bind Ollama to loopback with authentication and block inbound access from other hosts
- Run validation Docker workspaces with networking disabled, read-only mounts, dropped capabilities, and non-root users
- Use a proxy for external calls with request logging and block non-HTTP protocols
- Minimize secrets in CI environment and use masked, short-lived credentials
- Monitor and alert on unusual outbound bytes, destinations, and DNS query sizes

### Proposed acceptance tests

- From a workflow job, connections to non-allowlisted IP addresses and ports fail
- DNS resolution for non-approved domains or unusual TXT query patterns fails or is logged and blocked
- The Ollama port is not reachable from another host or container and requires an auth token on loopback
- A Docker validation container started with the standard profile has no outbound network and cannot reach host filesystem paths outside its mount
- A canary secret in the environment is not present in outbound request logs

### Evidence gaps

- Actual egress controls, DNS policy, and proxy configuration are not provided
- Ollama bind address and firewall rules are unknown
- Docker runtime network, mount, capability, and seccomp settings are unverified
- Logging coverage for outbound traffic is unknown

### Framework references

- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [OSA](https://www.opensecurityarchitecture.org/frameworks/)

## TM-004: Evidence sent to an external LLM could disclose source, secrets, or findings if sanitization or approval is insufficient

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-004`

**Domain:** data | **STRIDE:** Information Disclosure | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Attacker influencing repository content or scanner findings, a prompt-injection payload, or a compromised external model provider | **Asset:** Proprietary source code, security findings, Mistral API key, sanitized evidence, audit evidence | **Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If evidence sanitization is incomplete or approval is not bound to the exact bytes sent, attacker-influenced repository content could hypothesized to cause secret or source disclosure to an external model, or induce the model to emit unsafe remediation text.

### Preconditions

- Sanitization does not remove all secrets, canaries, internal hostnames, tokens, or sensitive paths
- Prompt includes file snippets, findings text, or log lines influenced by the scanned repository
- Disclosure approval is not cryptographically bound to the exact payload
- The Mistral API key has access to prompt contents and logs are retained or trainable by default
- Output parsing can be influenced by injected text

### Attack tree

- Attacker commits code, comments, dependency names, or crafted findings containing injection text or secret-like canaries
- Scanner output or evidence builder includes the untrusted text
- Redaction or sanitization fails to classify or remove the sensitive or malicious content
- Payload is sent to the external model with the API key
- Data is disclosed in prompts, logs, model outputs, or downstream remediation artifacts

### Kill chain (if applicable)

- Delivery
- Exploitation
- Actions on Objectives

### Proposed controls

- Minimize external payloads to structured finding metadata and explicitly exclude raw source unless approved
- Run secret scanning, canary detection, and sensitive-pattern redaction before any egress
- Bind human approval to a hash or immutable preview of the exact evidence payload
- Use a dedicated least-privilege API key, disable retention or training where contractually possible, and log requests
- Treat model output as untrusted and sanitize before it becomes a patch, test, or PR comment
- Prefer local Ollama for source-aware remediation and require explicit approval for external disclosure
- Apply data-loss prevention and egress inspection for prompts containing source-like content

### Proposed acceptance tests

- A canary secret or API-key-like string in scanned content is redacted or blocks egress before the external call
- The approval record references a payload hash and any change to the payload invalidates approval
- A prompt-injection string in a finding cannot cause an external request, tool call, or inclusion of hidden file contents
- External model request logs contain no raw source snippet unless an approved disclosure record exists
- Model output containing code is never applied without human diff review

### Evidence gaps

- Sanitization rules, redaction patterns, and disclosure approval workflow are not supplied
- Mistral data retention, training use, and logging behavior are unknown
- Prompt templates and which finding fields are sent externally are not specified
- Whether canary or secret detection runs before egress is unverified

### Framework references

- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_CSF](https://www.nist.gov/cyberframework)

## TM-005: An approval or triage web API, if exposed, could be spoofed or abused due to authentication and authorization gaps

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-005`

**Domain:** web-api | **STRIDE:** Spoofing | **Likelihood:** Unknown | **Impact:** High

**Threat actor:** Unauthenticated internet attacker, authenticated low-privilege user, or attacker replaying a captured token or webhook | **Asset:** Web API approval endpoints, remediation artifacts, audit records, pull-request state, notifications | **Trust boundary:** Assumed external clients to web/API approval surface; AI-generated proposals to human approval and pull-request process

**Attack hypothesis:** If the review platform exposes an API or webhook for approvals or artifact retrieval and object-level authorization is not enforced, an attacker could hypothesized to impersonate a reviewer, approve attacker-influenced patches, or read sensitive findings and evidence.

### Preconditions

- A web API or webhook endpoint is reachable beyond intended clients
- Authentication method, session binding, token lifetime, and MFA are unspecified
- Authorization is not enforced per object or per action
- Rate limiting, CSRF protection, and input validation are absent
- Webhooks or callbacks are not signature-verified

### Attack tree

- Discover or enumerate the API, webhook, or callback endpoint
- Bypass, replay, or brute-force an authentication token or session
- Call approval, artifact, or status endpoints as another user
- Approve a malicious remediation, alter evidence, or read findings
- Cover tracks by deleting or altering audit records if writable

### Kill chain (if applicable)

- Reconnaissance
- Delivery
- Exploitation
- Actions on Objectives

### Proposed controls

- Require strong authentication aligned with digital identity guidance, with short-lived scoped tokens and session binding
- Enforce per-object authorization for findings, artifacts, approvals, and PR actions, with server-side checks
- Verify webhook signatures and reject unsigned or replayed requests with nonce and timestamp checks
- Apply rate limiting, account lockout, CSRF protection, strict input validation, and security headers
- Expose the API only to required networks or authenticated clients and log all approval decisions immutably
- Require step-up authentication for high-impact approval actions

### Proposed acceptance tests

- Unauthenticated requests to approval and artifact endpoints are rejected
- User A cannot approve, read, or modify user B's pending artifact or finding
- A replayed or expired token and an unsigned webhook are rejected
- Approval actions require step-up authentication and produce an immutable audit record
- Rate limiting triggers and alerts on repeated failed authentication attempts

### Evidence gaps

- It is not confirmed that a web API exists; if it does, its authentication, authorization, and exposure are undescribed
- Webhook signing and callback verification are unknown
- Audit record immutability and access controls are unknown

### Framework references

- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-006: Mobile approval or notification clients could disclose findings or enable spoofed approvals if devices are compromised

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-006`

**Domain:** mobile | **STRIDE:** Spoofing | **Likelihood:** Unknown | **Impact:** Medium

**Threat actor:** Device thief, malware on a developer phone, or an attacker with a stolen push/approval token | **Asset:** Mobile approval client, push notification tokens, developer session, findings metadata, approval audit trail | **Trust boundary:** Assumed mobile client to approval or notification service; developer workstation to GitHub repository

**Attack hypothesis:** If mobile clients can approve security-sensitive actions, a compromised device could hypothesized to spoof a developer approval or read sensitive finding notifications, especially if tokens are long-lived, stored insecurely, or not revocable promptly.

### Preconditions

- Approvals or sensitive notifications can be acted on from mobile clients
- Devices are not under MDM or lack hardware-backed key storage
- Biometric or step-up authentication is not required for approvals
- Tokens or credentials are stored insecurely on the device
- Notifications may include finding snippets, source paths, or secrets

### Attack tree

- Steal or compromise a developer mobile device or app session
- Recover stored tokens, keys, or cached findings from the device
- Use the session to approve a malicious remediation or exfiltrate notifications
- Attempt to remove or alter local evidence before remote revocation
- Abuse the approval to influence the pull-request process

### Kill chain (if applicable)

- Reconnaissance
- Delivery
- Exploitation
- Actions on Objectives

### Proposed controls

- Require MDM enrollment, device encryption, screen lock, and remote wipe for any approval client
- Store tokens and keys in hardware-backed secure storage and avoid caching raw source or secrets
- Require biometric or step-up authentication for approvals and bind sessions to device posture
- Use short-lived scoped approval tokens with immediate revocation and push-token rotation
- Keep notifications minimal: no source code, secrets, or full finding bodies in push payloads
- Log mobile approval actions server-side with device attestation where possible

### Proposed acceptance tests

- A revoked mobile session or wiped device cannot approve or read new findings
- Approval from a device without biometric or compliant posture is rejected
- Push notifications and local cache contain no source snippet, secret, or API key
- Stolen token replay from a different device fails due to binding or attestation
- All mobile approvals create immutable server-side audit records

### Evidence gaps

- Whether mobile clients are used for approvals is an assumption, not a supplied fact
- MDM, biometric, secure-storage, and token-revocation details are unknown
- Push notification content policy is not specified

### Framework references

- [OWASP_MASVS](https://mas.owasp.org/)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_CSF](https://www.nist.gov/cyberframework)

## TM-007: MCP tool and resource surface could be manipulated by untrusted findings to invoke unintended tools or alter triage artifacts

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-007`

**Domain:** mcp | **STRIDE:** Tampering | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Indirect prompt injection in scanned code or findings, a malicious MCP tool or resource provider, or an over-privileged MCP client | **Asset:** MCP server, exposed tools, LLM context, remediation artifacts, audit evidence, Docker validation inputs | **Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; assumed MCP client/server/tool boundary around LLM access

**Attack hypothesis:** If MCP tools are reachable from model reasoning over untrusted findings, an indirect prompt injection could hypothesized to cause the agent to call file, network, patch, or validation tools in unintended ways, producing tampered triage or remediation artifacts even when final merge remains human-gated.

### Preconditions

- An MCP server exposes tools such as file read, patch generation, test execution, or Docker validation to an LLM
- Tool descriptions, resources, or arguments can include untrusted repository or finding text
- State-changing tools are not individually confirmed by a human
- Tool scopes are broader than needed for triage
- MCP client does not validate tool schemas or constrain egress

### Attack tree

- Untrusted repository content or scanner finding enters the LLM context or an MCP resource
- Injected instructions request a sensitive tool call or data transformation
- MCP client executes the tool with excessive scope
- Files, patches, tests, evidence, or validation inputs are modified
- Human review receives a plausible but tampered artifact

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Treat all MCP tool inputs and resource contents as untrusted data, never as instructions
- Allowlist tools per task and apply least-privilege scopes, separate read-only triage from state-changing tools
- Require human confirmation for any tool that writes files, creates patches, runs Docker, or sends data externally
- Validate tool schemas and reject unexpected arguments, paths, or commands
- Isolate the MCP server, restrict its egress, and log every tool call with arguments and results
- Sanitize tool outputs before they re-enter the prompt or become artifacts

### Proposed acceptance tests

- A prompt-injection string in a finding cannot invoke network, file-write, patch, or Docker tools outside the task allowlist
- A tool call with an unexpected argument or path is rejected and logged
- State-changing MCP tool calls require an explicit human confirmation record
- Tool output containing injection text is sanitized before use in later prompts or artifacts
- The MCP server cannot reach non-allowlisted network destinations

### Evidence gaps

- Whether MCP is used, and which tools/resources it exposes, is an assumption
- Tool permission model, human-confirmation enforcement, and MCP server network isolation are unknown
- Prompt and tool-output sanitization rules are not supplied

### Framework references

- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)

## TM-008: Agentic orchestration could be steered toward malicious or over-broad remediation that passes self-validation and human review

**Source:** `remediation/threat-models/cybersecurityagent-threat-model-v3-test.json` / `TM-008`

**Domain:** agentic-ai | **STRIDE:** Tampering | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Indirect prompt injection from repository content or findings, compromised model endpoint, reward hacking by the agent, or over-trusted automation in the review pipeline | **Asset:** Generated patches and tests, Docker validation results, remediation artifacts, human approval process, pull-request process, audit evidence | **Trust boundary:** AI-generated proposals to human approval and pull-request process; host filesystem to Docker validation workspace; untrusted repository files and scanner findings to LLM prompt

**Attack hypothesis:** If the agent has broad tool access and validation is not independent of the agent, untrusted input could hypothesized to steer it toward a remediation that looks correct, passes self-generated tests, and is approved by a human, even though the platform is intended to be review-only and non-deploying.

### Preconditions

- The orchestrating agent can read findings, propose patches, generate tests, and invoke validation tools
- Validation may rely partly on agent-generated tests or agent-selected checks
- Docker workspace isolation is assumed but not verified for mounts, capabilities, or image provenance
- Human review may be based on agent-written summaries rather than full diffs
- Model endpoint, MCP tools, or prompt context can be influenced by untrusted input

### Attack tree

- Agent consumes attacker-influenced findings or source snippets
- Optimization for a plausible fix introduces a hidden behavior change, backdoor, or unsafe dependency
- Agent-generated tests validate only the visible fix and miss the malicious change
- Validation workspace accepts the artifact because isolation or signing checks are weak
- Human approver accepts a plausible summary or PR and the tampered artifact enters review history

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Keep merge and deployment strictly human-gated and technically separate from agent tool permissions
- Require independent, non-agent-generated security regression tests plus deterministic diff review for every proposed patch
- Run validation in a network-disabled, non-root, capability-dropped container with read-only source mounts and verified image provenance
- Sign remediation artifacts and audit evidence, and record the exact prompt, model endpoint, tool calls, and diff hash
- Constrain agent goals and tools with explicit policies, and require confirmation for state-changing actions
- Use canary and behavioral tests that would fail on hidden exfiltration, privilege changes, or unexpected dependencies
- Apply AI risk governance with accountable human oversight, monitoring, and incident response for unsafe proposals

### Proposed acceptance tests

- A proposed patch that changes behavior outside the stated finding is flagged by independent diff or test checks before human approval
- Validation cannot be marked passed using only agent-generated tests; at least one independent test source is required
- The validation container cannot reach the network, write outside its workspace, escape to host filesystem, or run as root
- Unsigned or provenance-unverified artifacts are rejected before review
- Approval records include immutable links to prompt hash, tool-call log, patch diff, validation result, and approver identity
- An injected instruction cannot cause the agent to skip validation, alter audit records, or request deployment

### Evidence gaps

- Agent tool permissions, goal constraints, and human-confirmation enforcement are not specified
- Independence of validation tests from the agent is unknown
- Docker sandbox hardening and artifact signing/provenance are unverified
- AI governance ownership, monitoring, and incident-response process are not described

### Framework references

- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OECD_AI_PRINCIPLES](https://www.oecd.org/en/topics/ai-principles.html)
- [ISO_42001](https://www.iso.org/standard/42001)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)

## TM-009: Repudiation of privileged review and workflow actions

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-001`

**Domain:** iam | **STRIDE:** Repudiation | **Likelihood:** Unknown | **Impact:** High

**Threat actor:** Compromised developer or approver account, misused GitHub Actions token, or malicious insider | **Asset:** GitHub repository approval state, audit evidence, generated remediation artifacts | **Trust boundary:** AI-generated proposals to human approval / pull-request process; developer workstation to GitHub repository

**Attack hypothesis:** If approval and workflow events are not immutably bound to strongly authenticated identities, an actor could approve or alter remediation artifacts and later credibly deny the action, leaving the review trail unable to establish who decided what.

### Preconditions

- Branch protections, required reviewers, and environment approvals are unknown
- Approval and workflow events may not be append-only or cryptographically bound to authenticated identities
- Short-lived least-privilege tokens, MFA for approvers, and commit/PR signing are not confirmed

### Attack tree

- Obtain or misuse an approver identity or Actions token
- Bypass or find absence of branch protection or environment approval
- Approve, reject, or alter review decisions and remediation artifacts
- Later deny the action because audit records do not establish attribution

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Require phishing-resistant MFA and least-privilege, short-lived tokens for approvers and workflow identities.
- Enforce branch protections, required reviews, and environment approvals with separation of duties.
- Write approval, merge, reject, and artifact-creation events to append-only audit logs with synchronized time and integrity protection.
- Bind approvals to signed commits or signed review artifacts where supported.
- Alert on anomalous approval patterns and require re-authentication for high-impact actions.

### Proposed acceptance tests

- A non-approver or token-scoped identity attempting to approve a protected branch is denied and the denial is logged.
- Any attempt to modify or delete an approval audit record outside the audit service is denied and generates an alert.
- A review decision can be cryptographically tied to an authenticated identity and timestamp in the audit export.
- Revocation of an approver credential prevents further approvals after revocation propagation.

### Evidence gaps

- Actual GitHub branch protections and environment approval settings are unknown.
- Audit-log storage, retention, immutability, and clock synchronization are unspecified.
- Commit/PR signing and approval identity binding are not described.

### Framework references

- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_63](https://pages.nist.gov/800-63-4/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [ISO_27001](https://www.iso.org/standard/27001)

## TM-010: Repudiation of evidence provenance and external-disclosure approval

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-002`

**Domain:** data | **STRIDE:** Repudiation | **Likelihood:** Unknown | **Impact:** High

**Threat actor:** Pipeline actor with write access to evidence storage, compromised CI runner, or a party disputing whether source was disclosed externally | **Asset:** Sanitized scanner evidence, proprietary source snippets, security findings, disclosure-approval records | **Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If sanitized evidence, disclosure approvals, and outbound LLM requests are not integrity-protected and correlated, an actor could later deny that a particular source-derived snippet was sent to an external model or who approved it.

### Preconditions

- Evidence sanitization and external-disclosure approval steps may lack signed, append-only records
- Prompt contents, egress requests, and API responses may not be logged with integrity and correlation IDs
- Reviewer identity and approval decision may not be bound to the exact disclosed snippet hash

### Attack tree

- Untrusted repository content or scanner finding enters the pipeline
- Sanitization or disclosure-approval step occurs without a signed, append-only record
- Evidence, approval, or egress logs are altered, deleted, or never correlated
- It becomes impossible to prove who approved disclosure of which source-derived data

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Record hashes of inputs, sanitized evidence, prompts, model versions, and approval decisions in an append-only audit trail.
- Require explicit, identity-bound, non-repudiable approval before any source-aware disclosure to an external model.
- Log outbound API requests and responses with redaction, retention, and integrity protection.
- Separate evidence storage from CI runner write access and restrict log mutation to an audit service.
- Include disclosure decisions in reproducible evidence packages reviewed by humans.

### Proposed acceptance tests

- For a sample external-disclosure approval, the audit export shows approver identity, timestamp, input hash, prompt hash, and destination without gaps.
- Modifying or deleting a historical evidence record as a pipeline identity is denied and alerted.
- A disclosure attempt without an approval record fails closed and is logged.
- A replayed or altered approval token cannot authorize a second disclosure.

### Evidence gaps

- The source-snippet review and approval process for external disclosure is listed as unknown.
- No evidence of prompt/egress logging, hashing, or append-only audit storage is supplied.
- Credential storage and key rotation arrangements are unknown.

### Framework references

- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_800_53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [ISO_27001](https://www.iso.org/standard/27001)

## TM-011: Repudiation of model-assisted triage, tool actions, and remediation proposals

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-003`

**Domain:** agentic-ai | **STRIDE:** Repudiation | **Likelihood:** Unknown | **Impact:** High

**Threat actor:** Malicious repository contributor, prompt-injection-driven agent behavior, or compromised orchestrator session | **Asset:** LLM prompts and outputs, tool-call traces, Mistral/Ollama API usage logs, generated patches and tests | **Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; local orchestrator to Ollama HTTP service; GitHub Actions runner to external Mistral API

**Attack hypothesis:** If agent prompts, tool invocations, model outputs, and resulting proposals are not immutably attributed to a session, input, model version, and actor, a party could deny that the agent disclosed data, selected a finding, or generated a specific patch.

### Preconditions

- LLM sessions may not log prompts, tool calls, model outputs, and decisions with integrity and attribution
- Model version, system prompt, and policy version may not be recorded per action
- Generated proposals may not be bound to the input finding, session ID, or approving human

### Attack tree

- Untrusted input reaches an LLM-orchestrated triage or remediation step
- Agent performs tool calls, external API calls, or generates proposals
- Session records are incomplete, mutable, or not tied to an authenticated actor
- The actor or session later denies the model-assisted action or disclosure

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Log every model call with session ID, actor, input hash, system prompt hash, model version, tool calls, outputs, and downstream actions in append-only storage.
- Require human approval records that reference the exact generated artifact hash before any PR or remediation use.
- Bind external API usage and local Ollama calls to an authenticated orchestrator identity and policy decision.
- Apply least privilege to agent tools and separate read-only triage from write-capable remediation tools.
- Establish AI incident governance so model-assisted decisions are reviewable and attributable.

### Proposed acceptance tests

- For a sampled generated patch, the audit trail links finding ID, input hash, prompt/model version, tool calls, artifact hash, and human approval.
- Deleting or editing a model-call log entry as the orchestrator service account is denied and alerted.
- An unapproved generated artifact cannot be referenced by a pull request in the review workflow.
- Changing the model version or system prompt creates a new policy/audit context rather than overwriting history.

### Evidence gaps

- No LLM session logging, prompt hashing, model versioning, or tool-call audit spec is provided.
- No approval-to-artifact binding mechanism is described.
- Whether external Mistral usage and local Ollama usage are logged with the same rigor is unknown.

### Framework references

- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [ISO_42001](https://www.iso.org/standard/42001)
- [OECD_AI_PRINCIPLES](https://www.oecd.org/en/topics/ai-principles.html)

## TM-012: Denial of service through untrusted input resource exhaustion in AI triage

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-004`

**Domain:** agentic-ai | **STRIDE:** Denial of Service | **Likelihood:** Medium | **Impact:** High

**Threat actor:** Attacker-controlled repository content, malicious dependency, or crafted scanner finding designed to exhaust model or compute resources | **Asset:** CI/CD runners, Mistral API quota, local Ollama endpoint and workstation, triage pipeline availability | **Trust boundary:** Untrusted repository files and scanner findings to LLM prompt; GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service

**Attack hypothesis:** Crafted inputs could cause oversized contexts, repeated retries, long generations, or heavy local inference, stalling the triage pipeline or exhausting paid API quota if budgets and timeouts are not enforced.

### Preconditions

- Sanitization may not cap input size, token count, file count, nesting, or repetition
- No per-job token budget, timeout, retry limit, or queue isolation is confirmed
- Local Ollama inference load and external API rate limits are unknown

### Attack tree

- Attacker-controlled repository content or finding reaches scanner or LLM prompt
- Sanitizer fails to bound context size, complexity, or number of derived prompts
- Mistral API or local Ollama performs large generations, retries, or long inference
- CI job, queue, API quota, or workstation becomes unavailable to legitimate work

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Enforce maximum input size, token count, file count, and prompt depth before any LLM call.
- Set per-job and per-run budgets for tokens, API calls, wall-clock time, retries, and concurrency.
- Use timeouts, exponential backoff, circuit breakers, and queue isolation for external model calls.
- Prefer local/offline models for untrusted content where feasible and cap local inference CPU, memory, and concurrency.
- Reject or quarantine pathological inputs detected by deterministic checks before model invocation.

### Proposed acceptance tests

- A test repository containing an oversized or highly repetitive finding is rejected before an external LLM call and the rejection is logged.
- A job exceeding configured token/time/API-call budgets is terminated automatically and reported.
- When Mistral is unavailable or rate-limited, the pipeline fails closed or falls back to a queued/offline path without blocking other jobs.
- Local Ollama inference for untrusted content cannot exceed configured CPU/memory/concurrency limits.

### Evidence gaps

- No sanitizer limits, token budgets, retry policies, or queue design are specified.
- Mistral quota/rate-limit handling and Ollama resource limits are unknown.
- Whether untrusted content can reach the external model without deterministic pre-filtering is not evidenced.

### Framework references

- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [NIST_AI_RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-013: Denial of service through assumed tool/MCP-style validation loops

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-005`

**Domain:** mcp | **STRIDE:** Denial of Service | **Likelihood:** Unknown | **Impact:** Medium

**Threat actor:** Untrusted model output or repository content that reaches assumed tool orchestration and triggers repeated validation work | **Asset:** Docker validation workspace, CI/CD runner time, orchestrator tool endpoints, generated test/patch artifacts | **Trust boundary:** Host filesystem to Docker validation workspace; AI-generated proposals to human approval / pull-request process

**Attack hypothesis:** If tool-style orchestration allows model-influenced repeated Docker validation without resource caps or idempotency, untrusted content could keep the validator busy and deny service to legitimate remediation review.

### Preconditions

- The mcp domain was requested, but no MCP server or tool schema is explicitly described in the design
- Generated tests/patches are executed in temporary Docker, but CPU, memory, disk, network, and time limits are unknown
- No tool-call budget, idempotency key, recursion depth limit, or approval gate for repeated validation is confirmed

### Attack tree

- Untrusted repository content influences model-generated tool calls or validation requests
- Tool results or proposed tests lack idempotency and recursion limits
- Repeated or nested Docker validation jobs are spawned
- Runner CPU, memory, disk, or job time is exhausted and validation becomes unavailable

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Treat any MCP/tool endpoint as a trust boundary requiring authentication, authorization, and per-caller call budgets.
- Limit tool recursion depth, concurrency, idempotency-key reuse, and maximum jobs per finding.
- Run validation in network-disabled containers with explicit CPU, memory, disk, pids, and wall-clock limits.
- Require deterministic pre-checks and human approval before expensive validation of generated artifacts.
- Quarantine validation workspaces and prevent host filesystem access beyond the declared mount.

### Proposed acceptance tests

- A tool-call sequence that exceeds configured depth, count, or duplicate idempotency key is rejected and logged.
- A validation container attempting network egress or exceeding resource limits is killed and reported.
- Parallel validation jobs cannot exceed the configured global concurrency limit.
- Re-running the same artifact hash does not spawn unbounded duplicate jobs.

### Evidence gaps

- No MCP server, tool list, protocol, or authentication model is supplied.
- Docker validation resource limits and network-disabled enforcement are asserted in intent but not evidenced.
- Whether tool calls can be initiated directly by model output without human approval is unknown.

### Framework references

- [OWASP_MCP](https://owasp.org/projects/mcp-top-10)
- [MITRE_ATLAS](https://atlas.mitre.org/)
- [NIST_AI_100_2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [GOOGLE_SAIF](https://www.saif.google/secure-ai-framework)
- [OWASP_AGENTIC](https://owasp.github.io/www-project-agentic-skills-top-10/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)

## TM-014: Denial of service to local Ollama and egress/network path

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-006`

**Domain:** network | **STRIDE:** Denial of Service | **Likelihood:** Unknown | **Impact:** Medium

**Threat actor:** Malicious repository content, compromised workflow, or any local process able to reach the Ollama HTTP service or egress path | **Asset:** Local Ollama HTTP service, developer workstation, CI runner egress, DNS/TLS path to external APIs | **Trust boundary:** Local orchestrator to Ollama HTTP service; GitHub Actions runner to external Mistral API

**Attack hypothesis:** Without verified loopback-only Ollama access and egress controls, untrusted content or a compromised workflow could generate enough local or outbound requests, or malformed DNS/TLS traffic, to degrade the services the pipeline depends on.

### Preconditions

- Loopback-only binding for Ollama is listed as unknown rather than enforced
- Egress allowlists, DNS resolution controls, and TLS validation are not specified
- No rate limiting or request-size caps for local HTTP calls are confirmed

### Attack tree

- Untrusted content induces high-volume requests to Ollama or external endpoints
- Loopback-only, egress allowlist, DNS, or TLS validation is absent or misconfigured
- Malformed or repeated requests consume local service, resolver, or egress capacity
- Scanning, triage, or remediation steps that depend on network services stall

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Bind Ollama to loopback or an authenticated local socket and verify with network policy that no other host can reach it.
- Enforce egress allowlists for runners with default-deny and explicit destinations for Mistral and GitHub APIs.
- Cap request rate, concurrency, and payload size for all local and external HTTP calls.
- Validate TLS certificates and use pinned/authorized CA roots; avoid disabling validation for convenience.
- Monitor DNS/TLS failures and request volume as availability signals with alerts.

### Proposed acceptance tests

- From a non-loopback address, a connection to the Ollama port is refused and logged.
- A runner with default-deny egress cannot reach an unapproved external host but can reach approved API endpoints.
- Requests exceeding local rate/size limits are throttled or rejected without crashing the orchestrator.
- TLS validation failure against a test endpoint causes fail-closed behavior rather than silent fallback.

### Evidence gaps

- Actual network controls enforcing loopback-only Ollama are unknown.
- Egress allowlists, DNS filtering, TLS validation, and certificate pinning are not described.
- No rate-limit or availability monitoring evidence is supplied.

### Framework references

- [OSA](https://www.opensecurityarchitecture.org/frameworks/)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [NIST_CSF](https://www.nist.gov/cyberframework)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)

## TM-015: Denial of service through exhaustion of web/API quotas and rate limits

**Source:** `remediation/threat-models/cybersecurityagent-stride-gaps-v1.json` / `TM-007`

**Domain:** web-api | **STRIDE:** Denial of Service | **Likelihood:** Medium | **Impact:** Medium

**Threat actor:** Crafted findings, retry loops, or a compromised Actions token causing excessive calls to Mistral, GitHub, or local HTTP APIs | **Asset:** Mistral API key quota, GitHub Actions token, CI runner availability, web/API-dependent workflow steps | **Trust boundary:** GitHub Actions runner to external Mistral API; local orchestrator to Ollama HTTP service

**Attack hypothesis:** If outbound API calls are not budgeted or throttled, a small number of crafted findings or a retry storm could exhaust external API quota or rate limits and make the assessment workflow unavailable.

### Preconditions

- API quotas, IP rate limits, and backoff behavior for Mistral and GitHub are unknown
- No per-job request budget, circuit breaker, or concurrency cap is confirmed
- Secrets may be long-lived and usable for repeated API calls until rotated

### Attack tree

- Untrusted input or retry logic generates many API requests
- No quota-aware throttling, backoff, or circuit breaker stops the calls
- Mistral quota, GitHub rate limit, or local Ollama concurrency is exhausted
- API-dependent scan, triage, and review steps fail for legitimate jobs

### Kill chain (if applicable)

- None supplied

### Proposed controls

- Set explicit per-job and per-repository request budgets for Mistral, GitHub, and local HTTP APIs.
- Implement timeouts, exponential backoff, jitter, circuit breakers, and concurrency caps for all web/API calls.
- Use short-lived, scoped tokens and rotate API keys; alert on unusual call volume or destination.
- Cache deterministic results and avoid repeated identical LLM/API calls.
- Fail closed with clear audit records when quota or rate limits are reached.

### Proposed acceptance tests

- A test job that exceeds its configured API request budget stops making calls, records the event, and reports failure.
- When an API returns rate-limit responses, the pipeline backs off and does not retry in a tight loop.
- A revoked or expired Mistral key cannot be used by the workflow after revocation propagates.
- Concurrent jobs share a global API budget and cannot collectively exceed it.

### Evidence gaps

- Mistral and GitHub quota/rate-limit configurations are unknown.
- Retry/backoff/circuit-breaker behavior is not specified.
- Key rotation and credential storage arrangements are listed as unknown.

### Framework references

- [OWASP_WEB](https://owasp.org/Top10/2025/)
- [OWASP_TM](https://owasp.org/www-community/Threat_Modeling_Process)
- [MITRE_ATTACK](https://attack.mitre.org/)
- [CIS_CONTROLS](https://www.cisecurity.org/controls)
- [NIST_CSF](https://www.nist.gov/cyberframework)

## Review requirements

- Verify provenance, possible duplicates, architecture assumptions, threat relevance and exact standards mappings.
- No tests executed and no patches applied.
