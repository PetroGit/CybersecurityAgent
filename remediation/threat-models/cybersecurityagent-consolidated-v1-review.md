# Threat-model security requirements and verification review

> Offline derivation from an AI-generated model. No standards clauses independently verified; no tests executed.

**Source SHA-256:** `00c797728b58c42dcf53186685e44a371fdd72e49839d0657393f92068e83eab`

**Scenarios:** 15 | **Requirements:** 88 | **Proposed tests:** 69

## STRIDE coverage

| STRIDE | Scenarios |
|---|---:|
| Spoofing | 3 |
| Tampering | 2 |
| Repudiation | 3 |
| Information Disclosure | 2 |
| Denial of Service | 4 |
| Elevation of Privilege | 1 |

## Domain coverage

| Domain | Scenarios |
|---|---:|
| iam | 2 |
| pki | 1 |
| network | 2 |
| data | 2 |
| web-api | 2 |
| mobile | 1 |
| mcp | 2 |
| agentic-ai | 3 |

## Gaps requiring review

- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-001): Actual workflow permissions blocks, OIDC configuration, branch protection rules, and secret scopes are not provided; Developer MFA method and session-binding controls are unknown; Audit log retention and tamper-evidence for Actions and repository events are unknown
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-002): Actual TLS validation, pinning, and CA trust configuration are not provided; Ollama binding and authentication details are unknown; Whether artifacts or images are signed, and where keys are stored, is not specified; Internal PKI policy, certificate lifetimes, and revocation mechanisms are unknown
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-003): Actual egress controls, DNS policy, and proxy configuration are not provided; Ollama bind address and firewall rules are unknown; Docker runtime network, mount, capability, and seccomp settings are unverified; Logging coverage for outbound traffic is unknown
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-004): Sanitization rules, redaction patterns, and disclosure approval workflow are not supplied; Mistral data retention, training use, and logging behavior are unknown; Prompt templates and which finding fields are sent externally are not specified; Whether canary or secret detection runs before egress is unverified
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-005): It is not confirmed that a web API exists; if it does, its authentication, authorization, and exposure are undescribed; Webhook signing and callback verification are unknown; Audit record immutability and access controls are unknown
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-006): Whether mobile clients are used for approvals is an assumption, not a supplied fact; MDM, biometric, secure-storage, and token-revocation details are unknown; Push notification content policy is not specified
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-007): Whether MCP is used, and which tools/resources it exposes, is an assumption; Tool permission model, human-confirmation enforcement, and MCP server network isolation are unknown; Prompt and tool-output sanitization rules are not supplied
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-008): Agent tool permissions, goal constraints, and human-confirmation enforcement are not specified; Independence of validation tests from the agent is unknown; Docker sandbox hardening and artifact signing/provenance are unverified; AI governance ownership, monitoring, and incident-response process are not described
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-009): Actual GitHub branch protections and environment approval settings are unknown.; Audit-log storage, retention, immutability, and clock synchronization are unspecified.; Commit/PR signing and approval identity binding are not described.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-010): The source-snippet review and approval process for external disclosure is listed as unknown.; No evidence of prompt/egress logging, hashing, or append-only audit storage is supplied.; Credential storage and key rotation arrangements are unknown.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-011): No LLM session logging, prompt hashing, model versioning, or tool-call audit spec is provided.; No approval-to-artifact binding mechanism is described.; Whether external Mistral usage and local Ollama usage are logged with the same rigor is unknown.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-012): No sanitizer limits, token budgets, retry policies, or queue design are specified.; Mistral quota/rate-limit handling and Ollama resource limits are unknown.; Whether untrusted content can reach the external model without deterministic pre-filtering is not evidenced.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-013): No MCP server, tool list, protocol, or authentication model is supplied.; Docker validation resource limits and network-disabled enforcement are asserted in intent but not evidenced.; Whether tool calls can be initiated directly by model output without human approval is unknown.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-014): Actual network controls enforcing loopback-only Ollama are unknown.; Egress allowlists, DNS filtering, TLS validation, and certificate pinning are not described.; No rate-limit or availability monitoring evidence is supplied.
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-015): Mistral and GitHub quota/rate-limit configurations are unknown.; Retry/backoff/circuit-breaker behavior is not specified.; Key rotation and credential storage arrangements are listed as unknown.

## Domain × STRIDE analysis

A missing combination is a review prompt, not automatically a defect.

| Domain | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| iam | 0 | 0 | 1 | 0 | 0 | 1 |
| pki | 1 | 0 | 0 | 0 | 0 | 0 |
| network | 0 | 0 | 0 | 1 | 1 | 0 |
| data | 0 | 0 | 1 | 1 | 0 | 0 |
| web-api | 1 | 0 | 0 | 0 | 1 | 0 |
| mobile | 1 | 0 | 0 | 0 | 0 | 0 |
| mcp | 0 | 1 | 0 | 0 | 1 | 0 |
| agentic-ai | 0 | 1 | 1 | 0 | 1 | 0 |

## Suggested next threat-modeling pass

1. Confirm which components are implemented versus planned, and attach architecture evidence.
2. Prioritize missing STRIDE categories, particularly repudiation of approvals and evidence provenance.
3. Add scenario hypotheses only where assets, trust boundaries and plausible preconditions support them.
4. Verify exact framework control/category IDs against official publications before assigning compliance mappings.
5. Turn proposed acceptance criteria into independently reviewed, isolated tests; record results separately.
6. Reassess likelihood and impact using observed controls and threat intelligence.

## Artifact descriptions

- Requirements CSV/JSON: proposed security requirements with unverified framework pointers.
- Test catalog CSV/JSON: proposed tests, NOT runnable test code.
- Coverage gaps JSON: systematic gaps and evidence requests.
