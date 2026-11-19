# Threat-model security requirements and verification review

> Offline derivation from an AI-generated model. No standards clauses independently verified; no tests executed.

**Source SHA-256:** `34b62a57b5ad0e9d6ee3c733023503400522dedad3814835cb6b949c7caf7720`

**Scenarios:** 16 | **Requirements:** 64 | **Proposed tests:** 64

## STRIDE coverage

| STRIDE | Scenarios |
|---|---:|
| Spoofing | 3 |
| Tampering | 5 |
| Repudiation | 0 |
| Information Disclosure | 5 |
| Denial of Service | 1 |
| Elevation of Privilege | 2 |

## Domain coverage

| Domain | Scenarios |
|---|---:|
| iam | 2 |
| pki | 2 |
| network | 3 |
| data | 2 |
| web-api | 2 |
| mobile | 1 |
| mcp | 2 |
| agentic-ai | 2 |

## Gaps requiring review

- **STRIDE_NOT_COVERED** (global): Repudiation
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-001): Actual workflow files; GITHUB_TOKEN permission blocks; OIDC trust configuration; branch protection and environment approval settings; secret scoping
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-002): MFA enforcement evidence; session lifetime policy; commit signing configuration; device posture integration; approval audit log format
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-003): Key custody location; signing workflow; verification policy; provenance format; rotation evidence
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-004): HTTP client configuration; pinning policy; Ollama transport/auth details; egress allowlist; certificate monitoring
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-005): Actual bind address; auth token presence; firewall rules; proxy exposure; logging of access
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-006): Runner network policy; egress allowlist; secret masking config; proxy/DLP rules; log retention
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-007): Sanitizer implementation; approval workflow; redaction test corpus; Mistral data handling terms; egress payload inspection
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-008): Evidence storage location; hash/signing scheme; audit log permissions; retention policy; approval binding format
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-009): Custom web/API routes; webhook secret handling; token scopes; source allowlists; approval enforcement points
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-010): Review UI stack; markdown sanitizer; CSP headers; iframe usage; approval action URLs
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-011): Mobile app existence; storage mechanism; session lifetime; pinning implementation; notification content policy
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-012): MCP server implementation; tool inventory; permission model; confirmation UX; sandbox runtime flags
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-013): Tool provenance; prompt/system instruction design; policy engine; trace retention; output validation rules
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-014): Prompt templates; delimiting strategy; output validation; canary deployment; approval enforcement point
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-015): Model provenance process; hash pinning; output monitoring; regression corpus; fallback procedure
- **IMPLEMENTATION_EVIDENCE_MISSING** (TM-016): Docker run flags; rootless configuration; seccomp profile; resource limits; network policy; workspace teardown evidence

## Domain × STRIDE analysis

A missing combination is a review prompt, not automatically a defect.

| Domain | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| iam | 1 | 0 | 0 | 0 | 0 | 1 |
| pki | 0 | 1 | 0 | 1 | 0 | 0 |
| network | 0 | 0 | 0 | 2 | 1 | 0 |
| data | 0 | 1 | 0 | 1 | 0 | 0 |
| web-api | 1 | 1 | 0 | 0 | 0 | 0 |
| mobile | 0 | 0 | 0 | 1 | 0 | 0 |
| mcp | 1 | 0 | 0 | 0 | 0 | 1 |
| agentic-ai | 0 | 2 | 0 | 0 | 0 | 0 |

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
