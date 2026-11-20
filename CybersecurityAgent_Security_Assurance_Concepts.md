# CybersecurityAgent — Security Assurance Concepts

## Overview

In **CybersecurityAgent**, five concepts represent successive stages of security assurance, from identifying a possible attack to demonstrating that a security control is effective:

1. **Threat scenario** — What could go wrong?
2. **Security requirement** — What protection must exist?
3. **Test specification** — How will we check that protection?
4. **Locally passed test** — Did the test pass in the local environment?
5. **Verified control** — Is there sufficient trustworthy evidence that the protection works in its intended environment?

> **Important:** Passing a test does not automatically mean that a security control has been verified.

## 1. Threat scenario

A **threat scenario** describes a plausible sequence of events in which a threat exploits a weakness and causes harm.

**CybersecurityAgent example:** An attacker embeds malicious instructions inside a Semgrep finding or repository source file. When CybersecurityAgent sends that information to Mistral, the attacker attempts to make the agent execute an unauthorized command or disclose sensitive information.

A useful scenario identifies the attacker, entry point, exploited weakness, attack action and potential impact.

Threat scenarios are often classified using **STRIDE**:

- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

## 2. Security requirement

A **security requirement** describes a protection the system must implement to prevent, detect or limit a threat.

For the example scenario, requirements could include:

- The agent must treat repository content and scanner findings as untrusted data.
- The agent must not execute commands originating from untrusted content.
- Sensitive information must be detected before transmission to an external LLM.
- Tool execution must be restricted to explicitly authorized operations.

A requirement defines **what must be achieved**, not necessarily how it is implemented.

## 3. Test specification

A **test specification** defines a reproducible procedure to assess a security requirement.

**Example test:** `TM-004-TEST-01`

| Element | Description |
|---|---|
| Objective | Confirm that sensitive information is not sent to the external LLM. |
| Procedure | Submit synthetic input containing API keys, credentials or cloud metadata patterns to the pre-egress screening component. |
| Expected result | The system blocks or safely handles the sensitive content before transmission. |

A complete test specification should identify preconditions, inputs, execution steps, expected results and acceptance criteria.

A specification can exist **without executable test code**. It describes what should be tested; it is not proof that the test has run.

## 4. Locally passed test

A **locally passed test** means that executable test code ran and its assertions passed in a particular environment.

The TM-004 pilot executed **nine pytest cases successfully**, covering checks related to sensitive-data screening and prompt-injection handling. These results support **two test specifications**.

This is useful **regression evidence**, but it does not necessarily demonstrate protection across the complete production architecture. Local tests may exercise a single function, use synthetic inputs, mock dependencies or omit integration paths.

## 5. Verified control

A **verified control** is a security measure whose implementation and effectiveness have been demonstrated against defined acceptance criteria, with sufficient evidence for the intended assurance level.

For the pre-egress screening requirement, verification might include:

1. Reviewing the implemented screening logic.
2. Running positive and negative tests against the actual integration path.
3. Demonstrating that blocked payloads never reach the external Mistral API.
4. Confirming that the control cannot be bypassed through alternative execution paths.
5. Retaining reproducible evidence and obtaining the required review or approval.

Verification does not necessarily require production testing or an external auditor. The evidence and independence required depend on risk and the assurance objective.

## 6. Current CybersecurityAgent baseline

The coverage report generated on **20 November 2026** recorded:

| Metric | Value | Interpretation |
|---|---:|---|
| Threat scenarios | **15** | Proposed attack scenarios in the consolidated threat model |
| Security requirements | **88** | Proposed protections derived from threat analysis |
| Test specifications | **69** | Defined security tests in the consolidated catalog |
| Locally passed test specifications | **2** | Specifications supported by passing local regression evidence |
| Passing pytest cases | **9** | Individual successful pytest cases supporting those specifications |
| Not-executed test specifications | **67** | Catalog specifications without recorded execution |
| Failed or inconclusive specifications | **0** | None recorded in this coverage report |
| Verified security controls | **0** | No completed control verification recorded |

These values represent **different units** and must not be added together. In particular, nine passing pytest cases do not mean nine verified controls.

### Local test-specification coverage

\[
\frac{2\ \text{locally passed specifications}}{69\ \text{total specifications}} \times 100 = 2.9\%
\]

The **2.9%** figure measures locally passed *test specifications*, **not** verified control effectiveness or overall system security.

Likewise, **zero verified controls** does not establish that existing protections are ineffective. It means the current evidence register has not established or recorded completed control verification.

## 7. Recommended control assurance lifecycle

A future read-only dashboard or evidence-management extension could track the following states without changing the existing validators:

| Status | Meaning |
|---|---|
| **Proposed** | Control identified from a threat scenario |
| **Implemented** | Protection exists in the code or architecture |
| **Tested locally** | Relevant automated checks passed |
| **Evidence reviewed** | Results and scope have been assessed |
| **Verified** | Defined acceptance criteria have been satisfied |
| **Monitoring** | Control remains subject to ongoing checks |

This lifecycle distinguishes three questions:

- **Coverage:** Have tests been defined for the identified threats?
- **Validation:** Have those tests been executed successfully?
- **Assurance:** Is there sufficient evidence that the controls are effective?

Maintaining this distinction helps CybersecurityAgent support auditable assessments aligned with frameworks such as **ISO 27001**, **NIST CSF 2.0**, **DORA** and AI security assurance frameworks.

## 8. Key takeaway

**Threat scenarios → Security requirements → Test specifications → Locally passed tests → Verified controls**

Each stage adds evidence, but progression is **not automatic**. In particular, local test success must be assessed for relevance, completeness and reliability before any control is marked verified.

---

*Document scope: explanatory reference based on the previously discussed CybersecurityAgent coverage report. No validation engines or project code were changed.*
