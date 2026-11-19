# Security Roadmap and OWASP NHI Mapping

**Status:** Engineering roadmap. This document is not an attestation, audit report, or certification.

AgentGuard's risk taxonomy should be informed by the [OWASP Non-Human Identities Top 10 (2025)](https://owasp.github.io/www-project-non-human-identities-top-10/2025/top-10-2025/). The mapping below describes intended product coverage; it does not claim that the current scanner detects every listed risk.

## 1. OWASP NHI risk coverage

| OWASP risk | Product capability required | Current status |
|---|---|---|
| NHI1 Improper Offboarding | Last-seen tracking, owner and lifecycle state, stale identity detection, approved deactivation workflow | Not implemented |
| NHI2 Secret Leakage | Secret discovery, safe evidence, redaction, rotation guidance | Partial scanner heuristics |
| NHI3 Vulnerable Third-Party NHI | Integration inventory, vendor/source provenance, trust and version monitoring | Not implemented |
| NHI4 Insecure Authentication | Auth-method inventory, protocol and configuration checks, token validation in gateway | Not implemented |
| NHI5 Overprivileged NHI | Permission graph, least-privilege comparison, privilege-risk analysis | Not implemented |
| NHI6 Insecure Cloud Deployment Configurations | CI/CD identity inventory, OIDC claim and trust-policy checks | Not implemented |
| NHI7 Long-Lived Secrets | Credential metadata and expiry/rotation monitoring without collecting secret material | Not implemented |
| NHI8 Environment Isolation | Environment labels, cross-environment identity reuse detection | Not implemented |
| NHI9 NHI Reuse | Identity correlation and reuse graph | Not implemented |
| NHI10 Human Use of NHI | Workload identity attribution, activity context, anomalous human use detection | Not implemented |

## 2. Secure development baseline

Use the NIST Secure Software Development Framework (SSDF), SP 800-218, as a process reference:
- Prepare the organization: ownership, security requirements, risk acceptance and release criteria.
- Protect the software: access controls, dependency hygiene, build integrity and secrets handling.
- Produce well-secured software: secure design, code review, automated testing and vulnerability analysis.
- Respond to vulnerabilities: disclosure intake, triage, patching, release communication and lessons learned.

Reference: [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final).

## 3. Scanner hardening backlog

- [x] Add native fuzz tests for redaction, sensitive environment analysis, and JSON parsing.
- [ ] Expand fuzz coverage to malformed URLs, unusual Unicode, and report serialization.
- [x] Add explicit limits for traversal entries/depth, config count, aggregate bytes, JSON nesting, and per-file size.
- [x] Reject symlink and non-regular config inputs; verify opened file identity before reading.
- [ ] Add platform-specific race tests for path replacement and filesystem edge cases.
- [ ] Expand supported MCP client config formats based on documented fixtures.
- [ ] Detect credentials in command arguments and URL components without printing raw values.
- [ ] Ensure every report format is tested for secret leakage.
- [ ] Add stable rule IDs, rule versions, confidence, and remediation references.
- [ ] Add baseline creation and drift comparison with tamper-evident metadata.
- [ ] Add SARIF schema validation and CI integration tests.
- [ ] Add fuzzing and race-enabled tests to CI.
- [ ] Add signed releases, checksums, SBOM, and build provenance.
- [ ] Establish a vulnerability disclosure policy and response SLA.

## 4. Control-plane security backlog

- [ ] Define tenant boundary and data classification.
- [ ] Enforce tenant scope in every query, command, background job, export, and cache key.
- [ ] Add automated cross-tenant negative tests.
- [ ] Use a managed secret store; encrypt connector credentials with envelope encryption and KMS.
- [ ] Never log bearer tokens, client secrets, private keys, or raw provider payloads by default.
- [ ] Implement OIDC with secure state, nonce, PKCE where applicable, and strict issuer/audience checks.
- [ ] Implement RBAC with deny-by-default authorization and resource scoping.
- [ ] Add append-only audit event semantics and protected export.
- [ ] Add CSRF protections, secure cookies, rate limiting, request validation and security headers.
- [ ] Define retention, deletion, backup, restore, and incident response procedures.
- [ ] Run dependency, container, secret, and static analysis scans in CI.
- [ ] Complete an independent penetration test before general availability.

## 5. Connector security contract

Every connector must document:
- Provider API and supported operations.
- Exact OAuth scopes or permission grants, with justification.
- Read-only inventory behavior and any write-capable permissions.
- Token storage, refresh, rotation, and revocation behavior.
- Rate limits, pagination, retries, webhook validation, and sync checkpoints.
- Data collected, data excluded, retention, and deletion behavior.
- Provider API version and compatibility tests.
- Failure modes and what happens when a connector loses authorization.

Default to read-only permissions. Never request tenant-wide administrator permissions merely for convenience.

## 6. Gateway security contract

The gateway must be designed against the MCP authorization specification applicable to the implementation version. For HTTP transports, validate issuer, audience/resource, signature, expiry, and scopes; do not forward a token to a different resource server. Protect credentials from logs and caches. Use HTTPS for remote authorization endpoints and strict redirect URI validation.

Reference: [MCP Authorization specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/authorization.mdx).

The gateway must also address:
- Tool identity and schema integrity.
- Confused-deputy and confused-client risks.
- Prompt injection and untrusted tool output.
- Tool-call authorization and resource-level policy.
- Replay, request binding, rate limits and denial-of-service.
- Human approval spoofing, expiry, replay and separation of duties.
- Safe failure behavior and audit completeness.

## 7. Release gate

A release may be called production-ready only after the release owner can produce evidence for:
- Threat model and reviewed architecture.
- Automated test and security scan results.
- SBOM and signed release artifacts.
- Known-vulnerability review and remediation status.
- Independent security assessment for the deployed product.
- Backup/restore and incident-response exercise.
- Privacy and data-retention documentation.
- Customer support and operational SLOs.

A passing unit-test suite alone is not sufficient.
