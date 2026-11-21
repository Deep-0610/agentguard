# Security Review Checklist

Use this checklist as a release evidence tracker. An unchecked item is not complete. Link each completed item to test output, review notes, configuration, or an independent report.

## Current scanner MVP

- [ ] Verify report outputs do not expose secrets through environment variables, arguments, commands, URL userinfo/query values, metadata, or tool schema fields.
- [ ] Verify every finding's evidence and identifiers do not contain raw credentials.
- [ ] Test malformed JSON, deeply nested JSON, duplicate keys, invalid UTF-8, Unicode, and oversized files.
- [ ] Bound directory traversal by file count and total bytes.
- [ ] Test symlink and permission edge cases.
- [ ] Add fuzz tests for parsers, redaction, URL parsing, and rule evaluation.
- [ ] Validate SARIF output against the SARIF 2.1.0 schema.
- [ ] Add deterministic tests for rule IDs and schema fingerprints.
- [ ] Add false-positive and false-negative fixtures for every detection rule.
- [ ] Document supported formats and known blind spots.

## Build and supply chain

- [ ] Enforce formatting without mutating source during CI.
- [ ] Run tests, race detector, vet, static analysis, and vulnerability scanning. Go tests, race detector, vet, and govulncheck are present in CI; broader static analysis and container scanning remain outstanding.
- [ ] Generate an SBOM for each release.
- [ ] Sign release artifacts and publish checksums.
- [ ] Generate build provenance.
- [ ] Pin third-party GitHub Actions to reviewed commit SHAs.
- [ ] Protect main branch with required checks and review.
- [ ] Enable dependency update automation and vulnerability alerts.
- [ ] Establish release rollback and artifact retention procedures.

## Hosted control plane

- [ ] Tenant isolation verified for every API and data-access path.
- [ ] Cross-tenant access tests run automatically.
- [ ] OIDC/SSO implementation independently reviewed.
- [ ] MFA or step-up auth required for privileged actions. TOTP step-up currently protects API-key revocation; OIDC user-level MFA is not implemented.
- [ ] RBAC and resource-level authorization tested deny-by-default.
- [ ] Secrets encrypted with managed KMS-backed envelope encryption.
- [ ] Sensitive values excluded from logs, traces, analytics, and error messages.
- [ ] Audit log integrity, retention, and export tested.
- [ ] CSRF, CORS, SSRF, injection, IDOR, and rate-limit tests completed.
- [ ] Backups encrypted and restore tested.
- [ ] Data deletion and retention controls verified.
- [ ] Incident response and breach notification procedures approved.

## Connectors

- [ ] Permission/scope matrix documented per provider.
- [ ] Read-only mode verified by tests.
- [ ] OAuth state, PKCE, issuer, audience, redirect URI, and token expiry validated.
- [ ] Refresh token handling and revocation tested.
- [ ] Webhook signatures validated and replay protection implemented.
- [ ] Pagination, retries, rate limits, and partial sync behavior tested.
- [ ] Provider payloads treated as untrusted input.
- [ ] Connector sync health and permission changes observable.

## Runtime gateway

- [ ] MCP protocol version and transport behavior explicitly documented.
- [ ] Token issuer, signature, expiry, audience/resource and scopes validated.
- [ ] No token passthrough to unintended resource servers.
- [ ] Tool-level authorization tests cover allow, deny, and unknown tools.
- [ ] Prompt injection and malicious tool output threat scenarios tested.
- [ ] Request replay, rate limits, timeouts, and denial-of-service addressed.
- [ ] Approval flow prevents spoofing, replay, and expired approvals.
- [ ] Fail-open/fail-closed behavior documented and tested.
- [ ] Sensitive request/response data minimized in logs.

## External assurance

- [ ] Independent penetration test completed and findings remediated.
- [ ] Privacy and data protection review completed.
- [ ] Customer security questionnaire answered with evidence.
- [ ] DPA, terms, privacy notice, and subprocessors reviewed by counsel.
- [ ] Support escalation, incident communications, and status page operational.
- [ ] SLOs and service limits published.
- [ ] Disaster recovery exercise completed.

## Approval

| Role | Name | Date | Evidence / decision |
|---|---|---|---|
| Engineering owner | TBD | TBD | TBD |
| Security reviewer | TBD | TBD | TBD |
| Product owner | TBD | TBD | TBD |
| Release approver | TBD | TBD | TBD |
