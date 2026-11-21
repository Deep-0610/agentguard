# Roadmap

## Phase 1 — Local-first scanner

- [x] MCP JSON config parsing and bounded discovery
- [x] Secret-pattern checks with redacted evidence
- [x] Transport and shell-launch risk warnings
- [x] Tool schema fingerprinting when declarations are present
- [x] Table, JSON, HTML, and SARIF reports
- [x] Race tests, fuzz smoke tests, vet, build, and vulnerability scanning in CI
- [ ] Broader MCP client fixtures and additional config formats
- [ ] Signed release binaries, checksums, SBOM, and provenance

## Phase 2 — Commercial governance control-plane foundation

- [x] Go API and PostgreSQL tenant data model
- [x] Tenant-scoped API-key authentication and role allowlists
- [x] Concurrent-safe, checksummed schema migrations
- [x] Bounded, strict-JSON, idempotent scan ingestion
- [x] NHI inventory, relationships, identity drift history, and risk-ranked findings
- [x] Finding triage with reasons and audit history
- [x] Per-tenant hash-chained audit trail and verification
- [x] OPA/Rego policy evaluation with default deny
- [x] Tenant-owned approved tool schema baselines; client-supplied baselines are not trusted
- [x] TOTP step-up for API-key revocation, encrypted seed storage, replay protection, and lockout
- [x] OpenAPI 3.1 contract, Docker Compose, and deployment documentation
- [ ] OIDC SSO, user identities, user-level RBAC, SCIM, and IdP-enforced MFA
- [ ] Production provider connectors for GitHub, Okta, Microsoft Entra ID, and Google Workspace
- [ ] Full human approval lifecycle and policy simulation/versioning
- [ ] Browser administration dashboard and customer onboarding
- [ ] KMS-backed envelope encryption, shared rate limiting, external audit checkpoints, backup/restore drills, and independent penetration test

## Phase 3 — Identity connectors and runtime enforcement

- [ ] Read-only provider discovery with incremental sync and webhook validation
- [ ] OAuth 2.1 audience-bound MCP gateway
- [ ] Per-tool runtime authorization using tenant-approved baselines
- [ ] Human-in-the-loop approval orchestration for sensitive actions
- [ ] Safe revocation workflows with authorization, audit, and recovery controls

A checked item means implementation exists in the current development branch. It does not mean the feature has passed independent security review or is generally available.
