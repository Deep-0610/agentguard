# Roadmap

## Phase 1 - Local scanner

- [x] MCP JSON config parsing
- [x] Secret-pattern checks with redaction
- [x] HTTP endpoint warning
- [x] Shell launch warning
- [x] Tool schema fingerprinting when declarations are present
- [x] Table, JSON, HTML, and SARIF reports
- [x] Unit tests and CI workflow
- [ ] Additional client-specific config formats and broader fixture coverage
- [ ] Release binaries and signed checksums

## Phase 2 - Open-source hardening

- [ ] Plugin interface for identity and SaaS inventory connectors
- [ ] Baseline persistence and schema drift comparison
- [ ] GitHub, Okta, Entra ID, and Google Workspace inventory adapters
- [ ] Policy-as-code examples and richer SARIF rules

## Phase 3 - Governance control plane

- [ ] Tenant-aware API and PostgreSQL data model
- [ ] Identity graph and ownership attribution
- [ ] RBAC, MFA, immutable audit trail, and approval workflows
- [ ] OPA/Rego policy evaluation and drift monitoring

## Phase 4 - Runtime gateway

- [ ] MCP protocol proxy
- [ ] OAuth 2.1 token validation and audience binding
- [ ] Per-tool policy enforcement
- [ ] Human-in-the-loop approvals for sensitive tool calls

A checked item means code is present in this repository; unchecked items are not implemented.
