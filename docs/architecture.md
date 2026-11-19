# Architecture

## Design principles

1. **Read-only discovery:** the scanner reads local configuration and never starts discovered processes or contacts discovered services.
2. **Offline by default:** scanning and report generation require no network access. Upload is a separate explicit command.
3. **Evidence over assumptions:** findings include a category, severity, score, location, and remediation guidance.
4. **Redaction by default:** environment values are omitted from server inventory output and matching secrets are redacted in findings.
5. **Tenant isolation:** tenant context is derived from authenticated credentials and included in every data access path.
6. **Fail closed:** unavailable policy evaluation never produces an allow decision.

## Scanner and ingestion flow

AgentGuard CLI → path discovery → bounded JSON reader → MCP inventory → secret/transport/execution checks → schema fingerprint → local report.

An explicit `agentguard sync` command sends normalized inventory and redacted findings to the control plane over HTTPS. It does not upload raw MCP configuration files, command arguments, environment values, or endpoint credentials. The API additionally redacts common credential patterns from untrusted free-text evidence before persistence.

## Implemented control-plane foundation

Scanner/provider ingestion → Go HTTP API → API-key authentication and tenant context → PostgreSQL inventory → OPA/Rego policy evaluator.

The PostgreSQL model currently includes organizations, API keys, scan snapshots, NHI inventory, identity relationships, identity drift history, findings, finding workflow events, and hash-chained audit events.

The control plane currently supports:
- Tenant-scoped API keys with owner/admin/analyst/viewer/ingest roles, one-time secret display, expiry, and revocation.
- Idempotent scan ingestion, risk-ranked identity inventory, identity relationships, and drift timelines.
- Server-side risk heuristics for orphaned privileged identities, toxic permission combinations, unverified OAuth apps, and stale API tokens.
- Finding triage with a recorded reason and append-only audit event.
- Per-tenant hash-chained audit records and an audit-chain verification endpoint.
- OPA/Rego policy evaluation through an internal service; decisions are audited and OPA failures return an error rather than an allow.

## Remaining platform roadmap

- **Identity connectors:** GitHub, Okta, Microsoft Entra ID, and Google Workspace with read-only scopes, incremental sync, webhook ingestion, provider ownership attribution, and credential lifecycle context.
- **Enterprise user access:** OIDC SSO, MFA/step-up authentication, SCIM provisioning, user-level RBAC, and tenant administration.
- **Policy lifecycle:** signed/versioned Rego bundles, policy simulation, approvals, exceptions, policy assignment, and decision receipts.
- **Runtime gateway:** MCP protocol proxy, OAuth 2.1 audience validation, per-tool policy enforcement, schema drift blocking, and human approval for sensitive actions.
- **Operations:** shared rate limiting, external audit checkpoint anchoring, KMS-backed encryption, observability, backups/restore drills, incident response, signed releases, SBOM/provenance, and independent penetration testing.
- **Dashboard:** browser UI and customer onboarding experience.

The control plane is an early development foundation for controlled design-partner testing. It is not a complete enterprise NHI governance platform or a security certification.
