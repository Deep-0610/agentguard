# AgentGuard Control Plane — Phase 2 foundation

This service is the first commercial control-plane slice: tenant-scoped scan ingestion, NHI inventory, finding workflows, API-key administration, and append-only tamper-evident audit events.

## Implemented in this slice

- PostgreSQL-backed organizations, API keys, scan snapshots, identities, findings, finding history, and audit events.
- Tenant identity is derived only from a validated API key; client-supplied tenant IDs are not trusted.
- High-entropy API keys are shown once and stored as HMAC-SHA256 digests using a deployment pepper.
- Roles: owner, admin, analyst, viewer, ingest. API routes use explicit role allowlists.
- Bounded, strict-JSON scan ingestion with tenant-scoped idempotency.
- Identity first-seen/last-seen tracking, drift history, credential-age metadata, and risk-ranked inventory.
- Server-side risk rules for privileged identities without active owners, toxic permission combinations, unverified OAuth applications, and stale API tokens.
- OPA/Rego policy evaluation for tenant-scoped inventory reads and MCP tool invocation decisions; unknown actions and schema drift are denied by default.
- Finding status changes create finding-history and audit events.
- Audit events are hash-chained per tenant; database triggers reject UPDATE and DELETE.
- Health endpoints, security headers, request IDs, and graceful shutdown.

## Run locally

Requires Docker Compose and Go 1.26+.

```bash
cd control-plane
cp .env.example .env
# Replace both passwords with unique random values.
set -a && . ./.env && set +a
docker compose up -d postgres opa
go mod tidy
go run ./cmd/controlplane migrate
go run ./cmd/controlplane bootstrap --organization "Example Security"
# Copy the one-time owner API key into a secret manager.
export AG_OPA_URL=http://localhost:8181
go run ./cmd/controlplane serve
```

The bootstrap command creates a tenant and initial owner key. Duplicate organization slugs are rejected. Never commit .env.

## API

Except GET /healthz and GET /readyz, routes require Authorization: Bearer ag_live_<key-id>.<secret>.

| Method | Route | Roles | Purpose |
|---|---|---|---|
| POST | /v1/ingest/scans | owner, admin, ingest | Ingest a scan snapshot |
| POST | /v1/policies/evaluate | owner, admin, analyst | Evaluate a policy through OPA; unavailable policy service fails closed |
| GET | /v1/identities/{id}/events | owner, admin, analyst, viewer | Identity drift timeline |
| GET | /v1/audit-events/verify | owner, admin | Verify tenant audit hash chain |
| GET | /v1/dashboard/summary | owner, admin, analyst, viewer | Tenant KPI summary |
| GET | /v1/identities | owner, admin, analyst, viewer | Risk-ranked identity inventory |
| GET | /v1/findings | owner, admin, analyst, viewer | Findings with optional status filter |
| PATCH | /v1/findings/{id}/status | owner, admin, analyst | Update finding workflow status |
| GET | /v1/audit-events | owner, admin, analyst | Tenant audit history |
| GET | /v1/api-keys | owner, admin | List key metadata; never secrets |
| POST | /v1/api-keys | owner, admin | Create a scoped key; secret shown once |
| DELETE | /v1/api-keys/{id} | owner, admin | Revoke an API key |

### Example scan payload

```json
{
  "scan_id": "ci-run-2026-11-19-001",
  "source": "agentguard-cli",
  "scanner_version": "0.1.0",
  "collected_at": "2026-11-19T12:00:00Z",
  "assets": [{
    "external_id": "mcp:internal-docs",
    "source": "mcp",
    "kind": "mcp_server",
    "name": "internal-docs",
    "owner_status": "UNKNOWN",
    "environment": "development",
    "scopes": [],
    "risk_score": 45
  }],
  "findings": [{
    "fingerprint": "stable-rule-and-resource-fingerprint",
    "rule_id": "mcp.shell-launch",
    "severity": "medium",
    "confidence": "high",
    "category": "execution-risk",
    "title": "Shell-based MCP launch",
    "description": "Review shell command construction.",
    "resource": "internal-docs",
    "location": "command",
    "evidence": "shell executable: bash",
    "remediation": "Prefer fixed executables and explicit arguments."
  }]
}
```

A repeated scan ID with identical payload returns an idempotent duplicate result. Reusing the same scan ID with different content returns HTTP 409.

## Security boundaries and limitations

- Deploy behind HTTPS; do not expose plaintext HTTP publicly.
- Use a unique random API-key pepper and database password per deployment. Losing the pepper invalidates all API keys.
- Restrict PostgreSQL network access and use TLS for external database connections.
- API keys are an initial service/bootstrap mechanism, not a substitute for OIDC SSO, user sessions, MFA, or SCIM.
- Audit hash chaining is tamper-evident, not cryptographic non-repudiation. A database superuser can alter data and recompute hashes; external immutable checkpoint anchoring is required for stronger assurance.
- Provider connectors, OPA policy enforcement, user federation, approval workflows, revocation, and a browser dashboard are not implemented in this slice.
- Do not ingest raw credentials, access tokens, environment values, or customer secrets. Submit redacted evidence only.

This is a development foundation for design-partner validation, not a general-availability security certification.
