# AgentGuard

**Discover, assess, and govern AI agents, MCP servers, and non-human identities.**

AgentGuard is an early-stage security product for the attack surface created by AI agents, Model Context Protocol (MCP) servers, and non-human identities (NHIs).

> **Product status:** Early development / design-partner foundation. The local-first scanner is an MVP. The commercial control plane provides an early tenant-scoped inventory, findings, API-key administration, policy-evaluation, and audit foundation. It is not general availability. OIDC/SSO, user-level MFA and RBAC, SCIM, production provider connectors, a customer-facing dashboard, runtime gateway enforcement, independent penetration testing, and production operations remain incomplete. Do not represent this repository as an enterprise-ready platform or compliance certification.

## What works today

- Reads supported MCP JSON configuration files without launching servers or calling tools.
- Detects selected credential patterns and suspicious sensitive-field values in environment variables, command strings, arguments, and URL query parameters.
- Redacts detected credential values in finding evidence and omits credential-bearing configuration fields from report serialization.
- Bounds file traversal, JSON nesting, per-file size, discovered config count, and aggregate input size.
- Rejects symlink config inputs, duplicate JSON keys, and malformed server entries.
- Writes report files atomically with restrictive permissions and refuses symlink destinations or overwriting scanned inputs.
- Flags HTTP remote endpoints and shell-based launch commands for review.
- Produces deterministic SHA-256 fingerprints for declared tool schemas.
- Exports table, JSON, HTML, and SARIF reports.
- The commercial control-plane branch adds tenant-scoped scan ingestion, identity inventory and relationships, finding triage/suppression, scoped API keys, API-key TOTP step-up for key revocation, OPA evaluation, and hash-chained audit history.

Detection is heuristic. A clean scan does not prove that an environment is secure, and a finding does not prove that a credential is valid or exploitable.

## Quick start

Requires Go 1.26 or newer.

```bash
git clone https://github.com/Deep-0610/agentguard.git
cd agentguard
go test ./...
go run ./cmd/agentguard version
go run ./cmd/agentguard scan --path ./fixtures --format table
```

Discover common MCP configuration locations for the current user:

```bash
go run ./cmd/agentguard scan --discover --format json --output agentguard-report.json
```

Generate SARIF for code-scanning workflows:

```bash
go run ./cmd/agentguard scan --path . --format sarif --output agentguard.sarif
```

## Safety model

- Discovery is read-only and offline by default.
- AgentGuard does not execute MCP servers, invoke tools, authenticate to providers, or modify scanned configuration files.
- Report serialization omits credential-bearing configuration fields; finding evidence is redacted.
- Findings are review evidence, not a definitive security verdict.
- Provider inventory integrations must use least-privilege scopes and undergo provider-specific validation before release.
- Revocation, quarantine, and credential rotation must remain separate privileged workflows with explicit human approval.

## Repository layout

- `cmd/agentguard`: CLI entry point.
- `internal/discovery`: MCP configuration discovery and parsing.
- `internal/scanner`: heuristic checks, schema fingerprints, and risk scoring.
- `internal/report`: table, JSON, HTML, and SARIF output.
- `control-plane/`: Go API, PostgreSQL persistence, OPA policy evaluation, and tenant-scoped governance foundation.
- `dashboard/`: Next.js early-access read-only control-plane UI; currently API-key-backed, not OIDC or GA. See [dashboard setup](dashboard/README.md).
- `docs/`: architecture, threat model, security roadmap, deployment runbook, and commercial packaging.
- Runtime gateway enforcement is planned and is not implemented.

## Development

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build ./...
```

CI normalizes Go formatting in its temporary job workspace before vet/race tests and fuzz targets, builds the Go projects, scans Go dependencies, validates the control-plane container and Compose configuration, smoke-tests migrations, and tests OPA policies. A committed repository-wide formatting cleanup and a non-mutating formatting gate remain outstanding. Passing CI is not a security certification.

## Product and security documentation

- [Control-plane production deployment runbook](docs/PRODUCTION-DEPLOYMENT.md)
- [Security review checklist](docs/SECURITY-REVIEW.md)
- [Threat model](docs/threat-model.md)
- [Security roadmap](docs/SECURITY-ROADMAP.md)
- [Commercial positioning and design-partner plan](docs/GO-TO-MARKET.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
