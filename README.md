# AgentGuard

**Discover, assess, and govern AI agents, MCP servers, and non-human identities.**

AgentGuard is an early-stage security product focused on the growing attack surface created by AI agents, Model Context Protocol (MCP) servers, and non-human identities (NHIs). The current deliverable is a local-first, read-only Go scanner. The commercial roadmap adds centralized inventory, identity governance, policy enforcement, and runtime controls.

> **Product status:** Early development / scanner MVP. The governance control plane, provider integrations, and runtime gateway are not yet implemented. Do not represent this repository as a production-ready enterprise platform or as a compliance certification.

## What works today

- Reads supported MCP JSON configuration files without launching servers or calling tools.
- Detects selected credential patterns and suspicious sensitive-field values in environment variables, command strings, arguments, and URL query parameters.
- Redacts detected credential values in finding evidence.
- Flags HTTP remote endpoints and shell-based launch commands for review.
- Produces deterministic SHA-256 fingerprints for declared tool schemas.
- Exports table, JSON, HTML, and SARIF reports.

Detection is heuristic. A clean scan does not prove that an environment is secure, and a finding does not prove that a credential is valid or exploitable.

## Quick start

Requires Go 1.22 or newer.

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
- Provider inventory integrations are intended to use least-privilege, read-only scopes.
- Revocation, quarantine, and credential rotation must remain separate privileged workflows with explicit human approval.
- Treat findings as review evidence, not as a definitive security verdict.

## Repository layout

- `cmd/agentguard`: CLI entry point.
- `internal/discovery`: MCP configuration discovery and parsing.
- `internal/scanner`: heuristic checks, schema fingerprints, and risk scoring.
- `internal/report`: table, JSON, HTML, and SARIF output.
- `docs`: architecture, threat model, security roadmap, product requirements, and commercial packaging.
- `control-plane/` and `gateway/`: planned components; not implemented yet.

## Development

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build ./...
```

CI formats Go sources before vetting, race-enabled tests, and compilation. Passing CI is not a security certification.

## Product direction

AgentGuard is being developed around the OWASP Non-Human Identities Top 10 and the MCP authorization model. See:

- [Product requirements](docs/PRODUCT-REQUIREMENTS.md)
- [Security roadmap](docs/SECURITY-ROADMAP.md)
- [Commercial packaging](docs/COMMERCIALIZATION.md)
- [Security review checklist](docs/SECURITY-REVIEW.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
