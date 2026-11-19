# AgentGuard

**Open-source discovery and governance for AI agents, MCP servers, and non-human identities.**

AgentGuard starts with a safe, local-first scanner that inventories MCP configuration, detects exposed credentials, fingerprints tool schemas, and produces machine-readable security findings. The project is designed to grow into an enterprise control plane and policy-enforcing gateway without compromising the safety of the discovery layer.

> Status: early development. The CLI scanner is the first deliverable; integrations and enforcement components are being built incrementally. Do not use this project as a substitute for a production security review.

## Project goals

- Discover MCP servers from common local configuration files without executing them.
- Identify likely secrets using conservative, explainable patterns; redact values in all output.
- Fingerprint declared tool schemas with deterministic SHA-256 hashes to help detect unexpected changes.
- Report ownership hints and risk factors without claiming certainty where evidence is missing.
- Export JSON, HTML, and SARIF for automation and CI workflows.
- Keep discovery read-only and offline by default.

## Repository layout

- `cmd/agentguard`: Go CLI entry point.
- `internal/discovery`: supported config discovery and parsing.
- `internal/scanner`: secret checks, schema fingerprints, and risk scoring.
- `internal/report`: JSON, HTML, and SARIF output.
- `docs`: threat model, architecture, and integration guidance.
- `control-plane/`: planned policy and identity governance service.
- `gateway/`: planned MCP runtime gateway.

## Quick start

Requires Go 1.22 or newer.

```bash
git clone https://github.com/Deep-0610/agentguard.git
cd agentguard
go test ./...
go run ./cmd/agentguard scan --path . --format table
```

Scan common MCP configuration locations for the current user:

```bash
go run ./cmd/agentguard scan --discover --format json --output agentguard-report.json
```

Scan an explicit file or directory:

```bash
go run ./cmd/agentguard scan --path ./fixtures --format sarif --output results.sarif
```

## Safety model

- The scanner reads configuration files only. It does not launch MCP servers, call tools, authenticate to providers, or modify source files.
- Secret values are never included in reports; findings contain a redacted preview and location only.
- Provider integrations must use least-privilege, read-only scopes for inventory.
- Revocation, quarantine, and policy enforcement are separate privileged workflows and require explicit human approval.
- Treat scanner output as evidence for review, not as proof that a credential is valid or exploitable.

## CLI

```text
agentguard scan [--path PATH | --discover] [--format table|json|html|sarif] [--output FILE]
agentguard version
```

## Roadmap

1. **Local scanner:** MCP config discovery, secret detection, schema hashing, risk scoring, reports, fixtures, and tests.
2. **Open-source hardening:** CI, release automation, signed artifacts, additional config formats, and connector interfaces.
3. **Governance control plane:** PostgreSQL-backed inventory, identity graph, RBAC, audit events, drift monitoring, and OPA/Rego policy evaluation.
4. **Runtime gateway:** OAuth 2.1 token validation, audience binding, tool-call policy checks, and approval workflows.

## Development

```bash
gofmt -w .
go vet ./...
go test -race ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [architecture overview](docs/architecture.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
