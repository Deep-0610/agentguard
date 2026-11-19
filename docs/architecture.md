# Architecture

## Design principles

1. **Read-only discovery:** the scanner reads local configuration and never starts discovered processes or contacts discovered services.
2. **Offline by default:** scanning and report generation require no network access.
3. **Evidence over assumptions:** findings include a category, severity, score, location, and remediation guidance.
4. **Redaction by default:** environment values are omitted from server inventory output and matching secrets are redacted in findings.
5. **Privilege separation:** inventory and policy enforcement are separate systems.

## Current scanner flow

```text
CLI
  -> path discovery
  -> bounded JSON config reader
  -> MCP server inventory
  -> secret / transport / execution checks
  -> deterministic tool-schema fingerprint
  -> table | JSON | HTML | SARIF
```

## Planned platform

- Control plane: API service, PostgreSQL inventory, tenant RBAC, immutable audit events, identity relationships, and OPA/Rego policy evaluation.
- Connectors: GitHub, Okta, Microsoft Entra ID, and Google Workspace using read-only scopes for discovery.
- Gateway: MCP protocol proxy, OAuth 2.1 audience validation, policy enforcement, and explicit human approval for sensitive actions.

These components are roadmap items, not implemented or production-ready in this initial release.
