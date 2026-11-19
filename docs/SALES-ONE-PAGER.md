# AgentGuard — Sales One-Pager

## Discover the AI agent and MCP attack surface you cannot see

AI agents, MCP servers, and automation identities are entering engineering environments quickly. Security teams need to know what is deployed, what credentials are configured, who owns it, and what has changed.

**AgentGuard is being built to help security teams discover and govern AI agents, MCP servers, and non-human identities — with evidence, least-privilege principles, and human approval for high-impact actions.**

## The problem

- MCP servers and agent integrations are configured across developer machines and repositories.
- Credentials can be embedded in environment variables, command arguments, and remote endpoint configuration.
- Ownership and permission context is often scattered across tools.
- A changed tool schema or stale identity can go unnoticed.
- Security teams need evidence and accountability, not another opaque risk score.

## What the current product does

The current early-stage deliverable is a local-first Go scanner that:
- Reads supported MCP JSON configuration files without executing configured servers.
- Detects selected credential patterns and risky configuration signals.
- Redacts detected values in finding evidence.
- Flags HTTP endpoints and shell-based launch configurations for review.
- Fingerprints declared tool schemas.
- Exports table, JSON, HTML, and SARIF reports.

**Current maturity:** Scanner MVP. The hosted governance platform, provider integrations, identity graph, and runtime gateway are roadmap items and are not available today.

## Designed product direction

The commercial roadmap is intended to add:
1. Central inventory and ownership mapping.
2. Identity and permission graph.
3. Connector-based discovery with least-privilege access.
4. Risk, drift, and lifecycle monitoring.
5. Policy enforcement and approval-based remediation.
6. MCP runtime gateway and auditable tool-call controls.

## Best-fit early design partners

- B2B SaaS companies adopting AI agents or MCP.
- Product security and platform security teams.
- Fintech and regulated technology teams exploring AI governance.
- Organizations that need a local scanner and are willing to co-design the next layer.

## Suggested first engagement

A scoped 6–8 week design-partner pilot can evaluate the current scanner against customer-approved configuration sources. Deliverables should include an inventory of supported sources, reviewed findings, ownership gaps, repeat-scan observations where supported, and a prioritized roadmap.

No automatic remediation, credential validation, penetration test, compliance audit, or certification is included.

## Why engage early

Design partners can shape supported configuration formats, evidence quality, connector priorities, and enterprise requirements before the hosted product is built.

**Next step:** Schedule a technical discovery session to agree on the scan scope, data boundaries, success criteria, and whether the current scanner is useful for your environment.

Contact: [Add a verified business email and website before publishing.]
