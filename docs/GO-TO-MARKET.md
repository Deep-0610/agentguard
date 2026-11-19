# AgentGuard — commercial positioning and design-partner plan

## Positioning

**AgentGuard helps security teams discover, assess, and govern AI agents and non-human identities—starting with MCP servers, tool permissions, credential exposure, and schema drift.**

The initial product wedge is not a generic AI security dashboard. It is a practical inventory and governance workflow for identities and tool connections that are otherwise scattered across developer machines, agent runtimes, OAuth applications, and cloud providers.

## Initial ideal customer profile

Prioritize organizations that:
- Have developers or platform teams actively deploying MCP servers and internal AI agents.
- Already have a security engineering, AppSec, IAM, or AI platform owner.
- Need to answer "which agents and tools exist, who owns them, what can they access, and what changed?"
- Can run a self-hosted CLI and provide a technical design partner for feedback.

Initial buyer/champion roles:
- Security Engineering / Product Security lead
- IAM / Identity Security lead
- AI Platform Engineering lead
- DevSecOps / Cloud Security lead

Avoid selling broad enterprise NHI lifecycle automation until provider connectors, SSO, gateway enforcement, and revocation workflows are implemented and validated.

## Differentiation to validate with customers

- Local-first scanner that can inventory MCP configuration without starting discovered processes or sending configuration to a cloud service.
- Explicit scanner-to-control-plane sync, sending normalized inventory and redacted findings rather than raw config files.
- Identity-centric inventory and relationship graph, not just a list of vulnerable prompts or model outputs.
- Tool-schema fingerprints to help detect unexpected MCP tool definition changes.
- Risk workflows that combine ownership state, permissions, credential age, and tool context.
- Policy decision history designed for future runtime enforcement.

These are product capabilities and hypotheses to validate; they are not proof of market demand or a competitive moat.

## Recommended packaging

### Community
- Apache-2.0 local scanner.
- Offline discovery and analysis.
- JSON, HTML, and SARIF reports.
- CLI sync client compatible with a customer-operated control plane.

### Team / Design Partner
- Self-hosted control plane.
- Tenant inventory, findings workflow, identity graph, and audit history.
- Scoped API keys and OPA policy evaluation.
- Assisted onboarding and weekly product feedback.
- Clearly labelled early-access limitations and support boundaries.

### Enterprise — future, not currently sellable as GA
Only introduce after delivery and verification of:
- OIDC SSO, MFA/step-up, SCIM, user-level RBAC, and tenant administration.
- Production provider connectors with least-privilege OAuth scopes, incremental sync, webhooks, and tested token rotation.
- Runtime MCP gateway with enforceable per-tool policy decisions and approvals.
- Revocation workflows with explicit authorization and rollback safeguards.
- Shared rate limiting, KMS-backed encryption, backups/restore drills, audit checkpoint anchoring, signed releases, SBOM/provenance, incident response, and independent penetration testing.

## Design-partner offer

Offer a scoped 2–4 week technical evaluation, not an enterprise security guarantee:
1. Inventory a small set of developer MCP configurations.
2. Review discovered servers, owners, permissions, credential exposure indicators, and schema fingerprints.
3. Ingest results into a self-hosted control-plane instance.
4. Validate tenant isolation, risk workflow, audit verification, and policy decisions.
5. Collect false positives, missing identity sources, integration requirements, and operational constraints.

Pilot success criteria should be agreed with each customer. Suggested measures:
- Percentage of in-scope MCP servers discovered.
- Percentage of discovered identities with an accountable owner.
- Time to identify a high-risk or unowned privileged identity.
- Time to triage a finding and produce an audit record.
- False-positive rate by rule category.
- Customer willingness to run the scanner continuously and pay for centralized governance.

## Sales claims and boundaries

Safe claims today:
- The scanner is local-first and read-only with respect to discovered MCP configuration.
- The control-plane foundation supports tenant-scoped inventory ingestion and API-key roles.
- Common risk heuristics and OPA policy evaluation are implemented in the current development branch.
- Audit events are hash-chained and the service can verify the chain.

Do not claim:
- Complete discovery of all NHI types or all enterprise SaaS/cloud providers.
- Automatic identity attribution or comprehensive least-privilege analysis.
- Runtime tool-call blocking or human approvals in a live MCP gateway.
- Automated revocation or full credential lifecycle management.
- OIDC SSO, MFA, SCIM, or production-ready enterprise user administration.
- Independent security certification, penetration-test completion, or compliance attestation.
- General availability or production readiness.

## Pricing research before launch

Do not publish a fixed price until design partners confirm the value metric. Test pricing models around:
- Governed identities / active agents
- Connected provider integrations
- Number of environments or business units
- Self-hosted versus managed control plane
- Audit retention and advanced policy features

Use paid design-partner contracts to validate willingness to pay before committing to annual enterprise pricing.
