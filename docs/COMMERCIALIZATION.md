# Commercialization Plan

**Purpose:** Turn AgentGuard into a credible, sellable B2B security product without promising capabilities that do not exist yet.

## 1. Positioning

### Category
AI agent security and non-human identity governance.

### One-line positioning
**AgentGuard helps security teams discover AI agents, MCP servers, and non-human identities, understand their access risk, and govern high-impact actions with evidence and human approval.**

### Short pitch
AI agents and MCP integrations create new identities, credentials, tools, and trust relationships across engineering environments. AgentGuard is being built to give security and platform teams a single place to inventory that attack surface, detect risky configuration and identity drift, attribute ownership, and enforce policy safely.

### Message hierarchy
1. Discover what exists.
2. Understand who owns it and what it can access.
3. Detect exposed credentials, risky permissions, stale identities, and unexpected changes.
4. Govern sensitive actions with approvals and audit evidence.

Do not lead with "complete AI security platform" until the control plane and gateway are shipped and independently validated.

## 2. Beachhead market

Start with one focused customer profile:
- B2B SaaS or fintech with internal AI/agent adoption.
- 100–2,000 engineers, or a concentrated AI platform/security team.
- Uses MCP servers, coding assistants, internal agents, GitHub Actions, cloud service identities, and SaaS integrations.
- Has a security owner but lacks a consolidated inventory of agent and NHI access.

Avoid selling to every enterprise segment at once. A narrow ICP makes discovery, onboarding, integrations, and proof of value much easier.

## 3. Packaging

The following is a **pricing hypothesis for customer interviews**, not a validated market price or a currently purchasable offer.

| Package | Proposed buyer | Indicative price hypothesis | Intended scope |
|---|---|---:|---|
| Community | Individual developers | Free | Local scanner, reports, public rules |
| Team Pilot | Small security/platform team | USD $3,000–$8,000 per 6–8 week pilot | Assisted onboarding, agreed discovery scope, findings review, pilot report |
| Business | Growing SaaS security team | USD $500–$1,500/month | Hosted inventory, core connectors, team workflows, standard support — only after these features ship |
| Enterprise | Regulated or larger organization | Custom annual contract | SSO, advanced RBAC, private deployment options, audit exports, support commitments — only after validated delivery |

Pricing should eventually be tied to monitored identities/assets, connector coverage, deployment model, retention, and support tier. Avoid unlimited usage until infrastructure cost and abuse controls are understood.

## 4. Paid pilot offer

Sell a time-boxed assessment before attempting a large annual contract.

### Pilot outcome
At the end of 6–8 weeks, the customer receives:
- A documented inventory of agreed MCP/agent configuration sources.
- A prioritized list of observed security findings with evidence and confidence.
- Ownership gaps and recommended next actions.
- A baseline and a repeat-scan comparison where supported.
- A gap analysis against the agreed OWASP NHI risk areas.
- A final readout with recommendations and a proposed rollout plan.

### Pilot boundaries
- Customer approves the scope and scan locations.
- Scanner is read-only; no server execution or credential validation.
- No secrets are transmitted to AgentGuard as part of a local-only pilot.
- No automated revocation or remediation.
- Findings are not represented as a penetration test, compliance audit, or certification.
- Agree on data handling, retention, deletion, and support before receiving customer data.

### Pilot success criteria
- Time to first inventory.
- Percentage of assets with known owners.
- Number of findings validated by the customer.
- False-positive rate and time spent triaging.
- Repeat-scan drift value.
- Customer's willingness to deploy more broadly and pay for continued use.

## 5. Sales process

1. **Discovery call:** ask how the customer inventories MCP servers, agents, service accounts, secrets, owners, and permissions today.
2. **Qualification:** confirm a real AI/NHI problem, executive sponsor, technical champion, environment, and budget path.
3. **Scope:** agree on locations, source types, data boundaries, success criteria, and pilot owner.
4. **Technical validation:** run the local scanner with the customer; review output together.
5. **Value readout:** connect evidence to operational risk and ownership gaps; do not inflate severity.
6. **Commercial proposal:** offer a paid pilot with explicit deliverables and exclusions.
7. **Expansion:** convert validated needs into product requirements; sell the next capability only after it exists.

## 6. Website and sales assets required

Before public commercial launch, prepare:
- Product landing page with a truthful maturity statement.
- Architecture and data-flow diagram.
- Security and privacy overview.
- Supported-source and supported-platform matrix.
- Demo environment with synthetic data only.
- Technical evaluation guide and deployment guide.
- Pilot statement of work and pricing sheet.
- DPA, terms, privacy policy, subprocessors list, and support policy reviewed by counsel.
- Vulnerability disclosure policy and security contact.
- Release notes and product status page.

## 7. Competitive strategy

Do not compete on an unprovable claim that AgentGuard replaces every CNAPP, CIEM, PAM, secrets manager, or SIEM.

Differentiate through:
- MCP and AI-agent discovery as the initial entry point.
- Vendor-neutral inventory and evidence provenance.
- Local-first scanning and privacy-aware workflows.
- A unified graph connecting agents, tools, owners, identities, credentials, and permissions.
- Human-approved governance actions with audit trails.

Validate these differentiators in customer interviews and competitive evaluations. Do not publish competitor feature comparisons without current evidence.

## 8. Founder-led customer discovery

Target 15–20 interviews before committing to a broad SaaS build:
- 5 product security leaders.
- 5 platform/cloud security leads.
- 5 AI platform or developer infrastructure leads.
- 2–5 MSSP or regulated-enterprise stakeholders.

Ask:
- How do you discover MCP servers and AI agents today?
- Which identities and credentials do they use?
- How do you attribute ownership?
- What is the cost of a stale or overprivileged identity?
- Which systems must integrate first?
- What evidence is required for security approval?
- Would you pay for a local scanner, hosted inventory, or both?
- What would make a 6–8 week pilot successful?

Record actual buyer language. Do not treat positive feedback as purchase intent unless the buyer agrees to a paid pilot or a concrete procurement step.

## 9. Claims policy

Allowed today:
- "Early-stage local-first MCP configuration scanner."
- "Detects selected credential patterns and risky configuration signals."
- "Exports JSON, HTML, and SARIF."
- "Designed to evolve into AI agent and NHI governance."

Not allowed until evidenced:
- "Complete enterprise NHI platform."
- "Finds all secrets or all non-human identities."
- "Prevents prompt injection."
- "Zero-trust certified."
- "SOC 2 compliant" or "ISO 27001 certified."
- "Guaranteed breach prevention."
- "Production-ready runtime enforcement."

## 10. Commercial launch gates

Do not move from paid pilots to general availability until the hosted product has:
- Tenant isolation tests and independent review.
- Enterprise authentication and authorization.
- Managed secret storage and audited connector permissions.
- Audit events and retention controls.
- Security testing and a vulnerability response process.
- Backup/restore, monitoring, incident response, and support coverage.
- Legal review of customer contracts and privacy obligations.
- Customer-validated reliability and performance.
