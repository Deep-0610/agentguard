# AgentGuard Product Requirements

**Document status:** Product direction, not a statement of shipped functionality.  
**Product:** AgentGuard  
**Category:** AI agent security, MCP governance, and non-human identity (NHI) security.

## 1. Product thesis

Organizations are deploying AI agents and MCP servers faster than they can inventory their tools, credentials, owners, permissions, and runtime behavior. AgentGuard should provide a trustworthy control plane for discovering this attack surface, understanding ownership and exposure, detecting drift, and governing high-risk actions.

The initial wedge is **read-only visibility into MCP and agent infrastructure**. The expansion is enterprise NHI governance and runtime enforcement.

## 2. Ideal customer profiles

### Primary beachhead
- B2B SaaS companies with active AI-agent or MCP adoption.
- Platform engineering, product security, cloud security, and security engineering teams.
- Approximately 100–2,000 engineers or a meaningful fleet of internal agents and service identities.
- Buyers who need visibility before they are ready to deploy a broad identity-governance program.

### Secondary segments
- Financial services and fintech.
- Healthcare and other regulated technology providers.
- Large enterprises with internal AI platform teams.
- Managed security service providers, subject to a future multi-customer operating model.

### Buyer and champion
- Economic buyer: CISO, VP Security, Head of Platform Security.
- Technical champion: Product Security Lead, Cloud Security Architect, AI Platform Lead.
- Daily users: Security engineers, platform engineers, identity administrators, incident responders.

## 3. Product principles

1. **Read-only first:** discovery and inventory must not mutate customer systems.
2. **Evidence before score:** every risk must include source, timestamp, rationale, confidence, and remediation guidance.
3. **Least privilege:** connectors request the narrowest scopes required and explain why each permission is needed.
4. **Human approval for impact:** revoke, disable, quarantine, rotate, or block actions require explicit authorization and a durable audit event.
5. **Tenant isolation by design:** every customer-owned record is tenant-scoped and authorization is enforced server-side.
6. **Secure by default:** secrets are not stored in plaintext, displayed in full, or emitted into logs.
7. **Portable deployment:** provide a hosted service and an enterprise deployment path only when support and operations are ready.
8. **No compliance theater:** product capabilities must not be marketed as SOC 2, ISO 27001, or regulatory certification.

## 4. Product surfaces

### A. AgentGuard Scanner — open-source
**Current status:** Early MVP.

Required capabilities:
- Discover supported MCP configuration sources.
- Parse safely with size and resource limits.
- Detect credential patterns and risky configuration signals.
- Redact sensitive evidence.
- Generate JSON, SARIF, and human-readable reports.
- Compare a scan to a trusted baseline.
- Run in local development and CI without transmitting customer configuration.

Future hardening:
- Versioned rule catalog and rule metadata.
- Configurable allowlists with expiry and owner.
- Stable finding identifiers.
- Signed release artifacts, checksums, provenance, and SBOM.
- Platform-specific installers and reproducible release process.

### B. AgentGuard Control Plane — commercial
**Status:** Planned; not implemented.

Core modules:
- Organization, workspace, project, environment, and team management.
- Central asset inventory for agents, MCP servers, service accounts, API keys, OAuth apps, and workload identities.
- Identity graph linking identities to owners, applications, environments, resources, and permissions.
- Connectors with least-privilege scopes, credential rotation guidance, sync health, and revocation.
- Risk and policy engine with explainable decisions.
- Drift and lifecycle monitoring.
- Search, filtering, exports, evidence, and audit history.
- Role-based access control and enterprise identity federation.

### C. AgentGuard Gateway — commercial
**Status:** Planned; not implemented.

Core modules:
- MCP-aware reverse proxy / gateway.
- Authentication and authorization at the protocol boundary.
- Strict token audience and issuer validation.
- Tool-level allow/deny policies.
- Request and response metadata logging with sensitive-data minimization.
- Rate limits, quotas, and abuse controls.
- Approval workflows for high-risk operations.
- Fail-closed behavior for security-critical policy decisions, with documented availability trade-offs.

## 5. Functional requirements

### Inventory and identity
- Each asset has a stable internal ID and source-specific external ID.
- Record source system, connector, collection timestamp, last-seen timestamp, owner, environment, permissions, credential references, and evidence provenance.
- Ownership must support verified, inferred, and unknown states.
- Preserve history; do not silently overwrite material changes.
- Deduplicate only when strong identifiers support the match. Record merge provenance.

### Risk engine
- Use versioned rules with severity, confidence, evidence, rationale, and remediation.
- Separate severity from confidence.
- Support suppressions with reason, approver, creation time, and expiry.
- Track finding state: open, acknowledged, accepted-risk, remediated, false-positive.
- Keep a full history of state changes.

### Workflow and remediation
- Discovery is read-only.
- Remediation is a distinct privileged capability.
- Require step-up authentication for high-impact actions.
- Use a two-person approval option for enterprise customers.
- Support dry-run and preview.
- Make actions idempotent where possible.
- Capture actor, approver, target, request, result, timestamps, and correlation ID.
- Provide rollback guidance; do not promise rollback where the upstream provider cannot guarantee it.

### Enterprise controls
- OIDC SSO first; SAML support may follow.
- SCIM provisioning for eligible plans.
- RBAC with explicit tenant and resource scopes.
- MFA/step-up authentication for sensitive operations.
- Session management and administrative access review.
- Audit export and retention controls.
- Configurable data retention and deletion workflows.
- Regional data residency only when the infrastructure supports it.

## 6. Non-functional requirements and launch gates

| Area | Required gate before general availability |
|---|---|
| Tenant isolation | Automated cross-tenant authorization tests for every tenant-owned resource |
| Authentication | OIDC security review, secure sessions, MFA/step-up for privileged actions |
| Authorization | Deny-by-default policy tests and authorization checks at service boundaries |
| Secrets | Managed secret storage, encryption, redaction, rotation and access audit |
| Data | Encryption in transit and at rest; backup and tested restore |
| Availability | Defined SLOs, alerting, incident response and status communications |
| Performance | Published limits and load tests for agreed customer workloads |
| Supply chain | SBOM, dependency scanning, signed releases and provenance |
| Security | Threat model, independent penetration test, vulnerability disclosure process |
| Privacy | Data inventory, retention schedule, deletion process, DPA and subprocessors list |
| Support | Support process, escalation, onboarding and customer-facing documentation |

## 7. Success metrics

### Product
- Time to first useful inventory.
- Percentage of discovered assets with verified owners.
- Mean time from risky change to detection.
- Finding precision and customer-confirmed false-positive rate.
- Connector sync success and freshness.
- Percentage of high-risk actions with complete approval and audit evidence.

### Commercial
- Qualified design partners.
- Pilot-to-paid conversion.
- Time to deploy and time to first value.
- Monthly active security teams.
- Gross retention and expansion.
- Support cost per customer.

Do not optimize for the raw number of findings. Optimize for useful, trusted, actionable coverage.

## 8. Explicit non-goals for initial launch

- Automatically revoking credentials without approval.
- Claiming to discover every NHI in every cloud or SaaS platform.
- Replacing a full PAM, CIEM, CSPM, secrets manager, or SIEM.
- Claiming compliance certification.
- Executing arbitrary customer-provided MCP tools during discovery.
- Storing raw customer secrets to make correlation easier.

## 9. Delivery sequence

1. Harden scanner correctness, privacy, rules, tests, releases, and documentation.
2. Run design-partner pilots using local scanner and manual review workflows.
3. Build control-plane foundations: auth, tenancy, inventory, audit, and connector framework.
4. Add one provider integration at a time with least-privilege scopes and contract tests.
5. Add policy evaluation and drift workflows.
6. Build gateway only after the MCP protocol and threat model are reviewed.
7. Complete independent security testing and operational readiness before general availability.
