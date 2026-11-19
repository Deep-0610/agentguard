# AgentGuard Design-Partner Pilot — Statement of Work Template

> Template only. Have qualified counsel review this document and align it with the final master services agreement, data-processing terms, privacy notice, and security commitments before use.

## 1. Parties and term

- Provider: [Legal entity name]
- Customer: [Customer legal entity]
- Effective date: [Date]
- Pilot start and end: [Dates]
- Authorized customer sponsor: [Name / role]
- Technical owner: [Name / role]

## 2. Objective

Evaluate the AgentGuard local scanner against mutually agreed customer-controlled MCP configuration sources. The objective is to assess inventory usefulness, finding quality, evidence handling, and the value of a potential future governance platform.

## 3. Scope

Included:
- One kickoff and scope confirmation.
- Customer-approved configuration source list.
- Local execution of the scanner by the customer or under customer-supervised conditions.
- Review of supported scanner output.
- Findings triage session.
- Final readout and recommended next steps.

Excluded:
- Hosted SaaS control plane.
- Cloud or SaaS provider integrations unless separately agreed and already available.
- Runtime MCP proxy or gateway.
- Credential validation or authentication attempts.
- Penetration testing, vulnerability assessment, or compliance audit.
- Automated revocation, quarantine, rotation, or other changes to customer systems.
- Discovery outside the explicitly approved scope.

## 4. Customer responsibilities

- Approve all scan targets and confirm authority to scan them.
- Provide a technical contact and attend review sessions.
- Execute local scanning where required.
- Avoid sending raw secrets or unredacted configuration files unless a separate approved secure-transfer process exists.
- Review findings and confirm false positives or business context.
- Confirm any internal data-handling and retention requirements before the pilot.

## 5. Provider responsibilities

- Provide the agreed scanner version and setup instructions.
- Explain supported formats and known limitations.
- Help interpret scanner findings without representing heuristic results as verified compromise.
- Maintain a record of agreed scope and deliverables.
- Notify the customer of material issues discovered in the pilot process.

## 6. Deliverables

1. Scope and data-boundary record.
2. Supported-source inventory.
3. Findings review with severity, evidence, limitations, and customer disposition.
4. Ownership and governance gap summary where evidence supports it.
5. Final pilot readout and prioritized recommendations.

## 7. Data handling

Before the pilot begins, agree in writing:
- Whether any data leaves the customer's environment.
- Which report fields may be shared.
- Approved transfer channel, if any.
- Authorized personnel and access period.
- Retention and deletion dates.
- Whether the customer permits use of anonymized feedback for product improvement.

Do not send secrets through email, chat, or ordinary support channels. The pilot should prefer local execution and redacted outputs.

## 8. Security and operational boundaries

- The scanner is intended to be read-only.
- The scanner does not intentionally execute discovered MCP servers or invoke their tools.
- Findings are heuristic and may include false positives or false negatives.
- The pilot is not a substitute for a security assessment or professional incident response.
- No production enforcement or automated remediation is included.

## 9. Acceptance criteria

The pilot is complete when:
- The agreed scan scope has been attempted.
- The findings review has been held.
- The deliverables above have been provided.
- The customer has had an opportunity to record feedback and pilot outcomes.

## 10. Commercial terms

- Pilot fee: [Amount and currency]
- Payment schedule: [Terms]
- Expenses: [If any]
- Taxes: [Applicable terms]
- Cancellation: [Terms]

## 11. Legal terms

Insert or reference counsel-approved terms covering confidentiality, intellectual property, warranties, liability, indemnity, data protection, governing law, dispute resolution, and termination.

## 12. Signatures

Provider: ____________________  Date: __________

Customer: ____________________  Date: __________
