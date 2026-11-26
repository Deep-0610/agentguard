# Security Policy

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in public issues, pull requests, discussions, or social media.

Use GitHub's **Report a vulnerability** flow for this repository (Security → Advisories → Report a vulnerability) to send a private report to maintainers. If private vulnerability reporting is unavailable, contact the repository owner through their GitHub profile and request a private reporting channel. Do not include live credentials, customer data, or third-party exploit payloads in an initial report.

Include:
- The affected component, version, and commit where possible.
- Impact, attack prerequisites, and realistic threat scenario.
- Reproduction steps or a minimal proof of concept.
- Suggested mitigation and whether exploitation is known.

Maintainers will acknowledge and assess reports, coordinate remediation, and agree on disclosure timing where possible. A fixed response SLA is not currently offered because a staffed security-response function has not yet been established.

## Scope and safe harbor

In scope: the AgentGuard CLI, control-plane API, policy evaluation, ingestion pipeline, build/release workflows, and published container images.

Do not access, modify, or exfiltrate data belonging to other users or organizations; disrupt services; or perform social engineering, physical attacks, or denial-of-service testing against infrastructure without explicit authorization. Test against local instances or environments for which you have permission.

Good-faith research that follows this policy and applicable law is welcome. This statement does not authorize activity that violates law or impacts third-party systems.

## Current security posture

AgentGuard is an early-stage project. The scanner and control-plane foundation are under active development. A successful CI run is not a penetration test, security certification, or guarantee that the software is free of vulnerabilities. Do not use AgentGuard as the sole security control for production systems.
