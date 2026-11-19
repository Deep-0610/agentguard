# Security Policy

## Reporting a vulnerability

Please do not open public issues for suspected vulnerabilities. Use GitHub's private vulnerability reporting for this repository where available, or contact the maintainers through a private channel.

Include the affected version, impact, reproduction steps, and any relevant logs. Do not include live credentials or personal data.

## Security boundaries

AgentGuard's initial scanner is read-only and local-first. It does not execute discovered commands, connect to discovered endpoints, validate credentials, or change provider state. Findings can be false positives and require human review.

Never commit credentials, tokens, private keys, customer data, or production configuration. Rotate any credential that may have been exposed.
