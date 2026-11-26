# Threat Model

## Assets

- Provider credentials and tokens referenced by agent configuration.
- MCP server command lines, arguments, endpoints, and declared tool metadata.
- Identity and ownership metadata added by future connectors.
- Policy decisions and audit records in future control-plane components.

## Trust boundaries

- Local configuration files are untrusted input.
- MCP server binaries and remote endpoints are not trusted or executed by the scanner.
- Reports may be shared with CI systems; secret values must not be emitted.
- Future provider integrations must isolate credentials and use read-only scopes for inventory.

## Initial mitigations

- File size limit for JSON inputs.
- Symlink avoidance during directory traversal.
- No process execution and no outbound network calls.
- Secret redaction and omission of environment maps in reports.
- Tests for credential redaction and core detection behavior.

## Known limitations

Pattern-based detection can miss secrets and can flag benign values. Configuration formats vary by client and version. Schema fingerprints are only available when tool declarations are present in scanned configuration; runtime MCP introspection is not performed.

## Control-plane trust boundaries

- API keys are bearer credentials. Their secret component is stored as an HMAC-SHA256 digest using a deployment pepper.
- Tenant identity is resolved from the authenticated key; request payload tenant identifiers are not accepted as authority.
- Inventory fields that imply verified ownership, provider verification, or credential activity are reserved for future trusted connectors and are not accepted from the scanner ingestion payload.
- Tool risk and approved schema hashes are stored server-side per tenant. A caller cannot nominate its own approved baseline.
- TOTP seeds are encrypted at rest with AES-GCM using a key derived from the API-key pepper. TOTP codes are replay-protected; repeated invalid attempts trigger a temporary lockout.
- Audit events are hash-chained per tenant and protected from ordinary UPDATE/DELETE/TRUNCATE operations by database triggers.

## Known control-plane limitations

- TOTP step-up is per API key, not a user-level MFA system. OIDC SSO, SCIM, and IdP-enforced MFA are not implemented.
- Audit hash chaining is tamper-evident, not immutable against a database superuser. External checkpoint anchoring is not implemented.
- Provider connectors and runtime MCP tool-call enforcement are not implemented. OPA evaluation is an API operation, not a live gateway.
- KMS-backed encryption, shared rate limiting, external penetration testing, and production operational controls remain outstanding.
