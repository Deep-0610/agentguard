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
