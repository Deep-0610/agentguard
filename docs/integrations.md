# Provider integrations (planned)

The first release does not authenticate to SaaS providers. Future connectors should follow these requirements:

- GitHub: read-only organization and repository inventory scopes.
- Okta: read-only users, groups, applications, and system-log scopes where possible.
- Microsoft Entra ID: least-privilege Microsoft Graph application permissions, with admin consent reviewed by the tenant owner.
- Google Workspace: read-only directory and OAuth application inventory scopes.

Store credentials in a secret manager. Never commit access tokens or ask users to paste them into issues. Separate discovery credentials from remediation credentials. Any disable, revoke, rotate, or quarantine operation must require a separate approval workflow and auditable actor identity.
