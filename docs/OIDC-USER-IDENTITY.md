# OIDC and user identity rollout

## Status

The database primitives in migration `007_user_identity_primitives.sql` are groundwork only. They do **not** provide a working OIDC login, browser session, invitation endpoint, SCIM API, or user-level authorization yet. The current control-plane API still authenticates API keys. Do not enable customer login or claim SSO support based on this migration.

## Identity rules

- The durable external identity key is the validated pair `(issuer, subject)`; email is an attribute and must never be used as the account-linking key.
- Validate issuer, signature, audience, authorized party where applicable, expiry, not-before, nonce, and the exact redirect URI. Use provider discovery only after validating the configured issuer and require HTTPS outside local development.
- Never accept an issuer, JWKS URL, callback URL, or tenant ID supplied by an unauthenticated browser as trusted configuration.
- Resolve a tenant only through an active `tenant_memberships` row. Never infer tenant membership from an email domain or an OIDC group claim without an explicit, audited mapping.
- Enforce authorization server-side for every request and every resource query. The dashboard must not be the authorization boundary.
- User sessions are opaque random tokens. Persist only a cryptographic digest; set Secure, HttpOnly, SameSite cookies; rotate on authentication and privilege changes; revoke on logout, user disablement, membership suspension, and expiry.
- Invitation tokens are high-entropy, single-use, short-lived, stored only as digests, and accepted only by a verified identity matching the invited address. Email verification does not automatically link an existing identity.
- OIDC client secrets are referenced by `secret_ref` and must be retrieved from a KMS/secret manager. Never store client secrets in this database or environment-backed tenant configuration.
- SCIM provisioning must be separately authenticated, tenant-scoped, idempotent, audited, and support deactivation without deleting audit history.

## Required implementation sequence

1. Add a vetted OIDC relying-party implementation and issuer/JWKS cache with bounded refresh and fail-closed validation.
2. Add server-side login state, nonce, PKCE verifier, and callback handling. Bind state to a short-lived browser transaction cookie.
3. Implement user upsert by issuer + subject, membership lookup, and explicit tenant selection for users with multiple memberships.
4. Replace dashboard API-key login with server-side user sessions. Preserve API keys for machine-to-machine ingestion and automation.
5. Add audited membership management, owner transfer, invitations, suspension, and last-owner protection in database transactions.
6. Add user-level authorization middleware and cross-tenant negative tests for every endpoint.
7. Add SCIM only after the membership lifecycle and deprovisioning semantics are stable.
8. Add provider-specific integration tests against real test tenants before enabling production issuer configurations.

## Acceptance tests before enabling OIDC

- Reject wrong issuer, audience, authorized party, nonce, state, PKCE verifier, signature, algorithm, expired/not-yet-valid token, and untrusted redirect.
- Reject email-only account linking and domain-based tenant discovery.
- Reject suspended users, suspended memberships, revoked sessions, and sessions for another tenant.
- Verify that membership changes and owner transfer are transactional and audited.
- Verify CSRF protection on login/logout and all state-changing browser endpoints.
- Verify secrets, authorization codes, ID tokens, access tokens, refresh tokens, and session cookies never appear in logs, traces, errors, or audit payloads.
- Run race, fuzz, dependency vulnerability, and cross-tenant authorization tests.

## External setup still required

A real OIDC connection requires a customer-controlled IdP application, issuer URL, client ID, secret-manager reference, and exact callback URI. These cannot be fabricated or validated without an IdP tenant and credentials. A security reviewer must inspect the complete authentication and session implementation before production use.
