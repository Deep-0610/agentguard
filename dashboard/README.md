# AgentGuard Dashboard

Next.js early-access UI for the AgentGuard commercial control-plane API.

## Local development

Requires Node.js 22+ and a running control-plane API.

```bash
cp .env.example .env.local
```

Set:
- `AG_CONTROL_PLANE_URL`: base URL of the control-plane API.
- `AG_DASHBOARD_SESSION_KEY`: base64 encoding of exactly 32 cryptographically random bytes.

Generate a session key:

```bash
openssl rand -base64 32
```

Then run:

```bash
npm install
npm run dev
```

Open http://localhost:3000 and enter an AgentGuard tenant API key.

## Session security

- The API key is submitted once and stored in an AES-256-GCM encrypted, HttpOnly, SameSite=Strict cookie.
- The browser never receives the decrypted key after sign-in and no long-lived key is stored in localStorage or sessionStorage.
- The session cookie expires after eight hours.
- API calls are proxied server-side through a strict read-only route allowlist.
- Production requires HTTPS for the control-plane upstream and uses Secure cookies.
- Session-changing requests enforce same-origin checks.
- Do not reuse the dashboard session key across environments. Rotate it to invalidate all active dashboard sessions.

## Current limitations

This is an early-access, API-key-backed dashboard. It does not implement OIDC/SSO, individual user identities, user-level RBAC, SCIM, organization invitations, billing, or administrator workflows. Access is determined by the permissions of the API key used to sign in. The UI currently exposes read-only summary, identity, finding, and audit views; it is not a runtime MCP gateway and cannot execute or revoke provider credentials.

Do not expose the dashboard publicly until OIDC, per-user authorization, deployment hardening, and independent security review are complete.
