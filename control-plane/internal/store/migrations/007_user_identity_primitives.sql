-- User identity and organization membership primitives for the OIDC rollout.
-- Provider client secrets are deliberately NOT stored here; they must live in a
-- secret manager and be referenced by secret_ref.
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 issuer TEXT NOT NULL,
 subject TEXT NOT NULL,
 email TEXT,
 email_verified BOOLEAN NOT NULL DEFAULT FALSE,
 display_name TEXT NOT NULL DEFAULT '',
 disabled_at TIMESTAMPTZ,
 last_authenticated_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (issuer, subject)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_verified_email_idx
 ON users (lower(email)) WHERE email IS NOT NULL AND email_verified = TRUE AND disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS tenant_memberships (
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 role TEXT NOT NULL CHECK (role IN ('owner','admin','analyst','viewer')),
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
 invited_by UUID REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS tenant_memberships_user_idx
 ON tenant_memberships (user_id, status);

-- Hashed, single-use invitation secrets. Raw invitation tokens are only ever
-- delivered to the invitee and are not persisted.
CREATE TABLE IF NOT EXISTS tenant_invitations (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 email TEXT NOT NULL,
 role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
 token_hash BYTEA NOT NULL UNIQUE,
 invited_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 expires_at TIMESTAMPTZ NOT NULL,
 accepted_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS tenant_invitations_tenant_email_idx
 ON tenant_invitations (tenant_id, lower(email));

-- Server-side sessions store only a digest of a cryptographically random token.
CREATE TABLE IF NOT EXISTS user_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash BYTEA NOT NULL UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,
 user_agent_hash BYTEA,
 ip_prefix INET,
 CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS user_sessions_user_expiry_idx
 ON user_sessions (user_id, expires_at) WHERE revoked_at IS NULL;

-- Per-tenant OIDC issuer allowlist. Client secrets stay in a KMS/secret manager.
CREATE TABLE IF NOT EXISTS oidc_connections (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 issuer TEXT NOT NULL,
 client_id TEXT NOT NULL,
 secret_ref TEXT NOT NULL,
 redirect_uri TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 created_by UUID REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, issuer, client_id)
);
