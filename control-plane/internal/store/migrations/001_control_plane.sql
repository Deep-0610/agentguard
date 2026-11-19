CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
 slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 key_id TEXT NOT NULL UNIQUE,
 secret_hash BYTEA NOT NULL,
 name TEXT NOT NULL,
 role TEXT NOT NULL CHECK (role IN ('owner','admin','analyst','viewer','ingest')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_used_at TIMESTAMPTZ,
 expires_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 created_by TEXT NOT NULL DEFAULT 'bootstrap'
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS scans (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 scan_key TEXT NOT NULL,
 source TEXT NOT NULL,
 scanner_version TEXT NOT NULL DEFAULT '',
 collected_at TIMESTAMPTZ NOT NULL,
 payload_sha256 TEXT NOT NULL,
 asset_count INTEGER NOT NULL DEFAULT 0,
 finding_count INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, scan_key),
 UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS scans_tenant_collected_idx ON scans(tenant_id, collected_at DESC);

CREATE TABLE IF NOT EXISTS identities (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 external_key TEXT NOT NULL,
 source TEXT NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('agent','mcp_server','oauth_app','service_principal','api_token','service_account','workload_identity','bot','unknown')),
 name TEXT NOT NULL,
 owner_email TEXT,
 owner_status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (owner_status IN ('ACTIVE','SUSPENDED','UNKNOWN')),
 environment TEXT NOT NULL DEFAULT 'unknown',
 scopes TEXT[] NOT NULL DEFAULT '{}',
 risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
 first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_scan_id UUID,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, external_key),
 FOREIGN KEY (tenant_id, last_scan_id) REFERENCES scans(tenant_id, id)
);
CREATE INDEX IF NOT EXISTS identities_tenant_kind_idx ON identities(tenant_id, kind);
CREATE INDEX IF NOT EXISTS identities_tenant_owner_idx ON identities(tenant_id, owner_status);
CREATE INDEX IF NOT EXISTS identities_tenant_seen_idx ON identities(tenant_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS findings (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 fingerprint TEXT NOT NULL,
 rule_id TEXT NOT NULL,
 severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
 confidence TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
 category TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 resource TEXT NOT NULL DEFAULT '',
 location TEXT NOT NULL DEFAULT '',
 evidence TEXT NOT NULL DEFAULT '',
 remediation TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','accepted-risk','remediated','false-positive')),
 first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 occurrences BIGINT NOT NULL DEFAULT 1,
 suppression_reason TEXT,
 suppression_expires_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS findings_tenant_status_idx ON findings(tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS findings_tenant_seen_idx ON findings(tenant_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS scan_findings (
 tenant_id UUID NOT NULL,
 scan_id UUID NOT NULL,
 finding_id UUID NOT NULL,
 PRIMARY KEY (tenant_id, scan_id, finding_id),
 FOREIGN KEY (tenant_id, scan_id) REFERENCES scans(tenant_id, id),
 FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, id)
);

CREATE TABLE IF NOT EXISTS audit_heads (
 tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
 sequence BIGINT NOT NULL DEFAULT 0,
 last_hash TEXT NOT NULL DEFAULT repeat('0',64)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 sequence BIGINT NOT NULL,
 actor TEXT NOT NULL,
 actor_role TEXT NOT NULL,
 event_type TEXT NOT NULL,
 resource_type TEXT NOT NULL DEFAULT '',
 resource_id TEXT NOT NULL DEFAULT '',
 request_id TEXT NOT NULL DEFAULT '',
 payload JSONB NOT NULL DEFAULT '{}'::jsonb,
 previous_hash TEXT NOT NULL,
 event_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, sequence)
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_created_idx ON audit_events(tenant_id, created_at DESC);

CREATE OR REPLACE FUNCTION agentguard_reject_audit_mutation() RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION agentguard_reject_audit_mutation();

CREATE TABLE IF NOT EXISTS finding_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 finding_id UUID NOT NULL,
 actor TEXT NOT NULL,
 previous_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, id)
);
CREATE INDEX IF NOT EXISTS finding_events_tenant_finding_idx ON finding_events(tenant_id, finding_id, created_at DESC);
