CREATE TABLE IF NOT EXISTS tool_baselines (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 tool_name TEXT NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 256),
 approved_schema_hash TEXT NOT NULL CHECK (approved_schema_hash ~ '^[a-f0-9]{64}$'),
 risk TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
 approved_by TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, tool_name)
);
CREATE INDEX IF NOT EXISTS tool_baselines_tenant_idx ON tool_baselines(tenant_id, tool_name);
