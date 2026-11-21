CREATE TABLE IF NOT EXISTS identity_relationships (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 from_identity_id UUID NOT NULL,
 to_identity_id UUID NOT NULL,
 relationship_type TEXT NOT NULL CHECK (relationship_type IN ('uses','accesses','delegates_to','created_by','connected_to','owns')),
 evidence TEXT NOT NULL DEFAULT '',
 first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK (from_identity_id <> to_identity_id),
 UNIQUE (tenant_id,from_identity_id,to_identity_id,relationship_type),
 FOREIGN KEY (tenant_id,from_identity_id) REFERENCES identities(tenant_id,id),
 FOREIGN KEY (tenant_id,to_identity_id) REFERENCES identities(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS identity_relationships_tenant_from_idx ON identity_relationships(tenant_id,from_identity_id);
CREATE INDEX IF NOT EXISTS identity_relationships_tenant_to_idx ON identity_relationships(tenant_id,to_identity_id);
