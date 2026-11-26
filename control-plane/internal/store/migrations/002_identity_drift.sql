ALTER TABLE identities ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS secret_age_days INTEGER CHECK (secret_age_days IS NULL OR secret_age_days >= 0);
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS identity_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 identity_id UUID NOT NULL,
 event_type TEXT NOT NULL,
 actor TEXT NOT NULL DEFAULT 'scanner',
 before_state JSONB NOT NULL DEFAULT '{}'::jsonb,
 after_state JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id, identity_id) REFERENCES identities(tenant_id, id)
);
CREATE INDEX IF NOT EXISTS identity_events_tenant_identity_idx ON identity_events(tenant_id,identity_id,created_at DESC);

CREATE OR REPLACE FUNCTION agentguard_capture_identity_drift() RETURNS trigger AS $$
BEGIN
 IF (OLD.name,OLD.owner_email,OLD.owner_status,OLD.environment,OLD.scopes,OLD.risk_score,OLD.verified,OLD.secret_age_days,OLD.last_used_at)
    IS DISTINCT FROM
    (NEW.name,NEW.owner_email,NEW.owner_status,NEW.environment,NEW.scopes,NEW.risk_score,NEW.verified,NEW.secret_age_days,NEW.last_used_at) THEN
   INSERT INTO identity_events(tenant_id,identity_id,event_type,before_state,after_state)
   VALUES(
     NEW.tenant_id,NEW.id,'identity.changed',
     jsonb_build_object('name',OLD.name,'owner_email',OLD.owner_email,'owner_status',OLD.owner_status,'environment',OLD.environment,'scopes',OLD.scopes,'risk_score',OLD.risk_score,'verified',OLD.verified,'secret_age_days',OLD.secret_age_days,'last_used_at',OLD.last_used_at),
     jsonb_build_object('name',NEW.name,'owner_email',NEW.owner_email,'owner_status',NEW.owner_status,'environment',NEW.environment,'scopes',NEW.scopes,'risk_score',NEW.risk_score,'verified',NEW.verified,'secret_age_days',NEW.secret_age_days,'last_used_at',NEW.last_used_at)
   );
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS identities_capture_drift ON identities;
CREATE TRIGGER identities_capture_drift AFTER UPDATE ON identities
FOR EACH ROW EXECUTE FUNCTION agentguard_capture_identity_drift();
