CREATE INDEX IF NOT EXISTS findings_tenant_suppression_expiry_idx
 ON findings(tenant_id, suppression_expires_at)
 WHERE suppression_reason IS NOT NULL;
