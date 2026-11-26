ALTER TABLE api_keys
 ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext BYTEA,
 ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN IF NOT EXISTS mfa_last_used_step BIGINT NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS mfa_locked_until TIMESTAMPTZ,
 ADD COLUMN IF NOT EXISTS mfa_verified_at TIMESTAMPTZ;

ALTER TABLE api_keys
 ADD CONSTRAINT api_keys_mfa_failed_attempts_check
 CHECK (mfa_failed_attempts BETWEEN 0 AND 5);
