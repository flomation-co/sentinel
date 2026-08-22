ALTER TABLE "user"
    DROP COLUMN IF EXISTS marketing_opt_in,
    DROP COLUMN IF EXISTS marketing_consent_at,
    DROP COLUMN IF EXISTS marketing_consent_source,
    DROP COLUMN IF EXISTS marketing_consent_version;
