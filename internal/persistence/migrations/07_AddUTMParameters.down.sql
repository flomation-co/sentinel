ALTER TABLE "user"
    DROP COLUMN IF EXISTS utm_source,
    DROP COLUMN IF EXISTS utm_medium,
    DROP COLUMN IF EXISTS utm_campaign,
    DROP COLUMN IF EXISTS utm_term,
    DROP COLUMN IF EXISTS utm_content,
    DROP COLUMN IF EXISTS utm_referrer;

ALTER TABLE sso_account
    DROP COLUMN IF EXISTS utm_source,
    DROP COLUMN IF EXISTS utm_medium,
    DROP COLUMN IF EXISTS utm_campaign,
    DROP COLUMN IF EXISTS utm_term,
    DROP COLUMN IF EXISTS utm_content,
    DROP COLUMN IF EXISTS utm_referrer;
