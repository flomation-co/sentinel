-- UTM attribution columns for registration sources. Captured on first sign-up
-- (email/password and SSO) and on each SSO link, so we can attribute new users
-- and new linked identities back to the campaign/medium/source that drove them.
--
-- Stored unencrypted: UTM parameters are not PII, are typically logged by every
-- analytics tool in the pipeline, and keeping them queryable in plain text lets
-- the admin dashboard aggregate attribution reports without a per-row decrypt.
ALTER TABLE "user"
    ADD COLUMN IF NOT EXISTS utm_source     TEXT,
    ADD COLUMN IF NOT EXISTS utm_medium     TEXT,
    ADD COLUMN IF NOT EXISTS utm_campaign   TEXT,
    ADD COLUMN IF NOT EXISTS utm_term       TEXT,
    ADD COLUMN IF NOT EXISTS utm_content    TEXT,
    ADD COLUMN IF NOT EXISTS utm_referrer   TEXT;

ALTER TABLE sso_account
    ADD COLUMN IF NOT EXISTS utm_source     TEXT,
    ADD COLUMN IF NOT EXISTS utm_medium     TEXT,
    ADD COLUMN IF NOT EXISTS utm_campaign   TEXT,
    ADD COLUMN IF NOT EXISTS utm_term       TEXT,
    ADD COLUMN IF NOT EXISTS utm_content    TEXT,
    ADD COLUMN IF NOT EXISTS utm_referrer   TEXT;
