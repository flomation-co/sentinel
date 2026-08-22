-- Marketing consent captured at the point the email address is collected.
--
-- Registration is where the address is obtained, so it is also where PECR
-- reg 22(3)(c) requires a simple means of refusal to be offered. Recording the
-- choice here (rather than only in the downstream product) means every account
-- carries a consent decision from creation, including accounts that never
-- complete onboarding.
--
-- UK GDPR Art 7(1) requires us to be able to DEMONSTRATE consent, so the
-- boolean alone is insufficient — we keep when it was given, through which
-- surface, and which wording the user agreed to.
--
-- Stored unencrypted for the same reasons as the UTM columns: the consent
-- decision is not itself PII beyond its association with the row, and keeping
-- it queryable lets us evidence consent without a per-row decrypt.
ALTER TABLE "user"
    ADD COLUMN IF NOT EXISTS marketing_opt_in          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS marketing_consent_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS marketing_consent_source  TEXT,
    ADD COLUMN IF NOT EXISTS marketing_consent_version TEXT;
