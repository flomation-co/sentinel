-- Tracks the "turn on MFA" prompt shown after a successful password login.
--
-- Only the dismissal is recorded. Accepting the prompt needs no column: the
-- outcome is an enrolled device in mfa_device, and IsEnrolled already answers
-- "has this user got MFA" without a second source of truth to drift from.
--
-- The count is kept so the cadence can be softened later (asking less often
-- the more times somebody has said no) without another migration.
ALTER TABLE "user"
    ADD COLUMN mfa_nudge_dismissed_at TIMESTAMPTZ,
    ADD COLUMN mfa_nudge_count        INTEGER NOT NULL DEFAULT 0;
