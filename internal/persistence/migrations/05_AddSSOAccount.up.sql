CREATE TABLE IF NOT EXISTS sso_account (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    provider        VARCHAR(20) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email           BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_sso_account_user ON sso_account(user_id);
