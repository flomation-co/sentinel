DROP TABLE IF EXISTS mfa_device;

CREATE TABLE mfa_device (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    secret BYTEA NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enrolled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_device_user_id ON mfa_device(user_id);
