CREATE TABLE IF NOT EXISTS known_device (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES "user"(id),
    device_hash     BYTEA NOT NULL,
    ip_address      BYTEA,
    device          BYTEA,
    location        BYTEA,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, device_hash)
);

CREATE INDEX IF NOT EXISTS idx_known_device_user_hash ON known_device(user_id, device_hash);
