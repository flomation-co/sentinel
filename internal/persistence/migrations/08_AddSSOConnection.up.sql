-- Enterprise SSO (OIDC first, SAML later) connections, configured per Flomation
-- organisation. organisation_id is the API's org UUID (there is no organisation
-- table in Sentinel, so it's an opaque reference, not a FK). The client secret
-- is encrypted at rest with the same PGP key used for usernames.
CREATE TABLE IF NOT EXISTS sso_connection (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'oidc',   -- oidc | saml (saml later)
    issuer VARCHAR NOT NULL,                          -- e.g. https://login.microsoftonline.com/<tenant>/v2.0
    tenant_id VARCHAR,                                -- Entra tenant id, pinned on the id_token 'tid'
    client_id VARCHAR NOT NULL,
    client_secret BYTEA,                             -- PGP_SYM_ENCRYPT
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sso_connection_org ON sso_connection(organisation_id);

-- Claimed email domains. A domain routes to SSO only once verified (DNS TXT).
-- Domain is globally unique — one domain cannot be claimed by two orgs.
CREATE TABLE IF NOT EXISTS sso_domain (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES sso_connection(id) ON DELETE CASCADE,
    domain VARCHAR NOT NULL UNIQUE,
    verification_token VARCHAR NOT NULL,             -- value for the DNS TXT record
    verified_at TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sso_domain_connection ON sso_domain(connection_id);
