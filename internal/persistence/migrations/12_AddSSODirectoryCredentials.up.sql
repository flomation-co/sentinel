-- Optional directory-API credentials so the group→Team mapping UI can offer a
-- searchable group picker. Entra reuses the OIDC client id/secret via Graph, so
-- it needs nothing here; Okta needs an SSWS API token and Google needs a
-- service-account JSON (+ an admin email to impersonate). Secret is encrypted at
-- rest like client_secret.
ALTER TABLE sso_connection ADD COLUMN IF NOT EXISTS directory_secret BYTEA;
ALTER TABLE sso_connection ADD COLUMN IF NOT EXISTS directory_admin VARCHAR;
