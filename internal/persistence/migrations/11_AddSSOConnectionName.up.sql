-- Display label for an SSO connection (e.g. "Okta", "Google Workspace",
-- "Microsoft Entra ID"). Added as its own migration (rather than in 08) so
-- environments that already applied 08 pick it up. IF NOT EXISTS keeps it safe
-- for fresh installs too.
ALTER TABLE sso_connection ADD COLUMN IF NOT EXISTS name VARCHAR;
