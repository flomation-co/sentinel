package persistence

import (
	"database/sql"
	"time"
)

// SSOConnection is an enterprise IdP connection for a Flomation organisation.
// ClientSecret is decrypted on read only where needed (see GetSSOConnectionByID
// / ResolveSSOByDomain); list endpoints omit it.
type SSOConnection struct {
	ID             string    `db:"id" json:"id"`
	OrganisationID string    `db:"organisation_id" json:"organisation_id"`
	Protocol       string    `db:"protocol" json:"protocol"`
	Issuer         string    `db:"issuer" json:"issuer"`
	TenantID       *string   `db:"tenant_id" json:"tenant_id,omitempty"`
	ClientID       string    `db:"client_id" json:"client_id"`
	ClientSecret   *string   `db:"client_secret" json:"-"`
	Enabled        bool      `db:"enabled" json:"enabled"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

// SSODomain is a claimed email domain routing to a connection. Verified is
// derived from verified_at for JSON consumers.
type SSODomain struct {
	ID                string     `db:"id" json:"id"`
	ConnectionID      string     `db:"connection_id" json:"connection_id"`
	Domain            string     `db:"domain" json:"domain"`
	VerificationToken string     `db:"verification_token" json:"verification_token"`
	VerifiedAt        *time.Time `db:"verified_at" json:"verified_at,omitempty"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
}

func (d SSODomain) Verified() bool { return d.VerifiedAt != nil }

// CreateSSOConnection inserts a connection, encrypting the client secret at rest.
func (s *Service) CreateSSOConnection(c SSOConnection) (string, error) {
	var id string
	err := s.db.Get(&id, `
		INSERT INTO sso_connection (organisation_id, protocol, issuer, tenant_id, client_id, client_secret, enabled)
		VALUES ($1, $2, $3, $4, $5, PGP_SYM_ENCRYPT($6, $7), $8)
		RETURNING id
	`, c.OrganisationID, c.Protocol, c.Issuer, c.TenantID, c.ClientID, derefOr(c.ClientSecret), s.config.Database.EncryptionKey, c.Enabled)
	return id, err
}

// UpdateSSOConnection updates a connection. The client secret is only re-written
// when a non-nil value is supplied (so the UI can omit it to leave it unchanged).
func (s *Service) UpdateSSOConnection(c SSOConnection) error {
	if c.ClientSecret != nil {
		_, err := s.db.Exec(`
			UPDATE sso_connection
			SET issuer=$1, tenant_id=$2, client_id=$3, client_secret=PGP_SYM_ENCRYPT($4,$5), enabled=$6, updated_at=NOW()
			WHERE id=$7 AND organisation_id=$8
		`, c.Issuer, c.TenantID, c.ClientID, *c.ClientSecret, s.config.Database.EncryptionKey, c.Enabled, c.ID, c.OrganisationID)
		return err
	}
	_, err := s.db.Exec(`
		UPDATE sso_connection SET issuer=$1, tenant_id=$2, client_id=$3, enabled=$4, updated_at=NOW()
		WHERE id=$5 AND organisation_id=$6
	`, c.Issuer, c.TenantID, c.ClientID, c.Enabled, c.ID, c.OrganisationID)
	return err
}

// GetSSOConnectionsForOrg lists an org's connections WITHOUT the client secret.
func (s *Service) GetSSOConnectionsForOrg(orgID string) ([]SSOConnection, error) {
	var out []SSOConnection
	err := s.db.Select(&out, `
		SELECT id, organisation_id, protocol, issuer, tenant_id, client_id, enabled, created_at, updated_at
		FROM sso_connection WHERE organisation_id=$1 ORDER BY created_at
	`, orgID)
	return out, err
}

// GetSSOConnectionByID returns a connection WITH the decrypted client secret —
// used at login (IdP exchange). Returns (nil, nil) when not found.
func (s *Service) GetSSOConnectionByID(id string) (*SSOConnection, error) {
	var c SSOConnection
	err := s.db.Get(&c, `
		SELECT id, organisation_id, protocol, issuer, tenant_id, client_id,
		       PGP_SYM_DECRYPT(client_secret, $2) AS client_secret, enabled, created_at, updated_at
		FROM sso_connection WHERE id=$1
	`, id, s.config.Database.EncryptionKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// DeleteSSOConnection removes a connection (cascades to its domains).
func (s *Service) DeleteSSOConnection(id, orgID string) error {
	_, err := s.db.Exec(`DELETE FROM sso_connection WHERE id=$1 AND organisation_id=$2`, id, orgID)
	return err
}

// ResolveSSOByDomain is the Home Realm Discovery lookup: given an email domain,
// return the ENABLED connection (with decrypted secret) whose domain is VERIFIED.
// Returns (nil, nil) when the domain is not SSO-managed — the caller then falls
// back to the normal password flow.
func (s *Service) ResolveSSOByDomain(domain string) (*SSOConnection, error) {
	var c SSOConnection
	err := s.db.Get(&c, `
		SELECT c.id, c.organisation_id, c.protocol, c.issuer, c.tenant_id, c.client_id,
		       PGP_SYM_DECRYPT(c.client_secret, $2) AS client_secret, c.enabled, c.created_at, c.updated_at
		FROM sso_connection c
		JOIN sso_domain d ON d.connection_id = c.id
		WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND c.enabled = true
		LIMIT 1
	`, domain, s.config.Database.EncryptionKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ── Domains ──────────────────────────────────────────────────────────

// AddSSODomain claims a domain for a connection (unverified) with a fresh token.
func (s *Service) AddSSODomain(connectionID, domain, token string) (string, error) {
	var id string
	err := s.db.Get(&id, `
		INSERT INTO sso_domain (connection_id, domain, verification_token)
		VALUES ($1, $2, $3) RETURNING id
	`, connectionID, domain, token)
	return id, err
}

// GetSSODomainsForConnection lists a connection's domains.
func (s *Service) GetSSODomainsForConnection(connectionID string) ([]SSODomain, error) {
	var out []SSODomain
	err := s.db.Select(&out, `SELECT * FROM sso_domain WHERE connection_id=$1 ORDER BY domain`, connectionID)
	return out, err
}

// GetSSODomainByID returns a single domain (nil,nil when missing).
func (s *Service) GetSSODomainByID(id string) (*SSODomain, error) {
	var d SSODomain
	err := s.db.Get(&d, `SELECT * FROM sso_domain WHERE id=$1`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// MarkSSODomainVerified stamps verified_at once the DNS TXT check passes.
func (s *Service) MarkSSODomainVerified(id string) error {
	_, err := s.db.Exec(`UPDATE sso_domain SET verified_at=NOW() WHERE id=$1`, id)
	return err
}

// DeleteSSODomain removes a claimed domain.
func (s *Service) DeleteSSODomain(id string) error {
	_, err := s.db.Exec(`DELETE FROM sso_domain WHERE id=$1`, id)
	return err
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
