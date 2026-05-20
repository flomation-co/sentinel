package persistence

import (
	"time"
)

// WebAuthnCredential represents a stored passkey credential.
type WebAuthnCredential struct {
	ID             string    `db:"id"`
	UserID         string    `db:"user_id"`
	CredentialID   []byte    `db:"credential_id"`
	PublicKey      []byte    `db:"public_key"`
	AAGUID         []byte    `db:"aaguid"`
	SignCount      uint32    `db:"sign_count"`
	Name           *string   `db:"name"`
	BackupEligible bool      `db:"backup_eligible"`
	BackupState    bool      `db:"backup_state"`
	Transports     *string   `db:"transports"`
	CreatedAt      time.Time `db:"created_at"`
	LastUsedAt     *time.Time `db:"last_used_at"`
}

// CreateWebAuthnCredential stores a new passkey credential.
func (s *Service) CreateWebAuthnCredential(cred *WebAuthnCredential) error {
	_, err := s.db.NamedExec(`
		INSERT INTO webauthn_credential (
			user_id, credential_id, public_key, aaguid, sign_count,
			name, backup_eligible, backup_state, transports
		) VALUES (
			:user_id, :credential_id, :public_key, :aaguid, :sign_count,
			:name, :backup_eligible, :backup_state, :transports
		)`, cred)
	return err
}

// GetWebAuthnCredentialsByUserID returns all passkey credentials for a user.
func (s *Service) GetWebAuthnCredentialsByUserID(userID string) ([]WebAuthnCredential, error) {
	var creds []WebAuthnCredential
	err := s.db.Select(&creds,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count,
		        name, backup_eligible, backup_state, transports, created_at, last_used_at
		 FROM webauthn_credential
		 WHERE user_id = $1
		 ORDER BY created_at`, userID)
	return creds, err
}

// GetWebAuthnCredentialByCredentialID looks up a credential by its raw WebAuthn ID.
func (s *Service) GetWebAuthnCredentialByCredentialID(credentialID []byte) (*WebAuthnCredential, error) {
	var cred WebAuthnCredential
	err := s.db.Get(&cred,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count,
		        name, backup_eligible, backup_state, transports, created_at, last_used_at
		 FROM webauthn_credential
		 WHERE credential_id = $1`, credentialID)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// UpdateWebAuthnSignCount updates the sign counter and last-used timestamp after authentication.
func (s *Service) UpdateWebAuthnSignCount(credentialID []byte, signCount uint32) error {
	_, err := s.db.Exec(
		`UPDATE webauthn_credential SET sign_count = $1, last_used_at = NOW() WHERE credential_id = $2`,
		signCount, credentialID)
	return err
}

// DeleteWebAuthnCredential removes a passkey credential by its UUID.
func (s *Service) DeleteWebAuthnCredential(id string, userID string) error {
	_, err := s.db.Exec(
		`DELETE FROM webauthn_credential WHERE id = $1 AND user_id = $2`,
		id, userID)
	return err
}

// HasWebAuthnCredentials checks whether a user has any registered passkeys.
func (s *Service) HasWebAuthnCredentials(userID string) (bool, error) {
	var count int
	err := s.db.Get(&count,
		`SELECT COUNT(*) FROM webauthn_credential WHERE user_id = $1`, userID)
	return count > 0, err
}