package persistence

import "time"

// SSOAccount represents a linked third-party identity (e.g. Google).
type SSOAccount struct {
	ID             string    `db:"id"`
	UserID         string    `db:"user_id"`
	Provider       string    `db:"provider"`
	ProviderUserID string    `db:"provider_user_id"`
	Email          *string   `db:"email"`
	CreatedAt      time.Time `db:"created_at"`
}

// GetSSOAccount looks up a linked account by provider and external user ID.
func (s *Service) GetSSOAccount(provider, providerUserID string) (*SSOAccount, error) {
	var acct SSOAccount
	err := s.db.Get(&acct,
		`SELECT id, user_id, provider, provider_user_id, created_at
		 FROM sso_account
		 WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID)
	if err != nil {
		return nil, err
	}
	return &acct, nil
}

// CreateSSOAccount links an external provider identity to a local user.
func (s *Service) CreateSSOAccount(userID, provider, providerUserID, email string) error {
	_, err := s.db.Exec(
		`INSERT INTO sso_account (user_id, provider, provider_user_id, email)
		 VALUES ($1, $2, $3, PGP_SYM_ENCRYPT($4, $5))
		 ON CONFLICT (provider, provider_user_id) DO NOTHING`,
		userID, provider, providerUserID, email, s.config.Database.EncryptionKey)
	return err
}

// GetSSOAccountsByUserID returns all linked providers for a user.
func (s *Service) GetSSOAccountsByUserID(userID string) ([]SSOAccount, error) {
	var accts []SSOAccount
	err := s.db.Select(&accts,
		`SELECT id, user_id, provider, provider_user_id, created_at
		 FROM sso_account
		 WHERE user_id = $1
		 ORDER BY created_at`, userID)
	return accts, err
}
