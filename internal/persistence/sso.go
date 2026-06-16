package persistence

import (
	"database/sql"
	"time"
)

// SSOAccount represents a linked SSO provider account.
type SSOAccount struct {
	ID             string    `db:"id" json:"id"`
	UserID         string    `db:"user_id" json:"user_id"`
	Provider       string    `db:"provider" json:"provider"`
	ProviderUserID string    `db:"provider_user_id" json:"provider_user_id"`
	Email          *string   `db:"email" json:"email,omitempty"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

// FindSSOAccount looks up an SSO account by provider and provider user ID.
func (s *Service) FindSSOAccount(provider, providerUserID string) (*SSOAccount, error) {
	var result SSOAccount
	err := s.db.Get(&result,
		"SELECT id, user_id, provider, provider_user_id, created_at FROM sso_account WHERE provider = $1 AND provider_user_id = $2",
		provider, providerUserID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateSSOAccount links an SSO provider account to a user. UTM parameters
// captured at link time are persisted so we can attribute the source of the
// linked identity even when the underlying user account already existed.
// Empty UTM strings are stored as NULL.
func (s *Service) CreateSSOAccount(userID, provider, providerUserID, email string, utm UTMParameters) error {
	_, err := s.db.Exec(
		`INSERT INTO sso_account (
			user_id,
			provider,
			provider_user_id,
			email,
			utm_source,
			utm_medium,
			utm_campaign,
			utm_term,
			utm_content,
			utm_referrer
		) VALUES (
			$1, $2, $3,
			PGP_SYM_ENCRYPT($4, $5),
			NULLIF($6, ''),
			NULLIF($7, ''),
			NULLIF($8, ''),
			NULLIF($9, ''),
			NULLIF($10, ''),
			NULLIF($11, '')
		) ON CONFLICT (provider, provider_user_id) DO NOTHING`,
		userID, provider, providerUserID, email, s.config.Database.EncryptionKey,
		utm.Source, utm.Medium, utm.Campaign, utm.Term, utm.Content, utm.Referrer,
	)
	return err
}

// GetSSOAccountsForUser returns all SSO accounts linked to a user.
func (s *Service) GetSSOAccountsForUser(userID string) ([]SSOAccount, error) {
	var results []SSOAccount
	err := s.db.Select(&results,
		"SELECT id, user_id, provider, provider_user_id, created_at FROM sso_account WHERE user_id = $1 ORDER BY created_at",
		userID,
	)
	return results, err
}

// DeleteSSOAccount removes an SSO account link.
func (s *Service) DeleteSSOAccount(id, userID string) error {
	_, err := s.db.Exec(
		"DELETE FROM sso_account WHERE id = $1 AND user_id = $2",
		id, userID,
	)
	return err
}
