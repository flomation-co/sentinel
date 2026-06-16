package persistence

import (
	"database/sql"
	"time"
)

type User struct {
	ID                string    `db:"id"`
	Username          string    `db:"username"`
	Password          *string   `db:"password"`
	DisplayName       *string   `db:"display_name"`
	CreatedAt         time.Time `db:"created_at"`
	VerificationToken *string   `db:"verification_token"`
	Locked            bool      `db:"locked"`
	FailedAttempts    int64     `db:"failed_attempt"`
}

// UTMParameters captures marketing attribution data carried on the URL at
// the point a new user account is created or a new SSO identity is linked.
// All fields are optional — pass a zero-value struct when none are available.
type UTMParameters struct {
	Source   string `db:"utm_source"`
	Medium   string `db:"utm_medium"`
	Campaign string `db:"utm_campaign"`
	Term     string `db:"utm_term"`
	Content  string `db:"utm_content"`
	Referrer string `db:"utm_referrer"`
}

func (s *Service) UserExists(username string) (bool, error) {
	var count int64
	if err := s.stmtDoesUserExist.Get(&count, struct {
		Username string `db:"username"`
		Key      string `db:"key"`
	}{
		Username: username,
		Key:      s.config.Database.EncryptionKey,
	}); err != nil {
		return false, err
	}

	return count > 0, nil
}

func (s *Service) GetUserByUsername(username string) (*User, error) {
	var u User

	if err := s.stmtGetUserByUsername.Get(&u, struct {
		Username string `db:"username"`
		Key      string `db:"key"`
	}{
		Username: username,
		Key:      s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Service) GetUserByUsernameAndPassword(username string, password string) (*User, error) {
	var u User

	if err := s.stmtGetUserByUsernameAndPassword.Get(&u, struct {
		Username string `db:"username"`
		Password string `db:"password"`
		Key      string `db:"key"`
	}{
		Username: username,
		Password: password,
		Key:      s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Service) GetUserByID(userID string) (*User, error) {
	var u User

	if err := s.stmtGetUserByID.Get(&u, struct {
		UserID string `db:"id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Service) GetUserByVerificationToken(token string) (*User, error) {
	var u User

	if err := s.stmtGetUserByVerificationToken.Get(&u, struct {
		Token string `db:"token"`
		Key   string `db:"key"`
	}{
		Token: token,
		Key:   s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Service) GetUserByPasswordToken(token string) (*User, error) {
	var u User

	if err := s.stmtGetUserByPasswordToken.Get(&u, struct {
		Token string `db:"token"`
		Key   string `db:"key"`
	}{
		Token: token,
		Key:   s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Service) RegisterUser(username string, utm UTMParameters) (*User, error) {
	var id string
	if err := s.stmtInsertUser.Get(&id, struct {
		Username    string `db:"username"`
		Key         string `db:"key"`
		UTMSource   string `db:"utm_source"`
		UTMMedium   string `db:"utm_medium"`
		UTMCampaign string `db:"utm_campaign"`
		UTMTerm     string `db:"utm_term"`
		UTMContent  string `db:"utm_content"`
		UTMReferrer string `db:"utm_referrer"`
	}{
		Username:    username,
		Key:         s.config.Database.EncryptionKey,
		UTMSource:   utm.Source,
		UTMMedium:   utm.Medium,
		UTMCampaign: utm.Campaign,
		UTMTerm:     utm.Term,
		UTMContent:  utm.Content,
		UTMReferrer: utm.Referrer,
	}); err != nil {
		return nil, err
	}

	return s.GetUserByID(id)
}

func (s *Service) UpdatePassword(userID string, password string) error {
	_, err := s.stmtUpdateUserPassword.Exec(struct {
		UserID   string `db:"id"`
		Password string `db:"password"`
		Key      string `db:"key"`
	}{
		UserID:   userID,
		Password: password,
		Key:      s.config.Database.EncryptionKey,
	})

	return err
}

func (s *Service) LockUser(userID string) error {
	_, err := s.stmtLockUser.Exec(struct {
		UserID string `db:"id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	})

	return err
}

func (s *Service) UnlockUser(userID string) error {
	_, err := s.stmtUnlockUser.Exec(struct {
		UserID string `db:"id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	})

	return err
}

func (s *Service) UpdateFailedAttempts(userID string) error {
	_, err := s.stmtUpdateFailedAttempts.Exec(struct {
		UserID string `db:"id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	})

	return err
}

func (s *Service) Verify(userID string) error {
	_, err := s.stmtVerifyUser.Exec(struct {
		UserID string `db:"id"`
	}{
		UserID: userID,
	})

	return err
}

func (s *Service) GeneratePasswordReset(userID string) (*string, error) {
	var token string

	err := s.stmtInsertPasswordReset.Get(&token, struct {
		UserID string `db:"user_id"`
	}{
		UserID: userID,
	})

	return &token, err
}

func (s *Service) ResetFailedAttempts(userID string) error {
	_, err := s.stmtResetFailedAttempts.Exec(struct {
		UserID string `db:"id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	})

	return err
}

func (s *Service) UpdateDisplayName(userID string, displayName string) error {
	_, err := s.stmtUpdateDisplayName.Exec(struct {
		UserID      string `db:"id"`
		DisplayName string `db:"display_name"`
		Key         string `db:"key"`
	}{
		UserID:      userID,
		DisplayName: displayName,
		Key:         s.config.Database.EncryptionKey,
	})

	return err
}
