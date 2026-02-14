package persistence

import (
	"database/sql"
	"time"
)

type User struct {
	ID                string    `db:"id"`
	Username          string    `db:"username"`
	Password          *string   `db:"password"`
	CreatedAt         time.Time `db:"created_at"`
	VerificationToken *string   `db:"verification_token"`
	Locked            bool      `db:"locked"`
	FailedAttempts    int64     `db:"failed_attempt"`
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

func (s *Service) RegisterUser(username string) (*User, error) {
	var id string
	if err := s.stmtInsertUser.Get(&id, struct {
		Username string `db:"username"`
		Key      string `db:"key"`
	}{
		Username: username,
		Key:      s.config.Database.EncryptionKey,
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
