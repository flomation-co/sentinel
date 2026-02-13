package persistence

import (
	"database/sql"
	"time"

	log "github.com/sirupsen/logrus"
)

func (s *Service) StartSession(userID *string, ipAddress *string, location *string, device *string, metadata interface{}) (*string, error) {
	var id string
	if err := s.stmtInsertSession.Get(&id, struct {
		UserID    *string     `db:"user_id"`
		IPAddress *string     `db:"ip_address"`
		Location  *string     `db:"location"`
		Device    *string     `db:"device"`
		Key       string      `db:"key"`
		MetaData  interface{} `db:"metadata"`
	}{
		UserID:    userID,
		IPAddress: ipAddress,
		Location:  location,
		Device:    device,
		Key:       s.config.Database.EncryptionKey,
		MetaData:  metadata,
	}); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"id":      id,
		"user_id": userID,
	}).Info("Created session")

	return &id, nil
}

func (s *Service) ClearSession(ID string) error {
	_, err := s.stmtClearSession.Exec(struct {
		ID string `db:"id"`
	}{
		ID: ID,
	})

	return err
}

func (s *Service) ClearAllUserSessions(userID string) error {
	_, err := s.stmtClearUserSessions.Exec(struct {
		UserID string `db:"user_id"`
	}{
		UserID: userID,
	})

	return err
}

func (s *Service) UpdateSessionState(ID string, state int) error {
	_, err := s.stmtUpdateSessionState.Exec(struct {
		SessionID string `db:"id"`
		State     int    `db:"state"`
	}{
		SessionID: ID,
		State:     state,
	})

	return err
}

func (s *Service) UpdateSessionExpiration(ID string, expiration time.Time) error {
	_, err := s.stmtUpdateSessionExpiration.Exec(struct {
		SessionID  string    `db:"id"`
		Expiration time.Time `db:"expiration"`
	}{
		SessionID:  ID,
		Expiration: expiration,
	})

	return err
}

func (s *Service) UpdateSessionUserID(ID string, userID string) error {
	_, err := s.stmtUpdateSessionUserID.Exec(struct {
		SessionID string `db:"id"`
		UserID    string `db:"user_id"`
	}{
		SessionID: ID,
		UserID:    userID,
	})

	return err
}

func (s *Service) GetSessionState(ID string) (int, error) {
	var result int

	if err := s.stmtGetSessionState.Get(&result, struct {
		ID string `db:"id"`
	}{
		ID: ID,
	}); err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		}

		return -1, err
	}

	return result, nil
}

func (s *Service) GetSessionUserID(ID string) (*string, error) {
	var result string

	if err := s.stmtGetSessionUserID.Get(&result, struct {
		ID string `db:"id"`
	}{
		ID: ID,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	return &result, nil
}

func (s *Service) GetSessionUsername(ID string) (*string, error) {
	var result string

	if err := s.stmtGetSessionUsername.Get(&result, struct {
		ID  string `db:"id"`
		Key string `db:"key"`
	}{
		ID:  ID,
		Key: s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	return &result, nil
}

func (s *Service) GetSessionRedirectURL(ID string) (*string, error) {
	var result string

	if err := s.stmtGetSessionUsername.Get(&result, struct {
		ID  string `db:"id"`
		Key string `db:"key"`
	}{
		ID:  ID,
		Key: s.config.Database.EncryptionKey,
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, err
	}

	return &result, nil
}
