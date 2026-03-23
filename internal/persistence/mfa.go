package persistence

import (
	"database/sql"
	"time"
)

type MFADevice struct {
	ID         string    `db:"id"`
	UserID     string    `db:"user_id"`
	Secret     string    `db:"secret"`
	Enabled    bool      `db:"enabled"`
	EnrolledAt time.Time `db:"enrolled_at"`
}

func (s *Service) CreateMFADevice(userID string, secret string) (*MFADevice, error) {
	var id string
	if err := s.stmtCreateMFADevice.Get(&id, struct {
		UserID string `db:"user_id"`
		Secret string `db:"secret"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Secret: secret,
		Key:    s.config.Database.EncryptionKey,
	}); err != nil {
		return nil, err
	}

	return s.GetMFADeviceByUserID(userID)
}

func (s *Service) GetMFADeviceByUserID(userID string) (*MFADevice, error) {
	var device MFADevice
	if err := s.stmtGetMFADeviceByUserID.Get(&device, struct {
		UserID string `db:"user_id"`
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

	return &device, nil
}

func (s *Service) EnableMFADevice(deviceID string) error {
	_, err := s.stmtEnableMFADevice.Exec(struct {
		ID string `db:"id"`
	}{
		ID: deviceID,
	})
	return err
}

func (s *Service) DeleteMFADevice(userID string) error {
	_, err := s.stmtDeleteMFADevice.Exec(struct {
		UserID string `db:"user_id"`
	}{
		UserID: userID,
	})
	return err
}
