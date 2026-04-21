package persistence

import "time"

// LoginHistoryEntry represents a single known device / login record.
type LoginHistoryEntry struct {
	ID          string    `json:"id" db:"id"`
	IPAddress   *string   `json:"ip_address" db:"ip_address"`
	Device      *string   `json:"device" db:"device"`
	Location    *string   `json:"location" db:"location"`
	FirstSeenAt time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at" db:"last_seen_at"`
}

// IsKnownDevice checks whether the user has previously logged in with
// the given device fingerprint (user_agent + ip_address).
func (s *Service) IsKnownDevice(userID, deviceHash string) (bool, error) {
	var count int
	if err := s.stmtCheckKnownDevice.Get(&count, struct {
		UserID     string `db:"user_id"`
		DeviceHash string `db:"device_hash"`
	}{
		UserID:     userID,
		DeviceHash: deviceHash,
	}); err != nil {
		return false, err
	}
	return count > 0, nil
}

// RegisterKnownDevice records a device fingerprint for a user. If the
// device already exists, the insert is silently skipped (ON CONFLICT DO NOTHING).
func (s *Service) RegisterKnownDevice(userID, deviceHash, ipAddress, userAgent, location string) error {
	_, err := s.stmtInsertKnownDevice.Exec(struct {
		UserID     string `db:"user_id"`
		DeviceHash string `db:"device_hash"`
		IPAddress  string `db:"ip_address"`
		Device     string `db:"device"`
		Location   string `db:"location"`
		Key        string `db:"key"`
	}{
		UserID:     userID,
		DeviceHash: deviceHash,
		IPAddress:  ipAddress,
		Device:     userAgent,
		Location:   location,
		Key:        s.config.Database.EncryptionKey,
	})
	return err
}

// TouchKnownDevice updates the last_seen_at timestamp for an existing device.
func (s *Service) TouchKnownDevice(userID, deviceHash string) error {
	_, err := s.stmtUpdateKnownDevice.Exec(struct {
		UserID     string `db:"user_id"`
		DeviceHash string `db:"device_hash"`
	}{
		UserID:     userID,
		DeviceHash: deviceHash,
	})
	return err
}

// GetLoginHistory returns the most recent known device entries for a user.
func (s *Service) GetLoginHistory(userID string) ([]LoginHistoryEntry, error) {
	var results []LoginHistoryEntry
	if err := s.stmtGetLoginHistory.Select(&results, struct {
		UserID string `db:"user_id"`
		Key    string `db:"key"`
	}{
		UserID: userID,
		Key:    s.config.Database.EncryptionKey,
	}); err != nil {
		return nil, err
	}
	return results, nil
}
