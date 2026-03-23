package mfa

import (
	"bytes"
	"image/png"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/persistence"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type Service struct {
	config   *config.Config
	database *persistence.Service
}

func New(config *config.Config, database *persistence.Service) *Service {
	return &Service{
		config:   config,
		database: database,
	}
}

// GenerateSecret creates a new TOTP secret for the user and stores it
// (disabled) in the database. Returns the OTP key for QR code generation.
func (s *Service) GenerateSecret(username string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Flomation",
		AccountName: username,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// StoreSecret saves the TOTP secret to the database for the given user.
// Deletes any existing device first to prevent duplicates.
func (s *Service) StoreSecret(userID string, secret string) error {
	// Remove any existing device
	_ = s.database.DeleteMFADevice(userID)

	_, err := s.database.CreateMFADevice(userID, secret)
	return err
}

// GenerateQRCode returns a PNG image of the TOTP QR code.
func (s *Service) GenerateQRCode(key *otp.Key) ([]byte, error) {
	img, err := key.Image(250, 250)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ValidateCode checks a TOTP code against the user's stored secret.
func (s *Service) ValidateCode(userID string, code string) (bool, error) {
	device, err := s.database.GetMFADeviceByUserID(userID)
	if err != nil || device == nil {
		return false, err
	}

	return totp.Validate(code, device.Secret), nil
}

// EnableMFA marks the user's MFA device as enabled (setup confirmed).
func (s *Service) EnableMFA(userID string) error {
	device, err := s.database.GetMFADeviceByUserID(userID)
	if err != nil || device == nil {
		return err
	}

	return s.database.EnableMFADevice(device.ID)
}

// DisableMFA removes the user's MFA device.
func (s *Service) DisableMFA(userID string) error {
	return s.database.DeleteMFADevice(userID)
}

// IsEnrolled checks if the user has an enabled MFA device.
func (s *Service) IsEnrolled(userID string) (bool, error) {
	device, err := s.database.GetMFADeviceByUserID(userID)
	if err != nil {
		return false, err
	}

	return device != nil && device.Enabled, nil
}

// GetSecret retrieves the stored TOTP secret for QR code regeneration.
func (s *Service) GetSecret(userID string) (string, error) {
	device, err := s.database.GetMFADeviceByUserID(userID)
	if err != nil || device == nil {
		return "", err
	}

	return device.Secret, nil
}
