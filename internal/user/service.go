package user

import (
	"errors"
	"fmt"
	"time"

	"flomation.app/sentinel/internal/smtp"
	log "github.com/sirupsen/logrus"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/persistence"
)

var delays = [...]time.Duration{
	time.Second,
	time.Second * 2,
	time.Second * 10,
	time.Second * 30,
	time.Second * 60,
	time.Second * 120,
	time.Second * 300,
	time.Second * 600,
	time.Second * 1200,
	time.Second * 3600,
}

type Service struct {
	config   *config.Config
	database *persistence.Service
	smtp     *smtp.Service
}

func New(config *config.Config, database *persistence.Service) *Service {
	return &Service{
		config:   config,
		database: database,
		smtp:     smtp.New(config),
	}
}

func (s *Service) RegisterUser(username string) (*persistence.User, error) {
	u, err := s.database.RegisterUser(username)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"user": u.VerificationToken,
	}).Info("sending verification email")
	if u.VerificationToken != nil {
		if err := s.smtp.SendTemplatedEmail(username, "Welcome to Flomation", "Continue setting up your account", "Thanks for signing up! Please set your password so we can keep your account safe and get you started.", "Set Password", fmt.Sprintf("%v/verify?token=%v", s.config.Listener.URL, *u.VerificationToken)); err != nil {
			return nil, err
		}
	}

	return u, nil
}

func (s *Service) UpdatePassword(id string, password string) error {
	u, err := s.database.GetUserByID(id)
	if err != nil {
		return err
	}

	if u == nil {
		return errors.New("invalid user")
	}

	if err := s.database.UpdatePassword(id, password); err != nil {
		return err
	}

	if err := s.smtp.SendTemplatedEmail(u.Username, "Your password has been reset", "Your password has been reset", "The password on your account has been updated", "Login", fmt.Sprintf("%v", s.config.Security.LoginRedirect)); err != nil {
		return err
	}

	return nil
}

func (s *Service) GetUserByID(id string) (*persistence.User, error) {
	u, err := s.database.GetUserByID(id)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (s *Service) GetUserByUsernameAndPassword(username string, password string) (*persistence.User, error) {
	u, err := s.database.GetUserByUsername(username)
	if err != nil {
		time.Sleep(time.Second * 10)
		return nil, err
	}

	if u == nil {
		time.Sleep(time.Second * 10)
		return nil, nil
	}

	u, err = s.database.GetUserByUsernameAndPassword(username, password)
	if err != nil {
		if err := s.database.UpdateFailedAttempts(u.ID); err != nil {
			time.Sleep(time.Second * 10)
			return nil, err
		}

		fa := u.FailedAttempts + 1
		if fa > int64(len(delays)) {
			fa = int64(len(delays)) - 1
		}

		time.Sleep(delays[fa])

		return nil, nil
	}

	return u, nil
}

func (s *Service) GetUserByUsername(username string) (*persistence.User, error) {
	return s.database.GetUserByUsername(username)
}

func (s *Service) GetUserByVerificationToken(token string) (*persistence.User, error) {
	return s.database.GetUserByVerificationToken(token)
}

func (s *Service) GetUserByPasswordToken(token string) (*persistence.User, error) {
	return s.database.GetUserByPasswordToken(token)
}

func (s *Service) UpdateFailedAttempts(id string) error {
	return s.database.UpdateFailedAttempts(id)
}

func (s *Service) Verify(id string) error {
	return s.database.Verify(id)
}

func (s *Service) GeneratePasswordReset(id string) error {
	u, err := s.GetUserByID(id)
	if err != nil {
		return err
	}

	if u == nil {
		return errors.New("invalid user for password reset")
	}

	token, err := s.database.GeneratePasswordReset(id)
	if err != nil {
		return err
	}

	if err := s.smtp.SendTemplatedEmail(u.Username, "Reset your password", "Continue resetting your password", "A password reset has been requested on your account, use the button below to reset your password", "Reset Password", fmt.Sprintf("%v/password?token=%v", s.config.Listener.URL, *token)); err != nil {
		return err
	}

	return nil
}
