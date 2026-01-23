package session

import (
	"time"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/persistence"
)

const (
	StateNew               = 0
	StateDoneIdentity      = 1
	StateDonePassword      = 2
	StateDoneAuthenticator = 3

	StateComplete = 100
)

type Session struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	State      int64     `json:"-" db:"state"`
	Expiration time.Time `json:"expiration" db:"expiration"`
}

type Service struct {
	config *config.Config
	db     *persistence.Service
}

func NewService(config *config.Config, db *persistence.Service) *Service {
	return &Service{
		config: config,
		db:     db,
	}
}

func (s *Service) StartSession(userID string) (*Session, error) {
	return nil, nil
}

func (s *Service) UpdateState(sessionID string, state int64) error {
	return nil
}

func (s *Service) ClearSession(sessionID string) error {
	return nil
}

func (s *Service) ClearAllSessions(userID string) error {
	return nil
}
