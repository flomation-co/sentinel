package session

import (
	"encoding/json"
	"fmt"
	"time"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/geo"
	"flomation.app/sentinel/internal/persistence"
)

const (
	StateNew               = 0
	StateDoneIdentity      = 1
	StateDonePassword      = 2
	StateDoneAuthenticator = 3

	StateSetPassword = 50

	StateComplete = 100
	StateCleared  = 999
)

type Session struct {
	ID         string      `json:"id"`
	UserID     *string     `json:"-"`
	State      int64       `json:"-"`
	Expiration time.Time   `json:"expiration"`
	IPAddress  *string     `json:"-"`
	Location   *string     `json:"-"`
	Device     *string     `json:"-"`
	Metadata   interface{} `json:"-"`
}

type Service struct {
	config *config.Config
	db     *persistence.Service
}

func New(config *config.Config, db *persistence.Service) *Service {
	return &Service{
		config: config,
		db:     db,
	}
}

func (s *Service) StartSession(sess Session) (*Session, error) {
	if sess.IPAddress != nil && *sess.IPAddress != "127.0.0.1" {
		data, err := geo.GetGeoDataFromIP(*s.config, *sess.IPAddress)
		if err != nil {
			return nil, err
		}

		loc := fmt.Sprintf("%v, %v", data.Location.City, data.Location.Country.Name)
		sess.Location = &loc
	}

	sess.State = StateNew

	if sess.Metadata != nil {
		b, err := json.Marshal(sess.Metadata)
		if err != nil {
			return nil, err
		}

		sess.Metadata = b
	}

	sessionID, err := s.db.StartSession(sess.UserID, sess.IPAddress, sess.Location, sess.Device, sess.Metadata)
	if err != nil {
		return nil, err
	}

	sess.ID = *sessionID

	return &sess, nil
}

func (s *Service) UpdateState(sessionID string, state int) error {
	return s.db.UpdateSessionState(sessionID, state)
}

func (s *Service) UpdateStateExpiration(sessionID string, expiration time.Time) error {
	return s.db.UpdateSessionExpiration(sessionID, expiration)
}

func (s *Service) SetSessionUserID(sessionID string, userID string) error {
	return s.db.UpdateSessionUserID(sessionID, userID)
}

func (s *Service) ClearSession(sessionID string) error {
	return s.db.ClearSession(sessionID)
}

func (s *Service) ClearAllSessions(userID string) error {
	return s.db.ClearAllUserSessions(userID)
}

func (s *Service) GetSessionState(sessionID string) (int, error) {
	return s.db.GetSessionState(sessionID)
}

func (s *Service) GetSessionUserID(sessionID string) (*string, error) {
	return s.db.GetSessionUserID(sessionID)
}

func (s *Service) GetSessionUsername(sessionID string) (*string, error) {
	return s.db.GetSessionUsername(sessionID)
}

func (s *Service) GetSessionRedirectURL(sessionID string) (*string, error) {
	return s.db.GetSessionRedirectURL(sessionID)
}
