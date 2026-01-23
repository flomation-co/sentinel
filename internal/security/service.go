package security

import (
	"flomation.app/sentinel/internal/config"
)

type Service struct {
	config *config.Config

	realm  string
	secret string
}

func NewService(config *config.Config) *Service {
	s := Service{
		config: config,
		realm:  config.Security.Realm,

		secret: config.Security.Secret,
	}

	return &s
}

func (s *Service) WithSecret(secret string) *Service {
	s.secret = secret
	return s
}

func (s *Service) WithRealm(realm string) *Service {
	s.realm = realm
	return s
}
