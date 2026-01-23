package security

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	DefaultTokenExpirationSeconds = 3600
)

func (s *Service) Create(username string, expiration int64) (*string, error) {
	expiry := int64(DefaultTokenExpirationSeconds)
	if expiration > 0 {
		expiry = expiration
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    s.config.Security.Realm,
		Subject:   username,
		Audience:  []string{},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(expiry)).UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ID:        uuid.NewString(),
	})

	j, err := token.SignedString([]byte(s.secret))
	if err != nil {
		return nil, err
	}

	return &j, nil
}

func (s *Service) Decode(token string) (*string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return []byte(s.secret), nil
	})
	if err != nil {
		return nil, err
	}

	sub := claims["sub"].(string)
	return &sub, nil
}
