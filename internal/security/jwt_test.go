package security

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
)

func TestGenerateToken(t *testing.T) {
	RegisterTestingT(t)

	cfg := &config.Config{}

	secret := uuid.NewString()
	service := NewService(cfg).WithSecret(secret).WithRealm("flomation.test")
	Expect(service).To(Not(BeNil()))

	username := uuid.NewString()
	tkn, err := service.Create(username, 3600)
	Expect(err).To(BeNil())
	Expect(tkn).To(Not(BeNil()))

	sub, err := service.Decode(*tkn)
	Expect(err).To(BeNil())
	Expect(*sub).To(Equal(username))
}

func TestGenerateTokenNegativeExpiration(t *testing.T) {
	RegisterTestingT(t)

	cfg := &config.Config{}

	secret := uuid.NewString()
	service := NewService(cfg).WithSecret(secret).WithRealm("flomation.test")
	Expect(service).To(Not(BeNil()))

	username := uuid.NewString()
	tkn, err := service.Create(username, -1)
	Expect(err).To(BeNil())
	Expect(tkn).To(Not(BeNil()))

	sub, err := service.Decode(*tkn)
	Expect(err).To(BeNil())
	Expect(*sub).To(Equal(username))
}
