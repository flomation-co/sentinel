package persistence

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	. "github.com/onsi/gomega"
)

func TestMigrationsUpAndDown(t *testing.T) {
	RegisterTestingT(t)

	dbCfg, err := setupContainer(t)
	Expect(err).To(BeNil())
	Expect(dbCfg).To(Not(BeNil()))

	cfg := &config.Config{
		Database: *dbCfg,
	}

	err = Down(cfg)
	Expect(err).To(BeNil())

	err = CheckAndUpdate(cfg)
	Expect(err).To(BeNil())
}
