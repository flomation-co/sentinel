package persistence

import (
	"embed"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"flomation.app/sentinel/internal/config"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations
var migrations embed.FS

func CheckAndUpdate(config *config.Config) error {
	log.Info("Performing database migrations")

	d, err := iofs.New(migrations, "migrations")
	if err != nil {
		return err
	}

	cs := fmt.Sprintf("postgres://%v:%v@%v:%d/%v?sslmode=%v", config.Database.Username, config.Database.Password, config.Database.Hostname, config.Database.Port, config.Database.Database, config.Database.SSLModeOverride)

	m, err := migrate.NewWithSourceInstance("iofs", d, cs)
	if err != nil {
		return err
	}

	err = m.Up()
	if !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}

func Down(config *config.Config) error {
	log.Info("Rolling back database migrations")

	d, err := iofs.New(migrations, "migrations")
	if err != nil {
		return err
	}

	cs := fmt.Sprintf("postgres://%v:%v@%v:%d/%v?sslmode=%v", config.Database.Username, config.Database.Password, config.Database.Hostname, config.Database.Port, config.Database.Database, config.Database.SSLModeOverride)

	m, err := migrate.NewWithSourceInstance("iofs", d, cs)
	if err != nil {
		return err
	}

	err = m.Down()
	if !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}
