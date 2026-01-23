package main

import (
	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/listener"
	"flomation.app/sentinel/internal/persistence"
	"flomation.app/sentinel/internal/security"
	"flomation.app/sentinel/internal/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("unable to load config")
	}

	if err := persistence.CheckAndUpdate(cfg); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Unable to run database migrations")
	}

	db, err := persistence.NewService(cfg)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Unable to configure database connection")
	}

	if cfg.Security.Secret == "" {
		c, err := db.GetConfiguration("auth_secret")
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Fatal("Unable to read auth_secret from database")
		}

		authSecret := utils.GenerateRandomString(64)
		if c != nil {
			authSecret = string(c)
		} else {
			if err := db.InsertConfiguration("auth_secret", []byte(authSecret)); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Fatal("Unable to persist auth_secret to database")
			}
		}

		cfg.Security.Secret = authSecret
	}

	sec := security.NewService(cfg)

	l, err := listener.NewListener(cfg, sec, db)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("unable to create HTTP listener")
	}
	log.Fatal(l.Listen())
}
