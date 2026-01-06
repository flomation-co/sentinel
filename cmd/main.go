package main

import (
	"flomation.app/sentinel/internal/config"
	"fmt"
	log "github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("unable to load config")
	}

	fmt.Printf("Listening: %v\n", cfg.Listener.ListenAddress())
}
