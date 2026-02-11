package smtp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"flomation.app/sentinel/internal/assets"
	"github.com/google/uuid"

	"flomation.app/sentinel/internal/config"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	config  *config.Config
	enabled bool

	client *smtp.Client
}

func New(config *config.Config) *Service {
	notifier := Service{
		config: config,
	}

	if config.Notification.Enabled {
		notifier.enabled = true
	}

	return &notifier
}

func (s *Service) clientActive() bool {
	if s.client == nil {
		return false
	}

	if err := s.client.Noop(); err != nil {
		return false
	}

	return true
}

func (s *Service) configureBackgroundClient() error {
	host := s.config.Notification.SMTP.Host
	serverName := fmt.Sprintf("%v:%v", host, 587)

	auth := smtp.PlainAuth("", s.config.Notification.SMTP.Username, s.config.Notification.SMTP.Password, host)

	client, err := smtp.Dial(serverName)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err,
			"server": serverName,
		}).Error("unable to dial connection")
		return err
	}

	if err := client.Hello("Flomation"); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to say HELO")
		return err
	}

	if ok, _ := client.Extension("STARTTLS"); ok {
		cfg := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
		}
		if err = client.StartTLS(cfg); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to start tls")
			return err
		}
	}

	if err := client.Auth(auth); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to auth")
		return err
	}

	go func(c *smtp.Client) {
		if err := c.Noop(); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("smtp client has reset")
			_ = c.Close()
			return
		}

		time.Sleep(time.Second * 15)
	}(client)

	s.client = client

	return nil
}

func (s *Service) sendSMTPEmail(recipients []string, subject string, body string) error {
	if s.config.Notification.OverrideDestination != nil {
		recipients = []string{
			*s.config.Notification.OverrideDestination,
		}
	}

	for _, addr := range recipients {
		recipient := strings.TrimSuffix(strings.TrimPrefix(addr, " "), " ")
		msg := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\nMIME-Version: 1.0\nContent-Type: text/html; charset=\"UTF-8\";\n\n%v\n\n", s.config.Notification.SendFrom, recipient, subject, body)

		firstAttempt := true

		for i := 0; i < 10; i++ {
			if !firstAttempt {
				time.Sleep(time.Millisecond * time.Duration(1000*i))
			}

			firstAttempt = false

			if !s.clientActive() {
				if err := s.configureBackgroundClient(); err != nil {
					log.WithFields(log.Fields{
						"error": err,
					}).Error("unable to configure background client")
					return err
				}
			}

			client := s.client

			if err := client.Mail(s.config.Notification.SMTP.Username); err != nil {
				log.WithFields(log.Fields{
					"from":  s.config.Notification.SendFrom,
					"error": err,
				}).Error("unable to set from field")
				continue
			}

			if err := client.Rcpt(recipient); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set to field")
				continue
			}

			w, err := client.Data()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to get data writer")
				continue
			}

			_, err = w.Write([]byte(msg))
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to write message")
				continue
			}

			if err := w.Close(); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to close writer")
				continue
			}

			break
		}
	}

	return nil
}

func (s *Service) SendTemplatedEmail(to string, subject string, header string, message string, buttonText string, buttonUrl string) error {
	b, err := assets.Email.ReadFile("email/default_template.html")
	if err != nil {
		return err
	}

	tmpl, err := template.New("main").Parse(string(b))
	if err != nil {
		return err
	}

	transactionID := uuid.NewString()
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct {
		Header          string
		Message         string
		ButtonText      string
		ButtonURL       string
		TransactionID   string
		TransactionTime string
	}{
		Header:          header,
		Message:         message,
		ButtonText:      buttonText,
		ButtonURL:       buttonUrl,
		TransactionID:   transactionID,
		TransactionTime: time.Now().Format(time.RFC1123),
	}); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"transaction": transactionID,
	}).Info("sending email")

	err = s.sendSMTPEmail([]string{to}, subject, buf.String())
	if err != nil {
		log.WithFields(log.Fields{
			"transaction": transactionID,
			"error":       err,
		}).Error("error sending email")
		return err
	}

	return nil
}
