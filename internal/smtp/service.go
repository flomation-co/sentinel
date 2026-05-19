package smtp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"flomation.app/sentinel/internal/assets"
	"github.com/google/uuid"

	"flomation.app/sentinel/internal/config"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	config  *config.Config
	enabled bool

	mu     sync.Mutex
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

func (s *Service) connect() error {
	// Close any existing connection.
	if s.client != nil {
		_ = s.client.Quit()
		s.client = nil
	}

	host := s.config.Notification.SMTP.Host
	serverName := fmt.Sprintf("%v:%v", host, s.config.Notification.SMTP.Port)

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
		_ = client.Close()
		return err
	}

	if ok, _ := client.Extension("STARTTLS"); ok {
		cfg := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
		if err = client.StartTLS(cfg); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to start tls")
			_ = client.Close()
			return err
		}
	}

	if err := client.Auth(auth); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to auth")
		_ = client.Close()
		return err
	}

	s.client = client
	return nil
}

// ensureClient returns a usable SMTP client, reconnecting if necessary.
func (s *Service) ensureClient() (*smtp.Client, error) {
	if s.clientActive() {
		return s.client, nil
	}
	if err := s.connect(); err != nil {
		return nil, err
	}
	return s.client, nil
}

// envelopeSender extracts the bare email address from the configured
// SendFrom field (e.g. "Flomation <noreply@example.com>" → "noreply@example.com").
// SES requires the MAIL FROM to be a verified email address, not the
// SMTP username (which is an IAM access key).
func (s *Service) envelopeSender() string {
	from := s.config.Notification.SendFrom
	if idx := strings.Index(from, "<"); idx >= 0 {
		from = strings.TrimSuffix(from[idx+1:], ">")
	}
	from = strings.TrimSpace(from)
	if from != "" {
		return from
	}
	return s.config.Notification.SMTP.Username
}

func (s *Service) sendSMTPEmail(recipients []string, subject string, body string) error {
	if s.config.Notification.OverrideDestination != nil {
		recipients = []string{
			*s.config.Notification.OverrideDestination,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	mailFrom := s.envelopeSender()

	for _, addr := range recipients {
		recipient := strings.TrimSuffix(strings.TrimPrefix(addr, " "), " ")
		msg := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\nMIME-Version: 1.0\nContent-Type: text/html; charset=\"UTF-8\";\n\n%v\n\n", s.config.Notification.SendFrom, recipient, subject, body)

		var lastErr error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Second * time.Duration(attempt))
			}

			client, err := s.ensureClient()
			if err != nil {
				log.WithFields(log.Fields{
					"error":   err,
					"attempt": attempt + 1,
				}).Error("unable to get SMTP client")
				lastErr = err
				continue
			}

			if err := client.Mail(mailFrom); err != nil {
				log.WithFields(log.Fields{
					"from":    mailFrom,
					"error":   err,
					"attempt": attempt + 1,
				}).Warn("MAIL FROM failed, reconnecting")
				// Reset or reconnect — the connection is in a dirty state.
				if resetErr := client.Reset(); resetErr != nil {
					_ = client.Quit()
					s.client = nil
				}
				lastErr = err
				continue
			}

			if err := client.Rcpt(recipient); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set to field")
				_ = client.Reset()
				lastErr = err
				continue
			}

			w, err := client.Data()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to get data writer")
				_ = client.Reset()
				lastErr = err
				continue
			}

			if _, err = w.Write([]byte(msg)); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to write message")
				_ = client.Reset()
				lastErr = err
				continue
			}

			if err := w.Close(); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to close writer")
				_ = client.Reset()
				lastErr = err
				continue
			}

			lastErr = nil
			break
		}

		if lastErr != nil {
			return fmt.Errorf("failed to send to %s after 3 attempts: %w", recipient, lastErr)
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
		Message         template.HTML
		ButtonText      string
		ButtonURL       string
		TransactionID   string
		TransactionTime string
	}{
		Header:          header,
		Message:         template.HTML(message), // #nosec G203 -- caller-controlled content, not user input
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
