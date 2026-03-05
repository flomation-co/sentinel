package smtp

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"flomation.app/sentinel/internal/config"
	. "github.com/onsi/gomega"
)

func TestGenericEmail(t *testing.T) {
	RegisterTestingT(t)

	username := os.Getenv("SENTINEL_TEST_SMTP_USERNAME")
	password := os.Getenv("SENTINEL_TEST_SMTP_PASSWORD")
	sendFrom := os.Getenv("SENTINEL_TEST_SMTP_SEND_FROM")
	host := os.Getenv("SENTINEL_TEST_SMTP_HOST")
	port, _ := strconv.ParseInt(os.Getenv("SENTINEL_TEST_SMTP_PORT"), 10, 64)

	fmt.Printf("User: %v\nPassword: %v\nSend From: %v\nHost: %v\nPort: %v\n", username, password, sendFrom, host, port)

	s := New(&config.Config{
		Listener: config.ListenerConfig{
			URL: "localhost",
		},
		Notification: config.NotificationConfig{
			Enabled:  true,
			SendFrom: sendFrom,
			SMTP: config.SMTPConfig{
				Host:     host,
				Username: username,
				Password: password,
				Port:     port,
			},
		},
	})

	err := s.SendTemplatedEmail("hello@flomation.co", "Test Email", "Testing Flomation Emails", "This is just a simple test of the Flomation Sentinel Email service - please ignore", "Open", "https://www.flomation.co")
	Expect(err).To(BeNil())
}
