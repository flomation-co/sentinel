package smtp

import (
	"testing"

	"flomation.app/sentinel/internal/config"
	. "github.com/onsi/gomega"
)

func TestGenericEmail(t *testing.T) {
	RegisterTestingT(t)

	s := New(&config.Config{
		Listener: config.ListenerConfig{
			URL: "localhost",
		},
		Notification: config.NotificationConfig{
			Enabled:  true,
			SendFrom: "Flomation <hello@flomation.co>",
			SMTP: config.SMTPConfig{
				Host:     "smtp-relay.gmail.com",
				Username: "andy@flomation.co",
				Password: "zebg wpjd fnmd yfex",
				Port:     587,
			},
		},
	})

	err := s.SendTemplatedEmail("andy@flomation.co", "Test Email", "Testing Flomation Emails", "This is just a simple test of the Flomation Sentinel Email service - please ignore", "Open", "https://www.flomation.co")
	Expect(err).To(BeNil())
}
