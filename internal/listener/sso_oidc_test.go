package listener

import (
	"testing"

	"flomation.app/sentinel/internal/config"
)

func TestIsBreakGlassEmail(t *testing.T) {
	s := &Service{config: &config.Config{Security: config.SecurityConfig{
		BreakGlassEmails: []string{"Admin@Flomation.co", " ops@example.com "},
	}}}
	cases := map[string]bool{
		"admin@flomation.co": true,  // case-insensitive
		"ADMIN@FLOMATION.CO": true,
		"ops@example.com":    true, // whitespace-trimmed in config
		"user@flomation.co":  false,
		"":                   false,
	}
	for in, want := range cases {
		if got := s.isBreakGlassEmail(in); got != want {
			t.Errorf("isBreakGlassEmail(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSSODomainFromEmail(t *testing.T) {
	cases := map[string]string{
		"alice@dwp.gov.uk":     "dwp.gov.uk",
		"Bob@DWP.GOV.UK":       "dwp.gov.uk", // lower-cased
		"user@sub.example.com": "sub.example.com",
		"no-at-sign":           "",
		"trailing@":            "",
		"":                     "",
		"a@b@c.com":            "c.com", // last @ wins
	}
	for in, want := range cases {
		if got := ssoDomainFromEmail(in); got != want {
			t.Errorf("ssoDomainFromEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
