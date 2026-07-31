package listener

import "testing"

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
