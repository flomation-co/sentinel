package listener

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"flomation.app/sentinel/internal/config"
)

// isOrgAdminBreakGlass is API-backed; test it against a mock API that returns a
// canned admin verdict and asserts the service token is presented.
func TestIsOrgAdminBreakGlass(t *testing.T) {
	var gotToken string
	var admin bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Service-Token")
		w.Header().Set("Content-Type", "application/json")
		if admin {
			_, _ = w.Write([]byte(`{"admin":true}`))
		} else {
			_, _ = w.Write([]byte(`{"admin":false}`))
		}
	}))
	defer srv.Close()

	s := &Service{config: &config.Config{Security: config.SecurityConfig{
		APIURL: srv.URL, ServiceToken: "secret-123",
	}}}

	admin = true
	if !s.isOrgAdminBreakGlass(context.Background(), "user-1", "org-1") {
		t.Fatal("expected admin=true to grant break-glass")
	}
	if gotToken != "secret-123" {
		t.Fatalf("service token not presented, got %q", gotToken)
	}

	admin = false
	if s.isOrgAdminBreakGlass(context.Background(), "user-1", "org-1") {
		t.Fatal("expected admin=false to deny break-glass")
	}

	// Not configured → never break-glass.
	empty := &Service{config: &config.Config{}}
	if empty.isOrgAdminBreakGlass(context.Background(), "u", "o") {
		t.Fatal("unconfigured should not break-glass")
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
