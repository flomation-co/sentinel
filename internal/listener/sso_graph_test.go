package listener

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"flomation.app/sentinel/internal/persistence"
)

func strptr(s string) *string { return &s }

func TestProviderDetection(t *testing.T) {
	entraTenant := "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name                     string
		conn                     persistence.SSOConnection
		entra, okta, google, any bool
	}{
		{"entra", persistence.SSOConnection{Issuer: "https://login.microsoftonline.com/" + entraTenant + "/v2.0", TenantID: &entraTenant}, true, false, false, true},
		{"entra-no-tenant", persistence.SSOConnection{Issuer: "https://login.microsoftonline.com/x/v2.0"}, false, false, false, false},
		{"okta", persistence.SSOConnection{Issuer: "https://acme.okta.com"}, false, true, false, true},
		{"okta-emea", persistence.SSOConnection{Issuer: "https://acme.okta-emea.com/oauth2/default"}, false, true, false, true},
		{"google", persistence.SSOConnection{Issuer: "https://accounts.google.com"}, false, false, true, true},
		{"generic", persistence.SSOConnection{Issuer: "https://idp.example.com"}, false, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if isEntraConn(&c.conn) != c.entra {
				t.Errorf("isEntraConn = %v, want %v", isEntraConn(&c.conn), c.entra)
			}
			if isOktaConn(&c.conn) != c.okta {
				t.Errorf("isOktaConn = %v, want %v", isOktaConn(&c.conn), c.okta)
			}
			if isGoogleConn(&c.conn) != c.google {
				t.Errorf("isGoogleConn = %v, want %v", isGoogleConn(&c.conn), c.google)
			}
		})
	}
}

func TestSearchDirectoryGroupsUnsupported(t *testing.T) {
	s := &Service{}
	supported, groups, err := s.searchDirectoryGroups(context.Background(), &persistence.SSOConnection{Issuer: "https://idp.example.com"}, "")
	if supported {
		t.Fatal("generic OIDC provider should be unsupported for group search")
	}
	if err != nil || groups != nil {
		t.Fatalf("unsupported provider should return (false, nil, nil), got groups=%v err=%v", groups, err)
	}
}

func TestOrgBaseURL(t *testing.T) {
	got, err := orgBaseURL("https://acme.okta.com/oauth2/default")
	if err != nil || got != "https://acme.okta.com" {
		t.Fatalf("orgBaseURL = %q, %v; want https://acme.okta.com", got, err)
	}
	if _, err := orgBaseURL("not a url"); err == nil {
		t.Fatal("expected error for invalid issuer")
	}
}

// searchOktaGroups uses a plain SSWS-token GET, so we can exercise the whole
// parse path against a mock Okta org (the issuer points at the test server).
func TestSearchOktaGroups(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"id":"00g1","profile":{"name":"Engineering"}},
			{"id":"00g2","profile":{"name":"Sales"}},
			{"id":"00g3","profile":{"name":""}}
		]`))
	}))
	defer srv.Close()

	s := &Service{}
	conn := &persistence.SSOConnection{Issuer: srv.URL, DirectorySecret: strptr("tok-abc")}
	groups, err := s.searchOktaGroups(context.Background(), conn, "eng")
	if err != nil {
		t.Fatalf("searchOktaGroups: %v", err)
	}
	if gotAuth != "SSWS tok-abc" {
		t.Fatalf("expected SSWS auth header, got %q", gotAuth)
	}
	if gotQuery != "eng" {
		t.Fatalf("expected q=eng forwarded, got %q", gotQuery)
	}
	// Okta stores names as ids (its groups claim carries names); blank names dropped.
	if len(groups) != 2 || groups[0].ID != "Engineering" || groups[0].Name != "Engineering" {
		b, _ := json.Marshal(groups)
		t.Fatalf("unexpected groups: %s", b)
	}
}

func TestSearchOktaGroupsRequiresToken(t *testing.T) {
	s := &Service{}
	_, err := s.searchOktaGroups(context.Background(), &persistence.SSOConnection{Issuer: "https://acme.okta.com"}, "")
	if err == nil {
		t.Fatal("expected error when Okta API token is not configured")
	}
}
