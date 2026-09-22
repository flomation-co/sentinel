package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testKID = "test-kid"

// mockIdP is a minimal OIDC provider: discovery + JWKS + a token endpoint that
// returns a pre-minted, RS256-signed id_token. Enough to exercise the engine's
// verification path (signature/aud/iss/nonce) and tenant pinning end-to-end.
type mockIdP struct {
	server  *httptest.Server
	priv    *rsa.PrivateKey
	idToken string // set per test before calling Complete
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{priv: priv}
	mux := http.NewServeMux()
	m.server = httptest.NewServer(mux)

	issuer := m.server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     testKID,
			Algorithm: "RS256",
			Use:       "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     m.idToken,
		})
	})

	t.Cleanup(m.server.Close)
	return m
}

// mint signs an id_token with the given claims, filling iss/exp/iat defaults.
func (m *mockIdP) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKID),
	)
	if err != nil {
		t.Fatal(err)
	}
	full := map[string]any{
		"iss": m.server.URL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		full[k] = v
	}
	tok, err := jwt.Signed(signer).Claims(full).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func testConn(m *mockIdP, tenant string) Connection {
	return Connection{Issuer: m.server.URL, ClientID: "client-123", ClientSecret: "secret", TenantID: tenant}
}

func TestComplete_ValidToken(t *testing.T) {
	m := newMockIdP(t)
	m.idToken = m.mint(t, map[string]any{
		"aud":   "client-123",
		"nonce": "n-1",
		"oid":   "oid-abc",
		"email": "alice@dwp.gov.uk",
		"name":  "Alice",
		"tid":   "tenant-1",
	})

	claims, err := New().Complete(context.Background(), testConn(m, "tenant-1"), "http://cb", "code", "verifier", "n-1")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if claims.Subject != "oid-abc" || claims.Email != "alice@dwp.gov.uk" || claims.TenantID != "tenant-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestComplete_TenantMismatchRejected(t *testing.T) {
	m := newMockIdP(t)
	m.idToken = m.mint(t, map[string]any{
		"aud": "client-123", "nonce": "n-1", "oid": "x", "email": "e@x.com", "tid": "EVIL-TENANT",
	})
	// Connection pins tenant-1; token carries EVIL-TENANT → must be rejected.
	if _, err := New().Complete(context.Background(), testConn(m, "tenant-1"), "http://cb", "c", "v", "n-1"); err == nil {
		t.Fatal("expected tenant mismatch error, got nil")
	}
}

func TestComplete_NonceMismatchRejected(t *testing.T) {
	m := newMockIdP(t)
	m.idToken = m.mint(t, map[string]any{
		"aud": "client-123", "nonce": "WRONG", "oid": "x", "email": "e@x.com",
	})
	if _, err := New().Complete(context.Background(), testConn(m, ""), "http://cb", "c", "v", "n-1"); err == nil {
		t.Fatal("expected nonce mismatch error, got nil")
	}
}

func TestComplete_WrongAudienceRejected(t *testing.T) {
	m := newMockIdP(t)
	m.idToken = m.mint(t, map[string]any{
		"aud": "someone-else", "nonce": "n-1", "oid": "x", "email": "e@x.com",
	})
	if _, err := New().Complete(context.Background(), testConn(m, ""), "http://cb", "c", "v", "n-1"); err == nil {
		t.Fatal("expected aud mismatch error, got nil")
	}
}
