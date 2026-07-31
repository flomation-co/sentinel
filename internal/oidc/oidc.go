// Package oidc wraps go-oidc + oauth2 to run an OpenID Connect
// authorization-code + PKCE flow against an enterprise IdP (Microsoft Entra ID
// first). It handles provider discovery (cached per issuer), the authorization
// redirect, code exchange, and id_token verification (signature via JWKS, aud,
// exp, nonce), plus tenant pinning. It is deliberately independent of the
// persistence/listener packages so it can be unit-tested against a mock IdP.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Connection is the minimal IdP configuration the engine needs.
type Connection struct {
	Issuer       string // e.g. https://login.microsoftonline.com/<tenant>/v2.0
	ClientID     string
	ClientSecret string
	TenantID     string // Entra 'tid'; empty = don't pin
}

// AuthRequest is what the caller must stash (in a signed/short-lived cookie)
// between the redirect and the callback.
type AuthRequest struct {
	AuthURL      string
	State        string
	Nonce        string
	CodeVerifier string
}

// Claims are the verified identity claims extracted from the id_token.
type Claims struct {
	Subject  string // 'oid' (preferred, stable) or 'sub'
	Email    string
	Name     string
	TenantID string   // 'tid'
	Groups   []string // 'groups' (may be empty)
	// GroupsOverage is true when the IdP signalled a group-overage (Entra caps
	// groups in the token at ~200 and sets _claim_names instead). Groups is then
	// NOT authoritative — the caller must fetch via the directory API (Graph) or
	// skip group sync rather than treat the user as being in zero groups.
	GroupsOverage bool
}

// Engine caches discovered providers per issuer (discovery is a network call).
type Engine struct {
	mu        sync.Mutex
	providers map[string]*gooidc.Provider
}

func New() *Engine { return &Engine{providers: map[string]*gooidc.Provider{}} }

func (e *Engine) provider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	e.mu.Lock()
	p, ok := e.providers[issuer]
	e.mu.Unlock()
	if ok {
		return p, nil
	}
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", issuer, err)
	}
	e.mu.Lock()
	e.providers[issuer] = p
	e.mu.Unlock()
	return p, nil
}

func (e *Engine) oauthConfig(p *gooidc.Provider, conn Connection, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
	}
}

// BeginAuth builds the authorization redirect with state, nonce and PKCE (S256).
func (e *Engine) BeginAuth(ctx context.Context, conn Connection, redirectURL string) (*AuthRequest, error) {
	p, err := e.provider(ctx, conn.Issuer)
	if err != nil {
		return nil, err
	}
	state := randToken(16)
	nonce := randToken(16)
	verifier := oauth2.GenerateVerifier()

	cfg := e.oauthConfig(p, conn, redirectURL)
	url := cfg.AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return &AuthRequest{AuthURL: url, State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// Complete exchanges the code (with the PKCE verifier), verifies the id_token,
// enforces the nonce, pins the tenant, and returns the claims.
func (e *Engine) Complete(ctx context.Context, conn Connection, redirectURL, code, codeVerifier, expectedNonce string) (*Claims, error) {
	p, err := e.provider(ctx, conn.Issuer)
	if err != nil {
		return nil, err
	}
	cfg := e.oauthConfig(p, conn, redirectURL)

	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}

	verifier := p.Verifier(&gooidc.Config{ClientID: conn.ClientID})
	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("id_token verify: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	var raw struct {
		OID               string            `json:"oid"`
		Sub               string            `json:"sub"`
		Email             string            `json:"email"`
		PreferredUsername string            `json:"preferred_username"`
		Name              string            `json:"name"`
		TID               string            `json:"tid"`
		Groups            []string          `json:"groups"`
		ClaimNames        map[string]string `json:"_claim_names"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	overage := raw.ClaimNames != nil && raw.ClaimNames["groups"] != ""

	// Tenant pinning — reject any token from a different Entra tenant.
	if conn.TenantID != "" && raw.TID != "" && raw.TID != conn.TenantID {
		return nil, fmt.Errorf("tenant mismatch: token tid %q != connection %q", raw.TID, conn.TenantID)
	}

	subject := raw.OID
	if subject == "" {
		subject = raw.Sub
	}
	email := raw.Email
	if email == "" {
		email = raw.PreferredUsername
	}
	if subject == "" || email == "" {
		return nil, fmt.Errorf("id_token missing subject or email")
	}

	return &Claims{
		Subject:       subject,
		Email:         email,
		Name:          raw.Name,
		TenantID:      raw.TID,
		Groups:        raw.Groups,
		GroupsOverage: overage,
	}, nil
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read never fails on supported platforms; fall back to a
		// non-empty value rather than panicking in an auth path.
		return base64.RawURLEncoding.EncodeToString([]byte("fallbackstatevalue"))
	}
	return hex.EncodeToString(b)
}
