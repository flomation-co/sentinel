package listener

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"flomation.app/sentinel/internal/session"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	providerGoogle    = "google"
	providerMicrosoft = "microsoft"

	microsoftAuthURL  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	microsoftTokenURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" // #nosec G101 -- URL template, not credentials
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	msGraphMeURL      = "https://graph.microsoft.com/v1.0/me"
)

func (s *Service) getOAuthConfig(provider string) *oauth2.Config {
	if s.config.SSO == nil {
		return nil
	}

	callbackURL := fmt.Sprintf("%s/auth/%s/callback", s.config.Listener.URL, provider)

	switch provider {
	case providerGoogle:
		if s.config.SSO.Google == nil || !s.config.SSO.Google.Enabled {
			return nil
		}
		return &oauth2.Config{
			ClientID:     s.config.SSO.Google.ClientID,
			ClientSecret: s.config.SSO.Google.ClientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		}

	case providerMicrosoft:
		if s.config.SSO.Microsoft == nil || !s.config.SSO.Microsoft.Enabled {
			return nil
		}
		tenant := s.config.SSO.Microsoft.TenantID
		if tenant == "" {
			tenant = "common"
		}
		return &oauth2.Config{
			ClientID:     s.config.SSO.Microsoft.ClientID,
			ClientSecret: s.config.SSO.Microsoft.ClientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"openid", "email", "profile", "User.Read"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf(microsoftAuthURL, tenant),
				TokenURL: fmt.Sprintf(microsoftTokenURL, tenant),
			},
		}
	}
	return nil
}

func (s *Service) getAllowedDomains(provider string) []string {
	if s.config.SSO == nil {
		return nil
	}
	switch provider {
	case providerGoogle:
		if s.config.SSO.Google != nil {
			return s.config.SSO.Google.AllowedDomains
		}
	case providerMicrosoft:
		if s.config.SSO.Microsoft != nil {
			return s.config.SSO.Microsoft.AllowedDomains
		}
	}
	return nil
}

// ssoRedirect initiates the OAuth flow by redirecting to the provider.
func (s *Service) ssoRedirect(c *gin.Context) {
	provider := c.Param("provider")
	cfg := s.getOAuthConfig(provider)
	if cfg == nil {
		c.String(http.StatusNotFound, "SSO provider not configured")
		return
	}

	state := generateState()

	// Store state in a short-lived cookie for CSRF verification
	c.SetCookie("flomation-sso-state", state, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	// Store redirect URL if provided
	if redirectURL := c.Query("redirect_url"); redirectURL != "" {
		c.SetCookie("flomation-sso-redirect", redirectURL, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)
	}

	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// ssoCallback handles the OAuth callback after the user authenticates with the provider.
func (s *Service) ssoCallback(c *gin.Context) {
	provider := c.Param("provider")
	cfg := s.getOAuthConfig(provider)
	if cfg == nil {
		c.String(http.StatusNotFound, "SSO provider not configured")
		return
	}

	// Verify state
	storedState, err := c.Cookie("flomation-sso-state")
	if err != nil || storedState == "" {
		c.String(http.StatusBadRequest, "Invalid SSO state — please try again")
		return
	}
	if c.Query("state") != storedState {
		c.String(http.StatusBadRequest, "SSO state mismatch — possible CSRF attack")
		return
	}

	// Check for errors from the provider
	if errCode := c.Query("error"); errCode != "" {
		log.WithFields(log.Fields{
			"provider": provider,
			"error":    errCode,
			"desc":     c.Query("error_description"),
		}).Warn("SSO provider returned error")
		c.String(http.StatusBadRequest, "Authentication failed: %s", c.Query("error_description"))
		return
	}

	// Exchange code for token
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "No authorisation code received")
		return
	}

	token, err := cfg.Exchange(c.Request.Context(), code)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": provider,
			"error":    err,
		}).Error("SSO token exchange failed")
		c.String(http.StatusBadRequest, "Failed to exchange authorisation code")
		return
	}

	// Extract user info from the provider
	email, providerUserID, displayName, err := s.extractUserInfo(provider, token, cfg)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": provider,
			"error":    err,
		}).Error("SSO user info extraction failed")
		c.String(http.StatusBadRequest, "Failed to retrieve user information")
		return
	}

	// Check allowed domains
	if domains := s.getAllowedDomains(provider); len(domains) > 0 {
		parts := strings.SplitN(email, "@", 2)
		if len(parts) != 2 {
			c.String(http.StatusForbidden, "Invalid email address")
			return
		}
		domain := strings.ToLower(parts[1])
		allowed := false
		for _, d := range domains {
			if strings.EqualFold(d, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			c.String(http.StatusForbidden, "Your email domain is not permitted to sign in via SSO")
			return
		}
	}

	// Look up existing SSO link
	ssoAccount, err := s.user.FindSSOAccount(provider, providerUserID)
	if err != nil {
		log.WithError(err).Error("SSO account lookup failed")
		c.String(http.StatusInternalServerError, "Internal error")
		return
	}

	var userID string

	if ssoAccount != nil {
		// Existing SSO link — use the linked user
		userID = ssoAccount.UserID
	} else {
		// No SSO link — check if a user with this email already exists
		existingUser, err := s.user.GetUserByUsername(email)
		if err != nil {
			log.WithError(err).Error("SSO user lookup failed")
			c.String(http.StatusInternalServerError, "Internal error")
			return
		}

		if existingUser != nil {
			// User exists — link the SSO account
			userID = existingUser.ID
		} else {
			// New user — auto-register (no password)
			newUser, err := s.user.RegisterUserSSO(email, displayName)
			if err != nil {
				log.WithError(err).Error("SSO user registration failed")
				c.String(http.StatusInternalServerError, "Failed to create account")
				return
			}
			userID = newUser.ID
		}

		// Create the SSO account link
		if err := s.user.LinkSSOAccount(userID, provider, providerUserID, email); err != nil {
			log.WithError(err).Warn("failed to link SSO account")
		}
	}

	// Create session and issue JWT
	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	sess, err := s.session.StartSession(session.Session{
		UserID:    &userID,
		IPAddress: &ip,
		Device:    &ua,
	})
	if err != nil {
		log.WithError(err).Error("SSO session creation failed")
		c.String(http.StatusInternalServerError, "Failed to create session")
		return
	}

	if err := s.session.UpdateState(sess.ID, session.StateComplete); err != nil {
		log.WithError(err).Error("SSO session state update failed")
	}

	jwtToken, err := s.token.Create(userID, int64(s.config.Security.Cookie.Expiration))
	if err != nil {
		log.WithError(err).Error("SSO JWT creation failed")
		c.String(http.StatusInternalServerError, "Failed to create session token")
		return
	}

	c.SetCookie("flomation-token", *jwtToken, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

	// Check new device
	s.checkNewDeviceFromContext(c, userID)

	// Redirect
	redirectURL := s.config.Listener.URL
	if s.config.Security.LoginRedirect != nil {
		redirectURL = *s.config.Security.LoginRedirect
	}
	if savedRedirect, err := c.Cookie("flomation-sso-redirect"); err == nil && savedRedirect != "" {
		redirectURL = savedRedirect
	}

	log.WithFields(log.Fields{
		"provider": provider,
		"user_id":  userID,
		"email":    email,
	}).Info("SSO login successful")

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// extractUserInfo gets the user's email, provider ID, and display name from the OAuth token.
func (s *Service) extractUserInfo(provider string, token *oauth2.Token, cfg *oauth2.Config) (email, providerUserID, displayName string, err error) {
	switch provider {
	case providerGoogle:
		return s.extractGoogleUserInfo(token, cfg)
	case providerMicrosoft:
		return s.extractMicrosoftUserInfo(token)
	default:
		return "", "", "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *Service) extractGoogleUserInfo(token *oauth2.Token, cfg *oauth2.Config) (string, string, string, error) {
	// Try ID token first (faster, no extra API call)
	if idTokenStr, ok := token.Extra("id_token").(string); ok && idTokenStr != "" {
		// Parse without verification (we trust Google issued it via the OAuth flow)
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		claims := jwt.MapClaims{}
		_, _, err := parser.ParseUnverified(idTokenStr, claims)
		if err == nil {
			email, _ := claims["email"].(string)
			sub, _ := claims["sub"].(string)
			name, _ := claims["name"].(string)
			if email != "" && sub != "" {
				return email, sub, name, nil
			}
		}
	}

	// Fallback: call userinfo endpoint
	client := cfg.Client(context.Background(), token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return "", "", "", fmt.Errorf("google userinfo request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var info struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "", "", fmt.Errorf("google userinfo parse failed: %w", err)
	}
	return info.Email, info.Sub, info.Name, nil
}

func (s *Service) extractMicrosoftUserInfo(token *oauth2.Token) (string, string, string, error) {
	req, err := http.NewRequest(http.MethodGet, msGraphMeURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("microsoft graph request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var info struct {
		ID          string `json:"id"`
		Mail        string `json:"mail"`
		UPN         string `json:"userPrincipalName"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "", "", fmt.Errorf("microsoft graph parse failed: %w", err)
	}

	email := info.Mail
	if email == "" {
		email = info.UPN
	}
	return email, info.ID, info.DisplayName, nil
}

// ssoProviders returns the list of enabled SSO providers (for the login page to render buttons).
func (s *Service) ssoProviders(c *gin.Context) {
	providers := []map[string]string{}
	if s.config.SSO != nil {
		if s.config.SSO.Google != nil && s.config.SSO.Google.Enabled {
			providers = append(providers, map[string]string{
				"id":   providerGoogle,
				"name": "Google",
				"url":  fmt.Sprintf("%s/auth/%s", s.config.Listener.URL, providerGoogle),
			})
		}
		if s.config.SSO.Microsoft != nil && s.config.SSO.Microsoft.Enabled {
			providers = append(providers, map[string]string{
				"id":   providerMicrosoft,
				"name": "Microsoft",
				"url":  fmt.Sprintf("%s/auth/%s", s.config.Listener.URL, providerMicrosoft),
			})
		}
	}
	c.JSON(http.StatusOK, providers)
}

func generateState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

