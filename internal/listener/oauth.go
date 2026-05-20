package listener

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

)

// oauthUserInfo holds the profile data extracted from any OAuth provider.
type oauthUserInfo struct {
	ProviderID string
	Email      string
	Name       string
}

// ── Provider-specific profile fetchers ───────────────────────────────

func fetchGoogleProfile(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*oauthUserInfo, error) {
	svc, err := googleapi.NewService(ctx, option.WithTokenSource(cfg.TokenSource(ctx, token)))
	if err != nil {
		return nil, fmt.Errorf("create Google API service: %w", err)
	}
	info, err := svc.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("fetch Google user info: %w", err)
	}
	return &oauthUserInfo{ProviderID: info.Id, Email: info.Email, Name: info.Name}, nil
}

func fetchMicrosoftProfile(ctx context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft graph request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("microsoft graph %d: %s", resp.StatusCode, string(body))
	}

	var profile struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode Microsoft profile: %w", err)
	}

	email := profile.Mail
	if email == "" {
		email = profile.UserPrincipalName
	}

	return &oauthUserInfo{ProviderID: profile.ID, Email: email, Name: profile.DisplayName}, nil
}

func fetchGitHubProfile(ctx context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var profile struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode GitHub profile: %w", err)
	}

	// GitHub may not return email from /user if it's private. Fetch from /user/emails.
	if profile.Email == "" {
		profile.Email, _ = fetchGitHubPrimaryEmail(ctx, token)
	}

	return &oauthUserInfo{
		ProviderID: fmt.Sprintf("%d", profile.ID),
		Email:      profile.Email,
		Name:       profile.Name,
	}, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified primary email")
}

func fetchLinkedInProfile(ctx context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.linkedin.com/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LinkedIn API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LinkedIn API %d: %s", resp.StatusCode, string(body))
	}

	var profile struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode LinkedIn profile: %w", err)
	}

	return &oauthUserInfo{ProviderID: profile.Sub, Email: profile.Email, Name: profile.Name}, nil
}

// ── Provider registry ────────────────────────────────────────────────

type oauthProvider struct {
	Name         string
	Config       func(s *Service) *oauth2.Config
	FetchProfile func(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*oauthUserInfo, error)
	Enabled      func(s *Service) bool
}

var oauthProviders = map[string]oauthProvider{
	"google": {
		Name: "google",
		Config: func(s *Service) *oauth2.Config {
			cfg := s.config.GoogleOAuth
			return &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Scopes:       []string{"openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
				Endpoint:     google.Endpoint,
			}
		},
		FetchProfile: fetchGoogleProfile,
		Enabled:      func(s *Service) bool { return s.config.GoogleOAuth != nil && s.config.GoogleOAuth.ClientID != "" },
	},
	"microsoft": {
		Name: "microsoft",
		Config: func(s *Service) *oauth2.Config {
			cfg := s.config.MicrosoftOAuth
			return &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Scopes:       []string{"openid", "email", "profile", "User.Read"},
				Endpoint: oauth2.Endpoint{ // #nosec G101 -- OAuth endpoint URLs, not credentials
					AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
					TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
				},
			}
		},
		FetchProfile: fetchMicrosoftProfile,
		Enabled:      func(s *Service) bool { return s.config.MicrosoftOAuth != nil && s.config.MicrosoftOAuth.ClientID != "" },
	},
	"github": {
		Name: "github",
		Config: func(s *Service) *oauth2.Config {
			cfg := s.config.GitHubOAuth
			return &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Scopes:       []string{"user:email", "read:user"},
				Endpoint:     github.Endpoint,
			}
		},
		FetchProfile: fetchGitHubProfile,
		Enabled:      func(s *Service) bool { return s.config.GitHubOAuth != nil && s.config.GitHubOAuth.ClientID != "" },
	},
	"linkedin": {
		Name: "linkedin",
		Config: func(s *Service) *oauth2.Config {
			cfg := s.config.LinkedInOAuth
			return &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Scopes:       []string{"openid", "profile", "email"},
				Endpoint: oauth2.Endpoint{ // #nosec G101 -- OAuth endpoint URLs, not credentials
					AuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
					TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
				},
			}
		},
		FetchProfile: fetchLinkedInProfile,
		Enabled:      func(s *Service) bool { return s.config.LinkedInOAuth != nil && s.config.LinkedInOAuth.ClientID != "" },
	},
}

// ── Generic OAuth handlers ───────────────────────────────────────────

func generateOAuthState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// oauthLogin redirects the user to the provider's consent screen.
func (s *Service) oauthLogin(c *gin.Context) {
	providerName := c.Param("provider")
	provider, ok := oauthProviders[providerName]
	if !ok || !provider.Enabled(s) {
		c.String(http.StatusNotFound, "Unknown or unconfigured provider")
		return
	}

	state := generateOAuthState()
	c.SetCookie("oauth_state", state, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)
	c.SetCookie("oauth_provider", providerName, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	url := provider.Config(s).AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// oauthCallback handles the return from any OAuth provider.
func (s *Service) oauthCallback(c *gin.Context) {
	providerName := c.Param("provider")
	provider, ok := oauthProviders[providerName]
	if !ok || !provider.Enabled(s) {
		c.String(http.StatusNotFound, "Unknown or unconfigured provider")
		return
	}

	// Verify state parameter to prevent CSRF.
	storedState, err := c.Cookie("oauth_state")
	if err != nil || storedState == "" || storedState != c.Query("state") {
		log.Warn("OAuth state mismatch")
		c.String(http.StatusBadRequest, "Invalid state parameter")
		return
	}
	c.SetCookie("oauth_state", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)
	c.SetCookie("oauth_provider", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	// Check for error from provider.
	if errMsg := c.Query("error"); errMsg != "" {
		log.WithFields(log.Fields{"error": errMsg, "provider": providerName}).Warn("OAuth error from provider")
		c.Redirect(http.StatusTemporaryRedirect, "/authenticate")
		return
	}

	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Missing authorisation code")
		return
	}

	cfg := provider.Config(s)
	token, err := cfg.Exchange(c.Request.Context(), code)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "provider": providerName}).Error("OAuth code exchange failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Fetch the user profile from the provider.
	userInfo, err := provider.FetchProfile(c.Request.Context(), cfg, token)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "provider": providerName}).Error("unable to fetch user profile")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	if userInfo.Email == "" {
		c.String(http.StatusBadRequest, "No email address returned from provider")
		return
	}

	log.WithFields(log.Fields{
		"email":    userInfo.Email,
		"provider": providerName,
		"id":       userInfo.ProviderID,
	}).Info("OAuth callback")

	// Link or create user — shared logic for all providers.
	userID, err := s.linkOrCreateSSOUser(providerName, userInfo)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "provider": providerName}).Error("SSO user linking failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Issue JWT and set cookie.
	jwtToken, err := s.token.Create(userID, int64(s.config.Security.Cookie.Expiration))
	if err != nil {
		log.WithField("error", err).Error("unable to create JWT")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	c.SetCookie("flomation-token", *jwtToken, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

	redirectURL := "/"
	if s.config.Security.LoginRedirect != nil {
		redirectURL = *s.config.Security.LoginRedirect
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// linkOrCreateSSOUser finds or creates a user for the given SSO identity.
func (s *Service) linkOrCreateSSOUser(provider string, info *oauthUserInfo) (string, error) {
	// Check for existing SSO link.
	ssoAcct, err := s.user.Database().GetSSOAccount(provider, info.ProviderID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("SSO lookup: %w", err)
	}

	if ssoAcct != nil {
		return ssoAcct.UserID, nil
	}

	// No SSO link — check if a user with this email already exists.
	existing, err := s.user.Database().GetUserByUsername(info.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("user lookup: %w", err)
	}

	var userID string
	if existing != nil {
		userID = existing.ID
	} else {
		// Create a new user.
		newUser, err := s.user.RegisterUser(info.Email)
		if err != nil {
			return "", fmt.Errorf("register user: %w", err)
		}
		userID = newUser.ID

		if info.Name != "" {
			_ = s.user.Database().UpdateDisplayName(userID, info.Name)
		}
		_ = s.user.Database().Verify(userID)
	}

	// Create the SSO link.
	if err := s.user.Database().CreateSSOAccount(userID, provider, info.ProviderID, info.Email); err != nil {
		log.WithFields(log.Fields{"error": err, "provider": provider}).Error("unable to create SSO link")
	}

	return userID, nil
}

// EnabledOAuthProviders returns the list of configured provider names for template rendering.
func (s *Service) EnabledOAuthProviders() []string {
	var providers []string
	for name, p := range oauthProviders {
		if p.Enabled(s) {
			providers = append(providers, name)
		}
	}
	return providers
}

// renderOAuthButtons generates the HTML for all enabled OAuth provider buttons.
func (s *Service) renderOAuthButtons() string {
	type btnDef struct {
		Provider string
		Label    string
		Icon     string
	}

	// Ordered list — controls display order on the login page.
	allButtons := []btnDef{
		{Provider: "google", Label: "Continue with Google", Icon: `<svg viewBox="0 0 24 24" width="18" height="18"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>`},
		{Provider: "microsoft", Label: "Continue with Microsoft", Icon: `<svg viewBox="0 0 21 21" width="18" height="18"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>`},
		{Provider: "github", Label: "Continue with GitHub", Icon: `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>`},
		{Provider: "linkedin", Label: "Continue with LinkedIn", Icon: `<svg viewBox="0 0 24 24" width="18" height="18" fill="#0A66C2"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>`},
	}

	var buttons string
	for _, btn := range allButtons {
		p, ok := oauthProviders[btn.Provider]
		if !ok || !p.Enabled(s) {
			continue
		}
		if buttons == "" {
			buttons = `<div class="oauth-divider">or</div>`
		}
		buttons += fmt.Sprintf(`<a href="/auth/%s/login" class="google-btn" style="margin-bottom:6px;">%s %s</a>`, btn.Provider, btn.Icon, btn.Label)
	}

	return buttons
}
