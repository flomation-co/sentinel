package listener

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleapi "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func (s *Service) googleOAuthConfig() *oauth2.Config {
	cfg := s.config.GoogleOAuth
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func generateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// googleLogin redirects the user to Google's consent screen.
func (s *Service) googleLogin(c *gin.Context) {
	if s.config.GoogleOAuth == nil || s.config.GoogleOAuth.ClientID == "" {
		c.String(http.StatusNotFound, "Google sign-in is not configured")
		return
	}

	state := generateState()
	c.SetCookie("oauth_state", state, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	url := s.googleOAuthConfig().AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// googleCallback handles the return from Google after consent.
func (s *Service) googleCallback(c *gin.Context) {
	if s.config.GoogleOAuth == nil {
		c.String(http.StatusNotFound, "Google sign-in is not configured")
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

	// Check for error from Google (e.g. user denied consent).
	if errMsg := c.Query("error"); errMsg != "" {
		log.WithField("error", errMsg).Warn("Google OAuth error")
		c.Redirect(http.StatusTemporaryRedirect, "/authenticate")
		return
	}

	// Exchange the authorisation code for tokens.
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Missing authorisation code")
		return
	}

	token, err := s.googleOAuthConfig().Exchange(c.Request.Context(), code)
	if err != nil {
		log.WithField("error", err).Error("OAuth code exchange failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Fetch the user's Google profile.
	svc, err := googleapi.NewService(c.Request.Context(), option.WithTokenSource(s.googleOAuthConfig().TokenSource(c.Request.Context(), token)))
	if err != nil {
		log.WithField("error", err).Error("unable to create Google API service")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	userInfo, err := svc.Userinfo.Get().Do()
	if err != nil {
		log.WithField("error", err).Error("unable to fetch Google user info")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	if userInfo.Email == "" {
		c.String(http.StatusBadRequest, "No email address returned from Google")
		return
	}

	log.WithFields(log.Fields{
		"email":    userInfo.Email,
		"google_id": userInfo.Id,
	}).Info("Google OAuth callback")

	// Look up existing SSO link.
	ssoAcct, err := s.user.Database().GetSSOAccount("google", userInfo.Id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.WithField("error", err).Error("SSO account lookup failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	var userID string

	if ssoAcct != nil {
		// Existing link — use the linked user.
		userID = ssoAcct.UserID
	} else {
		// No SSO link — check if a user with this email already exists.
		existing, err := s.user.Database().GetUserByUsername(userInfo.Email)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.WithField("error", err).Error("user lookup failed")
			c.String(http.StatusInternalServerError, "Authentication failed")
			return
		}

		if existing != nil {
			// Link Google to the existing account.
			userID = existing.ID
		} else {
			// Create a new user (no password — Google-only for now).
			newUser, err := s.user.RegisterUser(userInfo.Email)
			if err != nil {
				log.WithField("error", err).Error("unable to register Google user")
				c.String(http.StatusInternalServerError, "Registration failed")
				return
			}
			userID = newUser.ID

			// Set display name from Google profile.
			if userInfo.Name != "" {
				_ = s.user.Database().UpdateDisplayName(userID, userInfo.Name)
			}

			// Mark user as verified (Google already verified the email).
			_ = s.user.Database().Verify(userID)
		}

		// Create the SSO link.
		if err := s.user.Database().CreateSSOAccount(userID, "google", userInfo.Id, userInfo.Email); err != nil {
			log.WithField("error", err).Error("unable to create SSO account link")
		}
	}

	// Issue JWT and set cookie — same as regular login.
	jwtToken, err := s.token.Create(userID, int64(s.config.Security.Cookie.Expiration))
	if err != nil {
		log.WithField("error", err).Error("unable to create JWT")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	c.SetCookie("flomation-token", *jwtToken, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

	// Redirect to the editor.
	redirectURL := "/"
	if s.config.Security.LoginRedirect != nil {
		redirectURL = *s.config.Security.LoginRedirect
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}
