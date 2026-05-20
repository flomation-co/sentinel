package listener

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	log "github.com/sirupsen/logrus"

	"flomation.app/sentinel/internal/assets"
	"flomation.app/sentinel/internal/passkey"
	"flomation.app/sentinel/internal/persistence"
)

// ── Registration (authenticated) ─────────────────────────────────────

func (s *Service) webauthnRegisterBegin(c *gin.Context) {
	userID, _ := c.Get("userID")
	user, err := s.user.Database().GetUserByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user"})
		return
	}

	opts, session, err := s.passkey.BeginRegistration(user)
	if err != nil {
		log.WithField("error", err).Error("webauthn register begin failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed"})
		return
	}

	// Store session data as a signed cookie for the finish step.
	sessionJSON, _ := json.Marshal(session)
	encoded := base64.StdEncoding.EncodeToString(sessionJSON)
	c.SetCookie("webauthn_session", encoded, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	c.JSON(http.StatusOK, opts)
}

func (s *Service) webauthnRegisterFinish(c *gin.Context) {
	userID, _ := c.Get("userID")
	user, err := s.user.Database().GetUserByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user"})
		return
	}

	sessionCookie, err := c.Cookie("webauthn_session")
	if err != nil || sessionCookie == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing session"})
		return
	}
	c.SetCookie("webauthn_session", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	sessionJSON, err := base64.StdEncoding.DecodeString(sessionCookie)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session"})
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session data"})
		return
	}

	// Parse the attestation response from the request body.
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to read body"})
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(body)))
	if err != nil {
		log.WithField("error", err).Error("webauthn parse attestation failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attestation"})
		return
	}

	cred, err := s.passkey.FinishRegistration(user, session, parsed)
	if err != nil {
		log.WithField("error", err).Error("webauthn register finish failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": "registration verification failed"})
		return
	}

	// Determine a friendly name from the request or default.
	var name *string
	var nameReq struct {
		Name string `json:"name"`
	}
	// Try to get name from query param (set by JS before calling finish).
	if n := c.Query("name"); n != "" {
		name = &n
	} else if err := json.Unmarshal(body, &nameReq); err == nil && nameReq.Name != "" {
		name = &nameReq.Name
	}
	if name == nil {
		defaultName := fmt.Sprintf("Passkey %s", time.Now().Format("02 Jan 2006"))
		name = &defaultName
	}

	// Store the credential.
	dbCred := &persistence.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		AAGUID:         cred.Authenticator.AAGUID,
		SignCount:      cred.Authenticator.SignCount,
		Name:           name,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Transports:     passkey.TransportsToString(cred.Transport),
	}

	if err := s.user.Database().CreateWebAuthnCredential(dbCred); err != nil {
		log.WithField("error", err).Error("unable to store webauthn credential")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to save passkey"})
		return
	}

	log.WithFields(log.Fields{
		"user_id": user.ID,
		"name":    *name,
	}).Info("passkey registered")

	c.JSON(http.StatusOK, gin.H{"status": "ok", "name": *name})
}

// ── Login (unauthenticated — session-based) ──────────────────────────

func (s *Service) webauthnLoginBegin(c *gin.Context) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing session_id"})
		return
	}

	// Get the user from the session.
	userID, err := s.session.GetSessionUserID(req.SessionID)
	if err != nil || userID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session"})
		return
	}

	user, err := s.user.Database().GetUserByID(*userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user"})
		return
	}

	opts, session, err := s.passkey.BeginLogin(user)
	if err != nil {
		log.WithField("error", err).Error("webauthn login begin failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
		return
	}

	sessionJSON, _ := json.Marshal(session)
	encoded := base64.StdEncoding.EncodeToString(sessionJSON)
	c.SetCookie("webauthn_session", encoded, 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	c.JSON(http.StatusOK, opts)
}

func (s *Service) webauthnLoginFinish(c *gin.Context) {
	var req struct {
		SessionID string `json:"session_id"`
	}

	// Read the session ID from a query param (JS sends assertion as body).
	sessionID := c.Query("session_id")
	if sessionID == "" {
		// Try from JSON wrapper.
		if err := c.ShouldBindJSON(&req); err == nil {
			sessionID = req.SessionID
		}
	}
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing session_id"})
		return
	}

	userID, err := s.session.GetSessionUserID(sessionID)
	if err != nil || userID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session"})
		return
	}

	user, err := s.user.Database().GetUserByID(*userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user"})
		return
	}

	sessionCookie, err := c.Cookie("webauthn_session")
	if err != nil || sessionCookie == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing webauthn session"})
		return
	}
	c.SetCookie("webauthn_session", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	sessionJSON, err := base64.StdEncoding.DecodeString(sessionCookie)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session"})
		return
	}

	var waSession webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &waSession); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session data"})
		return
	}

	// Parse the assertion response.
	parsed, err := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if err != nil {
		log.WithField("error", err).Error("webauthn parse assertion failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assertion"})
		return
	}

	_, err = s.passkey.FinishLogin(user, waSession, parsed)
	if err != nil {
		log.WithField("error", err).Error("webauthn login finish failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}

	// Issue JWT.
	jwtToken, err := s.token.Create(user.ID, int64(s.config.Security.Cookie.Expiration))
	if err != nil {
		log.WithField("error", err).Error("unable to create JWT after passkey auth")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token creation failed"})
		return
	}

	c.SetCookie("flomation-token", *jwtToken, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

	redirectURL := "/"
	if s.config.Security.LoginRedirect != nil {
		redirectURL = *s.config.Security.LoginRedirect
	}
	if r, err := s.session.GetSessionRedirectURL(sessionID); err == nil && r != nil && *r != "" {
		redirectURL = *r
	}

	// Mark session complete.
	_ = s.session.UpdateState(sessionID, 100)

	log.WithField("user_id", user.ID).Info("passkey login successful")

	c.JSON(http.StatusOK, gin.H{"status": "ok", "redirect": redirectURL})
}

// ── Management page (authenticated) ──────────────────────────────────

func (s *Service) passkeyManage(c *gin.Context) {
	userID, _ := c.Get("userID")

	creds, err := s.user.Database().GetWebAuthnCredentialsByUserID(userID.(string))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.WithField("error", err).Error("unable to load passkeys")
	}

	// Build credentials JSON for the template.
	type credView struct {
		ID        string  `json:"id"`
		Name      string  `json:"name"`
		CreatedAt string  `json:"created_at"`
		LastUsed  string  `json:"last_used"`
	}

	var credViews []credView
	for _, c := range creds {
		name := "Passkey"
		if c.Name != nil {
			name = *c.Name
		}
		lastUsed := "Never"
		if c.LastUsedAt != nil {
			lastUsed = c.LastUsedAt.Format("02 Jan 2006 15:04")
		}
		credViews = append(credViews, credView{
			ID:        c.ID,
			Name:      name,
			CreatedAt: c.CreatedAt.Format("02 Jan 2006 15:04"),
			LastUsed:  lastUsed,
		})
	}

	credJSON, _ := json.Marshal(credViews)

	// Load management page template.
	tmpl, err := assets.Passkey.ReadFile("passkey/manage.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "Template not found")
		return
	}

	html := strings.ReplaceAll(string(tmpl), "$$CREDENTIALS$$", string(credJSON))
	html = strings.ReplaceAll(html, "$$USER_ID$$", userID.(string))

	c.Data(http.StatusOK, "text/html", []byte(html))
}

func (s *Service) webauthnDeleteCredential(c *gin.Context) {
	userID, _ := c.Get("userID")
	credID := c.Param("id")

	if err := s.user.Database().DeleteWebAuthnCredential(credID, userID.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to delete passkey"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}