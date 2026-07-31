package listener

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"flomation.app/sentinel/internal/oidc"
	"flomation.app/sentinel/internal/persistence"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// SSO cookie names — short-lived, carrying the connection id and the OIDC
// state/nonce/PKCE-verifier across the IdP round-trip. A single fixed callback
// URL (/auth/sso/callback) serves every connection (Entra registers one
// redirect URI); the connection id travels in a cookie, not the path.
const (
	ssoConnCookie     = "sso_conn"
	ssoStateCookie    = "sso_state"
	ssoNonceCookie    = "sso_nonce"
	ssoVerifierCookie = "sso_verifier"
	ssoCookieTTL      = 300
	// Fixed OIDC redirect_uri path. Under /sso/ (not /auth/) with static-first
	// segments so it doesn't collide with the /auth/:provider/* OAuth routes.
	ssoCallbackPath = "/sso/callback"
)

func (s *Service) ssoRedirectURL() string {
	return strings.TrimRight(s.config.Listener.URL, "/") + ssoCallbackPath
}

func (s *Service) setSSOCookie(c *gin.Context, name, value string) {
	c.SetCookie(name, value, ssoCookieTTL, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)
}

func (s *Service) clearSSOCookies(c *gin.Context) {
	for _, n := range []string{ssoConnCookie, ssoStateCookie, ssoNonceCookie, ssoVerifierCookie} {
		c.SetCookie(n, "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)
	}
}

func connToEngine(conn *persistence.SSOConnection) oidc.Connection {
	tenant := ""
	if conn.TenantID != nil {
		tenant = *conn.TenantID
	}
	return oidc.Connection{
		Issuer:       conn.Issuer,
		ClientID:     conn.ClientID,
		ClientSecret: derefStr(conn.ClientSecret),
		TenantID:     tenant,
	}
}

// ssoBegin initiates the OIDC flow for a specific connection. The HRD step in
// the authenticate handler redirects here once it recognises an SSO domain.
func (s *Service) ssoBegin(c *gin.Context) {
	connID := c.Param("connection")
	conn, err := s.user.Database().GetSSOConnectionByID(connID)
	if err != nil || conn == nil || !conn.Enabled {
		c.String(http.StatusNotFound, "Unknown or disabled SSO connection")
		return
	}

	req, err := s.sso.BeginAuth(c.Request.Context(), connToEngine(conn), s.ssoRedirectURL())
	if err != nil {
		log.WithFields(log.Fields{"error": err, "connection": connID}).Error("SSO begin failed")
		c.Redirect(http.StatusTemporaryRedirect, "/authenticate")
		return
	}

	s.setSSOCookie(c, ssoConnCookie, connID)
	s.setSSOCookie(c, ssoStateCookie, req.State)
	s.setSSOCookie(c, ssoNonceCookie, req.Nonce)
	s.setSSOCookie(c, ssoVerifierCookie, req.CodeVerifier)
	c.Redirect(http.StatusTemporaryRedirect, req.AuthURL)
}

// ssoCallback is the fixed OIDC redirect_uri. It validates state, completes the
// flow, JIT-provisions the user (reusing linkOrCreateSSOUser), and issues the
// standard flomation-token — identical to every other login path.
func (s *Service) ssoCallback(c *gin.Context) {
	connID, _ := c.Cookie(ssoConnCookie)
	state, _ := c.Cookie(ssoStateCookie)
	nonce, _ := c.Cookie(ssoNonceCookie)
	verifier, _ := c.Cookie(ssoVerifierCookie)
	s.clearSSOCookies(c)

	if connID == "" || state == "" || state != c.Query("state") {
		log.Warn("SSO state mismatch")
		c.String(http.StatusBadRequest, "Invalid state parameter")
		return
	}
	if errMsg := c.Query("error"); errMsg != "" {
		log.WithField("error", errMsg).Warn("SSO error from IdP")
		c.Redirect(http.StatusTemporaryRedirect, "/authenticate")
		return
	}
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Missing authorisation code")
		return
	}

	conn, err := s.user.Database().GetSSOConnectionByID(connID)
	if err != nil || conn == nil || !conn.Enabled {
		c.String(http.StatusNotFound, "Unknown or disabled SSO connection")
		return
	}

	claims, err := s.sso.Complete(c.Request.Context(), connToEngine(conn), s.ssoRedirectURL(), code, verifier, nonce)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "connection": connID}).Error("SSO completion failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Key the SSO identity on tenant+subject (oid): stable across re-config and
	// unambiguous across Entra tenants. provider stays "oidc" (sso_account.provider
	// is VARCHAR(20)).
	providerUserID := claims.Subject
	if claims.TenantID != "" {
		providerUserID = claims.TenantID + ":" + claims.Subject
	}
	userID, err := s.linkOrCreateSSOUser("oidc", &oauthUserInfo{
		ProviderID: providerUserID,
		Email:      claims.Email,
		Name:       claims.Name,
	}, persistence.UTMParameters{})
	if err != nil {
		log.WithFields(log.Fields{"error": err, "connection": connID}).Error("SSO user linking failed")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Best-effort authorization sync (org membership now, group→Team in Phase 2).
	// Never blocks authentication — Sentinel is the auth authority.
	s.ensureOrgMembership(c.Request.Context(), userID, conn.OrganisationID, claims.Groups)

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

// ssoHTTPClient is used for the best-effort Sentinel→API authorization sync.
var ssoHTTPClient = &http.Client{Timeout: 8 * time.Second}

// ensureOrgMembership tells the API to JIT the SSO user into the connection's
// organisation. Best-effort: authentication is already done and the token is
// about to be issued, so a failure here is logged but never blocks login.
// (groups is unused in Phase 1; Phase 2 adds group→Team reconciliation.)
func (s *Service) ensureOrgMembership(ctx context.Context, userID, orgID string, _ []string) {
	apiURL := s.config.Security.APIURL
	token := s.config.Security.ServiceToken
	if apiURL == "" || token == "" || orgID == "" {
		return
	}
	payload, _ := json.Marshal(map[string]string{"user_id": userID, "organisation_id": orgID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(apiURL, "/")+"/api/v1/sso/ensure-membership", bytes.NewReader(payload))
	if err != nil {
		log.WithField("error", err).Warn("sso ensure-membership: build request")
		return
	}
	req.Header.Set("X-Service-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ssoHTTPClient.Do(req)
	if err != nil {
		log.WithField("error", err).Warn("sso ensure-membership: request failed (login unaffected)")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		log.WithField("status", resp.StatusCode).Warn("sso ensure-membership: non-2xx (login unaffected)")
	}
}

// ssoDomainFromEmail returns the lower-cased domain part of an email, or "".
func ssoDomainFromEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
