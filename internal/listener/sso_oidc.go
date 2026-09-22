package listener

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
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

	// Best-effort authorization sync (org membership + group→Team). Never blocks
	// authentication — Sentinel is the auth authority.
	s.syncSSOAuthorization(c.Request.Context(), userID, conn.OrganisationID, claims)

	// A challenged session: the user has just authenticated against their own
	// identity provider, with whatever factors that provider enforces. That is
	// a stronger proof than a password here, not a weaker one.
	if _, err := s.issueChallengedSession(c, userID); err != nil {
		log.WithField("error", err).Error("unable to create JWT")
		c.String(http.StatusInternalServerError, "Authentication failed")
		return
	}

	redirectURL := "/"
	if s.config.Security.LoginRedirect != nil {
		redirectURL = *s.config.Security.LoginRedirect
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// ssoHTTPClient is used for the best-effort Sentinel→API authorization sync.
var ssoHTTPClient = &http.Client{Timeout: 8 * time.Second}

// syncSSOAuthorization pushes the user's org membership and (unless the group
// list is in overage) their group→Team reconciliation to the API. Best-effort:
// authentication is already done and the token is about to be issued, so any
// failure here is logged but never blocks login.
func (s *Service) syncSSOAuthorization(ctx context.Context, userID, orgID string, claims *oidc.Claims) {
	apiURL := s.config.Security.APIURL
	token := s.config.Security.ServiceToken
	if apiURL == "" || token == "" || orgID == "" {
		return
	}
	base := strings.TrimRight(apiURL, "/")

	// 1. Ensure the user is a member of the connection's org.
	s.ssoPost(ctx, base+"/api/v1/sso/ensure-membership", token,
		map[string]interface{}{"user_id": userID, "organisation_id": orgID}, "ensure-membership")

	// 2. Reconcile group→Team membership — ONLY when the group list is
	// authoritative. On overage the token omits groups, so reconciling with an
	// empty list would wrongly strip the user from every mapped Team.
	if claims.GroupsOverage {
		log.Warn("SSO group overage (>200 groups) — group→Team sync skipped; directory/Graph fetch is a follow-up")
		return
	}
	s.ssoPost(ctx, base+"/api/v1/sso/reconcile", token,
		map[string]interface{}{"user_id": userID, "organisation_id": orgID, "idp_groups": claims.Groups}, "reconcile")
}

// ssoPost is a best-effort service-to-service POST used by the auth sync.
func (s *Service) ssoPost(ctx context.Context, url, token string, body interface{}, label string) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		log.WithFields(log.Fields{"error": err, "call": label}).Warn("sso sync: build request")
		return
	}
	req.Header.Set("X-Service-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ssoHTTPClient.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "call": label}).Warn("sso sync: request failed (login unaffected)")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		log.WithFields(log.Fields{"status": resp.StatusCode, "call": label}).Warn("sso sync: non-2xx (login unaffected)")
	}
}

// isOrgAdminBreakGlass asks the API whether the user is an admin of the given
// org. Org admins are exempt from SSO Home Realm Discovery (self-serve
// break-glass) so a broken SSO connection can't lock them out. Best-effort: on
// any error it returns false (fail toward SSO) — SSO being broken doesn't imply
// the API is down, so the common case still resolves.
func (s *Service) isOrgAdminBreakGlass(ctx context.Context, userID, orgID string) bool {
	apiURL := s.config.Security.APIURL
	token := s.config.Security.ServiceToken
	if apiURL == "" || token == "" || userID == "" || orgID == "" {
		return false
	}
	u := strings.TrimRight(apiURL, "/") + "/api/v1/sso/is-org-admin?user_id=" +
		url.QueryEscape(userID) + "&organisation_id=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Service-Token", token)
	resp, err := ssoHTTPClient.Do(req)
	if err != nil {
		log.WithField("error", err).Warn("sso break-glass admin check failed — defaulting to SSO")
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var out struct {
		Admin bool `json:"admin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	return out.Admin
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
