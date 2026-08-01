package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"flomation.app/sentinel/internal/persistence"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jwt"
)

// idpGroup is a directory group surfaced to the mapping UI: the stable id (what
// the token's groups claim carries) plus a human name to show.
type idpGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// directoryHTTP is the shared client for provider directory calls (Okta/Google
// oauth2 clients wrap their own transport; this is used for the raw Okta call).
var directoryHTTP = &http.Client{Timeout: 15 * time.Second}

// searchDirectoryGroups dispatches to the provider's directory API. supported is
// false for providers we can't query (generic OIDC), so the UI keeps free-text
// entry. A non-nil err means the provider is supported but the lookup failed
// (missing credentials / permissions) — also a signal to fall back to text.
func (s *Service) searchDirectoryGroups(ctx context.Context, conn *persistence.SSOConnection, q string) (bool, []idpGroup, error) {
	switch {
	case isEntraConn(conn):
		g, err := s.searchEntraGroups(ctx, conn, q)
		return true, g, err
	case isOktaConn(conn):
		g, err := s.searchOktaGroups(ctx, conn, q)
		return true, g, err
	case isGoogleConn(conn):
		g, err := s.searchGoogleGroups(ctx, conn, q)
		return true, g, err
	default:
		return false, nil, nil
	}
}

// ── Entra (Microsoft Graph) ──────────────────────────────────────────
// Reuses the OIDC client id/secret (client-credentials). Needs Group.Read.All
// (or Directory.Read.All) application permission with admin consent.

func isEntraConn(c *persistence.SSOConnection) bool {
	return c.TenantID != nil && *c.TenantID != "" && strings.Contains(strings.ToLower(c.Issuer), "microsoftonline")
}

func (s *Service) searchEntraGroups(ctx context.Context, conn *persistence.SSOConnection, q string) ([]idpGroup, error) {
	tenant := *conn.TenantID
	cc := &clientcredentials.Config{
		ClientID:     conn.ClientID,
		ClientSecret: derefStr(conn.ClientSecret),
		TokenURL:     "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
	client := cc.Client(ctx)

	graphURL := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName&$top=25&$orderby=displayName"
	if strings.TrimSpace(q) != "" {
		graphURL = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName&$top=25&$filter=" +
			url.QueryEscape("startswith(displayName,'"+strings.ReplaceAll(q, "'", "''")+"')")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, graphError("graph groups", resp)
	}

	var out struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// Entra's groups claim carries object ids, so store the id and show the name.
	groups := make([]idpGroup, 0, len(out.Value))
	for _, g := range out.Value {
		groups = append(groups, idpGroup{ID: g.ID, Name: g.DisplayName})
	}
	return groups, nil
}

// ── Okta ─────────────────────────────────────────────────────────────
// Okta's management API needs an SSWS API token (DirectorySecret), separate from
// the OIDC client secret. Okta's groups claim carries group NAMES by default, so
// store the name as the id.

func isOktaConn(c *persistence.SSOConnection) bool {
	iss := strings.ToLower(c.Issuer)
	return strings.Contains(iss, ".okta.com") || strings.Contains(iss, ".oktapreview.com") || strings.Contains(iss, ".okta-emea.com")
}

func (s *Service) searchOktaGroups(ctx context.Context, conn *persistence.SSOConnection, q string) ([]idpGroup, error) {
	token := derefStr(conn.DirectorySecret)
	if token == "" {
		return nil, fmt.Errorf("okta API token not configured")
	}
	base, err := orgBaseURL(conn.Issuer)
	if err != nil {
		return nil, err
	}
	oktaURL := base + "/api/v1/groups?limit=25"
	if strings.TrimSpace(q) != "" {
		oktaURL += "&q=" + url.QueryEscape(q)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oktaURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := directoryHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, graphError("okta groups", resp)
	}

	var arr []struct {
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		return nil, err
	}
	groups := make([]idpGroup, 0, len(arr))
	for _, g := range arr {
		if g.Profile.Name == "" {
			continue
		}
		groups = append(groups, idpGroup{ID: g.Profile.Name, Name: g.Profile.Name})
	}
	return groups, nil
}

// ── Google Workspace (Admin SDK Directory) ───────────────────────────
// Needs a service-account JSON (DirectorySecret) with domain-wide delegation and
// an admin email to impersonate (DirectoryAdmin). Uses the group email as the id.

func isGoogleConn(c *persistence.SSOConnection) bool {
	return strings.Contains(strings.ToLower(c.Issuer), "accounts.google.com")
}

func (s *Service) searchGoogleGroups(ctx context.Context, conn *persistence.SSOConnection, q string) ([]idpGroup, error) {
	saJSON := derefStr(conn.DirectorySecret)
	admin := derefStr(conn.DirectoryAdmin)
	if saJSON == "" || admin == "" {
		return nil, fmt.Errorf("google service account / admin email not configured")
	}

	var sa struct {
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return nil, fmt.Errorf("invalid service account JSON: %w", err)
	}
	if sa.TokenURI == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("service account JSON is missing token_uri, client_email or private_key")
	}
	cfg := &jwt.Config{
		Email:        sa.ClientEmail,
		PrivateKey:   []byte(sa.PrivateKey),
		PrivateKeyID: sa.PrivateKeyID,
		TokenURL:     sa.TokenURI,
		Scopes:       []string{"https://www.googleapis.com/auth/admin.directory.group.readonly"},
		Subject:      admin, // domain-wide delegation impersonates an admin
	}
	client := cfg.Client(ctx)

	googleURL := "https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer&maxResults=25"
	if strings.TrimSpace(q) != "" {
		googleURL += "&query=" + url.QueryEscape("name:'"+strings.ReplaceAll(q, "'", "")+"*'")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, graphError("google groups", resp)
	}

	var out struct {
		Groups []struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	groups := make([]idpGroup, 0, len(out.Groups))
	for _, g := range out.Groups {
		name := g.Name
		if name == "" {
			name = g.Email
		}
		groups = append(groups, idpGroup{ID: g.Email, Name: name})
	}
	return groups, nil
}

// ── helpers ──────────────────────────────────────────────────────────

// orgBaseURL returns scheme://host from an issuer (Okta issuers may carry an
// /oauth2/... path we must strip for the management API).
func orgBaseURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid issuer URL %q", issuer)
	}
	return u.Scheme + "://" + u.Host, nil
}

func graphError(label string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("%s %d: %s", label, resp.StatusCode, string(b))
}

// adminSearchGroups is the internal admin endpoint the API forwards to. Returns
// {supported, groups, error}: supported=false for providers we can't enumerate
// (the UI then keeps free-text entry); a populated error means supported but the
// lookup failed (credentials/permissions).
func (s *Service) adminSearchGroups(c *gin.Context) {
	conn, err := s.user.Database().GetSSOConnectionByID(c.Param("id"))
	if err != nil || conn == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	supported, groups, err := s.searchDirectoryGroups(c.Request.Context(), conn, c.Query("q"))
	if !supported {
		c.JSON(http.StatusOK, gin.H{"supported": false, "groups": []idpGroup{}})
		return
	}
	if err != nil {
		log.WithField("error", err).Warn("sso group search failed")
		c.JSON(http.StatusOK, gin.H{
			"supported": true,
			"groups":    []idpGroup{},
			"error":     directorySearchHint(conn),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"supported": true, "groups": groups})
}

// directorySearchHint gives the admin an actionable message for a failed lookup.
func directorySearchHint(conn *persistence.SSOConnection) string {
	switch {
	case isEntraConn(conn):
		return "Group search failed — ensure the app has Group.Read.All application permission with admin consent."
	case isOktaConn(conn):
		return "Group search failed — check the Okta API token has permission to read groups."
	case isGoogleConn(conn):
		return "Group search failed — check the service account has domain-wide delegation for admin.directory.group.readonly and the admin email is correct."
	default:
		return "Group search is not available for this provider — enter the group manually."
	}
}
