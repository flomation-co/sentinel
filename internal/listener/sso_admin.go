package listener

import (
	"net"
	"net/http"
	"strings"

	"flomation.app/sentinel/internal/persistence"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// serviceTokenGuard protects the internal SSO admin API. The main API service
// (the authenticated org-admin front door) presents the shared service token.
// If no token is configured the routes are refused entirely — they must never
// be open.
func (s *Service) serviceTokenGuard(c *gin.Context) {
	want := s.config.Security.ServiceToken
	got := c.GetHeader("X-Service-Token")
	if want == "" || got == "" || got != want {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Next()
}

// txtVerificationHost is the dedicated DNS label the verification TXT record
// lives under — i.e. flomation-verification.<domain> — so it never collides with
// apex records (SPF/DMARC/other verifications) and is easy to add and remove.
const txtVerificationHost = "flomation-verification"

// adminRedirectURI returns the exact OIDC redirect_uri Sentinel will use, so the
// UI can show the customer precisely what to register in their IdP (it must
// match byte-for-byte). Derived from Sentinel's own Listener.URL.
func (s *Service) adminRedirectURI(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"redirect_uri": s.ssoRedirectURL()})
}

// ── Connections ──────────────────────────────────────────────────────

func (s *Service) adminListConnections(c *gin.Context) {
	orgID := c.Query("organisation_id")
	if orgID == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	conns, err := s.user.Database().GetSSOConnectionsForOrg(orgID)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, conns)
}

// connectionInput is the inbound DTO. The storage struct tags ClientSecret
// json:"-" so it never leaks in responses — which also means BindJSON can't read
// it there. Binding through this DTO keeps both properties.
type connectionInput struct {
	OrganisationID string  `json:"organisation_id"`
	Name           *string `json:"name"`
	Protocol       string  `json:"protocol"`
	Issuer         string  `json:"issuer"`
	TenantID       *string `json:"tenant_id"`
	ClientID       string  `json:"client_id"`
	ClientSecret   *string `json:"client_secret"`
	Enabled        bool    `json:"enabled"`
}

func (in connectionInput) toModel() persistence.SSOConnection {
	protocol := in.Protocol
	if protocol == "" {
		protocol = "oidc"
	}
	return persistence.SSOConnection{
		OrganisationID: in.OrganisationID,
		Name:           in.Name,
		Protocol:       protocol,
		Issuer:         in.Issuer,
		TenantID:       in.TenantID,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		Enabled:        in.Enabled,
	}
}

func (s *Service) adminCreateConnection(c *gin.Context) {
	var in connectionInput
	if err := c.BindJSON(&in); err != nil || in.OrganisationID == "" || in.Issuer == "" || in.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organisation_id, issuer and client_id are required"})
		return
	}
	id, err := s.user.Database().CreateSSOConnection(in.toModel())
	if err != nil {
		log.WithField("error", err).Error("create sso connection")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) adminUpdateConnection(c *gin.Context) {
	var in connectionInput
	if err := c.BindJSON(&in); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	conn := in.toModel()
	conn.ID = c.Param("id")
	if err := s.user.Database().UpdateSSOConnection(conn); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Service) adminDeleteConnection(c *gin.Context) {
	orgID := c.Query("organisation_id")
	if err := s.user.Database().DeleteSSOConnection(c.Param("id"), orgID); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

// ── Domains ──────────────────────────────────────────────────────────

func (s *Service) adminListDomains(c *gin.Context) {
	domains, err := s.user.Database().GetSSODomainsForConnection(c.Param("id"))
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, domains)
}

func (s *Service) adminAddDomain(c *gin.Context) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.BindJSON(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	token := generateOAuthState()
	id, err := s.user.Database().AddSSODomain(c.Param("id"), domain, token)
	if err != nil {
		// Most likely the domain is already claimed (unique constraint).
		c.JSON(http.StatusConflict, gin.H{"error": "domain already claimed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":                 id,
		"verification_token": token,
		"record_name":        txtVerificationHost + "." + domain,
		"record_value":       token,
	})
}

// adminVerifyDomain performs the DNS-TXT ownership check. The customer adds a
// TXT record `flomation-verification=<token>` on the domain; we look it up and
// stamp verified_at on a match. Only verified domains route to SSO.
func (s *Service) adminVerifyDomain(c *gin.Context) {
	d, err := s.user.Database().GetSSODomainByID(c.Param("domainId"))
	if err != nil || d == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if d.Verified() {
		c.JSON(http.StatusOK, gin.H{"verified": true})
		return
	}

	records, lookupErr := net.LookupTXT(txtVerificationHost + "." + d.Domain)
	if lookupErr != nil {
		c.JSON(http.StatusOK, gin.H{"verified": false, "error": "DNS lookup failed"})
		return
	}
	for _, r := range records {
		if strings.TrimSpace(r) == d.VerificationToken {
			if err := s.user.Database().MarkSSODomainVerified(d.ID); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			c.JSON(http.StatusOK, gin.H{"verified": true})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"verified": false})
}

func (s *Service) adminDeleteDomain(c *gin.Context) {
	if err := s.user.Database().DeleteSSODomain(c.Param("domainId")); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}
