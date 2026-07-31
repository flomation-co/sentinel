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

// txtVerificationName is the DNS TXT host the customer adds the token under.
const txtVerificationPrefix = "flomation-verification="

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

func (s *Service) adminCreateConnection(c *gin.Context) {
	var body persistence.SSOConnection
	if err := c.BindJSON(&body); err != nil || body.OrganisationID == "" || body.Issuer == "" || body.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organisation_id, issuer and client_id are required"})
		return
	}
	if body.Protocol == "" {
		body.Protocol = "oidc"
	}
	id, err := s.user.Database().CreateSSOConnection(body)
	if err != nil {
		log.WithField("error", err).Error("create sso connection")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (s *Service) adminUpdateConnection(c *gin.Context) {
	var body persistence.SSOConnection
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	body.ID = c.Param("id")
	if err := s.user.Database().UpdateSSOConnection(body); err != nil {
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
		"record_name":        domain,
		"record_value":       txtVerificationPrefix + token,
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

	want := txtVerificationPrefix + d.VerificationToken
	records, lookupErr := net.LookupTXT(d.Domain)
	if lookupErr != nil {
		c.JSON(http.StatusOK, gin.H{"verified": false, "error": "DNS lookup failed"})
		return
	}
	for _, r := range records {
		if strings.TrimSpace(r) == want {
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
