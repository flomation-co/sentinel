package listener

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ssoProviders returns the list of enabled SSO providers (for the login page to render buttons).
func (s *Service) ssoProviders(c *gin.Context) {
	providers := []map[string]string{}
	if s.config.SSO != nil {
		if s.config.SSO.Google != nil && s.config.SSO.Google.Enabled {
			providers = append(providers, map[string]string{
				"id":   "google",
				"name": "Google",
				"url":  fmt.Sprintf("%s/auth/%s", s.config.Listener.URL, "google"),
			})
		}
		if s.config.SSO.Microsoft != nil && s.config.SSO.Microsoft.Enabled {
			providers = append(providers, map[string]string{
				"id":   "microsoft",
				"name": "Microsoft",
				"url":  fmt.Sprintf("%s/auth/%s", s.config.Listener.URL, "microsoft"),
			})
		}
	}
	c.JSON(http.StatusOK, providers)
}

