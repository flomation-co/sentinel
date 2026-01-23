package listener

import (
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (s *Service) issueToken(c *gin.Context) {
	tkn, err := s.security.Create("test@flomation.co", -1)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to create token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: *tkn,
	})
}
