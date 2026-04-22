package listener

import (
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func (s *Service) getLoginHistory(c *gin.Context) {
	userID, exists := c.Get(FlomationUserID)
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	entries, err := s.user.GetLoginHistory(userID.(string))
	if err != nil {
		log.WithFields(log.Fields{
			"error":   err,
			"user_id": userID,
		}).Error("unable to fetch login history")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if entries == nil {
		c.JSON(http.StatusOK, []struct{}{})
		return
	}

	c.JSON(http.StatusOK, entries)
}
