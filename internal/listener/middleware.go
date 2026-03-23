package listener

import (
	"net/http"
	"strings"

	"flomation.app/sentinel/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

const (
	FlomationUserID = "flomation-user-id"
)

func Sentinel(config *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// Try Authorization header first
		header := c.GetHeader("Authorization")
		headerParts := strings.Split(header, " ")
		if len(headerParts) == 2 && headerParts[0] == "Bearer" {
			tokenString = headerParts[1]
		}

		// Fall back to cookie for browser-based access
		if tokenString == "" {
			cookie, err := c.Cookie("flomation-token")
			if err != nil || cookie == "" {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			tokenString = cookie
		}

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return []byte(config.Security.Secret), nil
		})
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to parse jwt")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userID, err := claims.GetSubject()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to get sub")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if userID == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set(FlomationUserID, userID)

		c.Next()
	}
}
