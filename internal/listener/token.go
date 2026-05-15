package listener

import (
	"net/http"

	appmetrics "flomation.app/sentinel/internal/metrics"
	"flomation.app/sentinel/internal/session"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type TokenResponse struct {
	Session     string `json:"session"`
	AccessToken string `json:"access_token"`
}

type LoginRequest struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	MFACode  *string `json:"mfa_code,omitempty"`
}

func (s *Service) issueToken(c *gin.Context) {
	var request LoginRequest
	if err := c.BindJSON(&request); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.GetUserByUsernameAndPassword(request.Username, request.Password)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to query database via credentials")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if u == nil {
		appmetrics.LoginFailuresTotal.Inc()
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Check MFA
	mfaEnrolled, _ := s.mfa.IsEnrolled(u.ID)
	if mfaEnrolled {
		if request.MFACode == nil || *request.MFACode == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":        "mfa_required",
				"message":      "Multi-factor authentication code required",
			})
			return
		}

		valid, _ := s.mfa.ValidateCode(u.ID, *request.MFACode)
		if !valid {
			appmetrics.MFAVerificationsTotal.WithLabelValues("failure").Inc()
			appmetrics.LoginFailuresTotal.Inc()
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "mfa_invalid",
				"message": "Invalid MFA code",
			})
			return
		}
		appmetrics.MFAVerificationsTotal.WithLabelValues("success").Inc()
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	sess, err := s.session.StartSession(session.Session{
		UserID:    &u.ID,
		IPAddress: &ip,
		Device:    &ua,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to start session")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	location := ""
	if sess.Location != nil {
		location = *sess.Location
	}
	go s.user.CheckNewDevice(u.ID, ip, ua, location)

	tkn, err := s.token.Create(u.ID, -1)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to create token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	appmetrics.LoginsTotal.Inc()

	c.JSON(http.StatusOK, TokenResponse{
		Session:     sess.ID,
		AccessToken: *tkn,
	})
}
