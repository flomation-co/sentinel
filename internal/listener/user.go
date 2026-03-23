package listener

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Service) registerUser(c *gin.Context) {
	var request RegisterRequest
	if err := c.BindJSON(&request); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.RegisterUser(request.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to register user")
		time.Sleep(time.Second * 10)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err = s.user.UpdatePassword(u.ID, request.Password); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to set user password")
		time.Sleep(time.Second * 10)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.Status(http.StatusCreated)
}

func (s *Service) getUser(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userID := v.(string)

	u, err := s.user.GetUserByID(userID)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if u == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":      userID,
		"display_name": u.DisplayName,
	})
}

func (s *Service) getAccount(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userID := v.(string)

	u, err := s.user.GetUserByID(userID)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if u == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	mfaEnabled, _ := s.mfa.IsEnrolled(userID)

	c.JSON(http.StatusOK, gin.H{
		"id":           userID,
		"username":     u.Username,
		"display_name": u.DisplayName,
		"created_on":   u.CreatedAt,
		"locked":       u.Locked,
		"mfa_enabled":  mfaEnabled,
	})
}

type UpdateDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

func (s *Service) updateUser(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userID := v.(string)

	var request UpdateDisplayNameRequest
	if err := c.BindJSON(&request); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to bind json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := s.user.UpdateDisplayName(userID, request.DisplayName); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update display name")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.GetUserByID(userID)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":      userID,
		"display_name": u.DisplayName,
	})
}
