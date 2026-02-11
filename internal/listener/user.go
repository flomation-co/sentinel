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
		"user_id": userID,
	})
}
