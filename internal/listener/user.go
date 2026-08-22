package listener

import (
	"net/http"
	"time"

	"flomation.app/sentinel/internal/persistence"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type RegisterRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	UTMSource   string `json:"utm_source,omitempty"`
	UTMMedium   string `json:"utm_medium,omitempty"`
	UTMCampaign string `json:"utm_campaign,omitempty"`
	UTMTerm     string `json:"utm_term,omitempty"`
	UTMContent  string `json:"utm_content,omitempty"`
	UTMReferrer string `json:"utm_referrer,omitempty"`

	// MarketingOptIn is the caller's assertion that the user agreed to
	// marketing email. Callers that did not ask should omit it, which records
	// the user as unasked rather than as having refused.
	MarketingOptIn bool `json:"marketing_opt_in,omitempty"`
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

	utm := persistence.UTMParameters{
		Source:   request.UTMSource,
		Medium:   request.UTMMedium,
		Campaign: request.UTMCampaign,
		Term:     request.UTMTerm,
		Content:  request.UTMContent,
		Referrer: request.UTMReferrer,
	}

	consent := persistence.MarketingConsent{
		OptIn:   request.MarketingOptIn,
		Source:  persistence.MarketingConsentSourceRegistrationAPI,
		Version: persistence.MarketingConsentWordingSignupV1,
	}

	u, err := s.user.RegisterUser(request.Username, utm, consent)
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

	// The marketing consent decision is surfaced so the product can seed its
	// own copy when it first provisions the account, rather than asking a
	// second time for something the user already answered at sign-up.
	c.JSON(http.StatusOK, gin.H{
		"id":                        userID,
		"username":                  u.Username,
		"display_name":              u.DisplayName,
		"created_on":                u.CreatedAt,
		"locked":                    u.Locked,
		"mfa_enabled":               mfaEnabled,
		"marketing_opt_in":          u.MarketingOptIn,
		"marketing_consent_at":      u.MarketingConsentAt,
		"marketing_consent_source":  u.MarketingConsentSource,
		"marketing_consent_version": u.MarketingConsentVersion,
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
