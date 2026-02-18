package listener

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"flomation.app/sentinel/internal/security"

	"flomation.app/sentinel/internal/assets"
	"flomation.app/sentinel/internal/session"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	fragmentEnterEmailAddress         = "email_address"
	fragmentRegister                  = "register"
	fragmentPassword                  = "password"
	fragmentPasswordError             = "password_error"
	fragmentSubmitPassword            = "submit_password"
	fragmentSetPassword               = "set_new_password"
	fragmentForgottenPassword         = "forgot_password"
	fragmentSubmitForgottenPassword   = "submit_forgot_password"
	fragmentForgottenPasswordComplete = "forgot_password_complete"
)

func (s *Service) staticAssets(c *gin.Context) {
	path := c.Request.URL.Path
	if !strings.HasPrefix(path, "/assets") {
		c.Status(http.StatusNotFound)
		return
	}

	fileName := "static/" + strings.TrimPrefix(path, "/assets/")
	b, err := assets.Static.ReadFile(fileName)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"filename": fileName,
		}).Error("unable to read file")
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	c.Data(http.StatusOK, http.DetectContentType(b), b)
}

func (s *Service) setPassword(c *gin.Context) {
	sessionID := c.DefaultPostForm("session", "")
	password := c.DefaultPostForm("new-password", "")

	state, err := s.session.GetSessionState(sessionID)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get session state")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if state != session.StateSetPassword {
		log.WithFields(log.Fields{
			"state": state,
		}).Error("session incorrect state for password reset")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userID, err := s.session.GetSessionUserID(sessionID)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get session username")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := s.user.UpdatePassword(*userID, password); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update password")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	url := "https://www.google.com"
	if s.config.Security.LoginRedirect != nil {
		url = *s.config.Security.LoginRedirect
	}

	c.Redirect(http.StatusFound, url)
}

func (s *Service) resetPassword(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.GetUserByPasswordToken(token)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get user by password token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if u == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	sess, err := s.session.StartSession(session.Session{
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

	if err := s.session.UpdateState(sess.ID, session.StateSetPassword); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update session")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := s.session.SetSessionUserID(sess.ID, u.ID); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to set session user id")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	content, err := s.loadHTMLFragment("set_password")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to load html fragment")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	value := strings.ReplaceAll(*content, "$$USER$$", u.Username)
	value = strings.ReplaceAll(value, "$$SESSION_ID$$", sess.ID)

	c.Data(http.StatusOK, "text/html", []byte(value))
}

func (s *Service) verifyUser(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.GetUserByVerificationToken(token)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get user by verification token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if u == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := s.user.Verify(u.ID); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to verify user")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()

	sess, err := s.session.StartSession(session.Session{
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

	if err := s.session.UpdateState(sess.ID, session.StateSetPassword); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update session")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := s.session.SetSessionUserID(sess.ID, u.ID); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to set session user id")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	content, err := s.loadHTMLFragment("set_password")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to load html fragment")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	value := strings.ReplaceAll(*content, "$$USER$$", u.Username)
	value = strings.ReplaceAll(value, "$$SESSION_ID$$", sess.ID)

	c.Data(http.StatusOK, "text/html", []byte(value))
}

func (s *Service) authenticate(c *gin.Context) {
	sessionID := c.DefaultPostForm("session", "")
	email := c.DefaultPostForm("email_address", "")

	if sessionID == "" {
		ip := c.ClientIP()
		ua := c.Request.UserAgent()

		newSession, err := s.session.StartSession(session.Session{
			IPAddress: &ip,
			Device:    &ua,
			Metadata: struct {
				UTMSource   string `json:"utm_source,omitempty"`
				UTMMedium   string `json:"utm_medium,omitempty"`
				UTMCampaign string `json:"utm_campaign,omitempty"`
				UTMContent  string `json:"utm_content,omitempty"`
				UTMTerm     string `json:"utm_term,omitempty"`
				RedirectURL string `json:"redirect_url,omitempty"`
			}{
				UTMSource:   c.Query("utm_source"),
				UTMMedium:   c.Query("utm_medium"),
				UTMCampaign: c.Query("utm_campaign"),
				UTMContent:  c.Query("utm_content"),
				UTMTerm:     c.Query("utm_term"),
				RedirectURL: c.Query("redirect_url"),
			},
		})
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to start new session")
			c.AbortWithStatus(http.StatusOK)
			return
		}

		sessionID = newSession.ID
		c.SetCookie("flomation-sentinel-session-id", sessionID, 0, "/", c.Request.URL.Host, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
	}

	sessionState, err := s.session.GetSessionState(sessionID)
	if err != nil {
		log.WithFields(log.Fields{
			"error":      err,
			"session_id": sessionID,
		}).Error("unable to get session state")
	}
	formState := c.DefaultPostForm("form_state", "")

	if err := s.validateState(formState, sessionState); err != nil {
		// Invalid session state - reset to beginning
		if err := s.session.UpdateState(sessionID, session.StateNew); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
	}

	fragment := fragmentEnterEmailAddress

	switch formState {
	case fragmentEnterEmailAddress:
		u, err := s.user.GetUserByUsername(email)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if u == nil {
			fragment = fragmentRegister
		} else {
			if err := s.session.UpdateState(sessionID, session.StateDoneIdentity); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set session state")
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := s.session.SetSessionUserID(sessionID, u.ID); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set session user id")
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			fragment = fragmentPassword
		}
	case fragmentRegister:
		u, err := s.user.RegisterUser(email)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to register user")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if err := s.session.UpdateState(sessionID, session.StateDoneIdentity); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to set session state")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if err := s.session.SetSessionUserID(sessionID, u.ID); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to set session user id")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		token, err := s.token.Create(u.ID, int64(s.config.Security.Cookie.Expiration))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.SetCookie("flomation-token", *token, security.DefaultTokenExpirationSeconds, "/", c.Request.URL.Host, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			fragment = fragmentPasswordError
			break
		}

		url := "https://www.google.com"
		if s.config.Security.LoginRedirect != nil {
			url = *s.config.Security.LoginRedirect
		}

		c.Redirect(http.StatusFound, url)
		return

	case fragmentSubmitPassword:
		password := c.DefaultPostForm("current-password", "")
		username, err := s.session.GetSessionUsername(sessionID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to get session username")
			fragment = fragmentPasswordError
			break
		}

		if username == nil {
			fragment = fragmentPasswordError
			break
		}

		userID, err := s.session.GetSessionUserID(sessionID)
		if err != nil {
			fragment = fragmentPasswordError
			break
		}

		u, err := s.user.GetUserByUsernameAndPassword(*username, password)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to get session username")
			fragment = fragmentPasswordError
			break
		}

		if u == nil {
			log.WithFields(log.Fields{
				"username": *username,
			}).Error("invalid password")
			if err := s.user.UpdateFailedAttempts(*userID); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to update failed attempts")
			}
			fragment = fragmentPasswordError
			break
		}

		if err := s.session.UpdateState(sessionID, session.StateComplete); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to set session state")
			fragment = fragmentPasswordError
			break
		}

		token, err := s.token.Create(u.ID, int64(s.config.Security.Cookie.Expiration))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			fragment = fragmentPasswordError
			break
		}

		c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", c.Request.URL.Host, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			fragment = fragmentPasswordError
			break
		}

		url := "https://www.google.com"
		if s.config.Security.LoginRedirect != nil {
			url = *s.config.Security.LoginRedirect
		}
		c.Redirect(http.StatusFound, url)
		return

	case fragmentSetPassword:
		password := c.DefaultPostForm("new-password", "")
		if password == "" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		userID, err := s.session.GetSessionUserID(sessionID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to get session user ID")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if userID == nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if err := s.user.UpdatePassword(*userID, password); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update password")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if err := s.session.UpdateState(sessionID, session.StateComplete); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to set session state")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		token, err := s.token.Create(*userID, int64(s.config.Security.Cookie.Expiration))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", c.Request.URL.Host, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		url := "https://www.google.com"
		if s.config.Security.LoginRedirect != nil {
			url = *s.config.Security.LoginRedirect
		}
		c.Redirect(http.StatusFound, url)
		return

	case fragmentForgottenPassword:
		fragment = fragmentForgottenPassword

	case fragmentSubmitForgottenPassword:
		userID, err := s.session.GetSessionUserID(sessionID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to get session user ID")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if userID == nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if err := s.user.GeneratePasswordReset(*userID); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to generate password reset")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		fragment = fragmentForgottenPasswordComplete

	default:

	}

	content, err := s.loadHTMLFragment(fragment)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to load html fragment")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	value := strings.ReplaceAll(*content, "$$SESSION_ID$$", sessionID)
	value = strings.ReplaceAll(value, "$$EMAIL_ADDRESS$$", email)

	c.Data(http.StatusOK, "text/html", []byte(value))
}

func (s *Service) loadHTMLFragment(fragmentName string) (*string, error) {
	fragmentContent, err := assets.Fragments.ReadFile("authenticate/fragment/" + fragmentName + ".html")
	if err != nil {
		return nil, err
	}

	header, err := assets.Fragments.ReadFile("authenticate/default/header.html")
	if err != nil {
		return nil, err
	}

	footer, err := assets.Fragments.ReadFile("authenticate/default/footer.html")
	if err != nil {
		return nil, err
	}

	content := string(header) + string(fragmentContent) + string(footer)
	return &content, nil
}

func (s *Service) validateState(formState string, sessionState int) error {
	fmt.Printf("Validate State - Form: %v Session %v\n", formState, sessionState)
	return nil
}
