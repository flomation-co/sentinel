package listener

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"flomation.app/sentinel/internal/geo"
	"flomation.app/sentinel/internal/security"

	"flomation.app/sentinel/internal/assets"
	"flomation.app/sentinel/internal/session"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// checkNewDeviceFromContext fires the new-device check asynchronously using
// IP and User-Agent from the Gin request context.
func (s *Service) checkNewDeviceFromContext(c *gin.Context, userID string) {
	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	cfg := *s.config

	go func() {
		location := ""
		if ip != "127.0.0.1" {
			if data, err := geo.GetGeoDataFromIP(cfg, ip); err == nil && data != nil {
				location = fmt.Sprintf("%s, %s", data.Location.City, data.Location.Country.Name)
			}
		}
		s.user.CheckNewDevice(userID, ip, ua, location)
	}()
}

const (
	fragmentEnterEmailAddress         = "email_address"
	fragmentRegister                  = "register"
	fragmentPassword                  = "password"
	fragmentPasswordError             = "password_error"
	fragmentSubmitPassword            = "submit_password"
	fragmentSubmitMFA                 = "submit_mfa"
	fragmentEnterMFA                  = "enter_mfa"
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

	token, err := s.token.Create(*userID, int64(s.config.Security.Cookie.Expiration))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to create token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

	c.Redirect(http.StatusFound, s.getRedirectURL(sessionID))
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
		c.SetCookie("flomation-sentinel-session-id", sessionID, 0, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
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

		c.SetCookie("flomation-token", *token, security.DefaultTokenExpirationSeconds, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			fragment = fragmentPasswordError
			break
		}

		s.checkNewDeviceFromContext(c, u.ID)
		c.Redirect(http.StatusFound, s.getRedirectURL(sessionID))
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

		// Check if user has MFA enabled
		mfaEnrolled, _ := s.mfa.IsEnrolled(u.ID)
		if mfaEnrolled {
			if err := s.session.UpdateState(sessionID, session.StateDonePassword); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set session state for MFA")
				fragment = fragmentPasswordError
				break
			}
			fragment = fragmentEnterMFA
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

		c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			fragment = fragmentPasswordError
			break
		}

		s.checkNewDeviceFromContext(c, u.ID)
		c.Redirect(http.StatusFound, s.getRedirectURL(sessionID))
		return

	case fragmentSubmitMFA:
		code := collectMFACode(c)

		userID, err := s.session.GetSessionUserID(sessionID)
		if err != nil || userID == nil {
			fragment = fragmentPasswordError
			break
		}

		valid, err := s.mfa.ValidateCode(*userID, code)
		if err != nil || !valid {
			log.WithFields(log.Fields{
				"error": err,
			}).Warn("invalid MFA code")
			fragment = fragmentEnterMFA
			break
		}

		if err := s.session.UpdateState(sessionID, session.StateComplete); err != nil {
			fragment = fragmentPasswordError
			break
		}

		token, err := s.token.Create(*userID, int64(s.config.Security.Cookie.Expiration))
		if err != nil {
			fragment = fragmentPasswordError
			break
		}

		c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			fragment = fragmentPasswordError
			break
		}

		s.checkNewDeviceFromContext(c, *userID)
		c.Redirect(http.StatusFound, s.getRedirectURL(sessionID))
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

		c.SetCookie("flomation-token", *token, s.config.Security.Cookie.Expiration, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
		duration := time.Duration(s.config.Security.Cookie.Expiration) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update state expiration")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.Redirect(http.StatusFound, s.getRedirectURL(sessionID))
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

	// Inject Google OAuth button if configured.
	googleButton := ""
	if s.config.GoogleOAuth != nil && s.config.GoogleOAuth.ClientID != "" {
		googleButton = `<div class="oauth-divider">or</div>` +
			`<a href="/auth/google/login" class="google-btn">` +
			`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">` +
			`<path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>` +
			`<path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>` +
			`<path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>` +
			`<path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>` +
			`</svg>Continue with Google</a>`
	}
	content = strings.ReplaceAll(content, "$$GOOGLE_OAUTH_BUTTON$$", googleButton)

	return &content, nil
}

func (s *Service) validateState(formState string, sessionState int) error {
	fmt.Printf("Validate State - Form: %v Session %v\n", formState, sessionState)
	return nil
}

// getRedirectURL returns the session's stored redirect_url if set,
// otherwise falls back to the configured LoginRedirect.
func (s *Service) getRedirectURL(sessionID string) string {
	url := "https://www.google.com"
	if s.config.Security.LoginRedirect != nil {
		url = *s.config.Security.LoginRedirect
	}

	redirectURL, err := s.session.GetSessionRedirectURL(sessionID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("unable to get session redirect URL")
		return url
	}

	if redirectURL != nil && *redirectURL != "" {
		return *redirectURL
	}

	return url
}
