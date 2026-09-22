package listener

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"flomation.app/sentinel/internal/geo"
	"flomation.app/sentinel/internal/security"

	"flomation.app/sentinel/internal/assets"
	"flomation.app/sentinel/internal/persistence"
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
		if loc := geo.ResolveLocation(cfg, ip); loc != nil {
			location = *loc
		}
		s.user.CheckNewDevice(userID, ip, ua, location)
	}()
}

const (
	fragmentEnterEmailAddress = "email_address"
	fragmentRegister          = "register"
	fragmentPassword          = "password"
	fragmentEnterPasskey      = "enter_passkey"
	fragmentPasswordError     = "password_error"
	fragmentSubmitPassword    = "submit_password"
	fragmentSubmitMFA         = "submit_mfa"
	fragmentEnterMFA          = "enter_mfa"
	// fragmentEnterMFAForReset shares the TOTP-prompt shape with
	// enter_mfa but uses reset-specific copy ("Continue resetting
	// your password" instead of "Log in"), posts back with
	// form_state=submit_mfa_for_reset, and is rendered against
	// /password instead of /authenticate.
	fragmentEnterMFAForReset          = "enter_mfa_reset"
	fragmentSubmitMFAForReset         = "submit_mfa_for_reset"
	fragmentSetPassword               = "set_new_password"
	fragmentForgottenPassword         = "forgot_password"
	fragmentSubmitForgottenPassword   = "submit_forgot_password"
	fragmentForgottenPasswordComplete = "forgot_password_complete"

	// The post-password prompt offering to turn MFA on. Two ways out:
	// enable (finish the login, land on the MFA page) or skip (finish the
	// login and go where the user was headed).
	fragmentMFANudge       = "mfa_nudge"
	fragmentMFANudgeEnable = "mfa_nudge_enable"
	fragmentMFANudgeSkip   = "mfa_nudge_skip"
)

// mfaNudgeInterval is how long a decline is respected before the prompt
// returns. Long enough not to nag, short enough that somebody who was busy
// the first time gets asked again.
const mfaNudgeInterval = 30 * 24 * time.Hour

// shouldNudgeForMFA reports whether the post-password MFA prompt should be
// shown to this user.
//
// Deliberately NOT a reason to skip: a linked SSO account. Those users keep a
// usable password, so the password stays an MFA-free route into the account —
// which is precisely what the prompt is for. The same goes for a registered
// passkey, since reaching this branch at all means the user chose "use
// password instead".
//
// Externally managed identities (organisation SAML, where the provider
// enforces its own second factor and ours would be noise) belong here too, but
// Sentinel has no such concept yet — there is no SAML or organisation-managed
// account anywhere in this service. When that lands, this is where it goes.
//
// Any error answers false: a prompt is a courtesy, and a database hiccup must
// never stand between a user with the right password and their account.
func (s *Service) shouldNudgeForMFA(userID string) bool {
	enrolled, err := s.mfa.IsEnrolled(userID)
	if err != nil || enrolled {
		return false
	}

	state, err := s.user.Database().GetMFANudgeState(userID)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("unable to read MFA nudge state")
		return false
	}

	return mfaNudgeDue(state, time.Now())
}

// mfaNudgeDue decides whether enough time has passed since the user last
// declined. Split out from shouldNudgeForMFA so the cadence is testable
// without a database or a clock.
//
// Never asked (no row, or a row that has never been dismissed) is due.
func mfaNudgeDue(state *persistence.MFANudgeState, now time.Time) bool {
	if state == nil || state.DismissedAt == nil {
		return true
	}
	return now.Sub(*state.DismissedAt) > mfaNudgeInterval
}

// staticContentTypes gives the embedded assets an explicit media type.
//
// http.DetectContentType sniffs the bytes, which is wrong for two of the
// things we serve: an SVG sniffs as text/xml, and a browser will not paint an
// <img> whose type is not image/svg+xml, while a woff2 sniffs as
// application/octet-stream. Naming the type per extension is both correct and
// cheaper than sniffing.
var staticContentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".ico":   "image/x-icon",
	".jpeg":  "image/jpeg",
	".jpg":   "image/jpeg",
	".js":    "text/javascript; charset=utf-8",
	".png":   "image/png",
	".svg":   "image/svg+xml",
	".webp":  "image/webp",
	".woff":  "font/woff",
	".woff2": "font/woff2",
}

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

	contentType, ok := staticContentTypes[strings.ToLower(filepath.Ext(fileName))]
	if !ok {
		contentType = http.DetectContentType(b)
	}

	// Validate rather than expire.
	//
	// These URLs carry no content hash, so a far-future max-age means a
	// changed asset is invisible to anyone who has already loaded the old one
	// until their cache lapses. That is not hypothetical: a day-long max-age
	// here left a corrected image unseen behind a stale copy.
	//
	// no-cache does not mean "do not store", it means "ask before using". The
	// browser still keeps the bytes and still skips the download; it just
	// spends one conditional request confirming they are current, and a
	// deployed change is picked up at once.
	etag := staticETag(fileName, b)
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-cache")

	if matchesETag(c.GetHeader("If-None-Match"), etag) {
		// AbortWithStatus rather than Status: gin buffers the code until
		// something writes, and a 304 has no body to trigger that, so a plain
		// Status here leaves the response as a 200 with nothing in it.
		c.AbortWithStatus(http.StatusNotModified)
		return
	}

	c.Data(http.StatusOK, contentType, b)
}

// staticETags memoises the digests. The assets are embedded, so a given path's
// bytes cannot change while the process is alive and the hash is worth
// computing once rather than on every request.
var staticETags sync.Map

func staticETag(name string, b []byte) string {
	if v, ok := staticETags.Load(name); ok {
		return v.(string)
	}
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	staticETags.Store(name, etag)
	return etag
}

// matchesETag reports whether an If-None-Match header covers etag.
//
// The header is a comma-separated list, may be "*", and entries may carry the
// weak validator prefix, which we ignore: our tags are byte-exact, so a weak
// comparison and a strong one agree.
func matchesETag(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

// handleResetMFA validates a TOTP code submitted from the MFA-for-
// reset prompt. On success it moves the session to StateSetPassword
// and renders the set-password screen; on failure it re-renders the
// MFA prompt so the user can retry without losing their session.
//
// Rejects sessions that aren't in StateMFAForReset to prevent
// somebody hand-crafting a submit_mfa_for_reset POST from anywhere
// else in the flow.
func (s *Service) handleResetMFA(c *gin.Context, sessionID string, state int) {
	if state != session.StateMFAForReset {
		log.WithFields(log.Fields{
			"state": state,
		}).Error("session incorrect state for reset-flow MFA")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	userID, err := s.session.GetSessionUserID(sessionID)
	if err != nil || userID == nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get session user id")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	u, err := s.user.GetUserByID(*userID)
	if err != nil || u == nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get user during reset MFA")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	code := collectMFACode(c)
	valid, err := s.mfa.ValidateCode(*userID, code)
	if err != nil || !valid {
		log.WithFields(log.Fields{
			"error":   err,
			"user_id": *userID,
		}).Warn("invalid MFA code on password reset")
		s.renderResetMFAPrompt(c, sessionID, u.Username)
		return
	}

	if err := s.session.UpdateState(sessionID, session.StateSetPassword); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update session state after reset MFA")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	content, err := s.loadHTMLFragment("set_password")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to load set_password fragment")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	value := strings.ReplaceAll(*content, "$$USER$$", u.Username)
	value = strings.ReplaceAll(value, "$$SESSION_ID$$", sessionID)
	c.Data(http.StatusOK, "text/html", []byte(value))
}

func (s *Service) setPassword(c *gin.Context) {
	sessionID := c.DefaultPostForm("session", "")

	state, err := s.session.GetSessionState(sessionID)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to get session state")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// The MFA-for-reset fragment posts back to /password with
	// form_state=submit_mfa_for_reset. Branch here so the same
	// endpoint handles both the TOTP step and the eventual new
	// password — sharing the route keeps the form's empty
	// action="" (post-to-self) working without any client-side
	// awareness of which step it's on.
	if c.DefaultPostForm("form_state", "") == fragmentSubmitMFAForReset {
		s.handleResetMFA(c, sessionID, state)
		return
	}

	if state != session.StateSetPassword {
		log.WithFields(log.Fields{
			"state": state,
		}).Error("session incorrect state for password reset")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	password := c.DefaultPostForm("new-password", "")

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

	_, err = s.issueChallengedSession(c, *userID)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to create token")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

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
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if err := s.session.SetSessionUserID(sess.ID, u.ID); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to set session user id")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// When MFA is enrolled, require a valid TOTP code before
	// letting the user pick a new password. The reset email
	// already proves "controls the inbox"; the TOTP code proves
	// "still controls the second factor". Skipping this would
	// let a one-time email compromise drain the account.
	mfaEnrolled, _ := s.mfa.IsEnrolled(u.ID)
	if mfaEnrolled {
		if err := s.session.UpdateState(sess.ID, session.StateMFAForReset); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to update session state for MFA-gated password reset")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		s.renderResetMFAPrompt(c, sess.ID, u.Username)
		return
	}

	if err := s.session.UpdateState(sess.ID, session.StateSetPassword); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to update session")
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

// renderResetMFAPrompt loads the MFA-for-reset fragment and writes
// it with the user and session substituted. Pulled out as a helper
// because both the initial GET (after a valid reset link) and the
// POST retry path (after a bad TOTP code) render the same screen.
func (s *Service) renderResetMFAPrompt(c *gin.Context, sessionID, username string) {
	content, err := s.loadHTMLFragment(fragmentEnterMFAForReset)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to load reset MFA fragment")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	value := strings.ReplaceAll(*content, "$$USER$$", username)
	value = strings.ReplaceAll(value, "$$SESSION_ID$$", sessionID)
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
		c.AbortWithStatus(http.StatusInternalServerError)
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
			c.AbortWithStatus(http.StatusInternalServerError)
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

		// Home Realm Discovery: if the email's domain is claimed by a verified,
		// enabled SSO connection, hand off to the IdP instead of prompting for a
		// password — EXCEPT org admins of that connection's org, who keep the
		// password/MFA flow as a self-serve break-glass so a broken SSO
		// connection can't lock them out. New (JIT) users are never admins, so
		// they still go to SSO.
		if domain := ssoDomainFromEmail(email); domain != "" {
			if conn, derr := s.user.Database().ResolveSSOByDomain(domain); derr == nil && conn != nil {
				breakGlass := u != nil && s.isOrgAdminBreakGlass(c.Request.Context(), u.ID, conn.OrganisationID)
				if !breakGlass {
					c.Redirect(http.StatusSeeOther, "/sso/login/"+conn.ID)
					return
				}
			}
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

			// If the user has registered passkeys and WebAuthn is enabled, show passkey prompt.
			if s.passkey != nil {
				hasPasskeys, _ := s.user.Database().HasWebAuthnCredentials(u.ID)
				if hasPasskeys {
					fragment = fragmentEnterPasskey
				} else {
					fragment = fragmentPassword
				}
			} else {
				fragment = fragmentPassword
			}
		}
	case "use_password":
		// User clicked "Use password instead" from the passkey prompt.
		fragment = fragmentPassword
	case fragmentEnterPasskey:
		// Passkey JS handles authentication via API — this form submission
		// is a no-op (the fragment auto-triggers JS). Show passkey again.
		fragment = fragmentEnterPasskey
	case fragmentRegister:
		// Carry forward UTM attribution captured when the session was started
		// so the new user record reflects the campaign that drove the sign-up.
		// A failure to read metadata should not block registration.
		utm, utmErr := s.session.GetSessionUTMParameters(sessionID)
		if utmErr != nil {
			log.WithFields(log.Fields{
				"error":      utmErr,
				"session_id": sessionID,
			}).Warn("unable to read session UTM parameters")
		}

		// The sign-up form carries the marketing question, so this is the one
		// registration path where a decision is genuinely recorded. An unticked
		// box is a refusal, not an absence — Source is set either way so the
		// two remain distinguishable downstream.
		consent := persistence.MarketingConsent{
			OptIn:   c.DefaultPostForm("marketing_opt_in", "") == "true",
			Source:  persistence.MarketingConsentSourceRegistrationForm,
			Version: persistence.MarketingConsentWordingSignupV1,
		}

		u, err := s.user.RegisterUser(email, utm, consent)
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

		// Deliberately NOT issueChallengedSession.
		//
		// Nothing has been proved here. The user has given an email address and
		// has not yet shown they can receive anything at it, so this session
		// stays on the short, unchallenged lifetime; they reach the longer one
		// the first time they actually log in.
		//
		// The mismatched lifetimes below are pre-existing and left alone: the
		// token is good for Expiration while the cookie carrying it lasts an
		// hour, so in practice the session ends after the hour. Making them
		// agree means either lengthening the cookie, which is the wrong
		// direction for an unproved address, or shortening the token, which is
		// right but is a change nobody asked for. Worth settling separately.
		token, err := s.token.Create(u.ID, int64(s.config.Security.Cookie.Expiration))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.SetCookie(authCookie, *token, security.DefaultTokenExpirationSeconds, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)
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

		// No second factor. Offer one before finishing the login. The session
		// parks in StateMFANudge rather than completing, so no token exists
		// until the user answers.
		if s.shouldNudgeForMFA(u.ID) {
			if err := s.session.UpdateState(sessionID, session.StateMFANudge); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("unable to set session state for MFA nudge")
				fragment = fragmentPasswordError
				break
			}
			fragment = fragmentMFANudge
			break
		}

		if err := s.session.UpdateState(sessionID, session.StateComplete); err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to set session state")
			fragment = fragmentPasswordError
			break
		}

		_, err = s.issueChallengedSession(c, u.ID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			fragment = fragmentPasswordError
			break
		}

		// The session row records the same login, so it carries the same
		// lifetime. Nothing gates on it today, but a row that disagrees with
		// the token it was issued beside is a misleading thing to read.
		duration := time.Duration(s.challengedSessionExpiry()) * time.Second
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

	case fragmentMFANudgeEnable, fragmentMFANudgeSkip:
		// validateState is a no-op, so the gate is here: only a session that
		// actually got past the password may mint a token from this branch.
		if sessionState != session.StateMFANudge {
			log.WithFields(log.Fields{
				"state": sessionState,
			}).Warn("MFA nudge answered from an unexpected session state")
			fragment = fragmentPasswordError
			break
		}

		userID, err := s.session.GetSessionUserID(sessionID)
		if err != nil || userID == nil {
			fragment = fragmentPasswordError
			break
		}

		// A decline is recorded before the login finishes, so the prompt is
		// not repeated on the next login. Failing to record it is not worth
		// blocking a valid login over — the worst case is being asked again.
		if formState == fragmentMFANudgeSkip {
			if err := s.user.Database().RecordMFANudgeDismissed(*userID); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Warn("unable to record MFA nudge dismissal")
			}
		}

		if err := s.session.UpdateState(sessionID, session.StateComplete); err != nil {
			fragment = fragmentPasswordError
			break
		}

		_, err = s.issueChallengedSession(c, *userID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token after MFA nudge")
			fragment = fragmentPasswordError
			break
		}

		// The session row records the same login, so it carries the same
		// lifetime. Nothing gates on it today, but a row that disagrees with
		// the token it was issued beside is a misleading thing to read.
		duration := time.Duration(s.challengedSessionExpiry()) * time.Second
		expiration := time.Now().Add(duration)
		if err := s.session.UpdateStateExpiration(sessionID, expiration); err != nil {
			fragment = fragmentPasswordError
			break
		}

		s.checkNewDeviceFromContext(c, *userID)

		// Accepting sends the user to the MFA page to enrol; declining sends
		// them where they were going. Either way the login is complete, so
		// abandoning enrolment still leaves them logged in.
		if formState == fragmentMFANudgeEnable {
			c.Redirect(http.StatusFound, "/mfa")
			return
		}
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

		_, err = s.issueChallengedSession(c, *userID)
		if err != nil {
			fragment = fragmentPasswordError
			break
		}

		// The session row records the same login, so it carries the same
		// lifetime. Nothing gates on it today, but a row that disagrees with
		// the token it was issued beside is a misleading thing to read.
		duration := time.Duration(s.challengedSessionExpiry()) * time.Second
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

		_, err = s.issueChallengedSession(c, *userID)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("unable to create token")
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		// The session row records the same login, so it carries the same
		// lifetime. Nothing gates on it today, but a row that disagrees with
		// the token it was issued beside is a misleading thing to read.
		duration := time.Duration(s.challengedSessionExpiry()) * time.Second
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

	// Inject OAuth provider buttons for all configured providers.
	oauthButtons := s.renderOAuthButtons()
	content = strings.ReplaceAll(content, "$$GOOGLE_OAUTH_BUTTON$$", oauthButtons)

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
