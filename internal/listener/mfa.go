package listener

import (
	"fmt"
	"net/http"
	"strings"

	"flomation.app/sentinel/internal/assets"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	log "github.com/sirupsen/logrus"
)

func (s *Service) mfaManage(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.Redirect(http.StatusFound, "/authenticate")
		return
	}

	userID := v.(string)
	enrolled, _ := s.mfa.IsEnrolled(userID)

	// The header template already opens a <form>, so we set its action dynamically
	// via JavaScript and use the existing form rather than nesting forms.
	var content string
	if enrolled {
		content = `<div data-lang="mfa_manage">
			<h2>Multi-Factor Authentication</h2>
			<p>MFA is currently <strong>enabled</strong> on your account.</p>
			<p>Enter your current authenticator code to disable MFA:</p>
			<div class="mfa_container">
				<div class="mfa_boxes">
					<div class="mfa_box"></div>
					<div class="mfa_box"></div>
					<div class="mfa_box"></div>
					<div class="mfa_box"></div>
					<div class="mfa_box"></div>
					<div class="mfa_box"></div>
					<input type="text" name="mfa_code" id="mfa_code" required maxlength="6" minlength="6"
					       pattern="[0-9]{6}" inputmode="numeric" class="input_mfa_single" autofocus
					       oninput="this.value=this.value.replace(/[^0-9]/g,'')" />
				</div>
			</div>
			<input type="submit" value="Disable MFA" class="button button-continue" style="background-color: #be0000;" onclick="this.form.action='/mfa/disable'"/>
		</div>`
	} else {
		content = `<div data-lang="mfa_manage">
			<h2>Multi-Factor Authentication</h2>
			<p>MFA is currently <strong>not enabled</strong> on your account.</p>
			<p>Enabling MFA adds an extra layer of security by requiring a code from your authenticator app when logging in.</p>
			<input type="submit" value="Enable MFA" class="button button-continue" onclick="this.form.action='/mfa/enrol'"/>
		</div>`
	}

	page := s.wrapMFAPage(content)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func (s *Service) mfaEnrol(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.Redirect(http.StatusFound, "/authenticate")
		return
	}

	userID := v.(string)
	u, err := s.user.GetUserByID(userID)
	if err != nil || u == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	key, err := s.mfa.GenerateSecret(u.Username)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("unable to generate MFA secret")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if err := s.mfa.StoreSecret(userID, key.Secret()); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("unable to store MFA secret")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Store the key URL in session for QR code generation
	c.SetCookie("flomation-mfa-key", key.URL(), 300, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	// Read just the fragment content (not wrapped in header/footer)
	fragmentContent, err := assets.Fragments.ReadFile("authenticate/fragment/enrol_mfa.html")
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	content := string(fragmentContent) + `<script>document.getElementById('form').action='/mfa/verify';</script>`
	page := s.wrapMFAPage(content)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func (s *Service) mfaQR(c *gin.Context) {
	keyURL, err := c.Cookie("flomation-mfa-key")
	if err != nil || keyURL == "" {
		// Fall back to stored secret
		v, exists := c.Get(FlomationUserID)
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userID := v.(string)
		u, _ := s.user.GetUserByID(userID)
		secret, _ := s.mfa.GetSecret(userID)
		if secret == "" || u == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		key, err := otp.NewKeyFromURL(fmt.Sprintf("otpauth://totp/Flomation:%s?secret=%s&issuer=Flomation", u.Username, secret))
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		qr, err := s.mfa.GenerateQRCode(key)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Data(http.StatusOK, "image/png", qr)
		return
	}

	key, err := otp.NewKeyFromURL(keyURL)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	qr, err := s.mfa.GenerateQRCode(key)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "image/png", qr)
}

func (s *Service) mfaVerify(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.Redirect(http.StatusFound, "/authenticate")
		return
	}

	userID := v.(string)
	code := collectMFACode(c)

	valid, err := s.mfa.ValidateCode(userID, code)
	if err != nil || !valid {
		content := `<div>
			<h2>Invalid Code</h2>
			<p>The code you entered was incorrect. Please try again.</p>
			<div><a href="/mfa" class="button button-continue">Try Again</a></div>
		</div>`
		page := s.wrapMFAPage(content)
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
		return
	}

	if err := s.mfa.EnableMFA(userID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("unable to enable MFA")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.SetCookie("flomation-mfa-key", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, true)

	content := `<div>
		<h2>MFA Enabled</h2>
		<p>Multi-factor authentication has been successfully enabled on your account.</p>
		<p>You will now be required to enter a code from your authenticator app when logging in.</p>
	</div>`
	page := s.wrapMFAPage(content)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func (s *Service) mfaDisable(c *gin.Context) {
	v, exists := c.Get(FlomationUserID)
	if !exists {
		c.Redirect(http.StatusFound, "/authenticate")
		return
	}

	userID := v.(string)
	code := collectMFACode(c)

	valid, err := s.mfa.ValidateCode(userID, code)
	if err != nil || !valid {
		content := `<div>
			<h2>Invalid Code</h2>
			<p>The code you entered was incorrect. MFA has not been disabled.</p>
			<div><a href="/mfa" class="button button-continue">Try Again</a></div>
		</div>`
		page := s.wrapMFAPage(content)
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
		return
	}

	if err := s.mfa.DisableMFA(userID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("unable to disable MFA")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	content := `<div>
		<h2>MFA Disabled</h2>
		<p>Multi-factor authentication has been removed from your account.</p>
	</div>`
	page := s.wrapMFAPage(content)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

// collectMFACode reads the MFA code from the single input field.
func collectMFACode(c *gin.Context) string {
	return c.DefaultPostForm("mfa_code", "")
}

// wrapMFAPage wraps MFA content in the Sentinel authenticate page template.
func (s *Service) wrapMFAPage(content string) string {
	header, err := assets.Fragments.ReadFile("authenticate/default/header.html")
	if err != nil {
		return content
	}
	footer, err := assets.Fragments.ReadFile("authenticate/default/footer.html")
	if err != nil {
		return content
	}

	// The header opens a <form> and the footer closes it.
	// Replace the session placeholder since we're not in a session flow.
	h := strings.ReplaceAll(string(header), "$$SESSION_ID$$", "")
	// Fix relative asset paths for non-root pages like /mfa/*
	h = strings.ReplaceAll(h, `"assets/`, `"/assets/`)
	h = strings.ReplaceAll(h, `href="assets/`, `href="/assets/`)
	return h + content + string(footer)
}
