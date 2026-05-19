package listener

import (
	"net/http"

	"flomation.app/sentinel/internal/mfa"
	appmetrics "flomation.app/sentinel/internal/metrics"
	"flomation.app/sentinel/internal/session"
	"flomation.app/sentinel/internal/user"

	"flomation.app/sentinel/internal/persistence"
	"flomation.app/sentinel/internal/security"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/version"
	owasp "github.com/flomation-co/gin-owasp-headers"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	config  *config.Config
	engine  *gin.Engine
	token   *security.Service
	user    *user.Service
	session *session.Service
	mfa     *mfa.Service
}

func corsPublic(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}

func corsAuthenticated(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}

func NewListener(config *config.Config, sec *security.Service, db *persistence.Service) (*Service, error) {
	gin.SetMode(gin.ReleaseMode)

	s := Service{
		config:  config,
		engine:  gin.New(),
		token:   sec,
		user:    user.New(config, db),
		session: session.New(config, db),
		mfa:     mfa.New(config, db),
	}

	m := owasp.
		NewSecureHeadersMiddleware().
		ReferrerPolicy(owasp.ReferrerPolicySameOrigin).
		StrictTransportSecurity(owasp.DefaultMaxAge, true, true)

	s.engine.Use(m.Middleware())

	if config.Metrics.Enabled {
		s.engine.Use(appmetrics.RequestMetricsMiddleware())
		s.engine.GET("/metrics", appmetrics.IPRestrictionMiddleware(config.Metrics.AllowedIPs), gin.WrapH(promhttp.Handler()))
	}

	s.engine.GET("/", func(c *gin.Context) {
		target := "/authenticate"
		if c.Request.URL.RawQuery != "" {
			target += "?" + c.Request.URL.RawQuery
		}
		c.Redirect(http.StatusTemporaryRedirect, target)
	})

	s.engine.GET("/authenticate", s.authenticate)
	s.engine.POST("/authenticate", s.authenticate)
	s.engine.GET("/verify", s.verifyUser)
	s.engine.POST("/verify", s.setPassword)
	s.engine.GET("/password", s.resetPassword)
	s.engine.POST("/password", s.setPassword)

	// Google OAuth routes
	s.engine.GET("/auth/google/login", s.googleLogin)
	s.engine.GET("/auth/google/callback", s.googleCallback)

	s.engine.NoRoute(s.staticAssets)

	s.engine.GET("/version", corsPublic, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":    version.Version,
			"build_date": version.BuiltDate,
			"hash":       version.GetHash(),
		})
	})

	s.engine.GET("/health", corsPublic, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	s.engine.OPTIONS("/version", corsPublic)
	s.engine.OPTIONS("/health", corsPublic)

	s.engine.GET("/logout", owasp.NewSecureHeadersMiddleware().ClearSiteData(
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		true).Middleware(), func(c *gin.Context) {

		logoutUrl := s.config.Listener.ListenAddress()
		if config.Security.LogoutRedirect != nil {
			logoutUrl = *config.Security.LogoutRedirect
		}

		c.SetCookie("flomation-token", "", -1, "/", s.config.Security.Cookie.Domain, s.config.Security.Cookie.Secure, s.config.Security.Cookie.HttpOnly)

		c.Redirect(http.StatusTemporaryRedirect, logoutUrl)
	})

	s.engine.POST("/api/token", s.issueToken)
	s.engine.POST("/api/user", s.registerUser)
	s.engine.GET("/api/user", Sentinel(s.config), s.getUser)
	s.engine.PUT("/api/user", Sentinel(s.config), s.updateUser)
	s.engine.GET("/api/account", Sentinel(s.config), s.getAccount)
	s.engine.GET("/api/sessions", corsAuthenticated, Sentinel(s.config), s.getLoginHistory)
	s.engine.OPTIONS("/api/sessions", corsAuthenticated)

	s.engine.GET("/mfa", Sentinel(s.config), s.mfaManage)
	s.engine.POST("/mfa/enrol", Sentinel(s.config), s.mfaEnrol)
	s.engine.GET("/mfa/qr", Sentinel(s.config), s.mfaQR)
	s.engine.POST("/mfa/verify", Sentinel(s.config), s.mfaVerify)
	s.engine.POST("/mfa/disable", Sentinel(s.config), s.mfaDisable)

	return &s, nil
}

func (s *Service) Listen() error {
	log.Infof("Starting HTTP listener: http://%v", s.config.Listener.ListenAddress())
	return s.engine.Run(s.config.Listener.ListenAddress())
}

func (s *Service) ListenTLS(certificate string, key string) error {
	log.Infof("Starting HTTPS listener: https://%v", s.config.Listener.ListenAddress())
	return s.engine.RunTLS(s.config.Listener.ListenAddress(), certificate, key)
}
