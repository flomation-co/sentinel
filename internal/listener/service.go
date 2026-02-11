package listener

import (
	"net/http"

	"flomation.app/sentinel/internal/session"
	"flomation.app/sentinel/internal/user"

	"flomation.app/sentinel/internal/persistence"
	"flomation.app/sentinel/internal/security"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/version"
	owasp "github.com/flomation-co/gin-owasp-headers"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	config  *config.Config
	engine  *gin.Engine
	token   *security.Service
	user    *user.Service
	session *session.Service
}

func NewListener(config *config.Config, sec *security.Service, db *persistence.Service) (*Service, error) {
	gin.SetMode(gin.ReleaseMode)

	s := Service{
		config:  config,
		engine:  gin.New(),
		token:   sec,
		user:    user.New(config, db),
		session: session.New(config, db),
	}

	m := owasp.
		NewSecureHeadersMiddleware().
		ReferrerPolicy(owasp.ReferrerPolicySameOrigin).
		StrictTransportSecurity(owasp.DefaultMaxAge, true, true)

	s.engine.Use(m.Middleware())

	s.engine.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/authenticate")
	})

	s.engine.GET("/authenticate", s.authenticate)
	s.engine.POST("/authenticate", s.authenticate)
	s.engine.GET("/verify", s.verifyUser)
	//s.engine.GET("/password", s.passwordForm)
	//s.engine.POST("/password", s.resetPassword)

	s.engine.NoRoute(s.staticAssets)

	s.engine.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":    version.Version,
			"build_date": version.BuiltDate,
			"hash":       version.GetHash(),
		})
	})

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

		c.Redirect(http.StatusTemporaryRedirect, logoutUrl)
	})

	s.engine.POST("/api/token", s.issueToken)
	s.engine.POST("/api/user", s.registerUser)
	s.engine.GET("/api/user", Sentinel(s.config), s.getUser)

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
