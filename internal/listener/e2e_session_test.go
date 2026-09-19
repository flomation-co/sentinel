package listener

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Load the real config.json and prove a challenged session comes out at 7 days
// end to end, rather than trusting the constant in the test.
func TestRealConfigYieldsSevenDays(t *testing.T) {
	// go-config only accepts a path under the working directory, so the test
	// moves to the repository root rather than reaching up to it. t.Chdir
	// restores automatically and refuses to run in a parallel test, which is
	// what makes a process-wide chdir safe here.
	t.Chdir(filepath.Join("..", ".."))

	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Security.Secret = testSecret

	s := &Service{config: cfg, token: security.NewService(cfg)}

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := s.issueChallengedSession(c, "user-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims := jwt.RegisteredClaims{}
	if _, err := jwt.ParseWithClaims(*token, &claims, func(*jwt.Token) (any, error) {
		return []byte(testSecret), nil
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	life := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	t.Logf("challenged token lifetime from config.json: %s", life)
	if life < 167*time.Hour || life > 169*time.Hour {
		t.Errorf("lifetime %s, want about 7 days", life)
	}

	maxAge := regexp.MustCompile(`Max-Age=(\d+)`).FindStringSubmatch(rec.Header().Get("Set-Cookie"))
	t.Logf("cookie Max-Age: %s", maxAge[1])
	if maxAge[1] != "604800" {
		t.Errorf("cookie Max-Age %s, want 604800", maxAge[1])
	}

	// And the unchallenged lifetime must still be a day.
	if got := cfg.Security.Cookie.Expiration; got != 86400 {
		t.Errorf("unchallenged lifetime is %d, want 86400", got)
	}
}
