package listener

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"flomation.app/sentinel/internal/config"
	"flomation.app/sentinel/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

/*
A session's lifetime follows what the user proved.

Presenting a password, a TOTP code, a passkey or an identity provider's sign-in
earns the long lifetime. Registration does not: at that point the only thing
given is an email address nobody has shown they can receive at.

The risk these cover is a quiet one. Nothing fails when a lifetime is wrong --
a session just ends sooner or lasts longer than intended, and neither gets
reported.
*/

const testSecret = "test-secret-not-used-anywhere-real"

func testService(t *testing.T, expiration, challenged int) *Service {
	t.Helper()

	cfg := &config.Config{}
	cfg.Security.Secret = testSecret
	cfg.Security.Realm = "test"
	cfg.Security.Cookie.Expiration = expiration
	cfg.Security.Cookie.ChallengedExpiration = challenged
	cfg.Security.Cookie.Domain = "localhost"

	return &Service{config: cfg, token: security.NewService(cfg)}
}

func TestChallengedSessionExpiry(t *testing.T) {
	const day, week = 86400, 604800

	for _, c := range []struct {
		name                   string
		expiration, challenged int
		want                   int
	}{
		{"configured", day, week, week},
		// Zero is what an operator gets by setting it to zero, not what an
		// older config produces -- an absent key keeps the built-in default, so
		// an install that is never edited does pick up the longer lifetime.
		{"explicitly zeroed", day, 0, day},
		{"a negative value is not a lifetime", day, -1, day},
		{"an explicitly shorter one is honoured", day, 3600, 3600},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := testService(t, c.expiration, c.challenged).challengedSessionExpiry(); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// The token and the cookie carrying it must agree. They had drifted apart
// before this helper existed: one path minted a token good for a day and put it
// in a cookie that expired in an hour, so the user was logged out early with
// nothing to show why.
func TestIssueChallengedSessionKeepsTokenAndCookieInStep(t *testing.T) {
	const week = 604800
	s := testService(t, 86400, week)

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := s.issueChallengedSession(c, "user-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The cookie.
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, authCookie+"=") {
		t.Fatalf("no auth cookie was set: %q", setCookie)
	}
	maxAge := regexp.MustCompile(`Max-Age=(\d+)`).FindStringSubmatch(setCookie)
	if maxAge == nil {
		t.Fatalf("cookie has no Max-Age: %q", setCookie)
	}
	if maxAge[1] != "604800" {
		t.Errorf("cookie Max-Age is %s, want %d", maxAge[1], week)
	}

	// The token inside it.
	claims := jwt.RegisteredClaims{}
	if _, err := jwt.ParseWithClaims(*token, &claims, func(*jwt.Token) (any, error) {
		return []byte(testSecret), nil
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	life := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	if want := time.Duration(week) * time.Second; absDuration(life-want) > 2*time.Second {
		t.Errorf("token lives %s, want %s", life, want)
	}
	if claims.Subject != "user-1" {
		t.Errorf("token subject is %q", claims.Subject)
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

var (
	issuanceCall  = regexp.MustCompile(`s\.token\.Create\(`)
	challengedUse = regexp.MustCompile(`s\.issueChallengedSession\(`)
)

/*
Every login path must go through the helper.

This is the test that matters. The lifetime rule is only as good as its least
careful call site, and a new one that calls s.token.Create directly gets
whatever it happens to pass -- silently, because a working login looks the same
either way.

The exceptions are named individually rather than by pattern, so adding one is
a deliberate act.
*/
func TestOnlyKnownPathsIssueTokensDirectly(t *testing.T) {
	// file -> why it is allowed to mint a token without the helper.
	allowed := map[string]string{
		"session.go": "the helper itself",
		"token.go": "the API token endpoint, which returns JSON rather than a " +
			"cookie and has always had its own short lifetime",
		"authenticate.go": "the registration auto-login, which is deliberately " +
			"not a challenged session",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		direct := len(issuanceCall.FindAll(body, -1))
		if direct == 0 {
			continue
		}
		if reason, ok := allowed[name]; !ok {
			t.Errorf("%s mints a token with s.token.Create. Login paths must use "+
				"issueChallengedSession so the lifetime follows what the user "+
				"proved; if this one genuinely should not, name it in this test.",
				name)
		} else if testing.Verbose() {
			t.Logf("%s: %d direct call(s) allowed -- %s", name, direct, reason)
		}
	}
}

// The registration path must not drift onto the challenged lifetime.
func TestRegistrationDoesNotUseTheChallengedLifetime(t *testing.T) {
	body, err := os.ReadFile("authenticate.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(body)

	start := strings.Index(src, "case fragmentRegister:")
	if start < 0 {
		t.Fatal("cannot find the registration case; this test needs updating")
	}
	// Up to the next case at the same indentation.
	rest := src[start+len("case fragmentRegister:"):]
	if end := strings.Index(rest, "\n\tcase "); end >= 0 {
		rest = rest[:end]
	}

	if challengedUse.MatchString(rest) {
		t.Error("the registration auto-login now issues a challenged session. " +
			"Nothing has been proved at that point: the user has given an " +
			"email address and has not shown they can receive anything at it.")
	}
	if !issuanceCall.MatchString(rest) {
		t.Error("the registration path no longer issues a token at all; if that " +
			"is intended, this test needs updating")
	}
}
