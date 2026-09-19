package listener

import (
	"github.com/gin-gonic/gin"
)

// authCookie is the name of the cookie carrying the session JWT.
const authCookie = "flomation-token"

/*
How long a session lasts depends on what the user actually proved.

A challenge means the user presented something: a password, a TOTP code, a
passkey, or an identity provider's own sign-in. Registration is not one. There
the only thing given is an email address that nobody has yet proved they own,
so the session stays on the shorter, unchallenged lifetime and the user reaches
the longer one the first time they log in properly.
*/

// challengedSessionExpiry is the lifetime, in seconds, of a session created
// after a credential was presented.
//
// Zero falls back to Expiration. An absent key does not produce zero -- the
// config defaults fill it in, so an install that is never edited still gets the
// longer lifetime -- so this covers an operator who sets it to zero on purpose
// and a zero-value Config in tests.
func (s *Service) challengedSessionExpiry() int {
	if v := s.config.Security.Cookie.ChallengedExpiration; v > 0 {
		return v
	}
	return s.config.Security.Cookie.Expiration
}

// issueChallengedSession mints the JWT for a user who has just passed a
// challenge and sets the cookie carrying it.
//
// The two are issued together because they had drifted apart when they were
// not: one path minted a token good for a day and handed it to the browser in
// a cookie that expired in an hour. Nothing fails visibly when that happens,
// the user is just logged out early, which is exactly the sort of thing nobody
// reports.
func (s *Service) issueChallengedSession(c *gin.Context, userID string) (*string, error) {
	expiry := s.challengedSessionExpiry()

	token, err := s.token.Create(userID, int64(expiry))
	if err != nil {
		return nil, err
	}

	c.SetCookie(
		authCookie,
		*token,
		expiry,
		"/",
		s.config.Security.Cookie.Domain,
		s.config.Security.Cookie.Secure,
		s.config.Security.Cookie.HttpOnly,
	)

	return token, nil
}
