package listener

import (
	"testing"

	"flomation.app/sentinel/internal/persistence"
	. "github.com/onsi/gomega"
)

// TestEncodeDecodeUTMCookieRoundTrip is the happy path for the cookie codec
// used to carry UTM across the OAuth round-trip. Anything garbled here would
// silently lose attribution on every social sign-up.
func TestEncodeDecodeUTMCookieRoundTrip(t *testing.T) {
	RegisterTestingT(t)

	original := persistence.UTMParameters{
		Source:   "google",
		Medium:   "cpc",
		Campaign: "brand-Q4",
		Term:     "workflow automation",
		Content:  "ad-variant-b",
		Referrer: "https://example.com/post?id=42",
	}

	encoded := encodeUTMCookie(original)
	Expect(encoded).To(Not(BeEmpty()))

	decoded := decodeUTMCookie(encoded)
	Expect(decoded).To(Equal(original))
}

// TestEncodeUTMCookieEmptyReturnsEmpty guards the contract that we never set
// the cookie when no UTM was provided — callers gate on the returned string
// being non-empty.
func TestEncodeUTMCookieEmptyReturnsEmpty(t *testing.T) {
	RegisterTestingT(t)

	Expect(encodeUTMCookie(persistence.UTMParameters{})).To(BeEmpty())
}

// TestDecodeUTMCookieTolerantOfGarbage confirms that a malformed or absent
// cookie degrades to zero-value attribution rather than failing the OAuth
// callback. The callback path treats UTM as best-effort.
func TestDecodeUTMCookieTolerantOfGarbage(t *testing.T) {
	RegisterTestingT(t)

	Expect(decodeUTMCookie("")).To(Equal(persistence.UTMParameters{}))
	Expect(decodeUTMCookie("!!!not-base64!!!")).To(Equal(persistence.UTMParameters{}))
	// Valid base64 but not valid JSON.
	Expect(decodeUTMCookie("aGVsbG8")).To(Equal(persistence.UTMParameters{}))
}
