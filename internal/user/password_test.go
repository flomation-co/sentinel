package user

import (
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

func TestValidatePassword(t *testing.T) {
	RegisterTestingT(t)

	// Meets every rule (12+ chars, upper, lower, number).
	Expect(ValidatePassword("Password1234")).To(Succeed())
	Expect(ValidatePassword("aVeryLongPassphrase9")).To(Succeed())

	// Exactly at the boundary: 12 characters passes, 11 fails.
	Expect(len("Abcdefghij12")).To(Equal(12))
	Expect(ValidatePassword("Abcdefghij12")).To(Succeed())
	Expect(ValidatePassword("Abcdefghi12")).To(MatchError(ContainSubstring("at least 12 characters")))

	// The old 8-character minimum is now rejected.
	Expect(ValidatePassword("Passwr1d")).To(MatchError(ContainSubstring("at least 12 characters")))

	// Character-class rules still apply at 12+ characters.
	Expect(ValidatePassword(strings.Repeat("a", 12))).To(MatchError(ContainSubstring("uppercase")))
	Expect(ValidatePassword(strings.Repeat("A", 12))).To(MatchError(ContainSubstring("lowercase")))
	Expect(ValidatePassword("Abcdefghijkl")).To(MatchError(ContainSubstring("number")))
}
