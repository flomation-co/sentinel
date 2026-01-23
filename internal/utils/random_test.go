package utils

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestRandomString(t *testing.T) {
	RegisterTestingT(t)

	str := GenerateRandomString(32)
	Expect(str).To(Not(BeEmpty()))
	Expect(len(str)).To(Equal(32))
}
