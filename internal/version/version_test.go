package version

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestGetHash(t *testing.T) {
	RegisterTestingT(t)

	Hash = "abcdef1234567890"

	hash := GetHash()
	Expect(hash).To(Equal(Hash[:8]))
}
