package config

import (
	"bytes"
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

func TestLoadConfigBadPath(t *testing.T) {
	t.Parallel()
	RegisterTestingT(t)

	cfg, err := LoadConfig("some-bad-path")
	Expect(err).To(Not(BeNil()))
	Expect(cfg).To(BeNil())
}

func TestLoadConfigNotJSON(t *testing.T) {
	t.Parallel()
	RegisterTestingT(t)

	b := bytes.NewBufferString("").Bytes()

	defer func() {
		_ = os.Remove("not-json-config")
	}()

	t.Cleanup(func() {
		_ = os.Remove("not-json-config")
	})

	err := os.WriteFile("not-json-config", b, os.ModePerm)
	Expect(err).To(BeNil())

	cfg, err := LoadConfig("not-json-config")
	Expect(err).To(Not(BeNil()))
	Expect(cfg).To(BeNil())
}

func TestDefaultListener(t *testing.T) {
	RegisterTestingT(t)

	l := ListenerConfig{}
	Expect(l.Port).To(Equal(int64(0)))
	Expect(l.Address).To(BeEmpty())
	Expect(l.URL).To(BeEmpty())
	Expect(l.ListenAddress()).To(Equal("127.0.0.1:8999"))
}
