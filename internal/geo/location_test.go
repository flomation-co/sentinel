package geo

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"flomation.app/sentinel/internal/config"

	. "github.com/onsi/gomega"
)

const (
	ValidIPAddress   = "18.135.29.34"
	InvalidIPAddress = "x.y.z.w"
)

func TestGetGeoDataFromIP(t *testing.T) {
	RegisterTestingT(t)

	if os.Getenv("GEOIP_API_KEY") == "" {
		t.Skip("GEOIP_API_KEY not set; skipping live geo lookup test")
	}

	data, err := getGeoDataFromIP(config.Config{
		GeoIPConfig: config.GeoIPConfig{
			APIKey: os.Getenv("GEOIP_API_KEY"),
		},
	}, ValidIPAddress)
	Expect(err).To(BeNil())
	Expect(data.Connection.IP).To(Equal(ValidIPAddress))
	Expect(data.Location.City).To(Equal("City of London"))
	Expect(data.Location.Continent.Name).To(Equal("Europe"))
	Expect(data.Location.Country.Name).To(Equal("United Kingdom"))
	Expect(data.Location.Country.State).To(Equal("England"))
}

func TestGetGeoDataFromBadIP(t *testing.T) {
	RegisterTestingT(t)

	_, err := getGeoDataFromIP(config.Config{
		GeoIPConfig: config.GeoIPConfig{
			APIKey: "GEOIP_API_KEY",
		},
	}, InvalidIPAddress)
	Expect(err).To(Not(BeNil()))
}

func TestIsInternalIP(t *testing.T) {
	RegisterTestingT(t)

	internal := []string{
		"127.0.0.1",    // loopback v4
		"::1",          // loopback v6
		"10.0.0.5",     // RFC1918
		"172.16.4.2",   // RFC1918
		"192.168.1.10", // RFC1918
		"169.254.10.1", // link-local v4
		"fe80::1",      // link-local v6
		"0.0.0.0",      // unspecified v4
		"::",           // unspecified v6
		"fc00::1",      // unique-local v6
	}
	for _, addr := range internal {
		Expect(isInternalIP(addr)).To(BeTrue(), "expected %q to be internal", addr)
	}

	external := []string{
		"8.8.8.8",     // public
		"1.1.1.1",     // public
		"",            // not an IP literal
		"example.com", // hostname, resolved later by the caller
	}
	for _, addr := range external {
		Expect(isInternalIP(addr)).To(BeFalse(), "expected %q to be external/non-literal", addr)
	}
}

func TestResolveLocationGating(t *testing.T) {
	RegisterTestingT(t)

	// No API key configured: geo is off regardless of address, with no network call.
	Expect(ResolveLocation(config.Config{}, ValidIPAddress)).To(BeNil())

	// Key present, but internal/empty addresses short-circuit before any external call.
	withKey := config.Config{GeoIPConfig: config.GeoIPConfig{APIKey: "test-key"}}
	for _, addr := range []string{"", "127.0.0.1", "::1", "10.1.2.3", "192.168.0.1", "fe80::1"} {
		Expect(ResolveLocation(withKey, addr)).To(BeNil(), "expected nil for %q", addr)
	}
}

func TestAnonymizeIP(t *testing.T) {
	RegisterTestingT(t)

	cases := map[string]string{
		"8.8.8.8":          "8.8.8.0", // IPv4: last octet zeroed
		"203.0.113.42":     "203.0.113.0",
		"2001:db8::1":      "2001:db8::",      // IPv6: kept to /48
		"2001:db8:abcd::5": "2001:db8:abcd::", // /48 keeps the third group; bits below it dropped
		"not-an-ip":        "invalid",
		"":                 "invalid",
	}
	for in, want := range cases {
		Expect(anonymizeIP(in)).To(Equal(want), "anonymizeIP(%q)", in)
	}

	// The masked value must never equal the full input IP (the PII guarantee).
	Expect(anonymizeIP("8.8.8.8")).ToNot(Equal("8.8.8.8"))
}

// swapBaseURL points the geo client at u for the duration of a test and
// returns a restore func. Lets the lookup paths run against an httptest
// server instead of the live ip2loc API.
func swapBaseURL(u string) func() {
	old := baseURL
	baseURL = u
	return func() { baseURL = old }
}

// keyedConfig is a config with a non-empty API key so ResolveLocation does
// not short-circuit on the key-presence gate.
var keyedConfig = config.Config{GeoIPConfig: config.GeoIPConfig{APIKey: "test-key"}}

// TestResolveLocationDegradesOnUpstreamError is the direct guard against the
// FLO-292 regression: a public IP whose lookup fails upstream must degrade to
// nil, NOT propagate an error (the old fatal path blanked the login page with
// an empty 200).
func TestResolveLocationDegradesOnUpstreamError(t *testing.T) {
	RegisterTestingT(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer swapBaseURL(srv.URL)()

	Expect(ResolveLocation(keyedConfig, "8.8.8.8")).To(BeNil())
}

// TestResolveLocationHappyPath covers the success branch: a 2xx with City and
// Country yields the formatted "City, Country" string.
func TestResolveLocationHappyPath(t *testing.T) {
	RegisterTestingT(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"location":{"city":"Testville","country":{"name":"Testland"}}}`))
	}))
	defer srv.Close()
	defer swapBaseURL(srv.URL)()

	loc := ResolveLocation(keyedConfig, "8.8.8.8")
	Expect(loc).ToNot(BeNil())
	Expect(*loc).To(Equal("Testville, Testland"))
}

// TestResolveLocationEmptyResponse covers the empty-but-200 guard: a successful
// response with blank fields degrades to nil instead of a useless ", ".
func TestResolveLocationEmptyResponse(t *testing.T) {
	RegisterTestingT(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"location":{"city":"","country":{"name":""}}}`))
	}))
	defer srv.Close()
	defer swapBaseURL(srv.URL)()

	Expect(ResolveLocation(keyedConfig, "8.8.8.8")).To(BeNil())
}
