package geo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"flomation.app/sentinel/internal/config"
	log "github.com/sirupsen/logrus"
)

var (
	ErrInvalidResponse = errors.New("invalid http response")

	// baseURL is the ip2loc API root. Declared as a package var (not a const)
	// so tests can point it at an httptest server and exercise the lookup
	// paths hermetically, without a live network call or a real API key.
	baseURL = "https://api.ip2loc.com"
)

type ConnectionData struct {
	IP        string `json:"ip"`
	IPVersion string `json:"ip_version"`
}

type CurrencyData struct {
	Code []string `json:"code"`
}

type Continent struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type Country struct {
	CountryCode  string   `json:"alpha_2"`
	CountryCode3 string   `json:"alpha_3"`
	DialingCode  []string `json:"dialing_code"`
	Emoji        string   `json:"emoji"`
	EUMember     bool     `json:"eu_member"`
	Name         string   `json:"name"`
	State        string   `json:"subdivision"`
	StateCode    string   `json:"subdivision_id"`
	PostCode     string   `json:"zip_code"`
}

type LocationData struct {
	Capital   string    `json:"capital"`
	City      string    `json:"city"`
	Continent Continent `json:"continent"`
	Country   Country   `json:"country"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
}

type TimeData struct {
	Zone string `json:"zone"`
}

type Data struct {
	Connection ConnectionData `json:"connection"`
	Currency   CurrencyData   `json:"currency"`
	Location   LocationData   `json:"location"`
	Time       TimeData       `json:"time"`
}

func GetGeoDataFromIP(config config.Config, address string) (*Data, error) {
	var client http.Client
	var data Data

	if address == "" {
		return &data, nil
	}

	ip := address
	if s := net.ParseIP(address); s == nil {
		// address is not an IP address - try to resolve
		ips, err := net.LookupIP(address)
		if err != nil {
			return &data, err
		}

		ip = ips[0].String()
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s", baseURL, config.GeoIPConfig.APIKey, ip), nil)
	if err != nil {
		return &data, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return &data, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, ErrInvalidResponse
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return &data, err
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return &data, err
	}

	return &data, nil
}

// isInternalIP reports whether address is an IP that will never resolve to a
// meaningful public location — loopback, RFC1918 private, link-local, or the
// unspecified address. Internal traffic is skipped before any external call so
// that requests from ::1, 10.x, 172.16.x, 192.168.x, etc. behave the same way
// 127.0.0.1 always has, instead of triggering a doomed lookup.
func isInternalIP(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		// Not a literal IP (e.g. a hostname); let the caller attempt a
		// lookup, which resolves the name before querying the geo API.
		return false
	}

	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// ResolveLocation returns a human-readable "City, Country" string for the given
// client address, or nil when geo enrichment is unavailable. It is best-effort
// and never fails the caller: geolocation is decorative session metadata, so a
// missing API key, internal traffic, or an upstream error all degrade to nil
// rather than propagating an error (which previously blanked the login page with
// an empty 200 for any non-loopback client). Lookups that fail for a public IP
// are logged so the condition stays visible in operations.
func ResolveLocation(config config.Config, address string) *string {
	// Gate on key presence: with no key configured, geo is simply off.
	if config.GeoIPConfig.APIKey == "" {
		return nil
	}

	if address == "" || isInternalIP(address) {
		return nil
	}

	data, err := GetGeoDataFromIP(config, address)
	if err != nil || data == nil {
		log.WithFields(log.Fields{
			"error":   err,
			"address": address,
		}).Warn("geo lookup failed; continuing without location")
		return nil
	}

	// A 2xx response can still carry empty fields (e.g. reserved/anycast IPs).
	// Treat that as "no location" rather than persisting a useless ", " that
	// would later render as "Location: , " in new-device emails.
	if data.Location.City == "" && data.Location.Country.Name == "" {
		return nil
	}

	loc := fmt.Sprintf("%s, %s", data.Location.City, data.Location.Country.Name)
	return &loc
}
