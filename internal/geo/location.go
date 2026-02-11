package geo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"flomation.app/sentinel/internal/config"
)

const (
	ip2LocURL = "https://api.ip2loc.com/"
)

var (
	ErrInvalidResponse = errors.New("invalid http response")
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

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s", ip2LocURL, config.GeoIPConfig.APIKey, ip), nil)
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
