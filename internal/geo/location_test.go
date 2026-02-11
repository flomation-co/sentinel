package geo

import (
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

	data, err := GetGeoDataFromIP(config.Config{
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

	_, err := GetGeoDataFromIP(config.Config{
		GeoIPConfig: config.GeoIPConfig{
			APIKey: "GEOIP_API_KEY",
		},
	}, InvalidIPAddress)
	Expect(err).To(Not(BeNil()))
}
