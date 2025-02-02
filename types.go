package traefikgeoip2

import (
	"fmt"
	"net"

	"github.com/IncSW/geoip2"
)

// Unknown constant for undefined data.
const Unknown = "XX"

// DefaultDBPath default GeoIP2 database path.
const DefaultDBPath = "GeoLite2-Country.mmdb"

const (
	// RealIPHeader real ip header.
	RealIPHeader = "X-Real-IP"
	// ContinentHeader Continent header name.
	ContinentHeader = "X-GeoIP2-Continent"
	// ContinentNameHeader Continent name header name.
	ContinentNameHeader = "X-GeoIP2-ContinentName"
	// CountryHeader country header name.
	CountryHeader = "X-GeoIP2-Country"
	// CountryNameHeader country name header name.
	CountryNameHeader = "X-GeoIP2-CountryName"
	// RegionHeader region header name.
	RegionHeader = "X-GeoIP2-Region"
	// CityHeader city header name.
	CityHeader = "X-GeoIP2-City"
)

// GeoIPResult GeoIPResult.
type GeoIPResult struct {
	continent     	string
	continentName	string
	country     	string
	countryName 	string
	region      	string
	city        	string
}

// LookupGeoIP2 LookupGeoIP2.
type LookupGeoIP2 func(ip net.IP) (*GeoIPResult, error)

// CreateCityDBLookup CreateCityDBLookup.
func CreateCityDBLookup(rdr *geoip2.CityReader) LookupGeoIP2 {
	return func(ip net.IP) (*GeoIPResult, error) {
		rec, err := rdr.Lookup(ip)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		retval := GeoIPResult{
			continent:   	rec.Continent.Code,
			continentName:  rec.Continent.Names["en"],
			country:     	rec.Country.ISOCode,
			countryName: 	rec.Country.Names["en"],
			region:      	Unknown,
			city:        	rec.City.Names["en"],
		}
		if rec.Subdivisions != nil {
			retval.region = rec.Subdivisions[0].ISOCode
		}
		return &retval, nil
	}
}

// CreateCountryDBLookup CreateCountryDBLookup.
func CreateCountryDBLookup(rdr *geoip2.CountryReader) LookupGeoIP2 {
	return func(ip net.IP) (*GeoIPResult, error) {
		rec, err := rdr.Lookup(ip)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		retval := GeoIPResult{
			continent:   	rec.Continent.Code,
			continentName:  rec.Continent.Names["en"],
			country:     	rec.Country.ISOCode,
			countryName: 	rec.Country.Names["en"],
			region:      	Unknown,
			city:        	Unknown,
		}
		return &retval, nil
	}
}
