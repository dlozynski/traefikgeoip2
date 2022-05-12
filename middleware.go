// Package traefikgeoip2 is a Traefik plugin for Maxmind GeoIP2.
package traefikgeoip2

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/IncSW/geoip2"
)

// Headers part of the configuration
type Headers struct {
	// ContinentHeader      string `json:"ContinentHeader"`
	// ContinentNameHeader  string `json:"ContinentNameHeader"`
	Country        string `json:"country"`
	// CountryNameHeader    string `json:"CountryNameHeader"`
	// RegionHeader         string `json:"RegionHeader"`
	// CityHeader           string `json:"CityHeader"`
}

// Config the plugin configuration.
type Config struct {
	DBPath string `json:"dbPath,omitempty"`
	Headers Headers `json:"headers,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		DBPath: DefaultDBPath,
	}
}

// TraefikGeoIP2 a traefik geoip2 plugin.
type TraefikGeoIP2 struct {
	next   http.Handler
	lookup LookupGeoIP2
	name   string
	headers	Headers
}

// New created a new TraefikGeoIP2 plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if _, err := os.Stat(cfg.DBPath); err != nil {
		log.Printf("[geoip2] DB `%s' not found: %v", cfg.DBPath, err)
		return &TraefikGeoIP2{
			lookup: nil,
			next:   next,
			name:   name,
			headers: cfg.Headers,
		}, nil
	}

	var lookup LookupGeoIP2
	if strings.Contains(cfg.DBPath, "City") {
		rdr, err := geoip2.NewCityReaderFromFile(cfg.DBPath)
		if err != nil {
			log.Printf("[geoip2] DB `%s' not initialized: %v", cfg.DBPath, err)
		} else {
			lookup = CreateCityDBLookup(rdr)
		}
	}

	if strings.Contains(cfg.DBPath, "Country") {
		rdr, err := geoip2.NewCountryReaderFromFile(cfg.DBPath)
		if err != nil {
			log.Printf("[geoip2] DB `%s' not initialized: %v", cfg.DBPath, err)
		} else {
			lookup = CreateCountryDBLookup(rdr)
		}
	}

	return &TraefikGeoIP2{
		lookup: lookup,
		next:   next,
		name:   name,
		headers: cfg.Headers,
	}, nil
}

func (mw *TraefikGeoIP2) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// log.Printf("[geoip2] remoteAddr: %v, xRealIp: %v", req.RemoteAddr, req.Header.Get(RealIPHeader))

	if mw.lookup == nil {
		req.Header.Set(ContinentHeader, Unknown)
		req.Header.Set(ContinentNameHeader, Unknown)
		req.Header.Set(CountryHeader, Unknown)
		req.Header.Set(CountryNameHeader, Unknown)
		req.Header.Set(RegionHeader, Unknown)
		req.Header.Set(CityHeader, Unknown)
		mw.next.ServeHTTP(rw, req)
		return
	}

	ipStr := req.Header.Get(RealIPHeader)
	if ipStr == "" {
		ipStr = req.RemoteAddr
		tmp, _, err := net.SplitHostPort(ipStr)
		if err == nil {
			ipStr = tmp
		}
	}

	res, err := mw.lookup(net.ParseIP(ipStr))
	if err != nil {
		log.Printf("[geoip2] Unable to find for `%s', %v", ipStr, err)
		res = &GeoIPResult{
			continent:		Unknown,
			continentName:	Unknown,
			country:     	Unknown,
			countryName: 	Unknown,
			region:      	Unknown,
			city:        	Unknown,
		}
	}

	req.Header.Set(ContinentHeader, res.continent)
	req.Header.Set(ContinentNameHeader, res.continentName)
	req.Header.Set(CountryHeader, res.country)
	req.Header.Set(CountryNameHeader, res.countryName)
	req.Header.Set(RegionHeader, res.region)
	req.Header.Set(CityHeader, res.city)

	mw.addHeaders(req, res)

	mw.next.ServeHTTP(rw, req)
}

func (mw *TraefikGeoIP2) addHeaders(req *http.Request, res *GeoIPResult) {
	if mw.headers.Country != "" {
		req.Header.Add(mw.headers.Country, res.country)
	}
}