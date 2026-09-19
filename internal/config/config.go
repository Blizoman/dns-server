// Package config loads the DNS server's configuration from a YAML or JSON
// file: the address to listen on and the set of domain -> IP mappings the
// server answers authoritatively for.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultTTL is used for a record when its config entry does not set one.
const DefaultTTL = 300

// Record is a single domain -> IP mapping.
type Record struct {
	Domain string `yaml:"domain" json:"domain"`
	IP     string `yaml:"ip" json:"ip"`
	TTL    uint32 `yaml:"ttl" json:"ttl"`
}

// Config is the top-level server configuration.
type Config struct {
	// Listen is the UDP address (host:port) the server binds to.
	Listen string `yaml:"listen" json:"listen"`
	// DefaultTTL is applied to records that don't specify their own TTL.
	DefaultTTL uint32 `yaml:"default_ttl" json:"default_ttl"`
	// Records is the list of configured domain -> IP mappings.
	Records []Record `yaml:"records" json:"records"`
}

// Load reads and parses the configuration file at path. The format (YAML or
// JSON) is chosen from the file extension: .json is parsed as JSON, and
// anything else (.yaml, .yml, or no extension) is parsed as YAML.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	var cfg Config
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("config: parsing JSON %s: %w", path, err)
		}
	default:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("config: parsing YAML %s: %w", path, err)
		}
	}

	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	return &cfg, nil
}

// normalizeAndValidate fills in defaults and checks the configuration for
// obvious mistakes, returning an error describing the first one found.
func (c *Config) normalizeAndValidate() error {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8053"
	}
	if c.DefaultTTL == 0 {
		c.DefaultTTL = DefaultTTL
	}
	if len(c.Records) == 0 {
		return fmt.Errorf("no records configured")
	}

	for i := range c.Records {
		r := &c.Records[i]
		if r.Domain == "" {
			return fmt.Errorf("record %d: missing domain", i)
		}
		if net.ParseIP(r.IP) == nil || net.ParseIP(r.IP).To4() == nil {
			return fmt.Errorf("record %d (%s): invalid IPv4 address %q", i, r.Domain, r.IP)
		}
		r.Domain = normalizeDomain(r.Domain)
		if r.TTL == 0 {
			r.TTL = c.DefaultTTL
		}
	}

	return nil
}

// normalizeDomain lower-cases a domain and strips any trailing dot so that
// lookups are consistent regardless of how the domain was written in the
// query or the config file.
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// Lookup builds a map from normalized domain name to Record for fast
// resolution by the server.
func (c *Config) Lookup() map[string]Record {
	m := make(map[string]Record, len(c.Records))
	for _, r := range c.Records {
		m[r.Domain] = r
	}
	return m
}
