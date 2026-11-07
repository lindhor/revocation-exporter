package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	// Interval between checks. Results are cached between checks: a scrape
	// never triggers a download, so a slow CRL server cannot stall Prometheus.
	Interval Duration `yaml:"interval"`
	// Timeout for one fetch (CRL download, OCSP request, TLS handshake).
	Timeout Duration `yaml:"timeout"`
	// MaxCRLBytes caps one CRL download. Large public CAs publish CRLs of
	// tens of MB; the default (64 MiB) leaves room for those.
	MaxCRLBytes int64 `yaml:"max_crl_bytes"`

	CRLs         []CRLSource  `yaml:"crls"`
	Certificates []CertSource `yaml:"certificates"`

	// FollowCRLDP: for every certificate source, fetch the CRLs its
	// CRL Distribution Points name (and check the certificate against them).
	FollowCRLDP *bool `yaml:"follow_crl_distribution_points"`
	// CheckOCSP: for every certificate source, ask the OCSP responders its
	// Authority Information Access names.
	CheckOCSP *bool `yaml:"check_ocsp"`
}

// CRLSource is one CRL to watch: an http(s) URL or a file (PEM or DER).
type CRLSource struct {
	URL  string `yaml:"url"`
	File string `yaml:"file"`
	// Issuer is an optional PEM file holding the CRL issuer's certificate.
	// With it the CRL's signature is verified; without it
	// revocation_crl_signature_valid is not emitted for this CRL.
	Issuer string `yaml:"issuer"`
}

// CertSource is a certificate chain to check for revocation: a PEM file
// (leaf first, then its issuer) or a TLS endpoint (host:port).
type CertSource struct {
	File string `yaml:"file"`
	TLS  string `yaml:"tls"`
	// ServerName overrides SNI for a TLS source (default: the host part).
	ServerName string `yaml:"server_name"`
	// Issuer is an optional PEM file with the leaf's issuer, for a file
	// source that holds only the leaf.
	Issuer string `yaml:"issuer"`
}

// Duration is a time.Duration that reads "30s", "5m" from YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (c *Config) followCRLDP() bool { return c.FollowCRLDP == nil || *c.FollowCRLDP }
func (c *Config) checkOCSP() bool   { return c.CheckOCSP == nil || *c.CheckOCSP }

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true) // a misspelt key is an error, not a silently ignored setting
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Interval == 0 {
		c.Interval = Duration(5 * time.Minute)
	}
	if c.Timeout == 0 {
		c.Timeout = Duration(15 * time.Second)
	}
	if c.MaxCRLBytes == 0 {
		c.MaxCRLBytes = 64 << 20
	}
	if time.Duration(c.Interval) < 10*time.Second {
		return nil, errors.New("interval must be at least 10s")
	}
	if len(c.CRLs) == 0 && len(c.Certificates) == 0 {
		return nil, errors.New("nothing to watch: configure crls and/or certificates")
	}
	for i, s := range c.CRLs {
		if (s.URL == "") == (s.File == "") {
			return nil, fmt.Errorf("crls[%d]: set exactly one of url or file", i)
		}
	}
	for i, s := range c.Certificates {
		if (s.File == "") == (s.TLS == "") {
			return nil, fmt.Errorf("certificates[%d]: set exactly one of file or tls", i)
		}
	}
	return c, nil
}
