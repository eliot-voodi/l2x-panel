package dnsd

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the YAML config for l2x-dnsd.
type Config struct {
	Domain            string   `yaml:"domain"`
	Domains           []string `yaml:"domains"`
	ListenUDP         string   `yaml:"listen_udp"`
	ListenTCP         string   `yaml:"listen_tcp"`
	EncryptionMethod  int      `yaml:"encryption_method"`
	EncryptionKey     string   `yaml:"encryption_key"`
	EncryptionKeyFile string   `yaml:"encryption_key_file"`
	ProtocolType      string   `yaml:"protocol_type"`
	HealthListen      string   `yaml:"health_listen"`
	NSHostname        string   `yaml:"ns_hostname"`
	NSIP              string   `yaml:"ns_ip"`
	ConnectTimeoutSec int      `yaml:"connect_timeout_sec"`
	SessionTimeoutSec int      `yaml:"session_timeout_sec"`
	MaxSessions       int      `yaml:"max_sessions"`
	MaxStreams        int      `yaml:"max_streams_per_session"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if len(c.Domains) == 0 && c.Domain != "" {
		c.Domains = []string{c.Domain}
	}
	for i, d := range c.Domains {
		c.Domains[i] = normalizeDomain(d)
	}
	if c.Domain == "" && len(c.Domains) > 0 {
		c.Domain = c.Domains[0]
	}
	if c.ListenUDP == "" {
		c.ListenUDP = ":53"
	}
	if c.ListenTCP == "" {
		c.ListenTCP = c.ListenUDP
	}
	if c.ProtocolType == "" {
		c.ProtocolType = "SOCKS5"
	}
	if c.HealthListen == "" {
		c.HealthListen = "127.0.0.1:9111"
	}
	if c.ConnectTimeoutSec <= 0 {
		c.ConnectTimeoutSec = 30
	}
	if c.SessionTimeoutSec <= 0 {
		c.SessionTimeoutSec = 300
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 255
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 2000
	}
	if c.EncryptionKey == "" && c.EncryptionKeyFile != "" {
		if b, err := os.ReadFile(c.EncryptionKeyFile); err == nil {
			c.EncryptionKey = strings.TrimSpace(string(b))
		}
	}
}

func (c *Config) validate() error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("domain/domains required")
	}
	if c.EncryptionMethod < 0 || c.EncryptionMethod > 5 {
		return fmt.Errorf("encryption_method must be 0..5")
	}
	if c.EncryptionMethod != 0 && c.EncryptionKey == "" {
		return fmt.Errorf("encryption_key required for method %d", c.EncryptionMethod)
	}
	return nil
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	return d
}
