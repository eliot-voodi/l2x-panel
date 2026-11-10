package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Tunnel struct {
	PSK             string `yaml:"psk"`
	ListenUDP       string `yaml:"listen_udp"`
	PeerUDP         string `yaml:"peer_udp"`
	PathCount       int    `yaml:"path_count"`
	Cipher          string `yaml:"cipher"`
	PunchTimeoutMS  int    `yaml:"punch_timeout_ms"`
	PunchIntervalSec int   `yaml:"punch_interval_sec"`
	MaxStreams      int    `yaml:"max_streams"`
	MaxMbps         int    `yaml:"max_mbps"`
	Token           string `yaml:"token"`
	NodeID          string `yaml:"node_id"`
}

type Metrics struct {
	Listen string `yaml:"listen"`
}

type Config struct {
	Role      string  `yaml:"role"` // agent | portal
	MasterURL string  `yaml:"master_url"`
	Tunnel    Tunnel  `yaml:"tunnel"`
	Metrics   Metrics `yaml:"metrics"`
	// Portal: local TCP proxy that opens streams to agent (host:port to dial on agent side)
	ProxyListen string `yaml:"proxy_listen"`
	// Portal: SOCKS5 for Xray node_* egress (dynamic dial via tunnel)
	SocksListen string `yaml:"socks_listen"`
	// Transport: "wss" (default camouflage over HTTPS) | "udp" (lab / legacy)
	Transport string `yaml:"transport"`
	// Portal: local WS listen (nginx proxies public /ws-… → here)
	WSListen string `yaml:"ws_listen"`
	WSPath   string `yaml:"ws_path"`
	// Agent: full wss://master/ws-… URL (HTTPS camouflage)
	WSURL string `yaml:"ws_url"`
	// Agent default dial target if OPEN payload empty (lab)
	DefaultDial string `yaml:"default_dial"`
}

func Defaults(role string) *Config {
	c := &Config{
		Role: role,
		Tunnel: Tunnel{
			ListenUDP:        "0.0.0.0:4443",
			PathCount:        8,
			Cipher:           "chacha20poly1305",
			PunchTimeoutMS:   2500,
			PunchIntervalSec: 60,
			MaxStreams:       4000,
		},
		Metrics:     Metrics{Listen: "127.0.0.1:9109"},
		ProxyListen: "127.0.0.1:18080",
		SocksListen: "127.0.0.1:11080",
		Transport:   "wss",
		WSListen:    "127.0.0.1:11081",
		WSPath:      "/ws-l2x-tunnel",
		DefaultDial: "",
	}
	if role == "agent" {
		c.Tunnel.ListenUDP = "0.0.0.0:0"
	}
	return c
}

func Load(path string, role string) (*Config, error) {
	c := Defaults(role)
	if path == "" {
		applyEnv(c)
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.Role == "" {
		c.Role = role
	}
	applyEnv(c)
	if c.Tunnel.PathCount < 1 {
		c.Tunnel.PathCount = 1
	}
	if c.Tunnel.PathCount > 16 {
		c.Tunnel.PathCount = 16
	}
	if c.Tunnel.PSK == "" {
		return nil, fmt.Errorf("tunnel.psk is required")
	}
	if c.Tunnel.Token == "" {
		c.Tunnel.Token = os.Getenv("L2X_TUNNEL_TOKEN")
	}
	return c, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("L2X_TUNNEL_MASTER_URL"); v != "" {
		c.MasterURL = v
	}
	if v := os.Getenv("L2X_TUNNEL_TOKEN"); v != "" {
		c.Tunnel.Token = v
	}
	if v := os.Getenv("L2X_TUNNEL_PSK"); v != "" {
		c.Tunnel.PSK = v
	}
	if v := os.Getenv("L2X_TUNNEL_PEER"); v != "" {
		c.Tunnel.PeerUDP = v
	}
	if v := os.Getenv("L2X_TUNNEL_LISTEN"); v != "" {
		c.Tunnel.ListenUDP = v
	}
	if v := os.Getenv("L2X_TUNNEL_CIPHER"); v != "" {
		c.Tunnel.Cipher = v
	}
	if v := os.Getenv("L2X_TUNNEL_PROXY"); v != "" {
		c.ProxyListen = v
	}
	if v := os.Getenv("L2X_TUNNEL_SOCKS"); v != "" {
		c.SocksListen = v
	}
	if v := os.Getenv("L2X_TUNNEL_TRANSPORT"); v != "" {
		c.Transport = v
	}
	if v := os.Getenv("L2X_TUNNEL_WS_URL"); v != "" {
		c.WSURL = v
	}
	if v := os.Getenv("L2X_TUNNEL_WS_LISTEN"); v != "" {
		c.WSListen = v
	}
	if v := os.Getenv("L2X_TUNNEL_WS_PATH"); v != "" {
		c.WSPath = v
	}
}
