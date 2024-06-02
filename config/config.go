package config

import (
	"encoding/json"
)

type Config struct {
	Server           string   `json:"server"`
	CertPath         string   `json:"cert_path"`
	PrivateKey       string   `json:"private_key"`
	Password         string   `json:"password"`
	ALPN             []string `json:"alpn"`
	ZeroRTTHandshake bool     `json:"zero_rtt_handshake"`
	AuthTimeout      int      `json:"auth_timeout"`
	MaxIdleTime      int      `json:"max_idle_time"`
	MaxPacketSize    uint32   `json:"max_packet_size"`
}

func (c *Config) Unmarshal(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *Config) SetDefaults() {
	c.Server = "127.0.0.1:8888"
	c.CertPath = "cert/cert.pem"
	c.PrivateKey = "cert/key.pem"
	c.Password = "0dcd8b80-603c-49dd-bfb7-61ebcfd5fbb8"
	c.ALPN = []string{"h3"}
	c.ZeroRTTHandshake = false
	c.AuthTimeout = 3
	c.MaxIdleTime = 5
}
