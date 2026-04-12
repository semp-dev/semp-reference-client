// Package config provides TOML-based configuration for the SEMP reference client.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds the client configuration.
type Config struct {
	// Identity is the user's SEMP address (e.g. "alice@example.com").
	Identity string `toml:"identity"`

	// Domain is the user's home domain (e.g. "example.com").
	Domain string `toml:"domain"`

	// Server is the WebSocket endpoint of the home server.
	Server string `toml:"server"`

	Database DatabaseConfig `toml:"database"`
	TLS      TLSConfig      `toml:"tls"`
}

// DatabaseConfig holds database settings.
type DatabaseConfig struct {
	Path string `toml:"path"`
}

// TLSConfig holds TLS settings.
type TLSConfig struct {
	// Insecure allows plaintext ws:// connections (for development).
	Insecure bool `toml:"insecure"`
}

// Load reads and validates a TOML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	// Apply defaults.
	if cfg.Database.Path == "" {
		cfg.Database.Path = "semp-client.db"
	}

	// Validate.
	if cfg.Identity == "" {
		return nil, fmt.Errorf("config: identity is required")
	}
	if !strings.Contains(cfg.Identity, "@") {
		return nil, fmt.Errorf("config: identity must be a valid address (user@domain)")
	}
	if cfg.Domain == "" {
		// Derive from identity.
		parts := strings.SplitN(cfg.Identity, "@", 2)
		cfg.Domain = parts[1]
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("config: server endpoint is required")
	}

	return &cfg, nil
}
