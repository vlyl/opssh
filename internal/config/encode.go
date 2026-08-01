package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/vlyl/opssh/internal/domain"
	"gopkg.in/yaml.v3"
)

func Encode(configuration domain.Configuration) ([]byte, error) {
	if err := Validate(configuration); err != nil {
		return nil, fmt.Errorf("validate configuration before encoding: %w", err)
	}
	raw := fileConfig{
		Version: configuration.Version,
		Defaults: fileDefaults{
			IdentityAgent:       configuration.Defaults.IdentityAgent,
			ConnectTimeout:      durationValue{Duration: configuration.Defaults.ConnectTimeout},
			ServerAliveInterval: configuration.Defaults.ServerAliveInterval,
			ServerAliveCountMax: configuration.Defaults.ServerAliveCountMax,
		},
		Hosts:   make(map[string]fileHost, len(configuration.Hosts)),
		Tunnels: make(map[string]fileTunnel, len(configuration.Tunnels)),
	}
	for alias, host := range configuration.Hosts {
		identitiesOnly := host.Options.IdentitiesOnly
		raw.Hosts[alias] = fileHost{
			Hostname: host.Hostname, User: host.User, Port: host.Port,
			Key: fileKey{
				Provider: host.Key.Reference.Provider, AccountID: host.Key.Reference.AccountID,
				VaultID: host.Key.Reference.VaultID, ItemID: host.Key.Reference.ItemID,
				Title: host.Key.Title, Fingerprint: host.Key.Fingerprint,
				PublicKeyFile: host.Key.PublicKeyFile, LastSyncedAt: formatOptionalTime(host.Key.LastSyncedAt),
			},
			Proxy: fileProxy{Type: host.Proxy.Type, Host: host.Proxy.Host, Port: host.Proxy.Port, JumpHost: host.Proxy.JumpHost},
			Options: fileHostOptions{
				IdentitiesOnly: &identitiesOnly, StrictHostKeyChecking: host.Options.StrictHostKeyChecking,
				ServerAliveInterval: host.Options.ServerAliveInterval, ServerAliveCountMax: host.Options.ServerAliveCountMax,
			},
		}
	}
	for name, tunnel := range configuration.Tunnels {
		raw.Tunnels[name] = fileTunnel{
			SSHHost: tunnel.SSHHost, LocalHost: tunnel.LocalHost, LocalPort: tunnel.LocalPort,
			RemoteHost: tunnel.RemoteHost, RemotePort: tunnel.RemotePort, Reconnect: tunnel.Reconnect,
		}
	}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, errors.New("could not encode YAML configuration")
	}
	return data, nil
}

func (value durationValue) MarshalYAML() (any, error) {
	if value.Duration <= 0 {
		return nil, errors.New("duration must be positive")
	}
	return value.String(), nil
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
