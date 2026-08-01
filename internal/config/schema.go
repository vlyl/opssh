package config

import (
	"fmt"
	"runtime"
	"time"

	"github.com/vlyl/opssh/internal/domain"
)

type fileConfig struct {
	Version  int                   `yaml:"version"`
	Defaults fileDefaults          `yaml:"defaults"`
	Hosts    map[string]fileHost   `yaml:"hosts"`
	Tunnels  map[string]fileTunnel `yaml:"tunnels"`
}

type fileDefaults struct {
	IdentityAgent       string        `yaml:"identity_agent"`
	ConnectTimeout      durationValue `yaml:"connect_timeout"`
	ServerAliveInterval int           `yaml:"server_alive_interval"`
	ServerAliveCountMax int           `yaml:"server_alive_count_max"`
}

type fileHost struct {
	Hostname string          `yaml:"hostname"`
	User     string          `yaml:"user"`
	Port     uint16          `yaml:"port"`
	Key      fileKey         `yaml:"key"`
	Proxy    fileProxy       `yaml:"proxy"`
	Options  fileHostOptions `yaml:"options"`
}

type fileKey struct {
	Provider      domain.Provider `yaml:"provider"`
	AccountID     string          `yaml:"account_id"`
	VaultID       string          `yaml:"vault_id"`
	ItemID        string          `yaml:"item_id"`
	Title         string          `yaml:"title"`
	Fingerprint   string          `yaml:"fingerprint"`
	PublicKeyFile string          `yaml:"public_key_file"`
	LastSyncedAt  string          `yaml:"last_synced_at"`
}

type fileProxy struct {
	Type     domain.ProxyType `yaml:"type"`
	Host     string           `yaml:"host"`
	Port     uint16           `yaml:"port"`
	JumpHost string           `yaml:"jump_host"`
}

type fileHostOptions struct {
	IdentitiesOnly        *bool                  `yaml:"identities_only"`
	StrictHostKeyChecking domain.HostKeyChecking `yaml:"strict_host_key_checking"`
	ServerAliveInterval   int                    `yaml:"server_alive_interval"`
	ServerAliveCountMax   int                    `yaml:"server_alive_count_max"`
}

type fileTunnel struct {
	SSHHost    string `yaml:"ssh_host"`
	LocalHost  string `yaml:"local_host"`
	LocalPort  uint16 `yaml:"local_port"`
	RemoteHost string `yaml:"remote_host"`
	RemotePort uint16 `yaml:"remote_port"`
	Reconnect  bool   `yaml:"reconnect"`
}

type durationValue struct {
	time.Duration
}

func (value *durationValue) UnmarshalYAML(unmarshal func(any) error) error {
	var text string
	if err := unmarshal(&text); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration")
	}
	value.Duration = parsed
	return nil
}

func defaultAgentSocket(goos string) string {
	if goos == "darwin" {
		return "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
	}
	return "~/.1password/agent.sock"
}

func defaultsForCurrentOS() domain.Defaults {
	return domain.Defaults{
		IdentityAgent:       defaultAgentSocket(runtime.GOOS),
		ConnectTimeout:      10 * time.Second,
		ServerAliveInterval: 30,
		ServerAliveCountMax: 3,
	}
}
