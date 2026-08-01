package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vlyl/opssh/internal/domain"
)

const validConfig = `version: 1
defaults:
  identity_agent: "~/.1password/agent.sock"
  connect_timeout: 10s
  server_alive_interval: 30
  server_alive_count_max: 3
hosts:
  prod-web:
    hostname: 192.0.2.10
    user: root
    port: 22
    key:
      provider: 1password
      account_id: account01
      vault_id: vault01
      item_id: item01
      title: prod-web-key
      fingerprint: SHA256:abcdefghijklmnopqrstuvwx
      public_key_file: ~/.ssh/opssh/public_keys/prod-web.pub
    proxy:
      type: socks5
      host: 127.0.0.1
      port: 7890
    options:
      identities_only: true
      strict_host_key_checking: ask
      server_alive_interval: 30
      server_alive_count_max: 3
tunnels:
  prod-postgres:
    ssh_host: prod-web
    local_host: 127.0.0.1
    local_port: 15432
    remote_host: 127.0.0.1
    remote_port: 5432
`

func TestParseValidConfig(t *testing.T) {
	t.Parallel()

	configuration, err := Parse(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if configuration.Defaults.ConnectTimeout != 10*time.Second {
		t.Fatalf("ConnectTimeout = %v", configuration.Defaults.ConnectTimeout)
	}
	host := configuration.Hosts["prod-web"]
	if !host.Options.IdentitiesOnly {
		t.Fatal("IdentitiesOnly was not preserved")
	}
	if host.Key.Reference.Provider != domain.ProviderOnePassword {
		t.Fatalf("Provider = %q", host.Key.Reference.Provider)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	t.Parallel()

	text := validConfig + "unexpected: true\n"
	if _, err := Parse(strings.NewReader(text)); err == nil {
		t.Fatal("Parse() accepted an unknown field")
	}
}

func TestParseRejectsInjectedAlias(t *testing.T) {
	t.Parallel()

	text := strings.Replace(validConfig, "prod-web:", "'../../.ssh/config':", 1)
	if _, err := Parse(strings.NewReader(text)); err == nil {
		t.Fatal("Parse() accepted a traversal alias")
	}
}

func TestParseRejectsDisabledIdentitiesOnly(t *testing.T) {
	t.Parallel()

	text := strings.Replace(validConfig, "identities_only: true", "identities_only: false", 1)
	if _, err := Parse(strings.NewReader(text)); err == nil {
		t.Fatal("Parse() accepted identities_only: false")
	}
}

func TestParseRejectsSensitiveMarkerWithoutEchoingIt(t *testing.T) {
	t.Parallel()

	marker := "-----BEGIN OPENSSH PRIVATE KEY-----"
	text := validConfig + "unsafe: '" + marker + "'\n"
	_, err := Parse(strings.NewReader(text))
	if !errors.Is(err, ErrSensitiveConfigData) {
		t.Fatalf("Parse() error = %v, want ErrSensitiveConfigData", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("Parse() leaked rejected content: %v", err)
	}
}

func TestLoadFileRejectsSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target.yaml")
	link := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(target, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(link); !errors.Is(err, ErrUnsafeConfigFile) {
		t.Fatalf("LoadFile() error = %v, want ErrUnsafeConfigFile", err)
	}
}

func TestLoadFileRejectsBroadPermissions(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX permissions are required")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("LoadFile() error = %v, want ErrInsecurePermissions", err)
	}
}

func TestDefaultAgentSocket(t *testing.T) {
	t.Parallel()

	if got := defaultAgentSocket("darwin"); !strings.Contains(got, "2BUA8C4S2C.com.1password") {
		t.Fatalf("darwin socket = %q", got)
	}
	if got := defaultAgentSocket("linux"); got != "~/.1password/agent.sock" {
		t.Fatalf("linux socket = %q", got)
	}
}
