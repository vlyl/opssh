package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/security"
	"gopkg.in/yaml.v3"
)

const MaxConfigBytes int64 = 1 << 20

var (
	ErrConfigTooLarge      = errors.New("configuration exceeds size limit")
	ErrInsecurePermissions = errors.New("configuration permissions are too broad")
	ErrUnsafeConfigFile    = errors.New("configuration path is not a regular file")
	ErrSensitiveConfigData = errors.New("configuration was rejected by the security policy")
)

func New() domain.Configuration {
	return domain.Configuration{
		Version:  domain.CurrentConfigVersion,
		Defaults: defaultsForCurrentOS(),
		Hosts:    make(map[string]domain.Host),
		Tunnels:  make(map[string]domain.Tunnel),
	}
}

func LoadFile(path string) (configuration domain.Configuration, returnErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return domain.Configuration{}, fmt.Errorf("inspect configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return domain.Configuration{}, ErrUnsafeConfigFile
	}
	if info.Mode().Perm()&0o077 != 0 {
		return domain.Configuration{}, ErrInsecurePermissions
	}

	// #nosec G304 -- the path is checked with Lstat before opening and the
	// opened descriptor is matched to that exact regular file before parsing.
	file, err := os.Open(path)
	if err != nil {
		return domain.Configuration{}, fmt.Errorf("open configuration: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, file.Close())
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return domain.Configuration{}, fmt.Errorf("inspect opened configuration: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return domain.Configuration{}, ErrUnsafeConfigFile
	}

	configuration, err = Parse(file)
	if err != nil {
		return domain.Configuration{}, fmt.Errorf("parse configuration: %w", err)
	}
	return configuration, nil
}

func Parse(reader io.Reader) (domain.Configuration, error) {
	limited := io.LimitReader(reader, MaxConfigBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return domain.Configuration{}, fmt.Errorf("read configuration: %w", err)
	}
	if int64(len(data)) > MaxConfigBytes {
		return domain.Configuration{}, ErrConfigTooLarge
	}
	defer security.Wipe(data)
	if security.ContainsSensitiveMarker(data) {
		return domain.Configuration{}, ErrSensitiveConfigData
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var raw fileConfig
	if err := decoder.Decode(&raw); err != nil {
		return domain.Configuration{}, fmt.Errorf("decode YAML: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return domain.Configuration{}, errors.New("configuration must contain one YAML document")
		}
		return domain.Configuration{}, fmt.Errorf("decode trailing YAML: %w", err)
	}

	configuration, err := raw.toDomain()
	if err != nil {
		return domain.Configuration{}, err
	}
	if err := Validate(configuration); err != nil {
		return domain.Configuration{}, err
	}
	return configuration, nil
}

func (raw fileConfig) toDomain() (domain.Configuration, error) {
	defaults := defaultsForCurrentOS()
	if raw.Defaults.IdentityAgent != "" {
		defaults.IdentityAgent = raw.Defaults.IdentityAgent
	}
	if raw.Defaults.ConnectTimeout.Duration != 0 {
		defaults.ConnectTimeout = raw.Defaults.ConnectTimeout.Duration
	}
	if raw.Defaults.ServerAliveInterval != 0 {
		defaults.ServerAliveInterval = raw.Defaults.ServerAliveInterval
	}
	if raw.Defaults.ServerAliveCountMax != 0 {
		defaults.ServerAliveCountMax = raw.Defaults.ServerAliveCountMax
	}

	configuration := domain.Configuration{
		Version:  raw.Version,
		Defaults: defaults,
		Hosts:    make(map[string]domain.Host, len(raw.Hosts)),
		Tunnels:  make(map[string]domain.Tunnel, len(raw.Tunnels)),
	}
	for alias, source := range raw.Hosts {
		lastSyncedAt, err := parseOptionalTime(source.Key.LastSyncedAt)
		if err != nil {
			return domain.Configuration{}, fmt.Errorf("host %q last_synced_at: %w", alias, err)
		}
		identitiesOnly := true
		if source.Options.IdentitiesOnly != nil {
			identitiesOnly = *source.Options.IdentitiesOnly
		}
		proxyType := source.Proxy.Type
		if proxyType == "" {
			proxyType = domain.ProxyNone
		}
		strictHostKeyChecking := source.Options.StrictHostKeyChecking
		if strictHostKeyChecking == "" {
			strictHostKeyChecking = domain.HostKeyCheckingAsk
		}
		serverAliveInterval := source.Options.ServerAliveInterval
		if serverAliveInterval == 0 {
			serverAliveInterval = defaults.ServerAliveInterval
		}
		serverAliveCountMax := source.Options.ServerAliveCountMax
		if serverAliveCountMax == 0 {
			serverAliveCountMax = defaults.ServerAliveCountMax
		}
		configuration.Hosts[alias] = domain.Host{
			Alias: alias, Hostname: source.Hostname, User: source.User, Port: source.Port,
			Key: domain.KeyBinding{
				Reference: domain.KeyReference{Provider: source.Key.Provider, AccountID: source.Key.AccountID, VaultID: source.Key.VaultID, ItemID: source.Key.ItemID},
				Title:     source.Key.Title, Fingerprint: source.Key.Fingerprint, PublicKeyFile: source.Key.PublicKeyFile, LastSyncedAt: lastSyncedAt,
			},
			Proxy: domain.Proxy{Type: proxyType, Host: source.Proxy.Host, Port: source.Proxy.Port, JumpHost: source.Proxy.JumpHost},
			Options: domain.HostOptions{
				IdentitiesOnly: identitiesOnly, StrictHostKeyChecking: strictHostKeyChecking,
				ServerAliveInterval: serverAliveInterval, ServerAliveCountMax: serverAliveCountMax,
			},
		}
	}
	for name, source := range raw.Tunnels {
		configuration.Tunnels[name] = domain.Tunnel{
			Name: name, SSHHost: source.SSHHost, LocalHost: source.LocalHost, LocalPort: source.LocalPort,
			RemoteHost: source.RemoteHost, RemotePort: source.RemotePort, Reconnect: source.Reconnect,
		}
	}
	return configuration, nil
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func Validate(configuration domain.Configuration) error {
	if configuration.Version != domain.CurrentConfigVersion {
		return fmt.Errorf("unsupported configuration version %d", configuration.Version)
	}
	if err := security.ValidateConfigPathText(configuration.Defaults.IdentityAgent); err != nil {
		return fmt.Errorf("defaults.identity_agent: %w", err)
	}
	if configuration.Defaults.ConnectTimeout <= 0 || configuration.Defaults.ConnectTimeout > 10*time.Minute {
		return errors.New("defaults.connect_timeout must be between zero and ten minutes")
	}
	if err := validateKeepalive("defaults", configuration.Defaults.ServerAliveInterval, configuration.Defaults.ServerAliveCountMax); err != nil {
		return err
	}
	for alias, host := range configuration.Hosts {
		if err := validateHost(alias, host); err != nil {
			return fmt.Errorf("host %q: %w", alias, err)
		}
	}
	if err := validateProxyJumpGraph(configuration.Hosts); err != nil {
		return err
	}
	for name, tunnel := range configuration.Tunnels {
		if err := validateTunnel(name, tunnel, configuration.Hosts); err != nil {
			return fmt.Errorf("tunnel %q: %w", name, err)
		}
	}
	return nil
}

func validateHost(alias string, host domain.Host) error {
	if err := security.ValidateAlias(alias); err != nil {
		return err
	}
	if host.Alias != alias {
		return errors.New("alias does not match map key")
	}
	if err := security.ValidateHostname(host.Hostname); err != nil {
		return err
	}
	if err := security.ValidateUsername(host.User); err != nil {
		return err
	}
	if host.Port == 0 {
		return errors.New("port must be between 1 and 65535")
	}
	if host.Key.Reference.Provider != domain.ProviderOnePassword {
		return errors.New("key provider must be 1password")
	}
	if err := security.ValidateIdentifier("account ID", host.Key.Reference.AccountID, true); err != nil {
		return err
	}
	if err := security.ValidateIdentifier("vault ID", host.Key.Reference.VaultID, false); err != nil {
		return err
	}
	if err := security.ValidateIdentifier("item ID", host.Key.Reference.ItemID, false); err != nil {
		return err
	}
	if err := security.ValidateDisplayText("item title", host.Key.Title, 256, false); err != nil {
		return err
	}
	if err := security.ValidateFingerprint(host.Key.Fingerprint, true); err != nil {
		return err
	}
	if err := security.ValidateConfigPathText(host.Key.PublicKeyFile); err != nil {
		return err
	}
	expectedPublicKeyFile := "~/.ssh/opssh/public_keys/" + alias + ".pub"
	if host.Key.PublicKeyFile != expectedPublicKeyFile {
		return errors.New("public_key_file must reference the host's opssh-managed public key")
	}
	if !host.Options.IdentitiesOnly {
		return errors.New("identities_only must be true")
	}
	switch host.Options.StrictHostKeyChecking {
	case domain.HostKeyCheckingAsk, domain.HostKeyCheckingYes, domain.HostKeyCheckingAccept:
	default:
		return errors.New("unsupported strict_host_key_checking value")
	}
	if err := validateKeepalive("host options", host.Options.ServerAliveInterval, host.Options.ServerAliveCountMax); err != nil {
		return err
	}
	return validateProxy(host.Proxy)
}

// ValidateHost validates a host record without resolving cross-host references.
// Full configurations must use Validate so ProxyJump targets and cycles are checked.
func ValidateHost(alias string, host domain.Host) error {
	return validateHost(alias, host)
}

func validateProxyJumpGraph(hosts map[string]domain.Host) error {
	const (
		unvisited uint8 = iota
		visiting
		visited
	)
	state := make(map[string]uint8, len(hosts))
	var visit func(string) error
	visit = func(alias string) error {
		switch state[alias] {
		case visiting:
			return fmt.Errorf("host %q: ProxyJump cycle detected", alias)
		case visited:
			return nil
		}
		state[alias] = visiting
		host := hosts[alias]
		if host.Proxy.Type == domain.ProxyJump {
			target := host.Proxy.JumpHost
			if target == alias {
				return fmt.Errorf("host %q: ProxyJump cannot reference itself", alias)
			}
			if _, exists := hosts[target]; !exists {
				return fmt.Errorf("host %q: ProxyJump target %q does not exist", alias, target)
			}
			if err := visit(target); err != nil {
				return err
			}
		}
		state[alias] = visited
		return nil
	}
	for alias := range hosts {
		if state[alias] == unvisited {
			if err := visit(alias); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProxy(proxy domain.Proxy) error {
	switch proxy.Type {
	case domain.ProxyNone:
		if proxy.Host != "" || proxy.Port != 0 || proxy.JumpHost != "" {
			return errors.New("none proxy cannot contain proxy settings")
		}
	case domain.ProxySOCKS5, domain.ProxyHTTPConnect:
		if err := security.ValidateHostname(proxy.Host); err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
		if proxy.Port == 0 || proxy.JumpHost != "" {
			return errors.New("network proxy requires a port and cannot contain jump_host")
		}
	case domain.ProxyJump:
		if err := security.ValidateAlias(proxy.JumpHost); err != nil {
			return fmt.Errorf("proxy jump: %w", err)
		}
		if proxy.Host != "" || proxy.Port != 0 {
			return errors.New("jump proxy cannot contain host or port")
		}
	default:
		return errors.New("unsupported proxy type")
	}
	return nil
}

func validateTunnel(name string, tunnel domain.Tunnel, hosts map[string]domain.Host) error {
	if err := security.ValidateAlias(name); err != nil {
		return err
	}
	if tunnel.Name != name {
		return errors.New("name does not match map key")
	}
	if err := security.ValidateAlias(tunnel.SSHHost); err != nil {
		return fmt.Errorf("SSH host: %w", err)
	}
	if _, exists := hosts[tunnel.SSHHost]; !exists {
		return errors.New("SSH host does not exist")
	}
	localHost := tunnel.LocalHost
	if strings.HasPrefix(localHost, "[") && strings.HasSuffix(localHost, "]") && strings.Count(localHost, "[") == 1 && strings.Count(localHost, "]") == 1 {
		localHost = localHost[1 : len(localHost)-1]
	}
	localIP := net.ParseIP(localHost)
	if localIP == nil {
		return errors.New("local_host must be an IP address")
	}
	if tunnel.LocalPort == 0 || tunnel.RemotePort == 0 {
		return errors.New("tunnel ports must be between 1 and 65535")
	}
	if err := security.ValidateHostname(tunnel.RemoteHost); err != nil {
		return fmt.Errorf("remote host: %w", err)
	}
	return nil
}

func validateKeepalive(scope string, interval, count int) error {
	if interval < 0 || interval > 86400 || count < 0 || count > 1000 {
		return fmt.Errorf("%s keepalive values are outside supported limits", scope)
	}
	return nil
}
