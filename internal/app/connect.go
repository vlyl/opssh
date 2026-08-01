package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/vlyl/opssh/internal/agent"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
	"github.com/vlyl/opssh/internal/sshconfig"
)

type ConnectionTestResult struct {
	Success  bool     `json:"success"`
	Category string   `json:"category"`
	Message  string   `json:"message"`
	Actions  []string `json:"actions,omitempty"`
	ExitCode int      `json:"exit_code"`
}

func (service *Service) TestConnection(ctx context.Context, alias string, interactive bool) ConnectionTestResult {
	host, err := service.Show(alias)
	if err != nil {
		return failedTest("configuration", err.Error(), -1, "Run: opssh list")
	}
	if service.Runner == nil {
		return failedTest("dependency", "OpenSSH runner is unavailable.", -1, "Install OpenSSH and run: opssh doctor")
	}
	keyPath, _ := service.Repository.Layout.PublicKey(alias)
	keyData, _, exists, err := service.Repository.Read(keyPath, 1<<20)
	if err != nil || !exists {
		return failedTest("public_key_missing", "The managed public-key file is missing.", -1, "Run: opssh sync "+alias)
	}
	if err := sshconfig.ValidatePublicKey(keyData, host.Key.Fingerprint); err != nil {
		return failedTest("public_key_mismatch", "The managed public-key file does not match the configured fingerprint.", -1, "Run: opssh sync "+alias)
	}
	configuration, err := service.load()
	if err != nil {
		return failedTest("configuration", err.Error(), -1, "Run: opssh doctor")
	}
	agentSocket, err := ExpandUserPath(service.Repository.Layout.Home, configuration.Defaults.IdentityAgent)
	if err != nil {
		return failedTest("agent_socket", "The configured SSH Agent socket path is invalid.", -1, "Run: opssh doctor")
	}
	if info, statErr := os.Stat(agentSocket); statErr != nil || info.Mode()&os.ModeSocket == 0 {
		return failedTest("agent_socket_missing", "The configured 1Password SSH Agent socket is unavailable.", -1, "Enable the 1Password SSH Agent, then run: opssh doctor")
	}
	identities, err := (agent.Inspector{Runner: service.Runner}).List(ctx, agentSocket)
	if err != nil {
		return failedTest("agent_unavailable", "Could not inspect public identities exposed by the SSH Agent.", -1, "Unlock 1Password and run: opssh doctor")
	}
	if !agent.ContainsFingerprint(identities, host.Key.Fingerprint) {
		return failedTest("agent_key_missing", "The SSH Agent does not expose the public key bound to this host.", -1, "Check 1Password SSH Agent key settings", "Run: opssh sync "+alias)
	}
	if err := service.ValidateEffectiveConfig(ctx, alias); err != nil {
		return failedTest("effective_config", err.Error(), -1, "Run: opssh config render "+alias, "Run: opssh doctor")
	}
	batchMode := "yes"
	if interactive {
		batchMode = "no"
	}
	result, runErr := service.Runner.Run(ctx, process.Request{
		Tool:        process.ToolOpenSSH,
		Args:        []string{"-o", "BatchMode=" + batchMode, "-o", "ConnectTimeout=" + ConnectTimeoutSeconds(configuration), alias, "true"},
		OutputLimit: 1 << 20,
	})
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	if runErr == nil {
		return ConnectionTestResult{Success: true, Category: "ready", Message: "SSH connection and public-key authentication succeeded.", ExitCode: 0}
	}
	return diagnoseSSHFailure(result.Stderr, result.ExitCode)
}

func ExpandUserPath(home, value string) (string, error) {
	if strings.HasPrefix(value, "~/") {
		return filepath.Join(home, strings.TrimPrefix(value, "~/")), nil
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	return "", errors.New("path must be absolute or home-relative")
}

func diagnoseSSHFailure(stderr []byte, exitCode int) ConnectionTestResult {
	text := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(text, "too many authentication failures"):
		return failedTest("too_many_authentication_failures", "SSH rejected authentication because too many Agent identities were offered.", exitCode,
			"Verify: IdentitiesOnly yes", "Verify the host has exactly one .pub IdentityFile", "Run: opssh doctor")
	case strings.Contains(text, "permission denied") && strings.Contains(text, "publickey"):
		return failedTest("public_key_rejected", "The server rejected public-key authentication.", exitCode,
			"Verify the server authorized_keys entry", "Verify the SSH username", "Unlock 1Password", "Run: opssh sync")
	case strings.Contains(text, "connection refused"):
		return failedTest("connection_refused", "The SSH endpoint refused the connection.", exitCode, "Verify hostname, port, firewall, and sshd status")
	case strings.Contains(text, "timed out"):
		return failedTest("connection_timeout", "The SSH connection timed out.", exitCode, "Verify routing, firewall, proxy, and SSH port")
	case strings.Contains(text, "no route to host"):
		return failedTest("no_route", "No network route to the SSH host is available.", exitCode, "Verify VPN, routing, and proxy settings")
	case strings.Contains(text, "host key verification failed"):
		return failedTest("host_key", "SSH host-key verification failed.", exitCode, "Inspect known_hosts and verify the server fingerprint manually")
	case strings.Contains(text, "could not resolve hostname"):
		return failedTest("dns", "The SSH hostname could not be resolved.", exitCode, "Verify hostname and DNS configuration")
	case strings.Contains(text, "proxy") || strings.Contains(text, "connection closed by unknown port"):
		return failedTest("proxy", "The configured SSH proxy failed.", exitCode, "Verify proxy availability and run: opssh doctor")
	default:
		return failedTest("ssh_failed", "SSH exited without completing the connection test.", exitCode, "Run: opssh doctor", "Run: ssh -vvv <alias>")
	}
}

func failedTest(category, message string, exitCode int, actions ...string) ConnectionTestResult {
	return ConnectionTestResult{Success: false, Category: category, Message: message, Actions: actions, ExitCode: exitCode}
}

func (service *Service) LoadConfiguration() (domain.Configuration, error) {
	return service.load()
}
