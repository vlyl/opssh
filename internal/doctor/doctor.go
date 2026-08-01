package doctor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vlyl/opssh/internal/agent"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
	"github.com/vlyl/opssh/internal/sshconfig"
)

type ProviderChecker interface {
	Check(ctx context.Context) error
}

type Doctor struct {
	Service  *app.Service
	Runner   *process.Runner
	Resolver process.Resolver
	Provider ProviderChecker
	Keys     domain.PublicKeyProvider
}

func (doctor Doctor) Run(ctx context.Context) []domain.DoctorFinding {
	findings := []domain.DoctorFinding{{Level: domain.FindingInfo, Code: "operating_system", Message: runtime.GOOS + "/" + runtime.GOARCH}}
	if doctor.Resolver == nil {
		doctor.Resolver = process.PATHResolver{}
	}
	sshAvailable := doctor.toolChecks(ctx, &findings)
	if doctor.Service == nil {
		return append(findings, fail("service", "opssh application service is unavailable", "Reinstall opssh"))
	}
	configuration, err := doctor.Service.LoadConfiguration()
	if err != nil {
		return append(findings, fail("configuration", "opssh configuration could not be loaded safely", "Fix configuration permissions or YAML syntax"))
	}
	if err := config.Validate(configuration); err != nil {
		findings = append(findings, fail("config_injection", "Configuration validation failed", "Run: opssh config validate"))
	} else {
		findings = append(findings, pass("config_injection", "Configuration fields passed injection validation"))
	}

	layout := doctor.Service.Repository.Layout
	agentSocket, socketErr := app.ExpandUserPath(layout.Home, configuration.Defaults.IdentityAgent)
	socketReady := false
	if socketErr != nil {
		findings = append(findings, fail("agent_socket_exists", "Agent socket path is invalid", "Set defaults.identity_agent to an absolute or ~/ path"))
		findings = append(findings, fail("agent_socket_connect", "Agent socket could not be checked", "Fix the Agent socket path"))
	} else if info, statErr := os.Stat(agentSocket); statErr != nil || info.Mode()&os.ModeSocket == 0 {
		findings = append(findings, fail("agent_socket_exists", "1Password SSH Agent socket is unavailable", "Enable the SSH Agent in 1Password"))
		findings = append(findings, fail("agent_socket_connect", "1Password SSH Agent socket is not connectable", "Unlock 1Password and verify the socket path"))
	} else {
		findings = append(findings, pass("agent_socket_exists", "1Password SSH Agent socket exists"))
		connection, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", agentSocket)
		if dialErr != nil {
			findings = append(findings, fail("agent_socket_connect", "1Password SSH Agent socket did not accept a connection", "Unlock or restart 1Password"))
		} else {
			_ = connection.Close()
			socketReady = true
			findings = append(findings, pass("agent_socket_connect", "1Password SSH Agent socket accepted a connection"))
		}
	}

	var identities []agent.PublicIdentity
	if socketReady && doctor.Runner != nil {
		identities, err = (agent.Inspector{Runner: doctor.Runner}).List(ctx, agentSocket)
		if err != nil {
			findings = append(findings, fail("agent_key_count", "Agent public identities could not be listed", "Unlock 1Password and check Agent settings"))
		} else {
			findings = append(findings, pass("agent_key_count", fmt.Sprintf("Agent exposes %d public identities", len(identities))))
		}
	} else {
		findings = append(findings, warn("agent_key_count", "Agent public identities were not inspected", "Restore the Agent socket and rerun doctor"))
	}

	findings = append(findings, doctor.includeCheck(layout.SSHConfig)...)
	findings = append(findings, permissionCheck("ssh_config_permissions", layout.SSHConfig, 0o077))
	findings = append(findings, permissionCheck("opssh_config_permissions", layout.ConfigFile, 0o077))
	findings = append(findings, doctor.hostChecks(ctx, configuration, identities, sshAvailable)...)
	findings = append(findings, proxyCheck(configuration, doctor.Resolver))
	findings = append(findings, duplicateHostCheck(doctor.Service.Repository, layout.SSHConfigDir))
	findings = append(findings, tunnelPortCheck(configuration))
	return findings
}

func (doctor Doctor) toolChecks(ctx context.Context, findings *[]domain.DoctorFinding) bool {
	sshAvailable := false
	if _, err := doctor.Resolver.Resolve(process.ToolOpenSSH); err != nil {
		*findings = append(*findings, fail("ssh_installed", "OpenSSH client was not found", "Install OpenSSH"))
		*findings = append(*findings, warn("ssh_version", "OpenSSH version was not checked", "Install OpenSSH"))
	} else {
		sshAvailable = true
		*findings = append(*findings, pass("ssh_installed", "OpenSSH client is available"))
		if doctor.Runner != nil {
			result, runErr := doctor.Runner.Run(ctx, process.Request{Tool: process.ToolOpenSSH, Args: []string{"-V"}, OutputLimit: 64 << 10})
			security.Wipe(result.Stdout)
			security.Wipe(result.Stderr)
			if runErr != nil {
				*findings = append(*findings, warn("ssh_version", "OpenSSH version could not be read", "Run: ssh -V"))
			} else {
				*findings = append(*findings, pass("ssh_version", "OpenSSH version command succeeded"))
			}
		}
	}
	if _, err := doctor.Resolver.Resolve(process.ToolOnePassword); err != nil {
		*findings = append(*findings, fail("op_installed", "1Password CLI was not found", "Install 1Password CLI v2"))
		*findings = append(*findings, warn("op_usable", "1Password CLI login was not checked", "Install and sign in to 1Password CLI"))
	} else {
		*findings = append(*findings, pass("op_installed", "1Password CLI is available"))
		if doctor.Provider != nil {
			if err := doctor.Provider.Check(ctx); err != nil {
				*findings = append(*findings, fail("op_usable", "1Password CLI is unavailable or incompatible", "Sign in with op and use a supported v2 CLI"))
			} else {
				*findings = append(*findings, pass("op_usable", "1Password CLI v2 is available"))
			}
		}
	}
	return sshAvailable
}

func (doctor Doctor) includeCheck(path string) []domain.DoctorFinding {
	data, _, exists, err := doctor.Service.Repository.Read(path, 8<<20)
	if err != nil || !exists {
		return []domain.DoctorFinding{warn("ssh_include", "~/.ssh/config does not load opssh fragments", "Add Include ~/.ssh/config.d/* through opssh add")}
	}
	if !sshconfig.HasInclude(data) {
		return []domain.DoctorFinding{fail("ssh_include", "~/.ssh/config is missing the opssh Include", "Run opssh add and approve the Include change")}
	}
	return []domain.DoctorFinding{pass("ssh_include", "~/.ssh/config loads config.d fragments")}
}

func (doctor Doctor) hostChecks(ctx context.Context, configuration domain.Configuration, identities []agent.PublicIdentity, sshAvailable bool) []domain.DoctorFinding {
	publicValid := true
	fingerprintValid := true
	agentBindings := true
	effectiveValid := true
	identitiesOnly := true
	identityPublic := true
	noPrivatePaths := true
	referencesValid := true
	for alias, host := range configuration.Hosts {
		keyPath, _ := doctor.Service.Repository.Layout.PublicKey(alias)
		data, _, exists, err := doctor.Service.Repository.Read(keyPath, 1<<20)
		if err != nil || !exists {
			publicValid = false
			fingerprintValid = false
		} else if err := sshconfig.ValidatePublicKey(data, ""); err != nil {
			publicValid = false
		} else if err := sshconfig.ValidatePublicKey(data, host.Key.Fingerprint); err != nil {
			fingerprintValid = false
		}
		if len(identities) > 0 && !agent.ContainsFingerprint(identities, host.Key.Fingerprint) {
			agentBindings = false
		}
		if !host.Options.IdentitiesOnly {
			identitiesOnly = false
		}
		if !strings.HasSuffix(strings.ToLower(host.Key.PublicKeyFile), ".pub") {
			identityPublic = false
			noPrivatePaths = false
		}
		lowerPath := strings.ToLower(host.Key.PublicKeyFile)
		if strings.Contains(lowerPath, "id_rsa") || strings.Contains(lowerPath, "id_ed25519") || strings.Contains(lowerPath, "id_ecdsa") {
			noPrivatePaths = false
		}
		if sshAvailable && doctor.Runner != nil && doctor.Service.ValidateEffectiveConfig(ctx, alias) != nil {
			effectiveValid = false
		}
		if doctor.Keys != nil {
			key, err := doctor.Keys.GetPublicKey(ctx, host.Key.Reference)
			if err != nil || key.Fingerprint != host.Key.Fingerprint {
				referencesValid = false
			}
			security.Wipe(key.Line)
		}
	}
	return []domain.DoctorFinding{
		booleanFinding("public_key_valid", publicValid, "All managed public-key files are valid", "One or more managed public-key files are invalid", "Run: opssh sync"),
		booleanFinding("public_key_fingerprint", fingerprintValid, "Public-key fingerprints match configuration", "A public-key fingerprint mismatch was found", "Run: opssh sync"),
		booleanFinding("agent_key_binding", agentBindings, "Configured public keys are exposed by the Agent", "One or more configured keys are absent from the Agent", "Check 1Password SSH Agent settings"),
		booleanFinding("ssh_effective_config", effectiveValid, "OpenSSH accepted all effective host configurations", "OpenSSH rejected an effective host configuration", "Run: opssh config validate"),
		booleanFinding("identities_only", identitiesOnly, "IdentitiesOnly is enabled for every host", "A host may offer excessive Agent identities", "Run: opssh sync"),
		booleanFinding("identity_file_public", identityPublic, "Every IdentityFile points to a .pub file", "An IdentityFile does not point to a .pub file", "Fix the host binding"),
		booleanFinding("no_private_identity_path", noPrivatePaths, "No managed IdentityFile resembles a local private-key path", "A managed IdentityFile resembles a private-key path", "Remove the unsafe host configuration"),
		booleanFinding("authentication_failure_risk", identitiesOnly && identityPublic && effectiveValid, "Hosts are pinned to one Agent identity", "Configuration may trigger excessive authentication attempts", "Run: opssh sync"),
		booleanFinding("onepassword_references", referencesValid, "1Password item and Vault references resolve to expected public keys", "A 1Password reference is unavailable or rotated", "Run: opssh sync"),
	}
}

func permissionCheck(code, path string, forbidden os.FileMode) domain.DoctorFinding {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return infoFinding(code, "File does not exist yet")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fail(code, "File type is unsafe", "Replace symlinks or special files with a regular file")
	}
	if info.Mode().Perm()&forbidden != 0 {
		return fail(code, "File permissions are broader than required", "Restrict the file to mode 0600")
	}
	return pass(code, "File permissions are restricted")
}

func proxyCheck(configuration domain.Configuration, resolver process.Resolver) domain.DoctorFinding {
	needsNetcat := false
	for _, host := range configuration.Hosts {
		if host.Proxy.Type == domain.ProxySOCKS5 || host.Proxy.Type == domain.ProxyHTTPConnect {
			needsNetcat = true
		}
	}
	if !needsNetcat {
		return infoFinding("proxy_dependency", "No netcat-based proxy is configured")
	}
	if _, err := resolver.Resolve(process.ToolNetcat); err != nil {
		return fail("proxy_dependency", "A configured proxy requires nc, but nc was not found", "Install a compatible netcat implementation")
	}
	return pass("proxy_dependency", "Required proxy command dependency is available")
}

func duplicateHostCheck(repository *app.Repository, directory string) domain.DoctorFinding {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return infoFinding("duplicate_host", "No SSH fragments exist yet")
	}
	if err != nil {
		return warn("duplicate_host", "SSH fragments could not be scanned", "Check config.d permissions")
	}
	counts := make(map[string]int)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		data, _, exists, readErr := repository.Read(path, 1<<20)
		if readErr != nil || !exists {
			return fail("duplicate_host", "An SSH fragment could not be scanned safely", "Inspect managed config.d files and run: opssh doctor")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 && strings.EqualFold(fields[0], "Host") && !strings.ContainsAny(fields[1], "*?!") {
				counts[fields[1]]++
			}
		}
	}
	for _, count := range counts {
		if count > 1 {
			return fail("duplicate_host", "Duplicate concrete Host aliases were found", "Remove or rename conflicting SSH fragments")
		}
	}
	return pass("duplicate_host", "No duplicate concrete Host aliases were found")
}

func tunnelPortCheck(configuration domain.Configuration) domain.DoctorFinding {
	seen := make(map[string]struct{})
	for _, tunnel := range configuration.Tunnels {
		endpoint := fmt.Sprintf("%s:%d", tunnel.LocalHost, tunnel.LocalPort)
		if _, exists := seen[endpoint]; exists {
			return fail("tunnel_port_conflict", "Configured tunnels contain duplicate local endpoints", "Assign unique local tunnel ports")
		}
		seen[endpoint] = struct{}{}
	}
	return pass("tunnel_port_conflict", "Configured tunnel endpoints are unique")
}

func booleanFinding(code string, condition bool, success, failure, action string) domain.DoctorFinding {
	if condition {
		return pass(code, success)
	}
	return fail(code, failure, action)
}

func pass(code, message string) domain.DoctorFinding {
	return domain.DoctorFinding{Level: domain.FindingPass, Code: code, Message: message}
}

func warn(code, message, action string) domain.DoctorFinding {
	return domain.DoctorFinding{Level: domain.FindingWarn, Code: code, Message: message, Action: action}
}

func fail(code, message, action string) domain.DoctorFinding {
	return domain.DoctorFinding{Level: domain.FindingFail, Code: code, Message: message, Action: action}
}

func infoFinding(code, message string) domain.DoctorFinding {
	return domain.DoctorFinding{Level: domain.FindingInfo, Code: code, Message: message}
}
