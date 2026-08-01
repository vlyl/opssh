package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
	"golang.org/x/crypto/ssh"
)

var ErrNoAgentIdentities = errors.New("SSH agent exposed no public keys")

type CommandRunner interface {
	Run(ctx context.Context, request process.Request) (process.Result, error)
}

type PublicIdentity struct {
	Algorithm   string
	Fingerprint string
}

type Inspector struct {
	Runner CommandRunner
}

func (inspector Inspector) List(ctx context.Context, socket string) ([]PublicIdentity, error) {
	if inspector.Runner == nil {
		return nil, errors.New("agent inspector has no command runner")
	}
	result, err := inspector.Runner.Run(ctx, process.Request{
		Tool: process.ToolSSHAdd, Args: []string{"-L"}, AgentSocket: socket, OutputLimit: 4 << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("list SSH agent public keys: %w", err)
	}
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	if security.ContainsSensitiveMarker(result.Stdout) || security.ContainsSensitiveMarker(result.Stderr) {
		return nil, errors.New("SSH agent output was rejected by the security policy")
	}

	lines := bytes.Split(result.Stdout, []byte("\n"))
	identities := make([]PublicIdentity, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		key, _, options, rest, parseErr := ssh.ParseAuthorizedKey(line)
		if parseErr != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("SSH agent returned an invalid public-key line")
		}
		identities = append(identities, PublicIdentity{Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)})
	}
	if len(identities) == 0 {
		return nil, ErrNoAgentIdentities
	}
	return identities, nil
}

func ContainsFingerprint(identities []PublicIdentity, fingerprint string) bool {
	for _, identity := range identities {
		if identity.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}
