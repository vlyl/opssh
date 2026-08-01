package security

import (
	"errors"
	"testing"
)

func TestValidateAliasRejectsInjectionAndTraversal(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"../../.ssh/config",
		"../secret",
		"/a/b",
		"host; rm -rf ~",
		"$(touch /tmp/pwned)",
		"foo`whoami`",
		"foo\nProxyCommand malicious",
		"-oProxyCommand=malicious",
	}
	for _, value := range invalid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if err := ValidateAlias(value); !errors.Is(err, ErrUnsafeInput) {
				t.Fatalf("ValidateAlias(%q) error = %v, want ErrUnsafeInput", value, err)
			}
		})
	}
}

func TestValidateAliasAcceptsConservativeSet(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"prod-web", "db_01", "host.example", "A1"} {
		if err := ValidateAlias(value); err != nil {
			t.Errorf("ValidateAlias(%q) error = %v", value, err)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"example.com", "192.0.2.10", "2001:db8::1"} {
		if err := ValidateHostname(value); err != nil {
			t.Errorf("ValidateHostname(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"host %h", "host\nProxyCommand x", "-bad.example", "[[2001:db8::1]]", "[2001:db8::1"} {
		if err := ValidateHostname(value); !errors.Is(err, ErrUnsafeInput) {
			t.Errorf("ValidateHostname(%q) error = %v, want ErrUnsafeInput", value, err)
		}
	}
}

func TestValidateConfigPathText(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"relative/path", "~/../outside", "~/$HOME/key.pub", "~/.ssh/%h.pub", "/tmp/key`whoami`.pub",
	} {
		if err := ValidateConfigPathText(value); !errors.Is(err, ErrUnsafeInput) {
			t.Errorf("ValidateConfigPathText(%q) error = %v, want ErrUnsafeInput", value, err)
		}
	}
	for _, value := range []string{"~/.ssh/opssh/public_keys/prod-web.pub", "~/Library/Group Containers/example/agent.sock", "/run/user/1000/agent.sock"} {
		if err := ValidateConfigPathText(value); err != nil {
			t.Errorf("ValidateConfigPathText(%q) error = %v", value, err)
		}
	}
}

func TestContainsSensitiveMarker(t *testing.T) {
	t.Parallel()

	if !ContainsSensitiveMarker([]byte("prefix -----BEGIN OPENSSH PRIVATE KEY----- suffix")) {
		t.Fatal("marker was not detected")
	}
	if ContainsSensitiveMarker([]byte("ssh-ed25519 AAAAC3 public@example")) {
		t.Fatal("public key was incorrectly classified")
	}
}
