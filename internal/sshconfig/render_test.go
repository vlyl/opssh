package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vlyl/opssh/internal/domain"
)

func TestRenderHostPinsOnePublicIdentity(t *testing.T) {
	t.Parallel()

	host := testHost()
	output, err := RenderHost(testDefaults(), host)
	if err != nil {
		t.Fatalf("RenderHost() error = %v", err)
	}
	text := string(output)
	for _, required := range []string{
		ManagedMarker,
		"Host prod-web",
		"IdentityFile \"~/.ssh/opssh/public_keys/prod-web.pub\"",
		"IdentitiesOnly yes",
		"IdentityAgent \"~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock\"",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("rendered config lacks %q:\n%s", required, text)
		}
	}
	if strings.Count(text, "IdentityFile") != 1 {
		t.Fatalf("rendered config offers multiple identity files:\n%s", text)
	}
}

func TestRenderHostGolden(t *testing.T) {
	t.Parallel()

	got, err := RenderHost(testDefaults(), testHost())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sshconfig", "prod-web.conf.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("rendered config differs from golden\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderProxyVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy domain.Proxy
		want  string
	}{
		{"socks5", domain.Proxy{Type: domain.ProxySOCKS5, Host: "127.0.0.1", Port: 7890}, "ProxyCommand nc -x 127.0.0.1:7890 -X 5 %h %p"},
		{"http", domain.Proxy{Type: domain.ProxyHTTPConnect, Host: "2001:db8::2", Port: 8080}, "ProxyCommand nc -x [2001:db8::2]:8080 -X connect %h %p"},
		{"jump", domain.Proxy{Type: domain.ProxyJump, JumpHost: "bastion"}, "ProxyJump bastion"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host := testHost()
			host.Proxy = test.proxy
			output, err := RenderHost(testDefaults(), host)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("output does not contain %q:\n%s", test.want, output)
			}
		})
	}
}

func TestRenderRejectsInjection(t *testing.T) {
	t.Parallel()

	for _, alias := range []string{"host; rm -rf ~", "../../host", "foo\nProxyCommand bad"} {
		host := testHost()
		host.Alias = alias
		if _, err := RenderHost(testDefaults(), host); err == nil {
			t.Errorf("RenderHost() accepted %q", alias)
		}
	}
}

func TestAddIncludeIsIdempotentAndPreservesContent(t *testing.T) {
	t.Parallel()

	original := []byte("# user comment\nHost existing\n    HostName example.com\n")
	updated, changed := AddInclude(original)
	if !changed || !bytesContains(updated, string(original)) || !HasInclude(updated) {
		t.Fatalf("AddInclude() = %q, %v", updated, changed)
	}
	again, changed := AddInclude(updated)
	if changed || string(again) != string(updated) {
		t.Fatal("AddInclude() was not idempotent")
	}
}

func TestAddIncludeMigratesBroadLegacyGlob(t *testing.T) {
	t.Parallel()

	original := []byte("Host existing\n  HostName example.com\nInclude ~/.ssh/config.d/*\n")
	updated, changed := AddInclude(original)
	if !changed || !HasInclude(updated) {
		t.Fatalf("AddInclude() = %q, %v", updated, changed)
	}
	if strings.Contains(string(updated), legacyIncludePattern+"\n") {
		t.Fatalf("legacy broad include remains: %s", updated)
	}
}

func TestAddIncludeRemovesLegacyGlobBesideSafeInclude(t *testing.T) {
	t.Parallel()

	original := []byte("Include ~/.ssh/config.d/*\nInclude ~/.ssh/config.d/*.conf\n")
	updated, changed := AddInclude(original)
	if !changed || strings.Contains(string(updated), legacyIncludePattern+"\n") {
		t.Fatalf("AddInclude() = %q, %v", updated, changed)
	}
}

func testDefaults() domain.Defaults {
	return domain.Defaults{
		IdentityAgent:  "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
		ConnectTimeout: 10 * time.Second, ServerAliveInterval: 30, ServerAliveCountMax: 3,
	}
}

func testHost() domain.Host {
	return domain.Host{
		Alias: "prod-web", Hostname: "192.0.2.10", User: "root", Port: 22,
		Key: domain.KeyBinding{
			Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: "account01", VaultID: "vault01", ItemID: "item01"},
			Title:     "prod-web-key", Fingerprint: "SHA256:abcdefghijklmnopqrstuvwx",
			PublicKeyFile: "~/.ssh/opssh/public_keys/prod-web.pub",
		},
		Proxy: domain.Proxy{Type: domain.ProxyNone},
		Options: domain.HostOptions{
			IdentitiesOnly: true, StrictHostKeyChecking: domain.HostKeyCheckingAsk,
			ServerAliveInterval: 30, ServerAliveCountMax: 3,
		},
	}
}

func bytesContains(data []byte, text string) bool {
	return strings.Contains(string(data), text)
}
