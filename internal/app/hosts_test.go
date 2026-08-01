package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/sshconfig"
	"golang.org/x/crypto/ssh"
)

type fakeKeyProvider struct {
	key domain.AuthorizedKey
}

func (provider *fakeKeyProvider) ListPublicKeys(context.Context) ([]domain.PublicKeyMetadata, error) {
	return nil, nil
}

func (provider *fakeKeyProvider) GetPublicKey(context.Context, domain.KeyReference) (domain.AuthorizedKey, error) {
	return domain.AuthorizedKey{
		Line: append([]byte(nil), provider.key.Line...), Algorithm: provider.key.Algorithm, Fingerprint: provider.key.Fingerprint,
	}, nil
}

func TestAddAndRemoveHostTransaction(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	input := AddInput{
		Alias: "prod-web", Hostname: "192.0.2.10", User: "root", Port: 22,
		Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: "account01", VaultID: "vault01", ItemID: "item01"},
		KeyTitle:  "Production", Proxy: domain.Proxy{Type: domain.ProxySOCKS5, Host: "127.0.0.1", Port: 7890},
	}
	plan, err := service.PrepareAdd(context.Background(), input)
	if err != nil {
		t.Fatalf("PrepareAdd() error = %v", err)
	}
	if !plan.IncludeChanged || !strings.Contains(plan.ConfigPreview, "IdentitiesOnly yes") {
		t.Fatalf("plan = %#v", plan)
	}
	if err := service.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply(add) error = %v", err)
	}
	configuration, err := service.Repository.Load()
	if err != nil || len(configuration.Hosts) != 1 {
		t.Fatalf("configuration = %#v, error = %v", configuration, err)
	}
	hostPath, _ := layout.HostConfig("prod-web")
	keyPath, _ := layout.PublicKey("prod-web")
	assertManagedFile(t, hostPath, sshconfig.ManagedMarker)
	assertManagedFile(t, keyPath, "ssh-ed25519 ")
	mainConfig, err := os.ReadFile(layout.SSHConfig)
	if err != nil || !sshconfig.HasInclude(mainConfig) {
		t.Fatalf("main SSH config missing Include: %q, %v", mainConfig, err)
	}

	removePlan, err := service.PrepareRemove("prod-web")
	if err != nil {
		t.Fatalf("PrepareRemove() error = %v", err)
	}
	if err := service.Apply(context.Background(), removePlan); err != nil {
		t.Fatalf("Apply(remove) error = %v", err)
	}
	for _, path := range []string{hostPath, keyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed file still exists: %s", path)
		}
	}
}

func TestRenameHostTransactionMigratesFilesAndReferences(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	for _, input := range []AddInput{
		{
			Alias: "old-alias", Hostname: "git.example.com", User: "git", Port: 2222,
			Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
			KeyTitle:  "Git key", Proxy: domain.Proxy{Type: domain.ProxyNone},
		},
		{
			Alias: "through-jump", Hostname: "internal.example.com", User: "ubuntu", Port: 22,
			Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
			KeyTitle:  "Server key", Proxy: domain.Proxy{Type: domain.ProxyJump, JumpHost: "old-alias"},
		},
	} {
		plan, err := service.PrepareAdd(context.Background(), input)
		if err != nil {
			t.Fatalf("PrepareAdd(%q) error = %v", input.Alias, err)
		}
		if err := service.Apply(context.Background(), plan); err != nil {
			t.Fatalf("Apply(%q) error = %v", input.Alias, err)
		}
	}
	configuration, err := service.Repository.Load()
	if err != nil {
		t.Fatal(err)
	}
	configuration.Tunnels["database"] = domain.Tunnel{
		Name: "database", SSHHost: "old-alias", LocalHost: "127.0.0.1", LocalPort: 15432,
		RemoteHost: "database.internal", RemotePort: 5432,
	}
	encoded, err := config.Encode(configuration)
	if err != nil {
		t.Fatal(err)
	}
	current, _, exists, err := service.Repository.Read(layout.ConfigFile, config.MaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Repository.Apply([]FileChange{{
		Path: layout.ConfigFile, Data: encoded, Mode: 0o600, ExpectedDigest: Digest(current, exists),
	}}); err != nil {
		t.Fatal(err)
	}

	newAlias := "gitlab-renamed"
	plan, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &newAlias})
	if err != nil {
		t.Fatalf("PrepareEdit(rename) error = %v", err)
	}
	if plan.Operation != "rename" || plan.Alias != newAlias || !strings.Contains(plan.ConfigPreview, "Host "+newAlias) {
		t.Fatalf("rename plan = %#v", plan)
	}
	if len(plan.Notices) == 0 || !strings.Contains(strings.Join(plan.Notices, "\n"), "git@"+newAlias) {
		t.Fatalf("rename plan lacks Git remote guidance: %#v", plan.Notices)
	}
	if err := service.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply(rename) error = %v", err)
	}

	configuration, err = service.Repository.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := configuration.Hosts["old-alias"]; exists {
		t.Fatal("old host alias remains in configuration")
	}
	renamed, exists := configuration.Hosts[newAlias]
	if !exists || renamed.Alias != newAlias || renamed.Key.PublicKeyFile != managedPublicKeyPath(newAlias) {
		t.Fatalf("renamed host = %#v", renamed)
	}
	if got := configuration.Hosts["through-jump"].Proxy.JumpHost; got != newAlias {
		t.Fatalf("ProxyJump reference = %q, want %q", got, newAlias)
	}
	if got := configuration.Tunnels["database"].SSHHost; got != newAlias {
		t.Fatalf("tunnel SSH host = %q, want %q", got, newAlias)
	}

	oldHostPath, _ := layout.HostConfig("old-alias")
	oldKeyPath, _ := layout.PublicKey("old-alias")
	for _, path := range []string{oldHostPath, oldKeyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("old managed path still exists: %s", path)
		}
	}
	newHostPath, _ := layout.HostConfig(newAlias)
	newKeyPath, _ := layout.PublicKey(newAlias)
	assertManagedFile(t, newHostPath, sshconfig.ManagedMarker)
	assertManagedFile(t, newKeyPath, "ssh-ed25519 ")
	dependentPath, _ := layout.HostConfig("through-jump")
	dependentData, err := os.ReadFile(dependentPath)
	if err != nil || !strings.Contains(string(dependentData), "ProxyJump "+newAlias) {
		t.Fatalf("dependent host config = %q, error = %v", dependentData, err)
	}
}

func TestRenameHostRejectsAliasAndPathCollisions(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	for _, alias := range []string{"old-alias", "existing-alias"} {
		plan, err := service.PrepareAdd(context.Background(), AddInput{
			Alias: alias, Hostname: "example.com", User: "git", Port: 22,
			Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
			KeyTitle:  "Key", Proxy: domain.Proxy{Type: domain.ProxyNone},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Apply(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
	}
	existingAlias := "existing-alias"
	if _, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &existingAlias}); !errors.Is(err, ErrHostExists) {
		t.Fatalf("PrepareEdit(existing alias) error = %v, want ErrHostExists", err)
	}

	orphanAlias := "orphan-alias"
	orphanPath, _ := layout.HostConfig(orphanAlias)
	if err := os.WriteFile(orphanPath, []byte("# unmanaged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &orphanAlias}); !errors.Is(err, ErrRenameTargetExists) {
		t.Fatalf("PrepareEdit(orphan path) error = %v, want ErrRenameTargetExists", err)
	}

	oldHostPath, _ := layout.HostConfig("old-alias")
	if err := os.WriteFile(oldHostPath, []byte("Host manually-managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanAlias := "clean-target"
	if _, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &cleanAlias}); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("PrepareEdit(unmanaged source) error = %v, want ErrNotManaged", err)
	}
}

func TestRenameHostRequiresExistingValidPublicKey(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	plan, err := service.PrepareAdd(context.Background(), AddInput{
		Alias: "old-alias", Hostname: "example.com", User: "git", Port: 22,
		Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
		KeyTitle:  "Key", Proxy: domain.Proxy{Type: domain.ProxyNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	oldKeyPath, _ := layout.PublicKey("old-alias")
	if err := os.Remove(oldKeyPath); err != nil {
		t.Fatal(err)
	}
	newAlias := "new-alias"
	if _, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &newAlias}); err == nil || !strings.Contains(err.Error(), "synchronize") {
		t.Fatalf("PrepareEdit(missing public key) error = %v", err)
	}
}

func TestRenameHostTransactionRollsBackEveryPath(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	plan, err := service.PrepareAdd(context.Background(), AddInput{
		Alias: "old-alias", Hostname: "example.com", User: "git", Port: 22,
		Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
		KeyTitle:  "Key", Proxy: domain.Proxy{Type: domain.ProxyNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	newAlias := "new-alias"
	renamePlan, err := service.PrepareEdit(context.Background(), "old-alias", EditInput{NewAlias: &newAlias})
	if err != nil {
		t.Fatal(err)
	}
	postconditionErr := errors.New("postcondition failed")
	if err := service.Repository.ApplyAndCheck(renamePlan.changes, func() error { return postconditionErr }); !errors.Is(err, postconditionErr) {
		t.Fatalf("ApplyAndCheck(rename) error = %v", err)
	}
	configuration, err := service.Repository.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := configuration.Hosts["old-alias"]; !exists {
		t.Fatal("rollback did not restore old host")
	}
	if _, exists := configuration.Hosts[newAlias]; exists {
		t.Fatal("rollback left renamed host in configuration")
	}
	oldHostPath, _ := layout.HostConfig("old-alias")
	oldKeyPath, _ := layout.PublicKey("old-alias")
	assertManagedFile(t, oldHostPath, sshconfig.ManagedMarker)
	assertManagedFile(t, oldKeyPath, "ssh-ed25519 ")
	newHostPath, _ := layout.HostConfig(newAlias)
	newKeyPath, _ := layout.PublicKey(newAlias)
	for _, path := range []string{newHostPath, newKeyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback left renamed path: %s", path)
		}
	}
}

func TestRepositoryRollsBackWhenPostCheckFails(t *testing.T) {
	t.Parallel()

	layout, err := securefs.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ensure(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(layout.ConfigDir, "transaction-test")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	change := FileChange{Path: path, Data: []byte("new"), Mode: 0o600, ExpectedDigest: Digest([]byte("old"), true)}
	checkError := errors.New("postcondition failed")
	if err := repository.ApplyAndCheck([]FileChange{change}, func() error { return checkError }); !errors.Is(err, checkError) {
		t.Fatalf("ApplyAndCheck() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old" {
		t.Fatalf("rollback content = %q, error = %v", data, err)
	}
}

func TestPlanRejectsConcurrentModification(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	plan, err := service.PrepareAdd(context.Background(), AddInput{
		Alias: "host1", Hostname: "example.com", User: "root", Port: 22,
		Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
		KeyTitle:  "Key", Proxy: domain.Proxy{Type: domain.ProxyNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigFile, []byte("concurrent change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), plan); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("Apply() error = %v, want ErrConcurrentModification", err)
	}
}

func TestSyncRestoresMissingPublicKeyWhenFingerprintIsUnchanged(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	addPlan, err := service.PrepareAdd(context.Background(), AddInput{
		Alias: "host1", Hostname: "example.com", User: "root", Port: 22,
		Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"},
		KeyTitle:  "Key", Proxy: domain.Proxy{Type: domain.ProxyNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), addPlan); err != nil {
		t.Fatal(err)
	}
	keyPath, _ := layout.PublicKey("host1")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	syncPlan, err := service.PrepareSync(context.Background(), "host1")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), syncPlan); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, keyPath, "ssh-ed25519 ")
}

func TestRepositoryRejectsSensitiveManagedFileContent(t *testing.T) {
	t.Parallel()

	service, layout := testService(t)
	if err := service.Repository.Ensure(); err != nil {
		t.Fatal(err)
	}
	marker := "-----BEGIN OPENSSH PRIVATE KEY-----"
	if err := os.WriteFile(layout.SSHConfig, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _, _, err := service.Repository.Read(layout.SSHConfig, 1<<20)
	if !errors.Is(err, ErrSensitiveManagedData) || data != nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("Read() = %q, %v", data, err)
	}
}

func testService(t *testing.T) (*Service, securefs.Layout) {
	t.Helper()
	layout, err := securefs.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepository(layout)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeKeyProvider{key: testAuthorizedKey(t, 1)}
	service := &Service{Repository: repository, Keys: provider, Clock: func() time.Time {
		return time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	}}
	return service, layout
}

func testAuthorizedKey(t *testing.T, seed byte) domain.AuthorizedKey {
	t.Helper()
	publicBytes := make([]byte, ed25519.PublicKeySize)
	for index := range publicBytes {
		publicBytes[index] = seed + byte(index)
	}
	key, err := ssh.NewPublicKey(ed25519.PublicKey(publicBytes))
	if err != nil {
		t.Fatal(err)
	}
	return domain.AuthorizedKey{Line: ssh.MarshalAuthorizedKey(key), Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
}

func assertManagedFile(t *testing.T, path, prefix string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), prefix) {
		t.Fatalf("%s = %q", path, data)
	}
}
