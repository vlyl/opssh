package tunnel

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
	securefs "github.com/vlyl/opssh/internal/filesystem"
)

func TestSSHArgumentsAreStructured(t *testing.T) {
	t.Parallel()

	configured := domain.Tunnel{Name: "db", SSHHost: "prod-web", LocalHost: "127.0.0.1", LocalPort: 15432, RemoteHost: "127.0.0.1", RemotePort: 5432}
	args := sshArguments(configured, domain.Defaults{ServerAliveInterval: 30, ServerAliveCountMax: 3})
	want := []string{"-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-L", "127.0.0.1:15432:127.0.0.1:5432", "prod-web"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("sshArguments() = %#v", args)
	}
}

func TestRandomInstanceID(t *testing.T) {
	t.Parallel()

	left, err := randomInstanceID()
	if err != nil || len(left) != 32 {
		t.Fatalf("randomInstanceID() = %q, %v", left, err)
	}
	right, _ := randomInstanceID()
	if left == right {
		t.Fatal("random instance IDs collided")
	}
	for _, invalid := range []string{"", "0000", strings.Repeat("z", 32), strings.Repeat("0", 34)} {
		if validInstanceID(invalid) {
			t.Errorf("validInstanceID(%q) = true", invalid)
		}
	}
}

func TestStartRequiresBackendApprovalForNonLoopbackListener(t *testing.T) {
	t.Parallel()

	manager := testManager(t)
	configuration, err := manager.Service.Repository.Load()
	if err != nil {
		t.Fatal(err)
	}
	configured := configuration.Tunnels["db"]
	configured.LocalHost = "0.0.0.0"
	configuration.Tunnels["db"] = configured
	data, err := config.Encode(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Service.Repository.Apply([]app.FileChange{{Path: manager.Service.Repository.Layout.ConfigFile, Data: data, Mode: 0o600}}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), "db", StartOptions{}); !errors.Is(err, ErrNonLoopback) {
		t.Fatalf("Start() error = %v, want ErrNonLoopback", err)
	}
}

func TestSupervisorRequiresMatchingParentState(t *testing.T) {
	t.Parallel()

	manager := testManager(t)
	instance := strings.Repeat("a", 32)
	if err := manager.waitForSupervisorAuthorization(context.Background(), "db", instance, os.Getpid(), 20*time.Millisecond); err == nil {
		t.Fatal("supervisor authorization succeeded without parent state")
	}
	state := State{Version: StateVersion, Name: "db", InstanceID: instance, PID: os.Getpid()}
	if err := manager.writeState("db", state); err != nil {
		t.Fatal(err)
	}
	if err := manager.waitForSupervisorAuthorization(context.Background(), "db", instance, os.Getpid(), time.Second); err != nil {
		t.Fatalf("matching supervisor state was rejected: %v", err)
	}
}

func TestStatusWithoutStateIsStopped(t *testing.T) {
	t.Parallel()

	manager := testManager(t)
	status, err := manager.Status(context.Background(), "db")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Running || status.Reason != "no state file" {
		t.Fatalf("status = %#v", status)
	}
}

func TestStateRejectsSensitiveContentWithoutEcho(t *testing.T) {
	t.Parallel()

	manager := testManager(t)
	path, _ := manager.Service.Repository.Layout.TunnelState("db")
	marker := "-----BEGIN OPENSSH PRIVATE KEY-----"
	if err := manager.Service.Repository.Apply([]app.FileChange{{Path: path, Data: []byte(marker), Mode: 0o600}}); err != nil {
		t.Fatal(err)
	}
	_, _, err := manager.readState("db")
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("readState() error = %v", err)
	}
}

func TestCheckPortAvailable(t *testing.T) {
	t.Parallel()

	if err := checkPortAvailable(context.Background(), "invalid endpoint"); !errors.Is(err, ErrPortInUse) {
		t.Fatalf("checkPortAvailable() error = %v", err)
	}
}

func TestCancelOnErrorWriterCancelsCommandContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	wantErr := errors.New("log write failed")
	writer := &cancelOnErrorWriter{destination: failingWriter{err: wantErr}, cancel: cancel}
	if _, err := writer.Write([]byte("safe")); !errors.Is(err, wantErr) {
		t.Fatalf("Write() error = %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("writer did not cancel the command context")
	}
	if !errors.Is(writer.Err(), wantErr) {
		t.Fatalf("Err() = %v", writer.Err())
	}
}

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

func testManager(t *testing.T) Manager {
	t.Helper()
	layout, err := securefs.NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository, err := app.NewRepository(layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ensure(); err != nil {
		t.Fatal(err)
	}
	configuration := config.New()
	configuration.Hosts["prod-web"] = domain.Host{
		Alias: "prod-web", Hostname: "example.com", User: "root", Port: 22,
		Key:     domain.KeyBinding{Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01"}, Title: "Key", PublicKeyFile: "~/.ssh/opssh/public_keys/prod-web.pub"},
		Proxy:   domain.Proxy{Type: domain.ProxyNone},
		Options: domain.HostOptions{IdentitiesOnly: true, StrictHostKeyChecking: domain.HostKeyCheckingAsk, ServerAliveInterval: 30, ServerAliveCountMax: 3},
	}
	configuration.Tunnels["db"] = domain.Tunnel{Name: "db", SSHHost: "prod-web", LocalHost: "127.0.0.1", LocalPort: 15432, RemoteHost: "127.0.0.1", RemotePort: 5432}
	data, err := config.Encode(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Apply([]app.FileChange{{Path: layout.ConfigFile, Data: data, Mode: 0o600}}); err != nil {
		t.Fatal(err)
	}
	return Manager{Service: &app.Service{Repository: repository}, Now: func() time.Time { return time.Unix(0, 0).UTC() }}
}
