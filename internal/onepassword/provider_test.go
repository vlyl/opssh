package onepassword

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
	"golang.org/x/crypto/ssh"
)

type fakeRunner struct {
	requests []process.Request
	results  []process.Result
	errors   []error
}

func TestMain(testingMain *testing.M) {
	if filepath.Base(os.Args[0]) == "op" {
		runFakeOP()
		return
	}
	os.Exit(testingMain.Run())
}

func runFakeOP() {
	args := os.Args[1:]
	switch {
	case len(args) == 1 && args[0] == "--version":
		_, _ = fmt.Fprintln(os.Stdout, "2.32.0")
	case len(args) >= 2 && args[0] == "account" && args[1] == "list":
		_, _ = fmt.Fprint(os.Stdout, `[{"account_uuid":"account01","name":"Work"}]`)
	case len(args) >= 2 && args[0] == "vault" && args[1] == "list":
		_, _ = fmt.Fprint(os.Stdout, `[{"id":"vault01","name":"Infrastructure"}]`)
	case len(args) >= 2 && args[0] == "item" && args[1] == "list":
		_, _ = fmt.Fprint(os.Stdout, `[{"id":"item01","title":"Production","category":"SSH_KEY","vault":{"id":"vault01","name":"Infrastructure"}}]`)
	case len(args) >= 2 && args[0] == "item" && args[1] == "get":
		joined := strings.Join(args, "|")
		if !strings.Contains(joined, "--fields|"+publicKeyFieldSelector) || strings.Contains(joined, "--reveal") {
			os.Exit(42)
		}
		publicBytes := make([]byte, ed25519.PublicKeySize)
		for index := range publicBytes {
			publicBytes[index] = byte(index + 1)
		}
		key, _ := ssh.NewPublicKey(ed25519.PublicKey(publicBytes))
		_, _ = os.Stdout.Write(ssh.MarshalAuthorizedKey(key))
	default:
		os.Exit(43)
	}
	os.Exit(0)
}

func (runner *fakeRunner) Run(_ context.Context, request process.Request) (process.Result, error) {
	runner.requests = append(runner.requests, request)
	index := len(runner.requests) - 1
	var result process.Result
	var err error
	if index < len(runner.results) {
		result = runner.results[index]
	}
	if index < len(runner.errors) {
		err = runner.errors[index]
	}
	return result, err
}

func TestCommandCatalogIsSafe(t *testing.T) {
	t.Parallel()

	if err := ValidateCommandCatalog(); err != nil {
		t.Fatal(err)
	}
	for _, finding := range AuditCommandCatalog() {
		if !finding.Safe {
			t.Errorf("unsafe finding: %#v", finding)
		}
	}
}

func TestPublicKeyCommandUsesOnlyExplicitField(t *testing.T) {
	t.Parallel()

	request, err := buildPublicKeyGetCommand(commandInput{AccountID: "account01", VaultID: "vault01", ItemID: "item01"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasExactPublicKeySelector(request.Args) {
		t.Fatalf("argv is not field restricted: %#v", request.Args)
	}
	if containsForbiddenArgument(request.Args) {
		t.Fatalf("argv contains a forbidden argument: %#v", request.Args)
	}
}

func TestListPublicKeysUsesMetadataCommands(t *testing.T) {
	accounts, _ := json.Marshal([]accountSummary{{ID: "account01", Name: "Work"}})
	items := `[{
	  "id":"item01","title":"Production","category":"SSH_KEY",
      "vault":{"id":"vault01","name":"Infrastructure"}
    }]`
	runner := &fakeRunner{results: []process.Result{
		{Stdout: []byte("2.32.0\n")},
		{Stdout: accounts},
		{Stdout: []byte(items)},
	}}
	provider := &Provider{Runner: runner}

	keys, err := provider.ListPublicKeys(context.Background())
	if err != nil {
		t.Fatalf("ListPublicKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].Reference.ItemID != "item01" || keys[0].Reference.VaultID != "vault01" {
		t.Fatalf("keys = %#v", keys)
	}
	if len(runner.requests) != 3 || runner.requests[2].Args[0] != "item" || runner.requests[2].Args[1] != "list" {
		t.Fatalf("requests = %#v", runner.requests)
	}
}

func TestListPublicKeysExplainsUnsupportedCategoryWithoutEchoingMetadata(t *testing.T) {
	t.Parallel()

	accounts, _ := json.Marshal([]accountSummary{{ID: "account01", Name: "Work"}})
	runner := &fakeRunner{results: []process.Result{
		{Stdout: []byte("2.32.0\n")},
		{Stdout: accounts},
		{Stdout: []byte(`[{"id":"item01","title":"Production","category":"UNEXPECTED","vault":{"id":"vault01"}}]`)},
	}}
	provider := &Provider{Runner: runner}

	_, err := provider.ListPublicKeys(context.Background())
	if err == nil || !strings.Contains(err.Error(), "expected SSH_KEY") || strings.Contains(err.Error(), "UNEXPECTED") {
		t.Fatalf("ListPublicKeys() error = %v", err)
	}
}

func TestGetPublicKeyParsesAndFingerprintsPublicMaterial(t *testing.T) {
	publicBytes := make([]byte, ed25519.PublicKeySize)
	for index := range publicBytes {
		publicBytes[index] = byte(index + 1)
	}
	sshPublicKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicBytes))
	if err != nil {
		t.Fatal(err)
	}
	line := append([]byte(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublicKey)))), []byte(" test@example\n")...)
	runner := &fakeRunner{results: []process.Result{{Stdout: []byte("2.32.0\n")}, {Stdout: line}}}
	provider := &Provider{Runner: runner}

	key, err := provider.GetPublicKey(context.Background(), domain.KeyReference{
		Provider: domain.ProviderOnePassword, AccountID: "account01", VaultID: "vault01", ItemID: "item01",
	})
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}
	if key.Fingerprint != ssh.FingerprintSHA256(sshPublicKey) || !strings.HasPrefix(string(key.Line), "ssh-ed25519 ") {
		t.Fatalf("key = %#v", key)
	}
	if request := runner.requests[1]; !hasExactPublicKeySelector(request.Args) {
		t.Fatalf("unsafe public-key request: %#v", request.Args)
	}
}

func TestProviderRejectsSensitiveFakeOutputWithoutEcho(t *testing.T) {
	marker := "-----BEGIN OPENSSH PRIVATE KEY-----"
	runner := &fakeRunner{results: []process.Result{{Stdout: []byte("2.32.0\n")}, {Stdout: []byte(marker)}}}
	provider := &Provider{Runner: runner}

	_, err := provider.GetPublicKey(context.Background(), domain.KeyReference{
		Provider: domain.ProviderOnePassword, VaultID: "vault01", ItemID: "item01",
	})
	if !errors.Is(err, ErrUnsafeProviderOutput) {
		t.Fatalf("GetPublicKey() error = %v, want ErrUnsafeProviderOutput", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error leaked sensitive output: %v", err)
	}
}

func TestProviderRejectsUnknownMajorVersion(t *testing.T) {
	t.Parallel()

	provider := &Provider{Runner: &fakeRunner{results: []process.Result{{Stdout: []byte("3.0.0")}}}}
	if err := provider.Check(context.Background()); !errors.Is(err, ErrUnsupportedCLI) {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestProviderWithFakeOPOnPATH(t *testing.T) {
	directory := t.TempDir()
	fakeOP := filepath.Join(directory, "op")
	if err := os.Symlink(os.Args[0], fakeOP); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runner := process.NewRunner(nil, nil)
	provider := &Provider{Runner: runner}
	keys, err := provider.ListPublicKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListPublicKeys() = %#v, %v", keys, err)
	}
	key, err := provider.GetPublicKey(context.Background(), keys[0].Reference)
	if err != nil || key.Fingerprint == "" {
		t.Fatalf("GetPublicKey() = %#v, %v", key, err)
	}
}
