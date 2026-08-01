package agent

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/vlyl/opssh/internal/process"
	"golang.org/x/crypto/ssh"
)

type fakeRunner struct {
	result process.Result
	seen   process.Request
}

func (runner *fakeRunner) Run(_ context.Context, request process.Request) (process.Result, error) {
	runner.seen = request
	return runner.result, nil
}

func TestInspectorFindsTargetAmongManyKeys(t *testing.T) {
	var output []byte
	var target string
	for keyIndex := 0; keyIndex < 50; keyIndex++ {
		publicBytes := make([]byte, ed25519.PublicKeySize)
		for byteIndex := range publicBytes {
			publicBytes[byteIndex] = byte(keyIndex + byteIndex + 1)
		}
		key, err := ssh.NewPublicKey(ed25519.PublicKey(publicBytes))
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, ssh.MarshalAuthorizedKey(key)...)
		if keyIndex == 39 {
			target = ssh.FingerprintSHA256(key)
		}
	}
	runner := &fakeRunner{result: process.Result{Stdout: output}}
	identities, err := (Inspector{Runner: runner}).List(context.Background(), "/tmp/agent.sock")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(identities) != 50 || !ContainsFingerprint(identities, target) {
		t.Fatalf("target not found among %d identities", len(identities))
	}
	if len(runner.seen.Args) != 1 || runner.seen.Args[0] != "-L" {
		t.Fatalf("ssh-add argv = %#v", runner.seen.Args)
	}
}
