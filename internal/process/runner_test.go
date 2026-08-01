package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fixedResolver string

func (resolver fixedResolver) Resolve(Tool) (string, error) {
	return string(resolver), nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (audit *memoryAudit) Record(event AuditEvent) {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
}

func TestRunnerRejectsSensitiveOutputWithoutLeakingIt(t *testing.T) {
	audit := &memoryAudit{}
	runner := NewRunner(fixedResolver(os.Args[0]), audit)
	result, err := runner.Run(context.Background(), Request{
		Tool: ToolOnePassword,
		Args: []string{"-test.run=TestProcessHelper", "--", "sensitive"},
	})
	if !errors.Is(err, ErrSensitiveCommandOutput) {
		t.Fatalf("Run() error = %v, want ErrSensitiveCommandOutput", err)
	}
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatal("sensitive command output was returned")
	}
	if strings.Contains(err.Error(), "OPENSSH") {
		t.Fatalf("error leaked marker: %v", err)
	}
	if len(audit.events) != 1 || audit.events[0].Code != "sensitive_output_blocked" {
		t.Fatalf("audit events = %#v", audit.events)
	}
}

func TestSafeBufferDetectsMarkerAcrossWrites(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &captureState{cancel: cancel}
	buffer := newSafeBuffer(1024, state)
	first := []byte("safe prefix -----BEGIN OPENSSH PRI")
	second := []byte("VATE KEY----- unsafe suffix")
	_, _ = buffer.Write(first)
	_, _ = buffer.Write(second)
	if !state.containsSensitiveOutput() {
		t.Fatal("split marker was not detected")
	}
	if got := buffer.bytes(); len(got) != 0 {
		t.Fatalf("buffer retained %d bytes", len(got))
	}
}

func TestRunnerDoesNotInterpretArgumentsAsShell(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "pwned")
	payload := "$(touch " + target + ")"
	runner := NewRunner(fixedResolver(os.Args[0]), nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: ToolOpenSSH,
		Args: []string{"-test.run=TestProcessHelper", "--", "echo-argument", payload},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell payload created a file: %v", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != payload {
		t.Fatalf("argument was not preserved as argv: %q", result.Stdout)
	}
}

func TestRunnerEnforcesOutputLimit(t *testing.T) {
	runner := NewRunner(fixedResolver(os.Args[0]), nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: ToolOpenSSH, OutputLimit: 16,
		Args: []string{"-test.run=TestProcessHelper", "--", "large"},
	})
	if !errors.Is(err, ErrCommandOutputTooLarge) {
		t.Fatalf("Run() error = %v, want ErrCommandOutputTooLarge", err)
	}
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatal("oversized output was returned")
	}
}

func TestRunnerRejectsUnsafeAgentSocket(t *testing.T) {
	t.Parallel()

	runner := NewRunner(fixedResolver(os.Args[0]), nil)
	for _, socket := range []string{"relative/agent.sock", "/tmp/agent.sock\nINJECTED=value", "/tmp/$SOCKET"} {
		_, err := runner.Run(context.Background(), Request{Tool: ToolSSHAdd, AgentSocket: socket})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("AgentSocket %q error = %v, want ErrInvalidArgument", socket, err)
		}
	}
}

func TestRunnerReturnsSafeNonzeroError(t *testing.T) {
	runner := NewRunner(fixedResolver(os.Args[0]), nil)
	result, err := runner.Run(context.Background(), Request{
		Tool: ToolOpenSSH,
		Args: []string{"-test.run=TestProcessHelper", "--", "fail"},
	})
	var runError *RunError
	if !errors.As(err, &runError) || runError.ExitCode != 7 {
		t.Fatalf("Run() error = %#v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("ExitCode = %d", result.ExitCode)
	}
	if strings.Contains(err.Error(), "diagnostic text") {
		t.Fatalf("error leaked stderr: %v", err)
	}
}

func TestSafeBufferAcceptsPublicKey(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &captureState{cancel: cancel}
	buffer := newSafeBuffer(1024, state)
	want := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA public@example\n")
	input := bytes.Clone(want)
	_, _ = buffer.Write(input)
	if got := buffer.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("captured output = %q, want %q", got, want)
	}
}

func TestProcessHelper(_ *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator == -1 || separator+1 >= len(os.Args) {
		return
	}

	switch os.Args[separator+1] {
	case "sensitive":
		_, _ = fmt.Fprint(os.Stdout, "untrusted -----BEGIN OPENSSH PRIVATE KEY----- content")
	case "echo-argument":
		_, _ = fmt.Fprint(os.Stdout, os.Args[separator+2])
	case "large":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", 1024))
	case "fail":
		_, _ = fmt.Fprint(os.Stderr, "diagnostic text that must not enter the error")
		os.Exit(7)
	}
	os.Exit(0)
}
