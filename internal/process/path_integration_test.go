package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(testingMain *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "ssh":
		_, _ = fmt.Fprintln(os.Stdout, "fake ssh")
		os.Exit(0)
	case "ssh-add":
		_, _ = fmt.Fprintln(os.Stdout, "fake ssh-add public output")
		os.Exit(0)
	}
	os.Exit(testingMain.Run())
}

func TestPATHResolverUsesFakeSSHExecutablesWithoutShell(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"ssh", "ssh-add"} {
		if err := os.Symlink(os.Args[0], filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runner := NewRunner(nil, nil)
	sshResult, err := runner.Run(context.Background(), Request{Tool: ToolOpenSSH, Args: []string{"-V"}})
	if err != nil || !strings.Contains(string(sshResult.Stdout), "fake ssh") {
		t.Fatalf("fake ssh result = %q, %v", sshResult.Stdout, err)
	}
	addResult, err := runner.Run(context.Background(), Request{Tool: ToolSSHAdd, Args: []string{"-L"}, AgentSocket: "/tmp/fake-agent.sock"})
	if err != nil || !strings.Contains(string(addResult.Stdout), "fake ssh-add") {
		t.Fatalf("fake ssh-add result = %q, %v", addResult.Stdout, err)
	}
}
