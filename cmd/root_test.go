package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vlyl/opssh/internal/app"
)

func TestRootHelpInNonTTY(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runtime := &Runtime{In: strings.NewReader(""), Out: &stdout, ErrOut: &stderr, IsTTY: func() bool { return false }}
	command := NewRootCommand(runtime)
	command.SetArgs(nil)

	if err := command.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "1Password SSH Agent") {
		t.Fatalf("help output did not describe the security model: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestParseProxyRejectsCredentialsAndInjection(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"socks5://user:pass@localhost:1080", "jump://foo;bad", "http://host:8080/path"} {
		if _, err := parseProxy(value); err == nil {
			t.Errorf("parseProxy(%q) unexpectedly succeeded", value)
		}
	}
}

func TestEditHelpExplainsGitRemoteAliasSelection(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	command := newEditCommand(&Runtime{})
	command.SetOut(&output)
	command.SetErr(&output)
	if err := command.Help(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"hostname inside the remote URL", "git remote set-url", "git@new-alias"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("edit help lacks %q: %q", expected, output.String())
		}
	}
}

func TestPrintPlanIncludesRenameNotices(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printPlan(&output, app.Plan{Operation: "rename", Alias: "gitlab-work", Notices: []string{"Update Git remote URL hostname."}})
	if !strings.Contains(output.String(), "Notes:") || !strings.Contains(output.String(), "Update Git remote URL hostname.") {
		t.Fatalf("plan output = %q", output.String())
	}
}
