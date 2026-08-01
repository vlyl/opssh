package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/domain"
)

func TestHostViewAndSmallTerminalFallback(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	updated, _ := model.Update(hostsLoadedMsg{hosts: []domain.Host{{Alias: "prod-web", Hostname: "example.com", User: "root", Port: 22}}})
	model = updated.(Model)
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "prod-web") || !strings.Contains(view, "Enter Connect") {
		t.Fatalf("full view = %q", view)
	}
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 40, Height: 8})
	if view := updated.(Model).View(); !strings.Contains(view, "Terminal") && !strings.Contains(view, "prod-web") {
		t.Fatalf("compact view = %q", view)
	}
}

func TestEditWizardStartsWithEditableHostAlias(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model = model.beginEdit(domain.Host{
		Alias: "gitlab-old", Hostname: "gitlab.example.com", User: "git", Port: 2222,
		Proxy: domain.Proxy{Type: domain.ProxyNone},
	})
	if model.input.Prompt != "Host alias: " || model.input.Value() != "gitlab-old" {
		t.Fatalf("first edit field = prompt %q value %q", model.input.Prompt, model.input.Value())
	}
	if model.wizard.originalAlias != "gitlab-old" {
		t.Fatalf("original alias = %q", model.wizard.originalAlias)
	}

	model.input.SetValue("gitlab-work")
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := updated.(Model)
	if command != nil || got.wizard.alias != "gitlab-work" || got.wizard.originalAlias != "gitlab-old" {
		t.Fatalf("renamed wizard state = %#v, command = %v", got.wizard, command)
	}
	if got.wizard.step != 1 || got.input.Prompt != "Hostname or IP: " || got.input.Value() != "gitlab.example.com" {
		t.Fatalf("second edit field = step %d prompt %q value %q", got.wizard.step, got.input.Prompt, got.input.Value())
	}
}

func TestRenamePreviewExplainsGitRemoteHostname(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenPreview
	model.plan = app.Plan{
		Operation: "rename",
		Alias:     "gitlab-work",
		Notices: []string{
			"A Git remote name does not select an SSH Host block.",
			"Example: git remote set-url <remote> git@gitlab-work:<group>/<repository>.git",
		},
	}
	view := model.View()
	for _, expected := range []string{"Notes:", "remote name does not select", "git remote set-url", "git@gitlab-work"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("rename preview lacks %q: %q", expected, view)
		}
	}
}

func TestErrorViewRedactsSensitiveMarker(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model = model.showError(errors.New("-----BEGIN OPENSSH PRIVATE KEY----- material"))
	view := model.View()
	if strings.Contains(view, "PRIVATE KEY") || strings.Contains(view, "material") {
		t.Fatalf("error view leaked rejected content: %q", view)
	}
	if !strings.Contains(view, "opssh doctor") {
		t.Fatalf("error view lacks diagnostic command: %q", view)
	}
}

func TestErrorViewShowsOperationCauseAndControls(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.operation = "load 1Password SSH Key metadata"
	model.retry = func(context.Context, uint64) tea.Cmd { return nil }
	model = model.showError(fmt.Errorf("could not list keys: %w", errors.New("1Password account is unavailable")))

	view := model.View()
	for _, expected := range []string{
		"Operation:",
		"load 1Password SSH Key metadata",
		"Cause chain:",
		"1Password account is unavailable",
		"op --version",
		"r Retry",
		":/Enter Command",
		"Esc cancel current operation",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("error view lacks %q: %q", expected, view)
		}
	}
}

func TestEscapeCancelsFailedOperationAndReturnsToHosts(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.operation = "load 1Password SSH Key metadata"
	model.retry = func(context.Context, uint64) tea.Cmd { return nil }
	model.wizard = wizard{alias: "in-progress", step: 3}
	model = model.showError(errors.New("metadata failed"))

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := updated.(Model)
	if command != nil || got.screen != screenHosts || got.err != nil || got.loading {
		t.Fatalf("Esc did not cancel operation: screen=%v err=%v loading=%v command=%v", got.screen, got.err, got.loading, command)
	}
	if got.wizard != (wizard{}) || got.status != "Current operation canceled" {
		t.Fatalf("Esc left operation state behind: wizard=%#v status=%q", got.wizard, got.status)
	}
}

func TestEscapeCancelsOperationContextAndIgnoresLateResult(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	var operationContext context.Context
	updated, _ := model.startOperation("slow operation", func(ctx context.Context, operationID uint64) tea.Cmd {
		operationContext = ctx
		return func() tea.Msg { return hostsLoadedMsg{opID: operationID} }
	})
	model = updated.(Model)
	canceledOperationID := model.activeOpID

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	select {
	case <-operationContext.Done():
	default:
		t.Fatal("Esc did not cancel the operation context")
	}

	model.status = "late result ignored"
	updated, command := model.Update(hostsLoadedMsg{hosts: []domain.Host{{Alias: "stale"}}, opID: canceledOperationID})
	got := updated.(Model)
	if command != nil || got.status != "late result ignored" || len(got.hosts.Items()) != 0 {
		t.Fatalf("late operation result was applied: status=%q items=%d", got.status, len(got.hosts.Items()))
	}
}

func TestCommandPaletteRunsOnlyBuiltInCommands(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenError
	model.operation = "failed operation"
	model.retry = func(context.Context, uint64) tea.Cmd { return nil }
	model = model.openCommandPalette()
	model.command.SetValue("rm -rf /tmp/example")

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command != nil || !strings.Contains(model.commandErr, "arbitrary shell commands are intentionally disabled") {
		t.Fatalf("unsafe command was not rejected: command=%v error=%q", command, model.commandErr)
	}

	model.command.SetValue("opssh doctor")
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command == nil || !model.loading || model.operation != "run diagnostics" {
		t.Fatalf("built-in doctor command did not start: command=%v loading=%v operation=%q", command, model.loading, model.operation)
	}
}
