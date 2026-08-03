package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/domain"
)

func TestHostViewAndSmallTerminalFallback(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	updated, _ := model.Update(hostsLoadedMsg{hosts: []domain.Host{{Alias: "prod-web", Hostname: "example.com", User: "root", Port: 22}}})
	model = updated.(Model)
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model = updated.(Model)
	view := model.View()
	for _, expected := range []string{"opssh", "Hosts", "prod-web", "Target", "root@example.com:22", "enter", "connect", "refresh", "help"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("full view lacks %q: %q", expected, view)
		}
	}
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > 120 {
			t.Fatalf("full view line width = %d, want <= 120: %q", width, line)
		}
	}
	if strings.Contains(view, "↑/k up") {
		t.Fatalf("full view includes duplicate built-in help: %q", view)
	}
	if lines := len(strings.Split(view, "\n")); lines > 30 {
		t.Fatalf("full view height = %d, want <= 30", lines)
	}
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 40, Height: 8})
	if view := updated.(Model).View(); !strings.Contains(view, "prod-web") || !strings.Contains(view, "Terminal") && !strings.Contains(view, "enter connect") {
		t.Fatalf("full view = %q", view)
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
	for _, expected := range []string{"Notes", "remote name does not select", "git remote set-url", "git@gitlab-work", "edit draft"} {
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
		"retry",
		"command",
		"cancel current operation",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("error view lacks %q: %q", expected, view)
		}
	}
}

func TestWizardValidationStaysInlineAndSupportsPreviousStep(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model = model.beginAdd()

	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command != nil || model.screen != screenInput || model.formErr != "This field is required" {
		t.Fatalf("required validation left form: screen=%v error=%q command=%v", model.screen, model.formErr, command)
	}
	if view := model.View(); !strings.Contains(view, "This field is required") || !strings.Contains(view, "step 1 of 6") {
		t.Fatalf("inline validation view = %q", view)
	}

	model.input.SetValue("-invalid")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.wizard.step != 0 || !strings.Contains(model.formErr, "start with a letter or number") {
		t.Fatalf("alias validation did not stay inline: wizard=%#v error=%q", model.wizard, model.formErr)
	}

	model.input.SetValue("prod-web")
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.wizard.step != 1 || model.formErr != "" {
		t.Fatalf("wizard did not advance: wizard=%#v error=%q", model.wizard, model.formErr)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	model = updated.(Model)
	if model.wizard.step != 0 || model.input.Value() != "prod-web" {
		t.Fatalf("Shift+Tab did not restore previous field: wizard=%#v value=%q", model.wizard, model.input.Value())
	}
}

func TestHelpOverlayReturnsToPreviousScreen(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	model = updated.(Model)
	if command != nil || model.screen != screenHelp || model.helpBack != screenHosts {
		t.Fatalf("help did not open: screen=%v back=%v command=%v", model.screen, model.helpBack, command)
	}
	if view := model.View(); !strings.Contains(view, "Keyboard help") || !strings.Contains(view, "Shift+Tab") {
		t.Fatalf("help view = %q", view)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if got := updated.(Model); got.screen != screenHosts {
		t.Fatalf("Esc returned to screen %v, want hosts", got.screen)
	}
}

func TestPreviewCanReturnToEditableDraft(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.wizard = wizard{alias: "prod-web", hostname: "example.com", user: "ubuntu", port: 22}
	model.screen = screenPreview
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	got := updated.(Model)
	if command != nil || got.screen != screenInput || got.wizard.step != 0 || got.input.Value() != "prod-web" {
		t.Fatalf("preview edit did not restore draft: screen=%v wizard=%#v value=%q command=%v", got.screen, got.wizard, got.input.Value(), command)
	}
}

func TestEditWizardPreservesExistingProxyEndpoint(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model = model.beginEdit(domain.Host{
		Alias: "prod-web", Hostname: "example.com", User: "ubuntu", Port: 22,
		Proxy: domain.Proxy{Type: domain.ProxySOCKS5, Host: "127.0.0.1", Port: 1080},
	})
	model = model.beginProxyPicker()
	if model.choices.Index() != 1 {
		t.Fatalf("proxy picker selected index = %d, want SOCKS5", model.choices.Index())
	}
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := updated.(Model)
	if command != nil || got.screen != screenInput || got.wizard.step != 100 || got.input.Value() != "127.0.0.1:1080" {
		t.Fatalf("proxy endpoint was not preserved: screen=%v wizard=%#v value=%q command=%v", got.screen, got.wizard, got.input.Value(), command)
	}
}

func TestPrimaryViewsFitCommonTerminal(t *testing.T) {
	t.Parallel()

	base := NewModel(Dependencies{NoColor: true})
	base.loading = false

	hosts := base
	hosts.hosts.SetItems([]list.Item{hostItem{host: domain.Host{
		Alias: "prod-web", Hostname: "192.0.2.10", User: "ubuntu", Port: 22,
		Key: domain.KeyBinding{Title: "Production", Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}}})

	input := base.beginAdd()
	proxy := input.beginProxyPicker()
	preview := base
	preview.screen = screenPreview
	preview.wizard = wizard{alias: "prod-web"}
	preview.plan = app.Plan{Operation: "add", Alias: "prod-web", ConfigPreview: "Host prod-web\n    HostName 192.0.2.10", Changes: []app.ChangeSummary{{Action: "create", Path: "~/.ssh/config.d/prod-web.conf"}}}
	remove := base
	remove.screen, remove.deleteAlias = screenConfirmDelete, "prod-web"
	failure := base.showError(fmt.Errorf("could not test host: %w", errors.New("connection timed out")))
	command := base.openCommandPalette()
	help := base.openHelp()

	views := []struct {
		name  string
		model Model
	}{
		{"hosts", hosts},
		{"input", input},
		{"proxy", proxy},
		{"preview", preview},
		{"remove", remove},
		{"error", failure},
		{"command", command},
		{"help", help},
	}
	for _, item := range views {
		item := item
		t.Run(item.name, func(t *testing.T) {
			updated, _ := item.model.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
			view := updated.(Model).View()
			lines := strings.Split(view, "\n")
			if len(lines) > 30 {
				t.Fatalf("view height = %d, want <= 30: %q", len(lines), view)
			}
			for _, line := range lines {
				if width := lipgloss.Width(line); width > 80 {
					t.Fatalf("line width = %d, want <= 80: %q", width, line)
				}
			}
		})
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

	model.command.SetValue("help")
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command != nil || model.screen != screenHelp || model.helpBack != screenCommand {
		t.Fatalf("help command did not open keyboard help: screen=%v back=%v command=%v", model.screen, model.helpBack, command)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)

	model.command.SetValue("opssh doctor")
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command == nil || !model.loading || model.operation != "run diagnostics" {
		t.Fatalf("built-in doctor command did not start: command=%v loading=%v operation=%q", command, model.loading, model.operation)
	}
}
