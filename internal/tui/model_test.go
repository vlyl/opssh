package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/process"
)

func TestNewModelDisablesSystemClipboardBindings(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{})
	if model.input.KeyMap.Paste.Enabled() || model.command.KeyMap.Paste.Enabled() ||
		model.hosts.FilterInput.KeyMap.Paste.Enabled() || model.choices.FilterInput.KeyMap.Paste.Enabled() {
		t.Fatal("a TUI text field still exposes the system clipboard paste binding")
	}
}

func TestSensitiveBracketedPasteIsRejectedAndWiped(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{})
	model.loading = false
	model.screen = screenInput
	model.input.Focus()
	runes := []rune("-----BEGIN FUTURE PRIVATE KEY-----")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: runes, Paste: true})
	got := updated.(Model)
	if got.input.Value() != "" || got.formErr == "" {
		t.Fatalf("sensitive paste was retained: value=%q error=%q", got.input.Value(), got.formErr)
	}
	for _, value := range runes {
		if value != 0 {
			t.Fatal("sensitive paste runes were not wiped")
		}
	}
}

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
	model.wizard = wizard{alias: "gitlab-work"}
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

func TestErrorPageRunsSelectedSafeDiagnostic(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.operation = "failed operation"
	model = model.showError(errors.New("configuration failed"))
	if model.errorCommand < 0 || model.diagnostics[model.errorCommand] != "opssh doctor" {
		t.Fatalf("selected diagnostic = index %d commands %#v", model.errorCommand, model.diagnostics)
	}
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := updated.(Model)
	if command == nil || !got.loading || got.operation != "run diagnostics" {
		t.Fatalf("selected diagnostic run = command %v loading %v operation %q", command, got.loading, got.operation)
	}
}

func TestConnectionFailureShowsAliasDiagnosisAndFreshStatus(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = true
	model.activeOpID = 7
	model.operation = "connect to cybet-backend01"
	model.status = "Add completed for cybet-backend01"
	model.retry = func(context.Context, uint64) tea.Cmd { return nil }

	updated, command := model.Update(connectionDiagnosedMsg{
		alias:       "cybet-backend01",
		originalErr: errors.New("exit status 255"),
		opID:        7,
		result: app.ConnectionTestResult{
			Category: "public_key_rejected",
			Message:  "The server rejected public-key authentication.",
			Actions:  []string{"Verify the server authorized_keys entry", "Run: opssh sync cybet-backend01"},
			ExitCode: 255,
		},
	})
	got := updated.(Model)
	if command != nil || got.screen != screenError || got.operation != "connect to cybet-backend01" || got.status != "" || got.retry == nil {
		t.Fatalf("connection error state = screen %v operation %q status %q retry %v command %v", got.screen, got.operation, got.status, got.retry != nil, command)
	}
	view := got.View()
	for _, expected := range []string{
		"connect to cybet-backend01",
		"server rejected public-key authentication",
		"Suggested next steps",
		"authorized_keys",
		"opssh test cybet-backend01",
		"opssh config render cybet-backend01",
		"opssh sync cybet-backend01",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("connection error view lacks %q: %q", expected, view)
		}
	}
	if strings.Contains(view, "unspecified operation") || strings.Contains(view, "Add completed") {
		t.Fatalf("connection error view retained misleading context: %q", view)
	}
}

func TestStartingConnectionTracksOperationAndClearsOldStatus(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true, Runner: process.NewRunner(nil, nil)})
	model.loading = false
	model.status = "Add completed for cybet-backend01"
	updated, command := model.startConnection("cybet-backend01")
	got := updated.(Model)
	defer got.opCancel()

	if command == nil || !got.loading || got.operation != "connect to cybet-backend01" || got.retry == nil || got.opContext == nil {
		t.Fatalf("connection start = loading %v operation %q retry %v context %v command %v", got.loading, got.operation, got.retry != nil, got.opContext != nil, command)
	}
	if got.status != "" {
		t.Fatalf("connection start retained status %q", got.status)
	}
}

func TestClosedSSHSessionReturnsDirectlyToHosts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		err        error
		wantStatus string
	}{
		{name: "clean logout", wantStatus: "SSH session closed for prod-web"},
		{
			name:       "remote shell status",
			err:        &process.RunError{Tool: process.ToolOpenSSH, Kind: process.ErrorExit, ExitCode: 42},
			wantStatus: "SSH session closed for prod-web (remote exit status 42)",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			model := NewModel(Dependencies{NoColor: true})
			model.loading = true
			model.screen = screenError
			model.operation = "connect to prod-web"
			model.retry = func(context.Context, uint64) tea.Cmd { return nil }
			model.activeOpID = 11

			updated, command := model.Update(connectionFinishedMsg{alias: "prod-web", err: test.err, opID: 11})
			got := updated.(Model)
			if command != nil || got.screen != screenHosts || got.loading || got.operation != "" || got.retry != nil || got.status != test.wantStatus {
				t.Fatalf("closed session state = screen %v loading %v operation %q retry %v status %q command %v", got.screen, got.loading, got.operation, got.retry != nil, got.status, command)
			}
		})
	}
}

func TestSSHStatus255StillOpensConnectionError(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = true
	model.operation = "connect to blocked-host"
	model.activeOpID = 12
	err := &process.RunError{Tool: process.ToolOpenSSH, Kind: process.ErrorExit, ExitCode: 255}
	updated, command := model.Update(connectionFinishedMsg{alias: "blocked-host", err: err, opID: 12})
	got := updated.(Model)
	if command != nil || got.screen != screenError || got.operation != "connect to blocked-host" {
		t.Fatalf("SSH 255 state = screen %v operation %q command %v", got.screen, got.operation, command)
	}
	if !strings.Contains(got.View(), "SSH session ended before a connection could be established") {
		t.Fatalf("SSH 255 error view = %q", got.View())
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
	if view := model.View(); !strings.Contains(view, "Interaction help") || !strings.Contains(view, "Shift+Tab") {
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
	model.plan = app.Plan{Operation: "add", Alias: "prod-web"}
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	got := updated.(Model)
	if command != nil || got.screen != screenInput || got.wizard.step != 0 || got.input.Value() != "prod-web" {
		t.Fatalf("preview edit did not restore draft: screen=%v wizard=%#v value=%q command=%v", got.screen, got.wizard, got.input.Value(), command)
	}
}

func TestSyncPreviewCannotEnterEmptyEditWizard(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenPreview
	model.plan = app.Plan{Operation: "sync", Alias: "prod-web", ConfigPreview: "Host prod-web"}
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	got := updated.(Model)
	if command != nil || got.screen != screenPreview || got.wizard.alias != "" {
		t.Fatalf("sync preview entered an edit wizard: screen=%v wizard=%#v command=%v", got.screen, got.wizard, command)
	}
	if strings.Contains(got.View(), "edit draft") {
		t.Fatal("sync preview advertises an unavailable edit action")
	}
}

func TestTunnelMutationRefreshesTunnelTable(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenTunnels
	updated, command := model.Update(appliedMsg{message: "Started tunnel db", reloadTunnels: true})
	got := updated.(Model)
	if command == nil || !got.loading || got.operation != "refresh tunnel status" {
		t.Fatalf("tunnel mutation refresh state = loading %v operation %q command=%v", got.loading, got.operation, command)
	}
}

func TestScrolledTableMouseSelectionUsesVisibleOffset(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenDoctor
	model.width, model.height = 100, 18
	model.resizeComponents()
	rows := make([]table.Row, 30)
	for index := range rows {
		rows[index] = table.Row{"ok", fmt.Sprintf("check-%02d", index), "result"}
	}
	model.table.SetRows(rows)
	model.table.MoveDown(20)
	selectedVisualRow, ok := model.selectedTableVisualRow()
	if !ok || selectedVisualRow <= 0 {
		t.Fatalf("selected visual row = %d, found=%v", selectedVisualRow, ok)
	}
	want := model.table.Cursor() - selectedVisualRow
	updated, _ := model.Update(tea.MouseMsg{X: 10, Y: 6, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if got := updated.(Model).table.Cursor(); got != want {
		t.Fatalf("clicked first visible row selected %d, want %d", got, want)
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

func TestWideKeyPickerUsesTwoColumnsAndReportsPosition(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenKeys
	items := make([]list.Item, 0, 18)
	for index := 1; index <= 18; index++ {
		items = append(items, keyItem{key: domain.PublicKeyMetadata{
			Title:       fmt.Sprintf("key-%02d", index),
			AccountName: "Personal",
			VaultName:   "dev",
			Fingerprint: fmt.Sprintf("SHA256:test-%02d", index),
		}})
	}
	model.choices.SetItems(items)
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 160, Height: 37})
	model = updated.(Model)

	if model.keyPickerColumns() != 2 || model.choices.Paginator.PerPage != 16 || model.choices.Paginator.TotalPages != 2 {
		t.Fatalf("key grid = %d columns, %d per page, %d pages", model.keyPickerColumns(), model.choices.Paginator.PerPage, model.choices.Paginator.TotalPages)
	}
	view := model.View()
	for _, expected := range []string{"18 SSH keys", "Page 1 of 2", "Item 1 of 18"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("key picker lacks %q: %q", expected, view)
		}
	}
	foundTwoColumnRow := false
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "key-01") && strings.Contains(line, "key-02") {
			foundTwoColumnRow = true
		}
		if width := lipgloss.Width(line); width > 160 {
			t.Fatalf("key picker line width = %d, want <= 160: %q", width, line)
		}
	}
	if !foundTwoColumnRow {
		t.Fatalf("key picker did not render a two-column row: %q", view)
	}
	if height := len(strings.Split(view, "\n")); height > 37 {
		t.Fatalf("key picker height = %d, want <= 37", height)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRight})
	model = updated.(Model)
	if model.choices.Index() != 1 {
		t.Fatalf("right selected index = %d, want 1", model.choices.Index())
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	if model.choices.Index() != 3 {
		t.Fatalf("down selected index = %d, want 3", model.choices.Index())
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(Model)
	if model.choices.Index() != 17 || model.choices.Paginator.Page != 1 {
		t.Fatalf("page down selected index = %d page = %d, want index 17 page 1", model.choices.Index(), model.choices.Paginator.Page)
	}
}

func TestPreviewAccountsForNestedPanelFrames(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{})
	model.loading = false
	model.screen = screenPreview
	model.plan = app.Plan{
		Operation: "add",
		Alias:     "nyim-hk-2",
		ConfigPreview: strings.Join([]string{
			"# Managed by opssh. Manual changes may be overwritten.",
			"",
			"Host nyim-hk-2",
			"    HostName 43.199.247.207",
			"    User ubuntu",
			"    Port 22",
			`    IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"`,
			`    IdentityFile "~/.ssh/opssh/public_keys/nyim-hk-2.pub"`,
			"    IdentitiesOnly yes",
			"    StrictHostKeyChecking ask",
			"    ServerAliveInterval 30",
			"    ServerAliveCountMax 3",
			"    ProxyCommand nc -x localhost:7890 %h %p",
		}, "\n"),
		Changes: []app.ChangeSummary{
			{Action: "create", Path: "/Users/dev/.ssh/opssh/public_keys/nyim-hk-2.pub"},
			{Action: "create", Path: "/Users/dev/.ssh/config.d/nyim-hk-2.conf"},
		},
	}
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 160, Height: 37})
	view := updated.(Model).View()
	if !strings.Contains(view, "Host nyim-hk-2") || !strings.Contains(view, "nyim-hk-2.pub") {
		t.Fatalf("preview split short source lines unexpectedly: %q", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > 160 {
			t.Fatalf("preview line width = %d, want <= 160: %q", width, line)
		}
	}
}

func TestHostRefreshFocusesRequestedAlias(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.focusAlias = "host-18"
	hosts := make([]domain.Host, 0, 24)
	for index := 1; index <= 24; index++ {
		hosts = append(hosts, domain.Host{Alias: fmt.Sprintf("host-%02d", index), Hostname: "example.com", User: "ubuntu", Port: 22})
	}
	updated, _ := model.Update(hostsLoadedMsg{hosts: hosts})
	got := updated.(Model)
	if selected := got.selectedHost(); selected == nil || selected.Alias != "host-18" {
		t.Fatalf("selected host after refresh = %#v", selected)
	}
	if got.focusAlias != "" {
		t.Fatalf("focus alias was not consumed: %q", got.focusAlias)
	}
}

func TestEditWizardCanKeepOrChangeIdentity(t *testing.T) {
	t.Parallel()

	current := domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: "account", VaultID: "vault", ItemID: "current"}
	replacement := domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: "account", VaultID: "vault", ItemID: "replacement"}
	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model = model.beginEdit(domain.Host{
		Alias: "prod-web", Hostname: "example.com", User: "ubuntu", Port: 22,
		Proxy: domain.Proxy{Type: domain.ProxyNone}, Key: domain.KeyBinding{Reference: current, Title: "Current key"},
	})
	updated, command := model.afterProxy()
	model = updated.(Model)
	if command != nil || model.screen != screenIdentity || model.choices.Index() != 0 {
		t.Fatalf("identity decision = screen %v index %d command %v", model.screen, model.choices.Index(), command)
	}

	model.choices.Select(1)
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command == nil || !model.loading || model.operation != "load 1Password SSH Key metadata" || !model.wizard.changeKey {
		t.Fatalf("change identity start = loading %v operation %q change %v command %v", model.loading, model.operation, model.wizard.changeKey, command)
	}
	updated, _ = model.Update(keysLoadedMsg{opID: model.activeOpID, keys: []domain.PublicKeyMetadata{
		{Reference: current, Title: "Current key"},
		{Reference: replacement, Title: "Replacement key"},
	}})
	model = updated.(Model)
	if model.screen != screenKeys || model.choices.Index() != 0 {
		t.Fatalf("loaded key picker = screen %v index %d", model.screen, model.choices.Index())
	}
	model.choices.Select(1)
	updated, command = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if command == nil || !model.wizard.changeKey || model.wizard.reference != replacement || model.wizard.keyTitle != "Replacement key" {
		t.Fatalf("replacement identity = wizard %#v command %v", model.wizard, command)
	}
}

func TestMouseSelectsHostsKeysAndCommands(t *testing.T) {
	t.Parallel()

	hostModel := NewModel(Dependencies{NoColor: true})
	hostModel.loading = false
	hostModel.hosts.SetItems([]list.Item{
		hostItem{host: domain.Host{Alias: "one"}},
		hostItem{host: domain.Host{Alias: "two"}},
		hostItem{host: domain.Host{Alias: "three"}},
	})
	updated, _ := hostModel.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	if view := updated.(Model).View(); !strings.Contains(view, "Page 1 of 1") || !strings.Contains(view, "Host 1 of 3") {
		t.Fatalf("host list lacks explicit position: %q", view)
	}
	updated, _ = updated.(Model).Update(tea.MouseMsg{X: 4, Y: 7, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if selected := updated.(Model).selectedHost(); selected == nil || selected.Alias != "two" {
		t.Fatalf("mouse selected host = %#v", selected)
	}

	keyModel := NewModel(Dependencies{NoColor: true})
	keyModel.loading = false
	keyModel.screen = screenKeys
	keyModel.choices.SetItems([]list.Item{
		keyItem{key: domain.PublicKeyMetadata{Title: "left"}},
		keyItem{key: domain.PublicKeyMetadata{Title: "right"}},
	})
	updated, _ = keyModel.Update(tea.WindowSizeMsg{Width: 160, Height: 37})
	updated, _ = updated.(Model).Update(tea.MouseMsg{X: 84, Y: 7, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if index := updated.(Model).choices.Index(); index != 1 {
		t.Fatalf("mouse selected key index = %d, want 1", index)
	}

	commandModel := NewModel(Dependencies{NoColor: true})
	commandModel.loading = false
	commandModel = commandModel.openCommandPalette()
	updated, _ = commandModel.Update(tea.WindowSizeMsg{Width: 120, Height: 37})
	updated, _ = updated.(Model).Update(tea.MouseMsg{X: 4, Y: 10, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if got := updated.(Model); got.commandIndex != 1 || got.command.Value() != "test " {
		t.Fatalf("mouse command selection = index %d value %q", got.commandIndex, got.command.Value())
	}

	tableModel := NewModel(Dependencies{NoColor: true})
	tableModel.loading = false
	tableModel.screen = screenDoctor
	tableModel.table.SetRows([]table.Row{{"ok", "first", "one"}, {"warn", "second", "two"}})
	updated, _ = tableModel.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	updated, _ = updated.(Model).Update(tea.MouseMsg{X: 8, Y: 7, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if cursor := updated.(Model).table.Cursor(); cursor != 1 {
		t.Fatalf("mouse selected table row = %d, want 1", cursor)
	}
}

func TestScrollableViewsRespondToKeyboardAndMouseWheel(t *testing.T) {
	t.Parallel()

	model := NewModel(Dependencies{NoColor: true})
	model.loading = false
	model.screen = screenOutput
	model.outputBack = screenHosts
	model.outputTitle = "Long output"
	lines := make([]string, 50)
	for index := range lines {
		lines[index] = fmt.Sprintf("line %02d", index+1)
	}
	model.outputText = strings.Join(lines, "\n")
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model = updated.(Model)
	if model.viewport.YOffset != 0 || model.viewport.AtBottom() {
		t.Fatalf("initial viewport offset = %d bottom = %v", model.viewport.YOffset, model.viewport.AtBottom())
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	if model.viewport.YOffset == 0 {
		t.Fatal("keyboard did not scroll viewport")
	}
	before := model.viewport.YOffset
	updated, _ = model.Update(tea.MouseMsg{X: 10, Y: 8, Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	model = updated.(Model)
	if model.viewport.YOffset <= before {
		t.Fatalf("mouse wheel offset = %d, want > %d", model.viewport.YOffset, before)
	}
	if !strings.Contains(model.View(), "%") {
		t.Fatalf("scrolling view lacks position indicator: %q", model.View())
	}
}

func TestResponsiveViewMatrix(t *testing.T) {
	t.Parallel()

	base := NewModel(Dependencies{NoColor: true})
	base.loading = false
	hostItems := make([]list.Item, 0, 30)
	keyItems := make([]list.Item, 0, 25)
	for index := 1; index <= 30; index++ {
		hostItems = append(hostItems, hostItem{host: domain.Host{Alias: fmt.Sprintf("host-%02d", index), Hostname: "very-long-hostname.example.com", User: "ubuntu", Port: 22}})
		if index <= 25 {
			keyItems = append(keyItems, keyItem{key: domain.PublicKeyMetadata{Title: fmt.Sprintf("key-%02d", index), AccountName: "Personal", VaultName: "Development", Fingerprint: strings.Repeat("A", 48)}})
		}
	}
	hosts := base
	hosts.hosts.SetItems(hostItems)
	keys := base
	keys.screen = screenKeys
	keys.choices.SetItems(keyItems)
	preview := base
	preview.screen = screenPreview
	preview.plan = app.Plan{Operation: "edit", Alias: "host-01", ConfigPreview: strings.Repeat("Host host-01\n    ServerAliveInterval 30\n", 12)}
	failure := base
	failure.operation = "test SSH connection"
	failure = failure.showError(errors.New(strings.Repeat("connection diagnostic detail ", 20)))
	help := base.openHelp()
	output := base
	output.screen, output.outputTitle, output.outputText = screenOutput, "Rendered config", strings.Repeat("Host host-01\n", 40)
	command := base.openCommandPalette()

	views := []struct {
		name  string
		model Model
	}{{"hosts", hosts}, {"keys", keys}, {"preview", preview}, {"error", failure}, {"help", help}, {"output", output}, {"command", command}}
	sizes := []struct{ width, height int }{{60, 15}, {80, 24}, {120, 30}, {160, 37}}
	for _, size := range sizes {
		for _, item := range views {
			updated, _ := item.model.Update(tea.WindowSizeMsg{Width: size.width, Height: size.height})
			view := updated.(Model).View()
			lines := strings.Split(view, "\n")
			if len(lines) > size.height {
				t.Errorf("%s at %dx%d height = %d", item.name, size.width, size.height, len(lines))
			}
			for _, line := range lines {
				if width := lipgloss.Width(line); width > size.width {
					t.Errorf("%s at %dx%d line width = %d: %q", item.name, size.width, size.height, width, line)
				}
			}
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
