package tui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/vlyl/opssh/internal/domain"
)

const (
	compactWidth  = 58
	compactHeight = 11
	detailWidth   = 96
)

type keyHint struct {
	key   string
	label string
}

func (model Model) View() string {
	if model.loading {
		return model.renderLoading()
	}
	if model.width > 0 && (model.width < compactWidth || model.height < compactHeight) {
		return model.compactView()
	}

	body := ""
	switch model.screen {
	case screenHosts:
		body = model.renderHosts()
	case screenInput:
		body = model.renderInput()
	case screenProxy, screenKeys:
		body = model.renderChoices()
	case screenPreview:
		body = model.renderPreview()
	case screenConfirmDelete:
		body = model.renderDeleteConfirmation()
	case screenDoctor, screenTunnels:
		body = model.renderTable()
	case screenError:
		body = model.renderErrorView()
	case screenCommand:
		body = model.renderCommandPalette()
	case screenHelp:
		body = model.renderHelp()
	default:
		body = "opssh"
	}

	sections := []string{model.renderHeader(), body}
	if status := model.renderStatus(); status != "" {
		sections = append(sections, status)
	}
	if footer := model.renderFooter(); footer != "" {
		sections = append(sections, footer)
	}
	view := lipgloss.JoinVertical(lipgloss.Left, sections...)
	return lipgloss.NewStyle().Padding(0, 1).Render(view)
}

func (model *Model) resizeComponents() {
	width := model.contentWidth()
	height := model.bodyHeight()
	var hostWidth int
	if width >= detailWidth {
		hostWidth = (width*58)/100 - 6
	} else {
		hostWidth = width - 6
	}
	model.hosts.SetSize(max(28, hostWidth), max(5, height-2))
	model.choices.SetSize(max(28, width-6), max(5, height-2))
	model.table.SetWidth(max(40, width-4))
	model.table.SetHeight(max(5, height-3))
	model.configureTableColumns()
}

func (model *Model) configureTable(first, second, third string) {
	width := max(40, model.contentWidth()-4)
	firstWidth := 9
	secondWidth := min(28, max(16, width/3))
	thirdWidth := max(18, width-firstWidth-secondWidth-3)
	model.table.SetColumns([]table.Column{
		{Title: first, Width: firstWidth},
		{Title: second, Width: secondWidth},
		{Title: third, Width: thirdWidth},
	})
}

func (model *Model) configureTableColumns() {
	if model.screen == screenTunnels {
		model.configureTable("State", "Tunnel", "Route")
		return
	}
	model.configureTable("Level", "Check", "Result")
}

func (model Model) contentWidth() int {
	if model.width <= 0 {
		return 96
	}
	return max(30, model.width-2)
}

func (model Model) bodyHeight() int {
	if model.height <= 0 {
		return 17
	}
	return max(5, model.height-7)
}

func (model Model) renderHeader() string {
	width := model.contentWidth()
	left := model.styles.brand.Render("opssh") + model.styles.muted.Render("  /  ") + model.styles.title.Render(model.screenTitle())
	right := ""
	if model.screen == screenHosts {
		count := len(model.hosts.Items())
		noun := "hosts"
		if count == 1 {
			noun = "host"
		}
		right = model.styles.badge.Render(fmt.Sprintf("%d %s", count, noun))
	} else if progress := model.wizardProgress(); progress != "" {
		right = model.styles.badge.Render(progress)
	}
	line := joinEdges(left, right, width)
	divider := model.styles.muted.Render(strings.Repeat("─", max(1, width)))
	return line + "\n" + divider
}

func (model Model) screenTitle() string {
	switch model.screen {
	case screenHosts:
		return "Hosts"
	case screenInput:
		if model.wizard.editing {
			return "Edit host"
		}
		return "Add host"
	case screenProxy:
		return "Connection route"
	case screenKeys:
		return "SSH identity"
	case screenPreview:
		return "Review changes"
	case screenConfirmDelete:
		return "Remove host"
	case screenDoctor:
		return "Diagnostics"
	case screenTunnels:
		return "Tunnels"
	case screenError:
		return "Error details"
	case screenCommand:
		return "Command palette"
	case screenHelp:
		return "Keyboard help"
	default:
		return ""
	}
}

func (model Model) renderHosts() string {
	width := model.contentWidth()
	if len(model.hosts.Items()) == 0 {
		message := model.styles.title.Render("No managed hosts yet") + "\n\n" +
			model.styles.subtitle.Render("Add a host to bind one SSH destination to one 1Password Agent identity.") + "\n\n" +
			model.styles.accent.Render("Press a to add your first host")
		return model.styles.panelStrong.Width(max(28, width-4)).Padding(2, 2).Render(message)
	}

	if width < detailWidth {
		return model.styles.panel.Width(max(28, width-4)).Render(model.hosts.View())
	}

	leftWidth := (width * 58) / 100
	rightWidth := width - leftWidth - 1
	left := model.styles.panel.Width(max(28, leftWidth-4)).Render(model.hosts.View())
	right := model.styles.panelStrong.Width(max(28, rightWidth-4)).Height(max(8, model.bodyHeight())).Render(model.renderHostDetail(rightWidth - 6))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (model Model) renderHostDetail(width int) string {
	host := model.selectedHost()
	if host == nil {
		return model.styles.muted.Render("Select a host to inspect its connection details.")
	}
	route := proxyDescription(host.Proxy)
	target := fmt.Sprintf("%s@%s", host.User, net.JoinHostPort(unbracket(host.Hostname), strconv.Itoa(int(host.Port))))
	keyTitle := host.Key.Title
	if keyTitle == "" {
		keyTitle = "1Password SSH Key"
	}
	lines := []string{
		model.styles.accent.Render("● READY") + "  " + model.styles.title.Render(host.Alias),
		"",
		detailRow(model, "Target", target, width),
		detailRow(model, "Route", route, width),
		detailRow(model, "Identity", keyTitle, width),
		detailRow(model, "Fingerprint", host.Key.Fingerprint, width),
		"",
		model.styles.muted.Render("OpenSSH offers only this public identity"),
		model.styles.muted.Render("with IdentitiesOnly enabled."),
	}
	return strings.Join(lines, "\n")
}

func detailRow(model Model, label, value string, width int) string {
	labelWidth := min(11, max(7, width/4))
	labelText := model.styles.muted.Width(labelWidth).Render(label)
	valueWidth := max(12, width-labelWidth-2)
	return labelText + "  " + model.styles.subtitle.Render(truncate(value, valueWidth))
}

func (model Model) renderInput() string {
	width := model.contentWidth()
	fieldWidth := min(72, max(28, width-4))
	help := model.styles.subtitle.Render(model.inputHint())
	field := model.styles.panelStrong.Width(fieldWidth).Render(model.input.View())
	parts := []string{model.styles.title.Render(model.wizardPrompt()), help, "", field}
	if model.formErr != "" {
		parts = append(parts, model.styles.error.Render("! "+model.formErr))
	}
	parts = append(parts, "", model.styles.help.Render("Values are connection metadata only; private-key material is never requested."))
	form := strings.Join(parts, "\n")

	if width < detailWidth {
		return form
	}
	summaryWidth := max(28, width-fieldWidth-5)
	summary := model.styles.panel.Width(summaryWidth).Render(model.renderWizardSummary(summaryWidth - 4))
	return lipgloss.JoinHorizontal(lipgloss.Top, form, "   ", summary)
}

func (model Model) wizardPrompt() string {
	switch model.wizard.step {
	case 0:
		return "Choose a memorable SSH alias"
	case 1:
		return "Where should SSH connect?"
	case 2:
		return "Which remote user should SSH use?"
	case 3:
		return "Which SSH port is listening?"
	case 100:
		if model.wizard.proxy.Type == domain.ProxyJump {
			return "Which managed host is the jump host?"
		}
		return "Where is the proxy listening?"
	default:
		return "Host details"
	}
}

func (model Model) inputHint() string {
	switch model.wizard.step {
	case 0:
		return "Used by commands such as ssh <alias> and by Git SSH URLs."
	case 1:
		return "Enter a DNS hostname or IP address; both are supported."
	case 2:
		return "For example: ubuntu, root, deploy, or git."
	case 3:
		return "The default SSH port is 22."
	case 100:
		if model.wizard.proxy.Type == domain.ProxyJump {
			return "Enter another opssh host alias."
		}
		return "Use host:port, for example 127.0.0.1:1080."
	default:
		return ""
	}
}

func (model Model) renderWizardSummary(width int) string {
	title := "New host"
	if model.wizard.editing {
		title = "Current draft"
	}
	return strings.Join([]string{
		model.styles.title.Render(title),
		"",
		detailRow(model, "Alias", placeholder(model.wizard.alias), width),
		detailRow(model, "Host", placeholder(model.wizard.hostname), width),
		detailRow(model, "User", placeholder(model.wizard.user), width),
		detailRow(model, "Port", strconv.Itoa(int(model.wizard.port)), width),
		detailRow(model, "Route", proxyDescription(model.wizard.proxy), width),
		detailRow(model, "Identity", placeholder(model.wizard.keyTitle), width),
	}, "\n")
}

func (model Model) renderChoices() string {
	width := model.contentWidth()
	description := "Choose how OpenSSH reaches this host. Direct is the safest default."
	if model.screen == screenKeys {
		description = "Choose the public identity OpenSSH should request from the 1Password SSH Agent."
	}
	return model.styles.subtitle.Render(description) + "\n\n" +
		model.styles.panelStrong.Width(max(28, width-4)).Render(model.choices.View())
}

func (model Model) renderPreview() string {
	width := model.contentWidth()
	var changes strings.Builder
	if len(model.plan.Changes) == 0 {
		_, _ = fmt.Fprint(&changes, model.styles.muted.Render("No managed files change."))
	} else {
		for _, change := range model.plan.Changes {
			_, _ = fmt.Fprintf(&changes, "%s  %s\n", model.styles.accent.Render(strings.ToUpper(change.Action)), change.Path)
		}
	}
	sections := []string{
		model.styles.subtitle.Render("Review the exact OpenSSH fragment and managed paths before applying."),
		"",
		model.styles.title.Render("OpenSSH preview"),
		model.styles.code.Width(max(24, width-4)).Padding(0, 1).Render(strings.TrimSpace(model.plan.ConfigPreview)),
		"",
		model.styles.title.Render("File changes"),
		strings.TrimRight(changes.String(), "\n"),
	}
	if len(model.plan.Notices) > 0 {
		sections = append(sections, "", model.styles.warning.Render("Notes"))
		for _, notice := range model.plan.Notices {
			sections = append(sections, "  • "+notice)
		}
	}
	return model.styles.panelStrong.Width(max(28, width-4)).Render(strings.Join(sections, "\n"))
}

func (model Model) renderDeleteConfirmation() string {
	width := min(72, max(28, model.contentWidth()-4))
	content := strings.Join([]string{
		model.styles.error.Render("Remove “" + model.deleteAlias + "” from opssh?"),
		"",
		"Its managed SSH fragment and .pub file will be removed.",
		model.styles.muted.Render("The 1Password item and remote authorized_keys are never changed."),
	}, "\n")
	return model.styles.panelStrong.Width(width).Padding(1, 2).Render(content)
}

func (model Model) renderTable() string {
	description := "Dependency, configuration, and security-boundary checks."
	if model.screen == screenTunnels {
		description = "Inspect configured local forwards and control the selected tunnel."
	}
	return model.styles.subtitle.Render(description) + "\n\n" +
		model.styles.panel.Width(max(36, model.contentWidth()-4)).Render(model.table.View())
}

func (model Model) renderErrorView() string {
	operation := model.operation
	if operation == "" {
		operation = "unspecified operation"
	}
	var builder strings.Builder
	_, _ = fmt.Fprintln(&builder, model.styles.error.Render("! The operation did not complete"))
	_, _ = fmt.Fprintf(&builder, "\n%s\n  %s\n\n%s\n  %s\n", model.styles.title.Render("Operation:"), operation, model.styles.title.Render("Summary:"), model.err.Error())
	if len(model.errorCauses) > 0 {
		_, _ = fmt.Fprintln(&builder, "\n"+model.styles.title.Render("Cause chain:"))
		for index, cause := range model.errorCauses {
			_, _ = fmt.Fprintf(&builder, "  %d. %s\n", index+1, cause)
		}
	}
	if len(model.diagnostics) > 0 {
		_, _ = fmt.Fprintln(&builder, "\n"+model.styles.title.Render("Diagnostic commands:"))
		for _, command := range model.diagnostics {
			_, _ = fmt.Fprintf(&builder, "  %s\n", model.styles.code.Padding(0, 1).Render(command))
		}
	}
	return model.styles.panelStrong.Width(max(34, model.contentWidth()-4)).Render(strings.TrimRight(builder.String(), "\n"))
}

func (model Model) renderCommandPalette() string {
	width := model.contentWidth()
	commands := []string{
		"doctor          Run environment diagnostics",
		"config validate Validate every managed SSH host",
		"hosts           Refresh the managed host list",
		"tunnels         Open tunnel status",
		"retry           Retry the last failed operation",
		"cancel          Cancel the current operation",
		"help            Open keyboard help",
		"quit            Exit opssh",
	}
	input := model.styles.panelStrong.Width(min(76, max(28, width-4))).Render(model.command.View())
	parts := []string{
		model.styles.subtitle.Render("Run an opssh built-in. Shell commands are intentionally disabled."),
		"",
		input,
	}
	if model.commandErr != "" {
		parts = append(parts, model.styles.error.Render("! "+model.commandErr))
	}
	parts = append(parts, "", model.styles.title.Render("Available commands"))
	for _, command := range commands {
		parts = append(parts, "  "+command)
	}
	return strings.Join(parts, "\n")
}

func (model Model) renderHelp() string {
	sections := []string{
		model.styles.title.Render("Navigate"),
		"  ↑/k, ↓/j       Move selection",
		"  /              Search the current list",
		"  enter          Open or confirm",
		"  esc            Go back or cancel",
		"",
		model.styles.title.Render("Hosts"),
		"  a  Add          e  Edit          d  Delete",
		"  s  Sync key     x  Test          enter  Connect",
		"  t  Tunnels      D  Doctor        r  Refresh",
		"",
		model.styles.title.Render("Everywhere"),
		"  :  Command palette     ?  Toggle help     q  Quit",
		"",
		model.styles.muted.Render("Tip: Shift+Tab moves to the previous wizard step without discarding the draft."),
	}
	return model.styles.panelStrong.Width(min(82, max(34, model.contentWidth()-4))).Render(strings.Join(sections, "\n"))
}

func (model Model) renderStatus() string {
	if model.status == "" {
		return ""
	}
	return model.styles.status.Render("✓ " + model.status)
}

func (model Model) renderFooter() string {
	var hints []keyHint
	switch model.screen {
	case screenHosts:
		hints = []keyHint{{"enter", "connect"}, {"a", "add"}, {"e", "edit"}, {"s", "sync"}, {"x", "test"}, {"t", "tunnels"}, {"D", "doctor"}, {"r", "refresh"}, {"/", "search"}, {":", "command"}, {"?", "help"}, {"q", "quit"}}
	case screenInput:
		hints = []keyHint{{"enter", "continue"}, {"shift+tab", "previous"}, {"esc", "cancel"}}
	case screenProxy, screenKeys:
		hints = []keyHint{{"enter", "select"}, {"shift+tab", "previous"}, {"/", "search"}, {"esc", "cancel"}, {"?", "help"}}
	case screenPreview:
		hints = []keyHint{{"enter", "apply"}, {"e", "edit draft"}, {"esc", "cancel"}, {"?", "help"}}
	case screenConfirmDelete:
		hints = []keyHint{{"y", "remove"}, {"esc", "keep host"}}
	case screenDoctor:
		hints = []keyHint{{"j/k", "navigate"}, {"esc", "hosts"}, {"?", "help"}}
	case screenTunnels:
		hints = []keyHint{{"j/k", "navigate"}, {"s", "start"}, {"x", "stop"}, {"esc", "hosts"}, {"?", "help"}}
	case screenError:
		hints = []keyHint{{"r", "retry"}, {":/enter", "command"}, {"esc", "cancel current operation"}, {"q", "quit"}}
	case screenCommand:
		hints = []keyHint{{"enter", "run"}, {"esc", "close"}}
	case screenHelp:
		hints = []keyHint{{"?/esc", "close help"}}
	}
	return renderKeyHints(model.styles, hints, model.contentWidth())
}

func renderKeyHints(styleSet styles, hints []keyHint, width int) string {
	if len(hints) == 0 {
		return ""
	}
	rows := []string{""}
	rowWidth := 0
	for _, hint := range hints {
		piece := styleSet.key.Render(hint.key) + " " + styleSet.keyLabel.Render(hint.label)
		pieceWidth := lipgloss.Width(piece)
		separator := "   "
		if rowWidth > 0 && rowWidth+lipgloss.Width(separator)+pieceWidth > width {
			rows = append(rows, piece)
			rowWidth = pieceWidth
			continue
		}
		if rowWidth == 0 {
			rows[len(rows)-1] = piece
			rowWidth = pieceWidth
			continue
		}
		rows[len(rows)-1] += separator + piece
		rowWidth += lipgloss.Width(separator) + pieceWidth
	}
	return strings.Join(rows, "\n")
}

func (model Model) renderLoading() string {
	width := model.contentWidth()
	height := model.height
	if height <= 0 {
		height = 12
	}
	content := model.styles.brand.Render("opssh") + "\n\n" + model.spinner.View() + " " + titleWord(model.operation) + "…\n\n" + model.styles.help.Render("Esc cancels this operation")
	return lipgloss.Place(width, max(5, height-1), lipgloss.Center, lipgloss.Center, model.styles.panelStrong.Padding(1, 3).Render(content))
}

func (model Model) compactView() string {
	if model.screen != screenHosts {
		return "opssh · " + model.screenTitle() + "\n\nTerminal is too small for this view.\nResize it or press Esc to go back."
	}
	selected := model.selectedHost()
	if selected == nil {
		return "opssh · Hosts\n\nNo managed hosts\n\na add  ·  ? help  ·  q quit"
	}
	return fmt.Sprintf("opssh · %s\n%s@%s\nport %d · %s\n\nenter connect  ·  / search  ·  ? help", selected.Alias, selected.User, selected.Hostname, selected.Port, proxyDescription(selected.Proxy))
}

func (model Model) wizardProgress() string {
	if model.screen != screenInput && model.screen != screenProxy && model.screen != screenKeys {
		return ""
	}
	total := 6
	if model.wizard.editing {
		total = 5
	}
	step := model.wizard.step + 1
	if model.screen == screenProxy || model.wizard.step == 100 {
		step = 5
	}
	if model.screen == screenKeys {
		step = 6
	}
	return fmt.Sprintf("step %d of %d", min(step, total), total)
}

func proxyDescription(proxy domain.Proxy) string {
	switch proxy.Type {
	case domain.ProxyNone:
		return "Direct"
	case domain.ProxySOCKS5:
		return "SOCKS5 via " + net.JoinHostPort(unbracket(proxy.Host), strconv.Itoa(int(proxy.Port)))
	case domain.ProxyHTTPConnect:
		return "HTTP CONNECT via " + net.JoinHostPort(unbracket(proxy.Host), strconv.Itoa(int(proxy.Port)))
	case domain.ProxyJump:
		if proxy.JumpHost == "" {
			return "ProxyJump"
		}
		return "ProxyJump via " + proxy.JumpHost
	default:
		return "Direct"
	}
}

func joinEdges(left, right string, width int) string {
	if right == "" {
		return left
	}
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 2 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}

func truncate(value string, width int) string {
	if width <= 0 || lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	runes := []rune(value)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}

func placeholder(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

var _ list.Item = hostItem{}
