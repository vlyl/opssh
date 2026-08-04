package tui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
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
	case screenProxy, screenIdentity, screenKeys:
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
	case screenOutput:
		body = model.renderScrollablePanel()
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
	model.hosts.SetSize(max(28, hostWidth), max(5, height-3))
	model.choices.SetSize(max(28, width-6), max(5, height-2))
	if model.screen == screenKeys {
		model.configureKeyPicker()
	}
	model.table.SetWidth(max(40, width-4))
	model.table.SetHeight(max(5, height-3))
	model.configureTableColumns()
	if model.isScrollableScreen() {
		model.configureViewport(false)
	}
}

func (model Model) viewportSize() (int, int, int) {
	panel := model.styles.panelStrong
	panelWidth := max(24, model.contentWidth()-panel.GetHorizontalBorderSize())
	innerWidth := max(20, panelWidth-panel.GetHorizontalPadding())
	height := max(3, model.bodyHeight()-panel.GetVerticalFrameSize())
	return panelWidth, innerWidth, height
}

func (model *Model) configureViewport(reset bool) {
	_, width, height := model.viewportSize()
	model.viewport.Width = width
	model.viewport.Height = height
	model.viewport.SetContent(model.scrollableContent(width))
	if reset {
		model.viewport.GotoTop()
	}
}

func (model Model) isScrollableScreen() bool {
	return model.screen == screenPreview || model.screen == screenError || model.screen == screenHelp || model.screen == screenOutput
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
		return 24
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
	case screenIdentity:
		return "SSH identity"
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
		return "Interaction help"
	case screenOutput:
		return model.outputTitle
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
		return model.styles.panel.Width(max(28, width-4)).Render(model.renderHostList())
	}

	leftWidth := (width * 58) / 100
	rightWidth := width - leftWidth - 1
	left := model.styles.panel.Width(max(28, leftWidth-4)).Render(model.renderHostList())
	right := model.styles.panelStrong.Width(max(28, rightWidth-4)).Height(max(8, model.bodyHeight())).Render(model.renderHostDetail(rightWidth - 6))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (model Model) renderHostList() string {
	count := len(model.hosts.VisibleItems())
	page := model.hosts.Paginator.Page
	pages := max(1, model.hosts.Paginator.TotalPages)
	left := fmt.Sprintf("%d hosts", count)
	if model.hosts.IsFiltered() {
		left = fmt.Sprintf("%d matches", count)
	}
	right := fmt.Sprintf("Page %d of %d", page+1, pages)
	if count > 0 {
		right += fmt.Sprintf("  •  Host %d of %d", model.hosts.Index()+1, count)
	}
	width := max(24, model.hosts.Width())
	return joinEdges(model.styles.title.Render(left), model.styles.muted.Render(right), width) + "\n" + model.hosts.View()
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
		model.styles.accent.Render("● CONFIGURED") + "  " + model.styles.title.Render(host.Alias),
		"",
		detailRow(model, "Target", target, width),
		detailRow(model, "Route", route, width),
		detailRow(model, "Identity", keyTitle, width),
		detailRow(model, "Fingerprint", host.Key.Fingerprint, width),
		"",
		model.styles.muted.Render("Managed config pins this public identity."),
		model.styles.muted.Render("Run Test to verify network and authentication readiness."),
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
	if model.screen == screenKeys {
		return model.renderKeyPicker()
	}
	width := model.contentWidth()
	description := "Choose how OpenSSH reaches this host. Direct is the safest default."
	if model.screen == screenIdentity {
		description = "Keep the current public identity or bind this host to another 1Password SSH key."
	}
	return model.styles.subtitle.Render(description) + "\n\n" +
		model.styles.panelStrong.Width(max(28, width-4)).Render(model.choices.View())
}

func (model Model) keyPickerColumns() int {
	if model.contentWidth() >= 104 {
		return 2
	}
	return 1
}

func (model Model) keyPickerRows() int {
	return max(1, (model.bodyHeight()-5)/3)
}

func (model *Model) configureKeyPicker() {
	index := model.choices.Index()
	count := len(model.choices.VisibleItems())
	model.choices.Paginator.PerPage = model.keyPickerColumns() * model.keyPickerRows()
	if count == 0 {
		model.choices.Paginator.TotalPages = 1
		model.choices.Select(0)
		return
	}
	model.choices.Paginator.SetTotalPages(count)
	model.choices.Select(min(index, count-1))
}

func (model Model) renderKeyPicker() string {
	width := model.contentWidth()
	panel := model.styles.panelStrong
	panelWidth := max(24, width-panel.GetHorizontalBorderSize())
	innerWidth := max(20, panelWidth-panel.GetHorizontalPadding())
	items := model.choices.VisibleItems()
	count := len(items)
	page := model.choices.Paginator.Page
	pages := max(1, model.choices.Paginator.TotalPages)
	index := model.choices.Index()

	left := fmt.Sprintf("%d SSH keys", count)
	if model.choices.SettingFilter() {
		left = model.choices.FilterInput.View()
	} else if model.choices.IsFiltered() {
		left = fmt.Sprintf("%d matches for %q", count, model.choices.FilterValue())
	}
	right := fmt.Sprintf("Page %d of %d", page+1, pages)
	if count > 0 {
		right += fmt.Sprintf("  •  Item %d of %d", index+1, count)
	}

	parts := []string{joinEdges(model.styles.title.Render(left), model.styles.muted.Render(right), innerWidth), ""}
	perPage := max(1, model.choices.Paginator.PerPage)
	start := min(page*perPage, count)
	end := min(start+perPage, count)
	columns := model.keyPickerColumns()
	gap := 3
	cardWidth := innerWidth
	if columns == 2 {
		cardWidth = max(18, (innerWidth-gap)/2)
	}
	for rowStart := start; rowStart < end; rowStart += columns {
		cards := make([]string, 0, columns)
		for column := 0; column < columns; column++ {
			itemIndex := rowStart + column
			if itemIndex < end {
				cards = append(cards, model.renderKeyCard(items[itemIndex], itemIndex == index, cardWidth))
			} else {
				cards = append(cards, strings.Repeat(" ", cardWidth))
			}
		}
		row := cards[0]
		if len(cards) == 2 {
			row = lipgloss.JoinHorizontal(lipgloss.Top, cards[0], strings.Repeat(" ", gap), cards[1])
		}
		parts = append(parts, row)
		if rowStart+columns < end {
			parts = append(parts, "")
		}
	}
	if count == 0 {
		parts = append(parts, model.styles.muted.Render("No SSH keys match the current search."))
	}

	descriptionText := "Choose the public identity OpenSSH should request from the 1Password SSH Agent."
	if width < detailWidth {
		descriptionText = "Choose a 1Password SSH public identity."
	}
	description := model.styles.subtitle.Width(width).Render(descriptionText)
	return description + "\n\n" + panel.Width(panelWidth).Render(strings.Join(parts, "\n"))
}

func (model Model) renderKeyCard(item list.Item, selected bool, width int) string {
	key, ok := item.(keyItem)
	if !ok {
		return strings.Repeat(" ", width)
	}
	card := lipgloss.NewStyle().Border(lipgloss.ThickBorder(), false, false, false, true).PaddingLeft(1).BorderForeground(model.styles.muted.GetForeground())
	if selected {
		card = card.BorderForeground(model.styles.accent.GetForeground())
	}
	boxWidth := max(1, width-card.GetHorizontalBorderSize())
	contentWidth := max(1, boxWidth-card.GetHorizontalPadding())
	title := model.styles.title.Render(truncate(key.Title(), contentWidth))
	if selected {
		title = model.styles.accent.Render(truncate(key.Title(), contentWidth))
	}
	description := model.styles.muted.Render(truncate(key.Description(), contentWidth))
	return card.Width(boxWidth).Render(title + "\n" + description)
}

func (model Model) renderPreview() string {
	return model.renderScrollablePanel()
}

func (model Model) previewContent(innerWidth int) string {
	code := model.styles.code.Padding(0, 1)
	codeWidth := innerWidth
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
		code.Width(codeWidth).Render(strings.TrimSpace(model.plan.ConfigPreview)),
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
	return lipgloss.NewStyle().Width(innerWidth).Render(strings.Join(sections, "\n"))
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

func (model Model) selectedTableVisualRow() (int, bool) {
	row := model.table.SelectedRow()
	columns := model.table.Columns()
	if len(row) == 0 || len(columns) == 0 {
		return 0, false
	}
	for index, line := range strings.Split(model.table.View(), "\n") {
		if index > 0 && tableLineContainsRow(line, row, columns) {
			return index - 1, true
		}
	}
	return 0, false
}

func tableLineContainsRow(line string, row table.Row, columns []table.Column) bool {
	matched := false
	for index, value := range row {
		if index >= len(columns) || columns[index].Width <= 0 || value == "" {
			continue
		}
		token := runewidth.Truncate(value, columns[index].Width, "…")
		if token == "" || !strings.Contains(line, token) {
			return false
		}
		matched = true
	}
	return matched
}

func (model Model) renderErrorView() string {
	return model.renderScrollablePanel()
}

func (model Model) errorContent(innerWidth int) string {
	operation := model.operation
	if operation == "" {
		operation = "unspecified operation"
	}
	summary := "unknown error"
	if model.err != nil {
		summary = model.err.Error()
	}
	var builder strings.Builder
	_, _ = fmt.Fprintln(&builder, model.styles.error.Render("! The operation did not complete"))
	_, _ = fmt.Fprintf(&builder, "\n%s\n  %s\n\n%s\n  %s\n", model.styles.title.Render("Operation:"), operation, model.styles.title.Render("Summary:"), summary)
	if len(model.errorCauses) > 0 {
		_, _ = fmt.Fprintln(&builder, "\n"+model.styles.title.Render("Cause chain:"))
		for index, cause := range model.errorCauses {
			_, _ = fmt.Fprintf(&builder, "  %d. %s\n", index+1, cause)
		}
	}
	if len(model.errorActions) > 0 {
		_, _ = fmt.Fprintln(&builder, "\n"+model.styles.title.Render("Suggested next steps:"))
		for _, action := range model.errorActions {
			_, _ = fmt.Fprintf(&builder, "  • %s\n", action)
		}
	}
	if len(model.diagnostics) > 0 {
		_, _ = fmt.Fprintln(&builder, "\n"+model.styles.title.Render("Diagnostic commands:"))
		for index, command := range model.diagnostics {
			prefix := "  "
			style := model.styles.code.Padding(0, 1)
			if index == model.errorCommand && isBuiltinCommand(command) {
				prefix = model.styles.accent.Render("› ")
				style = style.Bold(true)
			}
			_, _ = fmt.Fprintf(&builder, "%s%s\n", prefix, style.Render(command))
		}
		_, _ = fmt.Fprintln(&builder, model.styles.muted.Render("  Tab selects an opssh command · Enter runs it"))
	}
	return lipgloss.NewStyle().Width(innerWidth).Render(strings.TrimRight(builder.String(), "\n"))
}

func (model Model) renderCommandPalette() string {
	width := model.contentWidth()
	input := model.styles.panelStrong.Width(min(76, max(28, width-4))).Render(model.command.View())
	description := "Run an opssh built-in. Shell commands are intentionally disabled."
	if width < detailWidth {
		description = "Run a safe opssh built-in command."
	}
	parts := []string{
		model.styles.subtitle.Width(width).Render(description),
		"",
		input,
	}
	if model.commandErr != "" {
		parts = append(parts, model.styles.error.Render("! "+model.commandErr))
	}
	parts = append(parts, "", model.styles.title.Render("Available commands"))
	specs := commandSpecs()
	start, end := model.commandWindow(len(specs))
	for index := start; index < end; index++ {
		command := specs[index]
		prefix := "  "
		usage := model.styles.subtitle.Render(command.usage)
		if index == model.commandIndex {
			prefix = model.styles.accent.Render("› ")
			usage = model.styles.accent.Render(command.usage)
		}
		parts = append(parts, prefix+usage+"  "+model.styles.muted.Render(command.description))
	}
	return strings.Join(parts, "\n")
}

func (model Model) commandWindow(count int) (int, int) {
	visible := min(count, max(1, model.bodyHeight()-7))
	start := max(0, model.commandIndex-visible/2)
	if start+visible > count {
		start = max(0, count-visible)
	}
	return start, min(count, start+visible)
}

func (model Model) renderHelp() string {
	return model.renderScrollablePanel()
}

func (model Model) helpContent(innerWidth int) string {
	sections := []string{
		model.styles.title.Render("Navigate"),
		"  ←/h, ↑/k, ↓/j, →/l  Move selection",
		"  pgup/pgdown          Change page",
		"  /              Search the current list",
		"  enter          Open or confirm",
		"  esc            Go back or cancel",
		"  Shift+Tab      Previous wizard step",
		"",
		model.styles.title.Render("Mouse"),
		"  click          Focus a host, key, route, table row, or command",
		"  wheel          Move list selection or scroll long content",
		"",
		model.styles.title.Render("Hosts"),
		"  a  Add          e  Edit          d  Delete",
		"  s  Sync key     x  Test          enter  Connect",
		"  t  Tunnels      D  Doctor        r  Refresh",
		"",
		model.styles.title.Render("Everywhere"),
		"  :  Command palette     ?  Toggle help     q  Quit",
		model.styles.muted.Render("Mouse actions use the same safe built-in command allow-list as the keyboard."),
	}
	return lipgloss.NewStyle().Width(innerWidth).Render(strings.Join(sections, "\n"))
}

func (model Model) outputContent(innerWidth int) string {
	return model.styles.code.Padding(0, 1).Width(innerWidth).Render(strings.TrimSpace(model.outputText))
}

func (model Model) scrollableContent(innerWidth int) string {
	switch model.screen {
	case screenPreview:
		return model.previewContent(innerWidth)
	case screenError:
		return model.errorContent(innerWidth)
	case screenHelp:
		return model.helpContent(innerWidth)
	case screenOutput:
		return model.outputContent(innerWidth)
	default:
		return ""
	}
}

func (model Model) renderScrollablePanel() string {
	panelWidth, innerWidth, height := model.viewportSize()
	contentViewport := model.viewport
	contentViewport.Width = innerWidth
	contentViewport.Height = height
	contentViewport.SetContent(model.scrollableContent(innerWidth))
	return model.styles.panelStrong.Width(panelWidth).Render(contentViewport.View())
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
		if model.contentWidth() < detailWidth {
			hints = []keyHint{{"enter", "connect"}, {"a", "add"}, {"e", "edit"}, {"/", "search"}, {":", "command"}, {"?", "more"}}
		} else {
			hints = []keyHint{{"enter", "connect"}, {"a", "add"}, {"e", "edit"}, {"s", "sync"}, {"x", "test"}, {"t", "tunnels"}, {"D", "doctor"}, {"r", "refresh"}, {"/", "search"}, {":", "command"}, {"?", "help"}, {"q", "quit"}}
		}
	case screenInput:
		hints = []keyHint{{"enter", "continue"}, {"shift+tab", "previous"}, {"esc", "cancel"}}
	case screenProxy, screenIdentity:
		hints = []keyHint{{"enter", "select"}, {"shift+tab", "previous"}, {"/", "search"}, {"esc", "cancel"}, {"?", "help"}}
	case screenKeys:
		hints = []keyHint{{"←↑↓→", "navigate"}, {"pgup/dn", "page"}, {"enter", "select"}, {"/", "search"}, {"shift+tab", "previous"}, {"esc", "cancel"}, {"?", "help"}}
	case screenPreview:
		hints = []keyHint{{"j/k", "scroll"}, {"pgup/dn", model.scrollPosition()}, {"enter", "apply"}}
		if model.canEditPreview() {
			hints = append(hints, keyHint{"e", "edit draft"})
		}
		hints = append(hints, keyHint{"esc", "cancel"}, keyHint{"?", "help"})
	case screenConfirmDelete:
		hints = []keyHint{{"y", "remove"}, {"esc", "keep host"}}
	case screenDoctor:
		hints = []keyHint{{"j/k", "navigate"}, {"esc", "hosts"}, {"?", "help"}}
	case screenTunnels:
		hints = []keyHint{{"j/k", "navigate"}, {"s", "start"}, {"x", "stop"}, {"esc", "hosts"}, {"?", "help"}}
	case screenError:
		hints = []keyHint{{"j/k", "scroll"}, {"pgup/dn", model.scrollPosition()}, {"tab", "select command"}, {"enter", "run"}, {"r", "retry"}, {":", "command"}, {"esc", "cancel current operation"}}
	case screenCommand:
		hints = []keyHint{{"enter", "run"}, {"esc", "close"}}
	case screenHelp:
		hints = []keyHint{{"j/k", "scroll"}, {"pgup/dn", model.scrollPosition()}, {"?/esc", "close help"}}
	case screenOutput:
		hints = []keyHint{{"j/k", "scroll"}, {"pgup/dn", model.scrollPosition()}, {"enter/esc", "back"}}
	}
	return renderKeyHints(model.styles, hints, model.contentWidth())
}

func (model Model) scrollPosition() string {
	if model.viewport.TotalLineCount() <= model.viewport.Height {
		return "all"
	}
	return fmt.Sprintf("%d%%", int(model.viewport.ScrollPercent()*100+0.5))
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
	if model.screen != screenInput && model.screen != screenProxy && model.screen != screenIdentity && model.screen != screenKeys {
		return ""
	}
	total := 6
	step := model.wizard.step + 1
	if model.screen == screenProxy || model.wizard.step == 100 {
		step = 5
	}
	if model.screen == screenIdentity || model.screen == screenKeys {
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
