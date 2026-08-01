package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/doctor"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/logging"
	"github.com/vlyl/opssh/internal/onepassword"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/tunnel"
)

type Dependencies struct {
	Context  context.Context
	Input    io.Reader
	Output   io.Writer
	Service  *app.Service
	Provider *onepassword.Provider
	Doctor   doctor.Doctor
	Tunnels  tunnel.Manager
	Runner   *process.Runner
	NoColor  bool
}

type screen uint8

const (
	screenHosts screen = iota
	screenInput
	screenProxy
	screenKeys
	screenPreview
	screenConfirmDelete
	screenDoctor
	screenTunnels
	screenError
	screenCommand
)

type operationFactory func(context.Context, uint64) tea.Cmd

type hostItem struct{ host domain.Host }

func (item hostItem) Title() string { return item.host.Alias }
func (item hostItem) Description() string {
	return net.JoinHostPort(unbracket(item.host.Hostname), strconv.Itoa(int(item.host.Port))) + "  " + item.host.Key.Fingerprint
}
func (item hostItem) FilterValue() string {
	return item.host.Alias + " " + item.host.Hostname + " " + item.host.User
}

type keyItem struct{ key domain.PublicKeyMetadata }

func (item keyItem) Title() string       { return item.key.Title }
func (item keyItem) Description() string { return item.key.AccountName + " / " + item.key.VaultName }
func (item keyItem) FilterValue() string { return item.Title() + " " + item.Description() }

type proxyItem struct {
	typeValue domain.ProxyType
	label     string
}

func (item proxyItem) Title() string       { return item.label }
func (item proxyItem) Description() string { return string(item.typeValue) }
func (item proxyItem) FilterValue() string { return item.label }

type wizard struct {
	editing       bool
	originalAlias string
	alias         string
	hostname      string
	user          string
	port          uint16
	proxy         domain.Proxy
	reference     domain.KeyReference
	keyTitle      string
	step          int
}

type Model struct {
	deps        Dependencies
	screen      screen
	hosts       list.Model
	choices     list.Model
	input       textinput.Model
	command     textinput.Model
	spinner     spinner.Model
	table       table.Model
	width       int
	height      int
	loading     bool
	status      string
	err         error
	errorCauses []string
	diagnostics []string
	operation   string
	retry       operationFactory
	opCancel    context.CancelFunc
	opSequence  uint64
	activeOpID  uint64
	commandBack screen
	commandErr  string
	plan        app.Plan
	wizard      wizard
	deleteAlias string
	tunnelNames []string
	styles      styles
}

type styles struct {
	title  lipgloss.Style
	help   lipgloss.Style
	error  lipgloss.Style
	status lipgloss.Style
}

type hostsLoadedMsg struct {
	hosts []domain.Host
	err   error
	opID  uint64
}
type keysLoadedMsg struct {
	keys []domain.PublicKeyMetadata
	err  error
	opID uint64
}
type planReadyMsg struct {
	plan app.Plan
	err  error
	opID uint64
}
type appliedMsg struct {
	message string
	err     error
	opID    uint64
}
type doctorLoadedMsg struct {
	findings []domain.DoctorFinding
	opID     uint64
}
type tunnelsLoadedMsg struct {
	statuses []tunnel.Status
	err      error
	opID     uint64
}
type connectionFinishedMsg struct{ err error }
type testFinishedMsg struct {
	result app.ConnectionTestResult
	opID   uint64
}
type validationFinishedMsg struct {
	count int
	err   error
	opID  uint64
}

func Run(dependencies Dependencies) error {
	model := NewModel(dependencies)
	options := []tea.ProgramOption{tea.WithAltScreen()}
	if dependencies.Input != nil {
		options = append(options, tea.WithInput(dependencies.Input))
	}
	if dependencies.Output != nil {
		options = append(options, tea.WithOutput(dependencies.Output))
	}
	if dependencies.Context != nil {
		options = append(options, tea.WithContext(dependencies.Context))
	}
	_, err := tea.NewProgram(model, options...).Run()
	return err
}

func NewModel(dependencies Dependencies) Model {
	delegate := list.NewDefaultDelegate()
	hostList := list.New(nil, delegate, 80, 20)
	hostList.Title = "opssh hosts"
	hostList.AdditionalFullHelpKeys = nil
	choiceList := list.New(nil, delegate, 80, 16)
	input := textinput.New()
	input.CharLimit = 253
	commandInput := textinput.New()
	commandInput.Prompt = ": "
	commandInput.CharLimit = 128
	spin := spinner.New()
	spin.Spinner = spinner.Dot
	columns := []table.Column{{Title: "Level", Width: 7}, {Title: "Check", Width: 26}, {Title: "Result", Width: 60}}
	tableModel := table.New(table.WithColumns(columns), table.WithHeight(15), table.WithFocused(true))
	noColor := dependencies.NoColor || os.Getenv("NO_COLOR") != ""
	styleSet := styles{
		title: lipgloss.NewStyle().Bold(true), help: lipgloss.NewStyle().Faint(true),
		error: lipgloss.NewStyle().Bold(true), status: lipgloss.NewStyle(),
	}
	if !noColor {
		styleSet.title = styleSet.title.Foreground(lipgloss.Color("63"))
		styleSet.error = styleSet.error.Foreground(lipgloss.Color("196"))
		styleSet.status = styleSet.status.Foreground(lipgloss.Color("42"))
	}
	return Model{deps: dependencies, screen: screenHosts, hosts: hostList, choices: choiceList, input: input, command: commandInput, spinner: spin, table: tableModel, loading: true, operation: "load managed hosts", styles: styleSet}
}

func (model Model) Init() tea.Cmd {
	return tea.Batch(model.spinner.Tick, model.loadHosts(model.baseContext(), 0))
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if operationID, ok := operationMessageID(message); ok && operationID != model.activeOpID {
		return model, nil
	}
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = typed.Width, typed.Height
		model.hosts.SetSize(max(30, typed.Width-4), max(5, typed.Height-8))
		model.choices.SetSize(max(30, typed.Width-4), max(5, typed.Height-8))
		model.table.SetWidth(max(40, typed.Width-4))
		model.table.SetHeight(max(5, typed.Height-8))
	case spinner.TickMsg:
		var command tea.Cmd
		model.spinner, command = model.spinner.Update(typed)
		if model.loading {
			return model, command
		}
	case hostsLoadedMsg:
		if typed.err != nil {
			if model.retry == nil {
				model.operation = "load managed hosts"
				model.retry = func(ctx context.Context, operationID uint64) tea.Cmd { return model.loadHosts(ctx, operationID) }
			}
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		items := make([]list.Item, 0, len(typed.hosts))
		for _, host := range typed.hosts {
			items = append(items, hostItem{host: host})
		}
		model.hosts.SetItems(items)
		model.screen = screenHosts
	case keysLoadedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		items := make([]list.Item, 0, len(typed.keys))
		for _, key := range typed.keys {
			items = append(items, keyItem{key: key})
		}
		model.choices.Title = "Select a 1Password SSH public key"
		model.choices.SetItems(items)
		model.screen = screenKeys
	case planReadyMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.plan, model.screen = typed.plan, screenPreview
	case appliedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.status = typed.message
		return model.startOperation("refresh managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd {
			return model.loadHosts(ctx, operationID)
		})
	case doctorLoadedMsg:
		model = model.completeOperation()
		rows := make([]table.Row, 0, len(typed.findings))
		for _, finding := range typed.findings {
			rows = append(rows, table.Row{string(finding.Level), finding.Code, finding.Message})
		}
		model.table.SetRows(rows)
		model.screen = screenDoctor
	case tunnelsLoadedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		rows := make([]table.Row, 0, len(typed.statuses))
		model.tunnelNames = model.tunnelNames[:0]
		for _, status := range typed.statuses {
			state := "stopped"
			if status.Running {
				state = "running"
			}
			rows = append(rows, table.Row{state, status.Name, status.Local + " → " + status.Remote})
			model.tunnelNames = append(model.tunnelNames, status.Name)
		}
		model.table.SetRows(rows)
		model.screen = screenTunnels
	case connectionFinishedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model.status = "SSH session closed"
		return model.startOperation("refresh managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd {
			return model.loadHosts(ctx, operationID)
		})
	case testFinishedMsg:
		if !typed.result.Success {
			return model.showError(errors.New(typed.result.Message + "\n" + strings.Join(typed.result.Actions, "\n"))), nil
		}
		model = model.completeOperation()
		model.status = typed.result.Message
	case validationFinishedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.status = fmt.Sprintf("Validated %d managed host configurations", typed.count)
		model.screen = screenHosts
	}

	key, isKey := message.(tea.KeyMsg)
	if isKey && key.String() == "ctrl+c" {
		if model.opCancel != nil {
			model.opCancel()
		}
		return model, tea.Quit
	}
	if model.loading {
		if isKey && key.String() == "esc" {
			return model.cancelOperation(), nil
		}
		return model, nil
	}
	if isKey && key.String() == ":" && model.screen != screenInput && model.screen != screenCommand && !model.hosts.SettingFilter() {
		return model.openCommandPalette(), nil
	}
	switch model.screen {
	case screenHosts:
		return model.updateHosts(message)
	case screenInput:
		return model.updateInput(message)
	case screenProxy, screenKeys:
		return model.updateChoices(message)
	case screenPreview:
		return model.updatePreview(message)
	case screenConfirmDelete:
		return model.updateDelete(message)
	case screenDoctor, screenTunnels:
		return model.updateTable(message)
	case screenError:
		if isKey {
			switch key.String() {
			case "esc":
				return model.cancelOperation(), nil
			case "r":
				if model.retry != nil {
					return model.startOperation(model.operation, model.retry)
				}
			case "enter":
				return model.openCommandPalette(), nil
			case "q":
				return model, tea.Quit
			}
		}
	case screenCommand:
		return model.updateCommand(message)
	}
	return model, nil
}

func (model Model) updateHosts(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok && !model.hosts.SettingFilter() {
		selected := model.selectedHost()
		switch key.String() {
		case "q":
			return model, tea.Quit
		case "a":
			return model.beginAdd(), nil
		case "e":
			if selected != nil {
				return model.beginEdit(*selected), nil
			}
		case "d":
			if selected != nil {
				model.deleteAlias, model.screen = selected.Alias, screenConfirmDelete
			}
		case "s":
			if selected != nil {
				alias := selected.Alias
				return model.startOperation("synchronize public key for "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.prepareSync(ctx, operationID, alias)
				})
			}
		case "x":
			if selected != nil {
				alias := selected.Alias
				return model.startOperation("test SSH connection to "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.testHost(ctx, operationID, alias)
				})
			}
		case "D":
			return model.startOperation("run diagnostics", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.loadDoctor(ctx, operationID)
			})
		case "t":
			return model.startOperation("load tunnel status", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.loadTunnels(ctx, operationID)
			})
		case "enter":
			if selected != nil && model.deps.Runner != nil {
				interactive := model.deps.Runner.InteractiveCommand(model.context(), process.Request{Tool: process.ToolOpenSSH, Args: []string{selected.Alias}})
				return model, tea.Exec(interactive, func(err error) tea.Msg { return connectionFinishedMsg{err: err} })
			}
		}
	}
	var command tea.Cmd
	model.hosts, command = model.hosts.Update(message)
	return model, command
}

func (model Model) beginAdd() Model {
	model.wizard = wizard{port: 22, proxy: domain.Proxy{Type: domain.ProxyNone}}
	model.screen = screenInput
	model.configureInput("Host alias", "")
	return model
}

func (model Model) beginEdit(host domain.Host) Model {
	model.wizard = wizard{editing: true, originalAlias: host.Alias, alias: host.Alias, hostname: host.Hostname, user: host.User, port: host.Port, proxy: host.Proxy, reference: host.Key.Reference, keyTitle: host.Key.Title}
	model.screen = screenInput
	model.configureInput("Host alias", host.Alias)
	return model
}

func (model *Model) configureInput(prompt, value string) {
	model.input.Prompt = prompt + ": "
	model.input.SetValue(value)
	model.input.CursorEnd()
	model.input.Focus()
}

func (model Model) updateInput(message tea.Msg) (tea.Model, tea.Cmd) {
	if model.wizard.step == 100 {
		return model.updateProxyEndpoint(message)
	}
	if key, ok := message.(tea.KeyMsg); ok {
		if key.String() == "esc" {
			model.screen = screenHosts
			return model, nil
		}
		if key.String() == "enter" {
			value := strings.TrimSpace(model.input.Value())
			if value == "" {
				return model.showError(errors.New("this field is required")), nil
			}
			if model.wizard.editing {
				switch model.wizard.step {
				case 0:
					model.wizard.alias = value
					model.wizard.step++
					model.configureInput("Hostname or IP", model.wizard.hostname)
				case 1:
					model.wizard.hostname = value
					model.wizard.step++
					model.configureInput("SSH user", model.wizard.user)
				case 2:
					model.wizard.user = value
					model.wizard.step++
					model.configureInput("SSH port", strconv.Itoa(int(model.wizard.port)))
				case 3:
					port, err := strconv.ParseUint(value, 10, 16)
					if err != nil || port == 0 {
						return model.showError(errors.New("invalid SSH port")), nil
					}
					model.wizard.port = uint16(port)
					return model.beginProxyPicker(), nil
				}
			} else {
				switch model.wizard.step {
				case 0:
					model.wizard.alias = value
					model.wizard.step++
					model.configureInput("Hostname or IP", "")
				case 1:
					model.wizard.hostname = value
					model.wizard.step++
					model.configureInput("SSH user", "")
				case 2:
					model.wizard.user = value
					model.wizard.step++
					model.configureInput("SSH port", "22")
				case 3:
					port, err := strconv.ParseUint(value, 10, 16)
					if err != nil || port == 0 {
						return model.showError(errors.New("invalid SSH port")), nil
					}
					model.wizard.port = uint16(port)
					return model.beginProxyPicker(), nil
				}
			}
			return model, nil
		}
	}
	var command tea.Cmd
	model.input, command = model.input.Update(message)
	return model, command
}

func (model Model) beginProxyPicker() Model {
	items := []list.Item{
		proxyItem{domain.ProxyNone, "No proxy"}, proxyItem{domain.ProxySOCKS5, "SOCKS5 proxy"},
		proxyItem{domain.ProxyHTTPConnect, "HTTP CONNECT proxy"}, proxyItem{domain.ProxyJump, "ProxyJump host"},
	}
	model.choices.Title = "Select proxy type"
	model.choices.SetItems(items)
	model.screen = screenProxy
	return model
}

func (model Model) updateChoices(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		if key.String() == "esc" {
			model.screen = screenHosts
			return model, nil
		}
		if key.String() == "enter" {
			switch selected := model.choices.SelectedItem().(type) {
			case proxyItem:
				model.wizard.proxy = domain.Proxy{Type: selected.typeValue}
				if selected.typeValue == domain.ProxyNone {
					return model.afterProxy()
				}
				model.screen = screenInput
				model.wizard.step = 100
				prompt := "Proxy host:port"
				if selected.typeValue == domain.ProxyJump {
					prompt = "ProxyJump alias"
				}
				model.configureInput(prompt, "")
				return model, nil
			case keyItem:
				model.wizard.reference, model.wizard.keyTitle = selected.key.Reference, selected.key.Title
				return model.startOperation("prepare host configuration preview", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.prepareWizardPlan(ctx, operationID)
				})
			}
		}
	}
	var command tea.Cmd
	model.choices, command = model.choices.Update(message)
	return model, command
}

func (model Model) updateProxyEndpoint(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok && key.String() == "enter" {
		value := strings.TrimSpace(model.input.Value())
		if model.wizard.proxy.Type == domain.ProxyJump {
			model.wizard.proxy.JumpHost = value
		} else {
			host, portText, err := net.SplitHostPort(value)
			if err != nil {
				return model.showError(errors.New("proxy endpoint must be host:port")), nil
			}
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port == 0 {
				return model.showError(errors.New("invalid proxy port")), nil
			}
			model.wizard.proxy.Host, model.wizard.proxy.Port = host, uint16(port)
		}
		return model.afterProxy()
	}
	var command tea.Cmd
	model.input, command = model.input.Update(message)
	return model, command
}

func (model Model) afterProxy() (tea.Model, tea.Cmd) {
	if model.wizard.editing {
		return model.startOperation("prepare host configuration preview", func(ctx context.Context, operationID uint64) tea.Cmd {
			return model.prepareWizardPlan(ctx, operationID)
		})
	}
	return model.startOperation("load 1Password SSH Key metadata", func(ctx context.Context, operationID uint64) tea.Cmd {
		return model.loadKeys(ctx, operationID)
	})
}

func (model Model) updatePreview(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "y", "enter":
			return model.startOperation("apply "+model.plan.Operation+" configuration", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.applyPlan(ctx, operationID)
			})
		case "n", "esc":
			model.screen = screenHosts
		}
	}
	return model, nil
}

func (model Model) updateDelete(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "y":
			alias := model.deleteAlias
			return model.startOperation("remove host "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.prepareDelete(ctx, operationID, alias)
			})
		case "n", "esc":
			model.screen = screenHosts
		}
	}
	return model, nil
}

func (model Model) updateTable(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		if key.String() == "esc" || key.String() == "q" {
			model.screen = screenHosts
			return model, nil
		}
		if model.screen == screenTunnels && len(model.tunnelNames) > 0 {
			index := model.table.Cursor()
			if index >= 0 && index < len(model.tunnelNames) {
				name := model.tunnelNames[index]
				switch key.String() {
				case "s":
					return model.startOperation("start tunnel "+name, func(ctx context.Context, operationID uint64) tea.Cmd {
						return model.startTunnel(ctx, operationID, name)
					})
				case "k":
					return model.startOperation("stop tunnel "+name, func(ctx context.Context, operationID uint64) tea.Cmd {
						return model.stopTunnel(ctx, operationID, name)
					})
				}
			}
		}
	}
	var command tea.Cmd
	model.table, command = model.table.Update(message)
	return model, command
}

func (model Model) View() string {
	if model.loading {
		return "\n  " + model.spinner.View() + " " + titleWord(model.operation) + "…\n\n  " + model.styles.help.Render("Esc cancel current operation")
	}
	if model.screen == screenHosts && model.width > 0 && (model.width < 60 || model.height < 12) {
		return model.compactView()
	}
	switch model.screen {
	case screenHosts:
		return model.hosts.View() + "\n" + model.styles.help.Render("Enter Connect   a Add   e Edit   t Tunnel   s Sync   d Delete   x Test   D Doctor   / Search   : Command   q Quit") + statusLine(model)
	case screenInput:
		return model.styles.title.Render("Host wizard") + "\n\n" + model.input.View() + "\n\n" + model.styles.help.Render("Enter continue • Esc cancel")
	case screenProxy, screenKeys:
		return model.choices.View()
	case screenPreview:
		return model.styles.title.Render("Configuration preview") + "\n\n" + model.plan.ConfigPreview + "\n" + renderChanges(model.plan) + renderNotices(model.plan) + "\nApply? y/Enter Yes • n/Esc No"
	case screenConfirmDelete:
		return model.styles.error.Render("Delete "+model.deleteAlias+" from opssh?") + "\nOnly its managed config and .pub file will be removed.\ny Yes • n/Esc No"
	case screenDoctor:
		return model.styles.title.Render("Doctor") + "\n" + model.table.View() + "\n" + model.styles.help.Render("Esc back")
	case screenTunnels:
		return model.styles.title.Render("Tunnels") + "\n" + model.table.View() + "\n" + model.styles.help.Render("s Start • k Stop • Esc back")
	case screenError:
		return model.renderErrorView()
	case screenCommand:
		message := ""
		if model.commandErr != "" {
			message = "\n\n" + model.styles.error.Render(model.commandErr)
		}
		return model.styles.title.Render("Command") + "\n\n" + model.command.View() + message + "\n\n" + model.styles.help.Render("Built-ins: doctor • config validate • list • tunnel list • retry • cancel • quit\nEnter run • Esc close command input")
	default:
		return "opssh"
	}
}

func (model Model) compactView() string {
	if model.screen == screenHosts {
		selected := model.selectedHost()
		if selected == nil {
			return "opssh — no hosts\nq quit • a add"
		}
		return fmt.Sprintf("opssh — %s\n%s@%s:%d\nEnter connect • / search • q quit", selected.Alias, selected.User, selected.Hostname, selected.Port)
	}
	return "opssh\nTerminal is small; resize or press Esc."
}

func (model Model) renderErrorView() string {
	var builder strings.Builder
	_, _ = fmt.Fprintln(&builder, model.styles.error.Render("Error details"))
	operation := model.operation
	if operation == "" {
		operation = "unspecified operation"
	}
	_, _ = fmt.Fprintf(&builder, "\nOperation:\n  %s\n\nSummary:\n  %s\n", operation, model.err.Error())
	if len(model.errorCauses) > 0 {
		_, _ = fmt.Fprintln(&builder, "\nCause chain:")
		for index, cause := range model.errorCauses {
			_, _ = fmt.Fprintf(&builder, "  %d. %s\n", index+1, cause)
		}
	}
	if len(model.diagnostics) > 0 {
		_, _ = fmt.Fprintln(&builder, "\nDiagnostic commands:")
		for _, command := range model.diagnostics {
			_, _ = fmt.Fprintf(&builder, "  %s\n", command)
		}
	}
	_, _ = fmt.Fprint(&builder, "\nr Retry   :/Enter Command   Esc cancel current operation   q Quit")
	return builder.String()
}

func safeErrorChain(err error) (string, []string) {
	if err == nil {
		return "unknown error", nil
	}
	summary := logging.Redact(err.Error())
	seen := map[string]struct{}{summary: {}}
	var causes []string
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if multiple, ok := current.(interface{ Unwrap() []error }); ok {
			for _, nested := range multiple.Unwrap() {
				visit(nested)
			}
			return
		}
		nested := errors.Unwrap(current)
		if nested == nil {
			return
		}
		detail := logging.Redact(nested.Error())
		if _, exists := seen[detail]; !exists {
			seen[detail] = struct{}{}
			causes = append(causes, detail)
		}
		visit(nested)
	}
	visit(err)
	return summary, causes
}

func diagnosticCommands(summary string) []string {
	commands := []string{"opssh doctor"}
	lower := strings.ToLower(summary)
	if strings.Contains(lower, "1password") || strings.Contains(lower, "ssh key metadata") {
		return []string{"op --version", `op item list --categories "SSH Key" --format=json`, "opssh doctor"}
	}
	if strings.Contains(lower, "config") || strings.Contains(lower, "ssh") {
		commands = append(commands, "opssh config validate")
	}
	return commands
}

func (model Model) openCommandPalette() Model {
	model.commandBack = model.screen
	model.screen = screenCommand
	model.commandErr = ""
	model.command.SetValue("")
	model.command.Focus()
	return model
}

func (model Model) updateCommand(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			model.command.Blur()
			model.screen = model.commandBack
			model.commandErr = ""
			return model, nil
		case "enter":
			value := strings.TrimSpace(model.command.Value())
			value = strings.TrimSpace(strings.TrimPrefix(value, "opssh "))
			model.commandErr = ""
			switch value {
			case "doctor":
				return model.startOperation("run diagnostics", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.loadDoctor(ctx, operationID)
				})
			case "config validate", "validate":
				return model.startOperation("validate managed SSH configurations", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.validateConfigurations(ctx, operationID)
				})
			case "list", "hosts":
				return model.startOperation("load managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.loadHosts(ctx, operationID)
				})
			case "tunnel list", "tunnels":
				return model.startOperation("load tunnel status", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.loadTunnels(ctx, operationID)
				})
			case "retry", "r":
				if model.retry == nil {
					model.commandErr = "No failed operation is available to retry"
					return model, nil
				}
				return model.startOperation(model.operation, model.retry)
			case "cancel":
				return model.cancelOperation(), nil
			case "back":
				model.screen = model.commandBack
				return model, nil
			case "quit", "q":
				return model, tea.Quit
			case "", "help":
				model.commandErr = "Enter one of the listed built-in commands"
				return model, nil
			default:
				model.commandErr = "Unknown built-in command; arbitrary shell commands are intentionally disabled"
				return model, nil
			}
		}
	}
	var command tea.Cmd
	model.command, command = model.command.Update(message)
	return model, command
}

func (model Model) startOperation(name string, factory operationFactory) (tea.Model, tea.Cmd) {
	if model.opCancel != nil {
		model.opCancel()
	}
	model.opSequence++
	model.activeOpID = model.opSequence
	ctx, cancel := context.WithCancel(model.baseContext())
	model.opCancel = cancel
	model.operation = name
	model.retry = factory
	model.loading = true
	model.err = nil
	model.errorCauses = nil
	model.diagnostics = nil
	return model, factory(ctx, model.activeOpID)
}

func (model Model) completeOperation() Model {
	if model.opCancel != nil {
		model.opCancel()
	}
	model.opCancel = nil
	model.loading = false
	model.operation = ""
	model.retry = nil
	return model
}

func (model Model) cancelOperation() Model {
	if model.opCancel != nil {
		model.opCancel()
	}
	model.opSequence++
	model.activeOpID = model.opSequence
	model.opCancel = nil
	model.loading = false
	model.operation = ""
	model.retry = nil
	model.err = nil
	model.errorCauses = nil
	model.diagnostics = nil
	model.commandErr = ""
	model.wizard = wizard{}
	model.plan = app.Plan{}
	model.screen = screenHosts
	model.status = "Current operation canceled"
	return model
}

func operationMessageID(message tea.Msg) (uint64, bool) {
	switch typed := message.(type) {
	case hostsLoadedMsg:
		return typed.opID, true
	case keysLoadedMsg:
		return typed.opID, true
	case planReadyMsg:
		return typed.opID, true
	case appliedMsg:
		return typed.opID, true
	case doctorLoadedMsg:
		return typed.opID, true
	case tunnelsLoadedMsg:
		return typed.opID, true
	case testFinishedMsg:
		return typed.opID, true
	case validationFinishedMsg:
		return typed.opID, true
	default:
		return 0, false
	}
}

func (model Model) selectedHost() *domain.Host {
	item, ok := model.hosts.SelectedItem().(hostItem)
	if !ok {
		return nil
	}
	host := item.host
	return &host
}

func (model Model) showError(err error) Model {
	if model.opCancel != nil {
		model.opCancel()
		model.opCancel = nil
	}
	summary, causes := safeErrorChain(err)
	model.screen, model.loading, model.err = screenError, false, errors.New(summary)
	model.errorCauses = causes
	model.diagnostics = diagnosticCommands(summary)
	return model
}

func (model Model) context() context.Context {
	return model.baseContext()
}

func (model Model) baseContext() context.Context {
	if model.deps.Context != nil {
		return model.deps.Context
	}
	return context.Background()
}

func (model Model) loadHosts(_ context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		hosts, err := model.deps.Service.List()
		return hostsLoadedMsg{hosts: hosts, err: err, opID: operationID}
	}
}
func (model Model) loadKeys(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		keys, err := model.deps.Provider.ListPublicKeys(ctx)
		return keysLoadedMsg{keys: keys, err: err, opID: operationID}
	}
}
func (model Model) prepareSync(ctx context.Context, operationID uint64, alias string) tea.Cmd {
	return func() tea.Msg {
		plan, err := model.deps.Service.PrepareSync(ctx, alias)
		return planReadyMsg{plan: plan, err: err, opID: operationID}
	}
}
func (model Model) prepareDelete(ctx context.Context, operationID uint64, alias string) tea.Cmd {
	return func() tea.Msg {
		plan, err := model.deps.Service.PrepareRemove(alias)
		if err != nil {
			return appliedMsg{err: err, opID: operationID}
		}
		err = model.deps.Service.Apply(ctx, plan)
		return appliedMsg{message: "Removed " + alias, err: err, opID: operationID}
	}
}
func (model Model) applyPlan(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		err := model.deps.Service.Apply(ctx, model.plan)
		return appliedMsg{message: titleWord(model.plan.Operation) + " completed for " + model.plan.Alias, err: err, opID: operationID}
	}
}
func (model Model) testHost(ctx context.Context, operationID uint64, alias string) tea.Cmd {
	return func() tea.Msg {
		return testFinishedMsg{result: model.deps.Service.TestConnection(ctx, alias, false), opID: operationID}
	}
}
func (model Model) loadDoctor(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg { return doctorLoadedMsg{findings: model.deps.Doctor.Run(ctx), opID: operationID} }
}

func (model Model) prepareWizardPlan(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		if model.wizard.editing {
			hostname, user, port, proxy := model.wizard.hostname, model.wizard.user, model.wizard.port, model.wizard.proxy
			newAlias := model.wizard.alias
			plan, err := model.deps.Service.PrepareEdit(ctx, model.wizard.originalAlias, app.EditInput{NewAlias: &newAlias, Hostname: &hostname, User: &user, Port: &port, Proxy: &proxy})
			return planReadyMsg{plan: plan, err: err, opID: operationID}
		}
		plan, err := model.deps.Service.PrepareAdd(ctx, app.AddInput{
			Alias: model.wizard.alias, Hostname: model.wizard.hostname, User: model.wizard.user, Port: model.wizard.port,
			Reference: model.wizard.reference, KeyTitle: model.wizard.keyTitle, Proxy: model.wizard.proxy,
		})
		return planReadyMsg{plan: plan, err: err, opID: operationID}
	}
}

func (model Model) loadTunnels(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		configured, err := model.deps.Tunnels.List()
		if err != nil {
			return tunnelsLoadedMsg{err: err, opID: operationID}
		}
		statuses := make([]tunnel.Status, 0, len(configured))
		for _, item := range configured {
			status, statusErr := model.deps.Tunnels.Status(ctx, item.Name)
			if statusErr != nil {
				return tunnelsLoadedMsg{err: statusErr, opID: operationID}
			}
			statuses = append(statuses, status)
		}
		return tunnelsLoadedMsg{statuses: statuses, opID: operationID}
	}
}

func (model Model) startTunnel(ctx context.Context, operationID uint64, name string) tea.Cmd {
	return func() tea.Msg {
		configured, err := model.deps.Tunnels.List()
		if err != nil {
			return appliedMsg{err: err, opID: operationID}
		}
		for _, item := range configured {
			if item.Name == name {
				ip := net.ParseIP(unbracket(item.LocalHost))
				if ip == nil || !ip.IsLoopback() {
					return appliedMsg{err: errors.New("use the CLI to explicitly confirm a non-loopback tunnel"), opID: operationID}
				}
			}
		}
		_, err = model.deps.Tunnels.Start(ctx, name, tunnel.StartOptions{})
		if err != nil {
			return appliedMsg{err: err, opID: operationID}
		}
		return appliedMsg{message: "Started tunnel " + name, opID: operationID}
	}
}

func (model Model) stopTunnel(ctx context.Context, operationID uint64, name string) tea.Cmd {
	return func() tea.Msg {
		err := model.deps.Tunnels.Stop(ctx, name)
		return appliedMsg{message: "Stopped tunnel " + name, err: err, opID: operationID}
	}
}

func (model Model) validateConfigurations(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		hosts, err := model.deps.Service.List()
		if err != nil {
			return validationFinishedMsg{err: err, opID: operationID}
		}
		for _, host := range hosts {
			if err := model.deps.Service.ValidateEffectiveConfig(ctx, host.Alias); err != nil {
				return validationFinishedMsg{err: fmt.Errorf("host %s: %w", host.Alias, err), opID: operationID}
			}
		}
		return validationFinishedMsg{count: len(hosts), opID: operationID}
	}
}

func renderChanges(plan app.Plan) string {
	var builder strings.Builder
	for _, change := range plan.Changes {
		_, _ = fmt.Fprintf(&builder, "%s %s\n", change.Action, change.Path)
	}
	return builder.String()
}

func renderNotices(plan app.Plan) string {
	if len(plan.Notices) == 0 {
		return ""
	}
	var builder strings.Builder
	_, _ = fmt.Fprintln(&builder, "\nNotes:")
	for _, notice := range plan.Notices {
		_, _ = fmt.Fprintf(&builder, "  - %s\n", notice)
	}
	return builder.String()
}

func statusLine(model Model) string {
	if model.status == "" {
		return ""
	}
	return "\n" + model.styles.status.Render(model.status)
}
func unbracket(value string) string { return strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[") }
func titleWord(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
