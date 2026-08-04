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
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/doctor"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/logging"
	"github.com/vlyl/opssh/internal/onepassword"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
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
	screenIdentity
	screenKeys
	screenPreview
	screenConfirmDelete
	screenDoctor
	screenTunnels
	screenError
	screenCommand
	screenHelp
	screenOutput
)

type operationFactory func(context.Context, uint64) tea.Cmd

type hostItem struct{ host domain.Host }

func (item hostItem) Title() string { return item.host.Alias }
func (item hostItem) Description() string {
	target := item.host.User + "@" + net.JoinHostPort(unbracket(item.host.Hostname), strconv.Itoa(int(item.host.Port)))
	return target + "  •  " + proxyDescription(item.host.Proxy)
}
func (item hostItem) FilterValue() string {
	return item.host.Alias + " " + item.host.Hostname + " " + item.host.User
}

type keyItem struct{ key domain.PublicKeyMetadata }

func (item keyItem) Title() string { return item.key.Title }
func (item keyItem) Description() string {
	location := strings.Trim(strings.TrimSpace(item.key.AccountName)+" / "+strings.TrimSpace(item.key.VaultName), " /")
	if item.key.Fingerprint == "" {
		return location
	}
	if location == "" {
		return item.key.Fingerprint
	}
	return location + "  •  " + item.key.Fingerprint
}
func (item keyItem) FilterValue() string { return item.Title() + " " + item.Description() }

type proxyItem struct {
	typeValue domain.ProxyType
	label     string
}

func (item proxyItem) Title() string       { return item.label }
func (item proxyItem) Description() string { return string(item.typeValue) }
func (item proxyItem) FilterValue() string { return item.label }

type identityItem struct {
	change bool
	label  string
	detail string
}

func (item identityItem) Title() string       { return item.label }
func (item identityItem) Description() string { return item.detail }
func (item identityItem) FilterValue() string { return item.label + " " + item.detail }

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
	changeKey     bool
	step          int
}

type Model struct {
	deps         Dependencies
	screen       screen
	hosts        list.Model
	choices      list.Model
	input        textinput.Model
	command      textinput.Model
	spinner      spinner.Model
	table        table.Model
	viewport     viewport.Model
	width        int
	height       int
	loading      bool
	status       string
	err          error
	errorCauses  []string
	diagnostics  []string
	errorActions []string
	operation    string
	retry        operationFactory
	opCancel     context.CancelFunc
	opContext    context.Context
	opSequence   uint64
	activeOpID   uint64
	commandBack  screen
	commandErr   string
	formErr      string
	helpBack     screen
	outputBack   screen
	outputTitle  string
	outputText   string
	focusAlias   string
	commandIndex int
	errorCommand int
	plan         app.Plan
	wizard       wizard
	deleteAlias  string
	tunnelNames  []string
	styles       styles
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
	message       string
	alias         string
	action        string
	reloadTunnels bool
	err           error
	opID          uint64
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
type connectionFinishedMsg struct {
	alias string
	err   error
	opID  uint64
}
type connectionDiagnosedMsg struct {
	alias       string
	originalErr error
	result      app.ConnectionTestResult
	opID        uint64
}
type testFinishedMsg struct {
	result app.ConnectionTestResult
	alias  string
	opID   uint64
}
type validationFinishedMsg struct {
	count int
	err   error
	opID  uint64
}
type renderedConfigMsg struct {
	alias string
	data  []byte
	err   error
	opID  uint64
}

func Run(dependencies Dependencies) error {
	model := NewModel(dependencies)
	options := []tea.ProgramOption{tea.WithAltScreen(), tea.WithMouseCellMotion()}
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
	noColor := dependencies.NoColor || os.Getenv("NO_COLOR") != ""
	styleSet := newStyles(noColor)
	delegate := newListDelegate(styleSet)
	hostList := list.New(nil, delegate, 80, 20)
	configureList(&hostList, "host", "hosts", styleSet)
	hostList.SetShowPagination(false)
	hostList.AdditionalFullHelpKeys = nil
	choiceList := list.New(nil, delegate, 80, 16)
	configureList(&choiceList, "choice", "choices", styleSet)
	input := textinput.New()
	input.CharLimit = 253
	input.PromptStyle = styleSet.fieldLabel
	input.TextStyle = styleSet.fieldValue
	input.Cursor.Style = styleSet.cursor
	input.KeyMap.Paste.SetEnabled(false)
	commandInput := textinput.New()
	commandInput.Prompt = "opssh  "
	commandInput.CharLimit = 128
	commandInput.PromptStyle = styleSet.fieldLabel
	commandInput.TextStyle = styleSet.fieldValue
	commandInput.Cursor.Style = styleSet.cursor
	commandInput.KeyMap.Paste.SetEnabled(false)
	spin := spinner.New()
	spin.Spinner = spinner.Dot
	spin.Style = styleSet.accent
	columns := []table.Column{{Title: "Level", Width: 7}, {Title: "Check", Width: 26}, {Title: "Result", Width: 60}}
	tableModel := table.New(table.WithColumns(columns), table.WithHeight(15), table.WithFocused(true))
	tableModel.SetStyles(newTableStyles(styleSet))
	contentViewport := viewport.New(80, 12)
	contentViewport.MouseWheelEnabled = true
	contentViewport.MouseWheelDelta = 3
	return Model{deps: dependencies, screen: screenHosts, hosts: hostList, choices: choiceList, input: input, command: commandInput, spinner: spin, table: tableModel, viewport: contentViewport, loading: true, operation: "load managed hosts", styles: styleSet}
}

func (model Model) Init() tea.Cmd {
	return tea.Batch(model.spinner.Tick, model.loadHosts(model.baseContext(), 0))
}

func (model Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if operationID, ok := operationMessageID(message); ok && operationID != model.activeOpID {
		if rendered, ok := message.(renderedConfigMsg); ok {
			security.Wipe(rendered.data)
		}
		return model, nil
	}
	switch typed := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = typed.Width, typed.Height
		model.resizeComponents()
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
		if model.focusAlias != "" {
			model.hosts.ResetFilter()
		}
		model.hosts.SetItems(items)
		if model.focusAlias != "" {
			model.selectHostAlias(model.focusAlias)
			model.focusAlias = ""
		}
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
		model.choices.ResetFilter()
		model.choices.SetItems(items)
		model.screen = screenKeys
		if model.wizard.editing {
			model.selectCurrentKey()
		}
		model.configureKeyPicker()
	case planReadyMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.plan, model.screen = typed.plan, screenPreview
		model.configureViewport(true)
	case appliedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.status = typed.message
		if typed.alias != "" && typed.action != "remove" {
			model.focusAlias = typed.alias
		}
		if typed.reloadTunnels {
			return model.startOperation("refresh tunnel status", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.loadTunnels(ctx, operationID)
			})
		}
		return model.startOperation("refresh managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd {
			return model.loadHosts(ctx, operationID)
		})
	case doctorLoadedMsg:
		model = model.completeOperation()
		model.configureTable("Level", "Check", "Result")
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
		model.configureTable("State", "Tunnel", "Route")
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
		if typed.err != nil && !isRemoteSessionExit(typed.err) {
			if model.deps.Service == nil {
				return model.showConnectionError(typed.alias, typed.err, app.ConnectionTestResult{}), nil
			}
			ctx := model.opContext
			if ctx == nil {
				ctx = model.baseContext()
			}
			return model, model.diagnoseConnection(ctx, typed.opID, typed.alias, typed.err)
		}
		model = model.completeOperation()
		model.screen = screenHosts
		model.status = "SSH session closed for " + typed.alias
		if typed.err != nil {
			var runErr *process.RunError
			if errors.As(typed.err, &runErr) {
				model.status += fmt.Sprintf(" (remote exit status %d)", runErr.ExitCode)
			}
		}
		return model, nil
	case connectionDiagnosedMsg:
		return model.showConnectionError(typed.alias, typed.originalErr, typed.result), nil
	case testFinishedMsg:
		if !typed.result.Success {
			model = model.showError(errors.New(typed.result.Message))
			model.errorActions, model.diagnostics = connectionGuidance(typed.alias, typed.result.Actions)
			model.resetErrorCommand()
			model.configureViewport(true)
			return model, nil
		}
		model = model.completeOperation()
		model.status = typed.result.Message
		model.screen = screenHosts
		model.selectHostAlias(typed.alias)
	case validationFinishedMsg:
		if typed.err != nil {
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.status = fmt.Sprintf("Validated %d managed host configurations", typed.count)
		model.screen = screenHosts
	case renderedConfigMsg:
		if typed.err != nil {
			security.Wipe(typed.data)
			return model.showError(typed.err), nil
		}
		model = model.completeOperation()
		model.outputTitle = "Rendered config · " + typed.alias
		model.outputText = string(typed.data)
		security.Wipe(typed.data)
		model.screen = screenOutput
		model.configureViewport(true)
	}

	key, isKey := message.(tea.KeyMsg)
	if isKey && key.Paste && containsSensitiveRunes(key.Runes) {
		wipeRunes(key.Runes)
		switch model.screen {
		case screenInput:
			model.formErr = "Pasted content was rejected by the private-key safety policy."
		case screenCommand:
			model.commandErr = "Pasted content was rejected by the private-key safety policy."
		}
		return model, nil
	}
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
	if mouse, ok := message.(tea.MouseMsg); ok {
		return model.updateMouse(mouse)
	}
	if isKey && key.String() == ":" && model.screen != screenInput && model.screen != screenCommand && !model.activeListFiltering() {
		return model.openCommandPalette(), nil
	}
	if isKey && key.String() == "?" && model.screen != screenInput && model.screen != screenCommand && !model.activeListFiltering() {
		if model.screen == screenHelp {
			model.screen = model.helpBack
			return model, nil
		}
		return model.openHelp(), nil
	}
	switch model.screen {
	case screenHosts:
		return model.updateHosts(message)
	case screenInput:
		return model.updateInput(message)
	case screenProxy, screenIdentity, screenKeys:
		return model.updateChoices(message)
	case screenPreview:
		return model.updatePreview(message)
	case screenConfirmDelete:
		return model.updateDelete(message)
	case screenDoctor, screenTunnels:
		return model.updateTable(message)
	case screenError:
		return model.updateError(message)
	case screenCommand:
		return model.updateCommand(message)
	case screenHelp:
		return model.updateScrollable(message, model.helpBack)
	case screenOutput:
		return model.updateScrollable(message, model.outputBack)
	}
	return model, nil
}

func containsSensitiveRunes(value []rune) bool {
	data := make([]byte, 0, len(value))
	var encoded [utf8.UTFMax]byte
	for _, character := range value {
		count := utf8.EncodeRune(encoded[:], character)
		data = append(data, encoded[:count]...)
	}
	security.Wipe(encoded[:])
	defer security.Wipe(data)
	return security.ContainsSensitiveMarker(data)
}

func wipeRunes(value []rune) {
	for index := range value {
		value[index] = 0
	}
}

func (model Model) updateHosts(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok && !model.hosts.SettingFilter() {
		selected := model.selectedHost()
		switch key.String() {
		case "q":
			return model, tea.Quit
		case "r":
			return model.startOperation("refresh managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.loadHosts(ctx, operationID)
			})
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
			if selected != nil && model.deps.Service != nil {
				return model.startConnection(selected.Alias)
			}
		}
	}
	var command tea.Cmd
	model.hosts, command = model.hosts.Update(message)
	return model, command
}

func (model Model) beginAdd() Model {
	model.wizard = wizard{port: 22, proxy: domain.Proxy{Type: domain.ProxyNone}}
	model.formErr = ""
	model.status = ""
	model.screen = screenInput
	model.configureInput("Host alias", "")
	return model
}

func (model Model) beginEdit(host domain.Host) Model {
	model.wizard = wizard{editing: true, originalAlias: host.Alias, alias: host.Alias, hostname: host.Hostname, user: host.User, port: host.Port, proxy: host.Proxy, reference: host.Key.Reference, keyTitle: host.Key.Title}
	model.formErr = ""
	model.status = ""
	model.screen = screenInput
	model.configureInput("Host alias", host.Alias)
	return model
}

func (model *Model) configureInput(prompt, value string) {
	model.input.Prompt = prompt + ": "
	model.input.SetValue(value)
	model.input.CursorEnd()
	model.input.Focus()
	model.formErr = ""
}

func (model Model) previousWizardField() Model {
	switch model.wizard.step {
	case 0:
		model.screen = screenHosts
	case 1:
		model.wizard.step = 0
		model.configureInput("Host alias", model.wizard.alias)
	case 2:
		model.wizard.step = 1
		model.configureInput("Hostname or IP", model.wizard.hostname)
	case 3:
		model.wizard.step = 2
		model.configureInput("SSH user", model.wizard.user)
	default:
		model.screen = screenHosts
	}
	return model
}

func (model Model) updateInput(message tea.Msg) (tea.Model, tea.Cmd) {
	if model.wizard.step == 100 {
		return model.updateProxyEndpoint(message)
	}
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			model.screen = screenHosts
			model.formErr = ""
			return model, nil
		case "shift+tab":
			return model.previousWizardField(), nil
		case "enter":
			value := strings.TrimSpace(model.input.Value())
			if value == "" {
				model.formErr = "This field is required"
				return model, nil
			}
			if validationMessage := wizardValidationMessage(model.wizard.step, value); validationMessage != "" {
				model.formErr = validationMessage
				return model, nil
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
						model.formErr = "Enter an SSH port from 1 to 65535"
						return model, nil
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
						model.formErr = "Enter an SSH port from 1 to 65535"
						return model, nil
					}
					model.wizard.port = uint16(port)
					return model.beginProxyPicker(), nil
				}
			}
			return model, nil
		default:
			model.formErr = ""
		}
	}
	var command tea.Cmd
	model.input, command = model.input.Update(message)
	return model, command
}

func wizardValidationMessage(step int, value string) string {
	switch step {
	case 0:
		if security.ValidateAlias(value) != nil {
			return "Use 1–64 letters, numbers, dots, underscores, or hyphens; start with a letter or number"
		}
	case 1:
		if security.ValidateHostname(value) != nil {
			return "Enter a valid DNS hostname or IP address"
		}
	case 2:
		if security.ValidateUsername(value) != nil {
			return "Enter a valid SSH username without spaces"
		}
	}
	return ""
}

func (model Model) beginProxyPicker() Model {
	items := []list.Item{
		proxyItem{domain.ProxyNone, "No proxy"}, proxyItem{domain.ProxySOCKS5, "SOCKS5 proxy"},
		proxyItem{domain.ProxyHTTPConnect, "HTTP CONNECT proxy"}, proxyItem{domain.ProxyJump, "ProxyJump host"},
	}
	model.choices.Title = "Select proxy type"
	model.choices.ResetFilter()
	model.choices.SetItems(items)
	model.choices.Select(proxyIndex(model.wizard.proxy.Type))
	model.formErr = ""
	model.screen = screenProxy
	return model
}

func (model Model) beginIdentityPicker() Model {
	current := placeholder(model.wizard.keyTitle)
	items := []list.Item{
		identityItem{change: false, label: "Keep current identity", detail: current},
		identityItem{change: true, label: "Choose another identity", detail: "Load SSH public-key metadata from 1Password"},
	}
	model.choices.Title = "SSH identity"
	model.choices.ResetFilter()
	model.choices.SetItems(items)
	model.choices.Select(0)
	model.screen = screenIdentity
	return model
}

func proxyIndex(proxyType domain.ProxyType) int {
	switch proxyType {
	case domain.ProxyNone:
		return 0
	case domain.ProxySOCKS5:
		return 1
	case domain.ProxyHTTPConnect:
		return 2
	case domain.ProxyJump:
		return 3
	default:
		return 0
	}
}

func (model Model) updateChoices(message tea.Msg) (tea.Model, tea.Cmd) {
	if model.choices.SettingFilter() {
		var command tea.Cmd
		model.choices, command = model.choices.Update(message)
		if model.screen == screenKeys {
			model.configureKeyPicker()
		}
		return model, command
	}
	if key, ok := message.(tea.KeyMsg); ok && key.String() == "esc" && model.choices.IsFiltered() {
		model.choices.ResetFilter()
		if model.screen == screenKeys {
			model.configureKeyPicker()
		}
		return model, nil
	}
	if model.screen == screenKeys {
		return model.updateKeyChoices(message)
	}

	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			model.screen = screenHosts
			return model, nil
		case "shift+tab":
			if model.screen == screenProxy {
				model.wizard.step = 3
				model.screen = screenInput
				model.configureInput("SSH port", strconv.Itoa(int(model.wizard.port)))
				return model, nil
			}
			if model.screen == screenIdentity {
				return model.beginProxyPicker(), nil
			}
		case "enter":
			switch selected := model.choices.SelectedItem().(type) {
			case proxyItem:
				if model.wizard.proxy.Type != selected.typeValue {
					model.wizard.proxy = domain.Proxy{Type: selected.typeValue}
				}
				if selected.typeValue == domain.ProxyNone {
					model.wizard.proxy = domain.Proxy{Type: domain.ProxyNone}
					return model.afterProxy()
				}
				model.screen = screenInput
				model.wizard.step = 100
				prompt := "Proxy host:port"
				value := ""
				if selected.typeValue == domain.ProxyJump {
					prompt = "ProxyJump alias"
					value = model.wizard.proxy.JumpHost
				} else if model.wizard.proxy.Host != "" && model.wizard.proxy.Port != 0 {
					value = net.JoinHostPort(unbracket(model.wizard.proxy.Host), strconv.Itoa(int(model.wizard.proxy.Port)))
				}
				model.configureInput(prompt, value)
				return model, nil
			case identityItem:
				if selected.change {
					model.wizard.changeKey = true
					return model.startOperation("load 1Password SSH Key metadata", func(ctx context.Context, operationID uint64) tea.Cmd {
						return model.loadKeys(ctx, operationID)
					})
				}
				model.wizard.changeKey = false
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

func (model Model) updateKeyChoices(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		columns := model.keyPickerColumns()
		index := model.choices.Index()
		count := len(model.choices.VisibleItems())
		switch key.String() {
		case "esc":
			model.screen = screenHosts
			return model, nil
		case "shift+tab":
			if model.wizard.editing {
				return model.beginIdentityPicker(), nil
			}
			return model.beginProxyPicker(), nil
		case "enter":
			if selected, ok := model.choices.SelectedItem().(keyItem); ok {
				model.wizard.reference, model.wizard.keyTitle = selected.key.Reference, selected.key.Title
				model.wizard.changeKey = model.wizard.editing
				return model.startOperation("prepare host configuration preview", func(ctx context.Context, operationID uint64) tea.Cmd {
					return model.prepareWizardPlan(ctx, operationID)
				})
			}
			return model, nil
		case "left", "h":
			model.selectKeyChoice(index - 1)
			return model, nil
		case "right", "l":
			model.selectKeyChoice(index + 1)
			return model, nil
		case "up", "k":
			if index >= columns {
				model.selectKeyChoice(index - columns)
			}
			return model, nil
		case "down", "j":
			if index+columns < count {
				model.selectKeyChoice(index + columns)
			}
			return model, nil
		case "pgup":
			model.selectKeyChoice(index - model.choices.Paginator.PerPage)
			return model, nil
		case "pgdown":
			model.selectKeyChoice(index + model.choices.Paginator.PerPage)
			return model, nil
		case "home", "g":
			model.selectKeyChoice(0)
			return model, nil
		case "end", "G":
			model.selectKeyChoice(count - 1)
			return model, nil
		}
	}

	var command tea.Cmd
	model.choices, command = model.choices.Update(message)
	model.configureKeyPicker()
	return model, command
}

func (model *Model) selectKeyChoice(index int) {
	count := len(model.choices.VisibleItems())
	if count == 0 {
		return
	}
	model.choices.Select(max(0, min(index, count-1)))
}

func (model *Model) selectCurrentKey() {
	for index, item := range model.choices.VisibleItems() {
		key, ok := item.(keyItem)
		if ok && key.key.Reference == model.wizard.reference {
			model.choices.Select(index)
			return
		}
	}
}

func (model Model) updateProxyEndpoint(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			model.screen = screenHosts
			model.formErr = ""
			return model, nil
		case "shift+tab":
			return model.beginProxyPicker(), nil
		case "enter":
			value := strings.TrimSpace(model.input.Value())
			if value == "" {
				model.formErr = "This field is required"
				return model, nil
			}
			if model.wizard.proxy.Type == domain.ProxyJump {
				if security.ValidateAlias(value) != nil {
					model.formErr = "Enter a valid managed host alias"
					return model, nil
				}
				model.wizard.proxy.JumpHost = value
			} else {
				host, portText, err := net.SplitHostPort(value)
				if err != nil {
					model.formErr = "Use host:port, for example 127.0.0.1:1080"
					return model, nil
				}
				if security.ValidateHostname(host) != nil {
					model.formErr = "Enter a valid proxy hostname or IP address"
					return model, nil
				}
				port, err := strconv.ParseUint(portText, 10, 16)
				if err != nil || port == 0 {
					model.formErr = "Enter a proxy port from 1 to 65535"
					return model, nil
				}
				model.wizard.proxy.Host, model.wizard.proxy.Port = host, uint16(port)
			}
			return model.afterProxy()
		default:
			model.formErr = ""
		}
	}
	var command tea.Cmd
	model.input, command = model.input.Update(message)
	return model, command
}

func (model Model) afterProxy() (tea.Model, tea.Cmd) {
	if model.wizard.editing {
		return model.beginIdentityPicker(), nil
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
			return model, nil
		case "e":
			if model.canEditPreview() {
				model.wizard.step = 0
				model.screen = screenInput
				model.configureInput("Host alias", model.wizard.alias)
				return model, nil
			}
		}
	}
	model.configureViewport(false)
	var command tea.Cmd
	model.viewport, command = model.viewport.Update(message)
	return model, command
}

func (model Model) canEditPreview() bool {
	if model.wizard.alias == "" {
		return false
	}
	switch model.plan.Operation {
	case "add", "edit", "rename":
		return true
	default:
		return false
	}
}

func (model Model) updateScrollable(message tea.Msg, back screen) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc", "q":
			model.screen = back
			return model, nil
		case "enter":
			if model.screen == screenHelp || model.screen == screenOutput {
				model.screen = back
				return model, nil
			}
		}
	}
	model.configureViewport(false)
	var command tea.Cmd
	model.viewport, command = model.viewport.Update(message)
	return model, command
}

func (model Model) updateMouse(message tea.MouseMsg) (tea.Model, tea.Cmd) {
	event := tea.MouseEvent(message)
	if model.isScrollableScreen() {
		if model.screen == screenError && event.Button == tea.MouseButtonLeft && event.Action == tea.MouseActionPress {
			model.selectErrorCommandAt(event.Y)
			return model, nil
		}
		model.configureViewport(false)
		var command tea.Cmd
		model.viewport, command = model.viewport.Update(message)
		return model, command
	}

	if event.IsWheel() {
		delta := 3
		if event.Button == tea.MouseButtonWheelUp {
			delta = -delta
		}
		switch model.screen {
		case screenHosts:
			model.selectHostIndex(model.hosts.Index() + delta)
		case screenProxy, screenIdentity:
			model.selectChoiceIndex(model.choices.Index() + delta)
		case screenKeys:
			model.selectKeyChoice(model.choices.Index() + delta*model.keyPickerColumns())
		case screenDoctor, screenTunnels:
			if delta < 0 {
				model.table.MoveUp(-delta)
			} else {
				model.table.MoveDown(delta)
			}
		case screenCommand:
			if delta < 0 {
				model.selectCommand(-1)
			} else {
				model.selectCommand(1)
			}
		}
		return model, nil
	}
	if event.Button != tea.MouseButtonLeft || event.Action != tea.MouseActionPress {
		return model, nil
	}

	switch model.screen {
	case screenHosts:
		model.selectHostAt(event.X, event.Y)
	case screenProxy, screenIdentity:
		model.selectChoiceAt(event.X, event.Y)
	case screenKeys:
		model.selectKeyAt(event.X, event.Y)
	case screenDoctor, screenTunnels:
		clickedVisualRow := event.Y - 6
		if selectedVisualRow, ok := model.selectedTableVisualRow(); ok && clickedVisualRow >= 0 {
			target := model.table.Cursor() + clickedVisualRow - selectedVisualRow
			if target >= 0 && target < len(model.table.Rows()) {
				model.table.SetCursor(target)
			}
		}
	case screenCommand:
		model.selectCommandAt(event.Y)
	case screenInput:
		model.input.Focus()
	}
	return model, nil
}

func (model *Model) selectHostIndex(index int) {
	count := len(model.hosts.VisibleItems())
	if count > 0 {
		model.hosts.Select(max(0, min(index, count-1)))
	}
}

func (model *Model) selectChoiceIndex(index int) {
	count := len(model.choices.VisibleItems())
	if count > 0 {
		model.choices.Select(max(0, min(index, count-1)))
	}
}

func (model *Model) selectHostAt(x, y int) {
	if model.hosts.SettingFilter() || y < 4 {
		return
	}
	right := model.contentWidth()
	if model.contentWidth() >= detailWidth {
		right = (model.contentWidth() * 58) / 100
	}
	if x < 1 || x > right {
		return
	}
	relative := y - 4
	if relative%3 >= 2 {
		return
	}
	index := model.hosts.Paginator.Page*model.hosts.Paginator.PerPage + relative/3
	model.selectHostIndex(index)
}

func (model *Model) selectChoiceAt(x, y int) {
	if model.choices.SettingFilter() || x < 1 || x >= model.width-1 || y < 5 {
		return
	}
	relative := y - 5
	if relative%3 >= 2 {
		return
	}
	index := model.choices.Paginator.Page*model.choices.Paginator.PerPage + relative/3
	model.selectChoiceIndex(index)
}

func (model *Model) selectKeyAt(x, y int) {
	if model.choices.SettingFilter() || y < 7 {
		return
	}
	columns := model.keyPickerColumns()
	relativeY := y - 7
	if relativeY%3 >= 2 {
		return
	}
	_, innerWidth, _ := model.viewportSize()
	gap := 3
	cardWidth := innerWidth
	if columns == 2 {
		cardWidth = max(18, (innerWidth-gap)/2)
	}
	relativeX := x - 3
	if relativeX < 0 {
		return
	}
	column := 0
	if columns == 2 && relativeX >= cardWidth+gap {
		column = 1
	}
	if relativeX >= innerWidth || columns == 2 && relativeX >= cardWidth && relativeX < cardWidth+gap {
		return
	}
	index := model.choices.Paginator.Page*model.choices.Paginator.PerPage + (relativeY/3)*columns + column
	model.selectKeyChoice(index)
}

func (model *Model) selectCommandAt(y int) {
	top := 9
	if model.commandErr != "" {
		top++
	}
	index := y - top
	specs := commandSpecs()
	start, end := model.commandWindow(len(specs))
	index += start
	if index < start || index >= end {
		return
	}
	model.commandIndex = index
	model.command.SetValue(specs[index].insert)
	model.command.CursorEnd()
}

func (model *Model) selectErrorCommandAt(y int) {
	_, width, _ := model.viewportSize()
	lineIndex := y - 3 + model.viewport.YOffset
	if lineIndex < 0 {
		return
	}
	lines := strings.Split(model.errorContent(width), "\n")
	if lineIndex >= len(lines) {
		return
	}
	for index, command := range model.diagnostics {
		if isBuiltinCommand(command) && strings.Contains(lines[lineIndex], command) {
			model.errorCommand = index
			model.configureViewport(false)
			return
		}
	}
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
				case "x":
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

func (model Model) openHelp() Model {
	model.helpBack = model.screen
	model.screen = screenHelp
	model.configureViewport(true)
	return model
}

func (model Model) activeListFiltering() bool {
	switch model.screen {
	case screenHosts:
		return model.hosts.SettingFilter()
	case screenProxy, screenIdentity, screenKeys:
		return model.choices.SettingFilter()
	case screenInput, screenPreview, screenConfirmDelete, screenDoctor, screenTunnels, screenError, screenCommand, screenHelp, screenOutput:
		return false
	}
	return false
}

func (model Model) updateCommand(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			model.command.Blur()
			model.screen = model.commandBack
			model.commandErr = ""
			return model, nil
		case "up", "ctrl+p":
			model.selectCommand(-1)
			return model, nil
		case "down", "ctrl+n":
			model.selectCommand(1)
			return model, nil
		case "enter":
			value := strings.TrimSpace(model.command.Value())
			model.commandErr = ""
			if value == "" {
				model.commandErr = "Enter one of the listed built-in commands"
				return model, nil
			}
			updated, command, recognized := model.executeBuiltin(value)
			if recognized {
				return updated, command
			}
			model.commandErr = "Unknown built-in command; arbitrary shell commands are intentionally disabled"
			return model, nil
		}
	}
	var command tea.Cmd
	model.command, command = model.command.Update(message)
	return model, command
}

type commandSpec struct {
	usage       string
	description string
	insert      string
}

func commandSpecs() []commandSpec {
	return []commandSpec{
		{usage: "connect <alias>", description: "Open an SSH session", insert: "connect "},
		{usage: "test <alias>", description: "Diagnose SSH connectivity", insert: "test "},
		{usage: "sync <alias>", description: "Synchronize the bound public key", insert: "sync "},
		{usage: "config render <alias>", description: "Show effective managed fragment", insert: "config render "},
		{usage: "edit <alias>", description: "Edit a managed host", insert: "edit "},
		{usage: "delete <alias>", description: "Review host removal", insert: "delete "},
		{usage: "hosts", description: "Refresh managed hosts", insert: "hosts"},
		{usage: "tunnels", description: "Open tunnel status", insert: "tunnels"},
		{usage: "doctor", description: "Run environment diagnostics", insert: "doctor"},
		{usage: "config validate", description: "Validate managed SSH configurations", insert: "config validate"},
		{usage: "retry", description: "Retry the failed operation", insert: "retry"},
		{usage: "help", description: "Open interaction help", insert: "help"},
		{usage: "quit", description: "Exit opssh", insert: "quit"},
	}
}

func (model *Model) selectCommand(delta int) {
	specs := commandSpecs()
	model.commandIndex = (model.commandIndex + delta + len(specs)) % len(specs)
	model.command.SetValue(specs[model.commandIndex].insert)
	model.command.CursorEnd()
}

func (model Model) executeBuiltin(value string) (tea.Model, tea.Cmd, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "opssh "))
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return model, nil, false
	}
	commandError := func(message string) (tea.Model, tea.Cmd, bool) {
		model.commandErr = message
		if model.screen == screenCommand {
			model.command.Focus()
		}
		return model, nil, true
	}
	aliasAt := func(index int) (string, error) {
		if len(fields) != index+1 {
			return "", errors.New("This command requires exactly one host alias")
		}
		alias := fields[index]
		if err := security.ValidateAlias(alias); err != nil {
			return "", errors.New("Enter a valid managed host alias")
		}
		if model.deps.Service == nil {
			return "", errors.New("Host service is unavailable")
		}
		if _, err := model.deps.Service.Show(alias); err != nil {
			return "", err
		}
		return alias, nil
	}

	switch fields[0] {
	case "connect", "test", "sync", "edit", "delete":
		alias, err := aliasAt(1)
		if err != nil {
			return commandError(logging.Redact(err.Error()))
		}
		model.command.Blur()
		switch fields[0] {
		case "connect":
			if model.deps.Service == nil {
				return commandError("Host service is unavailable")
			}
			updated, command := model.startConnection(alias)
			return updated, command, true
		case "test":
			updated, command := model.startOperation("test SSH connection to "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.testHost(ctx, operationID, alias)
			})
			return updated, command, true
		case "sync":
			updated, command := model.startOperation("synchronize public key for "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.prepareSync(ctx, operationID, alias)
			})
			return updated, command, true
		case "edit":
			host, _ := model.deps.Service.Show(alias)
			return model.beginEdit(host), nil, true
		case "delete":
			model.deleteAlias, model.screen = alias, screenConfirmDelete
			return model, nil, true
		}
	case "config":
		if len(fields) == 2 && fields[1] == "validate" {
			updated, command := model.startOperation("validate managed SSH configurations", func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.validateConfigurations(ctx, operationID)
			})
			return updated, command, true
		}
		if len(fields) >= 2 && fields[1] == "render" {
			alias, err := aliasAt(2)
			if err != nil {
				return commandError(logging.Redact(err.Error()))
			}
			model.outputBack = screenHosts
			updated, command := model.startOperation("render managed SSH configuration for "+alias, func(ctx context.Context, operationID uint64) tea.Cmd {
				return model.renderHostConfig(ctx, operationID, alias)
			})
			return updated, command, true
		}
		return model, nil, false
	case "doctor":
		updated, command := model.startOperation("run diagnostics", func(ctx context.Context, operationID uint64) tea.Cmd { return model.loadDoctor(ctx, operationID) })
		return updated, command, true
	case "hosts", "list":
		updated, command := model.startOperation("load managed hosts", func(ctx context.Context, operationID uint64) tea.Cmd { return model.loadHosts(ctx, operationID) })
		return updated, command, true
	case "tunnels":
		updated, command := model.startOperation("load tunnel status", func(ctx context.Context, operationID uint64) tea.Cmd { return model.loadTunnels(ctx, operationID) })
		return updated, command, true
	case "retry", "r":
		if model.retry == nil {
			return commandError("No failed operation is available to retry")
		}
		updated, command := model.startOperation(model.operation, model.retry)
		return updated, command, true
	case "cancel":
		return model.cancelOperation(), nil, true
	case "back":
		model.screen = model.commandBack
		return model, nil, true
	case "help", "?":
		return model.openHelp(), nil, true
	case "quit", "q":
		return model, tea.Quit, true
	}
	return model, nil, false
}

func isBuiltinCommand(value string) bool {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "opssh ")))
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "connect", "test", "sync", "edit", "delete":
		return len(fields) == 2
	case "config":
		return len(fields) == 2 && fields[1] == "validate" || len(fields) == 3 && fields[1] == "render"
	case "doctor", "hosts", "list", "tunnels", "retry", "r", "cancel", "back", "help", "?", "quit", "q":
		return len(fields) == 1
	default:
		return false
	}
}

func (model *Model) resetErrorCommand() {
	model.errorCommand = -1
	for index, command := range model.diagnostics {
		if isBuiltinCommand(command) {
			model.errorCommand = index
			return
		}
	}
}

func (model *Model) cycleErrorCommand(delta int) {
	if len(model.diagnostics) == 0 {
		return
	}
	start := model.errorCommand
	if start < 0 {
		start = 0
	}
	for step := 1; step <= len(model.diagnostics); step++ {
		index := (start + delta*step + len(model.diagnostics)*step) % len(model.diagnostics)
		if isBuiltinCommand(model.diagnostics[index]) {
			model.errorCommand = index
			model.configureViewport(false)
			return
		}
	}
}

func (model Model) updateError(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			return model.cancelOperation(), nil
		case "r":
			if model.retry != nil {
				return model.startOperation(model.operation, model.retry)
			}
		case "tab":
			model.cycleErrorCommand(1)
			return model, nil
		case "shift+tab":
			model.cycleErrorCommand(-1)
			return model, nil
		case "enter":
			if model.errorCommand >= 0 && model.errorCommand < len(model.diagnostics) {
				updated, command, recognized := model.executeBuiltin(model.diagnostics[model.errorCommand])
				if recognized {
					return updated, command
				}
			}
			return model.openCommandPalette(), nil
		case "q":
			return model, tea.Quit
		}
	}
	model.configureViewport(false)
	var command tea.Cmd
	model.viewport, command = model.viewport.Update(message)
	return model, command
}

func (model Model) startConnection(alias string) (tea.Model, tea.Cmd) {
	model.status = ""
	factory := func(ctx context.Context, operationID uint64) tea.Cmd {
		interactive := &serviceConnectionCommand{service: model.deps.Service, ctx: ctx, alias: alias}
		return tea.Exec(interactive, func(err error) tea.Msg {
			return connectionFinishedMsg{alias: alias, err: err, opID: operationID}
		})
	}
	return model.startOperation("connect to "+alias, factory)
}

type serviceConnectionCommand struct {
	service *app.Service
	ctx     context.Context
	alias   string
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
}

func (command *serviceConnectionCommand) SetStdin(input io.Reader)   { command.stdin = input }
func (command *serviceConnectionCommand) SetStdout(output io.Writer) { command.stdout = output }
func (command *serviceConnectionCommand) SetStderr(output io.Writer) { command.stderr = output }

func (command *serviceConnectionCommand) Run() error {
	if command.service == nil {
		return errors.New("Host service is unavailable")
	}
	return command.service.Connect(command.ctx, command.alias, command.stdin, command.stdout, command.stderr)
}

func isRemoteSessionExit(err error) bool {
	var runErr *process.RunError
	return errors.As(err, &runErr) && runErr.Kind == process.ErrorExit && runErr.ExitCode >= 0 && runErr.ExitCode != 255
}

func (model Model) diagnoseConnection(ctx context.Context, operationID uint64, alias string, originalErr error) tea.Cmd {
	return func() tea.Msg {
		// This is a separate BatchMode probe. Interactive session streams remain
		// attached directly to the terminal and are never read or buffered by opssh.
		result := model.deps.Service.TestConnection(ctx, alias, false)
		return connectionDiagnosedMsg{alias: alias, originalErr: originalErr, result: result, opID: operationID}
	}
}

func (model Model) showConnectionError(alias string, originalErr error, result app.ConnectionTestResult) Model {
	summary := "The SSH session ended before a connection could be established."
	actions := result.Actions
	if result.Success {
		summary = "The interactive SSH session ended, but a follow-up connection and authentication test succeeded."
		actions = append(actions, "Retry the connection; if it closes again, inspect the remote shell startup files")
	} else if strings.TrimSpace(result.Message) != "" {
		summary = strings.TrimSpace(result.Message)
	}

	err := errors.New(summary)
	if originalErr != nil {
		err = fmt.Errorf("%s: %w", strings.TrimSuffix(summary, "."), originalErr)
	}
	model.operation = "connect to " + alias
	model.status = ""
	model = model.showError(err)
	model.errorActions, model.diagnostics = connectionGuidance(alias, actions)
	model.resetErrorCommand()
	model.configureViewport(true)
	return model
}

func connectionGuidance(alias string, guidance []string) ([]string, []string) {
	actions := make([]string, 0, len(guidance))
	commands := []string{"opssh test " + alias, "opssh config render " + alias, "opssh doctor"}
	for _, item := range guidance {
		item = strings.ReplaceAll(strings.TrimSpace(item), "<alias>", alias)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "Run: ") {
			command := strings.TrimSpace(strings.TrimPrefix(item, "Run: "))
			if command == "opssh sync" || command == "opssh test" || command == "opssh config render" {
				command += " " + alias
			}
			commands = append(commands, command)
			continue
		}
		actions = append(actions, item)
	}
	return uniqueText(actions), uniqueText(commands)
}

func uniqueText(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (model Model) startOperation(name string, factory operationFactory) (tea.Model, tea.Cmd) {
	if model.opCancel != nil {
		model.opCancel()
	}
	model.opSequence++
	model.activeOpID = model.opSequence
	ctx, cancel := context.WithCancel(model.baseContext())
	model.opCancel = cancel
	model.opContext = ctx
	model.operation = name
	model.retry = factory
	model.loading = true
	model.err = nil
	model.errorCauses = nil
	model.diagnostics = nil
	model.errorActions = nil
	return model, factory(ctx, model.activeOpID)
}

func (model Model) completeOperation() Model {
	if model.opCancel != nil {
		model.opCancel()
	}
	model.opCancel = nil
	model.opContext = nil
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
	model.opContext = nil
	model.loading = false
	model.operation = ""
	model.retry = nil
	model.err = nil
	model.errorCauses = nil
	model.diagnostics = nil
	model.errorActions = nil
	model.commandErr = ""
	model.formErr = ""
	model.wizard = wizard{}
	model.plan = app.Plan{}
	model.outputTitle = ""
	model.outputText = ""
	model.focusAlias = ""
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
	case connectionFinishedMsg:
		return typed.opID, true
	case connectionDiagnosedMsg:
		return typed.opID, true
	case testFinishedMsg:
		return typed.opID, true
	case validationFinishedMsg:
		return typed.opID, true
	case renderedConfigMsg:
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

func (model *Model) selectHostAlias(alias string) bool {
	for index, item := range model.hosts.VisibleItems() {
		host, ok := item.(hostItem)
		if ok && host.host.Alias == alias {
			model.hosts.Select(index)
			return true
		}
	}
	return false
}

func (model Model) showError(err error) Model {
	if model.opCancel != nil {
		model.opCancel()
		model.opCancel = nil
	}
	model.opContext = nil
	summary, causes := safeErrorChain(err)
	model.screen, model.loading, model.err = screenError, false, errors.New(summary)
	model.formErr = ""
	model.errorCauses = causes
	model.diagnostics = diagnosticCommands(summary)
	model.errorActions = nil
	model.resetErrorCommand()
	model.configureViewport(true)
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
		return appliedMsg{message: "Removed " + alias, alias: alias, action: "remove", err: err, opID: operationID}
	}
}
func (model Model) applyPlan(ctx context.Context, operationID uint64) tea.Cmd {
	return func() tea.Msg {
		err := model.deps.Service.Apply(ctx, model.plan)
		return appliedMsg{message: titleWord(model.plan.Operation) + " completed for " + model.plan.Alias, alias: model.plan.Alias, action: model.plan.Operation, err: err, opID: operationID}
	}
}
func (model Model) testHost(ctx context.Context, operationID uint64, alias string) tea.Cmd {
	return func() tea.Msg {
		return testFinishedMsg{result: model.deps.Service.TestConnection(ctx, alias, false), alias: alias, opID: operationID}
	}
}
func (model Model) renderHostConfig(_ context.Context, operationID uint64, alias string) tea.Cmd {
	return func() tea.Msg {
		data, err := model.deps.Service.Render(alias)
		return renderedConfigMsg{alias: alias, data: data, err: err, opID: operationID}
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
			input := app.EditInput{NewAlias: &newAlias, Hostname: &hostname, User: &user, Port: &port, Proxy: &proxy}
			if model.wizard.changeKey {
				reference := model.wizard.reference
				input.Reference = &reference
				input.KeyTitle = model.wizard.keyTitle
			}
			plan, err := model.deps.Service.PrepareEdit(ctx, model.wizard.originalAlias, input)
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
		return appliedMsg{message: "Started tunnel " + name, reloadTunnels: true, opID: operationID}
	}
}

func (model Model) stopTunnel(ctx context.Context, operationID uint64, name string) tea.Cmd {
	return func() tea.Msg {
		err := model.deps.Tunnels.Stop(ctx, name)
		return appliedMsg{message: "Stopped tunnel " + name, reloadTunnels: true, err: err, opID: operationID}
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

func unbracket(value string) string { return strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[") }
func titleWord(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
