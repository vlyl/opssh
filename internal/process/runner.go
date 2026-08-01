package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vlyl/opssh/internal/security"
)

const (
	DefaultOutputLimit = 1 << 20
	MaximumOutputLimit = 8 << 20
)

type Tool uint8

const (
	ToolOnePassword Tool = iota + 1
	ToolOpenSSH
	ToolSSHAdd
	ToolNetcat
	ToolProcessStatus
	ToolSelf
)

func (tool Tool) String() string {
	switch tool {
	case ToolOnePassword:
		return "op"
	case ToolOpenSSH:
		return "ssh"
	case ToolSSHAdd:
		return "ssh-add"
	case ToolNetcat:
		return "nc"
	case ToolProcessStatus:
		return "ps"
	case ToolSelf:
		return "opssh"
	default:
		return "unknown"
	}
}

type Resolver interface {
	Resolve(tool Tool) (string, error)
}

type PATHResolver struct{}

func (PATHResolver) Resolve(tool Tool) (string, error) {
	if tool == ToolSelf {
		path, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve current executable: %w", err)
		}
		return path, nil
	}
	name := tool.String()
	if name == "unknown" {
		return "", ErrToolNotAllowed
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve %s executable: %w", name, err)
	}
	return path, nil
}

type DetachedProcess struct {
	PID int
}

type InteractiveCommand struct {
	runner  *Runner
	ctx     context.Context
	request Request
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
}

func (runner *Runner) InteractiveCommand(ctx context.Context, request Request) *InteractiveCommand {
	return &InteractiveCommand{runner: runner, ctx: ctx, request: request}
}

func (command *InteractiveCommand) SetStdin(input io.Reader)   { command.stdin = input }
func (command *InteractiveCommand) SetStdout(output io.Writer) { command.stdout = output }
func (command *InteractiveCommand) SetStderr(output io.Writer) { command.stderr = output }

func (command *InteractiveCommand) Run() error {
	return command.runner.RunInteractive(command.ctx, command.request, command.stdin, command.stdout, command.stderr)
}

func (runner *Runner) StartDetached(ctx context.Context, request Request) (DetachedProcess, error) {
	if err := validateRequest(request); err != nil {
		return DetachedProcess{}, err
	}
	executable, err := runner.resolver.Resolve(request.Tool)
	if err != nil {
		return DetachedProcess{}, err
	}
	// #nosec G204 -- executable is resolved from the closed Tool allow-list and no shell is used.
	command := exec.CommandContext(context.WithoutCancel(ctx), executable, request.Args...)
	configureDetached(command)
	if request.AgentSocket != "" {
		command.Env = withEnvironmentValue(os.Environ(), "SSH_AUTH_SOCK", request.AgentSocket)
	}
	if err := command.Start(); err != nil {
		return DetachedProcess{}, &RunError{Tool: request.Tool, Kind: ErrorStart, ExitCode: -1, cause: err}
	}
	pid := command.Process.Pid
	if err := command.Process.Release(); err != nil {
		return DetachedProcess{}, fmt.Errorf("release detached %s process: %w", request.Tool, err)
	}
	return DetachedProcess{PID: pid}, nil
}

type Request struct {
	Tool        Tool
	Args        []string
	AgentSocket string
	OutputLimit int
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type ErrorKind string

const (
	ErrorStart           ErrorKind = "start_failed"
	ErrorExit            ErrorKind = "nonzero_exit"
	ErrorCanceled        ErrorKind = "canceled"
	ErrorSensitiveOutput ErrorKind = "sensitive_output"
	ErrorOutputLimit     ErrorKind = "output_limit"
)

var (
	ErrToolNotAllowed         = errors.New("external tool is not allowed")
	ErrInvalidArgument        = errors.New("external command contains an invalid argument")
	ErrSensitiveCommandOutput = errors.New("external command output was rejected by the security policy")
	ErrCommandOutputTooLarge  = errors.New("external command output exceeded the safety limit")
)

type RunError struct {
	Tool     Tool
	Kind     ErrorKind
	ExitCode int
	cause    error
}

func (err *RunError) Error() string {
	switch err.Kind {
	case ErrorStart:
		return fmt.Sprintf("could not start %s command", err.Tool)
	case ErrorSensitiveOutput:
		return ErrSensitiveCommandOutput.Error()
	case ErrorOutputLimit:
		return ErrCommandOutputTooLarge.Error()
	case ErrorCanceled:
		return fmt.Sprintf("%s command was canceled", err.Tool)
	case ErrorExit:
		return fmt.Sprintf("%s command exited with status %d", err.Tool, err.ExitCode)
	default:
		return fmt.Sprintf("%s command failed", err.Tool)
	}
}

func (err *RunError) Unwrap() error {
	if err.Kind == ErrorSensitiveOutput {
		return ErrSensitiveCommandOutput
	}
	if err.Kind == ErrorOutputLimit {
		return ErrCommandOutputTooLarge
	}
	return err.cause
}

type AuditEvent struct {
	Code string
	Tool Tool
}

type AuditSink interface {
	Record(event AuditEvent)
}

type discardAudit struct{}

func (discardAudit) Record(AuditEvent) {}

type Runner struct {
	resolver Resolver
	audit    AuditSink
}

func NewRunner(resolver Resolver, audit AuditSink) *Runner {
	if resolver == nil {
		resolver = PATHResolver{}
	}
	if audit == nil {
		audit = discardAudit{}
	}
	return &Runner{resolver: resolver, audit: audit}
}

// RunInteractive attaches a child directly to the supplied terminal streams.
// opssh does not read, buffer, inspect, or log interactive session contents.
func (runner *Runner) RunInteractive(ctx context.Context, request Request, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	executable, err := runner.resolver.Resolve(request.Tool)
	if err != nil {
		return err
	}
	// #nosec G204 -- executable is resolved from the closed Tool allow-list and no shell is used.
	command := exec.CommandContext(ctx, executable, request.Args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if request.AgentSocket != "" {
		command.Env = withEnvironmentValue(os.Environ(), "SSH_AUTH_SOCK", request.AgentSocket)
	}
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return &RunError{Tool: request.Tool, Kind: ErrorCanceled, ExitCode: -1, cause: ctx.Err()}
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return &RunError{Tool: request.Tool, Kind: ErrorExit, ExitCode: exitError.ExitCode(), cause: err}
		}
		return &RunError{Tool: request.Tool, Kind: ErrorStart, ExitCode: -1, cause: err}
	}
	return nil
}

// Run executes an allow-listed binary directly. It never invokes a shell and
// never includes captured command output in returned errors.
func (runner *Runner) Run(ctx context.Context, request Request) (Result, error) {
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	executable, err := runner.resolver.Resolve(request.Tool)
	if err != nil {
		return Result{}, err
	}
	limit := request.OutputLimit
	if limit == 0 {
		limit = DefaultOutputLimit
	}

	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	state := &captureState{cancel: cancel}
	stdout := newSafeBuffer(limit, state)
	stderr := newSafeBuffer(limit, state)

	// #nosec G204,G702 -- executable is resolved from the closed Tool allow-list, arguments are validated, and no shell is used.
	command := exec.CommandContext(commandContext, executable, request.Args...)
	command.Stdout = stdout
	command.Stderr = stderr
	if request.AgentSocket != "" {
		command.Env = withEnvironmentValue(os.Environ(), "SSH_AUTH_SOCK", request.AgentSocket)
	}

	startErr := command.Start()
	if startErr != nil {
		stdout.wipe()
		stderr.wipe()
		return Result{}, &RunError{Tool: request.Tool, Kind: ErrorStart, ExitCode: -1, cause: startErr}
	}
	waitErr := command.Wait()

	if state.containsSensitiveOutput() {
		stdout.wipe()
		stderr.wipe()
		runner.audit.Record(AuditEvent{Code: "sensitive_output_blocked", Tool: request.Tool})
		return Result{}, &RunError{Tool: request.Tool, Kind: ErrorSensitiveOutput, ExitCode: -1}
	}
	if state.exceededOutputLimit() {
		stdout.wipe()
		stderr.wipe()
		runner.audit.Record(AuditEvent{Code: "output_limit_exceeded", Tool: request.Tool})
		return Result{}, &RunError{Tool: request.Tool, Kind: ErrorOutputLimit, ExitCode: -1}
	}

	result := Result{Stdout: stdout.bytes(), Stderr: stderr.bytes(), ExitCode: 0}
	if waitErr == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		result.ExitCode = -1
		return result, &RunError{Tool: request.Tool, Kind: ErrorCanceled, ExitCode: -1, cause: ctx.Err()}
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, &RunError{Tool: request.Tool, Kind: ErrorExit, ExitCode: result.ExitCode, cause: waitErr}
	}
	result.ExitCode = -1
	return result, &RunError{Tool: request.Tool, Kind: ErrorExit, ExitCode: -1, cause: waitErr}
}

func validateRequest(request Request) error {
	if request.Tool.String() == "unknown" {
		return ErrToolNotAllowed
	}
	if request.OutputLimit < 0 || request.OutputLimit > MaximumOutputLimit {
		return errors.New("output limit is outside the supported range")
	}
	for _, argument := range request.Args {
		if strings.ContainsRune(argument, '\x00') {
			return ErrInvalidArgument
		}
	}
	if request.AgentSocket != "" {
		if !filepath.IsAbs(request.AgentSocket) || security.ValidateConfigPathText(request.AgentSocket) != nil {
			return ErrInvalidArgument
		}
	}
	return nil
}

type captureState struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	sensitive bool
	overLimit bool
}

func (state *captureState) rejectSensitive() {
	state.mu.Lock()
	if !state.sensitive {
		state.sensitive = true
		state.cancel()
	}
	state.mu.Unlock()
}

func (state *captureState) rejectLimit() {
	state.mu.Lock()
	if !state.overLimit {
		state.overLimit = true
		state.cancel()
	}
	state.mu.Unlock()
}

func (state *captureState) containsSensitiveOutput() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.sensitive
}

func (state *captureState) exceededOutputLimit() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.overLimit
}

type safeBuffer struct {
	mu    sync.Mutex
	data  []byte
	tail  []byte
	limit int
	state *captureState
}

func newSafeBuffer(limit int, state *captureState) *safeBuffer {
	return &safeBuffer{limit: limit, state: state}
}

func (buffer *safeBuffer) Write(chunk []byte) (int, error) {
	written := len(chunk)
	buffer.mu.Lock()
	defer buffer.mu.Unlock()

	window := make([]byte, 0, len(buffer.tail)+len(chunk))
	window = append(window, buffer.tail...)
	window = append(window, chunk...)
	if security.ContainsSensitiveMarker(window) {
		security.Wipe(buffer.data)
		buffer.data = nil
		security.Wipe(buffer.tail)
		buffer.tail = nil
		security.Wipe(window)
		security.Wipe(chunk)
		buffer.state.rejectSensitive()
		return written, nil
	}
	if len(buffer.data)+len(chunk) > buffer.limit {
		security.Wipe(buffer.data)
		buffer.data = nil
		security.Wipe(buffer.tail)
		buffer.tail = nil
		security.Wipe(window)
		security.Wipe(chunk)
		buffer.state.rejectLimit()
		return written, nil
	}

	buffer.data = append(buffer.data, chunk...)
	keep := security.LongestSensitiveMarker() - 1
	if keep > len(window) {
		keep = len(window)
	}
	security.Wipe(buffer.tail)
	buffer.tail = append(buffer.tail[:0], window[len(window)-keep:]...)
	security.Wipe(window)
	security.Wipe(chunk)
	return written, nil
}

func (buffer *safeBuffer) bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return bytes.Clone(buffer.data)
}

func (buffer *safeBuffer) wipe() {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	security.Wipe(buffer.data)
	buffer.data = nil
	security.Wipe(buffer.tail)
	buffer.tail = nil
}

func withEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}
