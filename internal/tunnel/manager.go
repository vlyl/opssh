package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/domain"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
)

const StateVersion = 1

var (
	ErrTunnelMissing = errors.New("tunnel does not exist")
	ErrTunnelRunning = errors.New("tunnel is already running")
	ErrPortInUse     = errors.New("tunnel local endpoint is already in use")
	ErrUnsafeProcess = errors.New("tunnel process identity did not match its state file")
	ErrNonLoopback   = errors.New("non-loopback tunnel listener requires explicit approval")
)

type Manager struct {
	Service *app.Service
	Runner  *process.Runner
	Now     func() time.Time
}

type StartOptions struct {
	Foreground       bool
	NoReconnect      bool
	AllowNonLoopback bool
	Input            io.Reader
	Output           io.Writer
	Error            io.Writer
}

type State struct {
	Version        int       `json:"version"`
	Name           string    `json:"name"`
	InstanceID     string    `json:"instance_id"`
	PID            int       `json:"pid"`
	StartedAt      time.Time `json:"started_at"`
	ProcessStart   string    `json:"process_start"`
	CommandSummary string    `json:"command_summary"`
	HostAlias      string    `json:"host_alias"`
	LocalEndpoint  string    `json:"local_endpoint"`
	RemoteTarget   string    `json:"remote_target"`
	Reconnect      bool      `json:"reconnect"`
	LogPath        string    `json:"log_path"`
}

type Status struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	PID     int    `json:"pid,omitempty"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	Host    string `json:"host"`
	Reason  string `json:"reason,omitempty"`
}

func (manager Manager) List() ([]domain.Tunnel, error) {
	configuration, err := manager.Service.LoadConfiguration()
	if err != nil {
		return nil, err
	}
	tunnels := make([]domain.Tunnel, 0, len(configuration.Tunnels))
	for _, configured := range configuration.Tunnels {
		tunnels = append(tunnels, configured)
	}
	slicesSort(tunnels)
	return tunnels, nil
}

func (manager Manager) Start(ctx context.Context, name string, options StartOptions) (State, error) {
	configured, defaults, err := manager.configured(name)
	if err != nil {
		return State{}, err
	}
	localEndpoint := net.JoinHostPort(unbracket(configured.LocalHost), strconv.Itoa(int(configured.LocalPort)))
	remoteTarget := net.JoinHostPort(unbracket(configured.RemoteHost), strconv.Itoa(int(configured.RemotePort)))
	localIP := net.ParseIP(unbracket(configured.LocalHost))
	if localIP == nil {
		return State{}, errors.New("tunnel local host is not an IP address")
	}
	if !localIP.IsLoopback() && !options.AllowNonLoopback {
		return State{}, ErrNonLoopback
	}
	sshArgs := sshArguments(configured, defaults)
	if options.Foreground {
		if err := checkPortAvailable(ctx, localEndpoint); err != nil {
			return State{}, err
		}
		if err := manager.Runner.RunInteractive(ctx, process.Request{Tool: process.ToolOpenSSH, Args: sshArgs}, options.Input, options.Output, options.Error); err != nil {
			return State{}, err
		}
		return State{Name: name, HostAlias: configured.SSHHost, LocalEndpoint: localEndpoint, RemoteTarget: remoteTarget}, nil
	}
	statePath, err := manager.Service.Repository.Layout.TunnelState(name)
	if err != nil {
		return State{}, err
	}
	var state State
	err = manager.Service.Repository.WithLock(statePath+".lifecycle.lock", func() error {
		var startErr error
		state, startErr = manager.startBackground(ctx, name, configured, localEndpoint, remoteTarget, options)
		return startErr
	})
	return state, err
}

func (manager Manager) startBackground(ctx context.Context, name string, configured domain.Tunnel, localEndpoint, remoteTarget string, options StartOptions) (State, error) {
	if status, statusErr := manager.Status(ctx, name); statusErr == nil && status.Running {
		return State{}, ErrTunnelRunning
	}
	if err := checkPortAvailable(ctx, localEndpoint); err != nil {
		return State{}, err
	}
	instanceID, err := randomInstanceID()
	if err != nil {
		return State{}, errors.New("could not create tunnel instance ID")
	}
	reconnect := configured.Reconnect && !options.NoReconnect
	supervisorArgs := []string{"_tunnel-supervise", name, "--instance", instanceID}
	if reconnect {
		supervisorArgs = append(supervisorArgs, "--reconnect")
	}
	detached, err := manager.Runner.StartDetached(ctx, process.Request{Tool: process.ToolSelf, Args: supervisorArgs})
	if err != nil {
		return State{}, err
	}
	processStart, err := manager.processStart(ctx, detached.PID)
	if err != nil {
		_ = terminateProcess(detached.PID)
		return State{}, errors.New("could not verify tunnel supervisor startup")
	}
	logPath, _ := manager.Service.Repository.Layout.TunnelLog(name)
	state := State{
		Version: StateVersion, Name: name, InstanceID: instanceID, PID: detached.PID,
		StartedAt: manager.now(), ProcessStart: processStart,
		CommandSummary: strings.Join(supervisorArgs, " "), HostAlias: configured.SSHHost,
		LocalEndpoint: localEndpoint, RemoteTarget: remoteTarget, Reconnect: reconnect, LogPath: logPath,
	}
	if err := manager.writeState(name, state); err != nil {
		_ = terminateProcess(detached.PID)
		return State{}, err
	}
	if err := waitForListener(ctx, localEndpoint, detached.PID, 8*time.Second); err != nil {
		_ = terminateProcess(detached.PID)
		_ = manager.removeStateForInstance(name, instanceID)
		return State{}, err
	}
	return state, nil
}

func (manager Manager) Supervise(ctx context.Context, name, instanceID string, reconnect bool) (returnErr error) {
	configured, defaults, err := manager.configured(name)
	if err != nil {
		return err
	}
	if !validInstanceID(instanceID) {
		return errors.New("invalid tunnel instance ID")
	}
	if err := manager.waitForSupervisorAuthorization(ctx, name, instanceID, os.Getpid(), 5*time.Second); err != nil {
		return err
	}
	logPath, _ := manager.Service.Repository.Layout.TunnelLog(name)
	if err := manager.Service.Repository.Ensure(); err != nil {
		return err
	}
	logWriter, err := securefs.NewAtomicWriter(manager.Service.Repository.Layout.LogDir)
	if err != nil {
		return err
	}
	logFile, err := logWriter.OpenAppend(logPath, 0o600, 1<<20)
	if err != nil {
		return err
	}
	guardedLog := security.NewGuardedWriter(logFile, 1<<20)
	defer func() {
		returnErr = errors.Join(returnErr, guardedLog.Flush(), logFile.Close())
	}()
	args := sshArguments(configured, defaults)
	delay := time.Second
	for {
		commandContext, cancel := context.WithCancel(ctx)
		logSink := &cancelOnErrorWriter{destination: guardedLog, cancel: cancel}
		err := manager.Runner.RunInteractive(commandContext, process.Request{Tool: process.ToolOpenSSH, Args: args}, nil, logSink, logSink)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if guardedLog.Rejected() || errors.Is(logSink.Err(), security.ErrSensitiveStream) {
			_, _ = fmt.Fprintln(logFile, "[SECURITY] tunnel output was rejected and the process was stopped")
			return errors.New("tunnel output was rejected by the security policy")
		}
		if logErr := logSink.Err(); logErr != nil {
			return fmt.Errorf("write tunnel log: %w", logErr)
		}
		if !reconnect {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

type cancelOnErrorWriter struct {
	destination io.Writer
	cancel      context.CancelFunc
	mu          sync.Mutex
	err         error
}

func (writer *cancelOnErrorWriter) Write(data []byte) (int, error) {
	count, err := writer.destination.Write(data)
	if err != nil {
		writer.mu.Lock()
		if writer.err == nil {
			writer.err = err
		}
		writer.mu.Unlock()
		writer.cancel()
	}
	return count, err
}

func (writer *cancelOnErrorWriter) Err() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.err
}

func (manager Manager) Stop(ctx context.Context, name string) error {
	path, err := manager.Service.Repository.Layout.TunnelState(name)
	if err != nil {
		return err
	}
	return manager.Service.Repository.WithLock(path+".lifecycle.lock", func() error {
		return manager.stopLocked(ctx, name)
	})
}

func (manager Manager) stopLocked(ctx context.Context, name string) error {
	state, data, err := manager.readState(name)
	if err != nil {
		return err
	}
	if err := manager.verifyStateProcess(ctx, state); err != nil {
		return err
	}
	if err := terminateProcess(state.PID); err != nil {
		return fmt.Errorf("stop tunnel supervisor: %w", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(state.PID) {
			return manager.removeStateExpected(name, data)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("tunnel supervisor did not stop after SIGTERM")
}

func (manager Manager) Status(ctx context.Context, name string) (Status, error) {
	configured, _, err := manager.configured(name)
	if err != nil {
		return Status{}, err
	}
	status := Status{
		Name: name, Host: configured.SSHHost,
		Local:  net.JoinHostPort(unbracket(configured.LocalHost), strconv.Itoa(int(configured.LocalPort))),
		Remote: net.JoinHostPort(unbracket(configured.RemoteHost), strconv.Itoa(int(configured.RemotePort))),
	}
	state, _, err := manager.readState(name)
	if errors.Is(err, os.ErrNotExist) {
		status.Reason = "no state file"
		return status, nil
	}
	if err != nil {
		status.Reason = "invalid state file"
		return status, nil //nolint:nilerr // Status deliberately reports malformed state as non-running.
	}
	if err := manager.verifyStateProcess(ctx, state); err != nil {
		status.Reason = "stale or mismatched process"
		return status, nil //nolint:nilerr // Status deliberately reports stale state as non-running.
	}
	status.Running, status.PID = true, state.PID
	return status, nil
}

func (manager Manager) configured(name string) (domain.Tunnel, domain.Defaults, error) {
	configuration, err := manager.Service.LoadConfiguration()
	if err != nil {
		return domain.Tunnel{}, domain.Defaults{}, err
	}
	configured, exists := configuration.Tunnels[name]
	if !exists {
		return domain.Tunnel{}, domain.Defaults{}, ErrTunnelMissing
	}
	return configured, configuration.Defaults, nil
}

func (manager Manager) writeState(name string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("could not encode tunnel state")
	}
	data = append(data, '\n')
	path, _ := manager.Service.Repository.Layout.TunnelState(name)
	current, _, exists, err := manager.Service.Repository.Read(path, 1<<20)
	if err != nil {
		return err
	}
	return manager.Service.Repository.Apply([]app.FileChange{{Path: path, Data: data, Mode: 0o600, ExpectedDigest: app.Digest(current, exists)}})
}

func (manager Manager) readState(name string) (State, []byte, error) {
	path, err := manager.Service.Repository.Layout.TunnelState(name)
	if err != nil {
		return State{}, nil, err
	}
	data, _, exists, err := manager.Service.Repository.Read(path, 1<<20)
	if err != nil {
		return State{}, nil, err
	}
	if !exists {
		return State{}, nil, os.ErrNotExist
	}
	if security.ContainsSensitiveMarker(data) {
		security.Wipe(data)
		return State{}, nil, errors.New("tunnel state was rejected by the security policy")
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Version != StateVersion || state.Name != name || state.PID < 1 || !validInstanceID(state.InstanceID) {
		return State{}, data, errors.New("invalid tunnel state")
	}
	return state, data, nil
}

func (manager Manager) removeStateForInstance(name, instanceID string) error {
	state, data, err := manager.readState(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer security.Wipe(data)
	if state.InstanceID != instanceID {
		return ErrUnsafeProcess
	}
	return manager.removeStateExpected(name, data)
}

func (manager Manager) waitForSupervisorAuthorization(ctx context.Context, name, instanceID string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, data, err := manager.readState(name)
		security.Wipe(data)
		if err == nil && state.InstanceID == instanceID && state.PID == pid {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return errors.New("tunnel supervisor was not authorized by its parent process")
}

func (manager Manager) removeStateExpected(name string, data []byte) error {
	path, _ := manager.Service.Repository.Layout.TunnelState(name)
	return manager.Service.Repository.Apply([]app.FileChange{{Path: path, Delete: true, ExpectedDigest: app.Digest(data, true)}})
}

func (manager Manager) verifyStateProcess(ctx context.Context, state State) error {
	if !processAlive(state.PID) {
		return ErrUnsafeProcess
	}
	start, err := manager.processStart(ctx, state.PID)
	if err != nil || start != state.ProcessStart {
		return ErrUnsafeProcess
	}
	command, err := manager.processCommand(ctx, state.PID)
	if err != nil || !strings.Contains(command, state.CommandSummary) || !strings.Contains(command, state.InstanceID) {
		return ErrUnsafeProcess
	}
	return nil
}

func (manager Manager) processStart(ctx context.Context, pid int) (string, error) {
	result, err := manager.Runner.Run(ctx, process.Request{Tool: process.ToolProcessStatus, Args: []string{"-p", strconv.Itoa(pid), "-o", "lstart="}, OutputLimit: 64 << 10})
	if err != nil {
		return "", err
	}
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	value := strings.TrimSpace(string(result.Stdout))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid process start value")
	}
	return value, nil
}

func (manager Manager) processCommand(ctx context.Context, pid int) (string, error) {
	result, err := manager.Runner.Run(ctx, process.Request{Tool: process.ToolProcessStatus, Args: []string{"-p", strconv.Itoa(pid), "-o", "command="}, OutputLimit: 64 << 10})
	if err != nil {
		return "", err
	}
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	return strings.TrimSpace(string(result.Stdout)), nil
}

func sshArguments(configured domain.Tunnel, defaults domain.Defaults) []string {
	forward := net.JoinHostPort(unbracket(configured.LocalHost), strconv.Itoa(int(configured.LocalPort))) + ":" +
		net.JoinHostPort(unbracket(configured.RemoteHost), strconv.Itoa(int(configured.RemotePort)))
	return []string{
		"-N", "-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=" + strconv.Itoa(defaults.ServerAliveInterval),
		"-o", "ServerAliveCountMax=" + strconv.Itoa(defaults.ServerAliveCountMax),
		"-L", forward, configured.SSHHost,
	}
}

func checkPortAvailable(ctx context.Context, endpoint string) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", endpoint)
	if err != nil {
		return ErrPortInUse
	}
	return listener.Close()
}

func waitForListener(ctx context.Context, endpoint string, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return errors.New("tunnel supervisor exited before the listener became ready")
		}
		connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", endpoint)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errors.New("tunnel listener did not become ready")
}

func processAlive(pid int) bool {
	processHandle, err := os.FindProcess(pid)
	return err == nil && processHandle.Signal(syscall.Signal(0)) == nil
}

func terminateProcess(pid int) error {
	processHandle, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return processHandle.Signal(syscall.SIGTERM)
}

func randomInstanceID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func validInstanceID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func (manager Manager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}

func unbracket(value string) string {
	return strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
}

func slicesSort(tunnels []domain.Tunnel) {
	for index := 1; index < len(tunnels); index++ {
		for current := index; current > 0 && tunnels[current].Name < tunnels[current-1].Name; current-- {
			tunnels[current], tunnels[current-1] = tunnels[current-1], tunnels[current]
		}
	}
}
