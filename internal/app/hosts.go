package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
	"github.com/vlyl/opssh/internal/sshconfig"
)

var (
	ErrHostExists         = errors.New("host alias already exists")
	ErrHostMissing        = errors.New("host alias does not exist")
	ErrNotManaged         = errors.New("refusing to modify a file not managed by opssh")
	ErrRenameTargetExists = errors.New("new host alias conflicts with an existing managed path")
)

type Clock func() time.Time

type CommandRunner interface {
	Run(ctx context.Context, request process.Request) (process.Result, error)
	RunInteractive(ctx context.Context, request process.Request, stdin io.Reader, stdout, stderr io.Writer) error
}

type Service struct {
	Repository *Repository
	Keys       domain.PublicKeyProvider
	Runner     CommandRunner
	Clock      Clock
}

type AddInput struct {
	Alias           string
	Hostname        string
	User            string
	Port            uint16
	Reference       domain.KeyReference
	KeyTitle        string
	Proxy           domain.Proxy
	HostKeyChecking domain.HostKeyChecking
}

type EditInput struct {
	NewAlias  *string
	Hostname  *string
	User      *string
	Port      *uint16
	Reference *domain.KeyReference
	KeyTitle  string
	Proxy     *domain.Proxy
}

type Plan struct {
	Operation      string
	Alias          string
	Fingerprint    string
	ConfigPreview  string
	IncludeChanged bool
	Changes        []ChangeSummary
	Notices        []string

	changes         []FileChange
	validateAliases []string
}

type ChangeSummary struct {
	Action string
	Path   string
}

func (service *Service) List() ([]domain.Host, error) {
	configuration, err := service.load()
	if err != nil {
		return nil, err
	}
	hosts := make([]domain.Host, 0, len(configuration.Hosts))
	for _, host := range configuration.Hosts {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(left, right int) bool { return hosts[left].Alias < hosts[right].Alias })
	return hosts, nil
}

func (service *Service) Show(alias string) (domain.Host, error) {
	if err := security.ValidateAlias(alias); err != nil {
		return domain.Host{}, err
	}
	configuration, err := service.load()
	if err != nil {
		return domain.Host{}, err
	}
	host, exists := configuration.Hosts[alias]
	if !exists {
		return domain.Host{}, ErrHostMissing
	}
	return host, nil
}

func (service *Service) PrepareAdd(ctx context.Context, input AddInput) (Plan, error) {
	if service.Keys == nil {
		return Plan{}, errors.New("public-key provider is unavailable")
	}
	configuration, err := service.load()
	if err != nil {
		return Plan{}, err
	}
	if _, exists := configuration.Hosts[input.Alias]; exists {
		return Plan{}, ErrHostExists
	}
	key, err := service.Keys.GetPublicKey(ctx, input.Reference)
	if err != nil {
		return Plan{}, err
	}
	defer security.Wipe(key.Line)
	if input.KeyTitle == "" {
		input.KeyTitle = "1Password SSH Key"
	}
	if input.Port == 0 {
		input.Port = 22
	}
	if input.Proxy.Type == "" {
		input.Proxy.Type = domain.ProxyNone
	}
	if input.HostKeyChecking == "" {
		input.HostKeyChecking = domain.HostKeyCheckingAsk
	}
	host := domain.Host{
		Alias: input.Alias, Hostname: input.Hostname, User: input.User, Port: input.Port,
		Key: domain.KeyBinding{
			Reference: input.Reference, Title: input.KeyTitle, Fingerprint: key.Fingerprint,
			PublicKeyFile: managedPublicKeyPath(input.Alias), LastSyncedAt: service.now(),
		},
		Proxy: input.Proxy,
		Options: domain.HostOptions{
			IdentitiesOnly: true, StrictHostKeyChecking: input.HostKeyChecking,
			ServerAliveInterval: configuration.Defaults.ServerAliveInterval,
			ServerAliveCountMax: configuration.Defaults.ServerAliveCountMax,
		},
	}
	configuration.Hosts[input.Alias] = host
	return service.buildUpsertPlan(configuration, host, key.Line, "add")
}

func (service *Service) PrepareEdit(ctx context.Context, alias string, input EditInput) (Plan, error) {
	configuration, err := service.load()
	if err != nil {
		return Plan{}, err
	}
	host, exists := configuration.Hosts[alias]
	if !exists {
		return Plan{}, ErrHostMissing
	}
	originalHost := host
	newAlias := alias
	if input.NewAlias != nil {
		newAlias = *input.NewAlias
		if err := security.ValidateAlias(newAlias); err != nil {
			return Plan{}, err
		}
		if newAlias != alias {
			if _, exists := configuration.Hosts[newAlias]; exists {
				return Plan{}, ErrHostExists
			}
		}
	}
	if input.Hostname != nil {
		host.Hostname = *input.Hostname
	}
	if input.User != nil {
		host.User = *input.User
	}
	if input.Port != nil {
		host.Port = *input.Port
	}
	if input.Proxy != nil {
		host.Proxy = *input.Proxy
	}
	var publicLine []byte
	if input.Reference != nil {
		if service.Keys == nil {
			return Plan{}, errors.New("public-key provider is unavailable")
		}
		key, getErr := service.Keys.GetPublicKey(ctx, *input.Reference)
		if getErr != nil {
			return Plan{}, getErr
		}
		defer security.Wipe(key.Line)
		publicLine = bytes.Clone(key.Line)
		host.Key.Reference = *input.Reference
		host.Key.Fingerprint = key.Fingerprint
		host.Key.LastSyncedAt = service.now()
		if input.KeyTitle != "" {
			host.Key.Title = input.KeyTitle
		}
	}
	host.Alias = newAlias
	host.Key.PublicKeyFile = managedPublicKeyPath(newAlias)
	if newAlias != alias {
		delete(configuration.Hosts, alias)
	}
	configuration.Hosts[newAlias] = host
	if newAlias != alias {
		dependentAliases := updateAliasReferences(configuration, alias, newAlias)
		return service.buildRenamePlan(configuration, originalHost, host, publicLine, dependentAliases)
	}
	return service.buildUpsertPlan(configuration, host, publicLine, "edit")
}

func updateAliasReferences(configuration domain.Configuration, oldAlias, newAlias string) []string {
	var dependentAliases []string
	for alias, host := range configuration.Hosts {
		if host.Proxy.Type != domain.ProxyJump || host.Proxy.JumpHost != oldAlias {
			continue
		}
		host.Proxy.JumpHost = newAlias
		configuration.Hosts[alias] = host
		if alias != newAlias {
			dependentAliases = append(dependentAliases, alias)
		}
	}
	for name, configured := range configuration.Tunnels {
		if configured.SSHHost == oldAlias {
			configured.SSHHost = newAlias
			configuration.Tunnels[name] = configured
		}
	}
	sort.Strings(dependentAliases)
	return dependentAliases
}

func (service *Service) PrepareRemove(alias string) (Plan, error) {
	configuration, err := service.load()
	if err != nil {
		return Plan{}, err
	}
	host, exists := configuration.Hosts[alias]
	if !exists {
		return Plan{}, ErrHostMissing
	}
	hostPath, _ := service.Repository.Layout.HostConfig(alias)
	keyPath, _ := service.Repository.Layout.PublicKey(alias)
	configData, _, configExists, err := service.Repository.Read(hostPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	if configExists && !sshconfig.IsManaged(configData) {
		return Plan{}, ErrNotManaged
	}
	keyData, _, keyExists, err := service.Repository.Read(keyPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	if keyExists && sshconfig.ValidatePublicKey(keyData, host.Key.Fingerprint) != nil {
		return Plan{}, ErrNotManaged
	}
	delete(configuration.Hosts, alias)
	encoded, err := config.Encode(configuration)
	if err != nil {
		return Plan{}, err
	}
	currentConfig, _, configFileExists, err := service.Repository.Read(service.Repository.Layout.ConfigFile, config.MaxConfigBytes)
	if err != nil {
		return Plan{}, err
	}
	changes := []FileChange{{
		Path: service.Repository.Layout.ConfigFile, Data: encoded, Mode: 0o600,
		ExpectedDigest: Digest(currentConfig, configFileExists),
	}}
	summaries := []ChangeSummary{{Action: "update", Path: service.Repository.Layout.ConfigFile}}
	if configExists {
		changes = append(changes, FileChange{Path: hostPath, Delete: true, ExpectedDigest: Digest(configData, true)})
		summaries = append(summaries, ChangeSummary{Action: "delete", Path: hostPath})
	}
	if keyExists {
		changes = append(changes, FileChange{Path: keyPath, Delete: true, ExpectedDigest: Digest(keyData, true)})
		summaries = append(summaries, ChangeSummary{Action: "delete", Path: keyPath})
	}
	return Plan{Operation: "remove", Alias: alias, Fingerprint: host.Key.Fingerprint, Changes: summaries, changes: changes}, nil
}

func (service *Service) PrepareSync(ctx context.Context, alias string) (Plan, error) {
	if service.Keys == nil {
		return Plan{}, errors.New("public-key provider is unavailable")
	}
	configuration, err := service.load()
	if err != nil {
		return Plan{}, err
	}
	aliases := make([]string, 0, len(configuration.Hosts))
	if alias != "" {
		if _, exists := configuration.Hosts[alias]; !exists {
			return Plan{}, ErrHostMissing
		}
		aliases = append(aliases, alias)
	} else {
		for name := range configuration.Hosts {
			aliases = append(aliases, name)
		}
		sort.Strings(aliases)
	}
	var changes []FileChange
	var summaries []ChangeSummary
	var previews []string
	var fingerprints []string
	for _, name := range aliases {
		host := configuration.Hosts[name]
		key, getErr := service.Keys.GetPublicKey(ctx, host.Key.Reference)
		if getErr != nil {
			return Plan{}, fmt.Errorf("sync host %q: %w", name, getErr)
		}
		oldFingerprint := host.Key.Fingerprint
		host.Key.Fingerprint = key.Fingerprint
		host.Key.LastSyncedAt = service.now()
		host.Key.PublicKeyFile = managedPublicKeyPath(name)
		configuration.Hosts[name] = host
		rendered, renderErr := sshconfig.RenderHost(configuration.Defaults, host)
		if renderErr != nil {
			security.Wipe(key.Line)
			return Plan{}, renderErr
		}
		hostPath, _ := service.Repository.Layout.HostConfig(name)
		keyPath, _ := service.Repository.Layout.PublicKey(name)
		currentKey, _, keyExists, readErr := service.Repository.Read(keyPath, 1<<20)
		if readErr != nil {
			security.Wipe(key.Line)
			return Plan{}, readErr
		}
		keyChanged := !keyExists || oldFingerprint != key.Fingerprint || !bytes.Equal(currentKey, key.Line)
		security.Wipe(currentKey)
		if keyChanged {
			change, summary, changeErr := service.changeForWrite(keyPath, key.Line, 0o644)
			if changeErr != nil {
				security.Wipe(key.Line)
				return Plan{}, changeErr
			}
			changes = append(changes, change)
			summaries = append(summaries, summary)
		}
		security.Wipe(key.Line)
		change, summary, changeErr := service.changeForWrite(hostPath, rendered, 0o600)
		if changeErr != nil {
			return Plan{}, changeErr
		}
		changes = append(changes, change)
		summaries = append(summaries, summary)
		previews = append(previews, string(rendered))
		fingerprints = append(fingerprints, name+"="+host.Key.Fingerprint)
	}
	encoded, err := config.Encode(configuration)
	if err != nil {
		return Plan{}, err
	}
	configChange, configSummary, err := service.changeForWrite(service.Repository.Layout.ConfigFile, encoded, 0o600)
	if err != nil {
		return Plan{}, err
	}
	changes = append(changes, configChange)
	summaries = append(summaries, configSummary)
	return Plan{
		Operation: "sync", Alias: alias, Fingerprint: strings.Join(fingerprints, ", "),
		ConfigPreview: strings.Join(previews, "\n"), Changes: summaries, changes: changes, validateAliases: aliases,
	}, nil
}

func (service *Service) Apply(ctx context.Context, plan Plan) error {
	return service.Repository.ApplyAndCheck(plan.changes, func() error {
		if service.Runner == nil || len(plan.validateAliases) == 0 {
			return nil
		}
		for _, alias := range plan.validateAliases {
			if err := service.ValidateEffectiveConfig(ctx, alias); err != nil {
				return err
			}
		}
		return nil
	})
}

func (service *Service) Render(alias string) ([]byte, error) {
	host, err := service.Show(alias)
	if err != nil {
		return nil, err
	}
	configuration, err := service.load()
	if err != nil {
		return nil, err
	}
	return sshconfig.RenderHost(configuration.Defaults, host)
}

func (service *Service) Connect(ctx context.Context, alias string, stdin io.Reader, stdout, stderr io.Writer) error {
	if service.Runner == nil {
		return errors.New("OpenSSH runner is unavailable")
	}
	if err := service.ValidateEffectiveConfig(ctx, alias); err != nil {
		return fmt.Errorf("refusing to connect with an unverified SSH identity: %w", err)
	}
	return service.Runner.RunInteractive(ctx, process.Request{Tool: process.ToolOpenSSH, Args: []string{alias}}, stdin, stdout, stderr)
}

func (service *Service) ValidateEffectiveConfig(ctx context.Context, alias string) error {
	host, err := service.Show(alias)
	if err != nil {
		return err
	}
	if service.Runner == nil {
		return errors.New("OpenSSH runner is unavailable")
	}
	expectedIdentityFile, err := service.validateManagedPublicKey(alias, host)
	if err != nil {
		return err
	}
	result, err := service.Runner.Run(ctx, process.Request{Tool: process.ToolOpenSSH, Args: []string{"-G", alias}, OutputLimit: 2 << 20})
	if err != nil {
		return fmt.Errorf("OpenSSH rejected the effective configuration: %w", err)
	}
	defer security.Wipe(result.Stdout)
	defer security.Wipe(result.Stderr)
	values := parseSSHConfig(result.Stdout)
	if !containsValue(values["identitiesonly"], "yes") {
		return errors.New("effective SSH configuration does not enable IdentitiesOnly")
	}
	identityFiles := values["identityfile"]
	if len(identityFiles) != 1 {
		return errors.New("effective SSH configuration is not pinned to exactly one public-key file")
	}
	effectiveIdentityFile, err := ExpandUserPath(service.Repository.Layout.Home, strings.Trim(identityFiles[0], `"'`))
	if err != nil || filepath.Clean(effectiveIdentityFile) != filepath.Clean(expectedIdentityFile) {
		return errors.New("effective SSH IdentityFile is outside the selected host's managed path")
	}
	return nil
}

func (service *Service) validateManagedPublicKey(alias string, host domain.Host) (string, error) {
	keyPath, err := service.Repository.Layout.PublicKey(alias)
	if err != nil {
		return "", err
	}
	configuredPath, err := ExpandUserPath(service.Repository.Layout.Home, host.Key.PublicKeyFile)
	if err != nil || filepath.Clean(configuredPath) != filepath.Clean(keyPath) {
		return "", errors.New("configured public-key path is not the selected host's managed path")
	}
	keyData, _, exists, err := service.Repository.Read(keyPath, 1<<20)
	if err != nil {
		return "", fmt.Errorf("read managed public key: %w", err)
	}
	defer security.Wipe(keyData)
	if !exists {
		return "", errors.New("managed public-key file is missing; run opssh sync")
	}
	if err := sshconfig.ValidatePublicKey(keyData, host.Key.Fingerprint); err != nil {
		return "", errors.New("managed public-key file does not match the configured fingerprint; run opssh sync")
	}
	return keyPath, nil
}

func (service *Service) buildRenamePlan(
	configuration domain.Configuration,
	originalHost domain.Host,
	renamedHost domain.Host,
	replacementPublicLine []byte,
	dependentAliases []string,
) (Plan, error) {
	oldHostPath, err := service.Repository.Layout.HostConfig(originalHost.Alias)
	if err != nil {
		return Plan{}, err
	}
	oldKeyPath, err := service.Repository.Layout.PublicKey(originalHost.Alias)
	if err != nil {
		return Plan{}, err
	}
	newHostPath, err := service.Repository.Layout.HostConfig(renamedHost.Alias)
	if err != nil {
		return Plan{}, err
	}
	newKeyPath, err := service.Repository.Layout.PublicKey(renamedHost.Alias)
	if err != nil {
		return Plan{}, err
	}

	oldHostData, _, oldHostExists, err := service.Repository.Read(oldHostPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	defer security.Wipe(oldHostData)
	if oldHostExists && !sshconfig.IsManaged(oldHostData) {
		return Plan{}, ErrNotManaged
	}
	oldKeyData, _, oldKeyExists, err := service.Repository.Read(oldKeyPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	defer security.Wipe(oldKeyData)
	if oldKeyExists && sshconfig.ValidatePublicKey(oldKeyData, originalHost.Key.Fingerprint) != nil {
		return Plan{}, ErrNotManaged
	}

	newHostData, _, newHostExists, err := service.Repository.Read(newHostPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	defer security.Wipe(newHostData)
	newKeyData, _, newKeyExists, err := service.Repository.Read(newKeyPath, 1<<20)
	if err != nil {
		return Plan{}, err
	}
	defer security.Wipe(newKeyData)
	if newHostExists || newKeyExists {
		return Plan{}, ErrRenameTargetExists
	}

	publicLine := replacementPublicLine
	if publicLine == nil {
		if !oldKeyExists {
			return Plan{}, errors.New("managed public-key file is missing; synchronize the host before renaming it")
		}
		publicLine = oldKeyData
	}
	if err := sshconfig.ValidatePublicKey(publicLine, renamedHost.Key.Fingerprint); err != nil {
		return Plan{}, err
	}
	rendered, err := sshconfig.RenderHost(configuration.Defaults, renamedHost)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := config.Encode(configuration)
	if err != nil {
		return Plan{}, err
	}

	changes := []FileChange{
		{Path: newKeyPath, Data: bytes.Clone(publicLine), Mode: 0o644, ExpectedDigest: Digest(newKeyData, false)},
		{Path: newHostPath, Data: bytes.Clone(rendered), Mode: 0o600, ExpectedDigest: Digest(newHostData, false)},
	}
	summaries := []ChangeSummary{
		{Action: "create", Path: newKeyPath},
		{Action: "create", Path: newHostPath},
	}
	validateAliases := []string{renamedHost.Alias}
	for _, alias := range dependentAliases {
		dependent := configuration.Hosts[alias]
		dependentRendered, renderErr := sshconfig.RenderHost(configuration.Defaults, dependent)
		if renderErr != nil {
			return Plan{}, renderErr
		}
		dependentPath, pathErr := service.Repository.Layout.HostConfig(alias)
		if pathErr != nil {
			return Plan{}, pathErr
		}
		change, summary, changeErr := service.changeForWrite(dependentPath, dependentRendered, 0o600)
		if changeErr != nil {
			return Plan{}, changeErr
		}
		changes = append(changes, change)
		summaries = append(summaries, summary)
		validateAliases = append(validateAliases, alias)
	}
	configChange, configSummary, err := service.changeForWrite(service.Repository.Layout.ConfigFile, encoded, 0o600)
	if err != nil {
		return Plan{}, err
	}
	changes = append(changes, configChange)
	summaries = append(summaries, configSummary)
	if oldHostExists {
		changes = append(changes, FileChange{Path: oldHostPath, Delete: true, ExpectedDigest: Digest(oldHostData, true)})
		summaries = append(summaries, ChangeSummary{Action: "delete", Path: oldHostPath})
	}
	if oldKeyExists {
		changes = append(changes, FileChange{Path: oldKeyPath, Delete: true, ExpectedDigest: Digest(oldKeyData, true)})
		summaries = append(summaries, ChangeSummary{Action: "delete", Path: oldKeyPath})
	}
	return Plan{
		Operation: "rename", Alias: renamedHost.Alias, Fingerprint: renamedHost.Key.Fingerprint,
		ConfigPreview: string(rendered), Changes: summaries,
		Notices: []string{
			"External SSH references are not changed automatically.",
			"A Git remote name does not select an SSH Host block; the hostname inside its URL must use the new alias.",
			"Example: git remote set-url <remote> git@" + renamedHost.Alias + ":<group>/<repository>.git",
		},
		changes: changes, validateAliases: validateAliases,
	}, nil
}

func (service *Service) buildUpsertPlan(configuration domain.Configuration, host domain.Host, publicLine []byte, operation string) (Plan, error) {
	rendered, err := sshconfig.RenderHost(configuration.Defaults, host)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := config.Encode(configuration)
	if err != nil {
		return Plan{}, err
	}
	hostPath, _ := service.Repository.Layout.HostConfig(host.Alias)
	keyPath, _ := service.Repository.Layout.PublicKey(host.Alias)
	changes := make([]FileChange, 0, 4)
	summaries := make([]ChangeSummary, 0, 4)
	if publicLine != nil {
		if err := sshconfig.ValidatePublicKey(publicLine, host.Key.Fingerprint); err != nil {
			return Plan{}, err
		}
		change, summary, err := service.changeForWrite(keyPath, publicLine, 0o644)
		if err != nil {
			return Plan{}, err
		}
		changes = append(changes, change)
		summaries = append(summaries, summary)
	}
	change, summary, err := service.changeForWrite(hostPath, rendered, 0o600)
	if err != nil {
		return Plan{}, err
	}
	changes = append(changes, change)
	summaries = append(summaries, summary)
	change, summary, err = service.changeForWrite(service.Repository.Layout.ConfigFile, encoded, 0o600)
	if err != nil {
		return Plan{}, err
	}
	changes = append(changes, change)
	summaries = append(summaries, summary)

	mainData, _, mainExists, err := service.Repository.Read(service.Repository.Layout.SSHConfig, 8<<20)
	if err != nil {
		return Plan{}, err
	}
	updatedMain, includeChanged := sshconfig.AddInclude(mainData)
	if includeChanged {
		changes = append(changes, FileChange{
			Path: service.Repository.Layout.SSHConfig, Data: updatedMain, Mode: 0o600,
			ExpectedDigest: Digest(mainData, mainExists),
		})
		summaries = append(summaries, ChangeSummary{Action: actionFor(mainExists), Path: service.Repository.Layout.SSHConfig})
	}
	return Plan{
		Operation: operation, Alias: host.Alias, Fingerprint: host.Key.Fingerprint,
		ConfigPreview: string(rendered), IncludeChanged: includeChanged,
		Changes: summaries, changes: changes, validateAliases: []string{host.Alias},
	}, nil
}

func (service *Service) changeForWrite(path string, data []byte, mode os.FileMode) (FileChange, ChangeSummary, error) {
	current, _, exists, err := service.Repository.Read(path, 8<<20)
	if err != nil {
		return FileChange{}, ChangeSummary{}, err
	}
	return FileChange{Path: path, Data: bytes.Clone(data), Mode: mode, ExpectedDigest: Digest(current, exists)},
		ChangeSummary{Action: actionFor(exists), Path: path}, nil
}

func (service *Service) load() (domain.Configuration, error) {
	if service.Repository == nil {
		return domain.Configuration{}, errors.New("configuration repository is unavailable")
	}
	if err := service.Repository.Ensure(); err != nil {
		return domain.Configuration{}, err
	}
	return service.Repository.Load()
}

func (service *Service) now() time.Time {
	if service.Clock != nil {
		return service.Clock().UTC()
	}
	return time.Now().UTC()
}

func managedPublicKeyPath(alias string) string {
	return "~/.ssh/opssh/public_keys/" + alias + ".pub"
}

func actionFor(exists bool) string {
	if exists {
		return "update"
	}
	return "create"
}

func parseSSHConfig(data []byte) map[string][]string {
	values := make(map[string][]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		values[key] = append(values[key], strings.Join(fields[1:], " "))
	}
	return values
}

func containsValue(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func ConnectTimeoutSeconds(configuration domain.Configuration) string {
	seconds := int(configuration.Defaults.ConnectTimeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

func LayoutForHome(home string) (securefs.Layout, error) {
	return securefs.NewLayout(home)
}
