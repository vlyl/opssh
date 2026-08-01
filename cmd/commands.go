package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/onepassword"
	"github.com/vlyl/opssh/internal/security"
	"github.com/vlyl/opssh/internal/sshconfig"
)

func newAddCommand(runtime *Runtime) *cobra.Command {
	var hostname, username, accountID, vaultID, itemID, keyTitle, proxyText string
	var port uint16
	var yes, testAfter bool
	command := &cobra.Command{
		Use:   "add [alias]",
		Short: "Add an SSH host and bind it to a 1Password public key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			reader := bufio.NewReader(command.InOrStdin())
			alias := ""
			if len(args) == 1 {
				alias = args[0]
			}
			var err error
			if alias, err = promptMissing(reader, command.OutOrStdout(), "Host alias", alias); err != nil {
				return err
			}
			if hostname, err = promptMissing(reader, command.OutOrStdout(), "Hostname or IP", hostname); err != nil {
				return err
			}
			if username, err = promptMissing(reader, command.OutOrStdout(), "SSH user", username); err != nil {
				return err
			}
			if !yes && !command.Flags().Changed("port") {
				portText, promptErr := promptDefault(reader, command.OutOrStdout(), "SSH port", "22")
				if promptErr != nil {
					return promptErr
				}
				parsedPort, parseErr := strconv.ParseUint(portText, 10, 16)
				if parseErr != nil || parsedPort == 0 {
					return errors.New("invalid SSH port")
				}
				port = uint16(parsedPort)
			} else if port == 0 {
				port = 22
			}
			if vaultID == "" || itemID == "" {
				metadata, selectErr := selectKey(command.Context(), runtime.Provider, reader, command.OutOrStdout(), "")
				if selectErr != nil {
					return selectErr
				}
				accountID, vaultID, itemID, keyTitle = metadata.Reference.AccountID, metadata.Reference.VaultID, metadata.Reference.ItemID, metadata.Title
			}
			if !yes && !command.Flags().Changed("proxy") {
				proxyText, err = promptDefault(reader, command.OutOrStdout(), "Proxy", "none")
				if err != nil {
					return err
				}
			}
			proxy, err := parseProxy(proxyText)
			if err != nil {
				return err
			}
			plan, err := runtime.Service.PrepareAdd(command.Context(), app.AddInput{
				Alias: alias, Hostname: hostname, User: username, Port: port,
				Reference: domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: accountID, VaultID: vaultID, ItemID: itemID},
				KeyTitle:  keyTitle, Proxy: proxy,
			})
			if err != nil {
				return err
			}
			printPlan(command.OutOrStdout(), plan)
			approved, err := confirm(reader, command.OutOrStdout(), "Apply these changes?", yes)
			if err != nil || !approved {
				if err == nil {
					_, _ = fmt.Fprintln(command.OutOrStdout(), "No changes made.")
				}
				return err
			}
			if err := runtime.Service.Apply(command.Context(), plan); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(), "Added %s (%s).\n", alias, plan.Fingerprint)
			if testAfter {
				printConnectionResult(command.OutOrStdout(), runtime.Service.TestConnection(command.Context(), alias, false))
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&hostname, "hostname", "", "SSH hostname or IP address")
	flags.StringVar(&username, "user", "", "SSH username")
	flags.Uint16Var(&port, "port", 22, "SSH port")
	flags.StringVar(&accountID, "op-account-id", "", "1Password account ID")
	flags.StringVar(&vaultID, "op-vault-id", "", "1Password Vault ID")
	flags.StringVar(&itemID, "op-item-id", "", "1Password item ID")
	flags.StringVar(&keyTitle, "key-title", "", "non-sensitive key title")
	flags.StringVar(&proxyText, "proxy", "none", "none, socks5://host:port, http://host:port, or jump://alias")
	flags.BoolVarP(&yes, "yes", "y", false, "apply without confirmation")
	flags.BoolVar(&testAfter, "test", false, "test the connection after adding")
	return command
}

func newEditCommand(runtime *Runtime) *cobra.Command {
	var newAlias, hostname, username, proxyText, accountID, vaultID, itemID, keyTitle string
	var port uint16
	var yes bool
	command := &cobra.Command{
		Use:   "edit <alias>",
		Short: "Edit a managed SSH host",
		Long: `Edit a managed SSH host and optionally rename its local SSH alias.

Git selects an SSH Host block from the hostname inside the remote URL, not from
the Git remote name. After a rename, external Git URLs must use the new alias.`,
		Example: `  opssh edit old-alias --alias new-alias --yes
  git remote set-url origin git@new-alias:group/repository.git`,
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			reader := bufio.NewReader(command.InOrStdin())
			input := app.EditInput{}
			changed := command.Flags().Changed("alias") || command.Flags().Changed("hostname") || command.Flags().Changed("user") || command.Flags().Changed("port") ||
				command.Flags().Changed("proxy") || accountID != "" || vaultID != "" || itemID != ""
			if !changed {
				current, err := runtime.Service.Show(args[0])
				if err != nil {
					return err
				}
				newAlias, err = promptDefault(reader, command.OutOrStdout(), "Host alias", current.Alias)
				if err != nil {
					return err
				}
				hostname, err = promptDefault(reader, command.OutOrStdout(), "Hostname or IP", current.Hostname)
				if err != nil {
					return err
				}
				username, err = promptDefault(reader, command.OutOrStdout(), "SSH user", current.User)
				if err != nil {
					return err
				}
				portText, err := promptDefault(reader, command.OutOrStdout(), "SSH port", strconv.Itoa(int(current.Port)))
				if err != nil {
					return err
				}
				parsedPort, err := strconv.ParseUint(portText, 10, 16)
				if err != nil || parsedPort == 0 {
					return errors.New("invalid SSH port")
				}
				port = uint16(parsedPort)
				proxyText, err = promptDefault(reader, command.OutOrStdout(), "Proxy", formatProxy(current.Proxy))
				if err != nil {
					return err
				}
				input.NewAlias, input.Hostname, input.User, input.Port = &newAlias, &hostname, &username, &port
				proxy, err := parseProxy(proxyText)
				if err != nil {
					return err
				}
				input.Proxy = &proxy
				_, _ = fmt.Fprint(command.OutOrStdout(), "Change bound public key? [y/N]: ")
				answer, readErr := reader.ReadString('\n')
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					return readErr
				}
				if strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes") {
					metadata, selectErr := selectKey(command.Context(), runtime.Provider, reader, command.OutOrStdout(), "")
					if selectErr != nil {
						return selectErr
					}
					reference := metadata.Reference
					input.Reference, input.KeyTitle = &reference, metadata.Title
				}
			}
			if command.Flags().Changed("alias") {
				input.NewAlias = &newAlias
			}
			if command.Flags().Changed("hostname") {
				input.Hostname = &hostname
			}
			if command.Flags().Changed("user") {
				input.User = &username
			}
			if command.Flags().Changed("port") {
				input.Port = &port
			}
			if command.Flags().Changed("proxy") {
				proxy, err := parseProxy(proxyText)
				if err != nil {
					return err
				}
				input.Proxy = &proxy
			}
			if vaultID != "" || itemID != "" || accountID != "" {
				if vaultID == "" || itemID == "" {
					return errors.New("--op-vault-id and --op-item-id must be provided together")
				}
				reference := domain.KeyReference{Provider: domain.ProviderOnePassword, AccountID: accountID, VaultID: vaultID, ItemID: itemID}
				input.Reference, input.KeyTitle = &reference, keyTitle
			}
			plan, err := runtime.Service.PrepareEdit(command.Context(), args[0], input)
			if err != nil {
				return err
			}
			printPlan(command.OutOrStdout(), plan)
			approved, err := confirm(reader, command.OutOrStdout(), "Apply these changes?", yes)
			if err != nil || !approved {
				return err
			}
			return runtime.Service.Apply(command.Context(), plan)
		},
	}
	flags := command.Flags()
	flags.StringVar(&newAlias, "alias", "", "new host alias")
	flags.StringVar(&hostname, "hostname", "", "new SSH hostname or IP")
	flags.StringVar(&username, "user", "", "new SSH username")
	flags.Uint16Var(&port, "port", 22, "new SSH port")
	flags.StringVar(&proxyText, "proxy", "none", "new proxy")
	flags.StringVar(&accountID, "op-account-id", "", "new 1Password account ID")
	flags.StringVar(&vaultID, "op-vault-id", "", "new 1Password Vault ID")
	flags.StringVar(&itemID, "op-item-id", "", "new 1Password item ID")
	flags.StringVar(&keyTitle, "key-title", "", "new non-sensitive key title")
	flags.BoolVarP(&yes, "yes", "y", false, "apply without confirmation")
	return command
}

func newRemoveCommand(runtime *Runtime) *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use: "remove <alias>", Short: "Remove an opssh-managed host", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			plan, err := runtime.Service.PrepareRemove(args[0])
			if err != nil {
				return err
			}
			printPlan(command.OutOrStdout(), plan)
			approved, err := confirm(bufio.NewReader(command.InOrStdin()), command.OutOrStdout(), "Remove only these opssh-managed files?", yes)
			if err != nil || !approved {
				return err
			}
			return runtime.Service.Apply(command.Context(), plan)
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "remove without confirmation")
	return command
}

func newListCommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List managed SSH hosts", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			hosts, err := runtime.Service.List()
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(writer, "ALIAS\tTARGET\tUSER\tKEY\tPROXY\tSTATUS")
			for _, host := range hosts {
				status := "ready"
				keyPath, _ := runtime.Service.Repository.Layout.PublicKey(host.Alias)
				data, _, exists, _ := runtime.Service.Repository.Read(keyPath, 1<<20)
				if !exists || sshconfig.ValidatePublicKey(data, host.Key.Fingerprint) != nil {
					status = "stale"
				}
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n", host.Alias, net.JoinHostPort(unbracket(host.Hostname), strconv.Itoa(int(host.Port))), host.User, host.Key.Fingerprint, host.Proxy.Type, status)
			}
			return writer.Flush()
		},
	}
}

func newShowCommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{
		Use: "show <alias>", Short: "Show non-sensitive host metadata", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			host, err := runtime.Service.Show(args[0])
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(), "Alias: %s\nTarget: %s\nUser: %s\nKey title: %s\nFingerprint: %s\nVault ID: %s\nItem ID: %s\nProxy: %s\n",
				host.Alias, net.JoinHostPort(unbracket(host.Hostname), strconv.Itoa(int(host.Port))), host.User, host.Key.Title,
				host.Key.Fingerprint, host.Key.Reference.VaultID, host.Key.Reference.ItemID, host.Proxy.Type)
			return nil
		},
	}
}

func newConnectCommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{
		Use: "connect <alias>", Short: "Connect with the system OpenSSH client", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			stdin, inputOK := command.InOrStdin().(*os.File)
			stdout, outputOK := command.OutOrStdout().(*os.File)
			stderr, errorOK := command.ErrOrStderr().(*os.File)
			if !inputOK || !outputOK || !errorOK {
				return errors.New("connect requires a real terminal")
			}
			return runtime.Service.Connect(command.Context(), args[0], stdin, stdout, stderr)
		},
	}
}

func newTestCommand(runtime *Runtime) *cobra.Command {
	var interactive, asJSON bool
	command := &cobra.Command{
		Use: "test <alias>", Short: "Test and diagnose an SSH connection", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			result := runtime.Service.TestConnection(command.Context(), args[0], interactive)
			if asJSON {
				return json.NewEncoder(command.OutOrStdout()).Encode(result)
			}
			printConnectionResult(command.OutOrStdout(), result)
			if !result.Success {
				return errors.New("SSH connection test failed")
			}
			return nil
		},
	}
	command.Flags().BoolVar(&interactive, "interactive", false, "allow interactive SSH authentication mechanisms")
	command.Flags().BoolVar(&asJSON, "json", false, "emit structured JSON")
	return command
}

func newSyncCommand(runtime *Runtime) *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use: "sync [alias]", Short: "Refresh public keys from 1Password", Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			alias := ""
			if len(args) == 1 {
				alias = args[0]
			}
			plan, err := runtime.Service.PrepareSync(command.Context(), alias)
			if err != nil {
				return err
			}
			printPlan(command.OutOrStdout(), plan)
			approved, err := confirm(bufio.NewReader(command.InOrStdin()), command.OutOrStdout(), "Apply synchronized public keys?", yes)
			if err != nil || !approved {
				return err
			}
			return runtime.Service.Apply(command.Context(), plan)
		},
	}
	command.Flags().BoolVarP(&yes, "yes", "y", false, "sync without confirmation")
	return command
}

func newDoctorCommand(runtime *Runtime) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use: "doctor", Short: "Check OpenSSH, 1Password Agent, and managed configuration", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			findings := runtime.Doctor.Run(command.Context())
			if asJSON {
				return json.NewEncoder(command.OutOrStdout()).Encode(findings)
			}
			writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
			for _, finding := range findings {
				_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\n", finding.Level, finding.Code, finding.Message)
				if finding.Action != "" {
					_, _ = fmt.Fprintf(writer, "\t\t%s\n", finding.Action)
				}
			}
			return writer.Flush()
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "emit structured JSON without sensitive output")
	return command
}

func newConfigCommand(runtime *Runtime) *cobra.Command {
	configCommand := &cobra.Command{Use: "config", Short: "Render and validate managed SSH configuration"}
	configCommand.AddCommand(
		&cobra.Command{Use: "render <alias>", Args: cobra.ExactArgs(1), RunE: func(command *cobra.Command, args []string) error {
			data, err := runtime.Service.Render(args[0])
			if err != nil {
				return err
			}
			_, err = command.OutOrStdout().Write(data)
			return err
		}},
		&cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
			hosts, err := runtime.Service.List()
			if err != nil {
				return err
			}
			for _, host := range hosts {
				if err := runtime.Service.ValidateEffectiveConfig(command.Context(), host.Alias); err != nil {
					return fmt.Errorf("host %s: %w", host.Alias, err)
				}
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(), "Validated %d managed host configurations.\n", len(hosts))
			return nil
		}},
	)
	return configCommand
}

func newKeyCommand(runtime *Runtime) *cobra.Command {
	var search string
	keyCommand := &cobra.Command{Use: "key", Short: "Browse 1Password SSH public-key metadata"}
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		keys, err := runtime.Provider.ListPublicKeys(command.Context())
		if err != nil {
			return err
		}
		for _, key := range filterKeys(keys, search) {
			_, _ = fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s\t%s\n", key.Title, key.AccountName, key.VaultName, key.Reference.ItemID)
		}
		return nil
	}}
	list.Flags().StringVar(&search, "search", "", "filter by title, account, or Vault")
	selectCommand := &cobra.Command{Use: "select", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		metadata, err := selectKey(command.Context(), runtime.Provider, bufio.NewReader(command.InOrStdin()), command.OutOrStdout(), search)
		if err != nil {
			return err
		}
		key, err := runtime.Provider.GetPublicKey(command.Context(), metadata.Reference)
		if err != nil {
			return err
		}
		defer security.Wipe(key.Line)
		_, _ = fmt.Fprintf(command.OutOrStdout(), "Selected %s\nAccount ID: %s\nVault ID: %s\nItem ID: %s\nFingerprint: %s\n",
			metadata.Title, metadata.Reference.AccountID, metadata.Reference.VaultID, metadata.Reference.ItemID, key.Fingerprint)
		return nil
	}}
	selectCommand.Flags().StringVar(&search, "search", "", "filter choices")
	keyCommand.AddCommand(list, selectCommand)
	return keyCommand
}

func newSecurityCommand(_ *Runtime) *cobra.Command {
	var asJSON bool
	securityCommand := &cobra.Command{Use: "security", Short: "Inspect opssh security boundaries"}
	audit := &cobra.Command{Use: "audit", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		findings := onepassword.AuditCommandCatalog()
		if asJSON {
			return json.NewEncoder(command.OutOrStdout()).Encode(findings)
		}
		unsafe := false
		for _, finding := range findings {
			status := "PASS"
			if !finding.Safe {
				status, unsafe = "FAIL", true
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(), "%s  %s: %s\n", status, finding.Command, finding.Reason)
		}
		if unsafe {
			return errors.New("1Password command catalog audit failed")
		}
		return nil
	}}
	audit.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	securityCommand.AddCommand(audit)
	return securityCommand
}

func promptMissing(reader lineReader, output io.Writer, label, value string) (string, error) {
	if value != "" {
		return value, nil
	}
	if _, err := fmt.Fprintf(output, "%s: ", label); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = trimInput(line)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}

func promptDefault(reader lineReader, output io.Writer, label, fallback string) (string, error) {
	if _, err := fmt.Fprintf(output, "%s [%s]: ", label, fallback); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func trimInput(value string) string {
	return strings.TrimSpace(value)
}

func selectKey(ctx context.Context, provider *onepassword.Provider, reader lineReader, output io.Writer, search string) (domain.PublicKeyMetadata, error) {
	keys, err := provider.ListPublicKeys(ctx)
	if err != nil {
		return domain.PublicKeyMetadata{}, err
	}
	keys = filterKeys(keys, search)
	if len(keys) == 0 {
		return domain.PublicKeyMetadata{}, errors.New("no matching 1Password SSH Key items")
	}
	for index, key := range keys {
		_, _ = fmt.Fprintf(output, "%d) %s — %s / %s\n", index+1, key.Title, key.AccountName, key.VaultName)
	}
	_, _ = fmt.Fprint(output, "Select key number: ")
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return domain.PublicKeyMetadata{}, err
	}
	selection, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || selection < 1 || selection > len(keys) {
		return domain.PublicKeyMetadata{}, errors.New("invalid key selection")
	}
	return keys[selection-1], nil
}

func filterKeys(keys []domain.PublicKeyMetadata, search string) []domain.PublicKeyMetadata {
	needle := strings.ToLower(strings.TrimSpace(search))
	if needle == "" {
		return keys
	}
	filtered := make([]domain.PublicKeyMetadata, 0, len(keys))
	for _, key := range keys {
		haystack := strings.ToLower(key.Title + " " + key.AccountName + " " + key.VaultName)
		if strings.Contains(haystack, needle) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

func parseProxy(value string) (domain.Proxy, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return domain.Proxy{Type: domain.ProxyNone}, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return domain.Proxy{}, errors.New("invalid proxy URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "jump":
		alias := parsed.Host
		if alias == "" {
			alias = strings.TrimPrefix(parsed.Path, "/")
		}
		if err := security.ValidateAlias(alias); err != nil {
			return domain.Proxy{}, err
		}
		return domain.Proxy{Type: domain.ProxyJump, JumpHost: alias}, nil
	case "socks5", "http", "http-connect":
		if parsed.Path != "" {
			return domain.Proxy{}, errors.New("proxy URL cannot contain a path")
		}
		host := parsed.Hostname()
		portText := parsed.Port()
		portValue, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || portValue == 0 {
			return domain.Proxy{}, errors.New("proxy URL requires a valid port")
		}
		if err := security.ValidateHostname(host); err != nil {
			return domain.Proxy{}, err
		}
		proxyType := domain.ProxySOCKS5
		if scheme != "socks5" {
			proxyType = domain.ProxyHTTPConnect
		}
		return domain.Proxy{Type: proxyType, Host: host, Port: uint16(portValue)}, nil
	default:
		return domain.Proxy{}, errors.New("proxy scheme must be socks5, http, http-connect, or jump")
	}
}

func formatProxy(proxy domain.Proxy) string {
	switch proxy.Type {
	case domain.ProxyNone:
		return "none"
	case domain.ProxySOCKS5:
		return "socks5://" + net.JoinHostPort(unbracket(proxy.Host), strconv.Itoa(int(proxy.Port)))
	case domain.ProxyHTTPConnect:
		return "http://" + net.JoinHostPort(unbracket(proxy.Host), strconv.Itoa(int(proxy.Port)))
	case domain.ProxyJump:
		return "jump://" + proxy.JumpHost
	default:
		return "none"
	}
}

func newTUICommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{Use: "tui", Short: "Open the interactive terminal UI", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		if runtime.RunTUI == nil {
			return errors.New("TUI frontend is unavailable")
		}
		return runtime.RunTUI()
	}}
}

func printPlan(output io.Writer, plan app.Plan) {
	_, _ = fmt.Fprintf(output, "Operation: %s %s\nFingerprint: %s\n", plan.Operation, plan.Alias, plan.Fingerprint)
	for _, change := range plan.Changes {
		_, _ = fmt.Fprintf(output, "  %s %s\n", change.Action, change.Path)
	}
	if plan.ConfigPreview != "" {
		_, _ = fmt.Fprintf(output, "\nSSH configuration preview:\n%s", plan.ConfigPreview)
	}
	if len(plan.Notices) > 0 {
		_, _ = fmt.Fprintln(output, "\nNotes:")
		for _, notice := range plan.Notices {
			_, _ = fmt.Fprintf(output, "  - %s\n", notice)
		}
	}
}

func printConnectionResult(output io.Writer, result app.ConnectionTestResult) {
	status := "FAIL"
	if result.Success {
		status = "PASS"
	}
	_, _ = fmt.Fprintf(output, "%s: %s\n", status, result.Message)
	for _, action := range result.Actions {
		_, _ = fmt.Fprintf(output, "  %s\n", action)
	}
}

func unbracket(value string) string {
	return strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
}
