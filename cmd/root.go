package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var version = "dev"

func NewRootCommand(runtime *Runtime) *cobra.Command {
	root := &cobra.Command{
		Use:           "opssh",
		Short:         "Manage OpenSSH hosts backed by the 1Password SSH Agent",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if runtime.IsTTY != nil && runtime.IsTTY() && runtime.RunTUI != nil {
				return runtime.RunTUI()
			}
			return command.Help()
		},
	}
	root.SetIn(runtime.In)
	root.SetOut(runtime.Out)
	root.SetErr(runtime.ErrOut)
	root.PersistentFlags().Bool("verbose", false, "show additional non-sensitive operational detail")
	root.PersistentFlags().Bool("debug", false, "show debug detail without command output or key material")
	root.PersistentFlags().BoolVar(&runtime.NoColor, "no-color", false, "disable color output")

	root.AddCommand(
		newAddCommand(runtime), newEditCommand(runtime), newRemoveCommand(runtime),
		newListCommand(runtime), newShowCommand(runtime), newConnectCommand(runtime),
		newTestCommand(runtime), newSyncCommand(runtime), newDoctorCommand(runtime),
		newConfigCommand(runtime), newKeyCommand(runtime), newSecurityCommand(runtime),
		newTunnelCommand(runtime), newTUICommand(runtime),
		newTunnelSupervisorCommand(runtime),
	)
	root.AddCommand(newCompletionCommand(root))
	return root
}

func Execute() error {
	runtime, err := DefaultRuntime()
	if err != nil {
		return err
	}
	root := NewRootCommand(runtime)
	root.SetArgs(os.Args[1:])
	return root.ExecuteContext(context.Background())
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	completion := &cobra.Command{Use: "completion", Short: "Generate shell completion scripts"}
	completion.AddCommand(
		&cobra.Command{Use: "bash", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error { return root.GenBashCompletion(command.OutOrStdout()) }},
		&cobra.Command{Use: "zsh", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error { return root.GenZshCompletion(command.OutOrStdout()) }},
		&cobra.Command{Use: "fish", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
			return root.GenFishCompletion(command.OutOrStdout(), true)
		}},
	)
	return completion
}

func confirm(reader lineReader, output io.Writer, prompt string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if _, err := fmt.Fprintf(output, "%s [y/N]: ", prompt); err != nil {
		return false, err
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(trimInput(line))
	return answer == "y" || answer == "yes", nil
}

type lineReader interface {
	ReadString(delimiter byte) (string, error)
}
