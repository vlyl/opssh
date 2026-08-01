package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vlyl/opssh/internal/domain"
	"github.com/vlyl/opssh/internal/tunnel"
)

func newTunnelCommand(runtime *Runtime) *cobra.Command {
	command := &cobra.Command{Use: "tunnel", Short: "Manage SSH tunnels"}
	command.AddCommand(newTunnelStartCommand(runtime), newTunnelStopCommand(runtime), newTunnelStatusCommand(runtime), newTunnelListCommand(runtime))
	return command
}

func newTunnelStartCommand(runtime *Runtime) *cobra.Command {
	var foreground, background, noReconnect, yes bool
	command := &cobra.Command{
		Use: "start <name>", Short: "Start a configured SSH tunnel", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if foreground && background {
				return errors.New("--foreground and --background are mutually exclusive")
			}
			configured, err := configuredTunnel(runtime, args[0])
			if err != nil {
				return err
			}
			localIP := net.ParseIP(unbracket(configured.LocalHost))
			if localIP == nil {
				return errors.New("tunnel local host is not an IP address")
			}
			if !localIP.IsLoopback() {
				_, _ = fmt.Fprintf(command.ErrOrStderr(), "WARNING: %s exposes the tunnel beyond the loopback interface.\n", configured.LocalHost)
				approved, err := confirm(bufio.NewReader(command.InOrStdin()), command.OutOrStdout(), "Continue with a non-loopback listener?", yes)
				if err != nil || !approved {
					return err
				}
			}
			state, err := runtime.Tunnels.Start(command.Context(), args[0], tunnel.StartOptions{
				Foreground: foreground, NoReconnect: noReconnect,
				Input: command.InOrStdin(), Output: command.OutOrStdout(), Error: command.ErrOrStderr(),
			})
			if err != nil {
				return err
			}
			if !foreground {
				_, _ = fmt.Fprintf(command.OutOrStdout(), "Tunnel %s is running on %s (PID %d).\n", state.Name, state.LocalEndpoint, state.PID)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&foreground, "foreground", false, "run SSH in the foreground")
	command.Flags().BoolVar(&background, "background", false, "run under a detached opssh supervisor (default)")
	command.Flags().BoolVar(&noReconnect, "no-reconnect", false, "do not restart SSH after an unexpected exit")
	command.Flags().BoolVarP(&yes, "yes", "y", false, "confirm a non-loopback bind without prompting")
	return command
}

func newTunnelStopCommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{
		Use: "stop <name>", Short: "Gracefully stop a background tunnel", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if err := runtime.Tunnels.Stop(command.Context(), args[0]); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(command.OutOrStdout(), "Stopped tunnel %s.\n", args[0])
			return nil
		},
	}
}

func newTunnelStatusCommand(runtime *Runtime) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use: "status [name]", Short: "Show background tunnel status", Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			var names []string
			if len(args) == 1 {
				names = []string{args[0]}
			} else {
				configured, err := runtime.Tunnels.List()
				if err != nil {
					return err
				}
				for _, item := range configured {
					names = append(names, item.Name)
				}
			}
			statuses := make([]tunnel.Status, 0, len(names))
			for _, name := range names {
				status, err := runtime.Tunnels.Status(command.Context(), name)
				if err != nil {
					return err
				}
				statuses = append(statuses, status)
			}
			if asJSON {
				return json.NewEncoder(command.OutOrStdout()).Encode(statuses)
			}
			for _, status := range statuses {
				state := "stopped"
				if status.Running {
					state = "running"
				}
				_, _ = fmt.Fprintf(command.OutOrStdout(), "%s\t%s\t%s -> %s via %s\n", status.Name, state, status.Local, status.Remote, status.Host)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return command
}

func newTunnelListCommand(runtime *Runtime) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List configured tunnels", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			configured, err := runtime.Tunnels.List()
			if err != nil {
				return err
			}
			for _, item := range configured {
				_, _ = fmt.Fprintf(command.OutOrStdout(), "%s\t%s:%d -> %s:%d via %s\n", item.Name, item.LocalHost, item.LocalPort, item.RemoteHost, item.RemotePort, item.SSHHost)
			}
			return nil
		},
	}
}

func newTunnelSupervisorCommand(runtime *Runtime) *cobra.Command {
	var instance string
	var reconnect bool
	command := &cobra.Command{
		Use: "_tunnel-supervise <name>", Hidden: true, Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if strings.TrimSpace(instance) == "" {
				return errors.New("tunnel supervisor instance is required")
			}
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runtime.Tunnels.Supervise(ctx, args[0], instance, reconnect)
		},
	}
	command.Flags().StringVar(&instance, "instance", "", "internal tunnel instance identifier")
	command.Flags().BoolVar(&reconnect, "reconnect", false, "restart SSH after unexpected exits")
	return command
}

func configuredTunnel(runtime *Runtime, name string) (domain.Tunnel, error) {
	items, err := runtime.Tunnels.List()
	if err != nil {
		return domain.Tunnel{}, err
	}
	for _, item := range items {
		if item.Name == name {
			return item, nil
		}
	}
	return domain.Tunnel{}, tunnel.ErrTunnelMissing
}
