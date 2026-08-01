package cmd

import (
	"io"
	"os"

	"github.com/vlyl/opssh/internal/app"
	"github.com/vlyl/opssh/internal/doctor"
	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/logging"
	"github.com/vlyl/opssh/internal/onepassword"
	"github.com/vlyl/opssh/internal/process"
	uiterm "github.com/vlyl/opssh/internal/tui"
	"github.com/vlyl/opssh/internal/tunnel"
)

type Runtime struct {
	Home     string
	In       io.Reader
	Out      io.Writer
	ErrOut   io.Writer
	Service  *app.Service
	Provider *onepassword.Provider
	Doctor   doctor.Doctor
	Tunnels  tunnel.Manager
	IsTTY    func() bool
	RunTUI   func() error
	NoColor  bool
}

func NewRuntime(home string, input io.Reader, output, errorOutput io.Writer) (*Runtime, error) {
	layout, err := securefs.NewLayout(home)
	if err != nil {
		return nil, err
	}
	repository, err := app.NewRepository(layout)
	if err != nil {
		return nil, err
	}
	auditLogger := logging.New(layout)
	runner := process.NewRunner(nil, auditLogger)
	provider := &onepassword.Provider{Runner: runner}
	service := &app.Service{Repository: repository, Keys: provider, Runner: runner}
	runtime := &Runtime{
		Home: home, In: input, Out: output, ErrOut: errorOutput,
		Service: service, Provider: provider,
		IsTTY: func() bool {
			inputFile, inputOK := input.(*os.File)
			outputFile, outputOK := output.(*os.File)
			return inputOK && outputOK && isTerminal(inputFile.Fd()) && isTerminal(outputFile.Fd())
		},
	}
	runtime.Doctor = doctor.Doctor{
		Service: service, Runner: runner, Resolver: process.PATHResolver{}, Provider: provider, Keys: provider,
	}
	runtime.Tunnels = tunnel.Manager{Service: service, Runner: runner}
	runtime.RunTUI = func() error {
		return uiterm.Run(uiterm.Dependencies{
			Input: input, Output: output, Service: service, Provider: provider,
			Doctor: runtime.Doctor, Tunnels: runtime.Tunnels, Runner: runner,
			NoColor: runtime.NoColor,
		})
	}
	return runtime, nil
}

func DefaultRuntime() (*Runtime, error) {
	home := os.Getenv("OPSSH_HOME")
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	return NewRuntime(home, os.Stdin, os.Stdout, os.Stderr)
}
