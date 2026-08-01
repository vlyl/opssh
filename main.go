package main

import (
	"fmt"
	"os"

	"github.com/vlyl/opssh/cmd"
	"github.com/vlyl/opssh/internal/logging"
)

func main() {
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, logging.Redact(err.Error()))
		os.Exit(1)
	}
}
