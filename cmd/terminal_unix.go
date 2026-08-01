//go:build darwin || linux

package cmd

import "github.com/mattn/go-isatty"

func isTerminal(fileDescriptor uintptr) bool {
	return isatty.IsTerminal(fileDescriptor) || isatty.IsCygwinTerminal(fileDescriptor)
}
