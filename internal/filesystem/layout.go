package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vlyl/opssh/internal/security"
)

type Layout struct {
	Home         string
	ConfigDir    string
	ConfigFile   string
	SSHDir       string
	SSHConfig    string
	SSHConfigDir string
	PublicKeyDir string
	StateDir     string
	TunnelDir    string
	LogDir       string
}

func NewLayout(home string) (Layout, error) {
	absHome, err := filepath.Abs(home)
	if err != nil || home == "" {
		return Layout{}, errors.New("invalid home directory")
	}
	absHome = filepath.Clean(absHome)
	return Layout{
		Home:         absHome,
		ConfigDir:    filepath.Join(absHome, ".config", "opssh"),
		ConfigFile:   filepath.Join(absHome, ".config", "opssh", "config.yaml"),
		SSHDir:       filepath.Join(absHome, ".ssh"),
		SSHConfig:    filepath.Join(absHome, ".ssh", "config"),
		SSHConfigDir: filepath.Join(absHome, ".ssh", "config.d"),
		PublicKeyDir: filepath.Join(absHome, ".ssh", "opssh", "public_keys"),
		StateDir:     filepath.Join(absHome, ".local", "state", "opssh"),
		TunnelDir:    filepath.Join(absHome, ".local", "state", "opssh", "tunnels"),
		LogDir:       filepath.Join(absHome, ".local", "state", "opssh", "logs"),
	}, nil
}

func (layout Layout) HostConfig(alias string) (string, error) {
	if err := security.ValidateAlias(alias); err != nil {
		return "", err
	}
	return filepath.Join(layout.SSHConfigDir, alias+".conf"), nil
}

func (layout Layout) PublicKey(alias string) (string, error) {
	if err := security.ValidateAlias(alias); err != nil {
		return "", err
	}
	return filepath.Join(layout.PublicKeyDir, alias+".pub"), nil
}

func (layout Layout) TunnelState(name string) (string, error) {
	if err := security.ValidateAlias(name); err != nil {
		return "", err
	}
	return filepath.Join(layout.TunnelDir, name+".json"), nil
}

func (layout Layout) TunnelLog(name string) (string, error) {
	if err := security.ValidateAlias(name); err != nil {
		return "", err
	}
	return filepath.Join(layout.LogDir, "tunnel-"+name+".log"), nil
}

func (layout Layout) Ensure() error {
	if err := ensureDirectoryChain(layout.Home, layout.Home, 0); err != nil {
		return err
	}
	paths := []struct {
		path    string
		mode    os.FileMode
		enforce bool
	}{
		{layout.ConfigDir, 0o700, true},
		{layout.SSHDir, 0o700, false},
		{layout.SSHConfigDir, 0o700, true},
		{filepath.Dir(layout.PublicKeyDir), 0o700, true},
		{layout.PublicKeyDir, 0o700, true},
		{layout.StateDir, 0o700, true},
		{layout.TunnelDir, 0o700, true},
		{layout.LogDir, 0o700, true},
	}
	for _, entry := range paths {
		if err := ensureDirectoryChain(layout.Home, entry.path, entry.mode); err != nil {
			return err
		}
		if entry.enforce {
			if err := os.Chmod(entry.path, entry.mode); err != nil {
				return fmt.Errorf("restrict managed directory permissions: %w", err)
			}
		}
	}
	return nil
}

func ensureDirectoryChain(root, target string, finalMode os.FileMode) error {
	if !pathWithin(root, target) {
		return ErrPathOutsideRoot
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect layout root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafePath
	}
	relative, _ := filepath.Rel(root, target)
	if relative == "." {
		return nil
	}
	current := root
	parts := splitRelativePath(relative)
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			mode := os.FileMode(0o700)
			if index == len(parts)-1 && finalMode != 0 {
				mode = finalMode
			}
			if err := os.Mkdir(current, mode); err != nil {
				return fmt.Errorf("create managed directory: %w", err)
			}
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect managed directory: %w", statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func splitRelativePath(path string) []string {
	var parts []string
	for path != "." && path != string(filepath.Separator) && path != "" {
		directory, file := filepath.Split(path)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		path = filepath.Clean(directory)
	}
	return parts
}
