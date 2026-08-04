package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriterWritesAndBacksUp(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, _ := NewAtomicWriter(root)
	result, err := writer.Write(path, []byte("new"), WriteOptions{Mode: 0o600, Backup: true})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	assertFileContents(t, path, "new")
	assertFileContents(t, result.BackupPath, "old")
	if filepath.Base(filepath.Dir(result.BackupPath)) != ".opssh-backups" {
		t.Fatalf("backup path %q is not isolated", result.BackupPath)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, error = %v", info.Mode().Perm(), err)
	}
}

func TestLayoutEnsureMigratesLegacySSHBackups(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	legacyDir := filepath.Join(home, ".ssh", "config.d")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(legacyDir, "prod.conf.opssh.bak.1")
	if err := os.WriteFile(legacy, []byte("Host stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	layout, _ := NewLayout(home)
	if err := layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy backup still present: %v", err)
	}
	assertFileContents(t, filepath.Join(legacyDir, ".opssh-backups", filepath.Base(legacy)), "Host stale\n")
}

func TestAtomicWriterKeepsOldFileOnInterruption(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "host.conf")
	if err := os.WriteFile(path, []byte("old complete content"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, _ := NewAtomicWriter(root)
	writer.beforeRename = func() error { return errors.New("simulated interruption") }
	if _, err := writer.Write(path, []byte("partial replacement"), WriteOptions{Mode: 0o600}); err == nil {
		t.Fatal("Write() unexpectedly succeeded")
	}
	assertFileContents(t, path, "old complete content")
}

func TestAtomicWriterRejectsTraversalAndSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writer, _ := NewAtomicWriter(root)
	if _, err := writer.Write(outside, []byte("no"), WriteOptions{}); !errors.Is(err, ErrPathOutsideRoot) {
		t.Fatalf("outside write error = %v", err)
	}
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(link, []byte("replace"), WriteOptions{}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink write error = %v", err)
	}
	assertFileContents(t, target, "keep")
}

func TestLayoutRejectsUnsafeAlias(t *testing.T) {
	t.Parallel()

	layout, err := NewLayout(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"../../config", "foo/bar", "foo\nHost evil"} {
		if _, err := layout.HostConfig(alias); err == nil {
			t.Errorf("HostConfig(%q) unexpectedly succeeded", alias)
		}
		if _, err := layout.PublicKey(alias); err == nil {
			t.Errorf("PublicKey(%q) unexpectedly succeeded", alias)
		}
	}
}

func TestLayoutEnsureRejectsSymlinkedManagedDirectory(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".ssh", "opssh")); err != nil {
		t.Fatal(err)
	}
	layout, _ := NewLayout(home)
	if err := layout.Ensure(); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Ensure() error = %v, want ErrUnsafePath", err)
	}
}

func TestOpenAppendRestrictsExistingFilePermissions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "audit.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writer, _ := NewAtomicWriter(root)
	file, err := writer.OpenAppend(path, 0o600, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, error = %v", info.Mode().Perm(), err)
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}
