package security

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDomainHasNoSecretBearingTypes(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	domainRoot := filepath.Join(root, "internal", "domain")
	for _, forbidden := range []string{
		"type " + "PrivateKey",
		"type " + "PrivateKeyPEM",
		"type " + "SecretKey",
		"type " + "KeyPassphrase",
		"type " + "RawItemJSON",
	} {
		assertSourceDoesNotContain(t, domainRoot, forbidden)
	}
}

func TestExternalProcessesStayBehindRunner(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytesContain(data, "os/exec") && !pathIsInside(path, filepath.Join(root, "internal", "process")) {
			t.Errorf("direct process execution import outside process boundary: %s", path)
		}
		for _, shellForm := range []string{"exec.Command(\"sh\"", "exec.CommandContext(ctx, \"sh\"", "exec.Command(\"bash\""} {
			if bytesContain(data, shellForm) {
				t.Errorf("shell command construction found in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source tree: %v", err)
	}
}

func assertSourceDoesNotContain(t *testing.T, root, forbidden string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytesContain(data, forbidden) {
			t.Errorf("forbidden domain identifier %q found in %s", forbidden, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk domain source: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func bytesContain(data []byte, text string) bool {
	return strings.Contains(string(data), text)
}

func pathIsInside(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
