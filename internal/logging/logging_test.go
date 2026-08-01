package logging

import (
	"strings"
	"testing"
)

func TestRedactNeverReturnsKeyMaterial(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----\nmaterial",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA example",
		"token=abcdef password: hunter2",
	} {
		redacted := Redact(value)
		if strings.Contains(redacted, "material") || strings.Contains(redacted, "AAAAC3") || strings.Contains(redacted, "abcdef") || strings.Contains(redacted, "hunter2") {
			t.Fatalf("Redact(%q) = %q", value, redacted)
		}
	}
}

func TestMaskReference(t *testing.T) {
	t.Parallel()

	if got := MaskReference("abcdefghijklmnop"); got != "abcd…mnop" {
		t.Fatalf("MaskReference() = %q", got)
	}
}
