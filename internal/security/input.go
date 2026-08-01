package security

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	aliasPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	usernamePattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,63}$`)
	dnsLabelPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{20,128}={0,2}$`)
)

var ErrUnsafeInput = errors.New("unsafe input")

func ValidateAlias(value string) error {
	if !aliasPattern.MatchString(value) {
		return safeValidationError("host alias")
	}
	return nil
}

func ValidateUsername(value string) error {
	if !usernamePattern.MatchString(value) {
		return safeValidationError("SSH username")
	}
	return nil
}

func ValidateIdentifier(field, value string, optional bool) error {
	if optional && value == "" {
		return nil
	}
	if !idPattern.MatchString(value) {
		return safeValidationError(field)
	}
	return nil
}

func ValidateHostname(value string) error {
	if value == "" || len(value) > 253 || hasUnsafeText(value) {
		return safeValidationError("hostname")
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") || strings.Count(value, "[") != 1 || strings.Count(value, "]") != 1 {
			return safeValidationError("hostname")
		}
		if net.ParseIP(value[1:len(value)-1]) == nil {
			return safeValidationError("hostname")
		}
		return nil
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	value = strings.TrimSuffix(value, ".")
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return safeValidationError("hostname")
		}
	}
	return nil
}

func ValidateFingerprint(value string, optional bool) error {
	if optional && value == "" {
		return nil
	}
	if !fingerprintPattern.MatchString(value) {
		return safeValidationError("public key fingerprint")
	}
	return nil
}

func ValidateDisplayText(field, value string, maxRunes int, optional bool) error {
	if optional && value == "" {
		return nil
	}
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes || hasUnsafeText(value) {
		return safeValidationError(field)
	}
	return nil
}

// ValidateConfigPathText validates serialized path text. Filesystem containment
// and symlink checks are deliberately enforced later by the layout adapter.
func ValidateConfigPathText(value string) error {
	if value == "" || len(value) > 4096 || hasUnsafeText(value) {
		return safeValidationError("path")
	}
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "~/") {
		return safeValidationError("path")
	}
	if strings.ContainsAny(value, "\"'`$%\\") {
		return safeValidationError("path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return safeValidationError("path")
		}
	}
	if strings.HasSuffix(value, "/") {
		return safeValidationError("path")
	}
	return nil
}

func hasUnsafeText(value string) bool {
	for _, r := range value {
		if r == '\x00' || r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func safeValidationError(field string) error {
	return fmt.Errorf("%w: invalid %s", ErrUnsafeInput, field)
}
