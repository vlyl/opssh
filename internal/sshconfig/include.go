package sshconfig

import (
	"bufio"
	"bytes"
	"strings"
)

const (
	IncludePattern       = "~/.ssh/config.d/*.conf"
	legacyIncludePattern = "~/.ssh/config.d/*"
	includeComment       = "# Added by opssh to load managed host fragments."
)

func HasInclude(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isInclude(line, IncludePattern) {
			return true
		}
	}
	return false
}

func AddInclude(data []byte) (updated []byte, changed bool) {
	if HasInclude(data) {
		// Remove any legacy broad include left next to the safe include. Broad
		// globs can cause backup and lock files to be parsed as SSH config.
		lines := strings.Split(string(data), "\n")
		filtered := lines[:0]
		for _, line := range lines {
			if isInclude(strings.TrimSpace(line), legacyIncludePattern) {
				changed = true
				continue
			}
			filtered = append(filtered, line)
		}
		if changed {
			return []byte(strings.Join(filtered, "\n")), true
		}
		return bytes.Clone(data), false
	}

	// Migrate the old broad glob in place instead of adding a second Include.
	lines := strings.Split(string(data), "\n")
	for index, line := range lines {
		if isInclude(strings.TrimSpace(line), legacyIncludePattern) {
			indentLength := len(line) - len(strings.TrimLeft(line, " \t"))
			lines[index] = line[:indentLength] + "Include " + IncludePattern
			return []byte(strings.Join(lines, "\n")), true
		}
	}
	updated = bytes.Clone(data)
	if len(updated) > 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	if len(updated) > 0 {
		updated = append(updated, '\n')
	}
	updated = append(updated, includeComment...)
	updated = append(updated, '\n')
	updated = append(updated, "Include "+IncludePattern...)
	updated = append(updated, '\n')
	return updated, true
}

func isInclude(line, pattern string) bool {
	fields := splitFields(line)
	return len(fields) == 2 && strings.EqualFold(fields[0], "Include") && fields[1] == pattern
}

func splitFields(line string) []string {
	fields := strings.Fields(line)
	for index := range fields {
		fields[index] = strings.Trim(fields[index], `"'`)
	}
	return fields
}
