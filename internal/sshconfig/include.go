package sshconfig

import (
	"bufio"
	"bytes"
	"strings"
)

const (
	IncludePattern = "~/.ssh/config.d/*"
	includeComment = "# Added by opssh to load managed host fragments."
)

func HasInclude(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitFields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "Include") && fields[1] == IncludePattern {
			return true
		}
	}
	return false
}

func AddInclude(data []byte) (updated []byte, changed bool) {
	if HasInclude(data) {
		return bytes.Clone(data), false
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

func splitFields(line string) []string {
	fields := strings.Fields(line)
	for index := range fields {
		fields[index] = strings.Trim(fields[index], `"'`)
	}
	return fields
}
