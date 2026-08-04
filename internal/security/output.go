package security

import "bytes"

const sensitiveScanWindow = 256

var sensitiveMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
	[]byte("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"),
	[]byte("PuTTY-User-Key-File-2:"),
	[]byte("PuTTY-User-Key-File-3:"),
}

func ContainsSensitiveMarker(data []byte) bool {
	for _, marker := range sensitiveMarkers {
		if bytes.Contains(data, marker) {
			return true
		}
	}
	// Cover algorithm-specific PEM blocks without trying to enumerate every
	// current or future key algorithm (for example ED25519 PRIVATE KEY).
	remaining := data
	for {
		index := bytes.Index(remaining, []byte("-----BEGIN "))
		if index < 0 {
			break
		}
		line := remaining[index:]
		if len(line) > sensitiveScanWindow {
			line = line[:sensitiveScanWindow]
		}
		if newline := bytes.IndexByte(line, '\n'); newline >= 0 {
			line = line[:newline]
		}
		if bytes.Contains(line, []byte("PRIVATE KEY")) {
			return true
		}
		remaining = remaining[index+len("-----BEGIN "):]
	}
	return false
}

func LongestSensitiveMarker() int {
	longest := sensitiveScanWindow
	for _, marker := range sensitiveMarkers {
		if len(marker) > longest {
			longest = len(marker)
		}
	}
	return longest
}

// Wipe clears a byte slice on a best-effort basis before it is released.
func Wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
