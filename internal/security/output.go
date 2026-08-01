package security

import "bytes"

var sensitiveMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
}

func ContainsSensitiveMarker(data []byte) bool {
	for _, marker := range sensitiveMarkers {
		if bytes.Contains(data, marker) {
			return true
		}
	}
	return false
}

func LongestSensitiveMarker() int {
	longest := 0
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
