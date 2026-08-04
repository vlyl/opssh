package security

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestGuardedWriterBlocksSplitMarkerBeforePersistence(t *testing.T) {
	t.Parallel()

	var destination bytes.Buffer
	writer := NewGuardedWriter(&destination, 1024)
	_, _ = writer.Write([]byte("safe line\n-----BEGIN OPENSSH PRI"))
	_, err := writer.Write([]byte("VATE KEY-----\nmaterial"))
	if !errors.Is(err, ErrSensitiveStream) {
		t.Fatalf("Write() error = %v, want ErrSensitiveStream", err)
	}
	if !writer.Rejected() {
		t.Fatal("writer did not retain rejected state")
	}
	if strings.Contains(destination.String(), "PRIVATE KEY") || strings.Contains(destination.String(), "material") {
		t.Fatalf("destination leaked rejected stream: %q", destination.String())
	}
}

func TestGuardedWriterBlocksUnknownAlgorithmPrivateKeyMarker(t *testing.T) {
	t.Parallel()

	var destination bytes.Buffer
	writer := NewGuardedWriter(&destination, 1024)
	_, _ = writer.Write([]byte("safe line\n-----BEGIN FUTURE-ALGORITHM PRI"))
	_, err := writer.Write([]byte("VATE KEY-----\nmaterial"))
	if !errors.Is(err, ErrSensitiveStream) || destination.Len() != 0 {
		t.Fatalf("Write() error = %v, persisted = %q", err, destination.String())
	}
}

func TestGuardedWriterReportsShortWrites(t *testing.T) {
	t.Parallel()

	writer := NewGuardedWriter(shortWriter{}, 1024)
	_, err := writer.Write([]byte(strings.Repeat("x", LongestSensitiveMarker()+8)))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() error = %v, want io.ErrShortWrite", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func TestGuardedWriterCapsPersistedBytes(t *testing.T) {
	t.Parallel()

	var destination bytes.Buffer
	writer := NewGuardedWriter(&destination, 8)
	_, _ = writer.Write([]byte(strings.Repeat("x", 128)))
	_ = writer.Flush()
	if destination.Len() != 8 {
		t.Fatalf("persisted bytes = %d, want 8", destination.Len())
	}
}
