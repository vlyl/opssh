package security

import (
	"errors"
	"io"
	"sync"
)

var ErrSensitiveStream = errors.New("stream output was rejected by the security policy")

// GuardedWriter scans streaming process output before writing it. It retains a
// short suffix so a marker split across writes cannot be partially persisted.
type GuardedWriter struct {
	mu          sync.Mutex
	destination io.Writer
	tail        []byte
	written     int64
	maxWrite    int64
	rejected    bool
	truncated   bool
}

func NewGuardedWriter(destination io.Writer, maxWrite int64) *GuardedWriter {
	return &GuardedWriter{destination: destination, maxWrite: maxWrite}
}

func (writer *GuardedWriter) Write(chunk []byte) (int, error) {
	written := len(chunk)
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.rejected {
		Wipe(chunk)
		return written, ErrSensitiveStream
	}
	window := make([]byte, 0, len(writer.tail)+len(chunk))
	window = append(window, writer.tail...)
	window = append(window, chunk...)
	if ContainsSensitiveMarker(window) {
		Wipe(window)
		Wipe(writer.tail)
		writer.tail = nil
		Wipe(chunk)
		writer.rejected = true
		return written, ErrSensitiveStream
	}
	keep := LongestSensitiveMarker() - 1
	if keep > len(window) {
		keep = len(window)
	}
	flush := window[:len(window)-keep]
	if err := writer.writeAllowed(flush); err != nil {
		Wipe(window)
		Wipe(chunk)
		return 0, err
	}
	Wipe(writer.tail)
	writer.tail = append(writer.tail[:0], window[len(window)-keep:]...)
	Wipe(window)
	Wipe(chunk)
	return written, nil
}

func (writer *GuardedWriter) Flush() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.rejected {
		Wipe(writer.tail)
		writer.tail = nil
		return ErrSensitiveStream
	}
	err := writer.writeAllowed(writer.tail)
	Wipe(writer.tail)
	writer.tail = nil
	return err
}

func (writer *GuardedWriter) Rejected() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.rejected
}

func (writer *GuardedWriter) writeAllowed(data []byte) error {
	if len(data) == 0 || writer.truncated {
		return nil
	}
	remaining := writer.maxWrite - writer.written
	if remaining <= 0 {
		writer.truncated = true
		return nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
		writer.truncated = true
	}
	count, err := writer.destination.Write(data)
	writer.written += int64(count)
	if err == nil && count != len(data) {
		return io.ErrShortWrite
	}
	return err
}
