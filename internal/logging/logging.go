package logging

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	securefs "github.com/vlyl/opssh/internal/filesystem"
	"github.com/vlyl/opssh/internal/process"
	"github.com/vlyl/opssh/internal/security"
)

var (
	publicKeyPattern  = regexp.MustCompile(`(?m)(?:ssh|ecdsa|sk|rsa)-[A-Za-z0-9@._+-]+\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?`)
	assignmentPattern = regexp.MustCompile(`(?i)(password|passphrase|token|secret)\s*[:=]\s*[^\s,;]+`)
)

type Event struct {
	Time        time.Time `json:"time"`
	Level       string    `json:"level"`
	Operation   string    `json:"operation"`
	Alias       string    `json:"alias,omitempty"`
	Outcome     string    `json:"outcome"`
	ErrorCode   string    `json:"error_code,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	ItemRef     string    `json:"item_ref,omitempty"`
	VaultRef    string    `json:"vault_ref,omitempty"`
}

type Logger struct {
	layout securefs.Layout
	mu     sync.Mutex
}

func New(layout securefs.Layout) *Logger {
	return &Logger{layout: layout}
}

func (logger *Logger) Record(event process.AuditEvent) {
	logger.Log(Event{
		Time: time.Now().UTC(), Level: "SECURITY", Operation: event.Tool.String(),
		Outcome: "blocked", ErrorCode: event.Code,
	})
}

func (logger *Logger) Log(event Event) {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	event.ItemRef = MaskReference(event.ItemRef)
	event.VaultRef = MaskReference(event.VaultRef)
	if security.ContainsSensitiveMarker([]byte(event.Alias + event.Operation + event.Outcome + event.ErrorCode + event.Fingerprint)) {
		return
	}
	if err := logger.layout.Ensure(); err != nil {
		return
	}
	writer, err := securefs.NewAtomicWriter(logger.layout.LogDir)
	if err != nil {
		return
	}
	path := filepath.Join(logger.layout.LogDir, "opssh.log")
	file, err := writer.OpenAppend(path, 0o600, 1<<20)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	_ = json.NewEncoder(file).Encode(event)
}

func Redact(text string) string {
	if security.ContainsSensitiveMarker([]byte(text)) {
		return "[REDACTED]"
	}
	text = publicKeyPattern.ReplaceAllString(text, "[REDACTED: public key]")
	text = assignmentPattern.ReplaceAllStringFunc(text, func(value string) string {
		name, _, _ := strings.Cut(value, "=")
		if name == value {
			name, _, _ = strings.Cut(value, ":")
		}
		return strings.TrimSpace(name) + "=[REDACTED]"
	})
	return text
}

func MaskReference(value string) string {
	if len(value) <= 8 {
		if value == "" {
			return ""
		}
		return "[masked]"
	}
	return value[:4] + "…" + value[len(value)-4:]
}
