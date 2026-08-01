package domain

import (
	"context"
	"time"
)

const CurrentConfigVersion = 1

type Provider string

const ProviderOnePassword Provider = "1password"

type ProxyType string

const (
	ProxyNone        ProxyType = "none"
	ProxySOCKS5      ProxyType = "socks5"
	ProxyHTTPConnect ProxyType = "http_connect"
	ProxyJump        ProxyType = "jump"
)

type HostKeyChecking string

const (
	HostKeyCheckingAsk    HostKeyChecking = "ask"
	HostKeyCheckingYes    HostKeyChecking = "yes"
	HostKeyCheckingAccept HostKeyChecking = "accept-new"
)

// Configuration contains public-key references and non-secret connection
// metadata only.
type Configuration struct {
	Version  int
	Defaults Defaults
	Hosts    map[string]Host
	Tunnels  map[string]Tunnel
}

type Defaults struct {
	IdentityAgent       string
	ConnectTimeout      time.Duration
	ServerAliveInterval int
	ServerAliveCountMax int
}

type Host struct {
	Alias    string
	Hostname string
	User     string
	Port     uint16
	Key      KeyBinding
	Proxy    Proxy
	Options  HostOptions
}

type KeyReference struct {
	Provider  Provider
	AccountID string
	VaultID   string
	ItemID    string
}

type KeyBinding struct {
	Reference     KeyReference
	Title         string
	Fingerprint   string
	PublicKeyFile string
	LastSyncedAt  time.Time
}

type PublicKeyMetadata struct {
	Reference   KeyReference
	Title       string
	VaultName   string
	AccountName string
	Fingerprint string
}

// AuthorizedKey is an OpenSSH public-key line validated by the SSH parser.
type AuthorizedKey struct {
	Line        []byte
	Algorithm   string
	Fingerprint string
}

type PublicKeyProvider interface {
	ListPublicKeys(ctx context.Context) ([]PublicKeyMetadata, error)
	GetPublicKey(ctx context.Context, ref KeyReference) (AuthorizedKey, error)
}

type Proxy struct {
	Type     ProxyType
	Host     string
	Port     uint16
	JumpHost string
}

type HostOptions struct {
	IdentitiesOnly        bool
	StrictHostKeyChecking HostKeyChecking
	ServerAliveInterval   int
	ServerAliveCountMax   int
}

type Tunnel struct {
	Name       string
	SSHHost    string
	LocalHost  string
	LocalPort  uint16
	RemoteHost string
	RemotePort uint16
	Reconnect  bool
}

type FindingLevel string

const (
	FindingPass FindingLevel = "PASS"
	FindingWarn FindingLevel = "WARN"
	FindingFail FindingLevel = "FAIL"
	FindingInfo FindingLevel = "INFO"
)

type DoctorFinding struct {
	Level   FindingLevel `json:"level"`
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Action  string       `json:"action,omitempty"`
}
