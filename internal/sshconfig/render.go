package sshconfig

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"text/template"

	"github.com/vlyl/opssh/internal/config"
	"github.com/vlyl/opssh/internal/domain"
)

const ManagedMarker = "# Managed by opssh. Manual changes may be overwritten."

var hostTemplate = template.Must(template.New("host").Parse(`{{.Marker}}

Host {{.Alias}}
    HostName {{.Hostname}}
    User {{.User}}
    Port {{.Port}}
    IdentityAgent {{.IdentityAgent}}
    IdentityFile {{.IdentityFile}}
    IdentitiesOnly yes
    StrictHostKeyChecking {{.StrictHostKeyChecking}}
    ServerAliveInterval {{.ServerAliveInterval}}
    ServerAliveCountMax {{.ServerAliveCountMax}}
{{- if .ProxyCommand}}
    ProxyCommand {{.ProxyCommand}}
{{- end}}
{{- if .ProxyJump}}
    ProxyJump {{.ProxyJump}}
{{- end}}
`))

type hostTemplateData struct {
	Marker                string
	Alias                 string
	Hostname              string
	User                  string
	Port                  uint16
	IdentityAgent         string
	IdentityFile          string
	StrictHostKeyChecking domain.HostKeyChecking
	ServerAliveInterval   int
	ServerAliveCountMax   int
	ProxyCommand          string
	ProxyJump             string
}

func RenderHost(defaults domain.Defaults, host domain.Host) ([]byte, error) {
	configuration := domain.Configuration{
		Version: domain.CurrentConfigVersion, Defaults: defaults,
		Hosts: map[string]domain.Host{host.Alias: host}, Tunnels: map[string]domain.Tunnel{},
	}
	if err := config.Validate(configuration); err != nil {
		return nil, fmt.Errorf("validate host before rendering: %w", err)
	}
	if !strings.HasSuffix(strings.ToLower(host.Key.PublicKeyFile), ".pub") {
		return nil, errors.New("IdentityFile must point to a .pub public-key file")
	}

	hostname := strings.TrimPrefix(strings.TrimSuffix(host.Hostname, "]"), "[")
	data := hostTemplateData{
		Marker: ManagedMarker, Alias: host.Alias, Hostname: hostname, User: host.User, Port: host.Port,
		IdentityAgent: quote(defaults.IdentityAgent), IdentityFile: quote(host.Key.PublicKeyFile),
		StrictHostKeyChecking: host.Options.StrictHostKeyChecking,
		ServerAliveInterval:   host.Options.ServerAliveInterval, ServerAliveCountMax: host.Options.ServerAliveCountMax,
	}
	switch host.Proxy.Type {
	case domain.ProxySOCKS5:
		data.ProxyCommand = "nc -x " + net.JoinHostPort(unbracket(host.Proxy.Host), strconv.Itoa(int(host.Proxy.Port))) + " -X 5 %h %p"
	case domain.ProxyHTTPConnect:
		data.ProxyCommand = "nc -x " + net.JoinHostPort(unbracket(host.Proxy.Host), strconv.Itoa(int(host.Proxy.Port))) + " -X connect %h %p"
	case domain.ProxyJump:
		data.ProxyJump = host.Proxy.JumpHost
	case domain.ProxyNone:
	default:
		return nil, errors.New("unsupported proxy type")
	}

	var output bytes.Buffer
	if err := hostTemplate.Execute(&output, data); err != nil {
		return nil, fmt.Errorf("render SSH configuration: %w", err)
	}
	return output.Bytes(), nil
}

func IsManaged(data []byte) bool {
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	return string(bytes.TrimSpace(firstLine)) == ManagedMarker
}

func quote(value string) string {
	return `"` + value + `"`
}

func unbracket(value string) string {
	return strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
}
