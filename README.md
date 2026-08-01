# opssh

`opssh` is a Go CLI and terminal UI for managing OpenSSH hosts whose signing identities remain in the 1Password SSH Agent. It keeps server metadata, public-key bindings, proxy settings, and local tunnels together without importing or exporting SSH private keys.

> Security boundary: opssh only handles SSH public keys, fingerprints, 1Password item/Vault/account identifiers, Agent socket paths, and non-secret connection settings. SSH signatures are produced by the 1Password SSH Agent.

This is a security boundary, not a claim that the complete system is absolutely secure. Read [SECURITY.md](SECURITY.md) before using opssh in a sensitive environment.

## Why it exists

An SSH Agent may expose many identities. Without an explicit identity selection, OpenSSH can offer them in sequence until a server disconnects with `Too many authentication failures`.

opssh generates one fragment per Host:

```sshconfig
Host prod-web
    HostName 192.0.2.10
    User root
    Port 22
    IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    IdentityFile "~/.ssh/opssh/public_keys/prod-web.pub"
    IdentitiesOnly yes
```

The `IdentityFile` is a `.pub` public-key file. OpenSSH uses it to select the matching identity in the Agent; the corresponding private key is not present on disk and is not passed to opssh.

## Security model

opssh:

- never requests a complete 1Password SSH Key item;
- obtains the public key through an explicit `--fields "label=public key"` selector;
- never uses `--reveal`, `op read`, or a 1Password write command;
- never reads default local identity files;
- never invokes a command that adds identities to an Agent;
- executes external programs with independent argv entries, never `sh -c`;
- bounds captured output and rejects common private-key PEM markers;
- refuses unsafe aliases, newlines, path traversal, symlink targets, and unknown YAML fields;
- writes managed files with locks, backups, `fsync`, and atomic rename;
- has no telemetry, crash upload, analytics, or automatic updater.

Residual risks include a compromised local machine, a process that can already access the Agent socket, incorrect remote `authorized_keys`, compromised proxy infrastructure, and network access exposed by tunnels. Host inventories and public keys are not secrets, but may still be sensitive metadata.

Run the built-in static command-catalog check with:

```bash
opssh security audit
```

## Requirements

- macOS or Linux
- Go 1.26 or newer when building from source
- OpenSSH client
- 1Password desktop app and 1Password CLI v2
- 1Password SSH Agent enabled
- `nc` when using SOCKS5 or HTTP CONNECT proxy configurations

Configure and test the 1Password SSH Agent first. The default sockets are:

- macOS: `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`
- Linux: `~/.1password/agent.sock`

The Linux path can be changed in `defaults.identity_agent`.

## Install

Build from source:

```bash
git clone https://github.com/vlyl/opssh.git
cd opssh
make build
install -m 0755 bin/opssh ~/.local/bin/opssh
```

For releases, download the archive for `darwin/arm64`, `darwin/amd64`, `linux/arm64`, or `linux/amd64`, verify it against `checksums.txt`, and place `opssh` on `PATH`.

The repository also contains an illustrative [Homebrew formula](homebrew/opssh.rb.example). Replace its example checksums with those from a real release.

## First use

Launch the TUI:

```bash
opssh
```

In a non-TTY environment, running `opssh` prints CLI help instead.

Add a host interactively:

```bash
opssh add
```

Or use explicit non-interactive metadata:

```bash
opssh add prod-web \
  --hostname 192.0.2.10 \
  --user root \
  --port 22 \
  --op-account-id account-id \
  --op-vault-id vault-id \
  --op-item-id item-id \
  --proxy socks5://127.0.0.1:7890 \
  --yes
```

Rename a managed host alias while preserving its selected 1Password public key:

```bash
opssh edit old-alias --alias new-alias --yes
```

The rename preview includes the new and removed managed paths. Applying it atomically migrates the host fragment and `.pub` file and updates internal ProxyJump and Tunnel references. External references such as Git remote URLs must be updated separately to use the new alias:

```bash
git remote set-url <remote> git@new-alias:<group>/<repository>.git
```

The name passed to `git fetch` only selects a Git remote entry. Git then reads that entry's URL and passes its hostname to SSH. For example:

```text
git fetch work
  → remote.work.url = git@gitlab-work:example-group/example-repo.git
  → ssh gitlab-work
  → Host gitlab-work
  → HostName gitlab.example.com, Port 2222, selected IdentityFile
```

If the URL contains `git@gitlab.example.com` instead, `Host gitlab-work` is not selected, even when the Git remote itself is named `work`.

Before applying an interactive operation, opssh shows every path it will create, update, or delete plus the rendered SSH fragment. The public-key body is not displayed in the preview.

On the first add, opssh proposes adding:

```sshconfig
Include ~/.ssh/config.d/*
```

to `~/.ssh/config`. Existing content and comments are preserved, the old file is backed up, and repeated runs do not add duplicate Include directives.

## CLI

```text
opssh add [alias]
opssh edit <alias>
opssh remove <alias>
opssh list
opssh show <alias>
opssh connect <alias>
opssh test <alias> [--interactive] [--json]
opssh sync [alias]
opssh doctor [--json]

opssh config render <alias>
opssh config validate
opssh key list [--search text]
opssh key select [--search text]
opssh security audit [--json]

opssh tunnel start <name> [--foreground|--background] [--no-reconnect]
opssh tunnel stop <name>
opssh tunnel status [name] [--json]
opssh tunnel list

opssh completion bash|zsh|fish
```

`opssh connect` launches the system `ssh <alias>` with the current terminal attached. This allows normal host-key confirmation, Agent authorization windows, and interactive sessions. opssh does not read or log the session stream.

## TUI

The TUI includes:

- searchable Host list;
- Add and Edit wizards, including host-alias rename as the first Edit field;
- 1Password public-key and proxy pickers;
- configuration preview and deletion confirmation;
- connection testing and error detail;
- Doctor and Tunnel tables;
- loading spinners, cancelable operations, small-terminal fallback, Ctrl+C, and `NO_COLOR` support.

Press `:` from the host, Doctor, Tunnel, or error screen to open the built-in command input. It accepts `doctor`, `config validate`, `list`, `tunnel list`, `retry`, `cancel`, and `quit` (an optional `opssh ` prefix is accepted). Arbitrary shell commands are deliberately not executed.

An error screen shows the operation, a redacted cause chain, and relevant diagnostic commands. Press `r` to retry, `Enter` or `:` to open the command input, or `Esc` to cancel the failed operation and return to the host list. `Esc` also cancels an operation while its loading spinner is active; a late result from that canceled operation is ignored.

```text
┌─ opssh hosts ───────────────────────────────────────────────┐
│ Alias       Target               Key          Proxy   Status│
│ prod-web    192.0.2.10:22        SHA256:...   socks5  ready │
└──────────────────────────────────────────────────────────────┘
Enter Connect   a Add   e Edit   t Tunnel   s Sync
d Delete        x Test  D Doctor / Search   : Command   q Quit
```

Screenshot placeholder: add an asciinema recording or PNG under `docs/` when publishing a release.

## Proxy examples

SOCKS5:

```bash
opssh edit prod-web --proxy socks5://127.0.0.1:7890 --yes
```

HTTP CONNECT:

```bash
opssh edit prod-web --proxy http://127.0.0.1:8080 --yes
```

ProxyJump:

```bash
opssh edit prod-web --proxy jump://bastion --yes
```

Proxy values are parsed into protocol, validated host, and numeric port fields. Free-form ProxyCommand arguments are not accepted. HTTP CONNECT and SOCKS flags require a compatible `nc`; `opssh doctor` checks its availability.

## Tunnels

Tunnels are declared in `config.yaml`:

```yaml
tunnels:
  prod-postgres:
    ssh_host: prod-web
    local_host: 127.0.0.1
    local_port: 15432
    remote_host: 127.0.0.1
    remote_port: 5432
    reconnect: false
```

Start and inspect one:

```bash
opssh tunnel start prod-postgres
opssh tunnel status prod-postgres
opssh tunnel stop prod-postgres
```

Background mode uses a detached opssh supervisor. Its state records a random instance ID, PID, process start value, command summary, Host alias, and endpoints. Stop verifies all process identity fields before signaling it. Tunnel logs are bounded, rotated, and protected by the same sensitive-output marker scanner.

Listeners default to loopback. A non-loopback address displays a security warning and requires confirmation; the TUI declines such starts and directs the user to the explicit CLI flow.

## File locations

```text
~/.config/opssh/config.yaml
~/.ssh/config
~/.ssh/config.d/<alias>.conf
~/.ssh/opssh/public_keys/<alias>.pub
~/.local/state/opssh/tunnels/<name>.json
~/.local/state/opssh/logs/
```

Configuration and state files use mode `0600`; managed directories use `0700`; public-key files use `0644` under a `0700` parent.

Set `OPSSH_HOME` only for isolated testing or an intentionally separate home layout. Tests always use temporary directories and fake executables.

## Troubleshooting

Start with:

```bash
opssh doctor
opssh config validate
opssh config render prod-web
opssh test prod-web
```

For `Too many authentication failures`, confirm the effective Host has exactly one `.pub` `IdentityFile` and `IdentitiesOnly yes`.

For `Permission denied (publickey)`, check:

- the server has the corresponding public key in `authorized_keys`;
- the configured SSH username is correct;
- 1Password is unlocked and the SSH Agent is enabled;
- the selected identity is allowed in Agent settings;
- the key has not rotated;
- the server accepts the key algorithm.

opssh deliberately does not modify remote `authorized_keys`.

## Uninstall and data removal

Remove the executable from the location where it was installed. To remove data, first review these directories and delete them manually:

```text
~/.config/opssh/
~/.ssh/config.d/          # remove only files whose first line says Managed by opssh
~/.ssh/opssh/
~/.local/state/opssh/
```

Then remove the opssh Include line from `~/.ssh/config` if no other configuration uses it. Backups have names containing `.opssh.bak.` and can be retained or removed after inspection.

Uninstalling opssh never changes 1Password items or remote servers.

## Development

```bash
make build
make test
make race
make lint
make security-audit
make snapshot
```

Tests use fake `op`, `ssh`, and `ssh-add` executables, temporary homes, security regression fixtures, transaction interruption tests, Golden SSH configuration, and race detection. No real 1Password account or developer SSH directory is required.

## License

MIT. See [LICENSE](LICENSE).
