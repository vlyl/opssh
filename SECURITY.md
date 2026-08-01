# Security policy

## Supported versions

Security fixes are provided for the latest released minor version. Development builds from the default branch are not a substitute for a reviewed release.

## Reporting a vulnerability

Please use the repository's private GitHub Security Advisory workflow. Do not include real private keys, passwords, tokens, production host inventories, or complete 1Password item output in a report. A synthetic reproducer is preferred.

If private reporting is unavailable, open a minimal issue asking maintainers to establish a private channel without disclosing the vulnerability.

## Non-negotiable private-key boundary

opssh does not:

- read SSH private keys from 1Password or the local filesystem;
- export or store SSH private keys;
- place SSH private keys in memory caches, logs, errors, stdout, stderr, argv, environment variables, temporary files, or the clipboard;
- request complete 1Password SSH Key item JSON;
- pass a private-key file to OpenSSH;
- add identities to an SSH Agent;
- create, edit, or delete 1Password items.

The only local key material written by opssh is an OpenSSH `.pub` public-key line. Authentication signatures are requested by OpenSSH from the configured 1Password SSH Agent.

Public keys are not secrets, but full public-key lines are still excluded from logs and normal diagnostics.

## 1Password command boundary

All `op` commands are defined in one typed catalog. Supported operations are limited to:

- CLI version inspection;
- account and Vault metadata listing;
- SSH Key item metadata listing;
- retrieval of one field with `--fields "label=public key"`.

`--reveal`, OTP/share flags, `op read`, item mutation, document retrieval, archive inclusion, and unscoped item detail retrieval are forbidden. Unknown 1Password CLI major versions fail closed.

Run:

```bash
opssh security audit
```

The test suite also scans source code for process execution outside the unified Runner and for secret-bearing domain type names.

## External process boundary

Production process creation is confined to `internal/process` and uses `exec.CommandContext` with an executable allowlist and independent argv entries. opssh never builds a Shell command or invokes `sh -c`.

Captured output is bounded. A streaming detector checks these markers, including markers split across read boundaries:

```text
-----BEGIN PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
```

On detection, opssh cancels the process, wipes controllable buffers, returns a fixed error, and records only a content-free security event.

Interactive SSH attaches directly to terminal file descriptors. opssh does not read, buffer, or log the interactive stream. Tunnel output is different because it is logged: it passes through a streaming guard before any bytes are persisted.

Allowed external programs are:

- `op` for the public metadata operations above;
- `ssh` for configuration expansion, tests, connections, and tunnels;
- `ssh-add -L` for explicit Agent public-key inspection;
- `nc` as a fixed OpenSSH ProxyCommand dependency;
- `ps` for PID/start-time/argv validation of tunnel supervisors;
- the current `opssh` executable for the hidden tunnel supervisor.

## Input and configuration integrity

- Host and tunnel aliases use a conservative alphanumeric/`._-` grammar and cannot begin with punctuation.
- Usernames, hostnames, IP addresses, ports, IDs, proxy endpoints, enums, and paths have dedicated validators.
- Control characters, newlines, traversal components, OpenSSH path tokens, Shell substitutions, and unsafe quoting are rejected where applicable.
- YAML parsing rejects unknown fields, multiple documents, oversized input, and private-key markers.
- Every managed Host has `IdentitiesOnly yes` and exactly one `.pub` `IdentityFile`.
- Arbitrary SSH options and free-form ProxyCommand strings are not accepted.

## Filesystem boundary

Default permissions are:

```text
managed directories     0700
configuration/state     0600
SSH fragments           0600
public keys              0644 (inside a 0700 parent)
logs                     0600
```

Writes are restricted to configured managed roots. Before mutation, opssh checks containment, file type, and symlinks. It uses a no-follow lock file, same-directory temporary file, target permissions, `fsync`, atomic rename, and directory `fsync`. Existing files are backed up and multi-file operations retain snapshots for rollback after failure or failed `ssh -G` validation.

Removal is limited to alias-derived opssh paths. SSH fragments must have the managed marker, and public-key files must match the configured fingerprint.

## Logging and diagnostics

Logs are structured and only admit operation names, aliases, result codes, fingerprints, and masked item/Vault references. They exclude:

- complete public keys;
- external command output;
- complete item output;
- passwords, passphrases, tokens, and environment dumps;
- interactive SSH session content.

Debug mode does not weaken these rules. Logs are bounded, rotated, mode `0600`, and stored under `~/.local/state/opssh/logs/`.

Doctor JSON output uses fixed findings and non-sensitive actions. It does not embed raw `op`, Agent, or SSH output.

## Tunnel security

Tunnel listeners are loopback-only by default. Non-loopback binds require a visible warning and confirmation. Background state contains a random instance ID, PID, process start value, safe command summary, Host alias, and endpoints. Stop validates all available identity fields to reduce PID-reuse risk before sending SIGTERM.

Automatic reconnect is opt-in through tunnel configuration and can be disabled with `--no-reconnect`.

## Threat model and residual risk

The controls are intended to resist malicious configuration values, command/config injection, path traversal, symlink replacement, concurrent writers, oversized or malformed external output, accidental key rotation, Agent identity ordering, and PID reuse.

opssh cannot protect against:

- a compromised OS, user account, Go runtime, OpenSSH binary, 1Password installation, or `op` binary;
- local malware with access to the Agent socket or terminal;
- an authorized process requesting signatures from the Agent;
- incorrect remote `authorized_keys`, sshd policy, DNS, host keys, or server authorization;
- disclosure of host inventories, usernames, public keys, Vault/item identifiers, and network topology as metadata;
- a malicious SSH server displaying sensitive data in an interactive session;
- access introduced by proxies or port forwarding;
- replacement of trusted executables through a compromised `PATH` before execution.

Use filesystem permissions, trusted executable paths, 1Password Agent approval controls, host-key verification, least-privilege remote accounts, and loopback tunnel binds as additional layers.
