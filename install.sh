#!/bin/sh

set -eu

REPOSITORY="${OPSSH_REPOSITORY:-vlyl/opssh}"
VERSION="${OPSSH_VERSION:-latest}"
INSTALL_DIR="${OPSSH_INSTALL_DIR:-${HOME:-}/.local/bin}"

fail() {
	printf 'opssh installer: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "$REPOSITORY" in
	*/*) ;;
	*) fail "OPSSH_REPOSITORY must use owner/repository format" ;;
esac

[ -n "$INSTALL_DIR" ] || fail "HOME is unset; set OPSSH_INSTALL_DIR explicitly"

for command_name in curl tar awk mktemp install uname; do
	require_command "$command_name"
done

case "$(uname -s)" in
	Darwin) operating_system="darwin" ;;
	Linux) operating_system="linux" ;;
	*) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
	x86_64 | amd64) architecture="amd64" ;;
	arm64 | aarch64) architecture="arm64" ;;
	*) fail "unsupported CPU architecture: $(uname -m)" ;;
esac

release_base="https://github.com/${REPOSITORY}/releases"
if [ "$VERSION" = "latest" ]; then
	printf 'Resolving the latest opssh release...\n'
	latest_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "${release_base}/latest")" ||
		fail "could not resolve the latest GitHub release"
	release_tag="${latest_url##*/}"
else
	release_tag="$VERSION"
	case "$release_tag" in
		v*) ;;
		*) release_tag="v${release_tag}" ;;
	esac
fi

release_version="${release_tag#v}"
case "$release_version" in
	"" | *[!0-9A-Za-z.-]*) fail "invalid release version: $release_tag" ;;
esac

archive="opssh_${release_version}_${operating_system}_${architecture}.tar.gz"
download_base="${release_base}/download/${release_tag}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/opssh-install.XXXXXX")"
staged_binary=""

cleanup() {
	if [ -n "$staged_binary" ] && [ -e "$staged_binary" ]; then
		rm -f "$staged_binary"
	fi
	rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

printf 'Downloading opssh %s for %s/%s...\n' "$release_version" "$operating_system" "$architecture"
curl -fsSL "${download_base}/${archive}" -o "${temporary_directory}/${archive}" ||
	fail "could not download ${archive}"
curl -fsSL "${download_base}/checksums.txt" -o "${temporary_directory}/checksums.txt" ||
	fail "could not download checksums.txt"

expected_checksum="$(awk -v archive="$archive" '$2 == archive { print $1; exit }' "${temporary_directory}/checksums.txt")"
[ -n "$expected_checksum" ] || fail "checksums.txt does not contain ${archive}"

if command -v sha256sum >/dev/null 2>&1; then
	actual_checksum="$(sha256sum "${temporary_directory}/${archive}" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
	actual_checksum="$(shasum -a 256 "${temporary_directory}/${archive}" | awk '{ print $1 }')"
else
	fail "sha256sum or shasum is required to verify the download"
fi

[ "$actual_checksum" = "$expected_checksum" ] || fail "SHA-256 verification failed for ${archive}"
printf 'SHA-256 verified.\n'

tar -xzf "${temporary_directory}/${archive}" -C "$temporary_directory" opssh ||
	fail "could not extract opssh from ${archive}"
[ -f "${temporary_directory}/opssh" ] || fail "release archive does not contain opssh"

mkdir -p "$INSTALL_DIR" || fail "could not create ${INSTALL_DIR}"
[ -w "$INSTALL_DIR" ] || fail "${INSTALL_DIR} is not writable; set OPSSH_INSTALL_DIR to a writable directory"

staged_binary="$(mktemp "${INSTALL_DIR}/.opssh.XXXXXX")"
install -m 0755 "${temporary_directory}/opssh" "$staged_binary"
mv -f "$staged_binary" "${INSTALL_DIR}/opssh"
staged_binary=""

printf '\nopssh %s installed to %s/opssh\n' "$release_version" "$INSTALL_DIR"
case ":${PATH:-}:" in
	*":${INSTALL_DIR}:"*) ;;
	*)
		printf '%s\n' "Add ${INSTALL_DIR} to PATH, then restart your shell. For zsh:"
		printf '  echo '\''export PATH="%s:$PATH"'\'' >> ~/.zshrc\n' "$INSTALL_DIR"
		;;
esac
printf '%s\n' 'Next: run `opssh doctor`, then `opssh`.'
