#!/usr/bin/env bash
# Download and install a verified harden.sh. This installer never runs it.
set -Eeuo pipefail
IFS=$'\n\t'

readonly REPOSITORY="ManuTaycan/Linux-Hardening-Tool"
readonly RAW_BASE="https://raw.githubusercontent.com/${REPOSITORY}"
REF="main"
INSTALL_PATH="/usr/local/sbin/linux-hardening-tool"
TEMP_DIR=""

usage() {
    cat <<'EOF'
Usage: install.sh [--ref REF] [--install-path PATH] [--help]

Download harden.sh and SHA256SUMS from a GitHub branch or tag, verify the exact
harden.sh checksum entry, and install the script with mode 0755. The installer
does not run any hardening operation.

Defaults:
  --ref main
  --install-path /usr/local/sbin/linux-hardening-tool
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    [[ -z "$TEMP_DIR" || ! -d "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

while (($#)); do
    case "$1" in
        --ref)
            (($# >= 2)) || die "--ref requires a value"
            REF="$2"
            shift 2
            ;;
        --install-path)
            (($# >= 2)) || die "--install-path requires a value"
            INSTALL_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run this installer as root (for example: sudo bash install.sh --ref ${REF})"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ && "$REF" != *..* ]] || die "unsafe ref"
[[ "$INSTALL_PATH" == /* && "$INSTALL_PATH" != "/" ]] || die "install path must be an absolute non-root path"
[[ ! -d "$INSTALL_PATH" ]] || die "install path must be a destination file, not a directory"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v install >/dev/null 2>&1 || die "install is required"

TEMP_DIR="$(mktemp -d)"
curl -fsSL --retry 3 "${RAW_BASE}/${REF}/harden.sh" -o "$TEMP_DIR/harden.sh"
curl -fsSL --retry 3 "${RAW_BASE}/${REF}/SHA256SUMS" -o "$TEMP_DIR/SHA256SUMS"

entry_count="$(awk '$2 == "harden.sh" {count++} END {print count + 0}' "$TEMP_DIR/SHA256SUMS")"
[[ "$entry_count" == "1" ]] || die "SHA256SUMS must contain exactly one harden.sh entry"
awk '$2 == "harden.sh" {print}' "$TEMP_DIR/SHA256SUMS" > "$TEMP_DIR/harden.sh.sum"
(
    cd "$TEMP_DIR"
    sha256sum -c harden.sh.sum
)

install -d -o root -g root -m 0755 "$(dirname -- "$INSTALL_PATH")"
install -o root -g root -m 0755 "$TEMP_DIR/harden.sh" "$INSTALL_PATH"

printf 'Installed verified harden.sh as %s\n' "$INSTALL_PATH"
if [[ "$REF" == "main" ]]; then
    printf 'Note: main is the development branch. Prefer a reviewed release tag when one is available.\n'
fi
printf 'Next steps (the installer does not run hardening automatically):\n'
printf '  %s --help\n' "$INSTALL_PATH"
printf '  sha256sum %s\n' "$INSTALL_PATH"
printf '  sudo %s --dry-run --aggressive\n' "$INSTALL_PATH"
