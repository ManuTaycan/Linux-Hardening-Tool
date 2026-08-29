#!/usr/bin/env bash
# Debian/Ubuntu server hardening driven by the supplied Lynis 3.1.6 report.
# Source system: Ubuntu 26.04.1, kernel 7.0.0, x86_64; last validated Lynis index 86/100.
#
# Usage:
#   ./harden.sh --dry-run
#   sudo ./harden.sh --apply [--aggressive] [--reboot]
#   sudo ./harden.sh --apply --remote-log-server 10.0.0.9 --remote-log-port 5140 --remote-log-protocol tcp
#
# Optional non-interactive remote logging variables:
#   REMOTE_LOG_SERVER=logs.example.test REMOTE_LOG_PORT=6514
#   REMOTE_LOG_PROTOCOL=tls REMOTE_LOG_CA_FILE=/path/to/ca.pem

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_VERSION="1.1.3"
readonly LOG_FILE="${HARDEN_LOG_FILE:-/var/log/server-hardening.log}"
readonly SYSTEMD_HARDENING_REPORT="/root/systemd-hardening-report.txt"
readonly MAIN_PID="$BASHPID"

MODE=""
AGGRESSIVE=0
AUTO_REBOOT=0
NON_INTERACTIVE=0
OS_ID=""
OS_VERSION=""
OS_CODENAME=""
OS_PRETTY=""
BACKUP_DIR=""
CHANGE_LOG=""
SSH_PORT="22"
SSH_SERVICE=""
SSHD_BIN=""
ADMIN_USER=""
ADMIN_KEY_READY=0
REMOTE_LOG_ENABLED=0
REMOTE_LOG_SERVER="${REMOTE_LOG_SERVER:-}"
REMOTE_LOG_PORT="${REMOTE_LOG_PORT:-514}"
REMOTE_LOG_PROTOCOL="${REMOTE_LOG_PROTOCOL:-tcp}"
REMOTE_LOG_CA_FILE="${REMOTE_LOG_CA_FILE:-}"
REMOTE_LOG_OPTION_SEEN=0
REMOTE_LOG_DECLINED=0
PROMPT_REPLY=""
REBOOT_REQUIRED=0
LYNIS_BEFORE="NOT RUN"
LYNIS_AFTER="not run"
LYNIS_WARNINGS="unknown"
LYNIS_SUGGESTIONS="unknown"
LYNIS_PARSE_STATUS="NOT RUN"
FIREWALL_STATUS="NOT RUN"
SSH_STATUS="NOT RUN"
PAM_STATUS="NOT RUN"
AUDIT_STATUS="NOT RUN"
APPARMOR_STATUS="NOT RUN"
AIDE_STATUS="NOT RUN"
FAIL2BAN_STATUS="NOT RUN"
UPDATES_STATUS="NOT RUN"
REMOTE_LOG_STATUS="DISABLED"
USE_COLOR=0
LOG_READY=0
CURRENT_PHASE=0
COMPLETED=0
VALIDATION_COMPLETED=0
FINAL_LYNIS_COMPLETED=0
SUMMARY_PRINTED=0
NETWORK_HARDENING_COMPLETED=0
FIREWALL_COMPLETED=0
APPARMOR_COMPLETED=0
SYSTEMD_EXPOSURE_RESULT=""
IOWAIT_PREVIOUS_PIDS=""
MANAGED_FILE_CHANGED=0
MANAGED_SETTING_CHANGED=0
INITRAMFS_POLICY_CHANGED=0

readonly COLOR_RESET=$'\033[0m'
readonly COLOR_DIM=$'\033[2m'
readonly COLOR_BOLD=$'\033[1m'
readonly COLOR_RED=$'\033[31m'
readonly COLOR_GREEN=$'\033[32m'
readonly COLOR_YELLOW=$'\033[33m'
readonly COLOR_BLUE=$'\033[34m'
readonly COLOR_MAGENTA=$'\033[35m'
readonly COLOR_CYAN=$'\033[36m'

if [[ -t 1 && -z "${NO_COLOR+x}" ]]; then
    USE_COLOR=1
fi

declare -a PACKAGES_INSTALLED=()
declare -a PACKAGES_REMOVED=()
declare -a SERVICES_DISABLED=()
declare -a SERVICES_MASKED=()
declare -a SERVICES_HARDENED=()
declare -a SERVICES_DISABLE_REQUESTED=()
declare -a SERVICE_EXPOSURE_SUMMARY=()
declare -a ROLLBACKS=()
declare -a SKIPPED_FINDINGS=()
declare -A SERVICE_MASK_REQUESTED=()
declare -A SERVICE_EXPOSURE_BEFORE=()
declare -A SERVICE_EXPOSURE_AFTER=()

usage() {
    cat <<'EOF'
Usage: harden.sh (--dry-run | --apply) [--aggressive] [--reboot] [--non-interactive]
                 [--no-color] [--remote-log-server HOST]
                 [--remote-log-port PORT] [--remote-log-protocol tcp|udp|tls]

  --dry-run          Show planned changes. No files, logs, packages, or services change.
  --apply            Apply hardening (must run as root or through sudo).
  --aggressive       Enable compatibility-sensitive server controls.
  --reboot           Reboot after a successful --apply run if a reboot is required.
  --non-interactive  Do not prompt for a remote log server; use REMOTE_LOG_* variables.
  --no-color         Disable ANSI colors even on an interactive terminal.
  --remote-log-server
                     Remote syslog IP address or hostname; suppresses the prompt.
  --remote-log-port   Remote syslog port (default: 514).
  --remote-log-protocol
                     Remote syslog transport: tcp, udp, or tls (default: tcp).
EOF
}

timestamp() { date '+%Y-%m-%dT%H:%M:%S%z'; }

color_for_level() {
    case "$1" in
        INFO) printf '%s' "$COLOR_CYAN" ;;
        OK) printf '%s' "$COLOR_GREEN" ;;
        WARN) printf '%s' "$COLOR_YELLOW" ;;
        ERROR) printf '%s' "$COLOR_RED" ;;
        SKIP) printf '%s' "$COLOR_MAGENTA" ;;
        ROLLBACK) printf '%s' "$COLOR_RED$COLOR_BOLD" ;;
        *) printf '%s' "$COLOR_RESET" ;;
    esac
    return 0
}

render_colored_line() {
    local line="$1" color="" label="" value=""
    if [[ "$USE_COLOR" -ne 1 ]]; then
        printf '%s\n' "$line"
        return 0
    fi
    if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+\[([A-Z]+)\][[:space:]](.*)$ ]]; then
        color="$(color_for_level "${BASH_REMATCH[2]}")"
        printf '%s%s%s %s[%s]%s %s\n' "$COLOR_DIM" "${BASH_REMATCH[1]}" "$COLOR_RESET" \
            "$color" "${BASH_REMATCH[2]}" "$COLOR_RESET" "${BASH_REMATCH[3]}"
        return 0
    fi
    if [[ "$line" == '[PHASE '* ]]; then
        printf '%s%s%s%s\n' "$COLOR_BOLD" "$COLOR_BLUE" "$line" "$COLOR_RESET"
        return 0
    fi
    if [[ "$line" =~ ^={20,}$ ]]; then
        printf '%s%s%s\n' "$COLOR_CYAN" "$line" "$COLOR_RESET"
        return 0
    fi
    if [[ "$line" == *'DRY RUN MODE'* || "$line" == *'AGGRESSIVE HARDENING ENABLED'* ]]; then
        printf '%s%s%s%s\n' "$COLOR_BOLD" "$COLOR_YELLOW" "$line" "$COLOR_RESET"
        return 0
    fi
    if [[ "$line" == *'APPLY MODE'* ]]; then
        printf '%s%s%s%s\n' "$COLOR_BOLD" "$COLOR_RED" "$line" "$COLOR_RESET"
        return 0
    fi
    if [[ "$line" =~ ^([^:]+)([[:space:]]*:[[:space:]]*)(.*)$ ]]; then
        label="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        value="${BASH_REMATCH[3]}"
        case "${value^^}" in
            *FAILED*|*ERROR*) color="$COLOR_RED" ;;
            OK*|SUCCESS*|ENABLED*) color="$COLOR_GREEN" ;;
            *WARN*|YES|APPLY*) color="$COLOR_YELLOW" ;;
            PLANNED*|N/A*|DRY-RUN*) color="$COLOR_CYAN" ;;
        esac
        if [[ -n "$color" ]]; then
            printf '%s%s%s%s\n' "$label" "$color" "$value" "$COLOR_RESET"
            return 0
        fi
    fi
    printf '%s\n' "$line"
    return 0
}

emit_line() {
    local line="$1"
    if [[ "$MODE" == "apply" && "$LOG_READY" -eq 1 ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE" || true
    fi
    if [[ "$USE_COLOR" -eq 1 ]]; then
        render_colored_line "$line"
    else
        printf '%s\n' "$line"
    fi
    return 0
}

emit_block() {
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        emit_line "$line"
    done
    return 0
}

log() {
    local level="$1"
    shift
    emit_line "$(timestamp) [${level}] $*"
    return 0
}

phase() {
    local current="$1" total="$2" label="$3" current_num expected
    [[ "$current" =~ ^[0-9]{1,2}$ && "$total" == "18" ]] \
        || die "Internal phase-order violation: invalid phase request ${current}/${total}"
    current_num=$((10#$current))
    expected=$((CURRENT_PHASE + 1))
    if [[ "$current_num" -ne "$expected" ]]; then
        die "Internal phase-order violation: requested ${current_num}, expected ${expected}"
    fi
    CURRENT_PHASE="$current_num"
    emit_line '============================================================'
    printf -v current '%02d' "$current_num"
    emit_line "[PHASE ${current}/${total}] ${label}"
    emit_line '============================================================'
    return 0
}

show_mode_banner() {
    emit_line '============================================================'
    if [[ "$MODE" == "dry-run" ]]; then
        emit_line ' DRY RUN MODE - NO SYSTEM CHANGES WILL BE MADE'
    else
        emit_line ' APPLY MODE - SYSTEM CHANGES WILL BE PERFORMED'
    fi
    if [[ "$AGGRESSIVE" -eq 1 ]]; then
        emit_line ' AGGRESSIVE HARDENING ENABLED'
    fi
    emit_line '============================================================'
    return 0
}

die() {
    log ERROR "$*"
    exit 1
}

on_err() {
    local line="$1" command="$2" status="$3"
    log ERROR "Unexpected failure at line ${line} (exit ${status}): ${command}"
    log ERROR "Review ${LOG_FILE} and restore from ${BACKUP_DIR:-the system snapshot} if needed."
}

on_exit() {
    local status="$?" message
    trap - EXIT
    if [[ "$BASHPID" != "$MAIN_PID" ]]; then
        exit "$status"
    fi
    if [[ "$COMPLETED" -ne 1 ]]; then
        [[ "$status" -ne 0 ]] || status=1
        message="[ERROR] Hardening terminated before completion at phase ${CURRENT_PHASE}/18 (exit ${status})."
        if ! printf '%s\n' "$message" 2>/dev/null > /dev/tty; then
            printf '%s\n' "$message" >&2
        fi
        if [[ "$LOG_READY" -eq 1 ]]; then
            printf '%s\n' "$message" >> "$LOG_FILE" || true
        fi
    fi
    exit "$status"
}

trap 'on_err "$LINENO" "$BASH_COMMAND" "$?"' ERR
trap on_exit EXIT

quote_command() {
    local arg
    printf '  '
    for arg in "$@"; do printf '%q ' "$arg"; done
    printf '\n'
}

run() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would run:"
        quote_command "$@"
        return 0
    fi
    log INFO "Running: $(printf '%q ' "$@")"
    run_streamed "$@"
}

run_streamed() {
    local -a pipeline_status=()
    "$@" 2>&1 | emit_block
    pipeline_status=("${PIPESTATUS[@]}")
    [[ "${pipeline_status[0]}" -eq 0 && "${pipeline_status[1]}" -eq 0 ]]
}

record_change() {
    local message="$*"
    log OK "$message"
    if [[ "$MODE" == "apply" ]]; then
        printf '%s\t%s\n' "$(timestamp)" "$message" >> "$CHANGE_LOG"
    fi
}

record_skip() {
    local finding="$1" reason="$2"
    SKIPPED_FINDINGS+=("${finding}: ${reason}")
    log SKIP "${finding}: ${reason}"
}

prompt_value() {
    local prompt="$1" default_value="${2:-}" answer=""
    [[ -c /dev/tty && -r /dev/tty && -w /dev/tty ]] || return 1
    printf '%s' "$prompt" > /dev/tty
    if ! IFS= read -r answer < /dev/tty; then
        return 1
    fi
    PROMPT_REPLY="${answer:-$default_value}"
    return 0
}

prompt_yes_no() {
    local prompt="$1" answer=""
    while true; do
        prompt_value "$prompt" "n" || return 2
        answer="${PROMPT_REPLY,,}"
        case "$answer" in
            y|yes|j|ja) return 0 ;;
            n|no|nein|'') return 1 ;;
            *) printf '%s\n' 'Bitte mit y/yes/j/ja oder n/no/nein antworten.' > /dev/tty ;;
        esac
    done
}

parse_args() {
    while (($#)); do
        case "$1" in
            --dry-run)
                [[ -z "$MODE" ]] || die "Choose exactly one of --dry-run or --apply"
                MODE="dry-run"
                ;;
            --apply)
                [[ -z "$MODE" ]] || die "Choose exactly one of --dry-run or --apply"
                MODE="apply"
                ;;
            --aggressive) AGGRESSIVE=1 ;;
            --reboot) AUTO_REBOOT=1 ;;
            --non-interactive) NON_INTERACTIVE=1 ;;
            --no-color) USE_COLOR=0 ;;
            --remote-log-server)
                (($# >= 2)) || die "--remote-log-server requires a value"
                REMOTE_LOG_SERVER="$2"
                REMOTE_LOG_OPTION_SEEN=1
                shift
                ;;
            --remote-log-port)
                (($# >= 2)) || die "--remote-log-port requires a value"
                REMOTE_LOG_PORT="$2"
                REMOTE_LOG_OPTION_SEEN=1
                shift
                ;;
            --remote-log-protocol)
                (($# >= 2)) || die "--remote-log-protocol requires a value"
                REMOTE_LOG_PROTOCOL="$2"
                REMOTE_LOG_OPTION_SEEN=1
                shift
                ;;
            --remote-log-server=*) REMOTE_LOG_SERVER="${1#*=}"; REMOTE_LOG_OPTION_SEEN=1 ;;
            --remote-log-port=*) REMOTE_LOG_PORT="${1#*=}"; REMOTE_LOG_OPTION_SEEN=1 ;;
            --remote-log-protocol=*) REMOTE_LOG_PROTOCOL="${1#*=}"; REMOTE_LOG_OPTION_SEEN=1 ;;
            -h|--help) usage; COMPLETED=1; exit 0 ;;
            *) usage >&2; die "Unknown argument: $1" ;;
        esac
        shift
    done
    [[ -n "$MODE" ]] || { usage >&2; die "Specify --dry-run or --apply"; }
    if [[ "$AUTO_REBOOT" -eq 1 && "$MODE" != "apply" ]]; then
        die "--reboot is valid only with --apply"
    fi
    if [[ "$REMOTE_LOG_OPTION_SEEN" -eq 1 && -z "$REMOTE_LOG_SERVER" ]]; then
        die "--remote-log-port/--remote-log-protocol require --remote-log-server (or REMOTE_LOG_SERVER)"
    fi
}

check_root() {
    if [[ "$MODE" == "apply" && "$EUID" -ne 0 ]]; then
        die "--apply must run as root (for example: sudo ./harden.sh --apply)"
    fi
}

detect_os() {
    [[ -r /etc/os-release ]] || die "/etc/os-release is missing"
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID,,}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
    OS_PRETTY="${PRETTY_NAME:-${ID} ${OS_VERSION}}"
    case "$OS_ID" in
        debian|ubuntu) ;;
        *) die "Unsupported distribution '${OS_ID}'. Only Debian and Ubuntu are supported." ;;
    esac
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    command -v apt-get >/dev/null 2>&1 || die "APT is required"
    log INFO "Detected ${OS_PRETTY} (codename ${OS_CODENAME})"
}

init_logging() {
    local backup_root="${HARDEN_BACKUP_ROOT:-/root}"
    local log_parent=""
    if [[ "$MODE" == "dry-run" ]]; then
        return 0
    fi
    log_parent="$(dirname -- "$LOG_FILE")"
    if [[ -e "$log_parent" || -L "$log_parent" ]]; then
        [[ -d "$log_parent" ]] || die "Log parent is not a directory: ${log_parent}"
    else
        install -d -m 0750 "$log_parent"
    fi
    touch "$LOG_FILE"
    chmod 0640 "$LOG_FILE"
    LOG_READY=1
    BACKUP_DIR="${backup_root}/hardening-backup-$(date '+%Y%m%d-%H%M%S')"
    install -d -m 0700 "$BACKUP_DIR"
    CHANGE_LOG="$BACKUP_DIR/changes.tsv"
    : > "$CHANGE_LOG"
    chmod 0600 "$CHANGE_LOG"
    return 0
}

backup_config() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would back up managed configuration under /root/hardening-backup-YYYYMMDD-HHMMSS"
        return 0
    fi
    local -a candidates=(
        /etc/ssh /etc/pam.d /etc/security /etc/sysctl.conf /etc/sysctl.d
        /etc/systemd /etc/audit /etc/rsyslog.conf /etc/rsyslog.d
        /etc/nftables.conf /etc/nftables.d /etc/fail2ban /etc/sudoers
        /etc/sudoers.d /etc/login.defs /etc/modprobe.d /etc/fstab /etc/apt
        /etc/default/grub /etc/default/grub.d /etc/grub.d /etc/issue /etc/issue.net
    )
    local -a present=()
    local item
    for item in "${candidates[@]}"; do [[ -e "$item" ]] && present+=("$item"); done
    if ((${#present[@]})); then
        tar --acls --xattrs --numeric-owner -cpf "$BACKUP_DIR/config-backup.tar" "${present[@]}"
        chmod 0600 "$BACKUP_DIR/config-backup.tar"
    fi
    dpkg-query -W -f='${binary:Package}\t${Version}\n' > "$BACKUP_DIR/packages-before.tsv"
    systemctl list-unit-files > "$BACKUP_DIR/systemd-unit-files-before.txt" || true
    systemctl list-units --type=service --all > "$BACKUP_DIR/services-before.txt" || true
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset > "$BACKUP_DIR/nftables-before.conf" || true
    fi
    record_change "Created configuration and state backup at ${BACKUP_DIR}"
}

transaction_copy() {
    local source="$1" label="$2"
    [[ "$MODE" == "apply" ]] || return 0
    local target="$BACKUP_DIR/transactions/${label}"
    install -d -m 0700 "$(dirname "$target")"
    if [[ -e "$source" ]]; then
        cp -a -- "$source" "$target"
    else
        : > "${target}.absent"
    fi
}

transaction_restore() {
    local destination="$1" label="$2"
    [[ "$MODE" == "apply" ]] || return 0
    local saved="$BACKUP_DIR/transactions/${label}"
    if [[ -e "${saved}.absent" ]]; then
        rm -rf -- "$destination"
    elif [[ -e "$saved" ]]; then
        rm -rf -- "$destination"
        cp -a -- "$saved" "$destination"
    fi
    ROLLBACKS+=("$destination")
    log ROLLBACK "Restored ${destination}"
}

install_managed_file() {
    local destination="$1" mode="${2:-0644}" owner="${3:-root}" group="${4:-root}"
    MANAGED_FILE_CHANGED=0
    if [[ "$MODE" == "dry-run" ]]; then
        cat >/dev/null || return 1
        log INFO "Would install managed file ${destination} (${owner}:${group} ${mode})"
        return 0
    fi
    local temporary
    temporary="$(mktemp)" || return 1
    if ! cat > "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if [[ -f "$destination" ]] && cmp -s "$temporary" "$destination"; then
        rm -f -- "$temporary" || return 1
        log INFO "Managed file already current: ${destination}"
        return 0
    fi
    if ! install -d -m 0755 "$(dirname "$destination")" \
        || ! install -o "$owner" -g "$group" -m "$mode" "$temporary" "$destination"; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    MANAGED_FILE_CHANGED=1
    record_change "Installed managed file ${destination}"
    return 0
}

replace_setting() {
    local file="$1" key="$2" value="$3" separator="${4:- }"
    MANAGED_SETTING_CHANGED=0
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would set ${key}${separator}${value} in ${file}"
        return 0
    fi
    local temporary
    temporary="$(mktemp)"
    awk -v key="$key" -v value="$value" -v sep="$separator" '
        BEGIN { done=0 }
        $0 ~ "^[[:space:]#]*" key "([[:space:]]|=)" {
            if (!done) { print key sep value; done=1 }
            next
        }
        { print }
        END { if (!done) print key sep value }
    ' "$file" > "$temporary"
    if cmp -s "$temporary" "$file"; then
        rm -f "$temporary"
        log INFO "Setting already current: ${key} in ${file}"
        return 0
    fi
    install -o root -g root -m "$(stat -c '%a' "$file" 2>/dev/null || printf 0644)" "$temporary" "$file"
    rm -f "$temporary"
    MANAGED_SETTING_CHANGED=1
    record_change "Set ${key} in ${file}"
}

remove_setting() {
    local file="$1" key="$2"
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would remove active ${key} settings from ${file}"
        return 0
    fi
    [[ -f "$file" ]] || return 0
    local temporary
    temporary="$(mktemp)"
    awk -v key="$key" '$0 !~ "^[[:space:]]*" key "([[:space:]]|=)" { print }' "$file" > "$temporary"
    install -o root -g root -m "$(stat -c '%a' "$file" 2>/dev/null || printf 0644)" "$temporary" "$file"
    rm -f "$temporary"
    record_change "Removed obsolete active ${key} settings from ${file}"
}

package_installed() {
    local status
    status="$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null || true)"
    [[ "$status" == ii* ]]
}

package_available() {
    local package="$1" candidate policy
    policy="$(apt-cache policy "$package" 2>/dev/null || true)"
    candidate="$(awk '/Candidate:/ && candidate == "" {candidate=$2} END {print candidate}' <<<"$policy")"
    [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

unit_file_exists() {
    local unit="$1" listing
    listing="$(systemctl list-unit-files "$unit" --no-legend 2>/dev/null || true)"
    [[ -n "$listing" ]]
}

install_package() {
    local package="$1"
    if package_installed "$package"; then
        log INFO "Package already installed: ${package}"
        return 0
    fi
    if ! package_available "$package"; then
        record_skip "package:${package}" "no installable candidate in configured official repositories"
        return 1
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would install available package: ${package}"
        return 0
    fi
    if run_streamed env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package"; then
        PACKAGES_INSTALLED+=("$package")
        record_change "Installed package ${package}"
        return 0
    fi
    record_skip "package:${package}" "installation failed"
    return 0
}

prepare_packages() {
    if [[ "$MODE" == "apply" ]]; then
        log INFO "Refreshing APT metadata from configured repositories"
        run_streamed env DEBIAN_FRONTEND=noninteractive apt-get update
    else
        log INFO "Would run apt-get update before package availability checks"
    fi

    local -a common_packages=(
        auditd audispd-plugins apparmor apparmor-utils fail2ban aide aide-common rsyslog
        libpam-pwquality needrestart unattended-upgrades debsums acct nftables
        chrony apt-listchanges apt-show-versions libpam-tmpdir
    )
    local package
    for package in "${common_packages[@]}"; do install_package "$package" || true; done

    if [[ "$OS_ID" == "debian" ]]; then
        install_package apt-listbugs || true
    else
        record_skip "DEB-0810" "apt-listbugs is Debian-oriented and is not installed automatically on Ubuntu"
    fi

    if package_available rkhunter; then
        install_package rkhunter || true
    elif package_available chkrootkit; then
        install_package chkrootkit || true
    else
        record_skip "HRDN-7230" "neither rkhunter nor chkrootkit is available from configured repositories"
    fi

    if ! package_installed lynis; then
        install_package lynis || record_skip "Lynis" "not available from configured official repositories"
    fi
}

configure_apt() {
    install_managed_file /etc/apt/apt.conf.d/99security-hardening 0644 <<'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
DPkg::Pre-Invoke { "test -x /usr/bin/debsums && /usr/bin/debsums --silent || true"; };
EOF

    if [[ "$MODE" == "apply" ]]; then
        local suspicious=0
        if grep -RIE '^[[:space:]]*deb(-src)?[[:space:]].*(trusted=yes|allow-insecure=yes)' \
            /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
            suspicious=1
        fi
        if [[ "$suspicious" -eq 1 ]]; then
            record_skip "APT repositories" "trusted=yes or allow-insecure=yes found; source was not silently rewritten"
        fi
        run_streamed apt-get check
    fi
}

configure_updates() {
    install_managed_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    install_managed_file /etc/apt/apt.conf.d/52unattended-hardening 0644 <<'EOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    if command -v systemctl >/dev/null 2>&1; then
        run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer || true
    fi
    if [[ "$MODE" == "apply" ]] && command -v unattended-upgrade >/dev/null 2>&1; then
        if unattended-upgrade --dry-run --debug >/dev/null 2>&1; then
            UPDATES_STATUS="OK"
        else
            UPDATES_STATUS="FAILED"
            record_skip "automatic updates" "unattended-upgrade dry-run validation failed"
        fi
    else
        UPDATES_STATUS="PLANNED"
    fi
}

purge_removed_packages() {
    local -a residual=() safe=() verified=() protected=()
    mapfile -t residual < <(dpkg-query -W -f='${binary:Package}\t${Status}\n' 2>/dev/null | awk -F '\t' '$2 == "deinstall ok config-files" {print $1}')
    if ((${#residual[@]} == 0)); then
        log INFO "No residual package configurations found"
        return 0
    fi
    local package
    for package in "${residual[@]}"; do
        case "$package" in
            linux-*|grub*|shim*|systemd*|openssh*|sudo*|tailscale*|nftables*|iptables*|netplan*|network-manager*|ifupdown*|cloud-init*)
                protected+=("$package")
                ;;
            *) safe+=("$package") ;;
        esac
    done
    if ((${#protected[@]})); then
        record_skip "PKGS-7346" "protected residual boot/kernel/SSH/network package configurations were retained: ${protected[*]}"
    fi
    if ((${#safe[@]} == 0)); then
        log INFO "No non-protected residual package configurations are eligible for purge"
        return 0
    fi
    local status
    for package in "${safe[@]}"; do
        status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
        if [[ "$status" == "deinstall ok config-files" ]]; then
            verified+=("$package")
        else
            record_skip "package:${package}" "status changed from rc before purge; package was retained"
        fi
    done
    safe=("${verified[@]}")
    if ((${#safe[@]} == 0)); then
        log INFO "No twice-verified residual configurations remain eligible for purge"
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would simulate and purge only non-protected residual package configurations: ${safe[*]}"
        return 0
    fi
    local simulation removals
    simulation="$(apt-get -s purge "${safe[@]}" 2>&1)" || {
        record_skip "PKGS-7346" "APT simulation failed; nothing was purged"
        return 0
    }
    removals="$(awk '$1 == "Remv" {print $2}' <<<"$simulation")"
    if grep -E '^(linux-|grub|shim|systemd|openssh|sudo|tailscale|nftables|iptables|netplan|network-manager|ifupdown|cloud-init)' <<<"$removals" >/dev/null; then
        record_skip "PKGS-7346" "APT simulation included a protected dependency; nothing was purged"
        return 0
    fi
    if run_streamed env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${safe[@]}"; then
        PACKAGES_REMOVED+=("${safe[@]}")
        record_change "Purged only simulated, non-protected residual package configurations: ${safe[*]}"
    fi
}

configure_debsums() {
    if ! command -v debsums >/dev/null 2>&1; then
        record_skip "PKGS-7370" "debsums is unavailable"
        return 0
    fi
    if [[ ! -e /etc/default/debsums && "$MODE" == "apply" ]]; then
        install -o root -g root -m 0644 /dev/null /etc/default/debsums
    fi
    replace_setting /etc/default/debsums CRON_CHECK weekly '='
    if [[ -f /etc/cron.daily/debsums ]]; then
        run chown root:root /etc/cron.daily/debsums
        run chmod 0700 /etc/cron.daily/debsums
    else
        install_managed_file /etc/cron.weekly/debsums-hardening 0700 <<'EOF'
#!/bin/sh
# Managed by harden.sh: verify installed package files once per week.
exec /usr/bin/debsums --silent
EOF
    fi
    record_change "Enabled a real weekly debsums integrity check"
}

ask_remote_logging() {
    if [[ -n "$REMOTE_LOG_SERVER" ]]; then
        validate_remote_logging
        REMOTE_LOG_ENABLED=1
        return 0
    fi
    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        REMOTE_LOG_ENABLED=0
        REMOTE_LOG_DECLINED=1
        log INFO "Remote logging deliberately disabled by --non-interactive without a destination"
        return 0
    fi
    if ! [[ -c /dev/tty && -r /dev/tty && -w /dev/tty ]]; then
        REMOTE_LOG_ENABLED=0
        REMOTE_LOG_DECLINED=0
        log WARN "No controlling /dev/tty is available; remote logging remains disabled"
        return 0
    fi
    local prompt_status=0
    if prompt_yes_no "Soll ein Remote-Log-Server verwendet werden? [y/N] "; then
        prompt_status=0
    else
        prompt_status=$?
    fi
    if [[ "$prompt_status" -eq 2 ]]; then
        die "Could not read the remote logging decision from /dev/tty"
    fi
    if [[ "$prompt_status" -ne 0 ]]; then
        REMOTE_LOG_ENABLED=0
        REMOTE_LOG_DECLINED=1
        log INFO "Remote logging deliberately disabled by operator choice"
        return 0
    fi
    prompt_value "IP-Adresse oder Hostname des Log-Servers: " \
        || die "Could not read the remote log server from /dev/tty"
    REMOTE_LOG_SERVER="$PROMPT_REPLY"
    [[ -n "$REMOTE_LOG_SERVER" ]] || die "Remote logging was selected, but no host was entered"
    prompt_value "Port [${REMOTE_LOG_PORT:-514}]: " "${REMOTE_LOG_PORT:-514}" \
        || die "Could not read the remote log port from /dev/tty"
    REMOTE_LOG_PORT="$PROMPT_REPLY"
    prompt_value "Protokoll [${REMOTE_LOG_PROTOCOL:-tcp}] (tcp/udp/tls): " "${REMOTE_LOG_PROTOCOL:-tcp}" \
        || die "Could not read the remote log protocol from /dev/tty"
    REMOTE_LOG_PROTOCOL="$PROMPT_REPLY"
    validate_remote_logging
    REMOTE_LOG_ENABLED=1
    return 0
}

validate_remote_logging() {
    [[ "$REMOTE_LOG_SERVER" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]] \
        || die "Invalid remote log host"
    [[ "$REMOTE_LOG_PORT" =~ ^[0-9]{1,5}$ ]] \
        && ((REMOTE_LOG_PORT >= 1 && REMOTE_LOG_PORT <= 65535)) \
        || die "Invalid remote log port"
    REMOTE_LOG_PROTOCOL="${REMOTE_LOG_PROTOCOL,,}"
    case "$REMOTE_LOG_PROTOCOL" in tcp|udp|tls) ;; *) die "Protocol must be tcp, udp, or tls" ;; esac
    if [[ "$REMOTE_LOG_PROTOCOL" == "tls" ]]; then
        if [[ -z "$REMOTE_LOG_CA_FILE" && "$NON_INTERACTIVE" -eq 0 ]]; then
            prompt_value "CA certificate file for TLS: " \
                || die "Could not read the TLS CA path from /dev/tty"
            REMOTE_LOG_CA_FILE="$PROMPT_REPLY"
        fi
        [[ -r "$REMOTE_LOG_CA_FILE" ]] || die "TLS requires a readable REMOTE_LOG_CA_FILE"
        [[ "$REMOTE_LOG_CA_FILE" =~ ^/[A-Za-z0-9._/+:-]+$ ]] \
            || die "TLS CA path contains unsupported characters"
    fi
}

configure_logging() {
    transaction_copy /etc/rsyslog.d/10-security-hardening.conf rsyslog-local.conf
    transaction_copy /etc/rsyslog.d/90-remote-hardening.conf rsyslog-remote.conf
    install_managed_file /etc/systemd/journald.conf.d/99-security-hardening.conf 0644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
ForwardToSyslog=yes
RateLimitIntervalSec=30s
RateLimitBurst=10000
SystemMaxUse=1G
SystemKeepFree=1G
MaxRetentionSec=1month
EOF

    install_managed_file /etc/rsyslog.d/10-security-hardening.conf 0644 <<'EOF'
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0750
$Umask 0027
EOF

    install_managed_file /etc/logrotate.d/server-hardening 0644 <<'EOF'
/var/log/server-hardening.log /var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF

    if [[ "$REMOTE_LOG_ENABLED" -eq 1 ]]; then
        configure_remote_logging
        if [[ "$MODE" == "dry-run" ]]; then
            REMOTE_LOG_STATUS="PLANNED (${REMOTE_LOG_PROTOCOL}://${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT})"
        fi
    else
        REMOTE_LOG_STATUS="DISABLED"
        if [[ "$REMOTE_LOG_DECLINED" -eq 1 ]]; then
            REMOTE_LOG_STATUS="DISABLED (operator choice)"
            if [[ -f /etc/rsyslog.d/90-remote-hardening.conf ]] \
                && grep -q '^# Managed by harden.sh' /etc/rsyslog.d/90-remote-hardening.conf; then
                if [[ "$MODE" == "apply" ]]; then
                    rm -f -- /etc/rsyslog.d/90-remote-hardening.conf
                    record_change "Removed the managed remote rsyslog destination at the operator's request"
                else
                    log INFO "Would remove the managed remote rsyslog destination at the operator's request"
                fi
            fi
            record_skip "LOGG-2154" "remote logging was consciously disabled by the operator"
        elif [[ -f /etc/rsyslog.d/90-remote-hardening.conf ]] \
            && grep -q '^# Managed by harden.sh' /etc/rsyslog.d/90-remote-hardening.conf; then
            REMOTE_LOG_STATUS="PRESERVED (existing managed destination)"
            log INFO "Preserving the previously validated managed remote rsyslog destination"
        else
            record_skip "LOGG-2154" "remote logging was not selected; set REMOTE_LOG_SERVER or answer yes on a later run"
        fi
    fi

    if [[ "$MODE" == "apply" ]]; then
        install -d -o root -g systemd-journal -m 2750 /var/log/journal
        run_streamed systemd-tmpfiles --create --prefix /var/log/journal || true
        if ! run_streamed systemctl restart systemd-journald; then
            log WARN "systemd-journald restart failed; persistent settings remain installed for the next service start"
        fi
        if command -v rsyslogd >/dev/null 2>&1; then
            if run_streamed rsyslogd -N1 \
                && run_streamed systemctl enable --now rsyslog.service \
                && run_streamed systemctl restart rsyslog.service \
                && systemctl is-active --quiet rsyslog.service \
                && remote_logging_destination_loaded; then
                logger -p authpriv.notice -t harden.sh "rsyslog local/remote forwarding validation probe $(timestamp)" || true
                if [[ "$REMOTE_LOG_ENABLED" -eq 1 ]]; then
                    REMOTE_LOG_STATUS="ENABLED (${REMOTE_LOG_PROTOCOL}://${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT})"
                    record_change "Validated the loaded rsyslog destination/service and emitted a forwarding probe event"
                fi
            else
                transaction_restore /etc/rsyslog.d/10-security-hardening.conf rsyslog-local.conf
                transaction_restore /etc/rsyslog.d/90-remote-hardening.conf rsyslog-remote.conf
                rsyslogd -N1 >/dev/null 2>&1 && run_streamed systemctl restart rsyslog.service || true
                REMOTE_LOG_STATUS="FAILED"
                log ERROR "rsyslog validation failed; restored the prior local hardening fragment"
            fi
        elif [[ "$REMOTE_LOG_ENABLED" -eq 1 ]]; then
            transaction_restore /etc/rsyslog.d/10-security-hardening.conf rsyslog-local.conf
            transaction_restore /etc/rsyslog.d/90-remote-hardening.conf rsyslog-remote.conf
            REMOTE_LOG_STATUS="FAILED"
            record_skip "LOGG-2154" "rsyslogd is unavailable, so the requested remote destination was not left unvalidated"
        fi
        lsof +L1 2>/dev/null > "$BACKUP_DIR/deleted-open-files.txt" || true
        if [[ -s "$BACKUP_DIR/deleted-open-files.txt" ]]; then
            log INFO "Deleted-open-file inventory recorded; safe owning services will be evaluated after service hardening"
        fi
    fi
}

configure_remote_logging() {
    local protocol="$REMOTE_LOG_PROTOCOL" destination="$REMOTE_LOG_SERVER"
    if [[ "$destination" == *:* && "$destination" != \[*\] ]]; then
        destination="[${destination}]"
    fi
    if [[ "$protocol" == "tls" ]]; then
        install_package rsyslog-gnutls || die "TLS remote logging requested but rsyslog-gnutls is unavailable"
        install_managed_file /etc/rsyslog.d/90-remote-hardening.conf 0640 <<EOF
# Managed by harden.sh
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="${REMOTE_LOG_CA_FILE}"
)
*.* action(
  type="omfwd"
  target="${REMOTE_LOG_SERVER}"
  port="${REMOTE_LOG_PORT}"
  protocol="tcp"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="${REMOTE_LOG_SERVER}"
  action.resumeRetryCount="-1"
  queue.type="LinkedList"
  queue.filename="remote_tls"
  queue.maxDiskSpace="512m"
  queue.saveOnShutdown="on"
)
EOF
    else
        install_managed_file /etc/rsyslog.d/90-remote-hardening.conf 0640 <<EOF
# Managed by harden.sh
\$ActionQueueType LinkedList
\$ActionQueueFileName remote_${protocol}
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
*.* $([[ "$protocol" == "tcp" ]] && printf '@@' || printf '@')${destination}:${REMOTE_LOG_PORT}
EOF
    fi
    log INFO "Prepared remote logging to ${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT} over ${protocol}; activation awaits rsyslog validation"
    return 0
}

remote_logging_destination_loaded() {
    local config=/etc/rsyslog.d/90-remote-hardening.conf destination="$REMOTE_LOG_SERVER"
    [[ "$REMOTE_LOG_ENABLED" -eq 1 ]] || return 0
    [[ -s "$config" ]] || return 1
    if [[ "$REMOTE_LOG_PROTOCOL" == "tls" ]]; then
        grep -F -- "target=\"${REMOTE_LOG_SERVER}\"" "$config" >/dev/null \
            && grep -F -- "port=\"${REMOTE_LOG_PORT}\"" "$config" >/dev/null
        return $?
    fi
    if [[ "$destination" == *:* && "$destination" != \[*\] ]]; then
        destination="[${destination}]"
    fi
    local prefix='@'
    [[ "$REMOTE_LOG_PROTOCOL" == "tcp" ]] && prefix='@@'
    grep -F -- "*.* ${prefix}${destination}:${REMOTE_LOG_PORT}" "$config" >/dev/null
}

configure_banners() {
    install_managed_file /etc/issue 0644 <<'EOF'
NOTICE: This is a private system for authorized access and use only. Use is subject
to monitoring, recording, and audit. By continuing, you consent to these conditions.
Unauthorized use is prohibited and may result in disciplinary action and enforcement
under applicable law. There is no expectation of privacy. Disconnect if unauthorized.
EOF
    install_managed_file /etc/issue.net 0644 <<'EOF'
NOTICE: This is a private system for authorized access and use only. Use is subject
to monitoring, recording, and audit. By continuing, you consent to these conditions.
Unauthorized use is prohibited and may result in disciplinary action and enforcement
under applicable law. There is no expectation of privacy. Disconnect if unauthorized.
EOF
}

sysctl_candidates() {
    cat <<'EOF'
dev.tty.ldisc_autoload=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=2
net.core.bpf_jit_harden=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.default.forwarding=0
vm.mmap_min_addr=65536
vm.unprivileged_userfaultfd=0
EOF
}

aggressive_sysctl_candidates() {
    cat <<'EOF'
kernel.kexec_load_disabled=1
kernel.unprivileged_userns_clone=0
kernel.io_uring_disabled=2
EOF
}

configure_sysctl() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would write supported baseline sysctls to /etc/sysctl.d/99-security-hardening.conf"
        if [[ "$AGGRESSIVE" -eq 1 ]]; then
            log WARN "Would also disable unprivileged user namespaces, kexec loading, and io_uring when supported"
        fi
        return 0
    fi
    local temporary key value proc_path tailscale_active=0
    if systemctl is-active --quiet tailscaled.service 2>/dev/null; then
        tailscale_active=1
        log INFO "Tailscale is active; loose reverse-path filtering (2) will be used to preserve asymmetric overlay routing"
        record_skip "KRNL-6000:net.ipv4.conf.all.rp_filter" "value 2 is intentionally retained while Tailscale is active; strict value 1 can reject valid asymmetric overlay traffic"
    fi
    temporary="$(mktemp)"
    {
        printf '# Managed by harden.sh. Unsupported keys are intentionally omitted.\n'
        while IFS='=' read -r key value; do
            [[ -n "$key" ]] || continue
            if [[ "$tailscale_active" -eq 1 ]] \
                && [[ "$key" == "net.ipv4.conf.all.rp_filter" || "$key" == "net.ipv4.conf.default.rp_filter" ]]; then
                value=2
            fi
            if [[ "$tailscale_active" -eq 1 && "$key" == *'.forwarding' ]] \
                && [[ "$(sysctl -n "$key" 2>/dev/null || true)" == "1" ]]; then
                value=1
                log INFO "Preserving active forwarding control ${key}=1 for the existing Tailscale routing role" >&2
            fi
            if [[ "$key" == "kernel.unprivileged_userns_clone" ]] \
                && systemctl is-active --quiet snapd.service 2>/dev/null; then
                log SKIP "Skipped ${key}: active snapd requires user namespaces" >&2
                continue
            fi
            proc_path="/proc/sys/${key//./\/}"
            if [[ -e "$proc_path" ]]; then
                printf '%s = %s\n' "$key" "$value"
            else
                log SKIP "Unsupported sysctl omitted: ${key}" >&2
            fi
        done < <(sysctl_candidates; [[ "$AGGRESSIVE" -eq 1 ]] && aggressive_sysctl_candidates)
    } > "$temporary"
    install -o root -g root -m 0644 "$temporary" /etc/sysctl.d/99-security-hardening.conf
    rm -f "$temporary"
    record_change "Installed supported kernel/network controls in /etc/sysctl.d/99-security-hardening.conf"
    if ! run_streamed sysctl --system; then
        log WARN "sysctl --system returned a failure, possibly from an unrelated vendor file"
    fi
    local failed=0
    while IFS='=' read -r key value; do
        key="${key//[[:space:]]/}"
        value="${value//[[:space:]]/}"
        [[ -n "$key" ]] || continue
        if [[ "$(sysctl -n "$key" 2>/dev/null || true)" != "$value" ]]; then
            log WARN "sysctl did not retain requested value: ${key}=${value}"
            failed=1
        fi
    done < <(grep -Ev '^[[:space:]]*(#|$)' /etc/sysctl.d/99-security-hardening.conf)
    [[ "$failed" -eq 0 ]] || record_skip "KRNL-6000" "one or more supported sysctls could not be applied by the running environment"
    if [[ "$AGGRESSIVE" -eq 0 ]]; then
        record_skip "kernel.modules_disabled" "requires --aggressive because it is irreversible until reboot"
    fi
}

configure_core_dumps() {
    install_managed_file /etc/security/limits.d/99-disable-core-dumps.conf 0644 <<'EOF'
*       soft    core    0
*       hard    core    0
root    soft    core    0
root    hard    core    0
EOF
    install_managed_file /etc/systemd/coredump.conf.d/99-disable.conf 0644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
EOF
    install_managed_file /etc/profile.d/99-disable-core-dumps.sh 0644 <<'EOF'
ulimit -S -c 0 >/dev/null 2>&1 || true
EOF
    if unit_file_exists systemd-coredump.socket; then
        run systemctl mask systemd-coredump.socket || true
    fi
}

root_uses_module() {
    local module="$1" root_fs
    root_fs="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"
    [[ "$root_fs" == "$module" ]]
}

root_or_boot_uses_usb() {
    local mountpoint source transports
    for mountpoint in / /boot /boot/efi; do
        source="$(findmnt -n -o SOURCE "$mountpoint" 2>/dev/null || true)"
        [[ -n "$source" ]] || continue
        transports="$(lsblk -s -n -o TRAN "$source" 2>/dev/null || true)"
        if grep -Fxq usb <<<"$transports"; then
            return 0
        fi
    done
    return 1
}

binfmt_unregister_entry() {
    local entry_file="$1"
    printf '%s\n' -1 > "$entry_file"
}

configure_binfmt_misc() {
    local binfmt_root="${HARDEN_BINFMT_ROOT:-/proc/sys/fs/binfmt_misc}"
    local report="${BACKUP_DIR:-/root}/binfmt-misc-inventory.txt"
    local modprobe_file="${HARDEN_BINFMT_MODPROBE_FILE:-/etc/modprobe.d/99-disable-unused-binfmt-misc.conf}"
    local etc_binfmt_dir="${HARDEN_BINFMT_ETC_DIR:-/etc/binfmt.d}"
    local vendor_binfmt_dir="${HARDEN_BINFMT_VENDOR_DIR:-/usr/lib/binfmt.d}"
    local python_root="${HARDEN_BINFMT_PYTHON_ROOT:-/usr/bin}"
    local -a registrations=() consumers=() config_files=() python_names=() disabled_python=() already_disabled_python=()
    local entry package config_dir config_line status="unavailable" remaining_registration="" name="" base=""
    local override="" transaction_label="" python_binary="" validation_failed="" other_registration=""
    local override_was_current=0
    declare -A python_local_override=() active_registration=() seen_python=()
    local -a config_dirs=(/etc/binfmt.d /run/binfmt.d /usr/local/lib/binfmt.d /usr/lib/binfmt.d /lib/binfmt.d)
    if [[ -n "${HARDEN_BINFMT_CONFIG_DIRS:-}" ]]; then
        IFS=: read -r -a config_dirs <<<"$HARDEN_BINFMT_CONFIG_DIRS"
    fi

    if [[ -d "$binfmt_root" ]]; then
        while IFS= read -r entry; do registrations+=("$entry"); done < <(
            find "$binfmt_root" -maxdepth 1 -type f ! -name register ! -name status -printf '%f\n' 2>/dev/null | sort
        )
        [[ ! -r "$binfmt_root/status" ]] || status="$(tr -d '[:space:]' < "$binfmt_root/status" 2>/dev/null || true)"
    fi
    for config_dir in "${config_dirs[@]}"; do
        [[ -d "$config_dir" ]] || continue
        while IFS= read -r config_line; do config_files+=("$config_line"); done < <(
            find "$config_dir" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print 2>/dev/null | sort
        )
    done
    for entry in "${registrations[@]}"; do active_registration["$entry"]=1; done
    for config_line in "${config_files[@]}"; do
        base="$(basename -- "$config_line")"
        name="${base%.conf}"
        [[ "$name" =~ ^python3\.[0-9]+$ ]] || continue
        if [[ "$config_line" == "$etc_binfmt_dir/"* ]]; then
            python_local_override["$name"]="$config_line"
        elif [[ "$config_line" == "$vendor_binfmt_dir/"* && -f "$config_line" && ! -L "$config_line" ]] \
            && grep -Fq ":${name}:M::" "$config_line" \
            && grep -Fq "::/usr/bin/${name}:" "$config_line"; then
            if [[ -z "${seen_python[$name]+present}" ]]; then
                python_names+=("$name")
                seen_python["$name"]=1
            fi
        fi
    done
    for package in qemu-user qemu-user-static binfmt-support wine wine64 wine32 mono-runtime default-jre default-jre-headless; do
        package_installed "$package" && consumers+=("$package")
    done
    while IFS= read -r package; do
        [[ -n "$package" ]] && consumers+=("$package")
    done < <(dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\n' \
        'qemu-user*' 'wine*' 'openjdk-*' '*-jre*' 2>/dev/null \
        | awk '$1 ~ /^ii/ {print $2}' | sort -u || true)

    if [[ "$MODE" == "dry-run" ]]; then
        if ((${#python_names[@]})) && [[ "$AGGRESSIVE" -eq 1 ]]; then
            log INFO "Would mask only the vendor Python bytecode binfmt registrations (${python_names[*]}) and validate Python, APT, systemd, and all other registrations"
        elif ((${#registrations[@]} || ${#config_files[@]} || ${#consumers[@]})); then
            log INFO "Would preserve binfmt_misc after inventory because registrations, configuration, or interpreter consumers exist"
        elif [[ "$AGGRESSIVE" -eq 1 ]]; then
            log INFO "Would persistently disable unused systemd-binfmt/binfmt_misc and verify no registrations remain"
        else
            record_skip "HRDN-7231" "unused binfmt_misc deactivation requires --aggressive"
        fi
        return 0
    fi

    {
        printf 'binfmt_misc inventory generated %s\n' "$(timestamp)"
        printf 'kernel-status=%s\n' "${status:-unknown}"
        printf 'registrations=%s\n' "${registrations[*]:-none}"
        for entry in "${registrations[@]}"; do
            printf '\n[%s]\n' "$entry"
            sed -n '1,80p' "$binfmt_root/$entry" 2>/dev/null || true
        done
        printf '\nconfiguration-files=%s\n' "${config_files[*]:-none}"
        for entry in "${config_files[@]}"; do
            printf '\n[%s]\n' "$entry"
            grep -Ev '^[[:space:]]*(#|$)' "$entry" 2>/dev/null || true
        done
        printf '\nprotected-consumer-packages=%s\n' "${consumers[*]:-none}"
        printf 'python-bytecode-candidates=%s\n' "${python_names[*]:-none}"
        printf 'python-bytecode-purpose=direct execution of version-specific compiled .pyc files; normal interpreter execution does not require binfmt_misc\n'
    } > "$report"
    chmod 0600 "$report"

    if ((${#python_names[@]})); then
        if [[ "$AGGRESSIVE" -ne 1 ]]; then
            record_skip "HRDN-7231" "Python bytecode registrations ${python_names[*]} can be disabled individually, but persistent deactivation requires --aggressive; see ${report}"
            return 0
        fi
        for name in "${python_names[@]}"; do
            override="${etc_binfmt_dir}/${name}.conf"
            python_binary="${python_root}/${name}"
            validation_failed=""
            override_was_current=0
            if [[ -n "${python_local_override[$name]+present}" ]] \
                && [[ ! -L "$override" || "$(readlink -- "$override" 2>/dev/null || true)" != /dev/null ]]; then
                record_skip "HRDN-7231:${name}" "local administrator binfmt override ${override} is not a /dev/null mask and was preserved"
                continue
            fi
            if [[ -L "$override" && "$(readlink -- "$override" 2>/dev/null || true)" == /dev/null ]]; then
                override_was_current=1
            fi
            if [[ ! -x "$python_binary" ]]; then
                record_skip "HRDN-7231:${name}" "vendor bytecode registration exists but interpreter ${python_binary} is unavailable; retained due to inconsistent package state"
                continue
            fi
            if [[ -n "${active_registration[$name]+present}" ]] \
                && ! grep -Fxq "interpreter /usr/bin/${name}" "$binfmt_root/$name" 2>/dev/null; then
                record_skip "HRDN-7231:${name}" "active registration does not use the expected vendor interpreter /usr/bin/${name}; retained for manual review"
                continue
            fi
            if [[ ! -d "$etc_binfmt_dir" ]] \
                && ! install -d -o root -g root -m 0755 "$etc_binfmt_dir"; then
                record_skip "HRDN-7231:${name}" "could not create ${etc_binfmt_dir}; vendor registration was retained"
                continue
            fi
            transaction_label="binfmt-${name}.conf"
            transaction_copy "$override" "$transaction_label"
            if [[ ! -L "$override" || "$(readlink -- "$override" 2>/dev/null || true)" != /dev/null ]]; then
                rm -f -- "$override"
                if ! ln -s /dev/null "$override"; then
                    transaction_restore "$override" "$transaction_label"
                    record_skip "HRDN-7231:${name}" "could not install targeted ${override} -> /dev/null override"
                    continue
                fi
            fi
            if [[ -n "${active_registration[$name]+present}" ]] \
                && ! binfmt_unregister_entry "$binfmt_root/$name"; then
                validation_failed="runtime unregister failed"
            fi
            [[ ! -e "$binfmt_root/$name" ]] || validation_failed="runtime registration remained active"
            [[ -n "$validation_failed" ]] || "$python_binary" -c 'import sys; raise SystemExit(0)' >/dev/null 2>&1 \
                || validation_failed="${name} interpreter validation failed"
            [[ -n "$validation_failed" ]] || python3 -c 'import sys; raise SystemExit(0)' >/dev/null 2>&1 \
                || validation_failed="default python3 validation failed"
            [[ -n "$validation_failed" ]] || LC_ALL=C apt-get check >/dev/null 2>&1 \
                || validation_failed="apt-get check failed"
            [[ -n "$validation_failed" ]] || run_streamed systemctl daemon-reload \
                || validation_failed="systemctl daemon-reload failed"
            if [[ -z "$validation_failed" ]]; then
                for other_registration in "${registrations[@]}"; do
                    [[ "$other_registration" == "$name" || -e "$binfmt_root/$other_registration" ]] \
                        || validation_failed="unrelated registration ${other_registration} disappeared"
                done
            fi
            if [[ -n "$validation_failed" ]]; then
                transaction_restore "$override" "$transaction_label"
                if unit_file_exists systemd-binfmt.service; then
                    run_streamed systemctl restart systemd-binfmt.service || true
                fi
                record_skip "HRDN-7231:${name}" "targeted Python bytecode deactivation rolled back: ${validation_failed}"
                continue
            fi
            if [[ "$override_was_current" -eq 1 && -z "${active_registration[$name]+present}" ]]; then
                already_disabled_python+=("$name")
            else
                disabled_python+=("$name")
            fi
        done
        if ((${#disabled_python[@]})); then
            record_change "Target-disabled reversible Python bytecode binfmt registrations via /etc/binfmt.d -> /dev/null without changing normal Python/APT/systemd operation or unrelated formats: ${disabled_python[*]}"
        fi
        if ((${#already_disabled_python[@]})); then
            log OK "Python bytecode binfmt override already active and revalidated: ${already_disabled_python[*]}"
        fi
        record_skip "HRDN-7231" "global binfmt_misc disable was not used; non-Python registrations and consumers remain preserved and inventoried in ${report}"
        return 0
    fi

    if ((${#registrations[@]} || ${#config_files[@]} || ${#consumers[@]})); then
        record_skip "HRDN-7231" "binfmt_misc preserved; active/configured formats or protected qemu/Wine/JVM consumers are inventoried in ${report}"
        return 0
    fi
    if [[ "$AGGRESSIVE" -ne 1 ]]; then
        record_skip "HRDN-7231" "no consumer was found, but persistent deactivation requires --aggressive; see ${report}"
        return 0
    fi

    if [[ -w "$binfmt_root/status" ]]; then
        printf '0\n' > "$binfmt_root/status"
        status="$(tr -d '[:space:]' < "$binfmt_root/status" 2>/dev/null || true)"
        [[ "$status" == disabled || "$status" == 0 ]] || {
            record_skip "HRDN-7231" "binfmt_misc runtime status did not become disabled; see ${report}"
            return 0
        }
    fi
    if [[ -d "$binfmt_root" ]]; then
        remaining_registration="$(find "$binfmt_root" -maxdepth 1 -type f ! -name register ! -name status -print 2>/dev/null || true)"
    fi
    if [[ -n "$remaining_registration" ]]; then
        record_skip "HRDN-7231" "registrations remained after runtime disable; no persistent service/module block was installed and formats were not deleted blindly"
        return 0
    fi
    install_managed_file "$modprobe_file" 0644 <<'EOF'
# Managed by harden.sh after proving no active/configured foreign formats.
install binfmt_misc /bin/false
blacklist binfmt_misc
EOF
    if [[ "$MANAGED_FILE_CHANGED" -eq 1 ]]; then
        INITRAMFS_POLICY_CHANGED=1
    fi
    if unit_file_exists systemd-binfmt.service; then
        disable_service systemd-binfmt.service 1
    fi
    record_change "Inventoried and persistently disabled unused systemd-binfmt/binfmt_misc without deleting configured interpreters"
    return 0
}

configure_kernel_modules() {
    local -a modules=(cramfs freevxfs hfs hfsplus jffs2 udf dccp sctp rds tipc)
    local module loaded_modules=""
    command -v lsmod >/dev/null 2>&1 && loaded_modules="$(lsmod 2>/dev/null || true)"
    local content="# Managed by harden.sh"
    for module in "${modules[@]}"; do
        if root_uses_module "$module"; then
            record_skip "module:${module}" "module backs the root filesystem"
            continue
        fi
        if [[ "$module" == dccp || "$module" == sctp || "$module" == rds || "$module" == tipc ]] \
            && awk -v module="$module" '$1 == module {found=1} END {exit !found}' <<<"$loaded_modules"; then
            record_skip "NETW-3200:${module}" "protocol module is already loaded and may have an active consumer; it was not disabled blindly"
            continue
        fi
        content+=$'\n'"install ${module} /bin/false"$'\n'"blacklist ${module}"
    done

    if [[ "$AGGRESSIVE" -eq 1 ]]; then
        local block_devices
        block_devices="$(lsblk -nrpo NAME,TRAN,MOUNTPOINTS 2>/dev/null || true)"
        if root_or_boot_uses_usb; then
            record_skip "USB-1000" "root, /boot, or the EFI system partition is backed by USB storage"
        elif awk '$2 == "usb" {found=1} END {exit !found}' <<<"$block_devices"; then
            record_skip "USB-1000" "a non-boot USB block device is present and may be operationally required"
        else
            content+=$'\ninstall usb-storage /bin/false\nblacklist usb-storage'
        fi
        if [[ ! -d /sys/bus/firewire/devices || -z "$(ls -A /sys/bus/firewire/devices 2>/dev/null)" ]]; then
            content+=$'\ninstall firewire-core /bin/false\nblacklist firewire-core'
            content+=$'\ninstall firewire-ohci /bin/false\nblacklist firewire-ohci'
        else
            record_skip "module:firewire" "a FireWire device is present, so its core and controller modules were preserved"
        fi
        if [[ ! -d /sys/bus/thunderbolt/devices || -z "$(ls -A /sys/bus/thunderbolt/devices 2>/dev/null)" ]]; then
            content+=$'\ninstall thunderbolt /bin/false\nblacklist thunderbolt'
        fi
    else
        record_skip "USB-1000" "USB storage blocking requires --aggressive after verifying console and storage dependencies"
    fi
    INITRAMFS_POLICY_CHANGED=0
    printf '%s\n' "$content" | install_managed_file /etc/modprobe.d/99-security-hardening.conf 0644
    if [[ "$MANAGED_FILE_CHANGED" -eq 1 ]]; then
        INITRAMFS_POLICY_CHANGED=1
    fi
    configure_binfmt_misc
    if [[ "$MODE" == "apply" ]]; then
        if [[ "$INITRAMFS_POLICY_CHANGED" -ne 1 ]]; then
            log INFO "Managed module policy is unchanged; update-initramfs is not required"
        elif command -v update-initramfs >/dev/null 2>&1; then
            if run_streamed update-initramfs -u; then
                REBOOT_REQUIRED=1
            else
                record_skip "initramfs" "update-initramfs failed; module policy is installed but boot image may not contain it"
            fi
        else
            record_skip "initramfs" "update-initramfs is not installed on this image"
        fi
    fi
}

kernel_config_value() {
    local symbol="$1" config_file="${HARDEN_KERNEL_CONFIG:-/boot/config-$(uname -r)}"
    local value=""
    if [[ -r "$config_file" ]]; then
        value="$(awk -F= -v symbol="$symbol" '$1 == symbol {value=$2} END {print value}' "$config_file")"
    elif [[ -r "${HARDEN_PROC_CONFIG:-/proc/config.gz}" ]] && command -v gzip >/dev/null 2>&1; then
        value="$(gzip -cd "${HARDEN_PROC_CONFIG:-/proc/config.gz}" 2>/dev/null \
            | awk -F= -v symbol="$symbol" '$1 == symbol {value=$2} END {print value}')"
    else
        printf '%s\n' unknown
        return 0
    fi
    case "$value" in
        y) printf '%s\n' builtin ;;
        m) printf '%s\n' module ;;
        *) printf '%s\n' unavailable ;;
    esac
    return 0
}

kernel_module_is_loaded() {
    local module="${1//-/_}" sys_module_root="${HARDEN_SYS_MODULE_ROOT:-/sys/module}"
    local proc_modules="${HARDEN_PROC_MODULES:-/proc/modules}"
    [[ -d "$sys_module_root/$module" ]] && return 0
    [[ -r "$proc_modules" ]] \
        && awk -v module="$module" '$1 == module {found=1} END {exit !found}' "$proc_modules"
}

kernel_lock_report_start() {
    local report="${HARDEN_KERNEL_LOCK_REPORT:-/root/kernel-module-lockdown-report.txt}"
    local parent
    parent="$(dirname -- "$report")"
    if [[ ! -d "$parent" ]]; then
        install -d -m 0700 "$parent" || return 1
    fi
    KERNEL_LOCK_REPORT_WORK="${report}.tmp.$$"
    : > "$KERNEL_LOCK_REPORT_WORK" || return 1
    chmod 0600 "$KERNEL_LOCK_REPORT_WORK" || return 1
    printf 'kernel-module-lockdown diagnostic\ngenerated=%s\nkernel=%s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$(uname -r)" >> "$KERNEL_LOCK_REPORT_WORK"
    return 0
}

kernel_lock_report_line() {
    printf '%s=%s\n' "$1" "$2" >> "$KERNEL_LOCK_REPORT_WORK"
}

kernel_lock_report_finish() {
    local report="${HARDEN_KERNEL_LOCK_REPORT:-/root/kernel-module-lockdown-report.txt}"
    mv -f -- "$KERNEL_LOCK_REPORT_WORK" "$report"
    chmod 0600 "$report"
}

kernel_lock_fail() {
    local reason="$1"
    kernel_lock_report_line gate-result "BLOCKED"
    kernel_lock_report_line gate-error "$reason"
    kernel_lock_report_finish || true
    printf 'ERROR: kernel module lock blocked: %s\n' "$reason" >&2
    return 1
}

tailscale_kernel_runtime_ready() {
    local family command version summary backend chain_output="" health_problem=0 router_v4=0 router_v6=0
    local ipv4_masquerade=0 ipv6_masquerade=0
    KERNEL_GATE_FAILURE=""
    if ! systemctl is-active --quiet server-hardening-firewall.service 2>/dev/null; then
        KERNEL_GATE_FAILURE="server-hardening-firewall.service is not active"
        return 1
    fi
    kernel_lock_report_line firewall-service active
    if ! systemctl is-active --quiet tailscaled.service 2>/dev/null; then
        KERNEL_GATE_FAILURE="tailscaled.service stopped before the final lock gate"
        return 1
    fi
    for family in ipv4 ipv6; do
        if [[ "$family" == ipv4 ]]; then command=iptables; else command=ip6tables; fi
        if ! command -v "$command" >/dev/null 2>&1; then
            KERNEL_GATE_FAILURE="${command} is unavailable"
            return 1
        fi
        version="$($command --version 2>/dev/null || true)"
        kernel_lock_report_line "${family}-iptables-backend" "${version:-unavailable}"
        if [[ "$version" != *nf_tables* ]]; then
            KERNEL_GATE_FAILURE="${command} is not using the nf_tables backend"
            return 1
        fi
        if ! "$command" -w -t nat -S POSTROUTING >/dev/null 2>&1; then
            KERNEL_GATE_FAILURE="${family} nat/POSTROUTING is unavailable"
            return 1
        fi
        kernel_lock_report_line "${family}-nat-postrouting" OK
        chain_output="$($command -w -t nat -S ts-postrouting 2>/dev/null || true)"
        if ! "$command" -w -t filter -S ts-input >/dev/null 2>&1 \
            || ! "$command" -w -t filter -S ts-forward >/dev/null 2>&1 \
            || [[ -z "$chain_output" ]] \
            || ! "$command" -w -t filter -C INPUT -j ts-input >/dev/null 2>&1 \
            || ! "$command" -w -t filter -C FORWARD -j ts-forward >/dev/null 2>&1 \
            || ! "$command" -w -t nat -C POSTROUTING -j ts-postrouting >/dev/null 2>&1; then
            KERNEL_GATE_FAILURE="${family} Tailscale netfilter chains or hooks are incomplete"
            return 1
        fi
        kernel_lock_report_line "${family}-tailscale-chains" OK
        if grep -Fq MASQUERADE <<<"$chain_output"; then
            if [[ "$family" == ipv4 ]]; then ipv4_masquerade=1; else ipv6_masquerade=1; fi
        fi
    done
    if ! command -v tailscale >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
        KERNEL_GATE_FAILURE="tailscale status or the Python JSON parser is unavailable"
        return 1
    fi
    if ! summary="$(tailscale status --json 2>/dev/null | python3 -c '
import json, re, sys
import ipaddress
data = json.load(sys.stdin)
print("backend=" + str(data.get("BackendState", "")))
node = data.get("Self") or {}
routes = node.get("PrimaryRoutes") or []
router4 = bool(node.get("ExitNodeOption"))
router6 = bool(node.get("ExitNodeOption"))
for route in routes:
    try:
        network = ipaddress.ip_network(str(route), strict=False)
        router4 = router4 or network.version == 4
        router6 = router6 or network.version == 6
    except ValueError:
        pass
print("router-v4=" + ("1" if router4 else "0"))
print("router-v6=" + ("1" if router6 else "0"))
for item in data.get("Health") or []:
    if re.search(r"router|netfilter|firewall|iptables|nftables|masquerad|postrouting|forwarding", str(item), re.I):
        print("health-problem=1")
')"; then
        KERNEL_GATE_FAILURE="tailscale status --json could not be parsed"
        return 1
    fi
    backend="$(awk -F= '$1 == "backend" {print substr($0, index($0, "=") + 1)}' <<<"$summary")"
    grep -Fxq 'health-problem=1' <<<"$summary" && health_problem=1
    grep -Fxq 'router-v4=1' <<<"$summary" && router_v4=1
    grep -Fxq 'router-v6=1' <<<"$summary" && router_v6=1
    kernel_lock_report_line tailscale-backend-state "${backend:-unknown}"
    kernel_lock_report_line tailscale-router-role "ipv4=${router_v4};ipv6=${router_v6}"
    kernel_lock_report_line tailscale-router-netfilter-health "$([[ "$health_problem" -eq 0 ]] && printf clear || printf warning)"
    if [[ "$backend" != Running ]]; then
        KERNEL_GATE_FAILURE="Tailscale backend state is ${backend:-unknown}, not Running"
        return 1
    fi
    if [[ "$health_problem" -ne 0 ]]; then
        KERNEL_GATE_FAILURE="Tailscale reports a current router/netfilter health warning"
        return 1
    fi
    if [[ "$router_v4" -eq 1 && "$ipv4_masquerade" -ne 1 ]]; then
        KERNEL_GATE_FAILURE="IPv4 Tailscale router role lacks a MASQUERADE rule in nat/ts-postrouting"
        return 1
    fi
    if [[ "$router_v6" -eq 1 && "$ipv6_masquerade" -ne 1 ]]; then
        KERNEL_GATE_FAILURE="IPv6 Tailscale router role lacks a MASQUERADE rule in nat/ts-postrouting"
        return 1
    fi
    kernel_lock_report_line tailscale-router-masquerade "ipv4=${ipv4_masquerade};ipv6=${ipv6_masquerade}"
    return 0
}

preload_tailscale_kernel_modules() {
    local allow_load="${1:-1}" symbol module scope state loaded
    local unknown_config=0
    declare -A seen_modules=()
    while IFS=: read -r symbol module scope; do
        [[ -n "$symbol" ]] || continue
        state="$(kernel_config_value "$symbol")"
        loaded=no
        kernel_module_is_loaded "$module" && loaded=yes
        kernel_lock_report_line "$symbol" "${state};module=${module};scope=${scope};loaded=${loaded}"
        if [[ "$state" == unknown ]]; then
            unknown_config=1
            continue
        fi
        if [[ "$state" == module && -z "${seen_modules[$module]+present}" ]]; then
            seen_modules["$module"]=1
            if [[ "$loaded" == no ]]; then
                if [[ "$allow_load" -ne 1 ]]; then
                    kernel_lock_report_line "preloaded-${module}" blocked-already-locked
                    continue
                fi
                if ! modprobe "$module"; then
                    kernel_lock_fail "modprobe ${module} failed for ${symbol}"
                    return 1
                fi
                if ! kernel_module_is_loaded "$module"; then
                    kernel_lock_fail "${module} did not become loaded after modprobe"
                    return 1
                fi
                kernel_lock_report_line "preloaded-${module}" yes
            else
                kernel_lock_report_line "preloaded-${module}" already-loaded
            fi
        fi
    done <<'EOF'
CONFIG_NF_TABLES:nf_tables:common
CONFIG_NF_CONNTRACK:nf_conntrack:common
CONFIG_NF_NAT:nf_nat:common
CONFIG_NFT_NAT:nft_nat:nft
CONFIG_NFT_NAT:nft_chain_nat:nft
CONFIG_NFT_MASQ:nft_masq:nft
CONFIG_NFT_COMPAT:nft_compat:common
CONFIG_NETFILTER_XTABLES:x_tables:common
CONFIG_NETFILTER_XT_MARK:xt_mark:common
CONFIG_NETFILTER_XT_NAT:xt_nat:common
CONFIG_NETFILTER_XT_TARGET_MASQUERADE:xt_MASQUERADE:common
CONFIG_IP_NF_IPTABLES:ip_tables:ipv4
CONFIG_IP_NF_NAT:iptable_nat:ipv4
CONFIG_IP6_NF_IPTABLES:ip6_tables:ipv6
CONFIG_IP6_NF_NAT:ip6table_nat:ipv6
EOF
    if [[ "$unknown_config" -ne 0 && "$allow_load" -eq 1 ]]; then
        kernel_lock_fail "the running-kernel configuration could not be read"
        return 1
    fi
    return 0
}

kernel_module_preload_gate() {
    local module_control="${HARDEN_MODULES_DISABLED_PATH:-/proc/sys/kernel/modules_disabled}" before=""
    kernel_lock_report_start || { printf 'ERROR: cannot create kernel module preload diagnostic report\n' >&2; return 1; }
    before="$(tr -d '[:space:]' < "$module_control" 2>/dev/null || true)"
    kernel_lock_report_line stage preload-before-tailscaled
    kernel_lock_report_line modules-disabled-before "${before:-unknown}"
    if [[ "$before" != 0 ]]; then
        kernel_lock_fail "cannot preload Tailscale Netfilter prerequisites because kernel.modules_disabled is ${before:-unreadable}"
        return 1
    fi
    preload_tailscale_kernel_modules || return 1
    kernel_lock_report_line gate-result PRELOADED
    kernel_lock_report_finish || return 1
    printf 'OK: preloaded running-kernel Tailscale Netfilter/NAT prerequisites\n'
    return 0
}

kernel_lock_gate() {
    local module_control="${HARDEN_MODULES_DISABLED_PATH:-/proc/sys/kernel/modules_disabled}"
    local before="" tailscale_state=inactive attempts interval attempt
    kernel_lock_report_start || { printf 'ERROR: cannot create kernel module lock diagnostic report\n' >&2; return 1; }
    before="$(tr -d '[:space:]' < "$module_control" 2>/dev/null || true)"
    kernel_lock_report_line stage final-lock
    kernel_lock_report_line modules-disabled-before "${before:-unknown}"
    if systemctl is-active --quiet tailscaled.service 2>/dev/null; then tailscale_state=active; fi
    kernel_lock_report_line tailscale-service "$tailscale_state"
    if [[ "$before" == 1 ]]; then
        preload_tailscale_kernel_modules 0 || true
        kernel_lock_report_line module-preload skipped-already-locked
        if [[ "$tailscale_state" == active ]]; then
            if tailscale_kernel_runtime_ready; then
                kernel_lock_report_line already-locked-runtime-check OK
            else
                kernel_lock_report_line already-locked-runtime-check "FAILED; reboot-repair-required; ${KERNEL_GATE_FAILURE:-unknown}"
            fi
        else
            kernel_lock_report_line already-locked-runtime-check not-required-inactive
        fi
        kernel_lock_report_line gate-result already-locked-idempotent
        kernel_lock_report_finish || return 1
        printf 'INFO: kernel.modules_disabled is already 1; no module load was attempted\n'
        return 0
    fi
    [[ "$before" == 0 ]] || { kernel_lock_fail "kernel.modules_disabled runtime value is ${before:-unreadable}"; return 1; }
    if [[ "$tailscale_state" == active ]]; then
        preload_tailscale_kernel_modules || return 1
        attempts="${HARDEN_KERNEL_GATE_ATTEMPTS:-60}"
        interval="${HARDEN_KERNEL_GATE_INTERVAL:-1}"
        [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || attempts=60
        [[ "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || interval=1
        for ((attempt=1; attempt<=attempts; attempt++)); do
            if tailscale_kernel_runtime_ready; then
                kernel_lock_report_line runtime-attempt "$attempt"
                break
            fi
            if ((attempt == attempts)); then
                kernel_lock_fail "${KERNEL_GATE_FAILURE:-Tailscale runtime prerequisites remained unproven}"
                return 1
            fi
            sleep "$interval"
        done
    elif systemctl is-failed --quiet tailscaled.service 2>/dev/null \
        || systemctl is-failed --quiet kernel-module-netfilter-preload.service 2>/dev/null; then
        kernel_lock_fail "Tailscale or its Netfilter preload prerequisite failed during this boot"
        return 1
    else
        kernel_lock_report_line tailscale-runtime-check not-required-inactive
    fi
    if ! sysctl -w kernel.modules_disabled=1 >/dev/null \
        || [[ "$(tr -d '[:space:]' < "$module_control" 2>/dev/null || true)" != 1 ]]; then
        kernel_lock_fail "final kernel.modules_disabled=1 write or verification failed"
        return 1
    fi
    kernel_lock_report_line modules-disabled-after 1
    kernel_lock_report_line gate-result LOCKED
    kernel_lock_report_finish || return 1
    printf 'OK: verified runtime prerequisites and set kernel.modules_disabled=1\n'
    return 0
}

render_kernel_module_lock_helper() {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' "IFS=\$'\\n\\t'" 'umask 077'
    declare -f kernel_config_value kernel_module_is_loaded kernel_lock_report_start \
        kernel_lock_report_line kernel_lock_report_finish kernel_lock_fail \
        tailscale_kernel_runtime_ready preload_tailscale_kernel_modules \
        kernel_module_preload_gate kernel_lock_gate
    printf '%s\n' 'case "${1:-}" in --preload) kernel_module_preload_gate ;; "") kernel_lock_gate ;; *) exit 64 ;; esac'
}

render_kernel_module_lock_unit() {
    local module_control="$1" lock_helper="$2"
    cat <<EOF
[Unit]
Description=Late verified irreversible kernel module loading lock
Documentation=man:sysctl(8)
Wants=network-online.target
Requires=server-hardening-firewall.service
After=network-online.target server-hardening-firewall.service apparmor.service kernel-module-netfilter-preload.service tailscaled.service
ConditionPathExists=${module_control}

[Service]
Type=oneshot
ExecStart=${lock_helper}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

render_kernel_module_preload_unit() {
    local module_control="$1" lock_helper="$2"
    cat <<EOF
[Unit]
Description=Preload running-kernel Netfilter/NAT modules before Tailscale
Documentation=man:modprobe(8)
After=systemd-modules-load.service
Before=tailscaled.service
ConditionPathExists=${module_control}

[Service]
Type=oneshot
ExecStart=${lock_helper} --preload
RemainAfterExit=yes
EOF
}

render_tailscale_preload_dropin() {
    cat <<'EOF'
[Unit]
Requires=kernel-module-netfilter-preload.service
After=kernel-module-netfilter-preload.service
EOF
}

rollback_kernel_module_lock_install() {
    local lock_helper="$1" lock_unit="$2" preload_unit="$3" tailscale_dropin="$4"
    transaction_restore "$tailscale_dropin" tailscaled-netfilter-preload.conf
    transaction_restore "$preload_unit" kernel-module-netfilter-preload.service
    transaction_restore "$lock_unit" kernel-module-lockdown.service
    transaction_restore "$lock_helper" kernel-module-lockdown-helper
    run_streamed systemctl daemon-reload || true
}

prepare_kernel_module_lock() {
    local module_control="${HARDEN_MODULES_DISABLED_PATH:-/proc/sys/kernel/modules_disabled}"
    local lock_unit="${HARDEN_MODULE_LOCK_UNIT:-/etc/systemd/system/kernel-module-lockdown.service}"
    local lock_helper="${HARDEN_MODULE_LOCK_HELPER:-/usr/local/libexec/server-hardening/kernel-module-lockdown}"
    local preload_unit="${HARDEN_MODULE_PRELOAD_UNIT:-/etc/systemd/system/kernel-module-netfilter-preload.service}"
    local tailscale_dropin="${HARDEN_TAILSCALE_PRELOAD_DROPIN:-/etc/systemd/system/tailscaled.service.d/99-netfilter-module-preload.conf}"
    local candidate changed=0 enabled_state="" tailscale_unit=0
    if [[ "$AGGRESSIVE" -ne 1 || ! -e "$module_control" ]]; then
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would install the late prerequisite/preload verifier and lock unit without enabling or starting them before the final gate"
        return 0
    fi
    transaction_copy "$lock_helper" kernel-module-lockdown-helper
    transaction_copy "$lock_unit" kernel-module-lockdown.service
    transaction_copy "$preload_unit" kernel-module-netfilter-preload.service
    transaction_copy "$tailscale_dropin" tailscaled-netfilter-preload.conf
    candidate="$(mktemp)"
    render_kernel_module_lock_helper > "$candidate"
    if ! install_managed_file "$lock_helper" 0755 < "$candidate"; then
        rm -f -- "$candidate"
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "late-lock helper installation failed and was rolled back"
        return 1
    fi
    rm -f -- "$candidate"
    [[ "$MANAGED_FILE_CHANGED" -eq 0 ]] || changed=1
    candidate="$(mktemp --suffix=.service)"
    render_kernel_module_lock_unit "$module_control" "$lock_helper" > "$candidate"
    if ! systemd_verify_unit "$candidate"; then
        rm -f -- "$candidate"
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "candidate late-lock unit failed systemd-analyze verify"
        return 1
    fi
    if ! install_managed_file "$lock_unit" 0644 < "$candidate"; then
        rm -f -- "$candidate"
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "late-lock unit installation failed and was rolled back"
        return 1
    fi
    [[ "$MANAGED_FILE_CHANGED" -eq 0 ]] || changed=1
    rm -f -- "$candidate"
    if unit_file_exists tailscaled.service; then
        tailscale_unit=1
        candidate="$(mktemp --suffix=.service)"
        render_kernel_module_preload_unit "$module_control" "$lock_helper" > "$candidate"
        if ! systemd_verify_unit "$candidate"; then
            rm -f -- "$candidate"
            rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
            record_skip "kernel.modules_disabled" "candidate Tailscale Netfilter preload unit failed systemd-analyze verify"
            return 1
        fi
        if ! install_managed_file "$preload_unit" 0644 < "$candidate"; then
            rm -f -- "$candidate"
            rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
            record_skip "kernel.modules_disabled" "Tailscale Netfilter preload unit installation failed and was rolled back"
            return 1
        fi
        [[ "$MANAGED_FILE_CHANGED" -eq 0 ]] || changed=1
        rm -f -- "$candidate"
        candidate="$(mktemp)"
        render_tailscale_preload_dropin > "$candidate"
        if ! install_managed_file "$tailscale_dropin" 0644 < "$candidate"; then
            rm -f -- "$candidate"
            rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
            record_skip "kernel.modules_disabled" "Tailscale preload drop-in installation failed and was rolled back"
            return 1
        fi
        rm -f -- "$candidate"
        [[ "$MANAGED_FILE_CHANGED" -eq 0 ]] || changed=1
    fi
    if ! systemd_verify_unit "$lock_unit"; then
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "installed late-lock unit failed systemd-analyze verify"
        return 1
    fi
    if [[ "$tailscale_unit" -eq 1 ]] && { ! systemd_verify_unit "$preload_unit" \
        || ! systemd_verify_unit tailscaled.service; }; then
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "installed Tailscale preload unit/drop-in failed systemd-analyze verify"
        return 1
    fi
    if [[ "$changed" -eq 1 ]] && ! run_streamed systemctl daemon-reload; then
        rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
        record_skip "kernel.modules_disabled" "late lock unit could not be loaded; runtime locking will be skipped"
        return 1
    fi
    if [[ "$(tr -d '[:space:]' < "$module_control" 2>/dev/null || true)" != 1 ]]; then
        enabled_state="$(systemctl is-enabled kernel-module-lockdown.service 2>/dev/null || true)"
        if [[ "$enabled_state" != disabled && "$enabled_state" != masked ]] \
            && ! systemctl disable kernel-module-lockdown.service >/dev/null 2>&1; then
            rollback_kernel_module_lock_install "$lock_helper" "$lock_unit" "$preload_unit" "$tailscale_dropin"
            record_skip "kernel.modules_disabled" "could not disable the late lock unit before final prerequisite validation"
            return 1
        fi
    fi
    if [[ "$changed" -eq 1 ]]; then
        record_change "Installed and verified deterministic pre-tailscaled Netfilter preload plus the Tailscale-aware late kernel module lock helper/unit"
    else
        log INFO "Late kernel module lock helper and unit are already current and verified"
    fi
    return 0
}

lock_kernel_modules_late() {
    local module_control="${HARDEN_MODULES_DISABLED_PATH:-/proc/sys/kernel/modules_disabled}"
    local lock_unit="${HARDEN_MODULE_LOCK_UNIT:-/etc/systemd/system/kernel-module-lockdown.service}"
    local lock_helper="${HARDEN_MODULE_LOCK_HELPER:-/usr/local/libexec/server-hardening/kernel-module-lockdown}"
    local report="${HARDEN_KERNEL_LOCK_REPORT:-/root/kernel-module-lockdown-report.txt}"
    local enabled_state=""
    if [[ "$AGGRESSIVE" -ne 1 ]]; then
        record_skip "kernel.modules_disabled" "requires --aggressive because the change is irreversible until reboot"
        return 0
    fi
    if [[ ! -e "$module_control" ]]; then
        record_skip "kernel.modules_disabled" "the running kernel does not expose this control"
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log WARN "Would preload only running-kernel Netfilter/NAT modules needed by active Tailscale, verify dual-stack runtime health, then set kernel.modules_disabled=1 at the final gate"
        return 0
    fi
    if [[ "$CURRENT_PHASE" -ne 17 || "$NETWORK_HARDENING_COMPLETED" -ne 1 \
        || "$FIREWALL_COMPLETED" -ne 1 || "$APPARMOR_COMPLETED" -ne 1 \
        || "$VALIDATION_COMPLETED" -ne 1 || "$AIDE_STATUS" != "OK" ]]; then
        record_skip "kernel.modules_disabled" "final prerequisite gate failed (phase=${CURRENT_PHASE}, network=${NETWORK_HARDENING_COMPLETED}, firewall=${FIREWALL_COMPLETED}, AppArmor=${APPARMOR_COMPLETED}, validation=${VALIDATION_COMPLETED}, AIDE=${AIDE_STATUS})"
        return 1
    fi
    [[ -f "$lock_unit" && -x "$lock_helper" ]] \
        || { record_skip "kernel.modules_disabled" "late lock unit/helper preparation was not completed"; return 1; }
    enabled_state="$(systemctl is-enabled kernel-module-lockdown.service 2>/dev/null || true)"
    if [[ "$enabled_state" != enabled ]] && ! run_streamed systemctl enable kernel-module-lockdown.service; then
        record_skip "kernel.modules_disabled" "could not enable the verified late-boot unit"
        return 1
    fi
    log WARN "Final irreversible step: verifying Tailscale/netfilter prerequisites before disabling further kernel module loading until reboot"
    if ! run_streamed kernel_lock_gate; then
        [[ ! -f "$report" || -z "$BACKUP_DIR" ]] || cp -a -- "$report" "$BACKUP_DIR/kernel-module-lockdown-report.txt"
        record_skip "kernel.modules_disabled" "the Tailscale/netfilter-aware final gate failed; module loading remains enabled and the failure is recorded in ${report}"
        return 1
    fi
    [[ ! -f "$report" || -z "$BACKUP_DIR" ]] || cp -a -- "$report" "$BACKUP_DIR/kernel-module-lockdown-report.txt"
    if [[ "$(tr -d '[:space:]' < "$module_control" 2>/dev/null || true)" != 1 ]]; then
        record_skip "kernel.modules_disabled" "the helper returned success but runtime verification is not 1"
        return 1
    fi
    if grep -Fq 'gate-result=already-locked-idempotent' "$report" 2>/dev/null; then
        log INFO "Kernel module loading was already locked; verified runtime value 1 without modprobe and retained the late-boot unit"
    else
        record_change "Preloaded running-kernel Tailscale NAT prerequisites, validated dual-stack netfilter health, then set and verified kernel.modules_disabled=1"
    fi
    return 0
}

detect_ssh_context() {
    SSHD_BIN="$(command -v sshd 2>/dev/null || true)"
    if unit_file_exists ssh.service; then
        SSH_SERVICE="ssh.service"
    elif unit_file_exists sshd.service; then
        SSH_SERVICE="sshd.service"
    fi
    if [[ -n "$SSHD_BIN" ]] && "$SSHD_BIN" -T >/dev/null 2>&1; then
        local sshd_effective
        sshd_effective="$("$SSHD_BIN" -T 2>/dev/null)"
        SSH_PORT="$(awk '$1 == "port" && port == "" {port=$2} END {print port}' <<<"$sshd_effective")"
    fi
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local connection_port
        connection_port="$(awk '{print $4}' <<<"$SSH_CONNECTION")"
        [[ "$connection_port" =~ ^[0-9]+$ ]] && SSH_PORT="$connection_port"
    fi
    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || SSH_PORT=22

    local candidate="${SUDO_USER:-}"
    if [[ -n "$candidate" && "$candidate" != "root" ]] && id "$candidate" >/dev/null 2>&1; then
        if command -v sudo >/dev/null 2>&1 && sudo -n -l -U "$candidate" >/dev/null 2>&1; then
            ADMIN_USER="$candidate"
        fi
    fi
    if [[ -z "$ADMIN_USER" ]]; then
        local members user
        members="$(getent group sudo 2>/dev/null | cut -d: -f4 || true)"
        IFS=',' read -r -a sudo_members <<< "$members"
        for user in "${sudo_members[@]:-}"; do
            [[ -n "$user" ]] || continue
            if command -v sudo >/dev/null 2>&1 && sudo -n -l -U "$user" >/dev/null 2>&1; then
                ADMIN_USER="$user"
                break
            fi
        done
    fi
    if [[ -n "$ADMIN_USER" ]]; then
        local home authkeys
        home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
        authkeys="$home/.ssh/authorized_keys"
        if [[ -f "$authkeys" ]] && grep -Eq '^[[:space:]]*(sk-|ssh-|ecdsa-)' "$authkeys"; then
            ADMIN_KEY_READY=1
        fi
    fi
    log INFO "SSH context: service=${SSH_SERVICE:-none}, local port=${SSH_PORT}, admin=${ADMIN_USER:-none}, admin-key=${ADMIN_KEY_READY}"
}

supported_ssh_list() {
    local query="$1"
    shift
    local available item output=""
    available="$(ssh -Q "$query" 2>/dev/null || true)"
    if [[ -z "$available" && "$query" == "HostKeyAlgorithms" ]]; then
        available="$(ssh -Q key 2>/dev/null || true)"
    fi
    for item in "$@"; do
        if grep -Fxq "$item" <<< "$available"; then
            output+="${output:+,}${item}"
        fi
    done
    printf '%s' "$output"
}

render_server_hardening_firewall_unit() {
    cat <<'EOF'
[Unit]
Description=Server hardening owned nftables table
Wants=network-pre.target
Before=network-pre.target
After=nftables.service

[Service]
Type=oneshot
ExecStartPre=-/usr/sbin/nft delete table inet hardening_filter
ExecStart=/usr/sbin/nft -f /etc/nftables.d/99-security-hardening.nft
ExecReload=/bin/sh -c '/usr/sbin/nft delete table inet hardening_filter 2>/dev/null || true; exec /usr/sbin/nft -f /etc/nftables.d/99-security-hardening.nft'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

configure_firewall() {
    if ! command -v nft >/dev/null 2>&1; then
        FIREWALL_STATUS="FAILED"
        record_skip "firewall" "nft binary unavailable after package checks"
        return 0
    fi
    local tailscale_input="" tailscale_forward="" wireguard_rule="" tailscale_healthy_before=0
    if systemctl is-active --quiet tailscaled.service 2>/dev/null; then
        tailscale_input=$'        iifname "tailscale0" accept comment "preserve Tailscale administration"\n        udp dport 41641 accept comment "Tailscale WireGuard transport"'
        tailscale_forward=$'        iifname "tailscale0" accept comment "preserve Tailscale forwarding"\n        oifname "tailscale0" accept comment "preserve Tailscale forwarding"'
        if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
            tailscale_healthy_before=1
        fi
    fi
    if ip link show wg0 >/dev/null 2>&1; then
        wireguard_rule=$'        iifname "wg0" accept comment "preserve WireGuard administration"'
    fi

    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would validate and install only the owned inet hardening_filter table with SSH port ${SSH_PORT} allowed"
        log INFO "Would leave all Tailscale, iptables-nft, UFW, firewalld, and unrelated nftables tables untouched"
        [[ -n "$tailscale_input" ]] && log INFO "Would preserve Tailscale input, forwarding, and UDP transport traffic"
        return 0
    fi

    local candidate check_candidate unit_candidate own_before="" unit_ready=0
    candidate="$(mktemp)"
    check_candidate="$(mktemp)"
    cat > "$candidate" <<EOF
#!/usr/sbin/nft -f
table inet hardening_filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
        iifname "lo" accept
${tailscale_input}
${wireguard_rule}
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem, echo-request, echo-reply } limit rate 20/second burst 40 packets accept
        ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, echo-request, echo-reply } limit rate 50/second burst 100 packets accept
        tcp dport ${SSH_PORT} ct state new limit rate 30/minute burst 20 packets accept comment "administrative SSH"
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        ct state established,related accept
${tailscale_forward}
${wireguard_rule}
        counter drop
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
    sed "s/hardening_filter/hardening_filter_validate_$$/g" "$candidate" > "$check_candidate"
    if ! run_streamed nft -c -f "$check_candidate"; then
        rm -f "$candidate" "$check_candidate"
        FIREWALL_STATUS="FAILED"
        die "Candidate owned nftables table failed validation; all live firewall tables are untouched"
    fi
    rm -f "$check_candidate"

    unit_candidate="$(mktemp --suffix=.service)"
    render_server_hardening_firewall_unit > "$unit_candidate"
    if ! systemd_verify_unit "$unit_candidate"; then
        rm -f -- "$candidate" "$unit_candidate"
        FIREWALL_STATUS="FAILED"
        die "Candidate server-hardening-firewall.service failed systemd-analyze verify; live firewall state is untouched"
    fi

    transaction_copy /etc/nftables.d/99-security-hardening.nft nftables-hardening-table.nft
    transaction_copy /etc/systemd/system/server-hardening-firewall.service firewall-service
    if nft list table inet hardening_filter > "$BACKUP_DIR/nftables-hardening-table-before.nft" 2>/dev/null; then
        own_before="$BACKUP_DIR/nftables-hardening-table-before.nft"
    fi
    install -d -o root -g root -m 0755 /etc/nftables.d
    install -o root -g root -m 0600 "$candidate" /etc/nftables.d/99-security-hardening.nft
    rm -f "$candidate"
    if ! install_managed_file /etc/systemd/system/server-hardening-firewall.service 0644 < "$unit_candidate"; then
        rm -f -- "$unit_candidate"
        log ERROR "Could not install the verified server-hardening-firewall.service"
    elif ! systemd_verify_unit /etc/systemd/system/server-hardening-firewall.service; then
        rm -f -- "$unit_candidate"
        log ERROR "Installed server-hardening-firewall.service failed systemd-analyze verify"
    elif run_streamed systemctl daemon-reload; then
        rm -f -- "$unit_candidate"
        nft delete table inet hardening_filter 2>/dev/null || true
        unit_ready=1
    else
        rm -f -- "$unit_candidate"
        log ERROR "systemd daemon-reload failed after firewall service installation"
    fi
    if [[ "$unit_ready" -eq 1 ]] \
        && run_streamed nft -f /etc/nftables.d/99-security-hardening.nft \
        && nft list chain inet hardening_filter input >/dev/null 2>&1 \
        && run_streamed systemctl enable server-hardening-firewall.service \
        && run_streamed systemctl restart server-hardening-firewall.service; then
        if [[ "$tailscale_healthy_before" -eq 1 ]] && ! tailscale status >/dev/null 2>&1; then
            log ERROR "Tailscale health check failed after loading the owned table"
        else
            FIREWALL_STATUS="OK (owned table; other tables preserved)"
            record_change "Activated persistent owned dual-stack nftables table; SSH ${SSH_PORT}/tcp and Tailscale paths remain allowed"
            return 0
        fi
    fi

    nft delete table inet hardening_filter 2>/dev/null || true
    [[ -n "$own_before" ]] && nft -f "$own_before" || true
    if [[ -e "$BACKUP_DIR/transactions/firewall-service.absent" ]]; then
        systemctl disable server-hardening-firewall.service >/dev/null 2>&1 || true
    fi
    transaction_restore /etc/nftables.d/99-security-hardening.nft nftables-hardening-table.nft
    transaction_restore /etc/systemd/system/server-hardening-firewall.service firewall-service
    run_streamed systemctl daemon-reload
    FIREWALL_STATUS="FAILED/OWNED TABLE ROLLED BACK"
    die "Owned nftables table failed activation or health validation; unrelated tables were never modified"
}

harden_ssh() {
    if [[ -z "$SSHD_BIN" || -z "$SSH_SERVICE" ]]; then
        SSH_STATUS="NOT INSTALLED"
        log INFO "SSH daemon not present; SSH configuration skipped"
        return 0
    fi
    local ciphers macs kex hostkeys
    ciphers="$(supported_ssh_list cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)"
    macs="$(supported_ssh_list mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256)"
    kex="$(supported_ssh_list kex sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com mlkem768x25519-sha256 curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group16-sha512 diffie-hellman-group18-sha512)"
    hostkeys="$(supported_ssh_list HostKeyAlgorithms ssh-ed25519 sk-ssh-ed25519@openssh.com rsa-sha2-512 rsa-sha2-256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp256)"
    record_skip "SSH-7408:Port" "SSH port intentionally preserved; changing the port is not considered a meaningful security control for this deployment."

    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would harden SSH without writing a Port directive; detected port ${SSH_PORT} is used only by the firewall and Fail2ban"
        if [[ -n "$ADMIN_USER" && "$ADMIN_KEY_READY" -eq 1 ]]; then
            log INFO "Would disable root and password SSH login; verified sudo admin key: ${ADMIN_USER}"
        else
            log WARN "Would preserve the current password/root recovery path because no key-ready non-root sudo admin was proven"
        fi
        return 0
    fi

    install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        local main_tmp
        main_tmp="$(mktemp)"
        {
            printf 'Include /etc/ssh/sshd_config.d/*.conf\n'
            cat /etc/ssh/sshd_config
        } > "$main_tmp"
        transaction_copy /etc/ssh/sshd_config sshd_config
        install -o root -g root -m 0600 "$main_tmp" /etc/ssh/sshd_config
        rm -f "$main_tmp"
    fi
    transaction_copy /etc/ssh/sshd_config.d/99-hardening.conf sshd-hardening.conf
    {
        cat <<EOF
# Managed by harden.sh
AddressFamily any
LogLevel VERBOSE
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
HostbasedAuthentication no
IgnoreRhosts yes
UseDNS no
Compression no
StrictModes yes
PrintLastLog yes
Banner /etc/issue.net
RekeyLimit 512M 1h
EOF
        [[ -n "$ciphers" ]] && printf 'Ciphers %s\n' "$ciphers"
        [[ -n "$macs" ]] && printf 'MACs %s\n' "$macs"
        [[ -n "$kex" ]] && printf 'KexAlgorithms %s\n' "$kex"
        [[ -n "$hostkeys" ]] && printf 'HostKeyAlgorithms %s\n' "$hostkeys"
        if [[ -n "$ADMIN_USER" ]]; then
            printf 'PermitRootLogin no\n'
        fi
        if [[ -n "$ADMIN_USER" && "$ADMIN_KEY_READY" -eq 1 ]]; then
            printf 'PasswordAuthentication no\n'
        fi
    } | install_managed_file /etc/ssh/sshd_config.d/99-hardening.conf 0600

    chmod 0600 /etc/ssh/sshd_config
    find /etc/ssh/sshd_config.d -maxdepth 1 -type f -exec chmod 0600 {} +
    find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -exec chmod 0600 {} +
    find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} +

    if ! "$SSHD_BIN" -t; then
        transaction_restore /etc/ssh/sshd_config.d/99-hardening.conf sshd-hardening.conf
        [[ -e "$BACKUP_DIR/transactions/sshd_config" || -e "$BACKUP_DIR/transactions/sshd_config.absent" ]] \
            && transaction_restore /etc/ssh/sshd_config sshd_config
        SSH_STATUS="FAILED/ROLLED BACK"
        die "sshd rejected the hardening configuration; previous SSH configuration restored"
    fi
    local hardening_input
    hardening_input="$(nft list chain inet hardening_filter input 2>/dev/null || true)"
    if ! grep -Eq "tcp dport ${SSH_PORT}([^0-9]|$)" <<<"$hardening_input"; then
        SSH_STATUS="FAILED"
        die "Firewall does not visibly allow the active SSH port ${SSH_PORT}; refusing to reload SSH"
    fi
    if run_streamed systemctl reload "$SSH_SERVICE" && systemctl is-active --quiet "$SSH_SERVICE" && "$SSHD_BIN" -t; then
        SSH_STATUS="OK"
        record_change "Validated and reloaded hardened SSH configuration without terminating existing sessions"
        if [[ -z "$ADMIN_USER" ]]; then
            record_skip "PermitRootLogin" "no functional non-root sudo administrator was proven, so the existing setting was retained"
        elif [[ "$ADMIN_KEY_READY" -eq 0 ]]; then
            record_skip "PasswordAuthentication" "administrator ${ADMIN_USER} has no proven authorized_keys entry; password login was retained"
        fi
    else
        transaction_restore /etc/ssh/sshd_config.d/99-hardening.conf sshd-hardening.conf
        [[ -e "$BACKUP_DIR/transactions/sshd_config" || -e "$BACKUP_DIR/transactions/sshd_config.absent" ]] \
            && transaction_restore /etc/ssh/sshd_config sshd_config
        run_streamed systemctl reload "$SSH_SERVICE" || true
        SSH_STATUS="FAILED/ROLLED BACK"
        die "SSH reload/health check failed; prior configuration restored"
    fi
}

verify_fail2ban_runtime() {
    local attempts="${1:-1}" attempt ping_output="" jail_output="" report=""
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        FAIL2BAN_STATUS="NOT AVAILABLE"
        return 1
    fi
    [[ -z "$BACKUP_DIR" ]] || report="$BACKUP_DIR/fail2ban-runtime.txt"
    for ((attempt=1; attempt<=attempts; attempt++)); do
        ping_output="$(fail2ban-client ping 2>&1 || true)"
        jail_output="$(fail2ban-client status sshd 2>&1 || true)"
        if systemctl is-active --quiet fail2ban.service \
            && grep -Eiq 'pong|server replied' <<<"$ping_output" \
            && grep -Eiq 'status for the jail:[[:space:]]*sshd|jail.*sshd' <<<"$jail_output"; then
            FAIL2BAN_STATUS="OK"
            [[ -z "$report" ]] || {
                printf 'verified=%s\nping=%s\n%s\n' "$(timestamp)" "$ping_output" "$jail_output" > "$report"
                chmod 0600 "$report"
            }
            return 0
        fi
        ((attempt == attempts)) || sleep 1
    done
    FAIL2BAN_STATUS="FAILED"
    [[ -z "$report" ]] || {
        printf 'failed=%s\nping=%s\n%s\n' "$(timestamp)" "$ping_output" "$jail_output" > "$report"
        chmod 0600 "$report"
    }
    return 1
}

configure_fail2ban() {
    if ! command -v fail2ban-client >/dev/null 2>&1 || [[ -z "$SSH_SERVICE" ]]; then
        FAIL2BAN_STATUS="NOT AVAILABLE"
        return 0
    fi
    local banaction="nftables-multiport"
    [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]] || banaction="nftables"
    transaction_copy /etc/fail2ban/jail.local fail2ban-global.local
    transaction_copy /etc/fail2ban/jail.d/99-sshd-hardening.local fail2ban-jail.local
    install_managed_file /etc/fail2ban/jail.local 0640 <<EOF
# Managed by harden.sh. Site-wide update-safe overrides; vendor jail.conf is unchanged.
[DEFAULT]
backend = systemd
banaction = ${banaction}
bantime = 1h
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w
EOF
    install_managed_file /etc/fail2ban/jail.d/99-sshd-hardening.local 0640 <<EOF
# Managed by harden.sh. SSH-specific override.
[sshd]
enabled = true
port = ${SSH_PORT}
mode = aggressive
maxretry = 4
EOF
    if [[ "$MODE" == "dry-run" ]]; then
        FAIL2BAN_STATUS="PLANNED"
        return 0
    fi
    if run_streamed fail2ban-client -t \
        && run_streamed systemctl enable --now fail2ban.service \
        && run_streamed systemctl restart fail2ban.service; then
        if verify_fail2ban_runtime 10; then
            record_change "Enabled and validated Fail2ban SSH jail using nftables"
        else
            record_skip "DEB-0880" "Fail2ban started but its socket/sshd jail did not become verifiably ready; see ${BACKUP_DIR}/fail2ban-runtime.txt"
        fi
    else
        transaction_restore /etc/fail2ban/jail.local fail2ban-global.local
        transaction_restore /etc/fail2ban/jail.d/99-sshd-hardening.local fail2ban-jail.local
        run_streamed systemctl restart fail2ban.service || true
        FAIL2BAN_STATUS="FAILED/ROLLED BACK"
        log ROLLBACK "Fail2ban configuration failed validation or startup"
    fi
}

configure_password_policy() {
    [[ -f /etc/login.defs ]] || return 0
    replace_setting /etc/login.defs PASS_MAX_DAYS 90
    replace_setting /etc/login.defs PASS_MIN_DAYS 1
    replace_setting /etc/login.defs PASS_WARN_AGE 14
    replace_setting /etc/login.defs UMASK 027
    replace_setting /etc/login.defs LOGIN_RETRIES 5
    replace_setting /etc/login.defs LOGIN_TIMEOUT 60
    local chpasswd_help=""
    if command -v chpasswd >/dev/null 2>&1; then
        chpasswd_help="$(chpasswd --help 2>&1 || true)"
    fi
    if grep -F 'YESCRYPT' <<<"$chpasswd_help" >/dev/null; then
        replace_setting /etc/login.defs ENCRYPT_METHOD YESCRYPT
        remove_setting /etc/login.defs SHA_CRYPT_MIN_ROUNDS
        remove_setting /etc/login.defs SHA_CRYPT_MAX_ROUNDS
        record_skip "AUTH-9230" "Lynis 3.1.6 asks for SHA_CRYPT rounds even with YESCRYPT; meaningless SHA settings were intentionally not score-gamed"
    else
        replace_setting /etc/login.defs ENCRYPT_METHOD SHA512
        replace_setting /etc/login.defs SHA_CRYPT_MIN_ROUNDS 100000
        replace_setting /etc/login.defs SHA_CRYPT_MAX_ROUNDS 200000
    fi

    install_managed_file /etc/profile.d/99-security-umask.sh 0644 <<'EOF'
# Managed by harden.sh: restrictive default for interactive shell sessions.
umask 027
EOF

    install_managed_file /etc/security/pwquality.conf.d/99-hardening.conf 0644 <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 4
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF
    local faillock_module
    faillock_module="$(find /lib /usr/lib -path '*/security/pam_faillock.so' -print -quit 2>/dev/null || true)"
    if [[ -e /etc/security/faillock.conf || -n "$faillock_module" ]]; then
        install_managed_file /etc/security/faillock.conf 0644 <<'EOF'
deny = 5
fail_interval = 900
unlock_time = 900
audit
silent
local_users_only
EOF
    fi
}

insert_pam_before_unix() {
    local file="$1" line="$2" marker="$3"
    [[ -f "$file" ]] || return 1
    if grep -Fq "$marker" "$file"; then return 0; fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would insert ${marker} before the first pam_unix.so entry in ${file}"
        return 0
    fi
    local temporary
    temporary="$(mktemp)"
    awk -v newline="$line" -v marker="$marker" '
        !done && $0 ~ /pam_unix\.so/ { print "# " marker; print newline; done=1 }
        { print }
        END { if (!done) exit 42 }
    ' "$file" > "$temporary" || { rm -f "$temporary"; return 1; }
    install -o root -g root -m 0644 "$temporary" "$file"
    rm -f "$temporary"
    record_change "Inserted ${marker} in ${file}"
}

configure_pam() {
    configure_password_policy
    if [[ ! -f /etc/pam.d/common-password ]]; then
        PAM_STATUS="SKIPPED"
        record_skip "PAM" "Debian-family common-password file not found"
        return 0
    fi
    if [[ "$MODE" == "apply" ]] && command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package || true
    fi
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password; then
        if [[ -n "$(find /lib /usr/lib -path '*/security/pam_pwquality.so' -print -quit 2>/dev/null || true)" ]]; then
            insert_pam_before_unix /etc/pam.d/common-password \
                'password requisite pam_pwquality.so retry=3' 'harden.sh:pam_pwquality' \
                || record_skip "AUTH-9262" "could not safely place pam_pwquality before pam_unix"
        else
            record_skip "AUTH-9262" "pam_pwquality module is unavailable; common-password was not changed"
        fi
    fi
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwhistory\.so' /etc/pam.d/common-password; then
        if [[ -n "$(find /lib /usr/lib -path '*/security/pam_pwhistory.so' -print -quit 2>/dev/null || true)" ]]; then
            insert_pam_before_unix /etc/pam.d/common-password \
                'password required pam_pwhistory.so use_authtok remember=24 enforce_for_root' 'harden.sh:pam_pwhistory' \
                || record_skip "password history" "could not safely place pam_pwhistory before pam_unix"
        else
            record_skip "password history" "pam_pwhistory module is unavailable; common-password was not changed"
        fi
    fi

    configure_faillock_stack
    if [[ "$MODE" == "apply" ]]; then
        local pam_file
        for pam_file in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password; do
            [[ -f "$pam_file" ]] && chmod 0644 "$pam_file"
        done
        if grep -Eq 'pam_pwquality\.so' /etc/pam.d/common-password \
            && grep -Eq 'pam_pwhistory\.so' /etc/pam.d/common-password; then
            PAM_STATUS="OK"
        else
            PAM_STATUS="PARTIAL"
        fi
    else
        PAM_STATUS="PLANNED"
    fi
}

configure_faillock_stack() {
    local auth=/etc/pam.d/common-auth account=/etc/pam.d/common-account module=""
    module="$(find /lib /usr/lib -path '*/security/pam_faillock.so' -print -quit 2>/dev/null || true)"
    if [[ -z "$module" || ! -f "$auth" || ! -f "$account" ]]; then
        record_skip "failed login accounting" "pam_faillock module or Debian common PAM stack is unavailable"
        return 0
    fi
    if grep -q 'pam_faillock\.so' "$auth" && grep -q 'pam_faillock\.so' "$account"; then
        log INFO "pam_faillock is already active"
        return 0
    fi
    if grep -q 'pam_faillock\.so' "$auth" || grep -q 'pam_faillock\.so' "$account"; then
        record_skip "failed login accounting" "a partial pre-existing pam_faillock integration needs administrator review"
        return 0
    fi
    local unix_count unix_line jump
    unix_count="$(grep -Ec '^[[:space:]]*auth[[:space:]]+\[success=[0-9]+[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so' "$auth" || true)"
    unix_line="$(awk '/^[[:space:]]*auth[[:space:]]+\[success=[0-9]+[[:space:]]+default=ignore\][[:space:]]+pam_unix\.so/ && first == "" {first=NR ":" $0} END {print first}' "$auth")"
    if [[ "$unix_count" != "1" || -z "$unix_line" ]]; then
        record_skip "failed login accounting" "common-auth has a nonstandard control stack; direct mutation would risk authentication lockout"
        return 0
    fi
    jump="$(sed -n 's/.*\[success=\([0-9][0-9]*\)[[:space:]].*/\1/p' <<<"$unix_line")"
    [[ "$jump" =~ ^[0-9]+$ ]] || { record_skip "failed login accounting" "could not derive PAM success jump"; return 0; }
    if [[ "$MODE" == "dry-run" ]]; then
        log WARN "Would transactionally add pam_faillock to the recognized Debian/Ubuntu common PAM stack"
        return 0
    fi
    transaction_copy "$auth" pam-common-auth
    transaction_copy "$account" pam-common-account
    local auth_tmp account_tmp new_jump=$((jump + 2))
    auth_tmp="$(mktemp)"
    account_tmp="$(mktemp)"
    awk -v old="$jump" -v new="$new_jump" '
        !done && $0 ~ "^[[:space:]]*auth[[:space:]]+\\[success=" old "[[:space:]]+default=ignore\\][[:space:]]+pam_unix\\.so" {
            print "# harden.sh:pam_faillock-preauth"
            print "auth required pam_faillock.so preauth"
            sub("success=" old, "success=" new)
            print
            print "# harden.sh:pam_faillock-authfail"
            print "auth [default=die] pam_faillock.so authfail"
            print "auth sufficient pam_faillock.so authsucc"
            done=1
            next
        }
        { print }
        END { if (!done) exit 42 }
    ' "$auth" > "$auth_tmp" || {
        rm -f "$auth_tmp" "$account_tmp"
        record_skip "failed login accounting" "PAM auth transformation did not match exactly"
        return 0
    }
    awk '
        BEGIN { print "# harden.sh:pam_faillock-account"; print "account required pam_faillock.so" }
        { print }
    ' "$account" > "$account_tmp"
    install -o root -g root -m 0644 "$auth_tmp" "$auth"
    install -o root -g root -m 0644 "$account_tmp" "$account"
    rm -f "$auth_tmp" "$account_tmp"
    if grep -q 'pam_faillock\.so authfail' "$auth" && grep -q '^account required pam_faillock\.so' "$account"; then
        record_change "Enabled pam_faillock with a bounded 15-minute lockout"
    else
        transaction_restore "$auth" pam-common-auth
        transaction_restore "$account" pam-common-account
        record_skip "failed login accounting" "post-write verification failed and PAM files were restored"
    fi
}

configure_account_aging() {
    local passwd_file="${HARDEN_PASSWD_FILE:-/etc/passwd}"
    local login_defs="${HARDEN_LOGIN_DEFS:-/etc/login.defs}"
    if [[ ! -r "$passwd_file" ]]; then
        record_skip "account aging" "${passwd_file} is unavailable"
        return 0
    fi
    local uid_min
    uid_min="$(awk '$1 == "UID_MIN" {print $2; exit}' "$login_defs" 2>/dev/null || true)"
    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000
    local user uid shell shadow_line shadow_hash shadow_min shadow_max shadow_warn shadow_inactive
    while IFS=: read -r user _ uid _ _ _ shell; do
        ((uid >= uid_min)) || continue
        case "$shell" in */nologin|*/false) continue ;; esac
        shadow_line="$(getent shadow "$user" 2>/dev/null || true)"
        IFS=: read -r _ shadow_hash _ shadow_min shadow_max shadow_warn shadow_inactive _ _ <<<"$shadow_line"
        [[ -n "$shadow_hash" && "$shadow_hash" != '!'* && "$shadow_hash" != '*'* ]] || continue
        if [[ "$shadow_min" == 1 && "$shadow_max" == 90 && "$shadow_warn" == 14 && "$shadow_inactive" == 30 ]]; then
            log INFO "Account aging already current for ${user}"
        else
            run chage --mindays 1 --maxdays 90 --warndays 14 --inactive 30 "$user"
        fi
        record_skip "AUTH-9282:${user}" "fixed account expiration is intentionally not set; password aging and a 30-day inactive period are enforced"
    done < "$passwd_file"
}

configure_sudo() {
    if ! command -v visudo >/dev/null 2>&1; then
        record_skip "sudo hardening" "visudo is unavailable"
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would build a temporary sudoers policy, require the four portable defaults, probe every optional feature with visudo -cf, and install only the validated result"
        return 0
    fi
    if ! visudo -c; then
        die "Existing sudo configuration is invalid; refusing to modify it"
    fi
    local candidate probe option sudo_log_enabled=0 sudo_iolog_enabled=0
    local -a accepted_options=(
        'Defaults use_pty'
        'Defaults env_reset'
        'Defaults passwd_timeout=1'
        'Defaults timestamp_timeout=5'
    )
    local -a optional_options=(
        'Defaults always_set_home'
        'Defaults match_group_by_gid'
        'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
        'Defaults passwd_tries=3'
        'Defaults umask=0027'
        'Defaults umask_override'
        'Defaults !visiblepw'
        'Defaults ignore_dot'
        'Defaults logfile="/var/log/sudo.log"'
        'Defaults loglinelen=0'
    )
    if [[ "$AGGRESSIVE" -eq 1 ]]; then
        optional_options+=(
            'Defaults log_input'
            'Defaults log_output'
            'Defaults iolog_dir="/var/log/sudo-io/%{user}"'
        )
    fi
    candidate="$(mktemp)"
    probe="$(mktemp)"
    {
        printf '%s\n' '# Managed by harden.sh'
        printf '%s\n' "${accepted_options[@]}"
    } > "$candidate"
    if ! visudo -cf "$candidate" >/dev/null 2>&1; then
        rm -f "$candidate" "$probe"
        record_skip "sudo hardening" "visudo rejected the portable baseline; no live sudo file was changed"
        return 0
    fi
    for option in "${optional_options[@]}"; do
        {
            printf '%s\n' '# Managed by harden.sh'
            printf '%s\n' "${accepted_options[@]}"
            printf '%s\n' "$option"
        } > "$probe"
        if visudo -cf "$probe" >/dev/null 2>&1; then
            accepted_options+=("$option")
        else
            log INFO "visudo does not support this sudo default; omitted: ${option}"
        fi
    done
    {
        printf '%s\n' '# Managed by harden.sh'
        printf '%s\n' "${accepted_options[@]}"
    } > "$candidate"
    if ! visudo -cf "$candidate" >/dev/null 2>&1; then
        rm -f "$candidate" "$probe"
        record_skip "sudo hardening" "the composed temporary policy failed final validation; no live sudo file was changed"
        return 0
    fi
    if grep -q '^Defaults logfile=' "$candidate"; then sudo_log_enabled=1; fi
    if grep -q '^Defaults iolog_dir=' "$candidate"; then sudo_iolog_enabled=1; fi
    transaction_copy /etc/sudoers.d/99-hardening sudo-hardening
    install -d -o root -g root -m 0750 /etc/sudoers.d
    install -o root -g root -m 0440 "$candidate" /etc/sudoers.d/99-hardening
    rm -f "$candidate" "$probe"
    if ! visudo -c; then
        transaction_restore /etc/sudoers.d/99-hardening sudo-hardening
        visudo -c || die "Sudo rollback did not restore a valid configuration"
        log ROLLBACK "The complete sudo policy failed validation; the prior fragment was restored"
        return 0
    fi
    if [[ "$sudo_iolog_enabled" -eq 1 ]]; then
        install -d -o root -g root -m 0700 /var/log/sudo-io
    fi
    if [[ "$sudo_log_enabled" -eq 1 ]]; then
        touch /var/log/sudo.log
        chown root:adm /var/log/sudo.log
        chmod 0640 /var/log/sudo.log
    fi
    record_change "Installed a temporary-file-validated sudo policy with ${#accepted_options[@]} supported defaults"
    return 0
}

emit_audit_path_rules() {
    local arch="$1"
    cat <<EOF
-a always,exit -F arch=${arch} -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F arch=${arch} -F path=/etc/group -F perm=wa -k identity
-a always,exit -F arch=${arch} -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F arch=${arch} -F path=/etc/gshadow -F perm=wa -k identity
-a always,exit -F arch=${arch} -F path=/etc/security/opasswd -F perm=wa -k identity
-a always,exit -F arch=${arch} -F path=/etc/login.defs -F perm=wa -k auth-config
-a always,exit -F arch=${arch} -F path=/etc/sudoers -F perm=wa -k scope
-a always,exit -F arch=${arch} -F dir=/etc/sudoers.d -F perm=wa -k scope
-a always,exit -F arch=${arch} -F dir=/etc/ssh -F perm=wa -k ssh-config
-a always,exit -F arch=${arch} -F dir=/etc/pam.d -F perm=wa -k pam-config
-a always,exit -F arch=${arch} -F dir=/etc/security -F perm=wa -k security-config
-a always,exit -F arch=${arch} -F path=/var/log/lastlog -F perm=wa -k logins
-a always,exit -F arch=${arch} -F path=/var/log/faillog -F perm=wa -k logins
-a always,exit -F arch=${arch} -F path=/var/run/utmp -F perm=wa -k session
-a always,exit -F arch=${arch} -F path=/var/log/wtmp -F perm=wa -k session
-a always,exit -F arch=${arch} -F path=/var/log/btmp -F perm=wa -k session
-a always,exit -F arch=${arch} -F path=/etc/cron.allow -F perm=wa -k cron
-a always,exit -F arch=${arch} -F path=/etc/cron.deny -F perm=wa -k cron
-a always,exit -F arch=${arch} -F path=/etc/crontab -F perm=wa -k cron
-a always,exit -F arch=${arch} -F dir=/etc/cron.d -F perm=wa -k cron
-a always,exit -F arch=${arch} -F dir=/etc/systemd/system -F perm=wa -k systemd
-a always,exit -F arch=${arch} -F dir=/etc/modprobe.d -F perm=wa -k kernel-modules
-a always,exit -F arch=${arch} -F path=/etc/fstab -F perm=wa -k mounts
-a always,exit -F arch=${arch} -F path=/etc/hosts -F perm=wa -k network-config
-a always,exit -F arch=${arch} -F path=/etc/hostname -F perm=wa -k network-config
-a always,exit -F arch=${arch} -F dir=/etc/network -F perm=wa -k network-config
-a always,exit -F arch=${arch} -F dir=/etc/netplan -F perm=wa -k network-config
EOF
    return 0
}

emit_audit_syscall_rules() {
    local arch="$1"
    cat <<EOF
-a always,exit -F arch=${arch} -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=${arch} -S sethostname,setdomainname -k network-change
-a always,exit -F arch=${arch} -S init_module,finit_module,delete_module -k kernel-modules
-a always,exit -F arch=${arch} -S mount,umount2 -k mounts
-a always,exit -F arch=${arch} -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged-exec
-a always,exit -F arch=${arch} -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k permission-change
EOF
    return 0
}

configure_auditd() {
    if ! command -v auditctl >/dev/null 2>&1; then
        AUDIT_STATUS="NOT AVAILABLE"
        return 0
    fi
    local -a audit_arches=(b64)
    if [[ "$(uname -m)" == "x86_64" ]] && grep -q '^CONFIG_IA32_EMULATION=y' "/boot/config-$(uname -r)" 2>/dev/null; then
        audit_arches+=(b32)
    fi
    transaction_copy /etc/audit/rules.d/99-hardening.rules audit-hardening.rules
    {
        cat <<'EOF'
## Managed by harden.sh. Existing vendor/site rules are preserved.
-b 8192
-f 1
--backlog_wait_time 60000

EOF
        local arch
        for arch in "${audit_arches[@]}"; do
            emit_audit_path_rules "$arch"
            emit_audit_syscall_rules "$arch"
        done
        printf '%s\n' '-e 1'
    } | install_managed_file /etc/audit/rules.d/99-hardening.rules 0600
    if [[ "$MODE" == "dry-run" ]]; then
        AUDIT_STATUS="PLANNED"
        return 0
    fi
    # Remove filesystem rules for paths absent on this host; auditd rejects them.
    local filtered
    filtered="$(mktemp)"
    while IFS= read -r line; do
        if [[ "$line" =~ -F[[:space:]]+(path|dir)=([^[:space:]]+) ]]; then
            [[ -e "${BASH_REMATCH[2]}" ]] || continue
        fi
        printf '%s\n' "$line"
    done < /etc/audit/rules.d/99-hardening.rules > "$filtered"
    install -o root -g root -m 0600 "$filtered" /etc/audit/rules.d/99-hardening.rules
    rm -f "$filtered"
    if ! run_streamed augenrules --check; then
        log INFO "augenrules reports that the compiled rules need regeneration; proceeding to the validating load"
    fi
    if run_streamed augenrules --load; then
        run_streamed systemctl enable auditd.service || true
        if systemctl is-active --quiet auditd.service || run_streamed service auditd start; then
            local loaded_rules
            loaded_rules="$(auditctl -l 2>&1 || true)"
            if [[ -n "$loaded_rules" && "$loaded_rules" != "No rules" ]] \
                && grep -F -- 'path=/etc/passwd' <<<"$loaded_rules" >/dev/null; then
                AUDIT_STATUS="OK"
                record_change "Loaded and runtime-verified non-empty persistent audit rules for identity, auth, sudo, SSH, PAM, time, network, mounts, modules, systemd, and privileged execution"
            else
                AUDIT_STATUS="FAILED"
                record_skip "ACCT-9630" "auditd is active but auditctl did not show the required non-empty runtime rules"
            fi
        else
            AUDIT_STATUS="FAILED"
        fi
    else
        transaction_restore /etc/audit/rules.d/99-hardening.rules audit-hardening.rules
        run_streamed augenrules --load || true
        AUDIT_STATUS="FAILED/ROLLED BACK"
        log ROLLBACK "Audit rules failed augenrules validation/load"
    fi
}

configure_process_accounting() {
    if ! command -v accton >/dev/null 2>&1; then return 0; fi
    if unit_file_exists acct.service; then
        run systemctl enable --now acct.service || true
    elif [[ "$MODE" == "apply" ]]; then
        accton on || true
    else
        log INFO "Would enable process accounting with accton"
    fi
}

merge_mount_options() {
    local target="$1" additions="$2"
    local fstab="${HARDEN_FSTAB:-/etc/fstab}"
    [[ -f "$fstab" ]] || return 0
    if ! awk -v target="$target" '$0 !~ /^[[:space:]]*#/ && NF >= 4 && $2 == target {found=1} END {exit !found}' "$fstab"; then
        record_skip "mount:${target}" "not a distinct /etc/fstab mount; no risky repartition or synthetic mount was created"
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would merge mount options ${additions} into the existing ${target} fstab entry and validate it"
        return 0
    fi
    local temporary backup
    temporary="$(mktemp)"
    backup="$(mktemp)"
    cp -a "$fstab" "$backup"
    awk -v target="$target" -v additions="$additions" '
        function hasopt(list, opt, n, a, i) {
            n=split(list,a,","); for(i=1;i<=n;i++) if(a[i]==opt) return 1; return 0
        }
        $0 !~ /^[[:space:]]*#/ && NF >= 4 && $2 == target {
            n=split(additions,a,","); for(i=1;i<=n;i++) if(!hasopt($4,a[i])) $4=$4 "," a[i]
            print $1, $2, $3, $4, ($5==""?0:$5), ($6==""?0:$6); next
        }
        { print }
    ' "$fstab" > "$temporary"
    if command -v findmnt >/dev/null 2>&1 && findmnt --verify --tab-file "$temporary" >/dev/null; then
        if cmp -s "$temporary" "$fstab"; then
            rm -f "$temporary" "$backup"
            log INFO "Mount options for ${target} are already current; fstab and systemd state are unchanged"
            return 0
        fi
        install -o root -g root -m 0644 "$temporary" "$fstab"
        record_change "Added ${additions} to ${target} mount options"
        if ! run_streamed systemctl daemon-reload; then
            log WARN "systemd daemon-reload failed after the validated fstab update for ${target}"
        fi
        if mountpoint -q "$target"; then
            mount -o "remount,${additions}" "$target" || log WARN "Runtime remount of ${target} failed; fstab remains validated for the next reboot"
        fi
    else
        cp -a "$backup" "$fstab"
        log ROLLBACK "Rejected invalid fstab candidate for ${target}"
    fi
    rm -f "$temporary" "$backup"
}

harden_filesystems() {
    merge_mount_options /tmp nodev,nosuid,noexec
    merge_mount_options /var/tmp nodev,nosuid,noexec
    merge_mount_options /dev/shm nodev,nosuid,noexec
    merge_mount_options /boot nodev,nosuid,noexec
    if [[ "$AGGRESSIVE" -eq 1 ]]; then
        merge_mount_options /home nodev,nosuid
        merge_mount_options /var nodev,nosuid
    fi
    record_skip "FILE-6310" "separate /home and /var require storage design/repartitioning; this script will not move live filesystems"
    record_skip "proc:hidepid" "global hidepid can break monitoring, polkit, and support tooling; service-level ProtectProc is preferred"
}

configure_cron_at() {
    local allow_users="root"
    [[ -n "$ADMIN_USER" ]] && allow_users+=$'\n'"$ADMIN_USER"
    printf '%s\n' "$allow_users" | install_managed_file /etc/cron.allow 0600
    if command -v at >/dev/null 2>&1 || package_installed at; then
        printf '%s\n' "$allow_users" | install_managed_file /etc/at.allow 0600
    fi
    if [[ "$MODE" == "apply" ]]; then
        if [[ -f /etc/crontab ]]; then
            chown root:root /etc/crontab
            chmod 0600 /etc/crontab
        fi
        local dir
        for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
            if [[ -d "$dir" ]]; then
                chown root:root "$dir"
                chmod 0700 "$dir"
            fi
        done
        [[ -d /var/spool/cron/crontabs ]] && chmod 1730 /var/spool/cron/crontabs
        record_change "Restricted cron/at access and corrected Lynis-reported cron permissions"
    fi
}

log_account_check_output() {
    local level="$1" tool="$2" output="$3" line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -n "$line" ]] && log "$level" "${tool}: ${line}"
    done <<<"$output"
    return 0
}

pwck_output_is_metadata_only() {
    local output="$1" line saw_warning=0
    local home_warning_re="^user '[^']+': directory '[^']+' does not exist$"
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            ''|'pwck: no changes') continue ;;
        esac
        if [[ "$line" =~ $home_warning_re ]]; then
            saw_warning=1
            continue
        fi
        return 1
    done <<<"$output"
    [[ "$saw_warning" -eq 1 ]]
}

run_account_database_check() {
    local tool="$1" description="$2" output="" rc=0
    command -v "$tool" >/dev/null 2>&1 || die "${tool} is required for ${description}"
    if output="$(LC_ALL=C "$tool" -r 2>&1)"; then
        rc=0
    else
        rc=$?
    fi
    if [[ "$tool" == "pwck" && ( "$rc" -eq 0 || "$rc" -eq 2 ) ]] \
        && pwck_output_is_metadata_only "$output"; then
        log_account_check_output WARN "$tool" "$output"
        log WARN "pwck reported non-fatal account metadata findings"
        return 0
    fi
    if [[ "$rc" -eq 0 ]]; then
        [[ -z "$output" ]] || log_account_check_output INFO "$tool" "$output"
        return 0
    fi
    log_account_check_output ERROR "$tool" "$output"
    case "$rc" in
        1) die "${description} failed: invalid ${tool} invocation (exit 1)" ;;
        2) die "${description} found structurally invalid account entries (exit 2)" ;;
        3) die "${description} could not open the account database (exit 3)" ;;
        4) die "${description} could not lock the account database (exit 4)" ;;
        5) die "${description} could not update the account database (exit 5)" ;;
        6) die "${description} could not sort the account database (exit 6)" ;;
        *) die "${description} failed with unexpected exit ${rc}" ;;
    esac
}

harden_accounts_and_files() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would verify passwd/group databases, sensitive modes, UID 0 accounts, empty passwords, and unsafe trust files"
        return 0
    fi
    run_account_database_check pwck "passwd/shadow consistency check"
    run_account_database_check grpck "group/gshadow consistency check"
    chmod 0644 /etc/passwd /etc/group
    chmod 0640 /etc/shadow /etc/gshadow
    chown root:shadow /etc/shadow /etc/gshadow
    local extra_uid0
    extra_uid0="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)"
    [[ -z "$extra_uid0" ]] || record_skip "UID0 accounts" "manual review required: ${extra_uid0//$'\n'/, }"
    local empty_passwords
    empty_passwords="$(awk -F: '$2 == "" {print $1}' /etc/shadow)"
    if [[ -n "$empty_passwords" ]]; then
        local user
        while IFS= read -r user; do passwd -l "$user"; done <<< "$empty_passwords"
        record_change "Locked accounts with empty shadow password fields: ${empty_passwords//$'\n'/, }"
    fi
    if find /etc -xdev -type f -perm -0002 -print -exec chmod o-w {} + \
        > "$BACKUP_DIR/world-writable-etc-fixed.txt" 2> "$BACKUP_DIR/world-writable-etc-errors.txt"; then
        log INFO "Completed bounded world-writable file correction under /etc"
    else
        log WARN "find reported non-fatal errors while checking /etc; see ${BACKUP_DIR}/world-writable-etc-errors.txt"
    fi
    if ! find / -xdev \( -nouser -o -nogroup \) -print \
        > "$BACKUP_DIR/unowned-files.txt" 2> "$BACKUP_DIR/unowned-files-errors.txt"; then
        log WARN "find reported non-fatal errors while inventorying unowned files; see ${BACKUP_DIR}/unowned-files-errors.txt"
    fi
    local home trustfile
    while IFS=: read -r _ _ uid _ _ home _; do
        ((uid == 0 || uid >= 1000)) || continue
        [[ -d "$home" ]] || continue
        for trustfile in "$home/.rhosts"; do
            if [[ -e "$trustfile" ]]; then
                install -d -m 0700 "$BACKUP_DIR/quarantine${home}"
                mv -- "$trustfile" "$BACKUP_DIR/quarantine${home}/"
                record_change "Quarantined insecure trust file ${trustfile}"
            fi
        done
        [[ -f "$home/.netrc" ]] && chmod 0600 "$home/.netrc"
        [[ -d "$home/.ssh" ]] && chmod 0700 "$home/.ssh"
        [[ -f "$home/.ssh/authorized_keys" ]] && chmod 0600 "$home/.ssh/authorized_keys"
    done < /etc/passwd
    if [[ -e /etc/hosts.equiv ]]; then
        install -d -m 0700 "$BACKUP_DIR/quarantine/etc"
        mv -- /etc/hosts.equiv "$BACKUP_DIR/quarantine/etc/"
        record_change "Quarantined /etc/hosts.equiv"
    fi
    record_change "Completed account database and sensitive-file validation"
    return 0
}

disable_service() {
    local service="$1" mask="${2:-0}"
    if ! unit_file_exists "$service"; then
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would disable and stop ${service} (mask=${mask})"
        return 0
    fi
    if [[ -z "${SERVICE_MASK_REQUESTED[$service]+present}" ]]; then
        SERVICES_DISABLE_REQUESTED+=("$service")
    fi
    SERVICE_MASK_REQUESTED["$service"]="$mask"
    local disable_output="" mask_output="" enabled_state="" active_state="" load_state=""
    enabled_state="$(systemctl is-enabled "$service" 2>/dev/null || true)"
    active_state="$(systemctl is-active "$service" 2>/dev/null || true)"
    load_state="$(systemctl show "$service" -p LoadState --value 2>/dev/null || true)"
    if [[ "$active_state" != active && "$active_state" != activating ]] \
        && { [[ "$mask" -eq 0 && ( "$enabled_state" == disabled || "$enabled_state" == masked ) ]] \
            || [[ "$mask" -eq 1 && ( "$enabled_state" == masked || "$load_state" == masked ) ]]; }; then
        SERVICES_DISABLED+=("$service")
        if [[ "$mask" -eq 1 ]]; then SERVICES_MASKED+=("$service"); fi
        log INFO "Service already in requested inactive state: ${service} (enabled=${enabled_state:-unknown}, load=${load_state:-unknown})"
        return 0
    fi
    if ! disable_output="$(systemctl disable --now "$service" 2>&1)"; then
        log WARN "systemctl disable --now ${service} reported: ${disable_output//$'\n'/; }"
    fi
    if [[ "$mask" -eq 1 ]]; then
        if ! mask_output="$(systemctl mask "$service" 2>&1)"; then
            log WARN "systemctl mask ${service} reported: ${mask_output//$'\n'/; }"
        fi
    fi
    enabled_state="$(systemctl is-enabled "$service" 2>/dev/null || true)"
    active_state="$(systemctl is-active "$service" 2>/dev/null || true)"
    load_state="$(systemctl show "$service" -p LoadState --value 2>/dev/null || true)"
    if [[ "$active_state" != "active" && "$active_state" != "activating" ]] \
        && { [[ "$mask" -eq 0 && ( "$enabled_state" == "disabled" || "$enabled_state" == "masked" ) ]] \
            || [[ "$mask" -eq 1 && ( "$enabled_state" == "masked" || "$load_state" == "masked" ) ]]; }; then
        SERVICES_DISABLED+=("$service")
        if [[ "$mask" -eq 1 ]]; then
            SERVICES_MASKED+=("$service")
            record_change "Disabled and masked ${service}"
        else
            record_change "Disabled ${service}"
        fi
    else
        log WARN "${service} remained active/enabled; enabled=${enabled_state:-unknown}, active=${active_state:-unknown}, load=${load_state:-unknown}"
    fi
    return 0
}

verify_disabled_services() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would verify enabled, active, and masked state for every service selected for removal"
        return 0
    fi
    local service mask enabled_state active_state load_state
    for service in "${SERVICES_DISABLE_REQUESTED[@]}"; do
        mask="${SERVICE_MASK_REQUESTED[$service]:-0}"
        enabled_state="$(systemctl is-enabled "$service" 2>/dev/null || true)"
        active_state="$(systemctl is-active "$service" 2>/dev/null || true)"
        load_state="$(systemctl show "$service" -p LoadState --value 2>/dev/null || true)"
        if [[ "$active_state" != "active" && "$active_state" != "activating" ]] \
            && { [[ "$mask" -eq 0 && ( "$enabled_state" == "disabled" || "$enabled_state" == "masked" ) ]] \
                || [[ "$mask" -eq 1 && ( "$enabled_state" == "masked" || "$load_state" == "masked" ) ]]; }; then
            log OK "Verified ${service}: enabled=${enabled_state}, active=${active_state}, load=${load_state}"
        else
            log WARN "${service} failed post-disable verification: enabled=${enabled_state:-unknown}, active=${active_state:-unknown}, load=${load_state:-unknown}"
        fi
    done
    return 0
}

configure_startup_service_review() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would set and verify multi-user.target and write a startup-service inventory for BOOT-5180 review"
        record_skip "BOOT-5180" "startup-service necessity remains a host-role decision even after the default target and inventories are verified"
        return 0
    fi
    local default_target report=/root/startup-service-review.txt
    run_streamed systemctl set-default multi-user.target
    default_target="$(systemctl get-default 2>/dev/null || true)"
    [[ "$default_target" == "multi-user.target" ]] \
        || die "Default systemd target verification failed: ${default_target:-unknown}"
    {
        printf 'Startup service review generated %s\n' "$(timestamp)"
        printf 'Default target: %s\n\n' "$default_target"
        printf '%s\n' '=== Enabled unit files ==='
        systemctl list-unit-files --state=enabled --no-pager || true
        printf '\n%s\n' '=== multi-user.target dependencies ==='
        systemctl list-dependencies multi-user.target --plain --no-pager || true
        printf '\n%s\n' '=== Active services ==='
        systemctl list-units --type=service --state=active --plain --no-pager || true
    } > "$report" 2>&1
    chmod 0600 "$report"
    record_change "Verified multi-user.target and wrote startup-service inventory to ${report}"
    record_skip "BOOT-5180" "Lynis requires an operator determination of startup-service necessity; the exact enabled, dependent, and active inventories are in ${report}"
    return 0
}

parse_apt_purge_packages() {
    awk '$1 == "Purg" || $1 == "Remv" {print $2}' | sort -u
}

configure_headless_packagekit() {
    local -a installed=() removals=() dependency_removals=()
    local package simulation="" removal="" dependency_reason=""
    declare -A requested=()
    case "$OS_ID" in
        ubuntu) log INFO "Applying Ubuntu headless PackageKit policy" ;;
        debian) log INFO "Applying Debian headless PackageKit policy" ;;
        *)
            record_skip "PKGS-7394:PackageKit" "unsupported package policy platform ${OS_ID}; PackageKit was not changed"
            return 0
            ;;
    esac
    for package in packagekit packagekit-tools; do
        if package_installed "$package"; then
            installed+=("$package")
            requested["$package"]=1
        fi
    done
    if [[ "$MODE" == "dry-run" ]]; then
        if ((${#installed[@]})); then
            log INFO "Would simulate removal of headless PackageKit packages and preserve them unmasked if dependencies make removal unsafe (${OS_ID})"
        else
            log INFO "PackageKit is absent on this headless ${OS_ID} host; no service mask is needed"
        fi
        return 0
    fi

    # Remove stale harden.sh masks before auditing or removing the package. A masked
    # D-Bus activatable service makes package auditors emit UnitMasked errors.
    run_streamed systemctl unmask packagekit.service packagekit-offline-update.service \
        packagekit-offline-update.timer || true
    if ((${#installed[@]} == 0)); then
        run_streamed systemctl daemon-reload || true
        record_change "Verified PackageKit absent and removed stale service masks on headless ${OS_ID}"
        return 0
    fi
    if ! apt-get check >/dev/null 2>&1; then
        record_skip "PKGS-7394:PackageKit" "APT is not healthy before simulation; PackageKit was unmasked and retained"
        return 0
    fi
    if command -v unattended-upgrade >/dev/null 2>&1 \
        && ! unattended-upgrade --dry-run >/dev/null 2>&1; then
        record_skip "PKGS-7394:PackageKit" "unattended-upgrades failed its pre-removal dry-run; PackageKit was unmasked and retained"
        return 0
    fi
    simulation="$(LC_ALL=C apt-get -s purge "${installed[@]}" 2>&1)" || {
        record_skip "PKGS-7394:PackageKit" "APT purge simulation failed; PackageKit was unmasked and retained"
        return 0
    }
    mapfile -t removals < <(parse_apt_purge_packages <<<"$simulation")
    if ((${#removals[@]} == 0)); then
        record_skip "PKGS-7394:PackageKit" "APT simulation did not confirm a removable PackageKit package"
        return 0
    fi
    for removal in "${removals[@]}"; do
        [[ -n "${requested[$removal]+present}" ]] || dependency_removals+=("$removal")
    done
    if ((${#dependency_removals[@]})); then
        printf -v dependency_reason '%s, ' "${dependency_removals[@]}"
        dependency_reason="${dependency_reason%, }"
        record_skip "PKGS-7394:PackageKit" "APT simulation would also purge dependency packages: ${dependency_reason}; PackageKit was unmasked and retained"
        return 0
    fi
    if run_streamed env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${installed[@]}"; then
        PACKAGES_REMOVED+=("${installed[@]}")
    else
        record_skip "PKGS-7394:PackageKit" "simulated PackageKit purge failed; no service was masked"
        return 0
    fi
    if ! run_streamed apt-get check; then
        UPDATES_STATUS="FAILED"
        record_skip "PKGS-7394:PackageKit" "APT failed validation after PackageKit removal"
        return 0
    fi
    if command -v unattended-upgrade >/dev/null 2>&1 \
        && ! run_streamed unattended-upgrade --dry-run; then
        UPDATES_STATUS="FAILED"
        record_skip "PKGS-7394:PackageKit" "unattended-upgrades failed validation after PackageKit removal"
        return 0
    fi
    record_change "Safely purged headless PackageKit after dependency simulation and revalidated APT/unattended-upgrades (${OS_ID})"
    return 0
}

disable_unneeded_services() {
    configure_startup_service_review
    if [[ "$AGGRESSIVE" -eq 0 ]]; then
        record_skip "unused services" "compatibility-sensitive service removal requires --aggressive; service inventory is still recorded"
        return 0
    fi
    local virtualization="none"
    virtualization="$(systemd-detect-virt 2>/dev/null || true)"
    [[ -n "$virtualization" ]] || virtualization="none"
    log INFO "Virtualization detection: ${virtualization}; hypervisor guest agents remain preserved"
    if unit_file_exists ModemManager.service; then
        local modems=""
        command -v mmcli >/dev/null 2>&1 && modems="$(mmcli -L 2>/dev/null || true)"
        if [[ -z "$modems" || "$modems" != *'/Modem/'* ]]; then
            disable_service ModemManager.service 1
        else
            log INFO "Preserved ModemManager because a modem is present"
        fi
    fi
    if [[ ! -d /sys/class/bluetooth || -z "$(ls -A /sys/class/bluetooth 2>/dev/null)" ]]; then
        disable_service bluetooth.service 1
    fi
    local avahi_publications=""
    if [[ -d /etc/avahi/services ]]; then
        avahi_publications="$(find /etc/avahi/services -maxdepth 1 -type f -size +0c -print 2>/dev/null || true)"
    fi
    if [[ -z "$avahi_publications" ]]; then
        disable_service avahi-daemon.service 1
        disable_service avahi-daemon.socket 1
    else
        log INFO "Preserved Avahi because explicit service publications are configured"
    fi
    local print_queues="" usb_printers=""
    command -v lpstat >/dev/null 2>&1 && print_queues="$(lpstat -a 2>/dev/null || true)"
    usb_printers="$(compgen -G '/dev/usb/lp*' || true)"
    if [[ -z "$print_queues" && -z "$usb_printers" ]]; then
        disable_service cups.service 1
        disable_service cups.socket 1
        disable_service cups.path 1
    else
        log INFO "Preserved CUPS because a print queue or USB printer device is present"
    fi
    local nfs_mounts="" active_exports=""
    nfs_mounts="$(findmnt -rn -t nfs,nfs4 2>/dev/null || true)"
    if [[ -r /etc/exports ]]; then
        active_exports="$(awk '!/^[[:space:]]*(#|$)/ {print}' /etc/exports)"
    fi
    if [[ -z "$nfs_mounts" && -z "$active_exports" ]]; then
        disable_service rpcbind.service 1
        disable_service rpcbind.socket 1
        disable_service nfs-server.service 1
        disable_service nfs-kernel-server.service 1
    else
        log INFO "Preserved NFS/rpcbind because an NFS mount or export is configured"
    fi
    local samba_shares=""
    if [[ -r /etc/samba/smb.conf ]]; then
        samba_shares="$(awk '
            /^[[:space:]]*\[/ {
                name=tolower($0); gsub(/[[:space:]\[\]]/, "", name)
                if (name != "global" && name != "printers" && name != "print$") print name
            }
        ' /etc/samba/smb.conf)"
    fi
    if [[ -z "$samba_shares" ]]; then
        disable_service smbd.service 1
        disable_service nmbd.service 1
    else
        log INFO "Preserved Samba because one or more non-default shares are configured"
    fi
    disable_service apport.service 1
    local iscsi_sessions=""
    command -v iscsiadm >/dev/null 2>&1 && iscsi_sessions="$(iscsiadm -m session 2>/dev/null || true)"
    if ! grep -Eq '^(tcp|iser):' <<<"$iscsi_sessions"; then
        disable_service iscsid.service 1
        disable_service iscsid.socket 1
    fi
    if ! command -v multipath >/dev/null 2>&1 || [[ -z "$(multipath -ll 2>/dev/null)" ]]; then
        disable_service multipathd.service 1
        disable_service multipathd.socket 1
    fi
    if ! systemctl is-active --quiet display-manager.service 2>/dev/null; then
        disable_service udisks2.service 1
        disable_service upower.service 1
        configure_headless_packagekit
    else
        log INFO "Preserved udisks2, upower, and PackageKit because a display manager is active"
    fi
    log INFO "Preserved cloud-init, open-vm-tools, snapd, networking, chrony, fwupd, and tailscaled when present"
}

measure_service_exposure() {
    local service="$1" stage="$2" output_file="$3" output="" score=""
    SYSTEMD_EXPOSURE_RESULT=""
    if output="$(systemd-analyze security --no-pager "$service" 2>&1)"; then
        :
    else
        log WARN "systemd-analyze security could not fully score ${service} (${stage})"
    fi
    printf '%s\n' "$output" > "$output_file"
    chmod 0600 "$output_file"
    score="$(awk '
        /Overall exposure level/ {
            for (field=1; field<=NF; field++) {
                if ($field ~ /^[0-9]+([.][0-9]+)?$/) { print $field; exit }
            }
        }
    ' <<<"$output")"
    if [[ "$score" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        SYSTEMD_EXPOSURE_RESULT="$score"
    fi
    return 0
}

classify_systemd_exposure() {
    local before="$1" after="$2" dropin_was_current="$3"
    if awk -v before="$before" -v after="$after" 'BEGIN { exit !(after < before) }'; then
        printf '%s\n' decreased
    elif [[ "$dropin_was_current" -eq 1 ]] \
        && awk -v before="$before" -v after="$after" 'BEGIN { exit !(after == before) }'; then
        printf '%s\n' unchanged
    else
        printf '%s\n' not-decreased
    fi
}

systemd_verify_unit() {
    local unit_or_file="$1" analyze_help=""
    analyze_help="$(systemd-analyze --help 2>&1 || true)"
    if grep -Fq -- '--recursive-errors' <<<"$analyze_help"; then
        # Reject warnings in the explicitly checked unit without failing on an
        # unrelated optional dependency elsewhere in the host unit graph.
        systemd-analyze --recursive-errors=no verify "$unit_or_file"
    else
        systemd-analyze verify "$unit_or_file"
    fi
}

rollback_service_dropin() {
    local service="$1" destination="$2" transaction_label="$3" was_active="$4" health_action="$5" reason="$6"
    transaction_restore "$destination" "$transaction_label"
    run_streamed systemctl daemon-reload || true
    if [[ "$was_active" -eq 1 ]]; then
        run_streamed systemctl "$health_action" "$service" \
            || run_streamed systemctl restart "$service" || true
    else
        systemctl stop "$service" >/dev/null 2>&1 || true
    fi
    printf '%-36s ROLLED BACK: %s\n' "$service" "$reason" >> "$SYSTEMD_HARDENING_REPORT"
    log ROLLBACK "${reason}; restored the prior drop-in for ${service}"
    return 0
}

install_service_dropin() {
    local service="$1" name="$2"
    local destination="/etc/systemd/system/${service}.d/${name}.conf"
    if ! unit_file_exists "$service"; then
        cat >/dev/null
        return 0
    fi
    if [[ "$MODE" == "dry-run" ]]; then
        cat >/dev/null
        log INFO "Would install, verify, and health-test systemd sandbox for ${service}"
        return 0
    fi
    local transaction_label="systemd-${service}-${name}.conf"
    local before_file="$BACKUP_DIR/systemd-security-${service//[^A-Za-z0-9_.-]/_}-before.txt"
    local after_file="$BACKUP_DIR/systemd-security-${service//[^A-Za-z0-9_.-]/_}-after.txt"
    local preverify_file="$BACKUP_DIR/systemd-verify-${service//[^A-Za-z0-9_.-]/_}-pre-install.txt"
    local postverify_file="$BACKUP_DIR/systemd-verify-${service//[^A-Za-z0-9_.-]/_}-installed.txt"
    local before="" after="" was_active=0 health_action="restart" exposure_line="" exposure_outcome=""
    local dropin_was_current=0
    local dropin_stage="" verify_dir="" verify_unit=""
    if ! dropin_stage="$(mktemp)"; then
        log WARN "Could not create a staging file; skipped systemd hardening for ${service}"
        return 0
    fi
    if ! cat > "$dropin_stage"; then
        rm -f -- "$dropin_stage"
        log WARN "Could not stage the drop-in; skipped systemd hardening for ${service}"
        return 0
    fi
    if [[ -f "$destination" ]] && cmp -s "$dropin_stage" "$destination"; then
        dropin_was_current=1
    fi
    if ! verify_dir="$(mktemp -d)"; then
        rm -f -- "$dropin_stage"
        log WARN "Could not create a verification directory; skipped systemd hardening for ${service}"
        return 0
    fi
    verify_unit="${verify_dir}/${service}"
    if ! systemctl cat "$service" > "$verify_unit" 2> "$preverify_file"; then
        rm -f -- "$dropin_stage" "$verify_unit"
        rmdir -- "$verify_dir" 2>/dev/null || true
        log WARN "Could not stage the effective base unit; skipped systemd hardening for ${service}"
        return 0
    fi
    {
        printf '\n# Candidate drop-in %s for pre-install verification\n' "$name"
        cat "$dropin_stage"
    } >> "$verify_unit"
    if ! systemd_verify_unit "$verify_unit" >> "$preverify_file" 2>&1; then
        rm -f -- "$dropin_stage" "$verify_unit"
        rmdir -- "$verify_dir" 2>/dev/null || true
        log WARN "Pre-install systemd verification rejected the candidate drop-in for ${service}; see ${preverify_file}"
        return 0
    fi
    chmod 0600 "$preverify_file"
    rm -f -- "$verify_unit"
    rmdir -- "$verify_dir" 2>/dev/null || true
    measure_service_exposure "$service" before "$before_file"
    before="$SYSTEMD_EXPOSURE_RESULT"
    [[ -z "$before" ]] || SERVICE_EXPOSURE_BEFORE["$service"]="$before"
    systemctl is-active --quiet "$service" && was_active=1
    [[ -n "$SSH_SERVICE" && "$service" == "$SSH_SERVICE" ]] && health_action="reload"
    transaction_copy "$destination" "$transaction_label"
    if ! install_managed_file "$destination" 0644 < "$dropin_stage"; then
        rm -f -- "$dropin_stage"
        rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "drop-in installation failed"
        return 0
    fi
    rm -f -- "$dropin_stage"
    if ! systemd_verify_unit "$service" > "$postverify_file" 2>&1; then
        rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "systemd-analyze verify rejected the drop-in"
        return 0
    fi
    chmod 0600 "$postverify_file"
    if ! run_streamed systemctl daemon-reload; then
        rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "systemd daemon-reload failed"
        return 0
    fi
    if [[ "$was_active" -eq 1 ]]; then
        if ! run_streamed systemctl "$health_action" "$service" || ! systemctl is-active --quiet "$service"; then
            rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "active-service health check failed"
            return 0
        fi
    elif [[ "$service" == "uuidd.service" ]]; then
        if ! run_streamed systemctl start "$service" || systemctl is-failed --quiet "$service"; then
            rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "safe inactive-service health check failed"
            return 0
        fi
        run_streamed systemctl stop "$service" || true
    elif systemctl is-failed --quiet "$service"; then
        rollback_service_dropin "$service" "$destination" "$transaction_label" "$was_active" "$health_action" "inactive service is in failed state"
        return 0
    fi
    measure_service_exposure "$service" after "$after_file"
    after="$SYSTEMD_EXPOSURE_RESULT"
    [[ -z "$after" ]] || SERVICE_EXPOSURE_AFTER["$service"]="$after"
    SERVICES_HARDENED+=("$service")
    if [[ -n "$before" && -n "$after" ]]; then
        printf -v exposure_line '%-32s %s -> %s' "$service" "$before" "$after"
        SERVICE_EXPOSURE_SUMMARY+=("$exposure_line")
        printf '%-36s %s -> %s\n' "$service" "$before" "$after" >> "$SYSTEMD_HARDENING_REPORT"
        exposure_outcome="$(classify_systemd_exposure "$before" "$after" "$dropin_was_current")"
        if [[ "$exposure_outcome" == decreased ]]; then
            record_change "Installed and health-tested systemd hardening for ${service}; exposure ${before} -> ${after}"
        elif [[ "$exposure_outcome" == unchanged ]]; then
            log OK "${service} drop-in is already active and passed health checks; exposure unchanged/already hardened (${before} -> ${after})"
        else
            log WARN "${service} passed health checks but exposure did not decrease (${before} -> ${after})"
        fi
    else
        printf '%-36s exposure unavailable (before=%s, after=%s)\n' "$service" "${before:-N/A}" "${after:-N/A}" >> "$SYSTEMD_HARDENING_REPORT"
        record_change "Installed and health-tested systemd hardening for ${service}; exposure score unavailable"
    fi
    return 0
}

analyze_active_services() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would run systemd-analyze security SERVICE for every active service and retain the complete report"
        return 0
    fi
    local report="$BACKUP_DIR/systemd-security-active-services.txt" active_units service rest
    active_units="$(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null || true)"
    : > "$report"
    chmod 0600 "$report"
    while IFS=' ' read -r service rest; do
        [[ "$service" == *.service ]] || continue
        printf '\n===== %s =====\n' "$service" >> "$report"
        systemd-analyze security --no-pager "$service" >> "$report" 2>&1 || true
    done <<<"$active_units"
    record_change "Ran systemd-analyze security individually for every active service; report: ${report}"
    return 0
}

harden_systemd_services() {
    if [[ "$MODE" == "apply" ]]; then
        {
            printf 'systemd hardening exposure report\n'
            printf 'Generated: %s\n\n' "$(timestamp)"
        } > "$SYSTEMD_HARDENING_REPORT"
        chmod 0600 "$SYSTEMD_HARDENING_REPORT"
    else
        log INFO "Would write measured systemd exposure changes to ${SYSTEMD_HARDENING_REPORT}"
    fi
    install_service_dropin rsyslog.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=-/var/log -/var/spool/rsyslog -/run/rsyslog
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0027
EOF
    install_service_dropin fail2ban.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths=-/var/log -/var/lib/fail2ban -/run/fail2ban
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0027
EOF
    if [[ -n "$SSH_SERVICE" ]]; then
        install_service_dropin "$SSH_SERVICE" 99-hardening <<'EOF'
[Service]
PrivateTmp=yes
UMask=0027
EOF
    fi
    install_service_dropin unattended-upgrades.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
UMask=0027
EOF
    install_service_dropin acct.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=-/var/log/account
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SYS_PACCT
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
UMask=0027
EOF
    install_service_dropin acct-monthly-report.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths=-/var/log/account -/var/lib/acct
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
UMask=0027
EOF
    install_service_dropin uuidd.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ReadWritePaths=-/run/uuidd
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
UMask=0027
EOF
    install_service_dropin networkd-dispatcher.service 99-hardening <<'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0027
EOF
    analyze_active_services
    record_skip "BOOT-5264:cron.service" "cron executes arbitrary administrator jobs, so a global sandbox would break its purpose"
    record_skip "BOOT-5264:ssh.service" "only PrivateTmp/UMask are applied; stronger unit restrictions would propagate into sudo administrator sessions"
    record_skip "BOOT-5264:excluded-services" "dbus, cron, auditd, tailscaled, open-vm-tools, systemd-*, polkit, snapd, and cloud-init are not blindly sandboxed because their IPC, namespace, audit, overlay, or guest duties are host-critical"
    if [[ "$MODE" == "apply" ]]; then
        record_change "Wrote measured systemd hardening results to ${SYSTEMD_HARDENING_REPORT}"
    fi
    return 0
}

configure_apparmor() {
    if ! command -v aa-status >/dev/null 2>&1; then
        APPARMOR_STATUS="NOT AVAILABLE"
        return 0
    fi
    run systemctl enable --now apparmor.service || true
    if [[ "$MODE" == "apply" ]]; then
        if command -v apparmor_parser >/dev/null 2>&1; then
            local profile
            while IFS= read -r -d '' profile; do
                apparmor_parser -Q "$profile" >/dev/null 2>&1 || {
                    log WARN "AppArmor parser rejected ${profile}; left unchanged"
                    continue
                }
                if [[ "$AGGRESSIVE" -eq 1 ]] && command -v aa-enforce >/dev/null 2>&1; then
                    aa-enforce "$profile" >/dev/null 2>&1 || true
                fi
            done < <(find /etc/apparmor.d -maxdepth 1 -type f -print0 2>/dev/null)
        fi
        if aa-status --enabled >/dev/null 2>&1; then
            APPARMOR_STATUS="OK"
            record_change "Enabled AppArmor and parser-validated installed top-level profiles"
        else
            APPARMOR_STATUS="FAILED"
        fi
    else
        APPARMOR_STATUS="PLANNED"
    fi
}

configure_time_sync() {
    if ! command -v chronyd >/dev/null 2>&1; then
        record_skip "time synchronization" "chrony is unavailable"
        return 0
    fi
    install_managed_file /etc/chrony/conf.d/99-security-hardening.conf 0644 <<'EOF'
makestep 1.0 3
rtcsync
cmdport 0
minsources 2
maxupdateskew 100.0
EOF
    if [[ "$MODE" == "apply" ]]; then
        local chrony_config=/etc/chrony/chrony.conf
        [[ -f "$chrony_config" ]] || chrony_config=/etc/chrony.conf
        if run_streamed chronyd -p -f "$chrony_config"; then
            run_streamed systemctl disable --now systemd-timesyncd.service || true
            run_streamed systemctl disable --now ntp.service ntpsec.service || true
            run_streamed systemctl enable --now chrony.service
            run_streamed systemctl restart chrony.service
            record_change "Configured exactly one active time service: chrony"
        else
            log WARN "Chrony configuration validation failed"
        fi
    fi
}

configure_bootloader() {
    local grub_dir="${HARDEN_GRUB_DIR:-/boot/grub}"
    local grub_policy="${HARDEN_GRUB_POLICY:-/etc/default/grub.d/99-security-hardening.cfg}"
    local legacy_auth="${HARDEN_GRUB_LEGACY_AUTH:-/etc/grub.d/01_hardening_users}"
    record_skip "BOOT-5122" "intentionally accepted: no GRUB password is configured to preserve unattended/reliable reboot capability."
    if ! command -v update-grub >/dev/null 2>&1 || [[ ! -d "$grub_dir" ]]; then
        return 0
    fi
    transaction_copy "$grub_policy" grub-hardening.cfg
    local removed_managed_auth=0 grub_config_changed=0
    if [[ -f "$legacy_auth" ]] \
        && grep -q '^# Managed by harden.sh' "$legacy_auth"; then
        transaction_copy "$legacy_auth" grub-hardening-users
        if [[ "$MODE" == "apply" ]]; then
            rm -f -- "$legacy_auth"
            removed_managed_auth=1
            record_change "Removed the legacy harden.sh GRUB authentication fragment"
        else
            log INFO "Would remove the legacy harden.sh GRUB authentication fragment"
        fi
    fi
    install_managed_file "$grub_policy" 0600 <<'EOF'
# Managed by harden.sh
GRUB_DISABLE_RECOVERY="true"
GRUB_DISABLE_OS_PROBER="true"
EOF
    [[ "$MANAGED_FILE_CHANGED" -eq 0 ]] || grub_config_changed=1
    if [[ "$MODE" == "apply" ]]; then
        if [[ "$grub_config_changed" -eq 0 && "$removed_managed_auth" -eq 0 ]]; then
            log INFO "Managed GRUB policy is unchanged; update-grub is not required"
        elif run_streamed update-grub; then
            chmod 0600 "$grub_dir/grub.cfg"
            REBOOT_REQUIRED=1
            record_change "Disabled GRUB recovery entries and OS probing without boot authentication; regenerated grub.cfg"
        else
            transaction_restore "$grub_policy" grub-hardening.cfg
            if [[ "$removed_managed_auth" -eq 1 ]]; then
                transaction_restore "$legacy_auth" grub-hardening-users
            fi
            run_streamed update-grub || true
            log ROLLBACK "GRUB regeneration failed; hardening fragment restored/removed"
        fi
    fi
}

compiler_command_path() {
    command -v "$1" 2>/dev/null || true
}

dkms_is_in_use() {
    local dkms_state_dir="${HARDEN_DKMS_STATE_DIR:-/var/lib/dkms}"
    local status="" packages=""
    if command -v dkms >/dev/null 2>&1; then
        status="$(dkms status 2>/dev/null || true)"
        [[ -z "$status" ]] || return 0
    fi
    packages="$(dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\n' '*-dkms' 2>/dev/null \
        | awk '$1 ~ /^ii/ && $2 ~ /-dkms([:-]|$)/ {print $2}' || true)"
    [[ -z "$packages" ]] || return 0
    if [[ -d "$dkms_state_dir" ]] \
        && find "$dkms_state_dir" -mindepth 2 -maxdepth 2 -type d -print -quit 2>/dev/null | grep -q .; then
        return 0
    fi
    return 1
}

restrict_compilers() {
    # Lynis 3.1.6 sets COMPILER_INSTALLED only for these five binary names.
    local -a lynis_tools=(as cc clang g++ gcc)
    local -a restriction_tools=(cc gcc g++ c++ clang clang++ cpp make as ld ld.bfd ld.gold)
    local -a candidates=() lynis_paths=() owner_packages=() removals=() unsafe_removals=()
    local tool path real mode owner group owner_id group_id package simulation="" unsafe_reason="" unsafe_list=""
    local restricted_owner="${HARDEN_TEST_OWNER:-root}" restricted_group="${HARDEN_TEST_GROUP:-root}"
    local restricted_uid restricted_gid
    local compiler_usr_root="${HARDEN_COMPILER_USR_ROOT:-/usr}"
    local compiler_local_root="${HARDEN_COMPILER_LOCAL_ROOT:-/usr/local}"
    if [[ "$restricted_owner" =~ ^[0-9]+$ ]]; then restricted_uid="$restricted_owner"; else restricted_uid="$(id -u "$restricted_owner")"; fi
    if [[ "$restricted_group" =~ ^[0-9]+$ ]]; then restricted_gid="$restricted_group"; else restricted_gid="$(getent group "$restricted_group" | awk -F: 'NR == 1 {print $3}')"; fi
    local changed=0 nullglob_was_set=0 purge_completed=0
    declare -A seen_compilers=()
    declare -A seen_packages=()
    if [[ "$MODE" == "apply" && -n "$BACKUP_DIR" ]] && command -v lynis >/dev/null 2>&1; then
        lynis show details HRDN-7222 > "$BACKUP_DIR/lynis-HRDN-7222-details.txt" 2>&1 || true
        chmod 0600 "$BACKUP_DIR/lynis-HRDN-7222-details.txt"
    fi
    for tool in "${lynis_tools[@]}"; do
        path="$(compiler_command_path "$tool")"
        [[ -z "$path" ]] || lynis_paths+=("$path")
    done
    for tool in "${restriction_tools[@]}"; do
        path="$(compiler_command_path "$tool")"
        [[ -z "$path" ]] || candidates+=("$path")
    done
    shopt -q nullglob && nullglob_was_set=1
    shopt -s nullglob
    candidates+=(
        "${compiler_usr_root}"/bin/gcc-[0-9]* "${compiler_usr_root}"/bin/g++-[0-9]* "${compiler_usr_root}"/bin/cpp-[0-9]*
        "${compiler_usr_root}"/bin/clang-[0-9]* "${compiler_usr_root}"/bin/clang++-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-gcc "${compiler_usr_root}"/bin/*-linux-gnu-gcc-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-g++ "${compiler_usr_root}"/bin/*-linux-gnu-g++-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-as "${compiler_usr_root}"/bin/*-linux-gnu-ld "${compiler_usr_root}"/bin/*-linux-gnu-ld.*
        "${compiler_local_root}"/bin/gcc* "${compiler_local_root}"/bin/g++* "${compiler_local_root}"/bin/clang*
        "${compiler_local_root}"/bin/cc "${compiler_local_root}"/bin/c++
    )
    [[ "$nullglob_was_set" -eq 1 ]] || shopt -u nullglob

    if [[ "$MODE" == "apply" && -n "$BACKUP_DIR" ]]; then
        : > "$BACKUP_DIR/compiler-toolchain-inventory.txt"
        chmod 0600 "$BACKUP_DIR/compiler-toolchain-inventory.txt"
    fi
    for path in "${lynis_paths[@]}"; do
        real="$(readlink -f "$path" 2>/dev/null || true)"
        [[ -f "$real" ]] || continue
        package="$(dpkg-query -S "$real" "$path" 2>/dev/null | awk -F: 'NR == 1 {print $1}' | sed 's/:.*$//' || true)"
        if [[ "$MODE" == "apply" && -n "$BACKUP_DIR" ]]; then
            printf 'lynis-binary=%s\treal=%s\tpackage=%s\n' "$path" "$real" "${package:-unmanaged}" >> "$BACKUP_DIR/compiler-toolchain-inventory.txt"
        fi
        if [[ -n "$package" && -z "${seen_packages[$package]+present}" ]]; then
            seen_packages["$package"]=1
            owner_packages+=("$package")
        fi
    done

    if [[ "$AGGRESSIVE" -eq 1 && ${#owner_packages[@]} -gt 0 ]]; then
        if [[ "$MODE" == "dry-run" ]]; then
            log INFO "Would simulate purge of Lynis-detected compiler owner packages: ${owner_packages[*]}"
        elif simulation="$(LC_ALL=C apt-get -s purge "${owner_packages[@]}" 2>&1)"; then
            mapfile -t removals < <(parse_apt_purge_packages <<<"$simulation")
            if dkms_is_in_use; then
                unsafe_reason="active DKMS modules or installed *-dkms packages require the build toolchain"
            fi
            for package in "${removals[@]}"; do
                case "$package" in
                    gcc|gcc-[0-9]*|g++|g++-[0-9]*|clang|clang-[0-9]*|binutils|binutils-*|build-essential|cpp|cpp-[0-9]*) ;;
                    *) unsafe_removals+=("$package") ;;
                esac
            done
            if ((${#unsafe_removals[@]})); then
                printf -v unsafe_list '%s, ' "${unsafe_removals[@]}"
                unsafe_list="${unsafe_list%, }"
                unsafe_reason="APT simulation would also purge non-toolchain/dependent packages: ${unsafe_list}"
            fi
            if [[ -z "$unsafe_reason" && ${#removals[@]} -gt 0 ]] \
                && run_streamed env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${owner_packages[@]}"; then
                PACKAGES_REMOVED+=("${owner_packages[@]}")
                purge_completed=1
                if run_streamed apt-get check; then
                    record_change "Removed safely dispensable Lynis-detected compiler packages after APT dependency simulation: ${owner_packages[*]}"
                else
                    unsafe_reason="toolchain packages were removed but post-purge APT validation failed"
                fi
            elif [[ -z "$unsafe_reason" ]]; then
                unsafe_reason="simulated toolchain purge failed"
            fi
        else
            unsafe_reason="APT simulation failed"
        fi
    fi
    if [[ -n "$unsafe_reason" ]]; then
        record_skip "HRDN-7220" "compiler packages retained: ${unsafe_reason}; binaries are restricted root-only and inventory is in ${BACKUP_DIR:-planned}/compiler-toolchain-inventory.txt"
    fi

    candidates=()
    for tool in "${restriction_tools[@]}"; do
        path="$(compiler_command_path "$tool")"
        [[ -z "$path" ]] || candidates+=("$path")
    done
    nullglob_was_set=0
    shopt -q nullglob && nullglob_was_set=1
    shopt -s nullglob
    candidates+=(
        "${compiler_usr_root}"/bin/gcc-[0-9]* "${compiler_usr_root}"/bin/g++-[0-9]* "${compiler_usr_root}"/bin/cpp-[0-9]*
        "${compiler_usr_root}"/bin/clang-[0-9]* "${compiler_usr_root}"/bin/clang++-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-gcc "${compiler_usr_root}"/bin/*-linux-gnu-gcc-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-g++ "${compiler_usr_root}"/bin/*-linux-gnu-g++-[0-9]*
        "${compiler_usr_root}"/bin/*-linux-gnu-as "${compiler_usr_root}"/bin/*-linux-gnu-ld "${compiler_usr_root}"/bin/*-linux-gnu-ld.*
    )
    [[ "$nullglob_was_set" -eq 1 ]] || shopt -u nullglob
    seen_compilers=()
    for path in "${candidates[@]}"; do
        [[ -e "$path" || -L "$path" ]] || continue
        real="$(readlink -f "$path" 2>/dev/null || true)"
        [[ -f "$real" ]] || continue
        [[ -z "${seen_compilers[$real]+present}" ]] || continue
        seen_compilers["$real"]=1
        if [[ "$AGGRESSIVE" -eq 1 ]]; then
            mode="$(stat -c '%a' "$real" 2>/dev/null || true)"
            owner_id="$(stat -c '%u' "$real" 2>/dev/null || true)"
            group_id="$(stat -c '%g' "$real" 2>/dev/null || true)"
            if [[ "$owner_id" != "$restricted_uid" || "$group_id" != "$restricted_gid" ]]; then
                run chown "${restricted_owner}:${restricted_group}" "$real"
                changed=1
            fi
            if [[ "$mode" != 750 ]]; then
                run chmod 0750 "$real"
                changed=1
            fi
            if [[ "$MODE" == "apply" ]]; then
                mode="$(stat -c '%a' "$real" 2>/dev/null || true)"
                owner="$(stat -c '%U' "$real" 2>/dev/null || true)"
                group="$(stat -c '%G' "$real" 2>/dev/null || true)"
                owner_id="$(stat -c '%u' "$real" 2>/dev/null || true)"
                group_id="$(stat -c '%g' "$real" 2>/dev/null || true)"
                if [[ "$mode" != "750" || "$owner_id" != "$restricted_uid" || "$group_id" != "$restricted_gid" ]]; then
                    die "Compiler restriction verification failed for ${real}: ${owner:-?}:${group:-?} ${mode:-?}"
                fi
                printf '%s\t%s:%s\t%s\n' "$real" "$owner" "$group" "$mode" >> "$BACKUP_DIR/compiler-hardening.txt"
                if [[ "$mode" == 750 && "$owner_id" == "$restricted_uid" && "$group_id" == "$restricted_gid" ]]; then
                    log INFO "Compiler restriction already current for ${real}"
                fi
            fi
        else
            record_skip "HRDN-7222:${real}" "compiler exists; use --aggressive to restrict execution to root"
        fi
    done
    if [[ "$changed" -eq 1 ]]; then
        record_change "Restricted remaining compiler, assembler, linker, and make binaries to root:root 0750 (safe purge completed: ${purge_completed})"
    elif [[ "$AGGRESSIVE" -eq 1 ]]; then
        log INFO "No compiler ownership/mode changes were required"
    fi
    return 0
}

configure_malware_scanner() {
    if command -v rkhunter >/dev/null 2>&1; then
        local baseline_changed=0 property_db="${HARDEN_RKHUNTER_PROPERTY_DB:-/var/lib/rkhunter/db/rkhunter.dat}"
        local defaults_file="${HARDEN_RKHUNTER_DEFAULTS:-/etc/default/rkhunter}"
        local dpkg_status="${HARDEN_DPKG_STATUS:-/var/lib/dpkg/status}"
        local pending_marker="${HARDEN_RKHUNTER_PENDING_MARKER:-/var/lib/rkhunter/db/.harden-propupd-required}"
        [[ -f "$defaults_file" ]] || {
            if [[ "$MODE" == "apply" ]]; then
                install -o root -g root -m 0644 /dev/null "$defaults_file"
                baseline_changed=1
            fi
        }
        replace_setting "$defaults_file" CRON_DAILY_RUN '"true"' '='
        [[ "$MANAGED_SETTING_CHANGED" -eq 0 ]] || baseline_changed=1
        replace_setting "$defaults_file" CRON_DB_UPDATE '"true"' '='
        [[ "$MANAGED_SETTING_CHANGED" -eq 0 ]] || baseline_changed=1
        replace_setting "$defaults_file" APT_AUTOGEN '"true"' '='
        [[ "$MANAGED_SETTING_CHANGED" -eq 0 ]] || baseline_changed=1
        if [[ "$MODE" == "apply" ]]; then
            if [[ "$baseline_changed" -eq 1 || ! -s "$property_db" || "$dpkg_status" -nt "$property_db" || -e "$pending_marker" ]]; then
                if [[ ! -d "$(dirname -- "$pending_marker")" ]]; then
                    install -d -o root -g root -m 0700 "$(dirname -- "$pending_marker")"
                fi
                : > "$pending_marker"
                chmod 0600 "$pending_marker"
                if run_streamed rkhunter --propupd; then
                    rm -f -- "$pending_marker"
                    record_change "Enabled daily rkhunter checks and updated the trusted property baseline after a relevant configuration/package change"
                else
                    record_skip "HRDN-7230:rkhunter" "rkhunter property baseline update failed"
                fi
            else
                log INFO "rkhunter configuration and package property baseline are unchanged; --propupd is not required"
            fi
        fi
    elif command -v chkrootkit >/dev/null 2>&1; then
        [[ -f /etc/chkrootkit.conf ]] || {
            if [[ "$MODE" == "apply" ]]; then install -o root -g root -m 0644 /dev/null /etc/chkrootkit.conf; fi
        }
        replace_setting /etc/chkrootkit.conf RUN_DAILY '"true"' '='
        replace_setting /etc/chkrootkit.conf DIFF_MODE '"true"' '='
        record_change "Enabled daily chkrootkit checks"
    else
        record_skip "HRDN-7230" "no repository-provided malware/rootkit scanner is installed"
    fi
}

aide_runtime_path() {
    local config="$1" setting="$2"
    awk -F= -v wanted="$setting" '
        {
            key=$1; gsub(/[[:space:]]/, "", key)
            if (key != wanted) next
            value=$0; sub(/^[^=]*=/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            gsub(/^"|"$/, "", value)
            sub(/^file:/, "", value)
            sub(/^\/+/, "/", value)
            if (value ~ /^\//) { print value; exit }
        }
    ' "$config"
}

validate_aide_service_context() {
    local service="$1" vendor_context="$2" runtime_config="$3" database_path="$4" aide_policy="$5"
    local context_report="$BACKUP_DIR/aide-service-context.txt"
    local load_state="" service_user="" ambient_caps="" result="" exec_status=""
    load_state="$(systemctl show "$service" -p LoadState --value 2>/dev/null || true)"
    service_user="$(systemctl show "$service" -p User --value 2>/dev/null || true)"
    ambient_caps="$(systemctl show "$service" -p AmbientCapabilities --value 2>/dev/null || true)"
    if [[ "$load_state" != "loaded" ]]; then
        log ERROR "AIDE check service ${service} is not loaded"
        return 1
    fi
    if [[ "$vendor_context" -eq 1 ]]; then
        if [[ "$service_user" != "_aide" ]] \
            || ! grep -Eiq 'CAP_DAC_READ_SEARCH' <<<"$ambient_caps" \
            || ! grep -Eiq 'CAP_AUDIT_WRITE' <<<"$ambient_caps"; then
            log ERROR "Vendor AIDE service ${service} lacks the expected _aide user/capability context"
            return 1
        fi
    fi
    {
        printf 'AIDE service context validated %s\n' "$(timestamp)"
        systemctl show "$service" -p Id -p LoadState -p User -p Group \
            -p AmbientCapabilities -p CapabilityBoundingSet -p ExecStart
        stat -c 'runtime %U:%G %a %n' "$runtime_config"
        stat -c 'policy %U:%G %a %n' "$aide_policy"
        stat -c 'database %U:%G %a %n' "$database_path"
    } > "$context_report" 2>&1 || {
        log ERROR "Could not record the AIDE service/config/database execution context"
        return 1
    }
    chmod 0600 "$context_report"
    run_streamed systemctl reset-failed "$service" || true
    log INFO "Running one validated AIDE check through the actual ${service} execution context"
    if ! run_streamed systemctl start "$service"; then
        log ERROR "AIDE check service ${service} failed against the active runtime/database"
        return 1
    fi
    result="$(systemctl show "$service" -p Result --value 2>/dev/null || true)"
    exec_status="$(systemctl show "$service" -p ExecMainStatus --value 2>/dev/null || true)"
    {
        printf 'Result=%s\n' "$result"
        printf 'ExecMainStatus=%s\n' "$exec_status"
    } >> "$context_report"
    if [[ "$result" != "success" ]] || systemctl is-failed --quiet "$service"; then
        log ERROR "AIDE service-context check was not successful (Result=${result:-unknown}, ExecMainStatus=${exec_status:-unknown})"
        return 1
    fi
    log OK "AIDE service-context check succeeded via ${service} as ${service_user:-root}"
    return 0
}

install_aide_primary_sha2_group() {
    local runtime_config="$1" temporary mode owner group
    if awk '
        /^# BEGIN harden[.]sh SHA-2 group$/ {managed=1}
        managed && /^HardenSHA2 = p\+ftype\+i\+l\+n\+u\+g\+s\+b\+m\+c\+sha256\+sha512$/ {valid=1}
        /^# END harden[.]sh SHA-2 group$/ && managed {complete=1; managed=0}
        END {exit !(valid && complete)}
    ' "$runtime_config"; then
        return 1
    fi
    temporary="$(mktemp)"
    awk '
        function print_group() {
            print "# BEGIN harden.sh SHA-2 group"
            print "# Kept in the primary runtime config because AIDE and Lynis 3.1.6 both evaluate this effective definition."
            print "HardenSHA2 = p+ftype+i+l+n+u+g+s+b+m+c+sha256+sha512"
            print "# END harden.sh SHA-2 group"
            print ""
            inserted=1
        }
        /^# BEGIN harden[.]sh SHA-2 group$/ {managed=1; next}
        /^# END harden[.]sh SHA-2 group$/ {managed=0; next}
        managed {next}
        /^[[:space:]]*HardenSHA2[[:space:]]*=/ {next}
        /^@@(x_)?include[[:space:]]+/ && !inserted {print_group()}
        {print}
        END {
            if (!inserted) {
                print ""
                print_group()
            }
        }
    ' "$runtime_config" > "$temporary"
    if cmp -s "$temporary" "$runtime_config"; then
        rm -f -- "$temporary"
        return 1
    fi
    mode="$(stat -c '%a' "$runtime_config" 2>/dev/null || printf 0644)"
    owner="$(stat -c '%U' "$runtime_config" 2>/dev/null || printf root)"
    group="$(stat -c '%G' "$runtime_config" 2>/dev/null || printf root)"
    install -o "$owner" -g "$group" -m "$mode" "$temporary" "$runtime_config"
    rm -f -- "$temporary"
    return 0
}

configure_aide() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would validate the distribution AIDE runtime, add SHA256+SHA512 policy, atomically activate a missing or policy-obsolete baseline, verify aide --check, and only then enable its timer"
        AIDE_STATUS="PLANNED"
        return 0
    fi
    local aide_etc_dir="${HARDEN_AIDE_ETC_DIR:-/etc/aide}"
    local aide_state_dir="${HARDEN_AIDE_STATE_DIR:-/var/lib/aide}"
    local systemd_dir="${HARDEN_SYSTEMD_DIR:-/etc/systemd/system}"
    local managed_owner="${HARDEN_TEST_OWNER:-root}"
    local managed_group="${HARDEN_TEST_GROUP:-root}"
    if [[ ! -s "${aide_etc_dir}/aide.conf" && ! -s /etc/aide.conf ]]; then
        install_package aide-common || true
    fi
    if ! command -v aide >/dev/null 2>&1; then
        install_package aide || true
    fi
    local aide_raw="" aide_config="" runtime_config="" aide_timer="" aide_service=""
    local vendor_service_context=0
    local database_path="" database_out_path="" aide_check_output="" aide_check_rc=0
    local aide_policy="${aide_etc_dir}/aide.conf.d/99_harden_sha2"
    local aide_policy_changed=0 aide_config_changed=0 baseline_required=0
    local policy_content="" candidate="" version_output="" active_tmp="" fint_evidence=""
    local database_owner="" database_group="" database_parent=""
    local policy_digest="" policy_stamp="" stamp_tmp=""
    aide_raw="$(command -v aide 2>/dev/null || true)"
    # Match Lynis 3.1.6 FINT-4315/FINT-4402 search order exactly: its last
    # existing config wins (/etc, /etc/aide, then /usr/local/etc).
    for candidate in /etc/aide.conf "${aide_etc_dir}/aide.conf" /usr/local/etc/aide.conf; do
        if [[ -s "$candidate" ]]; then
            aide_config="$candidate"
        fi
    done
    if [[ -z "$aide_raw" || -z "$aide_config" ]]; then
        AIDE_STATUS="FAILED"
        systemctl disable --now aide-check.timer dailyaidecheck.timer >/dev/null 2>&1 || true
        record_skip "FINT-4315" "AIDE binary and a real non-empty configuration are both required; aide-common did not provide one"
        return 0
    fi
    run_streamed systemctl stop aide-check.timer dailyaidecheck.timer \
        aide-check.service dailyaidecheck.service || true
    policy_content='# Managed by harden.sh: SHA-2 integrity paths v1.1.3
=/etc/passwd HardenSHA2
=/etc/group HardenSHA2
=/etc/shadow HardenSHA2
=/etc/gshadow HardenSHA2
=/etc/sudoers HardenSHA2
/etc/sudoers\.d/.* HardenSHA2
/etc/ssh/.* HardenSHA2
/etc/pam\.d/.* HardenSHA2
/etc/audit/.* HardenSHA2'
    if [[ ! -f "$aide_policy" ]] || ! cmp -s <(printf '%s\n' "$policy_content") "$aide_policy"; then
        aide_policy_changed=1
    fi
    transaction_copy "$aide_policy" aide-sha2-policy
    printf '%s\n' "$policy_content" | install_managed_file "$aide_policy" 0644 "$managed_owner" "$managed_group"
    runtime_config="$aide_config"
    transaction_copy "$runtime_config" aide-runtime-config
    if install_aide_primary_sha2_group "$runtime_config"; then
        aide_config_changed=1
        record_change "Installed the effective HardenSHA2 group in primary AIDE runtime config ${runtime_config}"
    fi
    if ! awk -v directory="${aide_etc_dir}/aide.conf.d" \
        '$1 ~ /^@@(x_)?include$/ && $2 == directory {found=1} END {exit !found}' "$runtime_config" \
        && ! grep -Fqx "@@include ${aide_policy}" "$runtime_config"; then
        printf '\n@@include %s\n' "$aide_policy" >> "$runtime_config"
        aide_config_changed=1
    fi
    version_output="$("$aide_raw" --version 2>&1 || true)"
    if ! grep -Eiq '(^|[^[:alnum:]])sha256([^[:alnum:]]|$)' <<<"$version_output" \
        || ! grep -Eiq '(^|[^[:alnum:]])sha512([^[:alnum:]]|$)' <<<"$version_output"; then
        AIDE_STATUS="FAILED"
        systemctl disable --now aide-check.timer dailyaidecheck.timer >/dev/null 2>&1 || true
        record_skip "FINT-4402" "the installed AIDE binary does not report both SHA256 and SHA512 support"
        return 0
    fi
    if ! "$aide_raw" --config="$runtime_config" --config-check > "$BACKUP_DIR/aide-config-check.txt" 2>&1; then
        AIDE_STATUS="FAILED"
        systemctl disable --now aide-check.timer dailyaidecheck.timer >/dev/null 2>&1 || true
        record_skip "FINT-4315" "AIDE rejected active runtime configuration ${runtime_config}; no timer was enabled"
        return 0
    fi
    chmod 0600 "$BACKUP_DIR/aide-config-check.txt"
    fint_evidence="$BACKUP_DIR/aide-lynis-FINT-4402-evidence.txt"
    {
        printf 'Lynis 3.1.6 FINT-4402-compatible effective primary configuration evidence\n'
        printf 'runtime_config=%s\n' "$runtime_config"
        awk '!/^[[:space:]]*#/ && /= .*(sha256|sha512)/ {print}' "$runtime_config"
        printf 'aide_config_check=success\n'
    } > "$fint_evidence"
    chmod 0600 "$fint_evidence"
    if ! awk '!/^[[:space:]]*#/ && /= .*(sha256|sha512)/ {found=1} END {exit !found}' "$runtime_config"; then
        AIDE_STATUS="FAILED"
        systemctl disable --now aide-check.timer dailyaidecheck.timer >/dev/null 2>&1 || true
        record_skip "FINT-4402" "effective primary config passed AIDE but did not expose its SHA-2 group to Lynis 3.1.6; see ${fint_evidence}"
        return 0
    fi
    database_path="$(aide_runtime_path "$runtime_config" database_in 2>/dev/null || true)"
    [[ -n "$database_path" ]] || database_path="$(aide_runtime_path "$runtime_config" database 2>/dev/null || true)"
    database_out_path="$(aide_runtime_path "$runtime_config" database_out 2>/dev/null || true)"
    if [[ -z "$database_path" || -z "$database_out_path" || "$database_path" == "$database_out_path" ]]; then
        AIDE_STATUS="FAILED"
        systemctl disable --now aide-check.timer dailyaidecheck.timer >/dev/null 2>&1 || true
        record_skip "FINT-4316" "active runtime ${runtime_config} must declare distinct absolute database_in and database_out file paths"
        return 0
    fi
    case "$database_path:$database_out_path" in
        "${aide_state_dir}"/*:"${aide_state_dir}"/*) ;;
        *) log WARN "AIDE runtime uses distribution-defined database paths outside ${aide_state_dir}: ${database_path}, ${database_out_path}" ;;
    esac
    policy_digest="$(sha256sum "$runtime_config" "$aide_policy" | sha256sum | awk '{print $1}')"
    policy_stamp="${database_path}.harden-policy.sha256"
    if unit_file_exists dailyaidecheck.timer; then
        aide_timer=dailyaidecheck.timer
        aide_service=dailyaidecheck.service
        vendor_service_context=1
        if [[ -f "${systemd_dir}/aide-check.timer" ]] \
            && grep -q '^Description=Daily AIDE integrity check' "${systemd_dir}/aide-check.timer"; then
            systemctl disable --now aide-check.timer >/dev/null 2>&1 || true
        fi
        log INFO "Using the aide-common vendor timer ${aide_timer}"
    else
        aide_timer=aide-check.timer
        aide_service=aide-check.service
        install_managed_file "${systemd_dir}/aide-check.service" 0644 "$managed_owner" "$managed_group" <<EOF
[Unit]
Description=File integrity check with AIDE
After=local-fs.target

[Service]
Type=oneshot
ExecStart=${aide_raw} --config=${runtime_config} --check
Nice=19
IOSchedulingClass=idle
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
UMask=0027
SuccessExitStatus=1 2 3 4 5 6 7
EOF
        install_managed_file "${systemd_dir}/aide-check.timer" 0644 "$managed_owner" "$managed_group" <<'EOF'
[Unit]
Description=Daily AIDE integrity check

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    fi
    if ! run_streamed systemctl daemon-reload; then
        AIDE_STATUS="FAILED"
        record_skip "FINT-4316" "systemd could not load the validated AIDE timer definition"
        return 0
    fi
    # A persistent timer must not race an initialization against a missing or
    # policy-obsolete database. It is enabled again only after a readable
    # baseline has been proven below.
    run_streamed systemctl stop "$aide_timer" || true
    if [[ ! -s "$database_path" || ! -s "$policy_stamp" \
        || "$(tr -d '[:space:]' < "$policy_stamp" 2>/dev/null || true)" != "$policy_digest" \
        || "$aide_policy_changed" -eq 1 || "$aide_config_changed" -eq 1 ]]; then
        baseline_required=1
        log INFO "Initializing the AIDE database from validated runtime ${runtime_config}; this can take several minutes"
        rm -f -- "$database_out_path"
        if ! "$aide_raw" --config="$runtime_config" --init > "$BACKUP_DIR/aideinit.txt" 2>&1 \
            || [[ ! -s "$database_out_path" ]]; then
            AIDE_STATUS="FAILED"
            systemctl disable --now "$aide_timer" >/dev/null 2>&1 || true
            record_skip "FINT-4316" "aide --init failed to create database_out declared by ${runtime_config}; see ${BACKUP_DIR}/aideinit.txt"
            return 0
        fi
        chmod 0600 "$BACKUP_DIR/aideinit.txt"
        database_parent="$(dirname -- "$database_path")"
        if [[ -e "$database_parent" || -L "$database_parent" ]]; then
            [[ -d "$database_parent" ]] || {
                AIDE_STATUS="FAILED"
                record_skip "FINT-4316" "database_in parent is not a directory: ${database_parent}"
                return 0
            }
        else
            install -d -o "$managed_owner" -g "$managed_group" -m 0700 "$database_parent"
        fi
        database_owner="$(stat -c '%U' "$database_out_path" 2>/dev/null || printf '%s' "$managed_owner")"
        database_group="$(stat -c '%G' "$database_out_path" 2>/dev/null || printf '%s' "$managed_group")"
        active_tmp="$(mktemp "${database_path}.harden.XXXXXX")"
        install -o "$database_owner" -g "$database_group" -m 0600 "$database_out_path" "$active_tmp"
        mv -f -- "$active_tmp" "$database_path"
        stamp_tmp="$(mktemp "${policy_stamp}.harden.XXXXXX")"
        printf '%s\n' "$policy_digest" > "$stamp_tmp"
        install -o "$database_owner" -g "$database_group" -m 0600 "$stamp_tmp" "${policy_stamp}.new"
        mv -f -- "${policy_stamp}.new" "$policy_stamp"
        rm -f -- "$stamp_tmp"
    else
        log INFO "Existing active AIDE database matches the unchanged managed policy; baseline rebuild skipped"
    fi
    if [[ ! -s "$database_path" ]]; then
        AIDE_STATUS="FAILED"
        systemctl disable --now "$aide_timer" >/dev/null 2>&1 || true
        record_skip "FINT-4316" "active database_in ${database_path} is absent or empty after initialization"
        return 0
    fi
    if aide_check_output="$("$aide_raw" --config="$runtime_config" --check 2>&1)"; then
        aide_check_rc=0
    else
        aide_check_rc=$?
    fi
    printf '%s\n' "$aide_check_output" > "$BACKUP_DIR/aide-initial-check.txt"
    chmod 0600 "$BACKUP_DIR/aide-initial-check.txt"
    if [[ "$aide_check_rc" -gt 7 ]]; then
        AIDE_STATUS="FAILED"
        systemctl disable --now "$aide_timer" >/dev/null 2>&1 || true
        record_skip "FINT-4316" "the generated database exists but AIDE could not read and check it (exit ${aide_check_rc}); see ${BACKUP_DIR}/aide-initial-check.txt"
        return 0
    elif [[ "$aide_check_rc" -ne 0 ]]; then
        log WARN "AIDE baseline is readable but the immediate check reported changes (exit ${aide_check_rc}); see ${BACKUP_DIR}/aide-initial-check.txt"
    fi
    if ! validate_aide_service_context "$aide_service" "$vendor_service_context" \
        "$runtime_config" "$database_path" "$aide_policy"; then
        AIDE_STATUS="FAILED"
        systemctl disable --now "$aide_timer" >/dev/null 2>&1 || true
        record_skip "FINT-4316" "the actual ${aide_service} execution context could not read and check the active AIDE runtime/database"
        return 0
    fi
    if ! run_streamed systemctl enable --now "$aide_timer" \
        || ! systemctl is-enabled --quiet "$aide_timer" \
        || ! systemctl is-active --quiet "$aide_timer"; then
        AIDE_STATUS="FAILED"
        systemctl disable --now "$aide_timer" >/dev/null 2>&1 || true
        record_skip "FINT-4316" "the validated AIDE timer could not be enabled after baseline verification"
        return 0
    fi
    AIDE_STATUS="OK"
    record_change "Validated SHA256/SHA512 runtime ${runtime_config}, atomically activated database ${database_path}, successful readable check, and enabled active ${aide_timer} (baseline rebuilt: ${baseline_required})"
    return 0
}

systemd_unit_for_pid() {
    local pid="$1" cgroup_file="/proc/${pid}/cgroup"
    [[ -r "$cgroup_file" ]] || return 1
    awk -F/ '
        {
            for (field=NF; field>=1; field--) {
                if ($field ~ /^[A-Za-z0-9_.@\\-]+[.]service$/) { print $field; exit }
            }
        }
    ' "$cgroup_file"
}

remediate_deleted_open_files() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would map lsof +L1 PIDs to systemd units, restart only allowlisted safe services, and rescan"
        return 0
    fi
    if ! command -v lsof >/dev/null 2>&1; then
        record_skip "LOGG-2190" "lsof is unavailable"
        return 0
    fi
    local before="$BACKUP_DIR/deleted-open-files-before-remediation.txt"
    local after="$BACKUP_DIR/deleted-open-files-after-remediation.txt"
    local pids="" pid unit remaining=""
    declare -A restart_units=()
    lsof +L1 > "$before" 2>&1 || true
    chmod 0600 "$before"
    pids="$(awk 'NR > 1 && $2 ~ /^[0-9]+$/ {print $2}' "$before" | sort -u)"
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        unit="$(systemd_unit_for_pid "$pid" 2>/dev/null || true)"
        case "$unit" in
            rsyslog.service|fail2ban.service|cron.service|uuidd.service|networkd-dispatcher.service|acct.service)
                restart_units["$unit"]=1
                ;;
        esac
    done <<<"$pids"
    for unit in "${!restart_units[@]}"; do
        if systemctl is-active --quiet "$unit" && run_streamed systemctl restart "$unit" \
            && systemctl is-active --quiet "$unit"; then
            record_change "Restarted safe service ${unit} to release deleted open files"
        else
            log WARN "Did not restart ${unit} or it failed its post-restart health check"
        fi
    done
    lsof +L1 > "$after" 2>&1 || true
    chmod 0600 "$after"
    remaining="$(awk 'NR > 1 && $2 ~ /^[0-9]+$/ {print $2; found=1} END {if (!found) exit 0}' "$after")"
    if [[ -n "$remaining" ]]; then
        record_skip "LOGG-2190" "deleted open files remain after safe targeted restarts; see ${after}"
    else
        record_change "Confirmed that no deleted open files remain after targeted remediation"
    fi
    return 0
}

diagnose_iowait_processes() {
    local stage="${1:-validation}"
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would inventory PID/unit/stat/wchan/command for PROC-3614 (${stage}) without terminating processes"
        return 0
    fi
    local report="${HARDEN_IOWAIT_REPORT:-/root/hardening-iowait-processes.txt}"
    local ps_output="" rc=0 blocked="" pid stat wchan comm command unit classification
    local current_pids="" persistent=0
    if ps_output="$(ps -eo pid=,stat=,wchan:32=,comm=,args= 2>&1)"; then
        rc=0
    else
        rc=$?
    fi
    if [[ "$rc" -ne 0 ]]; then
        log WARN "ps failed while diagnosing PROC-3614 (exit ${rc})"
        return 0
    fi
    blocked="$(awk '$2 ~ /^D/ {print}' <<<"$ps_output")"
    current_pids="$(awk '$2 ~ /^D/ {print $1}' <<<"$ps_output")"
    {
        printf '\n=== PROC-3614 snapshot: %s at %s ===\n' "$stage" "$(timestamp)"
        printf '%s\n' 'PID UNIT STAT WCHAN COMMAND CLASSIFICATION'
        if [[ -n "$blocked" ]]; then
            while IFS=$' \t' read -r pid stat wchan comm command; do
                [[ -n "$pid" ]] || continue
                unit="$(systemd_unit_for_pid "$pid" 2>/dev/null || true)"
                [[ -n "$unit" ]] || unit="none"
                classification="new/transient-candidate"
                if grep -Fxq "$pid" <<<"$IOWAIT_PREVIOUS_PIDS"; then
                    classification="persistent-across-snapshots"
                    persistent=1
                fi
                printf '%s\t%s\t%s\t%s\t%s %s\t%s\n' "$pid" "$unit" "$stat" "$wchan" "$comm" "$command" "$classification"
                printf '%s\n' "-- /proc/${pid}/io --"
                sed -n '1,20p' "/proc/${pid}/io" 2>/dev/null || true
                printf '%s\n' "-- /proc/${pid}/fd targets (device/filesystem evidence) --"
                find "/proc/${pid}/fd" -maxdepth 1 -type l -printf '%f -> %l\n' 2>/dev/null || true
            done <<<"$blocked"
        else
            printf '%s\n' 'none'
            if [[ -n "$IOWAIT_PREVIOUS_PIDS" ]]; then
                printf 'classification=previous D-state PIDs resolved; transient IO wait\n'
            fi
        fi
    } >> "$report"
    chmod 0600 "$report"
    if [[ -n "$blocked" ]]; then
        if [[ "$persistent" -eq 1 ]]; then
            record_skip "PROC-3614" "persistent D-state processes were observed across snapshots; PID/unit/stat/wchan/command evidence is in ${report}; none were killed"
        else
            record_skip "PROC-3614" "new D-state processes were documented for recheck in ${report}; none were killed"
        fi
    else
        record_change "PROC-3614 ${stage} check found no processes in uninterruptible IO wait"
    fi
    IOWAIT_PREVIOUS_PIDS="$current_pids"
    return 0
}

run_validation() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would run post-hardening validation for SSH, sudo, systemd, nftables, auditd, AppArmor, sockets, sysctl, APT, and fstab"
        VALIDATION_COMPLETED=1
        return 0
    fi
    local report=/root/hardening-validation.txt
    : > "$report"
    chmod 0600 "$report"
    {
        printf 'Hardening validation at %s\n\n' "$(timestamp)"
        if [[ -n "$SSHD_BIN" ]]; then
            printf '%s\n' '=== sshd -t ==='
            "$SSHD_BIN" -t
        fi
        if command -v visudo >/dev/null 2>&1; then
            printf '%s\n' '=== visudo -c ==='
            visudo -c
        fi
        printf '%s\n' '=== systemctl --failed ==='
        systemctl --failed --no-pager || true
        printf '%s\n' '=== systemctl is-system-running ==='
        systemctl is-system-running || true
        if command -v nft >/dev/null 2>&1; then
            printf '%s\n' '=== nft list ruleset ==='
            nft list ruleset
        fi
        if command -v auditctl >/dev/null 2>&1; then
            printf '%s\n' '=== auditctl -s ==='
            auditctl -s || true
        fi
        if command -v aa-status >/dev/null 2>&1; then
            printf '%s\n' '=== aa-status ==='
            aa-status || true
        fi
        if command -v ss >/dev/null 2>&1; then
            printf '%s\n' '=== ss -tulpn ==='
            ss -tulpn
        fi
        printf '%s\n' '=== sysctl --system ==='
        sysctl --system || true
        if command -v findmnt >/dev/null 2>&1; then
            printf '%s\n' '=== findmnt fstab verification ==='
            findmnt --verify --tab-file /etc/fstab || true
        fi
        printf '%s\n' '=== apt-get check ==='
        apt-get check
        printf '%s\n' '=== systemd-analyze security summary ==='
        systemd-analyze security --no-pager || true
    } >> "$report" 2>&1
    systemd-analyze security --no-pager > /root/systemd-security-after.txt 2>&1 || true
    chmod 0600 /root/systemd-security-after.txt
    local failed_units
    failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' || true)"
    if [[ -n "$failed_units" ]]; then
        log WARN "Failed systemd units remain: ${failed_units//$'\n'/, }"
    else
        log OK "Post-hardening validation found no failed systemd units"
    fi
    record_change "Saved comprehensive validation output to ${report}"
    VALIDATION_COMPLETED=1
    return 0
}

run_lynis() {
    local output="$1" label="$2"
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would run Lynis audit (${label}) and save ${output}"
        return 0
    fi
    if ! command -v lynis >/dev/null 2>&1; then
        record_skip "Lynis ${label}" "lynis is not installed"
        return 1
    fi
    log INFO "Running Lynis ${label}; output will be saved to ${output}"
    local rc tee_rc render_rc
    local -a pipeline_status=()
    set +e
    TERM=dumb NO_COLOR=1 lynis audit system 2>&1 | tee "$output" | emit_block
    pipeline_status=("${PIPESTATUS[@]}")
    rc="${pipeline_status[0]}"
    tee_rc="${pipeline_status[1]}"
    render_rc="${pipeline_status[2]}"
    set -e
    [[ -s "$output" ]] || {
        log ERROR "Lynis ${label} produced no report output"
        return 1
    }
    chmod 0600 "$output"
    [[ -f /var/log/lynis-report.dat ]] && cp -a /var/log/lynis-report.dat "${output%.txt}-report.dat"
    if [[ "$rc" -ne 0 ]]; then
        log ERROR "Lynis ${label} exited with status ${rc}; its report was retained"
        return "$rc"
    fi
    if [[ "$tee_rc" -ne 0 ]]; then
        log ERROR "Could not persist the Lynis ${label} output (tee exit ${tee_rc})"
        return "$tee_rc"
    fi
    if [[ "$render_rc" -ne 0 ]]; then
        log ERROR "Could not render/log the Lynis ${label} output (renderer exit ${render_rc})"
        return "$render_rc"
    fi
    record_change "Completed Lynis ${label} and saved a non-empty report to ${output}"
    return 0
}

extract_lynis_score() {
    local report="$1" data="$2" score=""
    if [[ -s "$report" ]]; then
        score="$(sed $'s/\033\\[[0-9;]*[[:alpha:]]//g' "$report" | awk '
            /Hardening index[[:space:]]*:/ {
                line=$0
                sub(/^.*Hardening index[[:space:]]*:[[:space:]]*/, "", line)
                if (match(line, /[0-9]+/)) value=substr(line, RSTART, RLENGTH)
            }
            END {print value}
        ')"
    fi
    if [[ -z "$score" && -s "$data" ]]; then
        score="$(awk -F= '$1 == "hardening_index" {value=$2} END {print value}' "$data")"
    fi
    [[ "$score" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$score"
}

capture_lynis_baseline() {
    local report="${HARDEN_LYNIS_BASELINE_REPORT:-/root/lynis-before-hardening.txt}"
    local data="${HARDEN_LYNIS_BASELINE_DATA:-/root/lynis-before-hardening-report.dat}"
    local score=""
    if [[ "$MODE" == "dry-run" ]]; then
        LYNIS_BEFORE="N/A (dry-run; NOT RUN)"
        log INFO "Dry run: pre-hardening Lynis baseline is NOT RUN because Lynis would write runtime reports"
        return 0
    fi
    if ! command -v lynis >/dev/null 2>&1; then
        LYNIS_BEFORE="N/A (Lynis unavailable)"
        record_skip "Lynis baseline" "lynis is not installed before package hardening; no package was installed merely to obtain a baseline"
        return 0
    fi
    if ! run_lynis "$report" "pre-hardening baseline"; then
        LYNIS_BEFORE="FAILED"
        log WARN "Pre-hardening Lynis baseline failed; its separate report was retained"
        return 0
    fi
    if score="$(extract_lynis_score "$report" "$data")"; then
        LYNIS_BEFORE="$score"
        log OK "Measured pre-hardening Lynis baseline: ${LYNIS_BEFORE}"
    else
        LYNIS_BEFORE="PARSE ERROR"
        log WARN "Could not parse the pre-hardening Lynis score from ${report} or ${data}"
    fi
    return 0
}

second_optimization_pass() {
    if [[ "$MODE" == "dry-run" ]]; then
        log INFO "Would parse first-pass Test IDs, re-assert safe controls, then run Lynis a second time"
        return 0
    fi
    local first=/root/lynis-after-hardening-pass1.txt
    if [[ ! -f "$first" ]]; then
        log WARN "First-pass Lynis report is absent; optimization pass has nothing to parse"
        return 0
    fi
    log INFO "Starting report-driven second optimization pass"
    if grep -q '\[KRNL-6000\]' "$first"; then
        configure_sysctl
    fi
    if grep -q '\[FILE-7524\]' "$first"; then
        [[ -f /etc/crontab ]] && chown root:root /etc/crontab && chmod 0600 /etc/crontab
        [[ -f /etc/ssh/sshd_config ]] && chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config
        chown root:root /etc/sudoers.d 2>/dev/null || true
        chmod 0750 /etc/sudoers.d 2>/dev/null || true
        local dir
        for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
            [[ -d "$dir" ]] && chmod 0700 "$dir"
        done
    fi
    if grep -Eq '\[(ACCT-9622|ACCT-9628|ACCT-9630)\]' "$first"; then
        configure_process_accounting
        [[ "$AUDIT_STATUS" == "OK" ]] || configure_auditd
    fi
    if grep -q '\[DEB-0880\]' "$first"; then configure_fail2ban; fi
    if grep -q '\[SSH-7408\]' "$first" && [[ -n "$SSHD_BIN" ]]; then
        "$SSHD_BIN" -t && run_streamed systemctl reload "$SSH_SERVICE" || true
    fi
    if grep -q '\[PKGS-7346\]' "$first"; then purge_removed_packages; fi
    if grep -q '\[PKGS-7370\]' "$first"; then configure_debsums; fi
    # AIDE is owned exclusively by phase 16 so its database is complete immediately before final Lynis.
    record_change "Completed static second-pass actions selected from remaining first-pass Lynis Test IDs"
}

extract_lynis_summary() {
    local report="${HARDEN_LYNIS_FINAL_REPORT:-/root/lynis-after-hardening.txt}"
    local data="${HARDEN_LYNIS_FINAL_DATA:-/root/lynis-after-hardening-report.dat}"
    local diagnostic="${HARDEN_LYNIS_PARSE_DIAGNOSTIC:-/root/lynis-summary-parse-diagnostics.txt}"
    if [[ "$MODE" == "dry-run" ]]; then
        LYNIS_AFTER="N/A (dry-run)"
        LYNIS_WARNINGS="N/A"
        LYNIS_SUGGESTIONS="N/A"
        LYNIS_PARSE_STATUS="N/A"
        log INFO "Dry run: skipping Lynis summary extraction because no report is written"
        return 0
    fi
    if [[ ! -f "$report" ]]; then
        LYNIS_AFTER="unknown"
        LYNIS_WARNINGS="unknown"
        LYNIS_SUGGESTIONS="unknown"
        LYNIS_PARSE_STATUS="REPORT MISSING"
        log WARN "Final Lynis report is absent; summary values remain unknown"
        return 0
    fi
    LYNIS_AFTER="$(extract_lynis_score "$report" "$data" || true)"
    LYNIS_WARNINGS="$(sed $'s/\033\\[[0-9;]*[[:alpha:]]//g' "$report" | awk '
        /Warnings[[:space:]]*\([0-9]+\)/ {line=$0; sub(/^.*Warnings[[:space:]]*\(/,"",line); sub(/\).*$/,"",line); value=line}
        END {print value}
    ')"
    if grep -q 'Great, no warnings' "$report"; then LYNIS_WARNINGS=0; fi
    [[ -n "$LYNIS_WARNINGS" || ! -s "$data" ]] || LYNIS_WARNINGS="$(grep -c '^warning\[\]=' "$data" || true)"
    LYNIS_SUGGESTIONS="$(sed $'s/\033\\[[0-9;]*[[:alpha:]]//g' "$report" | awk '
        /Suggestions[[:space:]]*\([0-9]+\)/ {line=$0; sub(/^.*Suggestions[[:space:]]*\(/,"",line); sub(/\).*$/,"",line); value=line}
        /Suggestions[[:space:]]*:[[:space:]]*[0-9]+/ {line=$0; sub(/^.*Suggestions[[:space:]]*:[[:space:]]*/,"",line); if (match(line, /^[0-9]+/)) value=substr(line,RSTART,RLENGTH)}
        END {print value}
    ')"
    [[ -n "$LYNIS_SUGGESTIONS" || ! -s "$data" ]] || LYNIS_SUGGESTIONS="$(grep -c '^suggestion\[\]=' "$data" || true)"
    if [[ "$LYNIS_AFTER" =~ ^[0-9]+$ && "$LYNIS_WARNINGS" =~ ^[0-9]+$ \
        && "$LYNIS_SUGGESTIONS" =~ ^[0-9]+$ ]]; then
        LYNIS_PARSE_STATUS="OK"
        rm -f -- "$diagnostic"
    else
        [[ "$LYNIS_AFTER" =~ ^[0-9]+$ ]] || LYNIS_AFTER="PARSE ERROR"
        [[ "$LYNIS_WARNINGS" =~ ^[0-9]+$ ]] || LYNIS_WARNINGS="PARSE ERROR"
        [[ "$LYNIS_SUGGESTIONS" =~ ^[0-9]+$ ]] || LYNIS_SUGGESTIONS="PARSE ERROR"
        LYNIS_PARSE_STATUS="FAILED"
        {
            printf 'Lynis summary parse failure at %s\n' "$(timestamp)"
            grep -E 'Hardening index|Warnings|Suggestions|Great, no warnings' "$report" || true
            [[ ! -s "$data" ]] || grep -E '^(hardening_index|warning\[\]|suggestion\[\])=' "$data" || true
        } > "$diagnostic"
        chmod 0600 "$diagnostic"
        log WARN "Final Lynis summary parse failed; see ${diagnostic}"
    fi
    return 0
}

explain_open_test() {
    local id="$1"
    case "$id" in
        DEB-0280) printf '%s\n' 'Package/module was unavailable or PAM integration was not detected.' 'Install a repository-provided libpam-tmpdir and enable its PAM profile.' 'Per-session temporary directories can affect software expecting shared /tmp paths.' ;;
        DEB-0810) printf '%s\n' 'apt-listbugs is intentionally limited to Debian and repository availability.' 'Use Debian with an available apt-listbugs candidate, or accept the Ubuntu package workflow.' 'Installing a Debian-oriented APT hook on Ubuntu can block or destabilize unattended upgrades.' ;;
        DEB-0811|PKGS-7370|PKGS-7394|DEB-0880) printf '%s\n' 'The package was unavailable or its service/configuration failed validation.' 'Provide the package from an official configured distribution repository and rerun the script.' 'Adding third-party repositories expands supply-chain trust and was intentionally avoided.' ;;
        BOOT-5122) printf '%s\n' 'BOOT-5122 intentionally accepted: no GRUB password is configured to preserve unattended/reliable reboot capability.' 'No change is planned for this deployment.' 'Boot authentication would make unattended recovery and reliable remote reboot dependent on console input.' ;;
        BOOT-5180) printf '%s\n' 'Lynis treats startup-service review as an operator determination.' 'Review the saved enabled/running service inventories for this host role.' 'Disabling a required cloud, VM, storage, or network unit can make the host unreachable.' ;;
        BOOT-5264) printf '%s\n' 'Some system services must retain broad rights for their documented purpose.' 'Add per-service drop-ins after application-specific integration tests.' 'Over-hardening SSH, cron, cloud-init, snapd, or VM agents can break administration or boot.' ;;
        AUTH-9229) printf '%s\n' 'Existing password hashes cannot be rehashed without the users passwords.' 'Have each password-authenticated user change its password after the new hash policy is active.' 'Forcing expiry can lock unattended/service accounts if their ownership is not understood.' ;;
        AUTH-9230) printf '%s\n' 'Lynis 3.1.6 checks legacy SHA_CRYPT rounds even when the effective method is YESCRYPT.' 'Upgrade Lynis when its YESCRYPT-aware test is released; do not add ineffective SHA settings merely for a score.' 'Cosmetic legacy settings create false confidence and do not tune YESCRYPT.' ;;
        AUTH-9262) printf '%s\n' 'PAM strength module was unavailable or could not be inserted into a recognized stack safely.' 'Install libpam-pwquality and use the distribution PAM profile tooling.' 'A malformed PAM stack can lock out every administrator.' ;;
        AUTH-9282) printf '%s\n' 'Fixed account expiration is intentionally not set; password aging and inactivity locking remain enforced.' 'Set an account-specific expiration date only when an owner explicitly requests it.' 'Automatic account expiry can lock out the administrator or unattended service identities.' ;;
        AUTH-9286|AUTH-9328) printf '%s\n' 'Aging/umask settings remain absent for at least one account or alternate auth stack.' 'Review chage output and the account-specific policy.' 'Blind account changes can interrupt service accounts and emergency access.' ;;
        FILE-6310) printf '%s\n' '/home or /var is not a separate filesystem.' 'Repartition/LVM-migrate these paths during a maintenance window.' 'An in-place move can exhaust storage, corrupt boot mounts, or cause prolonged downtime.' ;;
        USB-1000) printf '%s\n' 'USB storage was preserved because --aggressive was not used or USB-backed storage is mounted.' 'Verify hardware dependencies and rerun with --aggressive.' 'Blocking usb-storage can make virtual media, backup disks, or boot/recovery devices unavailable.' ;;
        NAME-4028) printf '%s\n' 'The host has no administrator-provided DNS domain.' 'Create matching forward/reverse DNS and configure a valid FQDN.' 'Inventing a local domain can break TLS, mail, Kerberos, and service discovery.' ;;
        PKGS-7346) printf '%s\n' 'Residual package configuration could not be purged.' 'Review dpkg-query rc entries and purge the named packages.' 'Purge maintainer scripts can remove configuration still needed for rollback.' ;;
        NETW-3200) printf '%s\n' 'A protocol module remains loaded or available despite the modprobe policy.' 'Stop its consumer, unload it, rebuild initramfs, and reboot.' 'Removing an in-use protocol can terminate clustered/storage/network workloads.' ;;
        SSH-7408) printf '%s\n' 'SSH-7408: SSH port intentionally preserved; changing the port is not considered a meaningful security control for this deployment.' 'No Port directive is managed; the detected port is used only for firewall and Fail2ban policy.' 'Changing the listening port can cause lockout without providing a substantive security boundary.' ;;
        LOGG-2154) printf '%s\n' 'No remote logging destination was selected or rsyslog validation failed.' 'Rerun with REMOTE_LOG_SERVER/PORT/PROTOCOL and, for TLS, a trusted CA file.' 'A wrong destination can disclose logs; an invalid queue/TLS setup can drop remote copies.' ;;
        LOGG-2190) printf '%s\n' 'Deleted files remain open after allowlisted safe service restarts.' 'Review deleted-open-files-after-remediation.txt and restart the remaining owner only during an approved maintenance window.' 'Blind service restarts can interrupt SSH, networking, storage, or applications.' ;;
        PROC-3614) printf '%s\n' 'One or more processes were observed in uninterruptible IO wait.' 'Review /root/hardening-iowait-processes.txt and diagnose the named device, filesystem, or kernel wait channel.' 'Killing a blocked process can corrupt data and often cannot complete until the kernel IO wait resolves.' ;;
        ACCT-9622|ACCT-9628|ACCT-9630) printf '%s\n' 'Accounting/audit package or service was unavailable, rejected rules, could not start, or runtime rules were empty.' 'Review journalctl and auditctl -l, correct any rejected kernel-specific rule, and reload with augenrules.' 'Invalid or overly broad audit rules can cause boot delay, log exhaustion, or lost events.' ;;
        FINT-4315|FINT-4316|FINT-4350|FINT-4402) printf '%s\n' 'AIDE was unavailable, its effective SHA-2 runtime policy failed validation, or its declared active database was absent.' 'Review the saved config-check, aide --init, and aide --check output, then initialize a trusted SHA256/SHA512 baseline.' 'A baseline created on a compromised system legitimizes malicious files; scans are I/O intensive.' ;;
        TOOL-5002) printf '%s\n' 'No automation platform was installed solely to satisfy a score.' 'Adopt a real configuration-management platform when there is an operational owner.' 'An unused privileged agent expands attack surface and supply-chain trust.' ;;
        FILE-7524) printf '%s\n' 'At least one Lynis static permission target still differs from its profile.' 'Use lynis show details FILE-7524 and correct only the named object.' 'Blind recursive chmod can break package ownership, setuid helpers, ACLs, and services.' ;;
        KRNL-6000) printf '%s\n' 'All managed sysctls are validated; with active Tailscale, net.ipv4.conf.all.rp_filter=2 is an intentional overlay-routing exception to Lynis expected value 1.' 'Keep value 2 while asymmetric Tailscale routing is required; correct any separately listed mismatched key.' 'Forcing strict reverse-path filtering can discard valid overlay traffic and remove remote access.' ;;
        HRDN-7222) printf '%s\n' 'A compiler remains executable to non-root or was restored by a package update.' 'Remove unused development packages or rerun --aggressive after dependency review.' 'Removing/restricting toolchains can break DKMS, package builds, and diagnostics.' ;;
        HRDN-7230) printf '%s\n' 'No supported repository malware scanner was available/detected.' 'Install and schedule a maintained scanner from an official repository.' 'Rootkit scanners can produce false positives and consume significant I/O.' ;;
        BANN-7126|BANN-7130) printf '%s\n' 'The local policy banner did not match the Lynis heuristic.' 'Have legal counsel approve organization-specific /etc/issue and /etc/issue.net text.' 'Incorrect legal language can weaken rather than strengthen notice/consent arguments.' ;;
        *) printf '%s\n' 'The final Lynis output still reports this host-specific test.' 'Run lynis show details for the Test ID and review /var/log/lynis.log.' 'Risk depends on the exact host role; no unvalidated generic mutation was applied.' ;;
    esac
}

write_open_findings_report() {
    if [[ "$MODE" != "apply" ]]; then
        log INFO "Dry run: skipping remaining-findings report generation"
        return 0
    fi
    local lynis_report=/root/lynis-after-hardening.txt
    local output=/root/hardening-open-findings.txt
    {
        printf 'Remaining Lynis findings after hardening\n'
        printf 'Generated: %s\n' "$(timestamp)"
        printf 'Hardening index: %s\n\n' "$LYNIS_AFTER"
        if [[ ! -f "$lynis_report" ]]; then
            printf 'Lynis did not run; exact remaining test IDs are unavailable.\n'
        else
            local count=0 line id message reason change risk
            while IFS= read -r line; do
                id="$(sed -nE 's/.*\[([A-Z]+-[0-9]+)\].*/\1/p' <<<"$line")"
                [[ -n "$id" ]] || continue
                message="$(sed -E 's/^[[:space:]]*[*!][[:space:]]*//' <<<"$line")"
                mapfile -t explanation < <(explain_open_test "$id")
                reason="${explanation[0]}"
                change="${explanation[1]}"
                risk="${explanation[2]}"
                count=$((count + 1))
                printf '[%d] Test ID: %s\nFinding: %s\nWhy open: %s\nRequired change: %s\nRisk: %s\n\n' \
                    "$count" "$id" "$message" "$reason" "$change" "$risk"
            done < <(grep -E '^[[:space:]]*[*!] .+\[[A-Z]+-[0-9]+\]' "$lynis_report" || true)
            [[ "$count" -gt 0 ]] || printf 'No remaining warning/suggestion lines with Lynis Test IDs were found.\n'
        fi
        printf '\nDeliberately not score-gamed:\n'
        printf '%s\n' \
            '- Lynis 3.1.6 is older than six months; no third-party repository was added automatically.' \
            '- Disk encryption was not retrofitted in place.' \
            '- /home and /var were not repartitioned automatically.' \
            '- No fake DNS domain, automation agent, or GRUB password was introduced.' \
            '- Lynis tests/profiles were not disabled or edited.' \
            '- kernel.modules_disabled=1 is set only with --aggressive and only as the final irreversible lock-down step.'
        printf '\nExplicitly accepted Lynis findings:\n'
        printf '%s\n' \
            '- BOOT-5122 intentionally accepted: no GRUB password is configured to preserve unattended/reliable reboot capability.' \
            '- SSH-7408: SSH port intentionally preserved; changing the port is not considered a meaningful security control for this deployment.' \
            '- FILE-6310: /home and /var require planned repartitioning or LVM migration, never an in-place generic mutation.' \
            '- DEB-0810: apt-listbugs is Debian-oriented and is not forced onto Ubuntu.' \
            '- AUTH-9230: legacy SHA rounds are not added when YESCRYPT is the effective password hash method.' \
            '- NAME-4028: an organization/domain-dependent DNS identity is not invented.' \
            '- AUTH-9282: no fixed account expiration is imposed without an explicit owner decision.'
        if systemctl is-active --quiet tailscaled.service 2>/dev/null; then
            printf '%s\n' '- KRNL-6000/rp_filter: net.ipv4.conf.all.rp_filter=2 is intentionally retained for active Tailscale asymmetric overlay routing.'
        fi
    } > "$output"
    chmod 0600 "$output"
    record_change "Wrote exact remaining-test report to ${output}"
    return 0
}

print_summary() {
    local failed reboot="NO" mode_label="APPLY" aggressive_label="NO" service_exposure_lines="none measured"
    if [[ "$MODE" == "dry-run" ]]; then
        failed="N/A (dry-run)"
        reboot="N/A (dry-run)"
        mode_label="DRY-RUN"
    else
        failed="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd, - || true)"
        [[ -n "$failed" ]] || failed="none"
        if [[ "$REBOOT_REQUIRED" -eq 1 || -e /var/run/reboot-required ]]; then reboot="YES"; fi
    fi
    [[ "$AGGRESSIVE" -eq 1 ]] && aggressive_label="YES"
    if ((${#SERVICE_EXPOSURE_SUMMARY[@]})); then
        service_exposure_lines="${SERVICE_EXPOSURE_SUMMARY[*]}"
    elif [[ "$MODE" == "dry-run" ]]; then
        service_exposure_lines="planned on apply"
    fi
    emit_block <<EOF
============================================================
 HARDENING RESULT
============================================================
Distribution       : ${OS_PRETTY}
Version            : ${OS_VERSION}
Kernel             : $(uname -r)
Mode               : ${mode_label}
Aggressive         : ${aggressive_label}

SSH                : ${SSH_STATUS}
Firewall           : ${FIREWALL_STATUS}
PAM                : ${PAM_STATUS}
Audit              : ${AUDIT_STATUS}
AppArmor           : ${APPARMOR_STATUS}
AIDE               : ${AIDE_STATUS}
Fail2ban           : ${FAIL2BAN_STATUS}
Remote Logging     : ${REMOTE_LOG_STATUS}
Automatic Updates  : ${UPDATES_STATUS}

Lynis Score Before : ${LYNIS_BEFORE}
Lynis Score After  : ${LYNIS_AFTER}
Warnings           : ${LYNIS_WARNINGS}
Suggestions        : ${LYNIS_SUGGESTIONS}
Lynis Parse Status : ${LYNIS_PARSE_STATUS}

Packages installed : ${PACKAGES_INSTALLED[*]:-none}
Packages removed   : ${PACKAGES_REMOVED[*]:-none}
Services disabled  : ${SERVICES_DISABLED[*]:-none}
Services masked    : ${SERVICES_MASKED[*]:-none}
Services hardened  : ${SERVICES_HARDENED[*]:-none}
Service exposure   :
${service_exposure_lines}
Exposure report    : $([[ "$MODE" == "apply" ]] && printf '%s' "$SYSTEMD_HARDENING_REPORT" || printf 'planned')
Failed services    : ${failed}
Rollbacks          : ${ROLLBACKS[*]:-none}
Reboot required    : ${reboot}
Backup directory   : ${BACKUP_DIR:-not created in dry-run}
Log file           : $([[ "$MODE" == "apply" ]] && printf '%s' "$LOG_FILE" || printf 'not written in dry-run')
Validation         : $([[ "$MODE" == "apply" ]] && printf '/root/hardening-validation.txt' || printf 'planned')
Remaining findings : $([[ "$MODE" == "apply" ]] && printf '/root/hardening-open-findings.txt' || printf 'planned')
Exit Status        : SUCCESS
============================================================
EOF
    if [[ "$reboot" == "YES" ]]; then log WARN "REBOOT REQUIRED"; fi
    SUMMARY_PRINTED=1
    return 0
}

main() {
    CURRENT_PHASE=0
    COMPLETED=0
    VALIDATION_COMPLETED=0
    FINAL_LYNIS_COMPLETED=0
    SUMMARY_PRINTED=0
    NETWORK_HARDENING_COMPLETED=0
    FIREWALL_COMPLETED=0
    APPARMOR_COMPLETED=0
    parse_args "$@"
    check_root
    # Complete all terminal input before file logging starts.
    ask_remote_logging
    init_logging
    if [[ "$REMOTE_LOG_ENABLED" -eq 1 ]]; then
        log INFO "Remote logging selected: ${REMOTE_LOG_PROTOCOL}://${REMOTE_LOG_SERVER}:${REMOTE_LOG_PORT}"
    elif [[ "$REMOTE_LOG_DECLINED" -eq 1 ]]; then
        log INFO "Remote logging was consciously left disabled"
    fi

    show_mode_banner
    phase 01 18 "Preflight"
    log INFO "Server hardening ${SCRIPT_VERSION} started"
    [[ "$MODE" == "dry-run" ]] && log INFO "Dry run: no backup, log file, or system state will be changed"
    detect_os
    capture_lynis_baseline

    phase 02 18 "Backup"
    backup_config

    phase 03 18 "Package Security"
    log WARN "Phase 03 installs and configures security packages and may legitimately take several minutes on a fresh server; package operations are not subject to artificial timeouts"
    prepare_packages
    configure_apt
    configure_updates
    configure_debsums
    purge_removed_packages
    detect_ssh_context

    phase 04 18 "Logging"
    configure_banners
    configure_logging

    phase 05 18 "Kernel Hardening"
    configure_sysctl
    NETWORK_HARDENING_COMPLETED=1
    configure_core_dumps
    configure_kernel_modules

    phase 06 18 "Authentication"
    configure_pam
    configure_account_aging
    configure_sudo

    phase 07 18 "Firewall"
    configure_firewall
    if [[ "$MODE" != "apply" || "$FIREWALL_STATUS" == OK* ]]; then FIREWALL_COMPLETED=1; fi

    phase 08 18 "SSH"
    harden_ssh
    configure_fail2ban

    phase 09 18 "Audit"
    configure_cron_at
    configure_auditd
    configure_process_accounting

    phase 10 18 "Filesystems"
    harden_filesystems
    harden_accounts_and_files

    phase 11 18 "Services"
    configure_time_sync
    disable_unneeded_services
    configure_bootloader
    restrict_compilers
    configure_malware_scanner
    harden_systemd_services
    verify_disabled_services

    phase 12 18 "AppArmor"
    configure_apparmor
    if [[ "$MODE" != "apply" || "$APPARMOR_STATUS" != FAILED* ]]; then APPARMOR_COMPLETED=1; fi
    prepare_kernel_module_lock

    phase 13 18 "Validation"
    remediate_deleted_open_files
    diagnose_iowait_processes "validation-baseline"
    run_validation

    phase 14 18 "Lynis Pass 1"
    run_lynis /root/lynis-after-hardening-pass1.txt "first post-hardening pass"

    phase 15 18 "Optimization Pass"
    second_optimization_pass

    phase 16 18 "AIDE"
    configure_aide
    if [[ "$MODE" == "apply" && "$AIDE_STATUS" != "OK" ]]; then
        die "AIDE phase did not produce a validated SHA-2 configuration, active database, and timer"
    fi

    phase 17 18 "Final Lockdown and Lynis"
    diagnose_iowait_processes "pre-final-lynis"
    lock_kernel_modules_late
    run_lynis /root/lynis-after-hardening.txt "final pass"
    FINAL_LYNIS_COMPLETED=1
    if grep -q '\[PROC-3614\]' /root/lynis-after-hardening.txt 2>/dev/null; then
        log WARN "Final Lynis reported PROC-3614; waiting briefly for a second non-destructive D-state snapshot"
        sleep 2
        diagnose_iowait_processes "post-finding-recheck"
    fi
    verify_fail2ban_runtime 3 || true
    extract_lynis_summary
    write_open_findings_report

    phase 18 18 "Summary"
    print_summary

    if [[ "$CURRENT_PHASE" -ne 18 || "$VALIDATION_COMPLETED" -ne 1 \
        || "$FINAL_LYNIS_COMPLETED" -ne 1 || "$SUMMARY_PRINTED" -ne 1 ]]; then
        die "Internal completion-gate failure: phase=${CURRENT_PHASE}, validation=${VALIDATION_COMPLETED}, final-lynis=${FINAL_LYNIS_COMPLETED}, summary=${SUMMARY_PRINTED}"
    fi
    log OK "Phase 18/18 reached; validation, final Lynis audit, and summary completed"
    COMPLETED=1

    if [[ "$MODE" == "apply" && "$AUTO_REBOOT" -eq 1 \
        && ( "$REBOOT_REQUIRED" -eq 1 || -e /var/run/reboot-required ) ]]; then
        log WARN "Reboot requested; rebooting now"
        systemctl reboot
    fi
    return 0
}

if [[ "${HARDEN_SOURCE_ONLY:-0}" != "1" ]]; then
    main "$@"
fi
