#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

run_logging_tests() {
    local log_file="$test_root/logging/server-hardening.log"
    local terminal_output="$test_root/logging/terminal.txt"
    local no_color_output="$test_root/logging/no-color.txt"
    local cli_no_color_output="$test_root/logging/cli-no-color.txt"
    local mock_bin="$test_root/logging/bin"
    install -d "$test_root/logging/backups" "$mock_bin"
    cat > "$mock_bin/pvs" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
for fd in 3 4; do
    if [[ -e "/proc/$$/fd/$fd" ]] \
        && [[ "$(readlink "/proc/$$/fd/$fd")" == *server-hardening.log* ]]; then
        printf 'File descriptor %s leaked on pvs invocation\n' "$fd" >&2
        exit 1
    fi
done
printf 'mock-pvs-ok\n'
EOF
    chmod +x "$mock_bin/pvs"

    timeout 10 env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 NO_COLOR=1 HARDEN_LOG_FILE="$log_file" \
        HARDEN_BACKUP_ROOT="$test_root/logging/backups" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            init_logging
            run_streamed bash -c "for n in \$(seq 1 200); do printf \"package-progress-%s\\n\" \"\$n\"; done"
            run_streamed pvs
        ' _ "$repo_root" || fail "synchronous logger hung or leaked its log descriptor"
    grep -Fq 'package-progress-200' "$log_file" || fail "streamed package output was not logged"
    grep -Fq 'mock-pvs-ok' "$log_file" || fail "mock LVM output was not logged"
    if grep -Fq 'File descriptor' "$log_file"; then
        fail "mock LVM invocation inherited a logging descriptor"
    fi
    grep -Eq 'exec[[:space:]]+[34]|LOG_CAPTURE_ACTIVE|exec[[:space:]]*>[[:space:]]*>\(' "$repo_root/harden.sh" \
        && fail "legacy asynchronous logging or persistent FD 3/4 remains"

    env HARDEN_SOURCE_ONLY=1 HARDEN_LOG_FILE="$log_file" \
        HARDEN_BACKUP_ROOT="$test_root/logging/backups" \
        script -qec "source '$repo_root/harden.sh'; trap - ERR EXIT; [[ \"\$USE_COLOR\" -eq 1 ]]; MODE=apply; init_logging; log OK color-render-test" /dev/null \
        > "$terminal_output"
    grep -q $'\033\[' "$terminal_output" || fail "interactive apply output did not contain ANSI color"
    if grep -q $'\033\[' "$log_file"; then
        fail "persistent log contains ANSI escapes"
    fi

    env HARDEN_SOURCE_ONLY=1 NO_COLOR=1 HARDEN_LOG_FILE="$test_root/logging/no-color.log" \
        HARDEN_BACKUP_ROOT="$test_root/logging/backups" \
        script -qec "source '$repo_root/harden.sh'; trap - ERR EXIT; MODE=apply; init_logging; log OK no-color-test" /dev/null \
        > "$no_color_output"
    if grep -q $'\033\[' "$no_color_output"; then
        fail "NO_COLOR did not suppress interactive ANSI color"
    fi

    env HARDEN_SOURCE_ONLY=1 HARDEN_LOG_FILE="$test_root/logging/cli-no-color.log" \
        HARDEN_BACKUP_ROOT="$test_root/logging/backups" \
        script -qec "source '$repo_root/harden.sh'; trap - ERR EXIT; [[ \"\$USE_COLOR\" -eq 1 ]]; parse_args --apply --no-color; [[ \"\$USE_COLOR\" -eq 0 ]]; init_logging; log OK cli-no-color-test" /dev/null \
        > "$cli_no_color_output"
    if grep -q $'\033\[' "$cli_no_color_output" \
        || grep -q $'\033\[' "$test_root/logging/cli-no-color.log"; then
        fail "--no-color did not suppress ANSI color"
    fi
}

write_aide_mocks() {
    local mock_bin="$1"
    install -d "$mock_bin"
    cat > "$mock_bin/aide" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
config=""
for argument in "$@"; do
    case "$argument" in --config=*) config="${argument#*=}" ;; esac
done
case " $* " in
    *' --version '*) printf 'AIDE available hashes: sha256 sha512\n' ;;
    *' --config-check '*)
        [[ -s "$config" ]]
        policy="$(awk '/^@@(x_)?include[[:space:]]+/ {print $2; exit}' "$config")/99_harden_sha2"
        [[ -s "$policy" ]]
        grep -Fq 'HardenSHA2 = p+ftype+i+l+n+u+g+s+b+m+c+sha256+sha512' "$config"
        grep -Fq '=/etc/passwd HardenSHA2' "$policy"
        group_line="$(awk '/^HardenSHA2[[:space:]]*=/ {print NR; exit}' "$config")"
        include_line="$(awk '/^@@(x_)?include[[:space:]]+/ {print NR; exit}' "$config")"
        [[ -n "$group_line" && -n "$include_line" && "$group_line" -lt "$include_line" ]]
        ;;
    *' --init '*)
        database_out="$(awk -F= '$1 ~ /^[[:space:]]*database_out[[:space:]]*$/ {value=$2; gsub(/^[[:space:]]*file:|[[:space:]]*$/, "", value); print value; exit}' "$config")"
        printf 'mock-aide-database\n' > "$database_out"
        count=0
        [[ ! -f "$AIDE_TEST_COUNT_FILE" ]] || count="$(< "$AIDE_TEST_COUNT_FILE")"
        printf '%s\n' "$((count + 1))" > "$AIDE_TEST_COUNT_FILE"
        ;;
    *' --check '*)
        database_in="$(awk -F= '$1 ~ /^[[:space:]]*database_in[[:space:]]*$/ {value=$2; gsub(/^[[:space:]]*file:|[[:space:]]*$/, "", value); print value; exit}' "$config")"
        [[ -s "$database_in" ]]
        ;;
    *) exit 1 ;;
esac
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
property_value() {
    case "$1" in
        Id) printf 'dailyaidecheck.service' ;;
        LoadState) printf 'loaded' ;;
        User|Group) printf '_aide' ;;
        AmbientCapabilities|CapabilityBoundingSet) printf 'CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE' ;;
        ExecStart) printf '{ path=/usr/share/aide/bin/dailyaidecheck ; argv[]=/usr/share/aide/bin/dailyaidecheck --systemdservice ; }' ;;
        Result) [[ "${AIDE_TEST_SERVICE_FAIL:-0}" -eq 1 ]] && printf 'exit-code' || printf 'success' ;;
        ExecMainStatus) [[ "${AIDE_TEST_SERVICE_FAIL:-0}" -eq 1 ]] && printf '1' || printf '0' ;;
    esac
}

command_name="${1:-}"
shift || true
case "$command_name" in
    list-unit-files)
        printf 'dailyaidecheck.timer enabled\n'
        ;;
    show)
        service="${1:-}"
        shift || true
        value_only=0
        properties=()
        while (($#)); do
            case "$1" in
                -p|--property) properties+=("$2"); shift 2 ;;
                --value) value_only=1; shift ;;
                *) shift ;;
            esac
        done
        if [[ "$value_only" -eq 1 ]]; then
            property_value "${properties[0]}"
            printf '\n'
        else
            for property in "${properties[@]}"; do
                printf '%s=' "$property"
                property_value "$property"
                printf '\n'
            done
        fi
        [[ -n "$service" ]]
        ;;
    start)
        printf 'start %s\n' "${1:-}" >> "$AIDE_TEST_SYSTEMCTL_LOG"
        [[ "${AIDE_TEST_SERVICE_FAIL:-0}" -ne 1 ]]
        aide --config="$AIDE_TEST_CONFIG" --check
        printf 'vendor-service-context-ok\n' >> "$AIDE_TEST_SERVICE_RUN_FILE"
        ;;
    is-failed)
        exit 1
        ;;
    enable|disable|stop|reset-failed|daemon-reload|is-enabled|is-active)
        printf '%s %s\n' "$command_name" "$*" >> "$AIDE_TEST_SYSTEMCTL_LOG"
        ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$mock_bin/aide" "$mock_bin/systemctl"
}

run_aide_tests() {
    local case_root="$test_root/aide"
    local mock_bin="$case_root/bin"
    local config="$case_root/etc/aide/aide.conf"
    local state_dir="$case_root/var/lib/aide"
    local backup_dir="$case_root/backup"
    local count_file="$case_root/init-count"
    local service_run_file="$case_root/service-runs"
    local systemctl_log="$case_root/systemctl.log"
    local test_owner test_group
    test_owner="$(id -un)"
    test_group="$(id -gn)"
    install -d "$case_root/etc/aide/aide.conf.d" "$state_dir" "$backup_dir"
    write_aide_mocks "$mock_bin"
    cat > "$config" <<EOF
database_in=file:${state_dir}/aide.db
database_out=file:${state_dir}/aide.db.new
@@x_include ${case_root}/etc/aide/aide.conf.d ^[a-zA-Z0-9_-]+$
EOF

    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_AIDE_ETC_DIR="$case_root/etc/aide" \
        HARDEN_AIDE_STATE_DIR="$state_dir" HARDEN_SYSTEMD_DIR="$case_root/systemd" \
        HARDEN_TEST_OWNER="$test_owner" HARDEN_TEST_GROUP="$test_group" \
        AIDE_TEST_COUNT_FILE="$count_file" AIDE_TEST_CONFIG="$config" \
        AIDE_TEST_SERVICE_RUN_FILE="$service_run_file" AIDE_TEST_SYSTEMCTL_LOG="$systemctl_log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            BACKUP_DIR="$2"
            CHANGE_LOG="$2/changes.tsv"
            : > "$CHANGE_LOG"
            configure_aide
            [[ "$AIDE_STATUS" == OK ]]
            [[ -s "$3/aide.db" ]]
            [[ "$(< "$4")" == 1 ]]
            configure_aide
            [[ "$AIDE_STATUS" == OK ]]
            [[ "$(< "$4")" == 1 ]]
            [[ "$(wc -l < "$5")" == 2 ]]
            grep -Fq "User=_aide" "$2/aide-service-context.txt"
            grep -Fq "CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE" "$2/aide-service-context.txt"
            grep -Fq "Result=success" "$2/aide-service-context.txt"
            grep -Fq "HardenSHA2 = p+ftype+i+l+n+u+g+s+b+m+c+sha256+sha512" "$6"
            grep -Eq "= .*(sha256|sha512)" "$2/aide-lynis-FINT-4402-evidence.txt"
        ' _ "$repo_root" "$backup_dir" "$state_dir" "$count_file" \
        "$service_run_file" "$config" \
        || fail "Ubuntu-layout AIDE missing-database or idempotent second-run test failed"

    rm -f -- "$count_file"
    printf 'trusted-existing-database\n' > "$state_dir/aide.db"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_AIDE_ETC_DIR="$case_root/etc/aide" \
        HARDEN_AIDE_STATE_DIR="$state_dir" HARDEN_SYSTEMD_DIR="$case_root/systemd" \
        HARDEN_TEST_OWNER="$test_owner" HARDEN_TEST_GROUP="$test_group" \
        AIDE_TEST_COUNT_FILE="$count_file" AIDE_TEST_CONFIG="$config" \
        AIDE_TEST_SERVICE_RUN_FILE="$service_run_file" AIDE_TEST_SYSTEMCTL_LOG="$systemctl_log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            BACKUP_DIR="$2"
            CHANGE_LOG="$2/changes-existing.tsv"
            : > "$CHANGE_LOG"
            configure_aide
            [[ "$AIDE_STATUS" == OK ]]
            [[ ! -e "$3" ]]
        ' _ "$repo_root" "$backup_dir" "$count_file" \
        || fail "existing AIDE database was rebuilt despite unchanged policy"

    : > "$systemctl_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_AIDE_ETC_DIR="$case_root/etc/aide" \
        HARDEN_AIDE_STATE_DIR="$state_dir" HARDEN_SYSTEMD_DIR="$case_root/systemd" \
        HARDEN_TEST_OWNER="$test_owner" HARDEN_TEST_GROUP="$test_group" \
        AIDE_TEST_COUNT_FILE="$count_file" AIDE_TEST_CONFIG="$config" \
        AIDE_TEST_SERVICE_RUN_FILE="$service_run_file" AIDE_TEST_SYSTEMCTL_LOG="$systemctl_log" \
        AIDE_TEST_SERVICE_FAIL=1 bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            BACKUP_DIR="$2"
            CHANGE_LOG="$2/changes-service-failure.tsv"
            : > "$CHANGE_LOG"
            configure_aide
            [[ "$AIDE_STATUS" == FAILED ]]
        ' _ "$repo_root" "$backup_dir" || fail "AIDE service-context failure was not fatal to phase status"
    if grep -Fxq 'enable --now dailyaidecheck.timer' "$systemctl_log"; then
        fail "AIDE timer was enabled after service-context validation failed"
    fi

    if command -v update-aide.conf >/dev/null 2>&1; then
        printf 'INFO: host update-aide.conf exists; mock PATH still exercised the independent runtime path.\n'
    fi
    if sed -n '/^configure_aide()/,/^}/p' "$repo_root/harden.sh" | grep -q 'update-aide[.]conf'; then
        fail "configure_aide still depends on update-aide.conf"
    fi
}

run_kernel_gate_test() {
    local case_root="$test_root/kernel"
    local mock_bin="$case_root/bin"
    local control="$case_root/modules_disabled"
    local unit="$case_root/kernel-module-lockdown.service"
    local writes="$case_root/writes"
    install -d "$mock_bin"
    printf '0\n' > "$control"
    printf '[Service]\n' > "$unit"
    cat > "$mock_bin/sysctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == -n ]]; then
    tr -d '\n' < "$HARDEN_MODULES_DISABLED_PATH"
elif [[ "${1:-}" == -w && "${2:-}" == kernel.modules_disabled=1 ]]; then
    printf '1\n' > "$HARDEN_MODULES_DISABLED_PATH"
    printf 'write\n' >> "$KERNEL_WRITE_COUNT"
    printf 'kernel.modules_disabled = 1\n'
else
    exit 1
fi
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$mock_bin/sysctl" "$mock_bin/systemctl"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_MODULE_LOCK_UNIT="$unit" KERNEL_WRITE_COUNT="$writes" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            CHANGE_LOG="$4"
            : > "$CHANGE_LOG"
            CURRENT_PHASE=16
            if lock_kernel_modules_late; then exit 1; fi
            [[ "$(< "$2")" == 0 ]]
            CURRENT_PHASE=17
            NETWORK_HARDENING_COMPLETED=1
            FIREWALL_COMPLETED=1
            APPARMOR_COMPLETED=1
            VALIDATION_COMPLETED=1
            AIDE_STATUS=OK
            lock_kernel_modules_late
            [[ "$(< "$2")" == 1 ]]
            lock_kernel_modules_late
            [[ "$(wc -l < "$3")" == 1 ]]
        ' _ "$repo_root" "$control" "$writes" "$case_root/changes.tsv" || fail "final kernel.modules_disabled gate or idempotent path failed"
}

run_lynis_summary_tests() {
    local case_root="$test_root/lynis-summary"
    local report="$case_root/final.txt" data="$case_root/final-report.dat" diagnostic="$case_root/diagnostic.txt"
    install -d "$case_root"
    cat > "$report" <<'EOF'
  Lynis security scan details:
  Hardening index : 86 [#################   ]
  Great, no warnings
  Suggestions (16):
EOF
    cat > "$data" <<'EOF'
hardening_index=86
suggestion[]=PROC-3614|Check process listing for processes waiting for IO requests|||
EOF
    env HARDEN_SOURCE_ONLY=1 HARDEN_LYNIS_FINAL_REPORT="$report" HARDEN_LYNIS_FINAL_DATA="$data" \
        HARDEN_LYNIS_PARSE_DIAGNOSTIC="$diagnostic" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            extract_lynis_summary
            [[ "$LYNIS_AFTER" == 86 && "$LYNIS_WARNINGS" == 0 && "$LYNIS_SUGGESTIONS" == 16 ]]
            [[ "$LYNIS_PARSE_STATUS" == OK ]]
        ' _ "$repo_root" || fail "Lynis 3.1.6 console-summary parsing failed"

    cat > "$report" <<'EOF'
  Summary line intentionally unavailable in console capture
EOF
    cat > "$data" <<'EOF'
hardening_index=87
suggestion[]=FINT-4402|Use SHA256 or SHA512|||
suggestion[]=PROC-3614|Check process listing|||
EOF
    env HARDEN_SOURCE_ONLY=1 HARDEN_LYNIS_FINAL_REPORT="$report" HARDEN_LYNIS_FINAL_DATA="$data" \
        HARDEN_LYNIS_PARSE_DIAGNOSTIC="$diagnostic" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            extract_lynis_summary
            [[ "$LYNIS_AFTER" == 87 && "$LYNIS_WARNINGS" == 0 && "$LYNIS_SUGGESTIONS" == 2 ]]
            [[ "$LYNIS_PARSE_STATUS" == OK ]]
        ' _ "$repo_root" || fail "Lynis report.dat summary fallback failed"
}

run_fail2ban_tests() {
    local case_root="$test_root/fail2ban" mock_bin="$test_root/fail2ban/bin"
    local count="$case_root/count"
    install -d "$mock_bin" "$case_root/backup"
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == is-active && "${2:-}" == --quiet && "${3:-}" == fail2ban.service ]]
EOF
    cat > "$mock_bin/fail2ban-client" <<'EOF'
#!/usr/bin/env bash
count=0
[[ ! -f "$FAIL2BAN_TEST_COUNT" ]] || count="$(< "$FAIL2BAN_TEST_COUNT")"
count=$((count + 1))
printf '%s\n' "$count" > "$FAIL2BAN_TEST_COUNT"
if ((count < 3)); then
    printf 'ERROR Unable to contact server\n' >&2
    exit 1
fi
case "${1:-}" in
    ping) printf 'Server replied: pong\n' ;;
    status) printf 'Status for the jail: sshd\n|- Currently failed: 0\n' ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$mock_bin/systemctl" "$mock_bin/fail2ban-client"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 FAIL2BAN_TEST_COUNT="$count" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            BACKUP_DIR="$2"
            verify_fail2ban_runtime 4
            [[ "$FAIL2BAN_STATUS" == OK ]]
            grep -Fq "Server replied: pong" "$2/fail2ban-runtime.txt"
            grep -Fq "Status for the jail: sshd" "$2/fail2ban-runtime.txt"
        ' _ "$repo_root" "$case_root/backup" || fail "Fail2ban readiness/runtime verification failed"
}

run_packagekit_tests() {
    local case_root="$test_root/packagekit" mock_bin="$test_root/packagekit/bin"
    local apt_log="$test_root/packagekit/apt.log"
    install -d "$mock_bin"
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *' -s purge '* ]]; then
    printf 'Remv packagekit [1.2.8]\nRemv packagekit-tools [1.2.8]\n'
elif [[ "${1:-}" == check ]]; then
    printf 'apt-check-ok\n'
elif [[ " $* " == *' purge -y '* ]]; then
    printf 'purge %s\n' "$*" >> "$PACKAGEKIT_APT_LOG"
else
    exit 1
fi
EOF
    cat > "$mock_bin/unattended-upgrade" <<'EOF'
#!/usr/bin/env bash
printf 'unattended-ok\n'
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$PACKAGEKIT_SYSTEMCTL_LOG"
EOF
    chmod +x "$mock_bin/apt-get" "$mock_bin/unattended-upgrade" "$mock_bin/systemctl"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGEKIT_APT_LOG="$apt_log" \
        PACKAGEKIT_SYSTEMCTL_LOG="$case_root/systemctl.log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            OS_ID=ubuntu
            CHANGE_LOG="$2/changes.tsv"
            : > "$CHANGE_LOG"
            package_installed() { [[ "$1" == packagekit || "$1" == packagekit-tools ]]; }
            configure_headless_packagekit
            grep -Fq "purge" "$2/apt.log"
            grep -Fq "packagekit" "$2/apt.log"
            grep -Fq "packagekit-tools" "$2/apt.log"
            ! grep -Eq "^mask([[:space:]]|$)" "$2/systemctl.log"
        ' _ "$repo_root" "$case_root" || fail "safe headless PackageKit removal regression failed"

    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGEKIT_APT_LOG="$apt_log" \
        PACKAGEKIT_SYSTEMCTL_LOG="$case_root/systemctl-debian.log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            OS_ID=debian
            CHANGE_LOG="$2/debian.tsv"
            : > "$CHANGE_LOG"
            package_installed() { [[ "$1" == packagekit || "$1" == packagekit-tools ]]; }
            configure_headless_packagekit
            grep -Fq "purge" "$2/apt.log"
            grep -Fq "headless PackageKit" "$CHANGE_LOG"
            grep -Fq "(debian)" "$CHANGE_LOG"
        ' _ "$repo_root" "$case_root" || fail "Debian headless PackageKit policy regression failed"

    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGEKIT_APT_LOG="$apt_log" \
        PACKAGEKIT_SYSTEMCTL_LOG="$case_root/systemctl-unsafe.log" PACKAGEKIT_UNSAFE=1 bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            OS_ID=ubuntu
            CHANGE_LOG="$2/unsafe.tsv"
            : > "$CHANGE_LOG"
            package_installed() { [[ "$1" == packagekit || "$1" == packagekit-tools ]]; }
            apt-get() {
                if [[ "${1:-}" == -s && "${2:-}" == purge ]]; then
                    printf "Remv packagekit [1.2.8]\nRemv ubuntu-server [1.0]\n"
                elif [[ "${1:-}" == check ]]; then
                    return 0
                else
                    printf "unexpected-purge\n" >> "$PACKAGEKIT_APT_LOG"
                    return 1
                fi
            }
            export -f apt-get
            configure_headless_packagekit
            [[ ! -s "$2/apt.log" ]]
            grep -Fq "APT simulation would also remove ubuntu-server" "$CHANGE_LOG" || \
                printf "%s\n" "${SKIPPED_FINDINGS[*]}" | grep -Fq "ubuntu-server"
        ' _ "$repo_root" "$case_root" || fail "unsafe PackageKit dependency simulation was not blocked"
}

run_compiler_tests() {
    local case_root="$test_root/compiler" mock_bin="$test_root/compiler/bin" apt_log="$test_root/compiler/apt.log"
    install -d "$mock_bin" "$case_root/backup" "$case_root/empty-usr/bin" "$case_root/empty-local/bin"
    for binary in as gcc; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "$mock_bin/$binary"
        chmod 0755 "$mock_bin/$binary"
    done
    cat > "$mock_bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -S ]]; then
    target="${*: -1}"
    case "$target" in
        */as) printf 'binutils: %s\n' "$target" ;;
        *) printf 'gcc: %s\n' "$target" ;;
    esac
elif [[ "${COMPILER_PROTECTED:-0}" -eq 1 ]]; then
    printf 'dkms\nlinux-headers-generic\n'
else
    exit 1
fi
EOF
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *' -s purge '* ]]; then
    if [[ "${COMPILER_UNSAFE:-0}" -eq 1 ]]; then
        printf 'Remv gcc [14]\nRemv ubuntu-server [1.0]\n'
    else
        printf 'Remv gcc [14]\nRemv binutils [2.43]\n'
    fi
elif [[ " $* " == *' purge -y '* ]]; then
    printf '%s\n' "$*" >> "$COMPILER_APT_LOG"
    rm -f "$COMPILER_BIN_DIR/as" "$COMPILER_BIN_DIR/gcc"
elif [[ "${1:-}" == check ]]; then
    printf 'apt-check-ok\n'
else
    exit 1
fi
EOF
    chmod +x "$mock_bin/dpkg-query" "$mock_bin/apt-get"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 COMPILER_APT_LOG="$apt_log" \
        COMPILER_BIN_DIR="$mock_bin" HARDEN_TEST_OWNER="$(id -u)" HARDEN_TEST_GROUP="$(id -g)" \
        HARDEN_COMPILER_USR_ROOT="$case_root/empty-usr" HARDEN_COMPILER_LOCAL_ROOT="$case_root/empty-local" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/changes.tsv"
            : > "$CHANGE_LOG"
            compiler_command_path() { if [[ -x "$COMPILER_BIN_DIR/$1" ]]; then printf "%s/%s\n" "$COMPILER_BIN_DIR" "$1"; fi; return 0; }
            restrict_compilers
            grep -Fq "purge -y" "$2/apt.log"
            [[ ! -e "$3/as" && ! -e "$3/gcc" ]]
            grep -Fq "lynis-binary=" "$2/backup/compiler-toolchain-inventory.txt"
        ' _ "$repo_root" "$case_root" "$mock_bin" || fail "safe compiler owner-package purge regression failed"

    for binary in as gcc; do
        printf '#!/usr/bin/env bash\nexit 0\n' > "$mock_bin/$binary"
        chmod 0755 "$mock_bin/$binary"
    done
    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 COMPILER_APT_LOG="$apt_log" \
        COMPILER_BIN_DIR="$mock_bin" COMPILER_PROTECTED=1 HARDEN_TEST_OWNER="$(id -u)" \
        HARDEN_TEST_GROUP="$(id -g)" HARDEN_COMPILER_USR_ROOT="$case_root/empty-usr" \
        HARDEN_COMPILER_LOCAL_ROOT="$case_root/empty-local" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/protected.tsv"
            : > "$CHANGE_LOG"
            compiler_command_path() { if [[ -x "$COMPILER_BIN_DIR/$1" ]]; then printf "%s/%s\n" "$COMPILER_BIN_DIR" "$1"; fi; return 0; }
            restrict_compilers
            [[ ! -s "$2/apt.log" ]]
            [[ "$(stat -c "%a" "$3/as")" == 750 ]]
            [[ "$(stat -c "%a" "$3/gcc")" == 750 ]]
            printf "%s\n" "${SKIPPED_FINDINGS[*]}" | grep -Fq "DKMS or installed kernel headers"
        ' _ "$repo_root" "$case_root" "$mock_bin" || fail "protected compiler dependency/root-only fallback regression failed"
}

run_binfmt_tests() {
    local case_root="$test_root/binfmt" root="$test_root/binfmt/proc" config="$test_root/binfmt/config"
    install -d "$root" "$config" "$case_root/backup"
    printf 'enabled\n' > "$root/status"
    env HARDEN_SOURCE_ONLY=1 HARDEN_BINFMT_ROOT="$root" HARDEN_BINFMT_CONFIG_DIRS="$config" \
        HARDEN_BINFMT_MODPROBE_FILE="$case_root/modprobe.conf" BINFMT_DISABLE_LOG="$case_root/disable.log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/changes.tsv"
            : > "$CHANGE_LOG"
            package_installed() { return 1; }
            dpkg-query() { return 1; }
            unit_file_exists() { return 0; }
            disable_service() { printf "%s %s\n" "$1" "$2" > "$BINFMT_DISABLE_LOG"; }
            install_managed_file() { local target="$1"; shift; cp /dev/stdin "$target"; }
            configure_binfmt_misc
            [[ "$(tr -d "[:space:]" < "$3/status")" == 0 ]]
            grep -Fq "blacklist binfmt_misc" "$2/modprobe.conf"
            grep -Fq "registrations=none" "$2/backup/binfmt-misc-inventory.txt"
        ' _ "$repo_root" "$case_root" "$root" || fail "unused binfmt_misc disable regression failed"

    printf 'enabled\n' > "$root/status"
    printf 'enabled\ninterpreter /usr/bin/qemu-aarch64-static\n' > "$root/qemu-aarch64"
    env HARDEN_SOURCE_ONLY=1 HARDEN_BINFMT_ROOT="$root" HARDEN_BINFMT_CONFIG_DIRS="$config" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/preserve.tsv"
            : > "$CHANGE_LOG"
            package_installed() { return 1; }
            dpkg-query() { return 1; }
            disable_service() { exit 70; }
            install_managed_file() { exit 71; }
            configure_binfmt_misc
            [[ "$(tr -d "[:space:]" < "$3/status")" == enabled ]]
            grep -Fq "qemu-aarch64" "$2/backup/binfmt-misc-inventory.txt"
        ' _ "$repo_root" "$case_root" "$root" || fail "active binfmt registration was not preserved"
}

run_iowait_tests() {
    local case_root="$test_root/iowait" mock_bin="$test_root/iowait/bin" count="$test_root/iowait/count"
    install -d "$mock_bin"
    cat > "$mock_bin/ps" <<'EOF'
#!/usr/bin/env bash
count=0
[[ ! -f "$IOWAIT_TEST_COUNT" ]] || count="$(< "$IOWAIT_TEST_COUNT")"
count=$((count + 1))
printf '%s\n' "$count" > "$IOWAIT_TEST_COUNT"
if ((count <= 2)); then
    printf '4242 D io_schedule aide aide --check\n'
else
    printf '4242 S - aide aide --check\n'
fi
EOF
    chmod +x "$mock_bin/ps"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 IOWAIT_TEST_COUNT="$count" \
        HARDEN_IOWAIT_REPORT="$case_root/report.txt" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            CHANGE_LOG="$2/changes.tsv"
            : > "$CHANGE_LOG"
            systemd_unit_for_pid() { printf "dailyaidecheck.service\n"; }
            diagnose_iowait_processes baseline
            diagnose_iowait_processes pre-final
            diagnose_iowait_processes recheck
            grep -Fq "4242" "$2/report.txt"
            grep -Fq "dailyaidecheck.service" "$2/report.txt"
            grep -Fq "persistent-across-snapshots" "$2/report.txt"
            grep -Fq "transient IO wait" "$2/report.txt"
            ! grep -Eq "(^|[[:space:]])kill([[:space:]]|$)" "$1/harden.sh"
        ' _ "$repo_root" "$case_root" || fail "PROC-3614 classification/diagnostic regression failed"
}

case "${HARDEN_REGRESSION_FILTER:-all}" in
    compiler)
        run_compiler_tests
        ;;
    new-findings)
        run_lynis_summary_tests
        run_fail2ban_tests
        run_packagekit_tests
        run_compiler_tests
        run_binfmt_tests
        run_iowait_tests
        ;;
    all)
        run_logging_tests
        run_aide_tests
        run_kernel_gate_test
        run_lynis_summary_tests
        run_fail2ban_tests
        run_packagekit_tests
        run_compiler_tests
        run_binfmt_tests
        run_iowait_tests
        ;;
    *) fail "unknown HARDEN_REGRESSION_FILTER value" ;;
esac
printf 'Runtime regression tests passed.\n'
