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
        grep -Fq 'sha256+sha512' "$policy"
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
        ' _ "$repo_root" "$backup_dir" "$state_dir" "$count_file" \
        "$service_run_file" \
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

run_logging_tests
run_aide_tests
run_kernel_gate_test
printf 'Runtime regression tests passed.\n'
