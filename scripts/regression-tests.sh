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
            grep -Fq "baseline rebuilt: 0" "$CHANGE_LOG"
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
    local case_root="$test_root/kernel" mock_bin="$test_root/kernel/bin"
    local control="$case_root/modules_disabled" unit="$case_root/kernel-module-lockdown.service"
    local helper="$case_root/kernel-module-lockdown" writes="$case_root/writes"
    local module_log="$case_root/modprobe.log" command_log="$case_root/commands.log"
    local kernel_config="$case_root/kernel.config" sys_modules="$case_root/sys-module"
    local report="$case_root/kernel-module-lockdown-report.txt"
    install -d "$mock_bin" "$sys_modules" "$case_root/backup"
    printf '0\n' > "$control"
    printf '[Service]\n' > "$unit"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$helper"
    chmod 0755 "$helper"
    cat > "$kernel_config" <<'EOF'
CONFIG_NF_TABLES=y
CONFIG_NF_CONNTRACK=m
CONFIG_NF_NAT=m
CONFIG_NFT_NAT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_COMPAT=m
CONFIG_NETFILTER_XTABLES=m
CONFIG_NETFILTER_XT_MARK=m
CONFIG_NETFILTER_XT_NAT=m
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=m
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_NAT=m
CONFIG_IP6_NF_IPTABLES=y
# CONFIG_IP6_NF_NAT is not set
EOF
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
set -Eeuo pipefail
printf 'systemctl %s\n' "$*" >> "$KERNEL_COMMAND_LOG"
case "${1:-}" in
    is-active)
        service="${*: -1}"
        if [[ "$service" == tailscaled.service ]]; then
            [[ "${KERNEL_TAILSCALE_ACTIVE:-1}" -eq 1 ]]
        else
            [[ "${KERNEL_FIREWALL_ACTIVE:-1}" -eq 1 ]]
        fi
        ;;
    is-enabled) printf 'disabled\n' ;;
    is-failed)
        service="${*: -1}"
        [[ "$service" == kernel-module-netfilter-preload.service && "${KERNEL_PRELOAD_FAILED:-0}" -eq 1 ]]
        ;;
    enable|disable|daemon-reload) exit 0 ;;
    *) exit 0 ;;
esac
EOF
    cat > "$mock_bin/modprobe" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
module="${1:-}"
printf '%s\n' "$module" >> "$KERNEL_MODPROBE_LOG"
[[ "$module" != "${KERNEL_MODPROBE_FAIL:-}" ]] || exit 1
mkdir -p "$HARDEN_SYS_MODULE_ROOT/${module//-/_}"
EOF
    for command in iptables ip6tables; do
        cat > "$mock_bin/$command" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
name="$(basename "$0")"
printf '%s %s\n' "$name" "$*" >> "$KERNEL_COMMAND_LOG"
if [[ "${1:-}" == --version ]]; then
    printf '%s v1.8.11 (nf_tables)\n' "$name"
    exit 0
fi
if [[ "${KERNEL_MISSING_POSTROUTING:-0}" -eq 1 && " $* " == *' -t nat -S POSTROUTING '* ]]; then
    exit 1
fi
if [[ "${KERNEL_MISSING_IPV6_POSTROUTING:-0}" -eq 1 && "$name" == ip6tables \
    && " $* " == *' -t nat -S POSTROUTING '* ]]; then
    exit 1
fi
if [[ "$name" == iptables && " $* " == *' -t nat -S POSTROUTING '* \
    && -n "${KERNEL_POSTROUTING_READY_FILE:-}" ]]; then
    count="$(cat "$KERNEL_POSTROUTING_READY_FILE" 2>/dev/null || printf '0')"
    count=$((count + 1))
    printf '%s\n' "$count" > "$KERNEL_POSTROUTING_READY_FILE"
    if ((count <= ${KERNEL_POSTROUTING_FAILURES:-0})); then
        exit 1
    fi
fi
if [[ "${KERNEL_MISSING_TS_CHAINS:-0}" -eq 1 && " $* " == *' ts-'* ]]; then
    exit 1
fi
if [[ " $* " == *' -t nat -S ts-postrouting '* ]]; then
    printf '%s\n' '-N ts-postrouting'
    [[ "${KERNEL_MISSING_MASQUERADE:-0}" -eq 1 ]] \
        || printf '%s\n' '-A ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE'
fi
exit 0
EOF
        chmod 0755 "$mock_bin/$command"
    done
    cat > "$mock_bin/tailscale" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'tailscale %s\n' "$*" >> "$KERNEL_COMMAND_LOG"
[[ "${1:-}" == status && "${2:-}" == --json ]] || exit 64
if [[ "${KERNEL_TAILSCALE_HEALTH_ERROR:-0}" -eq 1 ]]; then
    printf '%s\n' '{"BackendState":"Running","Health":["router: netfilter setup failed"]}'
elif [[ "${KERNEL_TAILSCALE_UNRELATED_WARNING:-0}" -eq 1 ]]; then
    printf '%s\n' '{"BackendState":"Running","Self":{"PrimaryRoutes":["10.0.0.0/8","fd00::/64"]},"Health":["Some peers are advertising routes but --accept-routes is false."]}'
else
    printf '%s\n' '{"BackendState":"Running","Self":{"PrimaryRoutes":["10.0.0.0/8","fd00::/64"]},"Health":[]}'
fi
EOF
    cat > "$mock_bin/python3" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input="$(cat)"
grep -Fq '"BackendState":"Running"' <<<"$input" && printf 'backend=Running\n' || printf 'backend=Unknown\n'
grep -Fq '10.0.0.0/8' <<<"$input" && printf 'router-v4=1\n' || printf 'router-v4=0\n'
grep -Fq 'fd00::/64' <<<"$input" && printf 'router-v6=1\n' || printf 'router-v6=0\n'
grep -Eqi 'router|netfilter|firewall|iptables|nftables|masquerad|postrouting|forwarding' <<<"$input" \
    && printf 'health-problem=1\n' || true
EOF
    chmod +x "$mock_bin/sysctl" "$mock_bin/systemctl" "$mock_bin/modprobe" "$mock_bin/tailscale" "$mock_bin/python3"

    : > "$module_log"
    : > "$command_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_PROC_MODULES="$case_root/no-proc-modules" HARDEN_KERNEL_LOCK_REPORT="$report" \
        HARDEN_KERNEL_GATE_ATTEMPTS=1 HARDEN_KERNEL_GATE_INTERVAL=0 KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            kernel_module_preload_gate
            [[ "$(< "$2")" == 0 ]]
            grep -Fq "stage=preload-before-tailscaled" "$4"
            grep -Fq "gate-result=PRELOADED" "$4"
            preload_count="$(wc -l < "$3")"
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            [[ "$(wc -l < "$3")" == "$preload_count" ]]
            grep -Fxq nf_nat "$3"
            grep -Fxq nft_nat "$3"
            grep -Fxq nft_chain_nat "$3"
            grep -Fxq nft_masq "$3"
            grep -Fxq iptable_nat "$3"
            [[ "$(grep -Fxc xt_mark "$3")" == 1 ]]
            ! grep -Fxq nf_tables "$3"
            ! grep -Fxq ip6table_nat "$3"
            grep -Fq "CONFIG_NF_TABLES=builtin" "$4"
            grep -Fq "CONFIG_NF_NAT=module" "$4"
            grep -Fq "CONFIG_IP6_NF_NAT=unavailable" "$4"
            grep -Fq "ipv4-nat-postrouting=OK" "$4"
            grep -Fq "ipv6-nat-postrouting=OK" "$4"
            grep -Fq "gate-result=LOCKED" "$4"
            grep -Fq "iptables --version" "$5"
            grep -Fq "ip6tables --version" "$5"
            [[ "$(grep -Fxc "tailscale status --json" "$5")" == 1 ]]
            ! grep -Eq "tailscale (up|set)([[:space:]]|$)" "$5"
        ' _ "$repo_root" "$control" "$module_log" "$report" "$command_log" \
        || fail "active Tailscale modular/builtin/unavailable preload and dual-stack runtime gate failed"

    rm -rf -- "$sys_modules"
    install -d "$sys_modules"
    printf '0\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_PROC_MODULES="$case_root/no-proc-modules" HARDEN_KERNEL_LOCK_REPORT="$report" \
        HARDEN_KERNEL_GATE_ATTEMPTS=1 KERNEL_WRITE_COUNT="$writes" KERNEL_MODPROBE_LOG="$module_log" \
        KERNEL_COMMAND_LOG="$command_log" KERNEL_MODPROBE_FAIL=nft_masq bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            if kernel_lock_gate; then exit 1; fi
            [[ "$(< "$2")" == 0 ]]
            grep -Fq "modprobe nft_masq failed" "$3"
            grep -Fq "gate-result=BLOCKED" "$3"
        ' _ "$repo_root" "$control" "$report" || fail "modprobe failure did not block the irreversible lock"

    for failure in postrouting ipv6-postrouting health masquerade; do
        rm -rf -- "$sys_modules"
        install -d "$sys_modules"
        printf '0\n' > "$control"
        : > "$module_log"
        missing=0; missing_ipv6=0; health=0; masquerade=0
        case "$failure" in
            postrouting) missing=1 ;;
            ipv6-postrouting) missing_ipv6=1 ;;
            health) health=1 ;;
            masquerade) masquerade=1 ;;
        esac
        env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
            HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
            HARDEN_PROC_MODULES="$case_root/no-proc-modules" HARDEN_KERNEL_LOCK_REPORT="$report" \
            HARDEN_KERNEL_GATE_ATTEMPTS=1 KERNEL_WRITE_COUNT="$writes" KERNEL_MODPROBE_LOG="$module_log" \
            KERNEL_COMMAND_LOG="$command_log" KERNEL_MISSING_POSTROUTING="$missing" \
            KERNEL_MISSING_IPV6_POSTROUTING="$missing_ipv6" \
            KERNEL_TAILSCALE_HEALTH_ERROR="$health" KERNEL_MISSING_MASQUERADE="$masquerade" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                if kernel_lock_gate; then exit 1; fi
                [[ "$(< "$2")" == 0 ]]
                grep -Fq "gate-result=BLOCKED" "$3"
            ' _ "$repo_root" "$control" "$report" || fail "${failure} failure did not block the irreversible lock"
    done

    rm -rf -- "$sys_modules"
    install -d "$sys_modules"
    printf '0\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" HARDEN_KERNEL_GATE_ATTEMPTS=1 HARDEN_KERNEL_GATE_INTERVAL=0 \
        KERNEL_WRITE_COUNT="$writes" KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_TAILSCALE_UNRELATED_WARNING=1 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            grep -Fq "tailscale-router-netfilter-health=clear" "$3"
        ' _ "$repo_root" "$control" "$report" \
        || fail "unrelated accept-routes health text incorrectly blocked the final lock"

    rm -rf -- "$sys_modules"
    install -d "$sys_modules"
    printf '0\n' > "$control"
    printf '0\n' > "$case_root/readiness-count"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" HARDEN_KERNEL_GATE_ATTEMPTS=3 HARDEN_KERNEL_GATE_INTERVAL=0 \
        KERNEL_WRITE_COUNT="$writes" KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_POSTROUTING_READY_FILE="$case_root/readiness-count" KERNEL_POSTROUTING_FAILURES=2 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            [[ "$(< "$3")" == 3 ]]
            grep -Fq "runtime-attempt=3" "$4"
        ' _ "$repo_root" "$control" "$case_root/readiness-count" "$report" \
        || fail "bounded readiness polling did not succeed when prerequisites became ready"

    rm -rf -- "$sys_modules"
    install -d "$sys_modules"
    printf '0\n' > "$control"
    printf '0\n' > "$case_root/readiness-count"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" HARDEN_KERNEL_GATE_ATTEMPTS=2 HARDEN_KERNEL_GATE_INTERVAL=0 \
        KERNEL_WRITE_COUNT="$writes" KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_POSTROUTING_READY_FILE="$case_root/readiness-count" KERNEL_POSTROUTING_FAILURES=99 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            if kernel_lock_gate; then exit 1; fi
            [[ "$(< "$2")" == 0 ]]
            [[ "$(< "$3")" == 2 ]]
            grep -Fq "gate-result=BLOCKED" "$4"
        ' _ "$repo_root" "$control" "$case_root/readiness-count" "$report" \
        || fail "readiness polling timeout did not leave module loading enabled"

    rm -rf -- "$sys_modules"
    install -d "$sys_modules"
    printf '0\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_TAILSCALE_ACTIVE=0 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            [[ ! -s "$3" ]]
            grep -Fq "tailscale-runtime-check=not-required-inactive" "$4"
        ' _ "$repo_root" "$control" "$module_log" "$report" || fail "inactive Tailscale no-preload lock path failed"

    printf '0\n' > "$control"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_TAILSCALE_ACTIVE=0 KERNEL_PRELOAD_FAILED=1 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            if kernel_lock_gate; then exit 1; fi
            [[ "$(< "$2")" == 0 ]]
            grep -Fq "Tailscale or its Netfilter preload prerequisite failed" "$3"
        ' _ "$repo_root" "$control" "$report" || fail "failed boot preload was hidden by an inactive-Tailscale normal lock path"

    printf '1\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            [[ ! -s "$3" ]]
            grep -Fq "CONFIG_NF_NAT=module" "$4"
            grep -Fq "already-locked-runtime-check=OK" "$4"
            grep -Fq "gate-result=already-locked-idempotent" "$4"
        ' _ "$repo_root" "$control" "$module_log" "$report" || fail "already-locked no-modprobe idempotent path failed"

    printf '1\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" \
        KERNEL_MISSING_POSTROUTING=1 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            kernel_lock_gate
            [[ "$(< "$2")" == 1 ]]
            [[ ! -s "$3" ]]
            grep -Fq "already-locked-runtime-check=FAILED; reboot-repair-required" "$4"
            grep -Fq "gate-result=already-locked-idempotent" "$4"
        ' _ "$repo_root" "$control" "$module_log" "$report" \
        || fail "already-locked broken runtime was not diagnosed without an impossible live repair"

    printf '0\n' > "$control"
    : > "$writes"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_MODULE_LOCK_UNIT="$unit" HARDEN_MODULE_LOCK_HELPER="$helper" \
        HARDEN_KERNEL_CONFIG="$kernel_config" HARDEN_SYS_MODULE_ROOT="$sys_modules" \
        HARDEN_KERNEL_LOCK_REPORT="$report" HARDEN_KERNEL_GATE_ATTEMPTS=1 KERNEL_WRITE_COUNT="$writes" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$5"
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
            REBOOT_REQUIRED=0
            : > "$6"
            lock_kernel_modules_late
            [[ "$(wc -l < "$3")" == 1 ]]
            [[ "$REBOOT_REQUIRED" == 0 ]]
            [[ ! -s "$6" ]]
            grep -Fq "already-locked-runtime-check=OK" "$HARDEN_KERNEL_LOCK_REPORT"
            export KERNEL_MISSING_POSTROUTING=1
            REBOOT_REQUIRED=0
            : > "$6"
            lock_kernel_modules_late
            [[ "$(< "$2")" == 1 ]]
            [[ "$REBOOT_REQUIRED" == 1 ]]
            [[ ! -s "$6" ]]
            grep -Fq "already-locked-runtime-check=FAILED; reboot-repair-required" "$HARDEN_KERNEL_LOCK_REPORT"
            grep -Fq "gate-result=already-locked-idempotent" "$HARDEN_KERNEL_LOCK_REPORT"
        ' _ "$repo_root" "$control" "$writes" "$case_root/changes.tsv" "$case_root/backup" "$module_log" \
        || fail "final phase-17 kernel.modules_disabled gate or idempotent path failed"

    local prep_root="$case_root/prepare" prep_backup="$case_root/prepare-backup"
    install -d "$prep_root/tailscaled.service.d" "$prep_backup"
    printf '1\n' > "$control"
    : > "$module_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_MODULE_LOCK_HELPER="$prep_root/kernel-module-lockdown" \
        HARDEN_MODULE_LOCK_UNIT="$prep_root/kernel-module-lockdown.service" \
        HARDEN_MODULE_PRELOAD_UNIT="$prep_root/kernel-module-netfilter-preload.service" \
        HARDEN_TAILSCALE_PRELOAD_DROPIN="$prep_root/tailscaled.service.d/99-netfilter-module-preload.conf" \
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; AGGRESSIVE=1; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            install_managed_file() {
                local destination="$1" mode="$2"
                mkdir -p -- "$(dirname -- "$destination")"
                MANAGED_FILE_CHANGED=1
                cat > "$destination"
                chmod "$mode" "$destination"
            }
            systemd_verify_unit() { return 0; }
            unit_file_exists() { [[ "$1" == tailscaled.service ]]; }
            run_streamed() { "$@"; }
            prepare_kernel_module_lock
            [[ -x "$HARDEN_MODULE_LOCK_HELPER" ]]
            [[ -f "$HARDEN_MODULE_LOCK_UNIT" && -f "$HARDEN_MODULE_PRELOAD_UNIT" ]]
            [[ -f "$HARDEN_TAILSCALE_PRELOAD_DROPIN" ]]
        ' _ "$repo_root" "$prep_backup" \
        || fail "already-locked host did not install and verify patched boot helper/units"
    [[ ! -s "$module_log" ]] || fail "already-locked preparation attempted modprobe instead of deferring repair to reboot"

    local rollback_root="$case_root/rollback" rollback_backup="$case_root/rollback-backup"
    install -d "$rollback_root/tailscaled.service.d" "$rollback_backup"
    printf 'old-helper\n' > "$rollback_root/kernel-module-lockdown"
    printf 'old-lock\n' > "$rollback_root/kernel-module-lockdown.service"
    printf 'old-preload\n' > "$rollback_root/kernel-module-netfilter-preload.service"
    printf 'old-dropin\n' > "$rollback_root/tailscaled.service.d/99-netfilter-module-preload.conf"
    printf '0\n' > "$control"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_MODULES_DISABLED_PATH="$control" \
        HARDEN_MODULE_LOCK_HELPER="$rollback_root/kernel-module-lockdown" \
        HARDEN_MODULE_LOCK_UNIT="$rollback_root/kernel-module-lockdown.service" \
        HARDEN_MODULE_PRELOAD_UNIT="$rollback_root/kernel-module-netfilter-preload.service" \
        HARDEN_TAILSCALE_PRELOAD_DROPIN="$rollback_root/tailscaled.service.d/99-netfilter-module-preload.conf" \
        KERNEL_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; AGGRESSIVE=1; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            install_managed_file() {
                local destination="$1" mode="$2"
                MANAGED_FILE_CHANGED=1
                cat > "$destination"
                chmod "$mode" "$destination"
            }
            systemd_verify_unit() { return 1; }
            run_streamed() { "$@"; }
            if prepare_kernel_module_lock; then exit 1; fi
            grep -Fxq old-helper "$HARDEN_MODULE_LOCK_HELPER"
            grep -Fxq old-lock "$HARDEN_MODULE_LOCK_UNIT"
            grep -Fxq old-preload "$HARDEN_MODULE_PRELOAD_UNIT"
            grep -Fxq old-dropin "$HARDEN_TAILSCALE_PRELOAD_DROPIN"
            [[ -f "$BACKUP_DIR/transactions/kernel-module-lockdown-helper" ]]
            [[ -f "$BACKUP_DIR/transactions/kernel-module-lockdown.service" ]]
            [[ -f "$BACKUP_DIR/transactions/kernel-module-netfilter-preload.service" ]]
            [[ -f "$BACKUP_DIR/transactions/tailscaled-netfilter-preload.conf" ]]
        ' _ "$repo_root" "$rollback_backup" \
        || fail "failed kernel helper/unit verification did not restore all transaction backups"

    env HARDEN_SOURCE_ONLY=1 bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        helper="$(render_kernel_module_lock_helper)"
        grep -Fq "kernel_lock_gate" <<<"$helper"
        grep -Fq -- "--preload" <<<"$helper"
        ! grep -Eq "tailscale (up|set)([[:space:]]|$)" <<<"$helper"
        ! grep -Fq "sysctl -w kernel.modules_disabled=1" < <(sed -n "/^prepare_kernel_module_lock()/,/^}/p" "$1/harden.sh")
        [[ "$(grep -Fc "sysctl -w kernel.modules_disabled=1" "$1/harden.sh")" == 1 ]]
        grep -Fq "Requires=server-hardening-firewall.service" "$1/harden.sh"
        grep -Fq "Before=tailscaled.service" "$1/harden.sh"
        grep -Fq "Requires=kernel-module-netfilter-preload.service" "$1/harden.sh"
        grep -Fq "After=network-online.target server-hardening-firewall.service apparmor.service kernel-module-netfilter-preload.service tailscaled.service" "$1/harden.sh"
        grep -Fq "net.ipv4.conf.all.rp_filter" "$1/harden.sh"
        grep -Fq "value=2" "$1/harden.sh"
    ' _ "$repo_root" || fail "lock helper/unit ordering, Tailscale preference neutrality, or rp_filter preservation regressed"

    if command -v systemd-analyze >/dev/null 2>&1; then
        local verify_dir="$case_root/systemd-verify"
        install -d "$verify_dir/tailscaled.service.d"
        env HARDEN_SOURCE_ONLY=1 bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            render_kernel_module_lock_helper > "$2/kernel-module-lockdown"
            chmod 0755 "$2/kernel-module-lockdown"
            render_kernel_module_lock_unit /proc/sys/kernel/modules_disabled "$2/kernel-module-lockdown" \
                > "$2/kernel-module-lockdown.service"
            render_kernel_module_preload_unit /proc/sys/kernel/modules_disabled "$2/kernel-module-lockdown" \
                > "$2/kernel-module-netfilter-preload.service"
            render_server_hardening_firewall_unit > "$2/server-hardening-firewall.service"
            render_tailscale_preload_dropin > "$2/tailscaled.service.d/99-netfilter-module-preload.conf"
        ' _ "$repo_root" "$verify_dir" || fail "could not render the generated lock helper/unit fixture"
        cat > "$verify_dir/tailscaled.service" <<'EOF'
[Unit]
Description=Regression fixture for Tailscale ordering
[Service]
Type=simple
ExecStart=/bin/true
EOF
        SYSTEMD_UNIT_PATH="$verify_dir:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system" \
            systemd-analyze verify server-hardening-firewall.service \
            kernel-module-netfilter-preload.service tailscaled.service kernel-module-lockdown.service \
            || fail "systemd-analyze rejected the generated late-lock unit ordering"
    else
        printf 'INFO: systemd-analyze unavailable; generated-unit verify remains covered by Linux CI.\n'
    fi
}

run_lynis_summary_tests() {
    local case_root="$test_root/lynis-summary"
    local report="$case_root/final.txt" data="$case_root/final-report.dat" diagnostic="$case_root/diagnostic.txt"
    install -d "$case_root"
    cat > "$case_root/fresh.txt" <<'EOF'
  Hardening index : 61 [############        ]
EOF
    cat > "$case_root/fresh-report.dat" <<'EOF'
hardening_index=61
EOF
    cat > "$case_root/hardened.txt" <<'EOF'
  Hardening index : 87 [#################   ]
EOF
    cat > "$case_root/hardened-report.dat" <<'EOF'
hardening_index=87
EOF
    env HARDEN_SOURCE_ONLY=1 HARDEN_LYNIS_BASELINE_REPORT="$case_root/fresh.txt" \
        HARDEN_LYNIS_BASELINE_DATA="$case_root/fresh-report.dat" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            lynis() { :; }
            run_lynis() { :; }
            capture_lynis_baseline
            [[ "$LYNIS_BEFORE" == 61 && "$LYNIS_BEFORE" != 86 ]]
        ' _ "$repo_root" || fail "fresh-system Lynis Before baseline was not measured dynamically"
    env HARDEN_SOURCE_ONLY=1 HARDEN_LYNIS_BASELINE_REPORT="$case_root/hardened.txt" \
        HARDEN_LYNIS_BASELINE_DATA="$case_root/hardened-report.dat" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            lynis() { :; }
            run_lynis() { :; }
            capture_lynis_baseline
            [[ "$LYNIS_BEFORE" == 87 ]]
        ' _ "$repo_root" || fail "second-run Lynis Before did not reflect the already-hardened starting state"
    env HARDEN_SOURCE_ONLY=1 HARDEN_LYNIS_BASELINE_REPORT="$case_root/dry.txt" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=dry-run
            run_lynis() { exit 91; }
            capture_lynis_baseline
            [[ "$LYNIS_BEFORE" == "N/A (dry-run; NOT RUN)" ]]
            [[ ! -e "$HARDEN_LYNIS_BASELINE_REPORT" ]]
        ' _ "$repo_root" || fail "dry-run unexpectedly launched or wrote a Lynis baseline"
    ! grep -Fq 'SOURCE_LYNIS_INDEX=' "$repo_root/harden.sh" || fail "static Lynis Before source score remains"
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
    [[ "${LC_ALL:-}" == C ]] || exit 64
    printf 'Purg packagekit [1.2.8]\nPurg packagekit-tools [1.2.8]\n'
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
                    [[ "${LC_ALL:-}" == C ]] || return 64
                    printf "Purg ubuntu-server [1.0]\nPurg software-properties-common [0.111]\nPurg packagekit [1.2.8]\n"
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
            reason="$(printf "%s\n" "${SKIPPED_FINDINGS[*]}")"
            grep -Fq "software-properties-common" <<<"$reason"
            grep -Fq "ubuntu-server" <<<"$reason"
            ! grep -Eq "(^|[[:space:]])autoremove([[:space:]]|$)" "$1/harden.sh"
        ' _ "$repo_root" "$case_root" || fail "unsafe PackageKit dependency simulation was not blocked"
}

run_package_upgrade_tests() {
    local case_root="$test_root/package-upgrade" mock_bin="$test_root/package-upgrade/bin" apt_log="$test_root/package-upgrade/apt.log"
    install -d "$mock_bin"
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$PACKAGE_UPGRADE_APT_LOG"
case "${1:-}" in
    check) exit 0 ;;
    -s)
        case "${PACKAGE_UPGRADE_TEST_CASE:-nothing}" in
            nothing) printf '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n' ;;
            upgrades) printf 'Inst openssl [3.0.0] (3.0.1 Ubuntu:26.04/stable)\n' ;;
            removal) printf 'Remv critical-package [1.0]\nInst openssl [3.0.0] (3.0.1 Ubuntu:26.04/stable)\n' ;;
            downgrade) printf 'The following packages will be DOWNGRADED:\nInst openssl [3.0.1] (3.0.0 Ubuntu:26.04/stable)\n' ;;
            *) exit 1 ;;
        esac
        ;;
    -y)
        [[ "${PACKAGE_UPGRADE_TEST_CASE:-}" == upgrades ]] || exit 64
        [[ "${NEEDRESTART_MODE:-}" == l ]] || exit 65
        ;;
    *) exit 64 ;;
esac
EOF
    chmod +x "$mock_bin/apt-get"
    for test_case in nothing upgrades removal downgrade; do
        : > "$apt_log"
        env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGE_UPGRADE_APT_LOG="$apt_log" PACKAGE_UPGRADE_TEST_CASE="$test_case" \
            HARDEN_REBOOT_REQUIRED_FILE="$case_root/reboot-required" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                MODE=apply; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"; REBOOT_REQUIRED=0
                log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }
                upgrade_packages_safely
                case "$3" in
                    nothing) [[ "$PACKAGE_UPGRADE_STATUS" == "OK (nothing upgradeable)" ]]; ! grep -Eq "^-y | -y " "$PACKAGE_UPGRADE_APT_LOG" ;;
                    upgrades) [[ "$PACKAGE_UPGRADE_STATUS" == "OK (upgraded; no reboot required)" ]]; grep -Eq "^-y | -y " "$PACKAGE_UPGRADE_APT_LOG" ;;
                    removal|downgrade) [[ "$PACKAGE_UPGRADE_STATUS" == "BLOCKED"* ]]; ! grep -Eq "^-y | -y " "$PACKAGE_UPGRADE_APT_LOG" ;;
                esac
            ' _ "$repo_root" "$case_root" "$test_case" || fail "package upgrade ${test_case} safety regression failed"
    done
    : > "$apt_log"; : > "$case_root/reboot-required"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGE_UPGRADE_APT_LOG="$apt_log" PACKAGE_UPGRADE_TEST_CASE=upgrades \
        HARDEN_REBOOT_REQUIRED_FILE="$case_root/reboot-required" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; CHANGE_LOG="$2/reboot.tsv"; : > "$CHANGE_LOG"; REBOOT_REQUIRED=0
            log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }
            upgrade_packages_safely
            [[ "$REBOOT_REQUIRED" -eq 1 && "$PACKAGE_UPGRADE_STATUS" == "OK (upgraded; reboot required)" ]]
        ' _ "$repo_root" "$case_root" || fail "package upgrade reboot marker regression failed"

    local main_section detect_line guard_line migration_line refresh_line upgrade_line prepare_line backup_line update_count
    main_section="$(sed -n '/^main()/,$p' "$repo_root/harden.sh")"
    detect_line="$(awk '/^[[:space:]]*detect_ssh_context[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    guard_line="$(awk '/^[[:space:]]*enable_needrestart_list_only[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    migration_line="$(awk '/^[[:space:]]*migrate_legacy_ssh_private_tmp_early/ { print NR; exit }' <<<"$main_section")"
    refresh_line="$(awk '/^[[:space:]]*refresh_apt_metadata[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    upgrade_line="$(awk '/^[[:space:]]*upgrade_packages_safely[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    prepare_line="$(awk '/^[[:space:]]*prepare_packages[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    backup_line="$(awk '/^[[:space:]]*backup_config[[:space:]]*$/ { print NR; exit }' <<<"$main_section")"
    update_count="$(awk '!/^[[:space:]]*#/ && /run_streamed[[:space:]].*apt-get update/ {count++} END {print count+0}' "$repo_root/harden.sh")"
    [[ "$update_count" == 1 && "$backup_line" -lt "$detect_line" && "$detect_line" -lt "$guard_line" \
        && "$guard_line" -lt "$migration_line" && "$migration_line" -lt "$refresh_line" \
        && "$refresh_line" -lt "$upgrade_line" && "$upgrade_line" -lt "$prepare_line" ]] \
        || fail "backup/early-SSH/needrestart/APT/package-install order or single-update invariant regressed"

    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 PACKAGE_UPGRADE_APT_LOG="$apt_log" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=dry-run; log() { printf "%s\n" "$*"; }; refresh_apt_metadata; upgrade_packages_safely
        [[ ! -s "$PACKAGE_UPGRADE_APT_LOG" && "$PACKAGE_UPGRADE_STATUS" == PLANNED* ]]
    ' _ "$repo_root" || fail "Phase 03 APT dry-run performed a package operation"

    cat > "$mock_bin/needrestart" <<'EOF'
#!/usr/bin/env bash
[[ "${NEEDRESTART_MODE:-}" == l && "$*" == *"-b"* && "$*" == *"-r l"* ]] || exit 66
printf 'NEEDRESTART-VER: 3.11\n'
printf 'NEEDRESTART-SVC: ssh.service\n'
printf 'NEEDRESTART-SVC: tailscaled.service\n'
EOF
    chmod +x "$mock_bin/needrestart"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_NEEDRESTART_REPORT="$case_root/needrestart-report.txt" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/needrestart-changes"; : > "$CHANGE_LOG"; REBOOT_REQUIRED=0
        enable_needrestart_list_only
        report_needrestart_pending
        [[ "$NEEDRESTART_MODE" == l && "$REBOOT_REQUIRED" -eq 1 ]]
        [[ "$NEEDRESTART_STATUS" == PENDING* ]]
        grep -Fq "NEEDRESTART-SVC: ssh.service" "$NEEDRESTART_REPORT"
        grep -Fq "NEEDRESTART-SVC: tailscaled.service" "$NEEDRESTART_REPORT"
    ' _ "$repo_root" "$case_root" || fail "needrestart list-only critical-service pending report regression failed"
}

run_residual_purge_tests() {
    local case_root="$test_root/residual-purge" mock_bin="$test_root/residual-purge/bin"
    install -d "$mock_bin"
    cat > "$mock_bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -W ]]; then
    if [[ "${3:-}" == safe-residual ]]; then
        [[ "${RESIDUAL_STATE:-present}" == present ]] && printf 'deinstall ok config-files\n'
        exit 0
    fi
    if [[ "${RESIDUAL_STATE:-present}" == present ]]; then
        printf 'safe-residual\tdeinstall ok config-files\n'
    fi
    [[ "${RESIDUAL_PROTECTED:-0}" == 1 ]] && printf 'openssh-server\tdeinstall ok config-files\n'
fi
EOF
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -s ]]; then
    if [[ "${RESIDUAL_UNREQUESTED:-0}" == 1 ]]; then printf 'Purg safe-residual [1.0]\nPurg unrelated-config [1.0]\n'; else printf 'Purg safe-residual [1.0]\n'; fi
elif [[ " $* " == *' purge -y '* ]]; then
    printf '%s\n' "$*" >> "$RESIDUAL_APT_LOG"
    printf cleared > "$RESIDUAL_STATE_FILE"
fi
EOF
    chmod +x "$mock_bin/dpkg-query" "$mock_bin/apt-get"
    : > "$case_root/apt.log"; : > "$case_root/state"; install -d "$case_root/boot"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_APT_LOG="$case_root/apt.log" RESIDUAL_STATE_FILE="$case_root/state" HARDEN_BOOT_DIR="$case_root/boot" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"; BACKUP_DIR="$2/backup"; mkdir -p "$BACKUP_DIR"
        log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }
        dpkg-query() { if [[ -s "$RESIDUAL_STATE_FILE" ]]; then RESIDUAL_STATE=cleared command dpkg-query "$@"; else RESIDUAL_STATE=present command dpkg-query "$@"; fi; }
        purge_removed_packages final || { printf "purge status: %s\n" "$RESIDUAL_PURGE_STATUS" >&2; cat "$RESIDUAL_APT_LOG" >&2; exit 1; }
        grep -Fq "purge -y safe-residual" "$RESIDUAL_APT_LOG" || { cat "$RESIDUAL_APT_LOG" >&2; exit 1; }
        ! grep -Fq safe-residual < <(dpkg-query -W) || { dpkg-query -W >&2; exit 1; }
    ' _ "$repo_root" "$case_root" || fail "residual package final sweep regression failed"
    : > "$case_root/apt.log"; : > "$case_root/state"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_APT_LOG="$case_root/apt.log" RESIDUAL_STATE_FILE="$case_root/state" RESIDUAL_UNREQUESTED=1 bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; CHANGE_LOG="$2/unrequested.tsv"; : > "$CHANGE_LOG"; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }
        purge_removed_packages final
        [[ ! -s "$RESIDUAL_APT_LOG" ]]
    ' _ "$repo_root" "$case_root" || fail "residual package unrequested purge was not blocked"

    local fixture_root fixture_status fixture_log
    fixture_root="$case_root/boot-fixtures"
    fixture_status="$fixture_root/status.tsv"
    fixture_log="$fixture_root/apt.log"
    install -d "$fixture_root/bin" "$fixture_root/boot" "$fixture_root/efi/EFI/ubuntu" "$fixture_root/grub" "$fixture_root/links"
    cat > "$fixture_root/bin/uname" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${RESIDUAL_KERNEL_VERSION:-7.0.0-30-generic}"
EOF
    cat > "$fixture_root/bin/readlink" <<'EOF'
#!/usr/bin/env bash
[[ -n "${RESIDUAL_BOOT_TARGET:-}" ]] || exit 1
printf '%s\n' "$RESIDUAL_BOOT_TARGET"
EOF
    cat > "$fixture_root/bin/dpkg-query" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
fmt="${2:-}" package="${3:-}"
emit() {
    local name="$1" status="$2"
    case "$fmt" in
        *'${binary:Package}'*) printf '%s\t%s\n' "$name" "$status" ;;
        *'${db:Status-Abbrev}'*) [[ "$status" == 'install ok installed' ]] && printf 'ii \n' || printf 'rc \n' ;;
        *) printf '%s\n' "$status" ;;
    esac
}
if [[ -z "$package" ]]; then
    while IFS=$'\t' read -r name status; do [[ -n "$name" ]] && emit "$name" "$status"; done < "$RESIDUAL_FIXTURE_STATUS"
else
    while IFS=$'\t' read -r name status; do
        [[ "$name" == "$package" ]] && { emit "$name" "$status"; exit 0; }
    done < "$RESIDUAL_FIXTURE_STATUS"
fi
EOF
    cat > "$fixture_root/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -s ]]; then
    shift
    [[ "${1:-}" == purge ]] || exit 1
    shift
    for package in "$@"; do printf 'Purg %s [1.0]\n' "$package"; done
    if [[ "${RESIDUAL_SIM_EXTRA:-0}" == 1 ]]; then printf 'Purg unrelated-installed [1.0]\n'; fi
elif [[ "${1:-}" == check ]]; then
    exit 0
elif [[ "${1:-}" == purge ]]; then
    printf '%s\n' "$*" >> "$RESIDUAL_FIXTURE_APT_LOG"
    for package in "$@"; do
        [[ "$package" == -y ]] && continue
        awk -F '\t' -v package="$package" '$1 != package {print $0}' "$RESIDUAL_FIXTURE_STATUS" > "${RESIDUAL_FIXTURE_STATUS}.next"
        mv "${RESIDUAL_FIXTURE_STATUS}.next" "$RESIDUAL_FIXTURE_STATUS"
    done
else
    exit 1
fi
EOF
    chmod +x "$fixture_root/bin/uname" "$fixture_root/bin/readlink" "$fixture_root/bin/dpkg-query" "$fixture_root/bin/apt-get"
    printf 'grub configuration\n' > "$fixture_root/grub/grub.cfg"
    printf 'efi binary\n' > "$fixture_root/efi/EFI/ubuntu/shimx64.efi"
    for artifact in vmlinuz initrd.img System.map config; do printf 'current %s\n' "$artifact" > "$fixture_root/boot/${artifact}-7.0.0-30-generic"; done

    cat > "$fixture_status" <<'EOF'
linux-image-7.0.0-30-generic	install ok installed
linux-image-unsigned-7.0.0-14-generic	deinstall ok config-files
linux-main-modules-zfs-7.0.0-14-generic	deinstall ok config-files
linux-modules-7.0.0-14-generic	deinstall ok config-files
grub-pc	deinstall ok config-files
grub-efi-amd64	install ok installed
grub-efi-amd64-bin	install ok installed
grub2-common	install ok installed
shim-signed	install ok installed
EOF
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" \
        HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_BOOT_SYMLINK_DIR="$fixture_root/links" HARDEN_EFI_RUNTIME_DIR="$fixture_root/efi-runtime" \
        HARDEN_EFI_BOOT_DIR="$fixture_root/efi" HARDEN_GRUB_DIR="$fixture_root/grub" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; REBOOT_REQUIRED=0; CHANGE_LOG="$2/target.tsv"; : > "$CHANGE_LOG"; mkdir -p "$HARDEN_EFI_RUNTIME_DIR"
            log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }
            purge_removed_packages final
            ! grep -E "^(linux-image-unsigned-7.0.0-14-generic|linux-main-modules-zfs-7.0.0-14-generic|linux-modules-7.0.0-14-generic|grub-pc)[[:space:]]" "$RESIDUAL_FIXTURE_STATUS"
            [[ "$RESIDUAL_PURGE_STATUS" == OK* && "$REBOOT_REQUIRED" -eq 0 ]]
            grep -Fq "purge -y linux-image-unsigned-7.0.0-14-generic linux-main-modules-zfs-7.0.0-14-generic linux-modules-7.0.0-14-generic grub-pc" "$RESIDUAL_FIXTURE_APT_LOG"
            before="$(wc -l < "$RESIDUAL_FIXTURE_APT_LOG")"; purge_removed_packages final; [[ "$(wc -l < "$RESIDUAL_FIXTURE_APT_LOG")" == "$before" ]]
        ' _ "$repo_root" "$fixture_root" || fail "UEFI old-kernel/grub-pc residual purge regression failed"

    cat > "$fixture_status" <<'EOF'
linux-image-7.0.0-30-generic	deinstall ok config-files
grub-efi-amd64	install ok installed
EOF
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" \
        HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_BOOT_SYMLINK_DIR="$fixture_root/links" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "running kernel residual was not protected"

    cat > "$fixture_status" <<'EOF'
linux-image-unsigned-7.0.0-14-generic	deinstall ok config-files
EOF
    printf 'old artifact\n' > "$fixture_root/boot/vmlinuz-7.0.0-14-generic"
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" HARDEN_BOOT_DIR="$fixture_root/boot" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "old kernel residual with /boot artifact was not protected"
    rm -f "$fixture_root/boot/vmlinuz-7.0.0-14-generic"
    printf 'old boot target\n' > "$fixture_root/old-vmlinuz-7.0.0-14-generic"
    : > "$fixture_root/links/vmlinuz"
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" RESIDUAL_BOOT_TARGET="$fixture_root/old-vmlinuz-7.0.0-14-generic" \
        HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_BOOT_SYMLINK_DIR="$fixture_root/links" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "kernel residual referenced by a boot symlink was not protected"
    rm -f "$fixture_root/links/vmlinuz" "$fixture_root/old-vmlinuz-7.0.0-14-generic"

    cat > "$fixture_status" <<'EOF'
linux-image-custom	deinstall ok config-files
linux-image-generic	deinstall ok config-files
grub-pc	deinstall ok config-files
EOF
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_EFI_RUNTIME_DIR="$fixture_root/no-efi" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "ambiguous/meta kernel or BIOS grub-pc residual was not protected"

    cat > "$fixture_status" <<'EOF'
linux-image-unsigned-7.0.0-14-generic	deinstall ok config-files
linux-image-7.0.0-14-generic	install ok installed
grub-pc	deinstall ok config-files
EOF
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_EFI_RUNTIME_DIR="$fixture_root/efi-runtime" HARDEN_EFI_BOOT_DIR="$fixture_root/missing-efi" HARDEN_GRUB_DIR="$fixture_root/grub" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "installed old kernel or unverifiable EFI GRUB was not protected"

    cat > "$fixture_status" <<'EOF'
linux-image-unsigned-7.0.0-14-generic	deinstall ok config-files
grub-efi-amd64	install ok installed
unrelated-installed	install ok installed
EOF
    : > "$fixture_log"
    env PATH="$fixture_root/bin:$PATH" HARDEN_SOURCE_ONLY=1 RESIDUAL_FIXTURE_STATUS="$fixture_status" RESIDUAL_FIXTURE_APT_LOG="$fixture_log" RESIDUAL_SIM_EXTRA=1 \
        HARDEN_BOOT_DIR="$fixture_root/boot" HARDEN_EFI_RUNTIME_DIR="$fixture_root/efi-runtime" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }; run_streamed() { "$@"; }; purge_removed_packages; [[ ! -s "$RESIDUAL_FIXTURE_APT_LOG" ]]
        ' _ "$repo_root" "$fixture_root" || fail "residual purge simulation with extra removal was not blocked"
}

run_firewall_inventory_tests() {
    local case_root="$test_root/firewall-inventory" mock_bin="$test_root/firewall-inventory/bin" command_log="$test_root/firewall-inventory/commands.log"
    install -d "$mock_bin"
    cat > "$mock_bin/nft" <<'EOF'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >> "$FIREWALL_TEST_COMMAND_LOG"
if [[ "$*" == 'list ruleset' ]]; then printf 'table inet tailscale { chain ts-input { } }\n'; elif [[ "$*" == 'list table inet hardening_filter' ]]; then printf 'table inet hardening_filter { chain input { tcp dport 22 accept } }\n'; fi
EOF
    cat > "$mock_bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "$FIREWALL_TEST_COMMAND_LOG"
printf '%s\n' '-P INPUT ACCEPT'
EOF
    cp "$mock_bin/iptables" "$mock_bin/ip6tables"
    chmod +x "$mock_bin/nft" "$mock_bin/iptables" "$mock_bin/ip6tables"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_FIREWALL_RULE_REPORT="$case_root/report.txt" FIREWALL_TEST_COMMAND_LOG="$command_log" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; log() { :; }; record_skip() { :; }
        inspect_firewall_rule_hygiene
        [[ "$FIREWALL_RULE_HYGIENE_STATUS" == "INVENTORIED"* || "$FIREWALL_RULE_HYGIENE_STATUS" == "REVIEW REQUIRED"* ]]
        grep -Fq "table inet tailscale" "$HARDEN_FIREWALL_RULE_REPORT"
        ! grep -Eqi "(delete|flush| -D )" "$FIREWALL_TEST_COMMAND_LOG"
    ' _ "$repo_root" || fail "FIRE-4513 inventory safety regression failed"
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
    printf 'ii\tnvidia-dkms-570\n'
elif [[ "${COMPILER_HEADERS_ONLY:-0}" -eq 1 ]]; then
    printf 'ii\tlinux-headers-generic\n'
else
    exit 1
fi
EOF
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *' -s purge '* ]]; then
    [[ "${LC_ALL:-}" == C ]] || exit 64
    if [[ "${COMPILER_UNSAFE:-0}" -eq 1 ]]; then
        printf 'Purg rkhunter [1.4.6]\nPurg crash [8.0]\nPurg binutils [2.44]\nPurg binutils-x86-64-linux-gnu [2.44]\n'
    else
        printf 'Purg gcc [14]\nPurg binutils [2.43]\n'
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
            printf "%s\n" "${SKIPPED_FINDINGS[*]}" | grep -Fq "active DKMS modules or installed *-dkms packages"
            run() {
                if [[ "${1:-}" == chown || "${1:-}" == chmod ]]; then
                    printf "unexpected-compiler-metadata-write %s\n" "$*" >> "$COMPILER_APT_LOG"
                    return 99
                fi
                run_streamed "$@"
            }
            : > "$COMPILER_APT_LOG"
            restrict_compilers
            ! grep -Fq "unexpected-compiler-metadata-write" "$COMPILER_APT_LOG"
        ' _ "$repo_root" "$case_root" "$mock_bin" || fail "protected compiler dependency/root-only fallback regression failed"

    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 COMPILER_APT_LOG="$apt_log" \
        COMPILER_BIN_DIR="$mock_bin" COMPILER_UNSAFE=1 HARDEN_TEST_OWNER="$(id -u)" \
        HARDEN_TEST_GROUP="$(id -g)" HARDEN_COMPILER_USR_ROOT="$case_root/empty-usr" \
        HARDEN_COMPILER_LOCAL_ROOT="$case_root/empty-local" HARDEN_DKMS_STATE_DIR="$case_root/no-dkms" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/unsafe.tsv"
            : > "$CHANGE_LOG"
            compiler_command_path() { if [[ -x "$COMPILER_BIN_DIR/$1" ]]; then printf "%s/%s\n" "$COMPILER_BIN_DIR" "$1"; fi; return 0; }
            restrict_compilers
            [[ ! -s "$2/apt.log" ]]
            reason="$(printf "%s\n" "${SKIPPED_FINDINGS[*]}")"
            grep -Fq "rkhunter" <<<"$reason"
            grep -Fq "crash" <<<"$reason"
            ! grep -Eq "(^|[[:space:]])autoremove([[:space:]]|$)" "$1/harden.sh"
        ' _ "$repo_root" "$case_root" || fail "compiler purge dependency cascade fixture was not blocked with a concrete reason"

    : > "$apt_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 COMPILER_APT_LOG="$apt_log" \
        COMPILER_BIN_DIR="$mock_bin" COMPILER_HEADERS_ONLY=1 HARDEN_TEST_OWNER="$(id -u)" \
        HARDEN_TEST_GROUP="$(id -g)" HARDEN_COMPILER_USR_ROOT="$case_root/empty-usr" \
        HARDEN_COMPILER_LOCAL_ROOT="$case_root/empty-local" HARDEN_DKMS_STATE_DIR="$case_root/no-dkms" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/headers.tsv"
            : > "$CHANGE_LOG"
            compiler_command_path() { if [[ -x "$COMPILER_BIN_DIR/$1" ]]; then printf "%s/%s\n" "$COMPILER_BIN_DIR" "$1"; fi; return 0; }
            restrict_compilers
            grep -Fq "purge -y" "$2/apt.log"
        ' _ "$repo_root" "$case_root" || fail "kernel headers alone still blocked the compiler APT simulation/removal path"
}

run_binfmt_tests() {
    local case_root="$test_root/binfmt" root="$test_root/binfmt/proc" config="$test_root/binfmt/config"
    install -d "$root" "$config" "$case_root/backup"
    local etc_config="$case_root/etc-binfmt" python_root="$case_root/python-bin" mock_bin="$case_root/bin"
    install -d "$etc_config" "$python_root" "$mock_bin"
    cat > "$config/python3.14.conf" <<'EOF'
:python3.14:M::\x0e\x0d\x0d\x0a::/usr/bin/python3.14:
EOF
    cat > "$python_root/python3.14" <<'EOF'
#!/usr/bin/env bash
printf 'python3.14-ok\n' >> "$BINFMT_VERIFY_LOG"
EOF
    cat > "$mock_bin/python3" <<'EOF'
#!/usr/bin/env bash
printf 'python3-ok\n' >> "$BINFMT_VERIFY_LOG"
EOF
    cat > "$mock_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
[[ "${LC_ALL:-}" == C && "${1:-}" == check ]] || exit 64
printf 'apt-check-ok\n' >> "$BINFMT_VERIFY_LOG"
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$BINFMT_VERIFY_LOG"
EOF
    chmod +x "$python_root/python3.14" "$mock_bin/python3" "$mock_bin/apt-get" "$mock_bin/systemctl"
    printf 'enabled\n' > "$root/status"
    printf 'enabled\ninterpreter /usr/bin/python3.14\n' > "$root/python3.14"
    printf 'enabled\ninterpreter /usr/bin/qemu-aarch64-static\n' > "$root/qemu-aarch64"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_BINFMT_ROOT="$root" \
        HARDEN_BINFMT_CONFIG_DIRS="$etc_config:$config" HARDEN_BINFMT_ETC_DIR="$etc_config" \
        HARDEN_BINFMT_VENDOR_DIR="$config" HARDEN_BINFMT_PYTHON_ROOT="$python_root" \
        BINFMT_VERIFY_LOG="$case_root/python-verify.log" bash -c '
            source "$1/harden.sh"
            trap - ERR EXIT
            MODE=apply
            AGGRESSIVE=1
            BACKUP_DIR="$2/backup"
            CHANGE_LOG="$2/python.tsv"
            : > "$CHANGE_LOG"
            package_installed() { return 1; }
            dpkg-query() { return 1; }
            unit_file_exists() { return 1; }
            binfmt_unregister_entry() { rm -f -- "$1"; }
            transaction_copy() { :; }
            transaction_restore() { return 99; }
            configure_binfmt_misc
            [[ ! -e "$3/python3.14" ]]
            [[ -e "$3/qemu-aarch64" ]]
            [[ -L "$4/python3.14.conf" && "$(readlink -- "$4/python3.14.conf")" == /dev/null ]]
            grep -Fq "python3.14-ok" "$5"
            grep -Fq "python3-ok" "$5"
            grep -Fq "apt-check-ok" "$5"
            grep -Fq "systemctl daemon-reload" "$5"
            configure_binfmt_misc
            [[ "$(grep -c "Target-disabled reversible Python" "$CHANGE_LOG")" == 1 ]]
        ' _ "$repo_root" "$case_root" "$root" "$etc_config" "$case_root/python-verify.log" \
        || fail "targeted reversible python3.14 binfmt deactivation/validation failed"
    rm -f -- "$root/qemu-aarch64" "$config/python3.14.conf"
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

run_systemd_idempotency_tests() {
    env HARDEN_SOURCE_ONLY=1 bash -c '
        source "$1/harden.sh"
        trap - ERR EXIT
        [[ "$(classify_systemd_exposure 7.1 3.4 0)" == decreased ]]
        [[ "$(classify_systemd_exposure 3.4 3.4 1)" == unchanged ]]
        [[ "$(classify_systemd_exposure 3.4 3.4 0)" == not-decreased ]]
        [[ "$(classify_systemd_exposure 3.4 3.5 1)" == not-decreased ]]
    ' _ "$repo_root" || fail "systemd exposure idempotency classification failed"

    local case_root="$test_root/systemd-exposure"
    install -d "$case_root"
    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; BACKUP_DIR="$test_dir/backup"; CHANGE_LOG="$test_dir/changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR"; : > "$SYSTEMD_HARDENING_REPORT"; : > "$test_dir/commands"
        unit_file_exists() { return 0; }
        systemctl() { printf "%s " "$@" >> "$test_dir/commands"; printf "\n" >> "$test_dir/commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "is-failed --quiet") return 1 ;; cat*) printf "[Service]\nExecStart=/bin/true\n" ;; esac; return 0; }
        systemd_verify_unit() { return 0; }
        transaction_copy() { :; }; transaction_restore() { rm -f -- "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }
        run_streamed() { "$@"; }
        systemd_service_health_check() { return 0; }
        measure_service_exposure() { [[ "$2" == before ]] && SYSTEMD_EXPOSURE_RESULT=5.0 || SYSTEMD_EXPOSURE_RESULT=4.4; : > "$3"; }
        install_service_dropin fail2ban.service 99-hardening "test control" <<EOF
[Service]
PrivateMounts=yes
EOF
        [[ -f "$HARDEN_SYSTEMD_DIR/fail2ban.service.d/99-hardening.conf" ]] \
            && grep -Fq "restart fail2ban.service" "$test_dir/commands" \
            && grep -Fq "before-score=5.0" "$SYSTEMD_HARDENING_REPORT" \
            && grep -Fq "after-score=4.4" "$SYSTEMD_HARDENING_REPORT" \
            && grep -Fq "result=kept: measured exposure decrease" "$SYSTEMD_HARDENING_REPORT" \
            || exit 1
    ' _ "$repo_root" "$case_root" || fail "measurable systemd exposure improvement regression failed"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/no-gain-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/no-gain-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; BACKUP_DIR="$2/no-gain-backup"; CHANGE_LOG="$2/no-gain-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR"; : > "$SYSTEMD_HARDENING_REPORT"
        unit_file_exists() { return 0; }; systemctl() { case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "is-failed --quiet") return 1 ;; cat*) printf "[Service]\nExecStart=/bin/true\n" ;; esac; return 0; }
        systemd_verify_unit() { return 0; }; transaction_copy() { :; }; transaction_restore() { rm -f -- "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 0; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=5.0; : > "$3"; }
        install_service_dropin fail2ban.service 99-hardening "test control" <<EOF
[Service]
PrivateMounts=yes
EOF
        [[ ! -e "$HARDEN_SYSTEMD_DIR/fail2ban.service.d/99-hardening.conf" ]]
        grep -Fq "rolled back: score did not decrease" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "non-improving systemd sandbox was not rolled back"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/verify-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/verify-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; BACKUP_DIR="$2/verify-backup"; CHANGE_LOG="$2/verify-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR"; : > "$SYSTEMD_HARDENING_REPORT"
        unit_file_exists() { return 0; }; systemctl() { case "$1" in cat) printf "[Service]\nExecStart=/bin/true\n" ;; esac; return 0; }; systemd_verify_unit() { return 1; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=5.0; : > "$3"; }
        install_service_dropin fail2ban.service 99-hardening "test control" <<EOF
[Service]
PrivateMounts=yes
EOF
        [[ ! -e "$HARDEN_SYSTEMD_DIR/fail2ban.service.d/99-hardening.conf" ]]
        grep -Fq "candidate rejected before installation" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "invalid candidate systemd unit was installed"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/health-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/health-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; BACKUP_DIR="$2/health-backup"; CHANGE_LOG="$2/health-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR"; : > "$SYSTEMD_HARDENING_REPORT"
        unit_file_exists() { return 0; }; systemctl() { case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "is-failed --quiet") return 1 ;; cat*) printf "[Service]\nExecStart=/bin/true\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }; transaction_copy() { :; }; transaction_restore() { rm -f -- "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 1; }
        measure_service_exposure() { [[ "$2" == before ]] && SYSTEMD_EXPOSURE_RESULT=5.0 || SYSTEMD_EXPOSURE_RESULT=4.4; : > "$3"; }
        install_service_dropin fail2ban.service 99-hardening "test control" <<EOF
[Service]
PrivateMounts=yes
EOF
        [[ ! -e "$HARDEN_SYSTEMD_DIR/fail2ban.service.d/99-hardening.conf" ]]
        grep -Fq "health=failed" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "unhealthy systemd service did not roll back its drop-in"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/converged-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/converged-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; BACKUP_DIR="$test_dir/converged-backup"; CHANGE_LOG="$test_dir/converged-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/fail2ban.service.d"; : > "$SYSTEMD_HARDENING_REPORT"; : > "$test_dir/converged-commands"
        printf "[Service]\nPrivateMounts=yes\n" > "$HARDEN_SYSTEMD_DIR/fail2ban.service.d/99-hardening.conf"
        unit_file_exists() { return 0; }; systemctl() { printf "%s " "$@" >> "$test_dir/converged-commands"; printf "\n" >> "$test_dir/converged-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; cat*) printf "[Service]\nExecStart=/bin/true\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 0; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=4.4; : > "$3"; }
        install_service_dropin fail2ban.service 99-hardening "test control" <<EOF
[Service]
PrivateMounts=yes
EOF
        ! grep -Eq "daemon-reload|restart fail2ban.service" "$test_dir/converged-commands"
        grep -Fq "already hardened/unchanged" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "converged systemd drop-in caused a restart or rewrite"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/early-ssh-systemd" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/early-ssh-backup"; CHANGE_LOG="$test_dir/early-ssh-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$test_dir/early-ssh-commands"; REBOOT_REQUIRED=0
        printf "[Service]\\nPrivateTmp=yes\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        systemctl() { printf "%s " "$@" >> "$test_dir/early-ssh-commands"; printf "\\n" >> "$test_dir/early-ssh-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "show ssh.service") printf "yes\\n" ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }
        transaction_copy() { cp -- "$1" "$test_dir/early-ssh-original"; }; transaction_restore() { cp -- "$test_dir/early-ssh-original" "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }
        migrate_legacy_ssh_private_tmp_early
        grep -Fxq "UMask=0027" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        ! grep -Fq "PrivateTmp" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        grep -Fq "reload ssh.service" "$test_dir/early-ssh-commands"
        ! grep -Fq "restart ssh.service" "$test_dir/early-ssh-commands"
        [[ "$SSH_SYSTEMD_EARLY_MIGRATED" -eq 1 && "$SSH_SYSTEMD_LEGACY_RUNTIME" -eq 1 && "$REBOOT_REQUIRED" -eq 1 ]]
        [[ "$SSH_SYSTEMD_SAFETY_STATUS" == "MIGRATED/PENDING REBOOT"* ]]
    ' _ "$repo_root" "$case_root" || fail "early legacy SSH migration/reboot convergence regression failed"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/early-ssh-current-systemd" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/early-ssh-current-backup"; CHANGE_LOG="$test_dir/early-ssh-current-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$test_dir/early-ssh-current-commands"; REBOOT_REQUIRED=0
        printf "[Service]\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        systemctl() { printf "%s " "$@" >> "$test_dir/early-ssh-current-commands"; printf "\\n" >> "$test_dir/early-ssh-current-commands"; return 0; }
        migrate_legacy_ssh_private_tmp_early
        [[ "$SSH_SYSTEMD_SAFETY_STATUS" == "OK (already UMask-only; no reload required)" ]]
        [[ ! -s "$test_dir/early-ssh-current-commands" && "$REBOOT_REQUIRED" -eq 0 ]]
    ' _ "$repo_root" "$case_root" || fail "fresh UMask-only SSH state performed an unnecessary reload"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/early-ssh-reload-failure-systemd" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/early-ssh-reload-failure-backup"; CHANGE_LOG="$test_dir/early-ssh-reload-failure-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$test_dir/early-ssh-reload-failure-commands"
        printf "[Service]\\nPrivateTmp=yes\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        systemctl() { printf "%s " "$@" >> "$test_dir/early-ssh-reload-failure-commands"; printf "\\n" >> "$test_dir/early-ssh-reload-failure-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "show ssh.service") printf "yes\\n" ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; "reload ssh.service") return 1 ;; esac; return 0; }; systemd_verify_unit() { return 0; }
        transaction_copy() { cp -- "$1" "$test_dir/early-ssh-reload-failure-original"; }; transaction_restore() { cp -- "$test_dir/early-ssh-reload-failure-original" "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }
        ! migrate_legacy_ssh_private_tmp_early
        grep -Fq "PrivateTmp=yes" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        ! grep -Fq "restart ssh.service" "$test_dir/early-ssh-reload-failure-commands"
        [[ "$SSH_SYSTEMD_SAFETY_STATUS" == FAILED/ROLLED\ BACK* ]]
    ' _ "$repo_root" "$case_root" || fail "early SSH reload failure did not roll back without restart"

    cat > "$case_root/sshd-second-check-fails" <<'EOF'
#!/usr/bin/env bash
count="$(cat "$SSH_TEST_CHECK_COUNT" 2>/dev/null || printf 0)"
count=$((count + 1))
printf '%s\n' "$count" > "$SSH_TEST_CHECK_COUNT"
[[ "$count" -ne 2 ]]
EOF
    chmod +x "$case_root/sshd-second-check-fails"
    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/early-ssh-sshd-failure-systemd" SSH_TEST_CHECK_COUNT="$case_root/sshd-check-count" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN="$test_dir/sshd-second-check-fails"; BACKUP_DIR="$test_dir/early-ssh-sshd-failure-backup"; CHANGE_LOG="$test_dir/early-ssh-sshd-failure-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$test_dir/early-ssh-sshd-failure-commands"
        printf "[Service]\\nPrivateTmp=yes\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        systemctl() { printf "%s " "$@" >> "$test_dir/early-ssh-sshd-failure-commands"; printf "\\n" >> "$test_dir/early-ssh-sshd-failure-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "show ssh.service") printf "yes\\n" ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }
        transaction_copy() { cp -- "$1" "$test_dir/early-ssh-sshd-failure-original"; }; transaction_restore() { cp -- "$test_dir/early-ssh-sshd-failure-original" "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }
        ! migrate_legacy_ssh_private_tmp_early
        grep -Fq "PrivateTmp=yes" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        ! grep -Fq "restart ssh.service" "$test_dir/early-ssh-sshd-failure-commands"
        [[ "$SSH_SYSTEMD_SAFETY_STATUS" == FAILED/ROLLED\ BACK* ]]
    ' _ "$repo_root" "$case_root" || fail "early SSH sshd -t failure did not roll back safely"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/ssh-migration-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/ssh-migration-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/ssh-migration-backup"; CHANGE_LOG="$test_dir/ssh-migration-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$SYSTEMD_HARDENING_REPORT"; : > "$test_dir/ssh-migration-commands"
        printf "[Service]\\nPrivateTmp=yes\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        unit_file_exists() { return 0; }; systemctl() { printf "%s " "$@" >> "$test_dir/ssh-migration-commands"; printf "\\n" >> "$test_dir/ssh-migration-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "is-failed --quiet") return 1 ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }
        transaction_copy() { cp -- "$1" "$test_dir/ssh-migration-original"; }; transaction_restore() { cp -- "$test_dir/ssh-migration-original" "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 0; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=9.2; : > "$3"; }
        install_service_dropin ssh.service 99-hardening "SSH safety migration" <<EOF
[Service]
UMask=0027
EOF
        grep -Fxq "UMask=0027" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        ! grep -Fq "PrivateTmp" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        grep -Fq "reload ssh.service" "$test_dir/ssh-migration-commands"
        ! grep -Fq "restart ssh.service" "$test_dir/ssh-migration-commands"
        grep -Fq "SSH safety migration: PrivateTmp removed" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "SSH PrivateTmp migration did not retain the UMask-only safety exception"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/ssh-rollback-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/ssh-rollback-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/ssh-rollback-backup"; CHANGE_LOG="$test_dir/ssh-rollback-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$SYSTEMD_HARDENING_REPORT"; : > "$test_dir/ssh-rollback-commands"
        printf "[Service]\\nPrivateTmp=yes\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        unit_file_exists() { return 0; }; systemctl() { printf "%s " "$@" >> "$test_dir/ssh-rollback-commands"; printf "\\n" >> "$test_dir/ssh-rollback-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; "is-failed --quiet") return 1 ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }
        transaction_copy() { cp -- "$1" "$test_dir/ssh-rollback-original"; }; transaction_restore() { cp -- "$test_dir/ssh-rollback-original" "$1"; }
        install_managed_file() { local destination="$1" mode="$2"; mkdir -p -- "$(dirname -- "$destination")"; cat > "$destination"; chmod "$mode" "$destination"; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 1; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=9.2; : > "$3"; }
        install_service_dropin ssh.service 99-hardening "SSH safety migration" <<EOF
[Service]
UMask=0027
EOF
        grep -Fq "PrivateTmp=yes" "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        grep -Fq "reload ssh.service" "$test_dir/ssh-rollback-commands"
        ! grep -Fq "restart ssh.service" "$test_dir/ssh-rollback-commands"
        grep -Fq "health=failed" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "SSH migration health rollback restarted SSH or lost the prior drop-in"

    env HARDEN_SOURCE_ONLY=1 HARDEN_SYSTEMD_DIR="$case_root/ssh-converged-systemd" HARDEN_SYSTEMD_HARDENING_REPORT="$case_root/ssh-converged-report" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        test_dir="$2"; MODE=apply; SSH_SERVICE=ssh.service; SSHD_BIN=/bin/true; BACKUP_DIR="$test_dir/ssh-converged-backup"; CHANGE_LOG="$test_dir/ssh-converged-changes"; : > "$CHANGE_LOG"; mkdir -p "$BACKUP_DIR" "$HARDEN_SYSTEMD_DIR/ssh.service.d"; : > "$SYSTEMD_HARDENING_REPORT"; : > "$test_dir/ssh-converged-commands"
        printf "[Service]\\nUMask=0027\\n" > "$HARDEN_SYSTEMD_DIR/ssh.service.d/99-hardening.conf"
        unit_file_exists() { return 0; }; systemctl() { printf "%s " "$@" >> "$test_dir/ssh-converged-commands"; printf "\\n" >> "$test_dir/ssh-converged-commands"; case "${1:-} ${2:-}" in "is-active --quiet") return 0 ;; cat*) printf "[Service]\\nExecStart=/bin/true\\n" ;; esac; return 0; }; systemd_verify_unit() { return 0; }; run_streamed() { "$@"; }; systemd_service_health_check() { return 0; }
        measure_service_exposure() { SYSTEMD_EXPOSURE_RESULT=9.2; : > "$3"; }
        install_service_dropin ssh.service 99-hardening "SSH safety migration" <<EOF
[Service]
UMask=0027
EOF
        ! grep -Eq "daemon-reload|reload ssh.service|restart ssh.service" "$test_dir/ssh-converged-commands"
        grep -Fq "already hardened/unchanged" "$SYSTEMD_HARDENING_REPORT"
    ' _ "$repo_root" "$case_root" || fail "converged SSH UMask-only drop-in caused a reload or restart"

    env HARDEN_SOURCE_ONLY=1 bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        SSH_SERVICE=ssh.service
        [[ "$(systemd_service_classification ssh.service)" == "safety exception:"* ]]
        [[ "$(systemd_service_classification tailscaled.service)" == excluded:* ]]
        [[ "$(systemd_service_classification networkd-dispatcher.service)" == candidate:* ]]
        section="$(sed -n "/^harden_systemd_services()/,/^}/p" "$1/harden.sh")"
        ! grep -Eq "install_service_dropin (tailscaled|dbus|cron|auditd|open-vm-tools|snapd|systemd-|polkit|cloud-init)" <<<"$section"
        ssh_block="$(sed -n "/install_service_dropin \"\$SSH_SERVICE\"/,/EOF/p" "$1/harden.sh")"
        ! grep -Fq "PrivateTmp=yes" <<<"$ssh_block"; grep -Fxq "UMask=0027" <<<"$ssh_block"
        systemctl() { [[ "$1 $2" == "is-active --quiet" ]]; }
        SSHD_BIN=/bin/true; systemd_service_health_check ssh.service
        SSHD_BIN=/bin/false; ! systemd_service_health_check ssh.service
    ' _ "$repo_root" || fail "protected service or SSH preservation regression failed"
}

run_runtime_noop_tests() {
    local case_root="$test_root/runtime-noop"
    local mock_bin="$case_root/bin"
    local command_log="$case_root/commands.log"
    install -d "$mock_bin" "$case_root/grub" "$case_root/default" "$case_root/rkhunter-db"
    : > "$command_log"
    cat > "$mock_bin/getent" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == shadow && "${2:-}" == alice ]]; then
    printf 'alice:$6$hash:20000:%s:%s:%s:%s::\n' \
        "${AGING_MIN:-1}" "${AGING_MAX:-90}" "${AGING_WARN:-14}" "${AGING_INACTIVE:-30}"
else
    command /usr/bin/getent "$@"
fi
EOF
    cat > "$mock_bin/chage" <<'EOF'
#!/usr/bin/env bash
printf 'chage %s\n' "$*" >> "$NOOP_COMMAND_LOG"
EOF
    cat > "$mock_bin/findmnt" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "$mock_bin/mountpoint" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    is-enabled) printf '%s\n' "${NOOP_ENABLED_STATE:-masked}" ;;
    is-active) printf '%s\n' "${NOOP_ACTIVE_STATE:-inactive}"; [[ "${NOOP_ACTIVE_STATE:-inactive}" == active ]] ;;
    show) printf '%s\n' "${NOOP_LOAD_STATE:-masked}" ;;
    disable|mask) printf 'unexpected-systemctl %s\n' "$*" >> "$NOOP_COMMAND_LOG"; exit 91 ;;
    *) printf 'systemctl %s\n' "$*" >> "$NOOP_COMMAND_LOG" ;;
esac
EOF
    cat > "$mock_bin/update-grub" <<'EOF'
#!/usr/bin/env bash
printf 'update-grub\n' >> "$NOOP_COMMAND_LOG"
EOF
    cat > "$mock_bin/rkhunter" <<'EOF'
#!/usr/bin/env bash
printf 'rkhunter %s\n' "$*" >> "$NOOP_COMMAND_LOG"
EOF
    chmod +x "$mock_bin"/*
    cat > "$case_root/passwd" <<'EOF'
alice:x:1000:1000:Alice:/home/alice:/bin/bash
EOF
    printf 'UID_MIN 1000\n' > "$case_root/login.defs"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PASSWD_FILE="$case_root/passwd" \
        HARDEN_LOGIN_DEFS="$case_root/login.defs" NOOP_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply
            CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            configure_account_aging
            ! grep -Fq "chage " "$3"
            AGING_MAX=30 configure_account_aging
            [[ "$(grep -Fc "chage " "$3")" == 1 ]]
        ' _ "$repo_root" "$case_root" "$command_log" || fail "account-aging no-op/delta regression failed"

    printf '/dev/sda2 /boot ext4 defaults,nodev,nosuid,noexec 0 2\n' > "$case_root/fstab"
    : > "$command_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_FSTAB="$case_root/fstab" \
        NOOP_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply
            CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            install() { command cp -- "${@: -2:1}" "${@: -1}"; }
            merge_mount_options /boot nodev,nosuid,noexec
            [[ ! -s "$3" ]]
            printf "/dev/sda2 /boot ext4 defaults,nodev,nosuid 0 2\n" > "$4"
            merge_mount_options /boot nodev,nosuid,noexec
            [[ "$(grep -Fc "systemctl daemon-reload" "$3")" == 1 ]]
            grep -Eq "defaults,nodev,nosuid,noexec|defaults,nosuid,nodev,noexec" "$4"
            merge_mount_options /boot nodev,nosuid,noexec
            [[ "$(grep -Fc "systemctl daemon-reload" "$3")" == 1 ]]
        ' _ "$repo_root" "$case_root" "$command_log" "$case_root/fstab" \
        || fail "fstab /boot no-op and change-triggered daemon-reload regression failed"

    printf 'generated\n' > "$case_root/grub/grub.cfg"
    : > "$command_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_GRUB_DIR="$case_root/grub" \
        HARDEN_GRUB_POLICY="$case_root/default/99-security-hardening.cfg" \
        HARDEN_GRUB_LEGACY_AUTH="$case_root/no-legacy-auth" NOOP_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply
            BACKUP_DIR="$2/backup"; install -d "$BACKUP_DIR"
            CHANGE_LOG="$2/grub-changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }
            transaction_restore() { :; }
            install_managed_file() {
                local target="$1" temporary
                MANAGED_FILE_CHANGED=0
                temporary="$(mktemp)"; cat > "$temporary"
                if [[ -f "$target" ]] && cmp -s "$temporary" "$target"; then rm -f "$temporary"; return 0; fi
                command mkdir -p "$(dirname "$target")"; command cp "$temporary" "$target"; rm -f "$temporary"
                MANAGED_FILE_CHANGED=1
            }
            configure_bootloader
            [[ "$(grep -Fc update-grub "$3")" == 1 ]]
            [[ "$REBOOT_REQUIRED" == 1 ]]
            REBOOT_REQUIRED=0
            configure_bootloader
            [[ "$(grep -Fc update-grub "$3")" == 1 ]]
            [[ "$REBOOT_REQUIRED" == 0 ]]
        ' _ "$repo_root" "$case_root" "$command_log" || fail "GRUB no-op/update and reboot-required regression failed"

    cat > "$case_root/default/rkhunter" <<'EOF'
CRON_DAILY_RUN="true"
CRON_DB_UPDATE="true"
APT_AUTOGEN="true"
EOF
    printf 'package-state\n' > "$case_root/dpkg-status"
    printf 'properties\n' > "$case_root/rkhunter-db/rkhunter.dat"
    touch -t 202601010100 "$case_root/dpkg-status"
    touch -t 202601010200 "$case_root/rkhunter-db/rkhunter.dat"
    : > "$command_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_RKHUNTER_DEFAULTS="$case_root/default/rkhunter" \
        HARDEN_RKHUNTER_PROPERTY_DB="$case_root/rkhunter-db/rkhunter.dat" \
        HARDEN_RKHUNTER_PENDING_MARKER="$case_root/rkhunter-db/pending" \
        HARDEN_DPKG_STATUS="$case_root/dpkg-status" NOOP_COMMAND_LOG="$command_log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply
            CHANGE_LOG="$2/rkhunter-changes.tsv"; : > "$CHANGE_LOG"
            install() { command cp -- "${@: -2:1}" "${@: -1}"; }
            configure_malware_scanner
            ! grep -Fq "rkhunter --propupd" "$3"
            sed -i "s/CRON_DB_UPDATE=\"true\"/CRON_DB_UPDATE=\"false\"/" "$4"
            configure_malware_scanner
            [[ "$(grep -Fc "rkhunter --propupd" "$3")" == 1 ]]
            configure_malware_scanner
            [[ "$(grep -Fc "rkhunter --propupd" "$3")" == 1 ]]
        ' _ "$repo_root" "$case_root" "$command_log" "$case_root/default/rkhunter" \
        || fail "rkhunter property-baseline no-op regression failed"

    : > "$command_log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 NOOP_COMMAND_LOG="$command_log" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply
        unit_file_exists() { return 0; }
        disable_service packagekit.service 1
        [[ ! -s "$2" ]]
        [[ "${SERVICES_DISABLED[*]}" == *packagekit.service* ]]
        [[ "${SERVICES_MASKED[*]}" == *packagekit.service* ]]
    ' _ "$repo_root" "$command_log" || fail "already-disabled/masked service no-op regression failed"

    env HARDEN_SOURCE_ONLY=1 bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        kernel_section="$(sed -n "/^configure_kernel_modules()/,/^}/p" "$1/harden.sh")"
        grub_section="$(sed -n "/^configure_bootloader()/,/^}/p" "$1/harden.sh")"
        grep -Fq "INITRAMFS_POLICY_CHANGED" <<<"$kernel_section"
        grep -Fq "Managed module policy is unchanged" <<<"$kernel_section"
        grep -Fq "grub_config_changed" <<<"$grub_section"
        upgrade_section="$(sed -n "/^upgrade_packages_safely()/,/^}/p" "$1/harden.sh")"
        grep -Fq "reboot_marker=\"\${HARDEN_REBOOT_REQUIRED_FILE:-/var/run/reboot-required}\"" <<<"$upgrade_section"
        grep -Fq "PACKAGE_UPGRADE_STATUS=\"OK (upgraded; reboot required)\"" <<<"$upgrade_section"
        [[ "$(grep -Fc "REBOOT_REQUIRED=1" "$1/harden.sh")" == 7 ]]
    ' _ "$repo_root" || fail "initramfs/GRUB/reboot-required change gating regressed"
}

run_login_timeout_tests() {
    local case_root="$test_root/login-timeout"
    local mock_bin="$case_root/bin"
    install -d "$mock_bin" "$case_root/profile.d" "$case_root/log"
    cat > "$mock_bin/getent" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == group && "${2:-}" == utmp ]] && { printf 'utmp:x:43:\n'; exit 0; }
exit 2
EOF
    cat > "$mock_bin/lastb" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == -f && -f "${2:-}" ]]
EOF
    cat > "$mock_bin/faillog" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == -a ]]
EOF
    cat > "$mock_bin/journalctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == is-active && "${2:-}" == --quiet && "${3:-}" == systemd-journald.service ]]; then
    [[ "${LOGIN_TEST_JOURNALD_ACTIVE:-1}" == 1 ]]
    exit
fi
exit 1
EOF
    cat > "$mock_bin/sshd" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == -T ]] || exit 1
printf 'loglevel %s\n' "${LOGIN_TEST_LOGLEVEL:-VERBOSE}"
printf 'syslogfacility %s\n' "${LOGIN_TEST_SYSLOG_FACILITY:-AUTHPRIV}"
EOF
    cat > "$mock_bin/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat > "$mock_bin/stat" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -c && "${2:-}" == '%U:%G' && "${3:-}" == *btmp ]]; then printf 'root:utmp\n'; exit 0; fi
if [[ "${1:-}" == -c && "${2:-}" == '%a' && "${3:-}" == *btmp ]]; then printf '660\n'; exit 0; fi
exec /usr/bin/stat "$@"
EOF
    cat > "$mock_bin/install" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
mode="" directory=0
while (($#)); do
    case "$1" in
        -d) directory=1; shift ;;
        -m) mode="$2"; shift 2 ;;
        -o|-g) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
if ((directory)); then
    mkdir -p -- "$@"
    [[ -z "$mode" ]] || chmod "$mode" "$@"
else
    [[ $# -eq 2 ]] || exit 64
    cp -- "$1" "$2"
    [[ -z "$mode" ]] || chmod "$mode" "$2"
fi
EOF
    chmod +x "$mock_bin/getent" "$mock_bin/lastb" "$mock_bin/faillog" "$mock_bin/journalctl" "$mock_bin/systemctl" "$mock_bin/sshd" "$mock_bin/chown" "$mock_bin/stat" "$mock_bin/install"

    printf 'PASS_MAX_DAYS 90\nFAILLOG_ENAB yes\n# FTMP_FILE /wrong/path\n' > "$case_root/login.defs"
    printf 'existing failed-login record\n' > "$case_root/log/btmp"
    : > "$case_root/log/faillog"
    chmod 0660 "$case_root/log/btmp"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$case_root/login.defs" \
        HARDEN_BTMP_PATH="$case_root/log/btmp" HARDEN_FAILLOG_PATH="$case_root/log/faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/failed-login-report.txt" HARDEN_SHELL_TIMEOUT_PROFILE="$case_root/profile.d/99-security-shell-timeout.sh" \
        bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; BACKUP_DIR="$2/backup"; mkdir -p "$BACKUP_DIR"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            log() { :; }; record_change() { :; }; record_skip() { :; }
            original_btmp_hash="$(sha256sum "$HARDEN_BTMP_PATH")"
            configure_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == OK* ]]
            [[ "$FAILED_LOGIN_SHADOW_STATUS" == OK* && "$FAILED_LOGIN_BTMP_STATUS" == OK* && "$FAILED_LOGIN_FTMP_STATUS" == OK* ]]
            grep -Fxq "existing failed-login record" "$HARDEN_BTMP_PATH"
            grep -Fq "Lynis/shadow indicator:" "$HARDEN_FAILED_LOGIN_REPORT"
            grep -Fq "legacy btmp/lastb history:" "$HARDEN_FAILED_LOGIN_REPORT"
            grep -Fq "FTMP_FILE $HARDEN_BTMP_PATH" "$HARDEN_LOGIN_DEFS"
            grep -Fq "exists=yes" "$BACKUP_DIR/failed-login-btmp-metadata-before.txt"
            grep -Fq "content-rollback=never" "$BACKUP_DIR/failed-login-btmp-metadata-before.txt"
            [[ "$original_btmp_hash" == "$(sha256sum "$HARDEN_BTMP_PATH")" ]]
            configure_interactive_shell_timeout
            [[ "$SHELL_TIMEOUT_STATUS" == "OK (interactive default 900s; override preserved)" ]]
            before_login="$(sha256sum "$HARDEN_LOGIN_DEFS")"; before_profile="$(sha256sum "$HARDEN_SHELL_TIMEOUT_PROFILE")"
            configure_failed_login_logging; configure_interactive_shell_timeout
            [[ "$before_login" == "$(sha256sum "$HARDEN_LOGIN_DEFS")" ]]
            [[ "$before_profile" == "$(sha256sum "$HARDEN_SHELL_TIMEOUT_PROFILE")" ]]
        ' _ "$repo_root" "$case_root" || fail "failed-login logging or interactive timeout did not converge"
    grep -Fq 'FAILLOG_ENAB yes' "$case_root/login.defs" || fail "failed-login logging was not persisted in login.defs"
    grep -Fq 'FTMP_FILE '"$case_root/log/btmp" "$case_root/login.defs" || fail "existing FTMP_FILE was not set distro-conformantly"
    grep -Fq 'case "$-" in' "$case_root/profile.d/99-security-shell-timeout.sh" \
        || fail "timeout profile is not limited to interactive shells"
    ! grep -Fq 'transaction_copy "$btmp_path"' "$repo_root/harden.sh" \
        || fail "btmp content was added to transaction backup"
    ! sed -n '/backup_config()/,/^}/p' "$repo_root/harden.sh" | grep -Fq '/var/log/btmp' \
        || fail "btmp content was added to config backup"

    local broken_btmp="$case_root/broken-btmp"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$case_root/login.defs" \
        HARDEN_BTMP_PATH="$broken_btmp" HARDEN_FAILLOG_PATH="$case_root/log/faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/broken-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            validate_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == FAILED* && "$FAILED_LOGIN_BTMP_STATUS" == FAILED* ]]
        ' _ "$repo_root" || fail "FAILLOG_ENAB alone incorrectly validated unusable btmp"
    printf 'FAILLOG_ENAB no\n' > "$case_root/no-faillog-login.defs"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$case_root/no-faillog-login.defs" \
        HARDEN_BTMP_PATH="$case_root/log/btmp" HARDEN_FAILLOG_PATH="$case_root/log/faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/no-faillog-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            validate_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == FAILED* && "$FAILED_LOGIN_SHADOW_STATUS" == FAILED* ]]
        ' _ "$repo_root" || fail "usable btmp incorrectly validated missing FAILLOG_ENAB"

    local modern_login="$case_root/modern-login.defs"
    printf 'FAILLOG_ENAB yes\n' > "$modern_login"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$modern_login" \
        HARDEN_BTMP_PATH="$case_root/absent-modern-btmp" HARDEN_FAILLOG_PATH="$case_root/absent-faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/modern-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            failed_login_lastb_available() { return 1; }
            validate_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == OK* ]]
            [[ "$FAILED_LOGIN_BTMP_STATUS" == "N/A (lastb removed/unavailable; journal/syslog path used)" ]]
            [[ "$FAILED_LOGIN_MODERN_STATUS" == OK* ]]
            [[ "$FAILED_LOGIN_FAILLOG_STATUS" == "N/A (tool/path unavailable)" ]]
            [[ "$FAILED_LOGIN_FTMP_STATUS" == "N/A (FTMP_FILE unsupported by this login.defs)" ]]
            grep -Fq "modern journal/syslog SSH auth path: OK" "$HARDEN_FAILED_LOGIN_REPORT"
        ' _ "$repo_root" || fail "modern no-lastb journal/syslog path was not accepted"
    env PATH="$mock_bin:$PATH" LOGIN_TEST_JOURNALD_ACTIVE=0 HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$modern_login" \
        HARDEN_BTMP_PATH="$case_root/absent-modern-btmp" HARDEN_FAILLOG_PATH="$case_root/absent-faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/no-journal-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            failed_login_lastb_available() { return 1; }
            validate_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == FAILED* && "$FAILED_LOGIN_MODERN_STATUS" == FAILED* ]]
        ' _ "$repo_root" || fail "modern no-lastb host accepted an inactive journald path"
    env PATH="$mock_bin:$PATH" LOGIN_TEST_LOGLEVEL=ERROR HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$modern_login" \
        HARDEN_BTMP_PATH="$case_root/absent-modern-btmp" HARDEN_FAILLOG_PATH="$case_root/absent-faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/restrictive-sshd-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            failed_login_lastb_available() { return 1; }
            validate_failed_login_logging
            [[ "$FAILED_LOGIN_STATUS" == FAILED* && "$FAILED_LOGIN_MODERN_STATUS" == *"LogLevel=error"* ]]
        ' _ "$repo_root" || fail "restrictive SSH LogLevel was accepted for modern failed-login logging"
    printf 'new audit record after metadata capture\n' >> "$case_root/log/btmp"
    grep -Fq 'existing failed-login record' "$case_root/log/btmp" \
        && grep -Fq 'new audit record after metadata capture' "$case_root/log/btmp" \
        || fail "metadata-only capture/no-content-rollback handling lost btmp audit data"

    local missing="$case_root/missing-btmp"
    rm -f -- "$missing"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$case_root/login.defs" \
        HARDEN_BTMP_PATH="$missing" HARDEN_FAILLOG_PATH="$case_root/log/faillog" \
        HARDEN_FAILED_LOGIN_REPORT="$case_root/missing-report.txt" HARDEN_SHELL_TIMEOUT_PROFILE="$case_root/profile.d/99-security-shell-timeout.sh" \
        bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; BACKUP_DIR="$2/backup"; mkdir -p "$BACKUP_DIR"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            log() { :; }; record_change() { :; }; record_skip() { :; }; transaction_copy() { :; }
            configure_failed_login_logging
            [[ -f "$HARDEN_BTMP_PATH" && "$(stat -c "%a" "$HARDEN_BTMP_PATH")" == 660 ]]
        ' _ "$repo_root" "$case_root" || fail "missing btmp was not safely created"

    local dry_login="$case_root/dry-login.defs" dry_btmp="$case_root/dry-btmp" dry_profile="$case_root/dry-profile.sh"
    printf 'FAILLOG_ENAB no\n' > "$dry_login"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_LOGIN_DEFS="$dry_login" HARDEN_BTMP_PATH="$dry_btmp" \
        HARDEN_SHELL_TIMEOUT_PROFILE="$dry_profile" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=dry-run; log() { :; }; record_change() { :; }; record_skip() { :; }
            configure_failed_login_logging; configure_interactive_shell_timeout
            [[ "$FAILED_LOGIN_STATUS" == "N/A (dry-run)" && "$SHELL_TIMEOUT_STATUS" == "N/A (dry-run)" ]]
        ' _ "$repo_root" || fail "login timeout dry-run failed"
    grep -Fxq 'FAILLOG_ENAB no' "$dry_login" || fail "failed-login dry-run wrote login.defs"
    [[ ! -e "$dry_btmp" && ! -e "$dry_profile" ]] || fail "login timeout dry-run wrote managed state"
}

run_uefi_mor_tests() {
    local case_root="$test_root/uefi-mor"
    install -d "$case_root"
    run_mor_case() {
        local name="$1" expected="$2" efi_dir vars_dir
        efi_dir="$case_root/$name/efi"
        vars_dir="$case_root/$name/efivars"
        install -d "$(dirname -- "$efi_dir")"
        env HARDEN_SOURCE_ONLY=1 HARDEN_EFI_SYSFS="$efi_dir" HARDEN_EFIVARS_DIR="$vars_dir" \
            HARDEN_EFIVARS_FSTYPE=efivarfs HARDEN_UEFI_MOR_REPORT="$case_root/$name/report.txt" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
                inspect_uefi_mor
                [[ "$UEFI_MOR_STATUS" == "$2"* ]]
                grep -Fq "write-behavior=detection-only" "$HARDEN_UEFI_MOR_REPORT"
            ' _ "$repo_root" "$expected" || fail "UEFI MOR ${name} classification failed"
    }

    run_mor_case legacy-bios 'NOT_APPLICABLE (no UEFI runtime)'
    install -d "$case_root/uefi-no-efivarfs/efi"
    env HARDEN_SOURCE_ONLY=1 HARDEN_EFI_SYSFS="$case_root/uefi-no-efivarfs/efi" \
        HARDEN_EFIVARS_DIR="$case_root/uefi-no-efivarfs/efivars" HARDEN_EFIVARS_FSTYPE=tmpfs \
        HARDEN_UEFI_MOR_REPORT="$case_root/uefi-no-efivarfs/report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            inspect_uefi_mor
            [[ "$UEFI_MOR_STATUS" == "FAILED-TO-INSPECT (UEFI runtime variable access unavailable)" ]]
            grep -Fq "MOR support cannot be determined" "$HARDEN_UEFI_MOR_REPORT"
        ' _ "$repo_root" || fail "UEFI without efivarfs was not classified as unavailable runtime access"

    install -d "$case_root/mor-absent/efi" "$case_root/mor-absent/efivars"
    run_mor_case mor-absent 'UNSUPPORTED (firmware does not expose MOR variables)'

    local mor_name='MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829'
    local lock_name='MemoryOverwriteRequestControlLock-bb983ccf-151d-40e1-a07b-4a17be168292'
    install -d "$case_root/mor-inactive/efi" "$case_root/mor-inactive/efivars"
    printf '\007\000\000\000\000' > "$case_root/mor-inactive/efivars/$mor_name"
    run_mor_case mor-inactive 'SUPPORTED_INACTIVE (MOR=0; lock=absent)'
    grep -Fxq 'mor-attributes=0x00000007' "$case_root/mor-inactive/report.txt" \
        || fail "valid MOR control attributes were not reported"
    install -d "$case_root/mor-active/efi" "$case_root/mor-active/efivars"
    printf '\007\000\000\000\001' > "$case_root/mor-active/efivars/$mor_name"
    run_mor_case mor-active 'SUPPORTED_ACTIVE (MOR=1; lock=absent)'
    install -d "$case_root/mor-inactive-autodetect-disabled/efi" "$case_root/mor-inactive-autodetect-disabled/efivars"
    printf '\007\000\000\000\020' > "$case_root/mor-inactive-autodetect-disabled/efivars/$mor_name"
    run_mor_case mor-inactive-autodetect-disabled 'SUPPORTED_INACTIVE (MOR=16; lock=absent)'
    install -d "$case_root/mor-active-autodetect-disabled/efi" "$case_root/mor-active-autodetect-disabled/efivars"
    printf '\007\000\000\000\021' > "$case_root/mor-active-autodetect-disabled/efivars/$mor_name"
    run_mor_case mor-active-autodetect-disabled 'SUPPORTED_ACTIVE (MOR=17; lock=absent)'
    install -d "$case_root/mor-locked/efi" "$case_root/mor-locked/efivars"
    printf '\007\000\000\000\001' > "$case_root/mor-locked/efivars/$mor_name"
    printf '\007\000\000\000\001' > "$case_root/mor-locked/efivars/$lock_name"
    run_mor_case mor-locked 'LOCKED/firmware-controlled (MOR=1; lock=1)'
    grep -Fxq 'mor-lock-attributes=0x00000007' "$case_root/mor-locked/report.txt" \
        || fail "valid MOR lock attributes were not reported"
    install -d "$case_root/mor-malformed/efi" "$case_root/mor-malformed/efivars"
    printf '\007\000\000\000' > "$case_root/mor-malformed/efivars/$mor_name"
    run_mor_case mor-malformed 'FAILED-TO-INSPECT (malformed or unreadable MOR control attributes)'
    install -d "$case_root/mor-invalid-control-attributes/efi" "$case_root/mor-invalid-control-attributes/efivars"
    printf '\006\000\000\000\001' > "$case_root/mor-invalid-control-attributes/efivars/$mor_name"
    run_mor_case mor-invalid-control-attributes 'FAILED-TO-INSPECT (unexpected MOR control attributes 0x00000006)'
    install -d "$case_root/mor-invalid-lock-attributes/efi" "$case_root/mor-invalid-lock-attributes/efivars"
    printf '\007\000\000\000\000' > "$case_root/mor-invalid-lock-attributes/efivars/$mor_name"
    printf '\006\000\000\000\001' > "$case_root/mor-invalid-lock-attributes/efivars/$lock_name"
    run_mor_case mor-invalid-lock-attributes 'FAILED-TO-INSPECT (unexpected MOR lock attributes 0x00000006)'
    install -d "$case_root/mor-reserved-bits/efi" "$case_root/mor-reserved-bits/efivars"
    printf '\007\000\000\000\002' > "$case_root/mor-reserved-bits/efivars/$mor_name"
    run_mor_case mor-reserved-bits 'FAILED-TO-INSPECT (MOR control uses reserved bits)'
    install -d "$case_root/mor-invalid-lock/efi" "$case_root/mor-invalid-lock/efivars"
    printf '\007\000\000\000\000' > "$case_root/mor-invalid-lock/efivars/$mor_name"
    printf '\007\000\000\000\003' > "$case_root/mor-invalid-lock/efivars/$lock_name"
    run_mor_case mor-invalid-lock 'FAILED-TO-INSPECT (MOR lock has an unknown value)'
    install -d "$case_root/mor-unreadable/efi" "$case_root/mor-unreadable/efivars"
    printf '\007\000\000\000\001' > "$case_root/mor-unreadable/efivars/$mor_name"
    env HARDEN_SOURCE_ONLY=1 HARDEN_EFI_SYSFS="$case_root/mor-unreadable/efi" \
        HARDEN_EFIVARS_DIR="$case_root/mor-unreadable/efivars" HARDEN_EFIVARS_FSTYPE=efivarfs \
        HARDEN_UEFI_MOR_REPORT="$case_root/mor-unreadable/report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; log() { :; }; record_change() { :; }; record_skip() { :; }
            read_efivar_attributes() { return 1; }
            inspect_uefi_mor
            [[ "$UEFI_MOR_STATUS" == "FAILED-TO-INSPECT (malformed or unreadable MOR control attributes)" ]]
        ' _ "$repo_root" || fail "UEFI MOR unreadable control attributes were not handled safely"

    local dry_root="$case_root/dry-run"
    install -d "$dry_root/efi" "$dry_root/efivars"
    printf '\007\000\000\000\001' > "$dry_root/efivars/$mor_name"
    local before_hash
    before_hash="$(sha256sum "$dry_root/efivars/$mor_name")"
    env HARDEN_SOURCE_ONLY=1 HARDEN_EFI_SYSFS="$dry_root/efi" HARDEN_EFIVARS_DIR="$dry_root/efivars" \
        HARDEN_EFIVARS_FSTYPE=efivarfs HARDEN_UEFI_MOR_REPORT="$dry_root/report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=dry-run; log() { :; }; record_change() { :; }; record_skip() { :; }
            inspect_uefi_mor; [[ "$UEFI_MOR_STATUS" == "SUPPORTED_ACTIVE"* ]]
            [[ ! -e "$HARDEN_UEFI_MOR_REPORT" ]]
        ' _ "$repo_root" || fail "UEFI MOR dry-run wrote a report or changed classification"
    [[ "$before_hash" == "$(sha256sum "$dry_root/efivars/$mor_name")" ]] \
        || fail "UEFI MOR dry-run wrote an EFI variable"
    ! grep -Eq '(>|>>)[[:space:]]*"?\$?(mor_path|lock_path|efivars_dir)' "$repo_root/harden.sh" \
        || fail "UEFI MOR implementation redirects output to an EFI variable path"
    ! grep -Eq '\b(rm|dd|tee|install|cp|mv)\b.*\$?(mor_path|lock_path|efivars_dir)' "$repo_root/harden.sh" \
        || fail "UEFI MOR implementation contains an EFI-variable mutation command"
}

run_ipv6_banner_motd_tests() {
    local case_root="$test_root/ipv6-banner-motd" mock_bin
    mock_bin="$case_root/bin"
    install -d "$mock_bin"
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == is-active && "$2" == --quiet && "$3" == tailscaled.service && "${IPV6_TEST_TAILSCALE:-0}" == 1 ]] && exit 0
exit 1
EOF
    cat > "$mock_bin/ip" <<'EOF'
#!/usr/bin/env bash
case "${1:-} ${2:-} ${3:-} ${4:-}" in
    '-o link show up') printf '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' ;;
    '-6 -o addr show') [[ "${IPV6_TEST_GLOBAL:-0}" == 1 ]] && printf '2: eth0    inet6 2001:db8::10/64 scope global\n' ;;
    '-6 route show default') [[ "${IPV6_TEST_DEFAULT_ROUTE:-0}" == 1 ]] && printf 'default via 2001:db8::1 dev eth0\n' ;;
    '-6 rule show '*) [[ "${IPV6_TEST_POLICY_ROUTE:-0}" == 1 ]] && printf '100: from all lookup 100\n' || printf '0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n' ;;
esac
EOF
cat > "$mock_bin/ss" <<'EOF'
#!/usr/bin/env bash
[[ "$1 $2 $3" == '-H -6 -lntu' ]] || exit 64
case "${IPV6_TEST_LISTENER:-0}" in
    1) printf 'tcp LISTEN 0 128 [::]:22 [::]:*\n' ;;
    wildcard) printf 'tcp LISTEN 0 128 *:443 *:*\n' ;;
esac
EOF
cat > "$mock_bin/sysctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
root="${HARDEN_PROC_SYS_ROOT:?}"
set_value() {
    local key="$1" value="$2" path="$root/${key//./\/}"
    [[ -e "$path" ]] || return 1
    if [[ "$key" == net.ipv6.conf.all.disable_ipv6 ]]; then
        # Match Linux: writing conf/all/disable_ipv6 propagates to default and
        # every per-interface value before a deterministic restore rewrites them.
        while IFS= read -r path; do
            printf '%s\n' "$value" > "$path"
        done < <(find "$root/net/ipv6/conf" -mindepth 2 -maxdepth 2 -type f -name disable_ipv6 -print | sort)
        return 0
    fi
    printf '%s\n' "$value" > "$path"
}
case "${1:-}" in
    -n) cat "$root/${2//./\/}" ;;
    -w)
        key="${2%%=*}"; value="${2#*=}"
        set_value "$key" "$value"
        ;;
    -p)
        count=0
        while IFS='=' read -r key value; do
            key="${key//[[:space:]]/}"; value="${value//[[:space:]]/}"
            [[ -n "$key" && "$key" != \#* ]] || continue
            count=$((count + 1))
            set_value "$key" "$value"
            [[ "${IPV6_TEST_FAIL_SYSCTL_KEY:-}" != "$key" ]] || exit 1
            [[ "${IPV6_TEST_FAIL_SYSCTL_AFTER:-0}" -eq 0 || "$count" -lt "${IPV6_TEST_FAIL_SYSCTL_AFTER}" ]] || exit 1
        done < "$2"
        ;;
    *) exit 64 ;;
esac
EOF
    chmod +x "$mock_bin/systemctl" "$mock_bin/ip" "$mock_bin/ss" "$mock_bin/sysctl"

    make_ipv6_tree() {
        local root="$1" interface key
        for interface in all default lo eth0 tailscale0 down0; do
            install -d "$root/net/ipv6/conf/$interface"
            for key in disable_ipv6 accept_redirects accept_source_route forwarding; do printf '0\n' > "$root/net/ipv6/conf/$interface/$key"; done
        done
    }
    run_ipv6_case() {
        local name="$1" tailscale="$2" global="$3" default_route="$4" listener="$5" forwarding="$6" policy_route="$7" disable="$8" expected="$9"
        local root="$case_root/$name/proc/sys"
        make_ipv6_tree "$root"
        printf '%s\n' "$forwarding" > "$root/net/ipv6/conf/all/forwarding"
        env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$root" \
            IPV6_TEST_TAILSCALE="$tailscale" IPV6_TEST_GLOBAL="$global" IPV6_TEST_DEFAULT_ROUTE="$default_route" IPV6_TEST_LISTENER="$listener" IPV6_TEST_POLICY_ROUTE="$policy_route" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                MODE=apply; AGGRESSIVE=1; DISABLE_IPV6="$3"; log() { :; }; record_skip() { :; }
                set +e; detect_ipv6_policy; detect_status=$?; set -e
                [[ "$IPV6_POLICY" == "$2" ]] || { printf "status=%s policy=%s reason=%s forwarding=%s\n" "$detect_status" "$IPV6_POLICY" "$IPV6_REASON" "$IPV6_FORWARDING_STATE" >&2; exit 1; }
                if [[ "$IPV6_POLICY" == disabled-explicit-opt-in ]]; then
                    candidates="$(ipv6_policy_candidates)"
                    grep -Fxq "net.ipv6.conf.all.disable_ipv6=1" <<<"$candidates"
                    grep -Fxq "net.ipv6.conf.eth0.disable_ipv6=1" <<<"$candidates" || { printf "candidates=%s\n" "$candidates" >&2; exit 1; }
                    grep -Fxq "net.ipv6.conf.lo.disable_ipv6=1" <<<"$candidates"
                    grep -Fxq "net.ipv6.conf.tailscale0.disable_ipv6=1" <<<"$candidates"
                    grep -Fxq "net.ipv6.conf.down0.disable_ipv6=1" <<<"$candidates"
                else
                    ! ipv6_policy_candidates | grep -q disable_ipv6
                fi
            ' _ "$repo_root" "$expected" "$disable" || fail "IPv6 ${name} policy failed (expected ${expected})"
    }
    run_ipv6_case unused-default-off 0 0 0 0 0 0 0 enabled-safe
    run_ipv6_case unused-opt-in 0 0 0 0 0 0 1 disabled-explicit-opt-in
    run_ipv6_case global-address 0 1 0 0 0 0 1 enabled-safety-blocked
    run_ipv6_case default-route 0 0 1 0 0 0 1 enabled-safety-blocked
    run_ipv6_case listener 0 0 0 1 0 0 1 enabled-safety-blocked
    run_ipv6_case wildcard-listener 0 0 0 wildcard 0 0 1 enabled-safety-blocked
    run_ipv6_case forwarding 0 0 0 0 1 0 1 enabled-safety-blocked
    run_ipv6_case policy-routing 0 0 0 0 0 1 1 enabled-safety-blocked
    run_ipv6_case tailscale 1 0 0 0 0 0 1 enabled-safety-blocked

    local ipv6_dry="$case_root/dry-run"
    make_ipv6_tree "$ipv6_dry/proc/sys"
    printf 'unchanged\n' > "$ipv6_dry/99-security-hardening.conf"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$ipv6_dry/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$ipv6_dry/99-security-hardening.conf" HARDEN_IPV6_REPORT="$ipv6_dry/ipv6-report.txt" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=dry-run; AGGRESSIVE=1; DISABLE_IPV6=1; log() { :; }
            configure_sysctl
            [[ "$IPV6_POLICY" == disabled-explicit-opt-in ]]
            [[ "$IPV6_PERSISTENCE_STATUS" == PLANNED* ]]
            grep -Fxq unchanged "$HARDEN_SYSCTL_CONFIG"
            [[ ! -e "$HARDEN_IPV6_REPORT" ]]
        ' _ "$repo_root" || fail "IPv6 dry-run wrote managed state or did not plan explicit disable"

    run_ipv6_apply() {
        local root="$1" disable="$2" fail_after="${3:-0}" fail_key="${4:-}"
        env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$root/proc/sys" \
            HARDEN_SYSCTL_CONFIG="$root/99-security-hardening.conf" HARDEN_IPV6_REPORT="$root/ipv6-report.txt" \
            HARDEN_RP_FILTER_REPORT="$root/rp-filter-report.txt" IPV6_TEST_FAIL_SYSCTL_AFTER="$fail_after" IPV6_TEST_FAIL_SYSCTL_KEY="$fail_key" IPV6_TEST_EXPECT_FAILURE="$([[ "$fail_after" -gt 0 || -n "$fail_key" ]] && printf 1 || printf 0)" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                MODE=apply; AGGRESSIVE=1; DISABLE_IPV6="$3"; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"
                mkdir -p "$BACKUP_DIR"; : > "$CHANGE_LOG"
                log() { :; }; record_change() { :; }; record_skip() { :; }
                run_streamed() { "$@"; }
                write_rp_filter_report() { :; }
                write_ipv6_report() { printf "policy=%s\nreason=%s\nruntime=%s\npersistence=%s\n" "$IPV6_POLICY" "$IPV6_REASON" "$IPV6_RUNTIME_STATUS" "$IPV6_PERSISTENCE_STATUS" > "$HARDEN_IPV6_REPORT"; }
                transaction_copy() { [[ -e "$1" ]] && cp -a -- "$1" "$BACKUP_DIR/$2" || : > "$BACKUP_DIR/$2.absent"; }
                transaction_restore() { [[ -e "$BACKUP_DIR/$2.absent" ]] && rm -f -- "$1" || cp -a -- "$BACKUP_DIR/$2" "$1"; }
                install_managed_file() { local destination="$1" mode="$2" temporary; MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"; if [[ -f "$destination" ]] && cmp -s "$temporary" "$destination"; then rm -f "$temporary"; return 0; fi; mkdir -p -- "$(dirname -- "$destination")"; cp -- "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1; }
                set +e; configure_sysctl; configure_status=$?; set -e
                if [[ "$configure_status" -ne 0 ]]; then
                    [[ "$IPV6_TEST_EXPECT_FAILURE" == 1 ]] || printf "configure-status=%s ipv6-policy=%s runtime=%s persistence=%s\n" "$configure_status" "$IPV6_POLICY" "$IPV6_RUNTIME_STATUS" "$IPV6_PERSISTENCE_STATUS" >&2
                    exit "$configure_status"
                fi
            ' _ "$repo_root" "$root" "$disable"
    }

    local ipv6_apply="$case_root/apply"
    make_ipv6_tree "$ipv6_apply/proc/sys"
    : > "$ipv6_apply/99-security-hardening.conf"
    run_ipv6_apply "$ipv6_apply" 0 || fail "normal IPv6 safe sysctl application failed"
    grep -Fxq 'net.ipv6.conf.all.accept_source_route = -1' "$ipv6_apply/99-security-hardening.conf" \
        && grep -Fxq 'net.ipv6.conf.default.accept_source_route = -1' "$ipv6_apply/99-security-hardening.conf" \
        && grep -Fxq 'net.ipv6.conf.all.forwarding = 0' "$ipv6_apply/99-security-hardening.conf" \
        && grep -Fxq 'net.ipv6.conf.default.forwarding = 0' "$ipv6_apply/99-security-hardening.conf" \
        || fail "normal non-forwarding host did not persist source-route=-1 and forwarding=0"

    run_ipv6_apply "$ipv6_apply" 1 || fail "explicit IPv6 disable failed"
    for key in all default lo eth0 tailscale0 down0; do
        [[ "$(cat "$ipv6_apply/proc/sys/net/ipv6/conf/$key/disable_ipv6")" == 1 ]] \
            || fail "explicit IPv6 disable did not set ${key}"
    done
    grep -Fxq 'net.ipv6.conf.lo.disable_ipv6 = 1' "$ipv6_apply/99-security-hardening.conf" \
        || fail "explicit IPv6 disable did not persist lo"
    run_ipv6_apply "$ipv6_apply" 0 || fail "preserved IPv6 disable follow-up failed"
    grep -Fq 'previous explicit tool-managed IPv6 disable is retained' "$ipv6_apply/ipv6-report.txt" \
        || fail "normal follow-up did not report preserved IPv6 disable"
    for key in all default lo eth0 tailscale0 down0; do
        [[ "$(cat "$ipv6_apply/proc/sys/net/ipv6/conf/$key/disable_ipv6")" == 1 ]] \
            || fail "normal follow-up unexpectedly re-enabled ${key}"
    done

    local ipv6_forwarding="$case_root/interface-forwarding"
    make_ipv6_tree "$ipv6_forwarding/proc/sys"
    printf '1\n' > "$ipv6_forwarding/proc/sys/net/ipv6/conf/eth0/forwarding"
    : > "$ipv6_forwarding/99-security-hardening.conf"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$ipv6_forwarding/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$ipv6_forwarding/99-security-hardening.conf" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; AGGRESSIVE=1; DISABLE_IPV6=1; log() { :; }; record_skip() { :; }
            detect_ipv6_policy "$HARDEN_SYSCTL_CONFIG"
            [[ "$IPV6_POLICY" == enabled-safety-blocked && "$IPV6_REASON" == *ipv6-forwarding-active* ]]
        ' _ "$repo_root" || fail "active interface IPv6 forwarding did not block disable"

    local ipv6_down_forwarding="$case_root/down-interface-forwarding"
    make_ipv6_tree "$ipv6_down_forwarding/proc/sys"
    printf '1\n' > "$ipv6_down_forwarding/proc/sys/net/ipv6/conf/down0/forwarding"
    : > "$ipv6_down_forwarding/99-security-hardening.conf"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$ipv6_down_forwarding/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$ipv6_down_forwarding/99-security-hardening.conf" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; AGGRESSIVE=1; DISABLE_IPV6=1; log() { :; }; record_skip() { :; }
            detect_ipv6_policy "$HARDEN_SYSCTL_CONFIG"
            [[ "$IPV6_POLICY" == enabled-safety-blocked && "$IPV6_REASON" == *ipv6-forwarding-active* ]]
        ' _ "$repo_root" || fail "DOWN interface IPv6 forwarding did not block disable"

    local ipv6_force_forwarding="$case_root/down-interface-force-forwarding"
    make_ipv6_tree "$ipv6_force_forwarding/proc/sys"
    printf '0\n' > "$ipv6_force_forwarding/proc/sys/net/ipv6/conf/all/force_forwarding"
    printf '0\n' > "$ipv6_force_forwarding/proc/sys/net/ipv6/conf/default/force_forwarding"
    printf '1\n' > "$ipv6_force_forwarding/proc/sys/net/ipv6/conf/down0/force_forwarding"
    : > "$ipv6_force_forwarding/99-security-hardening.conf"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$ipv6_force_forwarding/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$ipv6_force_forwarding/99-security-hardening.conf" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            MODE=apply; AGGRESSIVE=1; DISABLE_IPV6=1; log() { :; }; record_skip() { :; }
            detect_ipv6_policy "$HARDEN_SYSCTL_CONFIG"
            [[ "$IPV6_POLICY" == enabled-safety-blocked && "$IPV6_REASON" == *ipv6-forwarding-active* ]]
        ' _ "$repo_root" || fail "DOWN interface IPv6 force_forwarding did not block disable"

    local ipv6_rollback="$case_root/rollback"
    make_ipv6_tree "$ipv6_rollback/proc/sys"
    printf '0\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/all/disable_ipv6"
    printf '1\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/default/disable_ipv6"
    printf '0\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/lo/disable_ipv6"
    printf '1\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/eth0/disable_ipv6"
    printf '0\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/tailscale0/disable_ipv6"
    printf '1\n' > "$ipv6_rollback/proc/sys/net/ipv6/conf/down0/disable_ipv6"
    printf 'old-config\n' > "$ipv6_rollback/99-security-hardening.conf"
    run_ipv6_apply "$ipv6_rollback" 1 0 net.ipv6.conf.all.disable_ipv6 && fail "partial IPv6 sysctl reload unexpectedly succeeded"
    [[ "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/all/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/default/disable_ipv6")" == 1 \
        && "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/lo/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/eth0/disable_ipv6")" == 1 \
        && "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/tailscale0/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_rollback/proc/sys/net/ipv6/conf/down0/disable_ipv6")" == 1 ]] \
        || fail "partial IPv6 sysctl reload did not restore exact runtime values"
    grep -Fxq old-config "$ipv6_rollback/99-security-hardening.conf" \
        || fail "partial IPv6 sysctl reload did not restore previous config"

    local ipv6_preserved_failure="$case_root/preserved-disable-failure"
    make_ipv6_tree "$ipv6_preserved_failure/proc/sys"
    cat > "$ipv6_preserved_failure/99-security-hardening.conf" <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.tailscale0.disable_ipv6 = 1
net.ipv6.conf.down0.disable_ipv6 = 1
EOF
    printf '0\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/all/disable_ipv6"
    printf '1\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/default/disable_ipv6"
    printf '0\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/lo/disable_ipv6"
    printf '1\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/eth0/disable_ipv6"
    printf '0\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/tailscale0/disable_ipv6"
    printf '1\n' > "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/down0/disable_ipv6"
    run_ipv6_apply "$ipv6_preserved_failure" 0 0 net.ipv6.conf.all.disable_ipv6 \
        && fail "preserved IPv6 disable reload failure unexpectedly succeeded"
    [[ "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/all/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/default/disable_ipv6")" == 1 \
        && "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/lo/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/eth0/disable_ipv6")" == 1 \
        && "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/tailscale0/disable_ipv6")" == 0 \
        && "$(cat "$ipv6_preserved_failure/proc/sys/net/ipv6/conf/down0/disable_ipv6")" == 1 ]] \
        || fail "preserved IPv6 disable reload failure did not restore exact pre-run runtime values"

    local banner_root="$case_root/banner" issue issue_net
    issue="$banner_root/issue"
    issue_net="$banner_root/issue.net"
    install -d "$banner_root"
    printf 'old banner\n' > "$issue"; printf 'old network banner\n' > "$issue_net"; chmod 0600 "$issue" "$issue_net"
    env HARDEN_SOURCE_ONLY=1 HARDEN_ISSUE_FILE="$issue" HARDEN_ISSUE_NET_FILE="$issue_net" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; mkdir -p "$BACKUP_DIR"; : > "$CHANGE_LOG"
        transaction_copy() { :; }; transaction_restore() { :; }
        chown() { :; }
        stat() {
            [[ "$1" == -c && "$2" == "%U:%G:%a" ]] && { printf "root:root:644\n"; return 0; }
            [[ "$1" == -c && "$2" == "%a" ]] && { printf "644\n"; return 0; }
            command stat "$@"
        }
        install_managed_file() {
            local destination="$1" mode="$2" temporary
            MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"
            if [[ -f "$destination" ]] && cmp -s "$temporary" "$destination"; then rm -f "$temporary"; return 0; fi
            mkdir -p -- "$(dirname -- "$destination")"; cp -- "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1
        }
        configure_banners
        expected="$(cat <<"EOF"
*******************************************************************************
                        AUTHORIZED ACCESS ONLY

  This system is the private property of its owner. Unauthorized access,
  use, modification, or disclosure of data on this system is prohibited
  and may be subject to criminal prosecution under applicable law.

  All activities on this system are monitored and recorded. By continuing,
  you consent to this monitoring. Evidence of unauthorized use may be
  disclosed to law enforcement authorities.

  Disconnect IMMEDIATELY if you are not an authorized user.
*******************************************************************************
EOF
)"
        [[ "$(cat "$HARDEN_ISSUE_FILE")" == "$expected" && "$(cat "$HARDEN_ISSUE_NET_FILE")" == "$expected" ]]
        cmp -s "$HARDEN_ISSUE_FILE" "$HARDEN_ISSUE_NET_FILE"
        grep -Fq "AUTHORIZED ACCESS ONLY" "$HARDEN_ISSUE_FILE"
        grep -Fq "monitored and recorded" "$HARDEN_ISSUE_FILE"
        grep -Fq "law enforcement authorities" "$HARDEN_ISSUE_FILE"
        [[ "$(stat -c %a "$HARDEN_ISSUE_FILE")" == 644 && "$(stat -c %a "$HARDEN_ISSUE_NET_FILE")" == 644 ]]
        configure_banners
    ' _ "$repo_root" "$banner_root" || fail "banner content, permissions, or idempotence failed"
    env HARDEN_SOURCE_ONLY=1 HARDEN_ISSUE_FILE="$issue" HARDEN_ISSUE_NET_FILE="$issue_net" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=dry-run; configure_banners
    ' _ "$repo_root" || fail "banner dry-run failed"

    local motd_root="$case_root/motd" motd_dir motd_cache
    motd_dir="$motd_root/update-motd.d"
    motd_cache="$motd_root/motd.dynamic"
    local motd_mock_exec=0
    [[ "$(uname -s)" == MINGW* ]] && motd_mock_exec=1
    install -d "$motd_dir"
    for hook in 00-header 50-landscape-sysinfo 90-updates-available 98-reboot-required; do printf '#!/bin/sh\nexit 0\n' > "$motd_dir/$hook"; chmod 0755 "$motd_dir/$hook"; done
    printf 'stale presentation\n' > "$motd_cache"
    env HARDEN_SOURCE_ONLY=1 HARDEN_UPDATE_MOTD_DIR="$motd_dir" HARDEN_MOTD_CACHE="$motd_cache" MOTD_TEST_MOCK_EXEC="$motd_mock_exec" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; AGGRESSIVE=1; OS_ID=ubuntu; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; mkdir -p "$BACKUP_DIR"; : > "$CHANGE_LOG"
        transaction_copy() { cp -a -- "$1" "$BACKUP_DIR/$2"; }
        transaction_restore() { cp -a -- "$BACKUP_DIR/$2" "$1"; chmod 0755 "$1"; }
        if [[ "$MOTD_TEST_MOCK_EXEC" == 1 ]]; then
            chmod() { [[ "$1" == a-x ]] && { : > "${2}.disabled"; return 0; }; command chmod "$@"; }
        fi
        configure_motd_presentation
        if [[ "$MOTD_TEST_MOCK_EXEC" == 1 ]]; then
            [[ -e "$HARDEN_UPDATE_MOTD_DIR/00-header.disabled" && -e "$HARDEN_UPDATE_MOTD_DIR/50-landscape-sysinfo.disabled" && -e "$HARDEN_UPDATE_MOTD_DIR/90-updates-available.disabled" ]]
            [[ ! -e "$HARDEN_UPDATE_MOTD_DIR/98-reboot-required.disabled" && ! -e "$HARDEN_MOTD_CACHE" ]]
        else
            [[ ! -x "$HARDEN_UPDATE_MOTD_DIR/00-header" && ! -x "$HARDEN_UPDATE_MOTD_DIR/50-landscape-sysinfo" && ! -x "$HARDEN_UPDATE_MOTD_DIR/90-updates-available" ]]
            [[ -x "$HARDEN_UPDATE_MOTD_DIR/98-reboot-required" && ! -e "$HARDEN_MOTD_CACHE" ]]
        fi
        transaction_restore "$HARDEN_UPDATE_MOTD_DIR/00-header" motd-hook-00-header
        [[ "$MOTD_TEST_MOCK_EXEC" == 1 || -x "$HARDEN_UPDATE_MOTD_DIR/00-header" ]]
    ' _ "$repo_root" "$motd_root" || fail "MOTD presentation classification, preservation, or rollback failed"
    env HARDEN_SOURCE_ONLY=1 HARDEN_UPDATE_MOTD_DIR="$motd_dir" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; AGGRESSIVE=1; OS_ID=debian; configure_motd_presentation
        [[ "$MOTD_STATUS" == "N/A (no Ubuntu presentation hooks)" ]]
    ' _ "$repo_root" || fail "Debian MOTD no-op failed"
    ! grep -Eq 'apt(-get)?[[:space:]]+(purge|remove).*motd|apt(-get)?[[:space:]]+(purge|remove).*ubuntu-pro' "$repo_root/harden.sh" \
        || fail "MOTD policy removes a package"
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

run_deleted_open_tests() {
    local case_root="$test_root/deleted-open" mock_bin="$test_root/deleted-open/bin"
    install -d "$mock_bin"
    cat > "$mock_bin/lsof" <<'EOF'
#!/usr/bin/env bash
case "${DO_TEST_STATE:-empty}" in
 empty) exit 0 ;;
 safe-before) { [[ "${DO_TEST_RESTART:-1}" == 1 && "${DO_TEST_HEALTH:-1}" == 1 ]] && grep -Fq 'restart rsyslog.service' "${DO_TEST_LOG:-/dev/null}" 2>/dev/null; } || printf 'p4242\ncworker\nu100\nf5\ntREG\nk0\nn/var/log/test (deleted)\n' ;;
 protected) printf 'p22\ncsshd\nu0\nf3\ntREG\nk0\nn/tmp/key (deleted)\n' ;;
 protected-clears) if [[ ! -e "${DO_TEST_MARKER:?}" ]]; then touch "$DO_TEST_MARKER"; printf 'p22\ncsshd\nu0\nf3\ntREG\nk0\nn/tmp/key (deleted)\n'; fi ;;
 memfd-systemd) printf 'p1\ncsystemd\nu0\nf9\ntREG\nk0\nn/memfd:systemd-udevd (deleted)\n' ;;
 memfd-other) printf 'p900\nctest-worker\nu1000\nf9\ntREG\nk0\nn/memfd:test (deleted)\n' ;;
 memfd-protected) printf 'p1\ncsystemd\nu0\nf9\ntREG\nk0\nn/memfd:systemd-udevd (deleted)\np22\ncsshd\nu0\nf3\ntREG\nk0\nn/tmp/key (deleted)\n' ;;
 memfd-safe) printf 'p1\ncsystemd\nu0\nf9\ntREG\nk0\nn/memfd:systemd-udevd (deleted)\n'; { [[ "${DO_TEST_RESTART:-1}" == 1 && "${DO_TEST_HEALTH:-1}" == 1 ]] && grep -Fq 'restart rsyslog.service' "${DO_TEST_LOG:-/dev/null}" 2>/dev/null; } || printf 'p4242\ncworker\nu100\nf5\ntREG\nk0\nn/var/log/test (deleted)\n' ;;
 unknown) printf 'p77\ncmystery\nu1000\nf4\ntREG\nk0\nn/tmp/x (deleted)\n' ;;
 multi) printf 'p4242\ncworker\nu100\nf5\ntREG\nk0\nn/tmp/a (deleted)\nf6\ntREG\nk0\nn/tmp/b (deleted)\n' ;;
esac
EOF
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${DO_TEST_LOG:?}"
case "$1 $2" in
 'is-active --quiet') [[ "${DO_TEST_HEALTH:-1}" == 1 ]] ;;
 restart\ *) [[ "${DO_TEST_RESTART:-1}" == 1 ]] ;;
 *) exit 0 ;;
esac
EOF
    chmod +x "$mock_bin/lsof" "$mock_bin/systemctl"
    local one="$case_root/one"; install -d "$one"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=empty DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$2/log"; : > "$CHANGE_LOG"; REBOOT_REQUIRED=0
            remediate_deleted_open_files
            [[ "$DELETED_OPEN_FILES_STATUS" == "OK: no deleted open files" && ! -s "$2/log" ]]
        ' _ "$repo_root" "$one" || fail "empty deleted-open inventory was not a no-op"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=safe-before DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "rsyslog.service\n"; }
            remediate_deleted_open_files
            grep -Fq "restart rsyslog.service" "$DO_TEST_LOG"
            [[ "$DELETED_OPEN_FILES_STATUS" == "OK: inventory clear after targeted remediation" ]]
        ' _ "$repo_root" "$one" || fail "safe deleted-open service was not restarted"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=safe-before DO_TEST_RESTART=0 DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "rsyslog.service\n"; }
            remediate_deleted_open_files
            grep -Fq "service-health=failed" "$HARDEN_DELETED_OPEN_REPORT"
            grep -Fq "deleted-file-released=no" "$HARDEN_DELETED_OPEN_REPORT"
        ' _ "$repo_root" "$one" || fail "failed safe restart was reported as successful"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=protected DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "sshd.service\n"; }
            remediate_deleted_open_files
            ! grep -Fq "restart" "$DO_TEST_LOG"; [[ "$REBOOT_REQUIRED" == 1 ]]
        ' _ "$repo_root" "$one" || fail "protected deleted-open owner was restarted or did not request controlled reboot"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=protected DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "tailscaled.service\n"; }
            remediate_deleted_open_files
            ! grep -Fq "restart" "$DO_TEST_LOG"; [[ "$REBOOT_REQUIRED" == 1 ]]
        ' _ "$repo_root" "$one" || fail "tailscaled deleted-open owner was restarted"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=protected DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "networkd-dispatcher.service\n"; }
            remediate_deleted_open_files
            ! grep -Fq "restart" "$DO_TEST_LOG"; [[ "$REBOOT_REQUIRED" == 1 ]]
        ' _ "$repo_root" "$one" || fail "networkd-dispatcher deleted-open owner was restarted"
    : > "$one/marker"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=protected-clears DO_TEST_MARKER="$one/marker" DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            rm -f "$DO_TEST_MARKER"; systemd_unit_for_pid() { printf "sshd.service\n"; }; remediate_deleted_open_files
            [[ "$REBOOT_REQUIRED" == 0 ]]
        ' _ "$repo_root" "$one" || fail "disappeared protected Before finding requested an unnecessary reboot"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=multi DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "rsyslog.service\n"; }; remediate_deleted_open_files
            [[ "$(grep -c "restart rsyslog.service" "$DO_TEST_LOG")" == 1 ]]
        ' _ "$repo_root" "$one" || fail "same-unit deleted-open files triggered more than one restart"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=memfd-systemd DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { printf "systemd.service\n"; }; remediate_deleted_open_files
            [[ "$DELETED_OPEN_FILES_STATUS" == "ACCEPTED: only anonymous memfd entries remain" && "$REBOOT_REQUIRED" == 0 ]]
            ! grep -Fq "restart" "$DO_TEST_LOG"; grep -Fq "classification=anonymous-memfd" "$HARDEN_DELETED_OPEN_REPORT"
        ' _ "$repo_root" "$one" || fail "systemd anonymous memfd was treated as an actionable deleted file"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=memfd-other DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            remediate_deleted_open_files
            [[ "$REBOOT_REQUIRED" == 0 ]]; ! grep -Fq "restart" "$DO_TEST_LOG"; grep -Fq "process=test-worker" "$HARDEN_DELETED_OPEN_REPORT"
        ' _ "$repo_root" "$one" || fail "non-systemd anonymous memfd was hidden or remediated"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=memfd-protected DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { [[ "$1" == 22 ]] && printf "sshd.service\n" || printf "systemd.service\n"; }; remediate_deleted_open_files
            [[ "$REBOOT_REQUIRED" == 1 ]]; grep -Fq "anonymous-memfd-exceptions=1" "$HARDEN_DELETED_OPEN_REPORT"
        ' _ "$repo_root" "$one" || fail "protected deleted file was masked by a memfd exception"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/report" \
        DO_TEST_STATE=memfd-safe DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=apply; BACKUP_DIR="$2"; CHANGE_LOG="$2/changes"; : > "$CHANGE_LOG"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            systemd_unit_for_pid() { [[ "$1" == 4242 ]] && printf "rsyslog.service\n" || printf "systemd.service\n"; }; remediate_deleted_open_files
            grep -Fq "restart rsyslog.service" "$DO_TEST_LOG"; [[ "$DELETED_OPEN_FILES_STATUS" == "ACCEPTED: only anonymous memfd entries remain" ]]
        ' _ "$repo_root" "$one" || fail "safe deleted file was not remediated alongside a memfd exception"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_DELETED_OPEN_REPORT="$one/dry-report" DO_TEST_STATE=unknown DO_TEST_LOG="$one/log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT; MODE=dry-run; BACKUP_DIR="$2"; : > "$DO_TEST_LOG"; REBOOT_REQUIRED=0
            remediate_deleted_open_files
            [[ ! -e "${HARDEN_DELETED_OPEN_REPORT:-/root/deleted-open-files-report.txt}" && ! -s "$DO_TEST_LOG" ]]
        ' _ "$repo_root" "$one" || fail "deleted-open dry-run wrote state or restarted a service"
}

run_rp_filter_tests() {
    local case_root="$test_root/rp-filter" mock_bin="$test_root/rp-filter/bin"
    local sysctl_section
    install -d "$mock_bin"
    cat > "$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == is-active && "${2:-}" == --quiet && "${3:-}" == tailscaled.service ]]; then
    [[ "${RP_TEST_TAILSCALE_ACTIVE:-0}" == 1 ]]
fi
EOF
    cat > "$mock_bin/ip" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "$*" in
    '-4 route show default') printf '%s\n' "${RP_TEST_DEFAULT_ROUTES:-}" ;;
    '-4 rule show') printf '%s\n' "${RP_TEST_RULES:-0: from all lookup local
32766: from all lookup main
32767: from all lookup default}" ;;
    '-o link show up') printf '%s\n' "${RP_TEST_INTERFACES:-2: eth0: <BROADCAST,UP> mtu 1500}" ;;
    '-4 route get 1.1.1.1') [[ -n "${RP_TEST_DEFAULT_ROUTES:-}" ]] ;;
    *) exit 1 ;;
esac
EOF
    cat > "$mock_bin/sysctl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
root="${HARDEN_PROC_SYS_ROOT:?}"
log="${RP_TEST_COMMAND_LOG:?}"
key_path() { printf '%s/%s\n' "$root" "${1//./\/}"; }
case "${1:-}" in
    -n)
        path="$(key_path "$2")"
        [[ -f "$path" ]] || exit 1
        cat "$path"
        ;;
    -p)
        printf 'sysctl -p %s\n' "$2" >> "$log"
        while IFS='=' read -r key value; do
            key="${key//[[:space:]]/}"; value="${value//[[:space:]]/}"
            [[ -n "$key" ]] || continue
            path="$(key_path "$key")"
            [[ -e "$path" ]] || continue
            printf '%s\n' "$value" > "$path"
        done < "$2"
        ;;
    --system)
        printf 'sysctl --system\n' >> "$log"
        ;;
    *) exit 1 ;;
esac
EOF
    cat > "$mock_bin/tailscale" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${1:-}" == status && "${2:-}" == --json ]] || exit 64
case "${RP_TEST_HEALTH:-clear}" in
    real) printf '%s\n' '{"BackendState":"Running","Health":["router: netfilter setup failed"]}' ;;
    harmless) printf '%s\n' '{"BackendState":"Running","Health":["Some peers are advertising routes but --accept-routes is false."]}' ;;
    *) printf '%s\n' '{"BackendState":"Running","Health":[]}' ;;
esac
EOF
    cat > "$mock_bin/python3" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input="$(cat)"
grep -Fq '"BackendState":"Running"' <<<"$input" && printf 'backend=Running\n' || printf 'backend=Unknown\n'
grep -Eqi 'router|netfilter|firewall|iptables|nftables|masquerad|postrouting|forwarding' <<<"$input" \
    && printf 'health-problem=1\n' || true
EOF
    chmod +x "$mock_bin/systemctl" "$mock_bin/ip" "$mock_bin/sysctl" "$mock_bin/tailscale" "$mock_bin/python3"

    run_rp_filter_case() {
        local name="$1" active="$2" routes="$3" rules="$4" health="$5" initial="$6" expected="$7"
        local root="$case_root/$name" sysroot config
        sysroot="$root/proc/sys"
        config="$root/99-security-hardening.conf"
        local report="$root/rp-filter-report.txt" commands="$root/commands.log"
        install -d "$sysroot/net/ipv4/conf/all" "$sysroot/net/ipv4/conf/default" \
            "$sysroot/net/ipv4/conf/eth0" "$sysroot/net/ipv4/conf/tailscale0"
        for path in "$sysroot/net/ipv4/conf/all/rp_filter" "$sysroot/net/ipv4/conf/default/rp_filter" \
            "$sysroot/net/ipv4/conf/eth0/rp_filter" "$sysroot/net/ipv4/conf/tailscale0/rp_filter"; do
            printf '%s\n' "$initial" > "$path"
        done
        : > "$commands"
        env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$sysroot" \
            HARDEN_SYSCTL_CONFIG="$config" HARDEN_RP_FILTER_REPORT="$report" \
            RP_TEST_TAILSCALE_ACTIVE="$active" RP_TEST_DEFAULT_ROUTES="$routes" RP_TEST_RULES="$rules" \
            RP_TEST_HEALTH="$health" RP_TEST_COMMAND_LOG="$commands" bash -c '
                source "$1/harden.sh"; trap - ERR EXIT
                sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
                MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
                transaction_copy() { :; }; transaction_restore() { :; }
                install_managed_file() {
                    local destination="$1" mode="$2" temporary
                    MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"
                    if [[ -f "$destination" ]] && cmp -s "$temporary" "$destination"; then rm -f "$temporary"; return 0; fi
                    mkdir -p -- "$(dirname -- "$destination")"; cp "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1
                }
                configure_sysctl
                [[ "$(sysctl -n net.ipv4.conf.all.rp_filter)" == "$3" ]]
                [[ "$(sysctl -n net.ipv4.conf.default.rp_filter)" == "$3" ]]
                [[ "$(sysctl -n net.ipv4.conf.eth0.rp_filter)" == "$3" ]]
                if [[ "$4" == 1 ]]; then [[ "$(sysctl -n net.ipv4.conf.tailscale0.rp_filter)" == "$3" ]]; fi
            ' _ "$repo_root" "$root" "$expected" "$active" || fail "rp_filter ${name} policy application failed"
    }

    run_rp_filter_case active 1 'default via 192.0.2.1 dev eth0' '' clear 1 2
    grep -Fq 'accepted-exception-loose-2' "$case_root/active/rp-filter-report.txt" \
        || fail "active Tailscale rp_filter exception was not reported"
    grep -Fq 'tailscale-runtime=OK: Tailscale backend Running; router/netfilter health clear' "$case_root/active/rp-filter-report.txt" \
        || fail "active Tailscale runtime verification was not recorded"

    : > "$case_root/active/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$case_root/active/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$case_root/active/99-security-hardening.conf" \
        HARDEN_RP_FILTER_REPORT="$case_root/active/rp-filter-report.txt" RP_TEST_TAILSCALE_ACTIVE=1 \
        RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' RP_TEST_HEALTH=clear \
        RP_TEST_COMMAND_LOG="$case_root/active/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { MANAGED_FILE_CHANGED=0; cat >/dev/null; }
            configure_sysctl
            [[ "$RP_FILTER_POLICY" == accepted-exception-loose-2 ]]
        ' _ "$repo_root" "$case_root/active" || fail "converged active Tailscale rp_filter run failed"
    [[ ! -s "$case_root/active/commands.log" ]] || fail "converged rp_filter policy reloaded sysctls unnecessarily"

    printf '1\n' > "$case_root/active/proc/sys/net/ipv4/conf/eth0/rp_filter"
    : > "$case_root/active/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$case_root/active/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$case_root/active/99-security-hardening.conf" \
        HARDEN_RP_FILTER_REPORT="$case_root/active/rp-filter-report.txt" RP_TEST_TAILSCALE_ACTIVE=1 \
        RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' RP_TEST_HEALTH=clear \
        RP_TEST_COMMAND_LOG="$case_root/active/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { MANAGED_FILE_CHANGED=0; cat >/dev/null; }
            configure_sysctl
            [[ "$(sysctl -n net.ipv4.conf.eth0.rp_filter)" == 2 ]]
        ' _ "$repo_root" "$case_root/active" || fail "drifted active rp_filter interface was not corrected"
    grep -Fq 'sysctl -p' "$case_root/active/commands.log" || fail "drifted rp_filter interface did not trigger targeted reload"

    run_rp_filter_case inactive-simple 0 'default via 192.0.2.1 dev eth0' '' clear 2 1
    grep -Fq 'policy=strict-1' "$case_root/inactive-simple/rp-filter-report.txt" \
        || fail "simple inactive routing did not report strict rp_filter policy"

    local uncertain="$case_root/inactive-policy"
    install -d "$uncertain/proc/sys/net/ipv4/conf/all" "$uncertain/proc/sys/net/ipv4/conf/default" \
        "$uncertain/proc/sys/net/ipv4/conf/eth0" "$uncertain/proc/sys/net/ipv4/conf/tailscale0"
    printf '0\n' > "$uncertain/proc/sys/net/ipv4/conf/all/rp_filter"
    printf '1\n' > "$uncertain/proc/sys/net/ipv4/conf/default/rp_filter"
    printf '2\n' > "$uncertain/proc/sys/net/ipv4/conf/eth0/rp_filter"
    printf '2\n' > "$uncertain/proc/sys/net/ipv4/conf/tailscale0/rp_filter"
    printf 'net.ipv4.conf.all.rp_filter = 2\nnet.ipv4.conf.default.rp_filter = 2\n' > "$uncertain/99-security-hardening.conf"
    : > "$uncertain/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$uncertain/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$uncertain/99-security-hardening.conf" HARDEN_RP_FILTER_REPORT="$uncertain/rp-filter-report.txt" \
        RP_TEST_TAILSCALE_ACTIVE=0 RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' \
        RP_TEST_RULES='100: from 198.51.100.0/24 lookup 100' RP_TEST_COMMAND_LOG="$uncertain/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { local destination="$1" mode="$2" temporary; MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"; cmp -s "$temporary" "$destination" && { rm -f "$temporary"; return 0; }; cp "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1; }
            configure_sysctl
            [[ "$RP_FILTER_POLICY" == preserved-uncertain-routing ]]
            [[ "$(sysctl -n net.ipv4.conf.all.rp_filter)" == 0 ]]
            [[ "$(sysctl -n net.ipv4.conf.default.rp_filter)" == 1 ]]
            [[ "$(sysctl -n net.ipv4.conf.eth0.rp_filter)" == 2 ]]
            grep -Fq "net.ipv4.conf.all.rp_filter = 0" "$HARDEN_SYSCTL_CONFIG"
            grep -Fq "net.ipv4.conf.default.rp_filter = 1" "$HARDEN_SYSCTL_CONFIG"
            grep -Fq "net.ipv4.conf.eth0.rp_filter = 2" "$HARDEN_SYSCTL_CONFIG"
            grep -Fq "routing-situation=asymmetric-policy-routing" "$HARDEN_RP_FILTER_REPORT"
            grep -Fq "persisted-current-values=yes" "$HARDEN_RP_FILTER_REPORT"
        ' _ "$repo_root" "$uncertain" || fail "policy-routing host had rp_filter forced to strict mode"
    printf '2\n' > "$uncertain/proc/sys/net/ipv4/conf/all/rp_filter"
    printf '2\n' > "$uncertain/proc/sys/net/ipv4/conf/default/rp_filter"
    printf '0\n' > "$uncertain/proc/sys/net/ipv4/conf/eth0/rp_filter"
    HARDEN_PROC_SYS_ROOT="$uncertain/proc/sys" RP_TEST_COMMAND_LOG="$uncertain/commands.log" \
        "$mock_bin/sysctl" -p "$uncertain/99-security-hardening.conf"
    [[ "$(cat "$uncertain/proc/sys/net/ipv4/conf/all/rp_filter")" == 0 \
        && "$(cat "$uncertain/proc/sys/net/ipv4/conf/default/rp_filter")" == 1 \
        && "$(cat "$uncertain/proc/sys/net/ipv4/conf/eth0/rp_filter")" == 2 ]] \
        || fail "uncertain routing values were not restored by the managed sysctl policy"
    : > "$uncertain/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$uncertain/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$uncertain/99-security-hardening.conf" HARDEN_RP_FILTER_REPORT="$uncertain/rp-filter-report.txt" \
        RP_TEST_TAILSCALE_ACTIVE=0 RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' \
        RP_TEST_RULES='100: from 198.51.100.0/24 lookup 100' RP_TEST_COMMAND_LOG="$uncertain/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { MANAGED_FILE_CHANGED=0; cat >/dev/null; }
            configure_sysctl
        ' _ "$repo_root" "$uncertain" || fail "converged uncertain-routing run failed"
    [[ ! -s "$uncertain/commands.log" ]] || fail "converged uncertain-routing policy reloaded sysctls unnecessarily"

    local multipath="$case_root/inactive-multipath"
    install -d "$multipath/proc/sys/net/ipv4/conf/all" "$multipath/proc/sys/net/ipv4/conf/default" "$multipath/proc/sys/net/ipv4/conf/eth0"
    printf '2\n' > "$multipath/proc/sys/net/ipv4/conf/all/rp_filter"
    printf '0\n' > "$multipath/proc/sys/net/ipv4/conf/default/rp_filter"
    printf '1\n' > "$multipath/proc/sys/net/ipv4/conf/eth0/rp_filter"
    : > "$multipath/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$multipath/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$multipath/99-security-hardening.conf" HARDEN_RP_FILTER_REPORT="$multipath/rp-filter-report.txt" \
        RP_TEST_TAILSCALE_ACTIVE=0 RP_TEST_DEFAULT_ROUTES=$'default via 192.0.2.1 dev eth0\ndefault via 198.51.100.1 dev eth1' \
        RP_TEST_COMMAND_LOG="$multipath/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { local destination="$1" mode="$2" temporary; MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"; mkdir -p -- "$(dirname -- "$destination")"; cp "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1; }
            configure_sysctl
            [[ "$RP_FILTER_POLICY" == preserved-uncertain-routing ]]
            [[ "$(sysctl -n net.ipv4.conf.all.rp_filter)" == 2 ]]
            [[ "$(sysctl -n net.ipv4.conf.default.rp_filter)" == 0 ]]
            [[ "$(sysctl -n net.ipv4.conf.eth0.rp_filter)" == 1 ]]
            grep -Fq "net.ipv4.conf.default.rp_filter = 0" "$HARDEN_SYSCTL_CONFIG"
            grep -Fq "routing-situation=asymmetric-multiple-default-routes" "$HARDEN_RP_FILTER_REPORT"
        ' _ "$repo_root" "$multipath" || fail "multiple-default routing had rp_filter forced to strict mode"

    local unreadable="$case_root/uncertain-invalid-values"
    install -d "$unreadable/proc/sys/net/ipv4/conf/all" "$unreadable/proc/sys/net/ipv4/conf/default" "$unreadable/proc/sys/net/ipv4/conf/eth0"
    printf '3\n' > "$unreadable/proc/sys/net/ipv4/conf/all/rp_filter"
    printf '1\n' > "$unreadable/proc/sys/net/ipv4/conf/default/rp_filter"
    printf 'bogus\n' > "$unreadable/proc/sys/net/ipv4/conf/eth0/rp_filter"
    : > "$unreadable/commands.log"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$unreadable/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$unreadable/99-security-hardening.conf" HARDEN_RP_FILTER_REPORT="$unreadable/rp-filter-report.txt" \
        RP_TEST_TAILSCALE_ACTIVE=0 RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' \
        RP_TEST_RULES='100: from 198.51.100.0/24 lookup 100' RP_TEST_COMMAND_LOG="$unreadable/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=apply; BACKUP_DIR="$2/backup"; CHANGE_LOG="$2/changes.tsv"; : > "$CHANGE_LOG"
            transaction_copy() { :; }; transaction_restore() { :; }
            install_managed_file() { local destination="$1" mode="$2" temporary; MANAGED_FILE_CHANGED=0; temporary="$(mktemp)"; cat > "$temporary"; mkdir -p -- "$(dirname -- "$destination")"; cp "$temporary" "$destination"; chmod "$mode" "$destination"; rm -f "$temporary"; MANAGED_FILE_CHANGED=1; }
            configure_sysctl
            grep -Fq "net.ipv4.conf.default.rp_filter = 1" "$HARDEN_SYSCTL_CONFIG"
            ! grep -Fq "net.ipv4.conf.all.rp_filter" "$HARDEN_SYSCTL_CONFIG"
            ! grep -Fq "net.ipv4.conf.eth0.rp_filter" "$HARDEN_SYSCTL_CONFIG"
        ' _ "$repo_root" "$unreadable" || fail "uncertain routing invented an unreadable or invalid rp_filter value"

    run_rp_filter_case harmless-health 1 'default via 192.0.2.1 dev eth0' '' harmless 1 2
    grep -Fq 'tailscale-runtime=OK: Tailscale backend Running; router/netfilter health clear' "$case_root/harmless-health/rp-filter-report.txt" \
        || fail "harmless accept-routes warning was treated as a Tailscale runtime failure"
    run_rp_filter_case real-health 1 'default via 192.0.2.1 dev eth0' '' real 1 2
    grep -Fq 'tailscale-runtime=WARN: Tailscale router/netfilter health warning' "$case_root/real-health/rp-filter-report.txt" \
        || fail "real Tailscale router/netfilter warning was not visible"

    local dry="$case_root/dry-run"
    install -d "$dry/proc/sys/net/ipv4/conf/all" "$dry/proc/sys/net/ipv4/conf/default"
    printf '1\n' > "$dry/proc/sys/net/ipv4/conf/all/rp_filter"
    printf '1\n' > "$dry/proc/sys/net/ipv4/conf/default/rp_filter"
    printf 'original\n' > "$dry/99-security-hardening.conf"
    env PATH="$mock_bin:$PATH" HARDEN_SOURCE_ONLY=1 HARDEN_PROC_SYS_ROOT="$dry/proc/sys" \
        HARDEN_SYSCTL_CONFIG="$dry/99-security-hardening.conf" HARDEN_RP_FILTER_REPORT="$dry/rp-filter-report.txt" \
        RP_TEST_TAILSCALE_ACTIVE=1 RP_TEST_DEFAULT_ROUTES='default via 192.0.2.1 dev eth0' RP_TEST_COMMAND_LOG="$dry/commands.log" bash -c '
            source "$1/harden.sh"; trap - ERR EXIT
            sysctl_candidates() { printf "%s\\n" "net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1"; }
            MODE=dry-run; configure_sysctl
            grep -Fxq original "$HARDEN_SYSCTL_CONFIG"
            [[ ! -e "$HARDEN_RP_FILTER_REPORT" ]]
        ' _ "$repo_root" "$dry" || fail "rp_filter dry-run wrote managed state"

    sysctl_section="$(sed -n '/^configure_sysctl()/,/^}/p' "$repo_root/harden.sh")"
    ! grep -Eq 'tailscale (up|set)([[:space:]]|$)' <<<"$sysctl_section" \
        || fail "rp_filter policy changed Tailscale preferences"
}

case "${HARDEN_REGRESSION_FILTER:-all}" in
    kernel)
        run_kernel_gate_test
        ;;
    noop)
        run_runtime_noop_tests
        ;;
    rp-filter)
        run_rp_filter_tests
        run_kernel_gate_test
        ;;
    compiler)
        run_compiler_tests
        ;;
    systemd)
        run_systemd_idempotency_tests
        ;;
    packages)
        run_packagekit_tests
        run_package_upgrade_tests
        run_residual_purge_tests
        run_firewall_inventory_tests
        ;;
    residual)
        run_residual_purge_tests
        ;;
    deleted-open)
        run_deleted_open_tests
        ;;
    login-timeout)
        run_login_timeout_tests
        ;;
    uefi-mor)
        run_uefi_mor_tests
        ;;
    ipv6-banner-motd-only)
        run_ipv6_banner_motd_tests
        ;;
    ipv6-banner-motd)
        run_ipv6_banner_motd_tests
        run_rp_filter_tests
        run_deleted_open_tests
        run_login_timeout_tests
        run_uefi_mor_tests
        run_kernel_gate_test
        ;;
    new-findings)
        run_lynis_summary_tests
        run_fail2ban_tests
        run_packagekit_tests
        run_package_upgrade_tests
        run_residual_purge_tests
        run_firewall_inventory_tests
        run_compiler_tests
        run_binfmt_tests
        run_systemd_idempotency_tests
        run_runtime_noop_tests
        run_deleted_open_tests
        run_login_timeout_tests
        run_uefi_mor_tests
        run_ipv6_banner_motd_tests
        run_rp_filter_tests
        run_iowait_tests
        ;;
    all)
        run_logging_tests
        run_aide_tests
        run_kernel_gate_test
        run_lynis_summary_tests
        run_fail2ban_tests
        run_packagekit_tests
        run_package_upgrade_tests
        run_residual_purge_tests
        run_firewall_inventory_tests
        run_compiler_tests
        run_binfmt_tests
        run_systemd_idempotency_tests
        run_runtime_noop_tests
        run_deleted_open_tests
        run_login_timeout_tests
        run_uefi_mor_tests
        run_ipv6_banner_motd_tests
        run_rp_filter_tests
        run_iowait_tests
        ;;
    *) fail "unknown HARDEN_REGRESSION_FILTER value" ;;
esac
printf 'Runtime regression tests passed.\n'
