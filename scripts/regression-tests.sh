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
        KERNEL_MODPROBE_LOG="$module_log" KERNEL_COMMAND_LOG="$command_log" KERNEL_TAILSCALE_ACTIVE=0 bash -c '
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
            lock_kernel_modules_late
            [[ "$(wc -l < "$3")" == 1 ]]
        ' _ "$repo_root" "$control" "$writes" "$case_root/changes.tsv" "$case_root/backup" \
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
        [[ "$(grep -Fc "REBOOT_REQUIRED=1" "$1/harden.sh")" == 2 ]]
    ' _ "$repo_root" || fail "initramfs/GRUB/reboot-required change gating regressed"
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
    kernel)
        run_kernel_gate_test
        ;;
    noop)
        run_runtime_noop_tests
        ;;
    compiler)
        run_compiler_tests
        ;;
    new-findings)
        run_lynis_summary_tests
        run_fail2ban_tests
        run_packagekit_tests
        run_compiler_tests
        run_binfmt_tests
        run_systemd_idempotency_tests
        run_runtime_noop_tests
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
        run_systemd_idempotency_tests
        run_runtime_noop_tests
        run_iowait_tests
        ;;
    *) fail "unknown HARDEN_REGRESSION_FILTER value" ;;
esac
printf 'Runtime regression tests passed.\n'
