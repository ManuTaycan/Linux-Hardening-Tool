#!/usr/bin/env bash
# Isolated mocks: never load a firewall or write a host sysctl.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
export HARDEN_SOURCE_ONLY=1 HARDEN_DOCKER_EGRESS_RULES="$test_root/egress.rules"
source "$repo_root/harden.sh"
trap - ERR EXIT
trap 'rm -rf -- "$test_root"' EXIT
MODE=apply
log() { :; }
record_skip() { :; }
record_change() { :; }
systemctl() { return 1; }
ip() { return 1; }
mock_protected=0
mock_sysctl_fail=0
nft() {
    [[ "$mock_protected" -eq 1 ]] || return 1
    printf 'type filter hook forward priority filter; policy drop;\n'
}
ssh_firewall_ports() { printf '2222\n'; }
# Mock only the privileged helper boundary; real trust/grammar checks run in
# firewall-helper-tests.py and the separate Linux network namespace test.
firewall_helper_command() {
    case "$1" in
        --docker-select) [[ "$state" == absent ]] || printf '%s\n' "$HARDEN_DOCKER_EGRESS_RULES" ;;
        --api-rule) return 0 ;;
        --check-stdin) cat > "$test_root/candidate.nft"; return 1 ;;
        --docker-check) [[ -s "$2" && ! -L "$2" && "$state" != unsafe ]] ;;
        *) return 1 ;;
    esac
}
detect_ipv6_policy() { IPV6_POLICY=NOT_APPLICABLE; }
detect_rp_filter_routing_situation() { RP_FILTER_ROUTING_SITUATION=unknown; RP_FILTER_REASON=test; }
preserve_current_rp_filter_values() { :; }
sysctl_candidates() { printf 'net.ipv4.conf.all.forwarding=0\n'; }
ipv6_policy_candidates() { :; }
transaction_copy() { [[ ! -f "$1" ]] || cp "$1" "$test_root/$2"; }
transaction_restore() { cp "$test_root/$2" "$1"; }
install_managed_file() { cat > "$1"; MANAGED_FILE_CHANGED=1; }
managed_sysctl_runtime_needs_reload() { return 1; }
sysctl() {
    if [[ "$1" == -p ]]; then
        awk '/^net.ipv4.conf.all.forwarding/ {print $3}' "$HARDEN_SYSCTL_CONFIG" > "$test_root/runtime"
    elif [[ "$1" == -w ]]; then
        [[ "$mock_sysctl_fail" -ne 1 || "$2" != net.ipv4.conf.all.forwarding=1 ]] || return 1
        printf '%s\n' "${2##*=}" > "$test_root/runtime"
    elif [[ -f "$test_root/runtime" ]]; then cat "$test_root/runtime"
    else printf '0\n'; fi
}
tailscale_rp_filter_health() { RP_FILTER_RUNTIME_STATUS=OK; }
write_rp_filter_report() { :; }
write_ipv6_report() { :; }
export HARDEN_PROC_SYS_ROOT="$test_root/proc/sys" HARDEN_SYSCTL_CONFIG="$test_root/sysctl.conf"
mkdir -p "$HARDEN_PROC_SYS_ROOT/net/ipv4/conf/all"
touch "$HARDEN_PROC_SYS_ROOT/net/ipv4/conf/all/forwarding"
for state in absent empty enabled unsafe missing; do
    export HARDEN_DOCKER_EGRESS_RULES="$test_root/egress.rules"
    mock_protected=0; mock_sysctl_fail=0
    rm -f "$HARDEN_DOCKER_EGRESS_RULES" "$HARDEN_SYSCTL_CONFIG" "$test_root/runtime"
    case "$state" in
        empty) touch "$HARDEN_DOCKER_EGRESS_RULES" ;;
        enabled|unsafe) printf 'iifname "docker0" oifname "eth0" ip saddr 172.17.0.0/16 tcp dport 443 counter accept\n' > "$HARDEN_DOCKER_EGRESS_RULES" ;;
    esac
    [[ ! -e "$HARDEN_DOCKER_EGRESS_RULES" ]] || chmod 600 "$HARDEN_DOCKER_EGRESS_RULES"
    [[ "$state" != unsafe ]] || chmod 666 "$HARDEN_DOCKER_EGRESS_RULES"
    [[ "$state" != absent ]] || unset HARDEN_DOCKER_EGRESS_RULES
    if configure_firewall --recoverable; then
        printf 'Unexpected firewall apply success\n' >&2; exit 1
    fi
    if [[ "$state" == empty || "$state" == unsafe || "$state" == missing ]]; then
        ! configure_sysctl
        [[ ! -e "$HARDEN_SYSCTL_CONFIG" ]]
        continue
    fi
    configure_sysctl
    if [[ "$state" == enabled ]]; then
        grep -Fq "include \"$HARDEN_DOCKER_EGRESS_RULES\"" "$test_root/candidate.nft"
        grep -Fxq 'net.ipv4.conf.all.forwarding = 0' "$HARDEN_SYSCTL_CONFIG"
        [[ "$DOCKER_FORWARDING_DEFERRED" -eq 1 && "$(sysctl -n net.ipv4.conf.all.forwarding)" == 0 ]]
        ! activate_deferred_docker_forwarding
        [[ "$(sysctl -n net.ipv4.conf.all.forwarding)" == 0 ]]
        mock_protected=1; mock_sysctl_fail=1
        ! activate_deferred_docker_forwarding
        [[ "$DOCKER_FORWARDING_RESTORE_FAILED" -eq 0 && "$(sysctl -n net.ipv4.conf.all.forwarding)" == 0 ]]
        grep -Fxq 'net.ipv4.conf.all.forwarding = 0' "$HARDEN_SYSCTL_CONFIG"
        mock_sysctl_fail=0
        activate_deferred_docker_forwarding
        grep -Fxq 'net.ipv4.conf.all.forwarding = 1' "$HARDEN_SYSCTL_CONFIG"
        [[ "$DOCKER_FORWARDING_DEFERRED" -eq 0 && "$(sysctl -n net.ipv4.conf.all.forwarding)" == 1 ]]
        configure_sysctl
        [[ "$DOCKER_FORWARDING_DEFERRED" -eq 0 && "$(sysctl -n net.ipv4.conf.all.forwarding)" == 1 ]]
    else
        ! grep -Fq 'include ' "$test_root/candidate.nft"
        grep -Fxq 'net.ipv4.conf.all.forwarding = 0' "$HARDEN_SYSCTL_CONFIG"
    fi
    grep -Fq 'tcp dport 2222' "$test_root/candidate.nft"
    grep -Fq 'type filter hook forward priority filter; policy drop;' "$test_root/candidate.nft"
done
printf 'Docker egress opt-in rendering and persistent forwarding: PASS\n'
