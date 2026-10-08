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
nft() { return 1; }
ssh_firewall_ports() { printf '2222\n'; }
# Capture the actual rendered nft candidate at its validation boundary.
# Reject validation deliberately so configure_firewall cannot install anything.
run_streamed() {
    if [[ "$1" == nft ]]; then cp "$4" "$test_root/candidate.nft"; return 1; fi
    "$@"
}
detect_ipv6_policy() { IPV6_POLICY=NOT_APPLICABLE; }
detect_rp_filter_routing_situation() { RP_FILTER_ROUTING_SITUATION=unknown; RP_FILTER_REASON=test; }
preserve_current_rp_filter_values() { :; }
sysctl_candidates() { printf 'net.ipv4.conf.all.forwarding=0\n'; }
ipv6_policy_candidates() { :; }
transaction_copy() { :; }
install_managed_file() { cat > "$1"; MANAGED_FILE_CHANGED=1; }
managed_sysctl_runtime_needs_reload() { return 1; }
sysctl() {
    if [[ "$1" == -p ]]; then return 0; fi
    if [[ -f "$HARDEN_SYSCTL_CONFIG" ]]; then
        awk '/^net.ipv4.conf.all.forwarding/ {print $3}' "$HARDEN_SYSCTL_CONFIG"
    else printf '0\n'; fi
}
tailscale_rp_filter_health() { RP_FILTER_RUNTIME_STATUS=OK; }
write_rp_filter_report() { :; }
write_ipv6_report() { :; }
export HARDEN_PROC_SYS_ROOT="$test_root/proc/sys" HARDEN_SYSCTL_CONFIG="$test_root/sysctl.conf"
mkdir -p "$HARDEN_PROC_SYS_ROOT/net/ipv4/conf/all"
touch "$HARDEN_PROC_SYS_ROOT/net/ipv4/conf/all/forwarding"
for state in absent empty enabled; do
    rm -f "$HARDEN_DOCKER_EGRESS_RULES" "$HARDEN_SYSCTL_CONFIG"
    case "$state" in
        empty) touch "$HARDEN_DOCKER_EGRESS_RULES" ;;
        enabled) printf 'iifname "docker0" oifname "eth0" ip saddr 172.17.0.0/16 tcp dport 443 counter accept\n' > "$HARDEN_DOCKER_EGRESS_RULES" ;;
    esac
    if configure_firewall --recoverable; then
        printf 'Unexpected firewall apply success\n' >&2; exit 1
    fi
    configure_sysctl
    if [[ "$state" == enabled ]]; then
        grep -Fq "include \"$HARDEN_DOCKER_EGRESS_RULES\"" "$test_root/candidate.nft"
        grep -Fxq 'net.ipv4.conf.all.forwarding = 1' "$HARDEN_SYSCTL_CONFIG"
    else
        ! grep -Fq 'include ' "$test_root/candidate.nft"
        grep -Fxq 'net.ipv4.conf.all.forwarding = 0' "$HARDEN_SYSCTL_CONFIG"
    fi
    grep -Fq 'tcp dport 2222' "$test_root/candidate.nft"
    grep -Fq 'type filter hook forward priority filter; policy drop;' "$test_root/candidate.nft"
done
printf 'Docker egress opt-in rendering and persistent forwarding: PASS\n'
