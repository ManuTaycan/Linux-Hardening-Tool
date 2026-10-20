#!/usr/bin/env bash
# Query/render boundaries only; no host firewall or interface writes.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for scenario in nondefault upper leading-zero ssh-udp zero too-large excessive injected multiple query-failure missing-tool; do
    env HARDEN_SOURCE_ONLY=1 TEST_WG_CASE="$scenario" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        wg() {
            [[ "$#" == 3 && "$1:$2:$3" == show:wg0:listen-port ]] || return 64
            case "$TEST_WG_CASE" in
                nondefault) printf "51829\n" ;;
                upper) printf "65535\n" ;;
                leading-zero) printf "00053\n" ;;
                ssh-udp) printf "22\n" ;;
                zero) printf "0\n" ;;
                too-large) printf "65536\n" ;;
                excessive) printf "123456\n" ;;
                injected) printf "51829; accept\n" ;;
                multiple) printf "51829\n53\n" ;;
                query-failure) return 1 ;;
                *) return 127 ;;
            esac
        }
        command() {
            if [[ "$TEST_WG_CASE" == missing-tool && "${1:-}:${2:-}" == -v:wg ]]; then return 1; fi
            builtin command "$@"
        }
        case "$TEST_WG_CASE" in
            nondefault|upper|leading-zero|ssh-udp)
                result="$(wireguard_transport_rule)"
                case "$TEST_WG_CASE" in nondefault) port=51829 ;; upper) port=65535 ;; leading-zero) port=53 ;; ssh-udp) port=22 ;; esac
                [[ "$result" == "        udp dport $port accept comment \"preserve WireGuard UDP transport wg0\"" ]]
                ;;
            *) ! wireguard_transport_rule ;;
        esac
    ' _ "$repo_root"
done
printf 'WireGuard measured UDP listener, strict ports and unavailable query: PASS\n'
