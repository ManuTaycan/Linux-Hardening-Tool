#!/usr/bin/env bash
# Integration of Apply orchestration with explicit mocked host boundaries.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
for scenario in fresh existing converged install-failure unit-failure nft-failure enable-failure start-failure health-failure rollback-failure; do
    env HARDEN_SOURCE_ONLY=1 TEST_CASE="$scenario" TEST_ROOT="$test_root/$scenario" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        mkdir -p "$TEST_ROOT"; MODE=apply; BACKUP_DIR="$TEST_ROOT"; SSH_PORT=22
        log() { printf "%s\n" "$*" >> "$TEST_ROOT/log"; }
        record_change() { :; }; record_skip() { :; }
        ip() { return 1; }; ssh_firewall_ports() { printf "22\n"; }
        docker_egress_requested() { return 1; }
        run_streamed() { "$@"; }
        systemd_verify_unit() { [[ "$TEST_CASE" != unit-failure ]]; }
        systemctl() {
            printf "%s\n" "$*" >> "$TEST_ROOT/systemctl"
            case "$1:$TEST_CASE" in
                is-active:fresh|is-active:start-failure|enable:enable-failure|start:start-failure) return 1 ;;
                *) return 0 ;;
            esac
        }
        nft() {
            printf "%s\n" "$*" >> "$TEST_ROOT/nft"
            if [[ "$1" == -s ]]; then
                [[ "$TEST_CASE" != fresh ]] || return 1
                printf "previous snapshot\n"
            fi
        }
        transaction_copy() { printf "%s\n" "$*" >> "$TEST_ROOT/copies"; }
        transaction_restore() { printf "%s\n" "$*" >> "$TEST_ROOT/restores"; }
        install_managed_file() {
            cat > "$TEST_ROOT/${1##*/}"
            [[ "$TEST_CASE" != install-failure ]] || return 1
            MANAGED_FILE_CHANGED=1
            [[ "$TEST_CASE" != converged ]] || MANAGED_FILE_CHANGED=0
        }
        firewall_helper_command() {
            printf "%s\n" "$*" >> "$TEST_ROOT/helper"
            case "$1" in
                --api-rule|--path-check) return 0 ;;
                --check-stdin) cat > "$TEST_ROOT/candidate" ;;
                --apply-stdin)
                    cat > "$TEST_ROOT/restored-runtime"
                    [[ "$TEST_CASE" != rollback-failure ]]
                    ;;
                *) return 1 ;;
            esac
        }
        firewall_apply_persisted() {
            printf "apply\n" >> "$TEST_ROOT/helper"
            [[ "$TEST_CASE" != nft-failure && "$TEST_CASE" != rollback-failure ]]
        }
        ssh_owned_firewall_allows_ports() { [[ "$TEST_CASE" != health-failure ]]; }
        case "$TEST_CASE" in
            fresh|existing|converged)
                configure_firewall
                [[ "$FIREWALL_STATUS" == OK* ]]
                ! grep -Eq "restart|reload server" "$TEST_ROOT/systemctl"
                if [[ "$TEST_CASE" == converged ]]; then ! grep -Fq daemon-reload "$TEST_ROOT/systemctl"; fi
                ;;
            *)
                ! configure_firewall --recoverable
                [[ "$FIREWALL_STATUS" == FAILED* ]]
                if [[ "$TEST_CASE" != unit-failure ]]; then
                    grep -Fxq "previous snapshot" "$TEST_ROOT/restored-runtime"
                    grep -Fq firewall-service "$TEST_ROOT/restores"
                fi
                if [[ "$TEST_CASE" == rollback-failure ]]; then [[ "$FIREWALL_STATUS" == *restored=0* ]]; fi
                ;;
        esac
        [[ ! -f "$TEST_ROOT/nft" ]] || ! grep -Eq "^delete|flush" "$TEST_ROOT/nft"
    ' _ "$repo_root"
done
printf 'Firewall Apply orchestration, rollback and converged no-restart: PASS\n'
