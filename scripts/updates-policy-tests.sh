#!/usr/bin/env bash
# File fixtures and mocked systemctl/unattended boundaries only. No host writes.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
for scenario in success conflict removal reboot parse validation timer dry-run converged; do
    env HARDEN_SOURCE_ONLY=1 TEST_CASE="$scenario" TEST_ROOT="$test_root/$scenario" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        mkdir -p "$TEST_ROOT"; MODE=apply; OS_ID=ubuntu
        [[ "$TEST_CASE" != dry-run ]] || MODE=dry-run
        log() { :; }; record_skip() { printf "%s\n" "$*" >> "$TEST_ROOT/skip"; }
        transaction_copy() { printf "%s\n" "$*" >> "$TEST_ROOT/copy"; }
        transaction_restore() { printf "%s\n" "$*" >> "$TEST_ROOT/restore"; }
        install_managed_file() { cat > "$TEST_ROOT/${1##*/}"; }
        updates_timer_state() { case "$1" in is-enabled) printf "disabled\n" ;; is-active) printf "inactive\n" ;; esac; }
        systemctl() {
            local IFS=" "
            printf "%s\n" "$*" >> "$TEST_ROOT/timers"
            [[ "$TEST_CASE" != timer || "$1" != enable ]]
        }
        run() { "$@"; }
        unattended-upgrade() { :; }
        package_unattended_capture() {
            printf "validate\n" >> "$TEST_ROOT/order"
            [[ "$TEST_CASE" != validation ]] || { PACKAGE_COMMAND_ERROR_CLASS=package-command-error; return 1; }
        }
        # Real policy validator parses an apt-config-shaped merged dump.
        # Real APT merging is exercised separately below on Linux.
        apt-config() {
            [[ "$TEST_CASE" != parse ]] || return 100
            local origin
            while IFS= read -r origin; do printf "Unattended-Upgrade::Origins-Pattern:: \"%s\";\n" "$origin"; done < <(unattended_security_origins)
            [[ "$TEST_CASE" != conflict ]] || printf "Unattended-Upgrade::Allowed-Origins:: \"ThirdParty:stable\";\n"
            local key value
            for key in Remove-Unused-Kernel-Packages Remove-New-Unused-Dependencies Remove-Unused-Dependencies Automatic-Reboot Automatic-Reboot-WithUsers Allow-downgrade AutoFixInterruptedDpkg; do
                value=false
                [[ "$TEST_CASE:$key" != removal:Remove-Unused-Dependencies && "$TEST_CASE:$key" != reboot:Automatic-Reboot ]] || value=true
                printf "Unattended-Upgrade::%s \"%s\";\n" "$key" "$value"
            done
            for key in Enable Update-Package-Lists Unattended-Upgrade; do printf "APT::Periodic::%s \"1\";\n" "$key"; done
        }
        configure_updates
        case "$TEST_CASE" in
            success|converged)
                [[ "$UPDATES_STATUS" == OK ]]
                grep -Fq "enable --now apt-daily.timer apt-daily-upgrade.timer" "$TEST_ROOT/timers"
                [[ ! -e "$TEST_ROOT/restore" ]]
                ;;
            dry-run)
                [[ "$UPDATES_STATUS" == PLANNED* && ! -e "$TEST_ROOT/order" && ! -e "$TEST_ROOT/timers" ]]
                ;;
            *)
                [[ "$UPDATES_STATUS" == FAILED* ]]
                automatic_updates_failed
                grep -Fq updates-policy "$TEST_ROOT/restore"
                if [[ "$TEST_CASE" != timer ]]; then [[ ! -e "$TEST_ROOT/timers" ]] || ! grep -Fq "enable --now" "$TEST_ROOT/timers"; fi
                ;;
        esac
        grep -Fq "#clear Unattended-Upgrade::Allowed-Origins;" "$TEST_ROOT/52unattended-hardening"
        ! grep -Eq "Remove-.*\"true\"|Automatic-Reboot.*\"true\"" "$TEST_ROOT/52unattended-hardening"
        [[ ! -e "$TEST_ROOT/timers" ]] || ! grep -Eq "(stop|disable).*(service|unattended|dpkg)" "$TEST_ROOT/timers"
    ' _ "$repo_root"
done

if command -v apt-config >/dev/null 2>&1; then
    env HARDEN_SOURCE_ONLY=1 TEST_ROOT="$test_root/real-apt" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        mkdir -p "$TEST_ROOT/parts"
        printf "Dir::Etc::parts \"%s\";\nDir::Etc::main \"%s/nonexistent\";\n" "$TEST_ROOT/parts" "$TEST_ROOT" > "$TEST_ROOT/apt.conf"
        export APT_CONFIG="$TEST_ROOT/apt.conf"
        printf "Unattended-Upgrade::Allowed-Origins { \"ThirdParty:stable\"; };\n" > "$TEST_ROOT/parts/50vendor"
        printf "APT::Periodic::Enable \"1\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > "$TEST_ROOT/parts/20auto-upgrades"
        for OS_ID in ubuntu debian; do
            render_unattended_policy > "$TEST_ROOT/parts/52unattended-hardening"
            validate_unattended_policy
            printf "Unattended-Upgrade::Allowed-Origins { \"ThirdParty:stable\"; };\n" > "$TEST_ROOT/parts/99conflict"
            ! validate_unattended_policy
            rm "$TEST_ROOT/parts/99conflict"
            printf "Unattended-Upgrade::Automatic-Reboot \"true\";\n" > "$TEST_ROOT/parts/99conflict"
            ! validate_unattended_policy
            rm "$TEST_ROOT/parts/99conflict"
        done
    ' _ "$repo_root"
else
    printf 'INFO: apt-config unavailable locally; real APT list merge is covered by Linux CI.\n'
fi
printf 'Conservative unattended policy, conflicts, timers, rollback and dry-run: PASS\n'
