#!/usr/bin/env bash
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for result in timestamp-lock zero-error mixed-error success; do
    env HARDEN_SOURCE_ONLY=1 TEST_RESULT="$result" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        MODE=apply; log() { :; }; emit_block() { cat >/dev/null; }
        HARDEN_APT_LOCK_MAX_ATTEMPTS=1
        unattended-upgrade() {
            case "$TEST_RESULT" in
                timestamp-lock) printf "2026-10-19 12:00:00,000 ERROR Lock could not be acquired (another package manager running?)\n" ;;
                zero-error) printf "2026-10-19 12:00:00,000 DEBUG upgrade result: False broken configuration\n" ;;
                mixed-error) printf "Lock could not be acquired (another package manager running?)\nERROR: dependency failure\n" ;;
                success) printf "upgrade result: True\n" ;;
            esac
            return 0
        }
        if [[ "$TEST_RESULT" == success ]]; then
            package_unattended_capture test --dry-run --debug
            [[ "$PACKAGE_COMMAND_ERROR_CLASS" == none ]]
        else
            if package_unattended_capture test --dry-run --debug; then exit 1; else status=$?; fi
            if [[ "$TEST_RESULT" == timestamp-lock ]]; then
                [[ "$status" == 75 && "$PACKAGE_COMMAND_ERROR_CLASS" == lock-wait-expired ]]
            else
                [[ "$status" == 1 && "$PACKAGE_COMMAND_ERROR_CLASS" == package-command-error && "$PACKAGE_COMMAND_LOCK_STATUS" == not-contended ]]
            fi
        fi
    ' _ "$repo_root"
done
printf 'Unattended results with logger prefixes, zero exit and mixed errors: PASS\n'
