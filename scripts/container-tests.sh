#!/usr/bin/env bash
# Fixtures cannot change the actual host; test both detection and the early gate.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
for scenario in docker podman lxc nspawn kubernetes env-marker cgroup chroot userns unknown non-systemd no-bus host dry-run; do
    env HARDEN_SOURCE_ONLY=1 TEST_CASE="$scenario" TEST_ROOT="$test_root/$scenario" bash -c '
        source "$1/harden.sh"; trap - ERR EXIT
        mkdir -p "$TEST_ROOT/proc/1"; printf "systemd\n" > "$TEST_ROOT/proc/1/comm"
        MODE=apply; failed=0; mutations=0; container=""
        execution_file_exists() { [[ -e "$TEST_ROOT$1" ]]; }
        execution_read_file() { cat "$TEST_ROOT$1"; }
        die() { failed=1; }; log() { :; }
        systemctl() { [[ "$TEST_CASE" != no-bus ]]; }
        systemd-detect-virt() {
            case "$1:$TEST_CASE" in
                --container:docker) printf "docker\n"; return 0 ;;
                --container:podman) printf "podman\n"; return 0 ;;
                --container:lxc) printf "lxc\n"; return 0 ;;
                --container:nspawn) printf "systemd-nspawn\n"; return 0 ;;
                --container:unknown) return 2 ;;
                --chroot:chroot|--private-users:userns) return 0 ;;
                --container:*) printf "none\n"; return 1 ;;
                *) return 1 ;;
            esac
        }
        case "$TEST_CASE" in
            env-marker) container=oci ;;
            cgroup|kubernetes) printf "0::/kubepods.slice/pod-test/container\n" > "$TEST_ROOT/proc/1/cgroup" ;;
            non-systemd) printf "bash\n" > "$TEST_ROOT/proc/1/comm" ;;
            dry-run) MODE=dry-run; touch "$TEST_ROOT/.dockerenv" ;;
        esac
        if [[ "$TEST_CASE" == host || "$TEST_CASE" == dry-run ]]; then
            check_execution_environment
            [[ "$failed" == 0 ]]
        else
            ! check_execution_environment
            [[ "$failed" == 1 ]]
        fi
        # The complete main entry point must stop before prompting/logging and
        # all phase operations, even if root or a privileged container is used.
        if [[ "$TEST_CASE" != host && "$TEST_CASE" != dry-run ]]; then
            parse_args() { MODE=apply; }; check_root() { :; }
            ask_remote_logging() { mutations=1; }; init_logging() { mutations=1; }
            # Real die exits; use a subshell to observe that main stops there.
            die() { exit 78; }
            if (main --apply); then exit 1; else [[ "$?" == 78 ]]; fi
            [[ "$mutations" == 0 ]]
        fi
    ' _ "$repo_root"
done
printf 'Container/chroot/userns detection and pre-mutation Apply gate: PASS\n'
