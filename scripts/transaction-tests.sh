#!/usr/bin/env bash
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
env HARDEN_SOURCE_ONLY=1 TEST_ROOT="$test_root" bash -c '
    source "$1/harden.sh"; trap - ERR EXIT
    MODE=apply; BACKUP_DIR="$TEST_ROOT/backup"; log() { :; }
    file="$TEST_ROOT/policy"; directory="$TEST_ROOT/tree"
    transaction_copy "$file" repeated
    printf "known-good\n" > "$file"
    transaction_copy "$file" repeated
    printf "candidate\n" > "$file"
    transaction_restore "$file" repeated
    [[ "$(cat "$file")" == known-good ]]
    rm "$file"
    transaction_copy "$file" repeated
    printf "new candidate\n" > "$file"
    transaction_restore "$file" repeated
    [[ ! -e "$file" ]]
    mkdir "$directory"; printf original > "$directory/original"
    transaction_copy "$directory" repeated-directory
    rm "$directory/original"; printf latest > "$directory/latest"
    transaction_copy "$directory" repeated-directory
    rm -rf "$directory"; mkdir "$directory"; touch "$directory/candidate"
    transaction_restore "$directory" repeated-directory
    [[ "$(cat "$directory/latest")" == latest && ! -e "$directory/original" && ! -e "$directory/candidate" && ! -e "$directory/tree" ]]
    ln -s "$TEST_ROOT/nonexistent" "$file"
    transaction_copy "$file" repeated-link
    rm "$file"; printf candidate > "$file"
    transaction_restore "$file" repeated-link
    [[ -L "$file" && "$(readlink "$file")" == "$TEST_ROOT/nonexistent" ]]
    MODE=dry-run
    transaction_copy "$TEST_ROOT/dry-run" dry-run
    transaction_restore "$TEST_ROOT/dry-run" dry-run
    [[ ! -e "$BACKUP_DIR/transactions/dry-run.absent" ]]
' _ "$repo_root"
printf 'Repeated absent/file/directory/symlink transaction snapshots: PASS\n'
