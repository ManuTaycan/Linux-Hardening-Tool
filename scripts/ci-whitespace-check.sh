#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

resolve_commit() {
    local ref="$1"
    git rev-parse --verify "${ref}^{commit}"
}

event_name="${GITHUB_EVENT_NAME:-}"
head_ref="${GITHUB_SHA:-HEAD}"

if [[ "$event_name" == "pull_request" || "$event_name" == "pull_request_target" ]]; then
    base_ref="${GITHUB_BASE_REF:-}"
    [[ "$base_ref" =~ ^[A-Za-z0-9._/-]+$ ]] || {
        printf 'Unable to resolve pull-request base ref safely\n' >&2
        exit 1
    }
    base_commit="$(resolve_commit "refs/remotes/origin/${base_ref}")"
    head_commit="$(resolve_commit "$head_ref")"
    git diff --check "$base_commit" "$head_commit"
else
    head_commit="$(resolve_commit "$head_ref")"
    parent_commit="$(git rev-parse --verify "${head_commit}^" 2>/dev/null || true)"
    if [[ -n "$parent_commit" ]]; then
        git diff --check "$parent_commit" "$head_commit"
    else
        git diff --check "$head_commit"
    fi
fi
