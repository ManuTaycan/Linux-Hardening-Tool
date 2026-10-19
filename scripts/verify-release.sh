#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for script in harden.sh install.sh scripts/*.sh; do bash -n "$script"; done
sha256sum -c SHA256SUMS
./scripts/ci-static-checks.sh

[[ -x harden.sh ]] || { printf 'harden.sh must be executable\n' >&2; exit 1; }
[[ -x install.sh ]] || { printf 'install.sh must be executable\n' >&2; exit 1; }
[[ "$(tr -d '\r\n' < VERSION)" == "$(sed -nE 's/^readonly SCRIPT_VERSION="([^"]+)"$/\1/p' harden.sh)" ]] \
    || { printf 'VERSION and SCRIPT_VERSION differ\n' >&2; exit 1; }

printf 'Release verification passed.\n'
