#!/usr/bin/env bash
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
mkdir "$test_root/scripts"
cp "$repo_root/Makefile" "$test_root/Makefile"
for script in harden.sh install.sh scripts/first.sh scripts/last.sh; do
    printf '#!/usr/bin/env bash\ntrue\n' > "$test_root/$script"
done
make --no-print-directory -C "$test_root" syntax
printf '#!/usr/bin/env bash\nif then\n' > "$test_root/scripts/last.sh"
if make --no-print-directory -C "$test_root" syntax > "$test_root/result" 2>&1; then
    printf 'FAIL: syntax target did not inspect the later shell script\n' >&2
    exit 1
fi
grep -Fq last.sh "$test_root/result"
printf 'Syntax target rejects errors in later expanded scripts: PASS\n'
