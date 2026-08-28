#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
report() {
    printf 'FAIL: %s\n' "$*" >&2
    fail=1
}

check_lf() {
    local file="$1" output
    output="$(LC_ALL=C awk '/\r$/ {printf "%s:%d: CRLF\n", FILENAME, NR}' "$file")"
    [[ -z "$output" ]] || { printf '%s\n' "$output" >&2; report "CRLF line ending in ${file}"; }
}

check_bom() {
    local file="$1" prefix
    prefix="$(LC_ALL=C od -An -tx1 -N3 "$file" | tr -d ' \n')"
    [[ "$prefix" != "efbbbf" ]] || report "UTF-8 BOM in ${file}"
}

for file in harden.sh install.sh scripts/*.sh; do
    check_lf "$file"
    check_bom "$file"
done

[[ -x harden.sh ]] || report "harden.sh is not executable"
[[ -x install.sh ]] || report "install.sh is not executable"

while IFS= read -r match; do
    [[ -z "$match" ]] || { printf '%s\n' "$match" >&2; report "naked return found"; }
done < <(awk '!/^[[:space:]]*#/ && /^[[:space:]]*return[[:space:]]*$/ {printf "harden.sh:%d:%s\n", NR, $0}' harden.sh)

while IFS= read -r match; do
    [[ -z "$match" ]] || { printf '%s\n' "$match" >&2; report "possible SIGPIPE early-reader pipeline"; }
done < <(awk '!/^[[:space:]]*#/ && /\|[[:space:]]*(head|grep[[:space:]]+-m|sed[[:space:]][^|]*[[:space:]]q([[:space:]]|$)|awk[[:space:]][^|]*[[:space:]]exit)/ {printf "harden.sh:%d:%s\n", NR, $0}' harden.sh)

while IFS= read -r match; do
    [[ -z "$match" ]] || { printf '%s\n' "$match" >&2; report "managed SSH Port directive found"; }
done < <(awk '!/^[[:space:]]*#/ && /^[[:space:]]*Port[[:space:]]+[0-9]/ {printf "harden.sh:%d:%s\n", NR, $0}' harden.sh)

while IFS= read -r match; do
    [[ -z "$match" ]] || { printf '%s\n' "$match" >&2; report "GRUB credential logic found"; }
done < <(awk '!/^[[:space:]]*#/ && /(grub-mkpasswd|password_pbkdf2|^[[:space:]]*set[[:space:]]+superusers)/ {printf "harden.sh:%d:%s\n", NR, $0}' harden.sh)

mapfile -t phases < <(awk '/^[[:space:]]*phase[[:space:]]+[0-9][0-9][[:space:]]+18[[:space:]]+"/ {print NR ":" $2 ":" $4}' harden.sh)
expected=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18)
main_line="$(awk '/^main\(\)/ {print NR; exit}' harden.sh)"
[[ ${#phases[@]} -eq 18 ]] || report "expected exactly 18 phase calls, found ${#phases[@]}"
for index in "${!phases[@]}"; do
    IFS=: read -r line number _ <<<"${phases[$index]}"
    [[ "$number" == "${expected[$index]}" ]] || report "phase position $((index + 1)) is ${number}, expected ${expected[$index]}"
    [[ -n "$main_line" && "$line" -gt "$main_line" ]] || report "phase ${number} is outside main()"
done

aide_call_line="$(awk '/^[[:space:]]+configure_aide[[:space:]]*$/ {print NR; exit}' harden.sh)"
phase17_line="$(awk '/^[[:space:]]+phase[[:space:]]+17[[:space:]]+18[[:space:]]+/ {print NR; exit}' harden.sh)"
module_lock_line="$(awk '/^[[:space:]]+lock_kernel_modules_late[[:space:]]*$/ {print NR; exit}' harden.sh)"
if [[ -z "$aide_call_line" || -z "$phase17_line" || -z "$module_lock_line" \
    || "$aide_call_line" -ge "$phase17_line" || "$phase17_line" -ge "$module_lock_line" ]]; then
    report "kernel.modules_disabled final gate is not ordered after AIDE at phase 17"
fi

for streamed_command in update-grub update-initramfs augenrules chronyd rkhunter; do
    grep -Eq "run_streamed[[:space:]]+${streamed_command}([[:space:]]|$)" harden.sh \
        || report "${streamed_command} is not routed through synchronous logging"
done
if grep -Eq 'harden[.]sh.*[|][[:space:]]*tee|tee.*harden[.]sh' docs/TESTING.md README.md; then
    report "official harden.sh test documentation still requires external tee"
fi

script_version="$(sed -nE 's/^readonly SCRIPT_VERSION="([^"]+)"$/\1/p' harden.sh)"
version_file="$(tr -d '\r\n' < VERSION)"
[[ -n "$script_version" && "$script_version" == "$version_file" ]] || report "VERSION does not match SCRIPT_VERSION"
sha256sum -c SHA256SUMS >/dev/null || report "SHA256SUMS does not verify"

[[ "$fail" -eq 0 ]] || exit 1
printf 'Static checks passed.\n'
