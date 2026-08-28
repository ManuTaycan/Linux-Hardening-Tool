#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_path="${1:-$PWD/hardening-test-artifacts-$(date +%Y%m%d-%H%M%S).tar.gz}"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT

copy_if_readable() {
    local source="$1" target="$2"
    [[ -r "$source" ]] || return 0
    install -d -m 0700 "$(dirname "$temp_dir/$target")"
    cp -- "$source" "$temp_dir/$target"
}

{
    printf 'Collected: %s\n' "$(date --iso-8601=seconds)"
    printf 'Kernel: %s\n' "$(uname -a)"
    printf 'Script version: %s\n' "$(sed -nE 's/^readonly SCRIPT_VERSION="([^"]+)"$/\1/p' "$repo_root/harden.sh")"
    git -C "$repo_root" rev-parse HEAD 2>/dev/null || true
} > "$temp_dir/summary.txt"

copy_if_readable /etc/os-release system/os-release
copy_if_readable /var/log/server-hardening.log reports/server-hardening.log
copy_if_readable /root/hardening-open-findings.txt reports/hardening-open-findings.txt
copy_if_readable /root/systemd-hardening-report.txt reports/systemd-hardening-report.txt
copy_if_readable /root/lynis-after-hardening-pass1.txt reports/lynis-pass1.txt
copy_if_readable /root/lynis-after-hardening.txt reports/lynis-final.txt

systemctl --failed --no-pager > "$temp_dir/systemd-failed.txt" 2>&1 || true
for service in ssh.service rsyslog.service fail2ban.service unattended-upgrades.service; do
    systemctl status "$service" --no-pager > "$temp_dir/${service}.status.txt" 2>&1 || true
done

tar -C "$temp_dir" -czf "$output_path" .
printf 'Created %s\n' "$output_path"
printf 'Review the archive for sensitive information before uploading it.\n'
