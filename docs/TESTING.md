# Testing

## Scope and safety

Run target-system tests only in an approved maintenance window with a current
snapshot or backup, a verified recovery path, and a second authenticated SSH
session. Start with Dry-run. Run Apply directly in a TTY without external tee:
the tool supplies the complete ANSI-free log at /var/log/server-hardening.log.

Never create intentional failed logins against the remote administrator. Never
change Tailscale preferences, routes, exit-node state, or firewall ownership
outside the test scope. Redact all exported logs and archives before sharing.

## Local and CI checks

For a repository checkout:

~~~bash
bash -n harden.sh
bash -n install.sh
bash -n scripts/*.sh
make check
sha256sum -c SHA256SUMS
git diff --check
~~~

The GitHub Actions workflow runs whitespace validation, ShellCheck, static
checks, regression tests, checksum validation, help validation, and isolated
installer tests. Linux CI is authoritative for the full mode-sensitive
regression suite.

## Historical acceptance evidence

These results are recorded evidence from Ubuntu 26.04.1 target testing. They
are not a general release certification, and they do not validate later changes
unless the exact commit is stated in its PR.

| Area | Recorded evidence |
| --- | --- |
| Fresh aggressive Apply | Lynis 63 → 87; AIDE baseline rebuilt 1 |
| Converged Apply | Lynis 87 → 87; AIDE baseline rebuilt 0; no package changes, failed services, rollbacks, or reboot request; Phase 18 SUCCESS |
| Tailscale and kernel lock | Patched reboot confirmed Netfilter/NAT preload before tailscaled, healthy IPv4/IPv6 postrouting and MASQUERADE state, Tailscale health clear, successful ping, and kernel.modules_disabled=1 only after the runtime gate |
| Failed-login and timeout | Failed-login status OK through the modern journal/SSH configuration path; interactive TMOUT=900; non-interactive shell unchanged; Lynis recorded both checks |
| UEFI MOR | Runtime and efivarfs available; standardized MOR variables absent; status UNSUPPORTED; detection-only, no EFI variable modification |
| Deleted-open files | Only /memfd:systemd-udevd (deleted) remained; classified anonymous-memfd, visible but non-actionable; no automatic restart, kill, or reboot |
| IPv6, banners, and MOTD | Conservative IPv6 policy, authorized-access banners, and presentation-only MOTD controls accepted on the tested target |

The current repository remains pre-release. Perform the relevant target tests
again for any feature branch or release candidate that changes these paths.

## Baseline Apply checklist

~~~bash
sha256sum -c SHA256SUMS
bash -n harden.sh
sudo ./harden.sh --dry-run --aggressive
sudo ./harden.sh --apply --aggressive
sudo ./harden.sh --apply --aggressive
systemctl --failed --no-pager
sudo apt-get check
sudo lynis audit system
~~~

Expected properties:

- Apply reaches Phase 18 with SUCCESS.
- The second Apply is converged: it does not introduce unexpected package
  changes, rollbacks, service failures, or a reboot request.
- AIDE validates the active runtime configuration, database, check-service
  context, and timer before it reports success.
- The final summary uses a measured pre-hardening baseline; Dry-run reports
  N/A / NOT RUN and does not create a Lynis baseline report.
- Preserve the console reports and report.dat files before comparing different
  Lynis scores. A score difference alone is not a root-cause finding.

## Tailscale and final kernel gate

Use an approved peer in place of <TAILSCALE-PEER>.

~~~bash
sudo ./harden.sh --apply --aggressive
sudo reboot
sysctl kernel.modules_disabled
systemctl status kernel-module-lockdown.service --no-pager
sudo cat /root/kernel-module-lockdown-report.txt
iptables -t nat -S POSTROUTING
ip6tables -t nat -S POSTROUTING
tailscale status
tailscale ping <TAILSCALE-PEER>
nft list table inet hardening_filter
systemctl --failed --no-pager
sudo apt-get check
sudo ./harden.sh --apply --aggressive
~~~

The lock may be set only after the runtime gate proves required netfilter/NAT,
firewall, and Tailscale conditions. A failed gate must leave the value writable
and record a diagnostic; it must not modify Tailscale preferences.

## SSH and optional port migration

A port change is optional and is not a primary security control. Keep the old
port until a separately proven new connection exists.

~~~bash
# Inspect the plan first.
sudo ./harden.sh --dry-run --aggressive --ssh-port 2222

# Stage: firewall first, then dual listeners and Fail2ban coverage.
sudo ./harden.sh --apply --aggressive --ssh-port 2222
ss -H -ltn
sudo cat /root/ssh-port-migration-report.txt
sudo cat /root/ssh-port-migration-state.conf
~~~

Stop here. From a separate terminal, establish and verify a real new SSH session
on port 2222. Only then may the old port be retired:

~~~bash
sudo ./harden.sh --apply --aggressive --non-interactive --retire-ssh-port
ss -H -ltn
sudo ./harden.sh --apply --aggressive --non-interactive --retire-ssh-port
~~~

For socket-activated SSH, ssh.socket is the listener carrier and an inactive
ssh.service can be normal. A port stage or retire may restart ssh.socket once;
normal unchanged SSH hardening must touch neither unit. If normal configuration
changed during a socket migration, an already active ssh.service may receive one
reload only. Never accept an automatic SSH service restart.

## systemd exposure and acct reporting

~~~bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/systemd-hardening-report.txt
systemctl is-active fail2ban.service ssh.service tailscaled.service
sudo fail2ban-client ping
sudo fail2ban-client status sshd
sudo systemd-analyze security fail2ban.service unattended-upgrades.service networkd-dispatcher.service
sudo systemctl cat acct-monthly-report.service
sudo stat -c '%U:%G %a %n' /var/log/wtmp.report
sudo systemctl start --wait acct-monthly-report.service
sudo ./harden.sh --apply --aggressive
~~~

A candidate service drop-in must be merged-unit validated and healthy before it
is retained. Generic services keep a measurable exposure-improvement gate.
acct-monthly-report.service has a narrowly verified compatibility exception:
only /var/log/wtmp.report is writable under ProtectSystem=strict, with
root:adm mode 0640, and a successful one-shot validates the vendor path.
A converged second run must not recreate the report, reload units, or rerun the
one-shot.

## AppArmor and deleted-open files

~~~bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/apparmor-service-coverage-report.txt
sudo cat /root/deleted-open-files-report.txt
sudo lsof +L1
sudo ./harden.sh --apply --aggressive
~~~

Only an enabled, matching distribution-owned profile for an explicitly assessed
stable service may be transitioned. Parser validation, service-specific health,
and confinement must all succeed; otherwise the tool proves unload, restart,
health, and unconfined restoration before reporting rollback success.

For deleted-open files, only explicitly allowlisted service units can restart
once. SSH, Tailscale, networking, firewall, system, dbus, and unknown ownership
remain default-denied. Anonymous /memfd:* (deleted) entries with link count 0
remain visible as anonymous-memfd exceptions. They do not trigger restart or
reboot; normal persistent deleted files remain actionable or manual-review
findings.

## Failed-login logging and shell timeout

~~~bash
sudo ./harden.sh --apply --aggressive
grep -E '^(FAILLOG_ENAB|FTMP_FILE)' /etc/login.defs || true
systemctl is-active systemd-journald.service
sudo sshd -T | grep -E '^(loglevel|syslogfacility) '
sudo bash -ic 'echo "$TMOUT"'
sudo bash -c 'echo "$TMOUT"'
sudo ./harden.sh --apply --aggressive
~~~

On modern Ubuntu without lastb, legacy btmp/lastb evidence is N/A, not failed.
The accepted configuration proof is active journald plus effective SSH LogLevel
of INFO, VERBOSE, or more detailed, with a documented SyslogFacility. Optional
faillog is also N/A when unavailable. Do not claim a failed-login event was
written unless one was safely observed on an approved disposable test account.

btmp contents have audit priority: the tool captures metadata only, never backs
up, restores, truncates, or deletes its content.

## IPv6, banners, MOTD, and package residuals

~~~bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/ipv6-policy-report.txt
cmp -s /etc/issue /etc/issue.net
stat -c '%U:%G:%a %n' /etc/issue /etc/issue.net
cat /etc/issue
find /etc/update-motd.d -maxdepth 1 -type f -printf '%m %f\n' | sort
systemctl cat motd-news.service
grep -E '^ENABLED=' /etc/default/motd-news
sudo apt-get check
dpkg-query -W
~~~

IPv6 remains enabled by default. Active Tailscale, global addresses, routes,
listeners, forwarding, or ambiguous routing block disable. On a clear
non-forwarding host, validate all/default accept_source_route=-1 and
forwarding=0. Test the explicit --disable-ipv6 path only on a dedicated,
proven-unused IPv6 VM.

The two pre-login banners must be byte-identical, root:root, mode 0644, and
contain exactly:

~~~text
Authorized access only. Disconnect if you are not authorized.
~~~

On Ubuntu, 50-motd-news must remain executable because motd-news.service calls
it directly. News are disabled through the documented ENABLED=0 setting.
Presentation hooks may be disabled, but reboot-required remains executable and
no APT, unattended-upgrades, Ubuntu Pro, networking, or monitoring package is
removed.

Residual cleanup may purge only conclusively safe rc-only old kernel remnants
and rc-only grub-pc on a verified UEFI EFI-GRUB stack. It must never touch the
running kernel, kernel meta packages, current /boot artifacts, grub2-common,
installed EFI GRUB packages, or shim packages.

## AIDE, MOR, and package decisions

~~~bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/aide-lynis-FINT-4402-evidence.txt
sudo aide --config-check
sudo systemctl start dailyaidecheck.service
sudo systemctl status dailyaidecheck.service dailyaidecheck.timer --no-pager
sudo cat /root/uefi-mor-report.txt
sudo ./harden.sh --apply --aggressive
~~~

AIDE must validate the active runtime configuration, SHA-256/SHA-512 policy,
active database, real check-service context, and timer. update-aide.conf is not
a prerequisite.

MOR inspection is detection-only. On the recorded Ubuntu target, efivarfs was
available but neither standardized MOR variable existed, so the correct status
was UNSUPPORTED. Never create, overwrite, delete, echo to, or dd under efivars.

APT simulations run with LC_ALL=C and parse Purg and Remv. PackageKit remains
when simulation would remove ubuntu-server or software-properties-common.
Compiler packages remain when simulation would remove rkhunter, crash, or other
protected dependencies; kernel headers alone do not bypass simulation. No path
runs autoremove. Python binfmt handling is narrow and reversible; qemu, Wine,
JVM, and other foreign consumers remain protected.

## Artifact handling

~~~bash
scripts/collect-test-artifacts.sh ./artifacts
~~~

Review the archive before transfer. Remove secrets, private keys, credentials,
tokens, hostnames, addresses, and production-sensitive logs. Create one bounded
issue per verified finding with the exact commit, command, phase, sanitized
evidence, rollback state, and acceptance criteria.
