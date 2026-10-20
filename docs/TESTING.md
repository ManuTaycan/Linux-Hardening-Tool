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


## Atomic firewall loader and recovery (#53, #54, #52)

Apply, systemd start/reload and SSH rollback use the embedded Python 3 loader,
installed at `/usr/local/libexec/server-hardening-firewall`. It checks a complete
batch then submits the same immutable bytes in one nft transaction. Only
`inet hardening_filter` is replaced; there is no separate live deletion or
ruleset flush. A converged runtime fingerprint avoids redundant nft commits.
The unit has no firewall-removing stop action. Do not disable the vendor
nftables service or restart Docker, networking, SSH or Tailscale to apply this.

Docker fragments are optional, but an explicitly selected missing file, an
existing empty file, unsafe permissions, or malformed rules now fail visibly.
The default path is `/etc/nftables.d/90-docker-egress.rules`; an override must
also be a canonical path beneath `/etc/nftables.d`. Every directory and file
must be root-owned, with no group/other write access and no symlinks. Suggested
modes: directories 0755, fragments 0600. The loader reads through directory FDs
with O_NOFOLLOW and validates a snapshot before nft sees it, including on boot.

The supported fragment grammar is one rule per line: explicit distinct
`iifname` and `oifname`, an IPv4 source CIDR (never /0), `tcp` or `udp`, explicit
`dport` or a literal port set, optional `counter`, `accept`, and an optional
simple comment. Nested includes, commands, wildcard interfaces and bare
accepts are rejected. Comments and empty lines are allowed around real rules.
For example (replace the interfaces and subnet with your assessed bridge):

~~~nft
iifname "docker0" oifname "eth0" ip saddr 172.17.0.0/16 tcp dport { 80, 443 } counter accept
~~~

If a reload fails, the current policy stays active. A self-contained,
root-owned `/etc/nftables.d/.hardening-last-good.nft` snapshot provides boot
recovery if the configured file/fragment later disappears or becomes invalid;
the unit still reports failure and requires operator attention. A first setup
with no previous policy never rolls back by removing an already committed
protective table. File installation, service activation or recovery failures
are errors, and console recovery may be required. The snapshot does not depend
on Docker's startup order. Apply retains the persisted fragment selection,
including a custom path, when its environment override is omitted on a later
run. To opt out deliberately, unset the path override and run
`sudo env HARDEN_DOCKER_EGRESS_DISABLE=1 ./harden.sh --apply`; the fragment can
then be removed. Simply deleting a selected fragment is a rejected
configuration and leaves both forwarding sysctls and the live policy untouched.
New Docker forwarding is enabled only after the owned default-drop firewall
has committed and passed its health checks. Phase 05 defers a transition from
forwarding=0 until that point; an already enabled routing role is preserved.
Failed forwarding activation restores the prior sysctl file/value. If runtime
restoration cannot be proven, the validated protective firewall stays active
and Apply fails with a console-recovery diagnostic.

An optional host TCP exception for Ollama/n8n or another API requires both
`HARDEN_INPUT_TCP_SOURCE` (one IPv4/IPv6 host literal, no CIDR/hostname) and
`HARDEN_INPUT_TCP_PORT` (1..65535). Supply both to the same Apply command using
your own values, for example:

~~~bash
sudo env HARDEN_INPUT_TCP_SOURCE=YOUR_TRUSTED_SOURCE_IP HARDEN_INPUT_TCP_PORT=YOUR_API_TCP_PORT ./harden.sh --apply
~~~

The feature is disabled on first installation unless both values are supplied.
The managed source/port selection persists across parameterless Apply, reload,
restart and reboot. To remove it explicitly, unset both overrides and run
`sudo env HARDEN_INPUT_TCP_DISABLE=1 ./harden.sh --apply`. Disable plus either
override, partial overrides, malformed saved selections and overlap with any
current/staged SSH port are rejected before changing the live policy. To change
the selection, supply both new values. Older managed additive TCP exceptions
are retained and upgraded to the exclusive boundary on the next Apply.

For the selected host INPUT TCP port, only the selected source is permitted
from network interfaces, including Tailscale and WireGuard. A per-port drop
precedes established/related and general overlay accepts; existing connections
from other sources are also denied. A source in one IP family does not open
the port to the other family. Loopback access remains available for local
processes. Other ports, SSH administration and UDP overlay transport retain
their existing policy. This is a firewall boundary, not API authentication;
source spoofing protection and the security of the trusted client still matter.
Published Docker ports traverse forwarding and need their own reviewed Docker
policy; this INPUT feature does not restrict a DNAT-published container API.

`make check` includes unit/mocked failures and rendering tests. Linux CI also
runs `sudo unshare --net --fork python3 scripts/firewall-helper-tests.py --namespace`
with real nft for fresh/replacement/no-op transactions, invalid/missing includes,
permissions, scope rejection, snapshot rollback, boot recovery and preservation
of a foreign table. This is not a full Ubuntu target deployment test.

Before merging, use a disposable Ubuntu VM with console recovery to test:
fresh Apply and unchanged second Apply; reload/restart/boot with valid, invalid,
missing and permission-invalid fragment; forced nft failure; failed SSH stage
and retire rollback; IPv4/IPv6 SSH and Tailscale/WireGuard connectivity; Docker
DNS/web/BuildKit egress and denied unsolicited forwarding. For the API exception,
verify allowed/denied sources on both ordinary and overlay ingress, IPv4/IPv6
cross-family denial, already established unauthorized flows, and unrelated SSH
access, including after reload/restart/reboot and parameterless Apply. Check
explicit opt-out and that invalid/partial/SSH-overlapping selections retain
the previous policy. Never run these service/reboot tests on a
production server without explicit approval.

## Conservative automatic security updates (#50)

The managed policy uses the distribution's `apt-daily.timer` and
`apt-daily-upgrade.timer`; it adds no cron job or second scheduler. Security
origins are explicit: Ubuntu's security archive and optional Ubuntu Pro ESM
security archives, or Debian's release-specific Debian-Security codename.
Ubuntu security pockets have the base release codename and a `-security`
archive, so matching `codename=RELEASE-security` would miss normal Ubuntu
security updates. No third-party, updates, proposed, backports or release
upgrade origin is enabled. Missing ESM repositories are not added/enabled.

APT combines Allowed-Origins and Origins-Pattern lists. The managed fragment
clears both before defining the security list; a later override is detected
from `apt-config dump`. All three automatic unused-package/kernel/dependency
removal settings, automatic reboots (including with users), downgrades and
automatic interrupted-dpkg repair are disabled. Autoclean only clears cached
package archives; it does not uninstall packages. Existing blacklists remain.
No implementation can guarantee every upstream security update is compatible
with every workload; operators still need snapshots, monitoring and staging.

Effective policy and `unattended-upgrade --dry-run --debug` are validated before
new timers are enabled. Existing timers can already hold APT locks; command
retries remain bounded and preserve their owner. Missing tools, masked or
ambiguous timers, later policy conflicts, parse errors, failed validation and
failed timer activation produce FAILED in the final summary and exit status.
Configuration is restored on failure, along with newly changed timer state;
running package services/processes are never stopped to obtain a lock.
Dry-run only plans these changes and never runs unattended-upgrade or enables
timers. The timer rollback stops/disables only timers that were previously
inactive/disabled; it never stops an in-progress package operation.

The fixture tests exercise failure and rollback boundaries. Linux CI also
uses real `apt-config` with an isolated APT configuration directory to test
list-clearing, both distribution policies and later conflicting overrides.
This does not prove a successful upgrade on Ubuntu. On a disposable Ubuntu VM,
inspect `apt-cache policy`, `apt-config dump`, `systemctl list-timers apt-daily*`,
the unattended-upgrades logs and a real unattended dry-run; exercise live
apt-daily contention, a broken dependency/configuration case and a converged
second Apply. Confirm no package removal or automatic reboot is proposed.

Policy reference: the upstream [Ubuntu configuration](https://github.com/mvo5/unattended-upgrades/blob/master/data/50unattended-upgrades.Ubuntu),
[Debian configuration](https://github.com/mvo5/unattended-upgrades/blob/master/data/50unattended-upgrades.Debian)
and [origin-list handling](https://github.com/mvo5/unattended-upgrades/blob/master/unattended-upgrade).

## Execution boundaries (#51)

Apply targets a dedicated Ubuntu/Debian host or full VM with systemd as PID 1,
an accessible system bus and APT. Before any prompt, file log, backup, package
operation or hardening phase, it checks systemd's container/chroot/user-namespace
detection, container environment/filesystem markers and cgroup evidence. A
positive container signal or an inconclusive environment blocks Apply. Root
or extra Linux capabilities do not bypass this gate.

| Environment | Current policy |
| --- | --- |
| Dedicated Ubuntu/Debian host or full VM | Apply may pass preflight; role-specific acceptance still required |
| Docker/Podman/OCI, including privileged or host-network containers | Apply blocked; shared kernel/network/mount exposure can affect the host |
| LXC/LXD, systemd-nspawn, OpenVZ | Apply blocked, even with systemd or delegated capabilities |
| Kubernetes workloads, rootless containers, private user namespace | Apply blocked |
| Chroot, WSL, missing detector, ambiguous environment or non-systemd PID 1 | Apply blocked |
| Dry-run in an unsupported environment | Read-only diagnostics/planning where tools exist; host controls may be unavailable |

Kernel module lockdown, sysctl, audit, boot/initramfs, firewall, host package and
service changes are not safe generic container controls. This repository does
not claim support for any container family or automatically enable privileged
operation. Detection is evidence-based, not a security boundary against a
malicious root operator who conceals its environment or modifies the script.
Use a dedicated VM for target acceptance and harden workload images/runtime
policies separately. See [systemd's detection semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html).

Fixture regressions exercise positive signals, ambiguous detection, PID 1/bus
requirements and main's early refusal before mutation. Manual compatibility
checks still needed: run the actual CLI in disposable Docker/Podman, LXC/nspawn
and a normal Ubuntu VM; confirm --help works, blocked Apply writes no log/backup
and touches no host control, and dry-run reports diagnostic limitations.
