# Troubleshooting

## Execute permission or Permission denied

Check ls -l harden.sh, do not place the repository on a noexec filesystem, and
restore the executable bit with chmod +x harden.sh when appropriate.

## SSH, nftables, and Tailscale

Keep the second SSH session open. Before any reload, validate sshd -t, inspect
the owned nftables rules, and test Tailscale routing separately. Restore the
backup state or snapshot if the access path is unhealthy.

## rsyslog or remote destination is unavailable

Check destination, port, transport, DNS, firewall, and the CA path for TLS.
Local logging must continue independently of a remote destination.

## A systemd drop-in was rolled back

Read /root/systemd-hardening-report.txt, the saved before/after
systemd-analyze output, and journalctl -u NAME.service. Do not remove sandbox
controls blindly; identify the service requirement and prepare a focused fix.

## AIDE takes a long time

A baseline reads many files and can be I/O intensive. Do not interrupt it
without inspecting the database, timer, and backup state.

For FINT-4402, Lynis 3.1.6 inspects only the recognised primary AIDE
configuration and does not expand included files for this test. Inspect
aide-lynis-FINT-4402-evidence.txt and aide --config-check. Do not add a
non-functional comment merely to affect a score.

## PackageKit, compiler, or binfmt decision

Decision artifacts are stored in the run backup. Unsafe PackageKit or compiler
purges are skipped rather than forced. Restore an intentionally removed package
only from configured distribution sources, then validate APT and the related
service. Kernel headers alone are not a purge veto; active DKMS use and every
simulated non-toolchain dependency are.

The vendor python3.X binfmt rule supports direct execution of version-specific
compiled .pyc files. On a host without protected foreign-format consumers, only
that matching vendor rule can be disabled reversibly. Python, APT, systemd, and
other registrations are validated afterwards. Unknown qemu, Wine, and JVM
formats remain protected.

## Lynis summary or Fail2ban mismatch

Inspect lynis-after-hardening-report.dat,
lynis-summary-parse-diagnostics.txt, and the fail2ban-runtime.txt backup
artifact. An OK Fail2ban status requires an active service, a successful server
ping, and a live sshd jail query.

## PROC-3614

/root/hardening-iowait-processes.txt contains repeated D-state snapshots with
unit and wait channel. Short-lived waits are expected; repeated PIDs require
storage/filesystem diagnosis. Never kill D-state processes automatically.

## kernel.modules_disabled=1

This aggressive setting is irreversible until reboot. Test required kernel
modules first and recover through reboot or snapshot when necessary.

With active Tailscale, the late lock runs only after successful netfilter/NAT
preload and dual-stack runtime validation. If the gate fails, inspect
/root/kernel-module-lockdown-report.txt and the boot journal. A failed gate is
deliberately not success: module loading remains enabled so that targeted repair
is still possible. It does not change Tailscale routes, exit-node state,
accept-routes, or advertise-routes.

## The run stops before Phase 18

The EXIT trap reports the current phase. Read /var/log/server-hardening.log, the
backup, and the concrete error. Do not start another Apply until the cause and
rollback state are understood.
