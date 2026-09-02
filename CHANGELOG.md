# Changelog

All notable changes are documented here. Version 1.1.3 remains unreleased; no
release tag or GitHub Release is created by this file.

## Unreleased

### Public release polish

- Reworked repository-facing documentation, templates, examples, and
  troubleshooting guidance into consistent English.
- Added a factual third-party/Lynis dependency review with authoritative source
  links, distribution inventory, Enterprise and plugin separation, and explicit
  release controls. No project license was selected.
- Reorganized the README around scope, safety boundaries, common commands,
  historical validation evidence, and documentation links.
- Added repository-native Mermaid visuals for the hardening flow and recorded
  validation evidence.
- Kept the explicit pre-release and not-production-ready warning. Licensing and
  final release governance remain open and are not decided here.

### Runtime hardening and validation

- Preserved the fixed Phase 01–18 order, visible incomplete-run EXIT trap, and
  separate Apply-mode Lynis baseline. Dry-run reports N/A / NOT RUN and does not
  launch a write-producing baseline scan.
- Made logging synchronous and fully owned by the script: interactive output
  can retain color, the file log is ANSI-free, descriptors do not leak to
  external commands, and package tools do not stall through logger job control.
- Ordered Phase 03 as APT metadata refresh, controlled no-removal upgrade, then
  hardening/security package preparation. Upgrade simulation is locale-stable,
  blocks removals and downgrades, and records reboot state.
- Made package operations lock-aware at the command boundary. APT uses its
  native lock timeout plus bounded delayed retries for confirmed contention,
  reports reliable owner evidence when available, and leaves package processes
  and lock files untouched; non-lock package errors still fail immediately.
- Validated AIDE against the actual distribution runtime configuration without
  requiring update-aide.conf. The baseline is atomically activated, the real
  check-service context is proven, and the timer is enabled only after success.
- Kept kernel.modules_disabled=1 as the final irreversible gate. Tailscale
  Netfilter/NAT prerequisites are loaded and validated before locking; an
  already locked but unhealthy runtime is reported for controlled reboot repair
  without impossible live modprobe attempts.
- Retained Tailscale-compatible rp_filter=2 as an explicit routing-policy
  exception. Ambiguous inactive-Tailscale routing preserves observed runtime
  values persistently rather than forcing strict filtering.
- Treated IPv6 as an observed network policy. The default remains enabled;
  explicit aggressive disable is blocked by addresses, routes, listeners,
  forwarding, Tailscale, or ambiguity and has deterministic rollback.
- Added conservative UEFI MOR inspection with required efivarfs attribute
  validation. The implementation never creates, changes, or deletes an EFI
  variable.
- Added deleted-open-file inventory and default-deny remediation. Anonymous
  memfd entries remain visible, are classified separately, and never force
  restart or reboot.
- Separated failed-login evidence for Shadow/FAILLOG_ENAB, optional faillog,
  legacy btmp/lastb, and the modern journald/SSH path. Audit history remains
  content-preserving; interactive TMOUT defaults to 900 seconds while
  non-interactive shells remain unaffected.
- Added a conservative, optional two-stage SSH port migration. It validates
  state against actual listeners, stages firewall before dual listeners, and
  proves single- or dual-port rollback. Socket activation is supported without
  automatic mode conversion or duplicate listener restarts.
- Hardened the recoverable firewall contract so SSH retirement cannot write
  final state when the firewall is unavailable or migration state is unsafe.
- Added service-specific systemd exposure handling with merged-unit validation,
  health checks, rollback, and idempotent convergence. Compatibility retention
  is narrowly documented for acct-monthly-report.service and its vendor report
  file /var/log/wtmp.report.
- Restricted AppArmor transitions to explicit stable services with matching
  enabled distribution profiles, parser validation, service-specific health,
  and proven rollback.
- Improved PackageKit, compiler, binfmt, residual-kernel, and rc-only grub-pc
  handling through APT simulation and explicit dependency/boot safety gates.
- Kept firewall rule inventory non-destructive: foreign, Tailscale, SSH,
  Fail2ban, NAT, forwarding, and unowned rules are not deleted.
- Managed the Ubuntu MOTD news path through the documented ENABLED=0 setting
  while preserving the executable hook required by motd-news.service and the
  reboot-required notice.

### Tooling and repository behavior

- CI checks the committed Base-to-Head diff for whitespace, runs ShellCheck and
  regression tests, validates SHA256SUMS, and tests the installer against the
  exact CI commit in temporary target paths.
- install.sh treats --install-path as an executable destination file, validates
  the checksum before install, preserves existing parent-directory metadata,
  and never runs hardening automatically.
- Existing valid service and configuration state converges without needless
  daemon reloads, service restarts, package changes, update-initramfs,
  update-grub, compiler metadata changes, or rkhunter property updates.

## Recorded validation status

- Ubuntu 26.04.1 fresh Apply: Lynis 63 → 87; AIDE baseline rebuilt 1.
- Ubuntu 26.04.1 converged Apply: Lynis 87 → 87; AIDE baseline rebuilt 0.
- Patched reboot acceptance confirmed Tailscale/Netfilter/NAT health and set
  kernel.modules_disabled=1 only after the runtime gate.
- The documented converged run recorded no installed or removed packages, no
  failed services, no rollbacks, no reboot request, and Phase 18 SUCCESS.
- Separate focused target acceptances also cover modern failed-login evidence,
  interactive TMOUT=900 with unchanged non-interactive shells, detection-only
  UEFI MOR UNSUPPORTED status, IPv6/banner/MOTD policy, and anonymous memfd
  deleted-open-file handling.

This is historical acceptance evidence, not a score promise or a general
production-release certification. Current feature branches require their own
target validation. No >=90 Lynis target is claimed.
