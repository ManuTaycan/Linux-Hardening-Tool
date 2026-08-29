# Changelog

Alle relevanten Änderungen werden in dieser Datei dokumentiert. Ein Release-Tag
für 1.1.3 wird erst nach dem vollständigen Zielsystemtest erstellt.

## Unreleased — Repository-Aufnahme von 1.1.3

### Changed

- Unreleased real-test fix: synchronous dual logging replaces the asynchronous
  process-substitution logger, keeps interactive colors, writes ANSI-free logs,
  prevents logging FD inheritance or package-process job-control stalls, and
  captures user-visible Apply commands such as `update-grub` without external
  `tee`.
- Phase 03 now warns about legitimate multi-minute package work and streams APT
  progress without imposing artificial package timeouts.
- AIDE now validates the distribution's active configuration directly, without
  requiring `update-aide.conf`; it resolves `database_in`/`database_out`,
  atomically activates a verified baseline, skips unnecessary second-run
  rebuilds, checks the database, validates one real vendor/custom systemd
  service run (including Ubuntu `_aide` capabilities), and enables the timer
  only after success.
- The irreversible `kernel.modules_disabled=1` write is guarded by the final
  phase-17 network, firewall, AppArmor, validation, and AIDE prerequisites and
  is verified after the write.
- The late kernel-module lock now closes the confirmed Tailscale boot race:
  it classifies the running kernel's Netfilter/NAT features, preloads only
  present modular IPv4/IPv6 components, waits on observable iptables-nft,
  Tailscale-chain, backend, and router/netfilter-health readiness, and only
  then performs the irreversible write. The same verified helper runs during
  Apply and boot; a failed prerequisite leaves module loading enabled, fails
  the unit visibly, and writes a secret-free diagnostic report.
- Kernel-lock helper, preload unit, late-lock unit and Tailscale drop-in are
  transaction-backed and rolled back together if candidate/installed unit
  verification or daemon reload fails. The owned firewall unit is rendered
  once and verified before installation as well as after installation.
- Hosts already locked by an earlier run receive the corrected boot units
  without an impossible live `modprobe`; recovery of missing modules is
  explicitly deferred to the next controlled reboot.
- Converged runs avoid unnecessary `update-initramfs`, `update-grub`, fstab
  daemon reloads, compiler ownership/mode writes, account-aging changes,
  rkhunter property rebuilds, and service disable/mask calls. Reboot-required
  is set by managed initramfs/GRUB work only when its input actually changed.
- CI prüft den committed Base-to-Head-Diff auf Whitespace und testet den
  Installer in einem temporären Zielpfad.
- `--install-path` bezeichnet jetzt die ausführbare Zieldatei statt eines
  Verzeichnisses.
- AIDE writes its validated `HardenSHA2` group into the effective primary
  runtime configuration. This matches what AIDE executes and what Lynis 3.1.6
  actually inspects for `FINT-4402`; included path rules, database activation,
  service-context validation, and the timer remain unchanged.
- Headless PackageKit is unmasked and removed only when an APT purge simulation
  contains no other package. Simulations run with `LC_ALL=C` and parse both
  `Purg` and `Remv`; unsafe dependency graphs (including the confirmed
  `ubuntu-server`/`software-properties-common` cascade) retain PackageKit
  unmasked with the exact dependency reason.
- Aggressive compiler handling inventories the exact Lynis 3.1.6 detector set
  (`as`, `cc`, `clang`, `g++`, `gcc`) and owning packages. A simulated purge is
  allowed only for a narrow toolchain set and is blocked by active DKMS or any
  simulated non-toolchain dependency (including the confirmed `rkhunter` and
  `crash` cascade); installed kernel headers alone no longer preempt the APT
  simulation. The fallback remains root-only and never runs autoremove.
- `binfmt_misc` registrations, persistent definitions, and qemu/Wine/JVM
  consumers are inventoried. The Python-version registration is identified as
  direct `.pyc` execution support and is disabled reversibly and individually
  with a same-name `/etc/binfmt.d` `/dev/null` override only after Python, APT,
  systemd, and unrelated registrations validate; no global blacklist is used
  for that case. Only an otherwise empty, consumer-free aggressive host gets
  the whole runtime facility and `systemd-binfmt` persistently disabled.
- Final Lynis score/warning/suggestion parsing now accepts real 3.1.6 console
  output and falls back to the saved structured report. Fail2ban status is
  refreshed from service, server ping, and the live `sshd` jail after a bounded
  readiness check.
- Apply now captures a separate pre-hardening Lynis console report and
  `report.dat`, and the summary uses that measured baseline instead of a static
  source score. Dry-run explicitly reports `N/A / NOT RUN` and launches no
  writing Lynis scan.
- Reverse-path filtering is now an explicit routing policy: an active
  Tailscale overlay receives loose mode `2` for `all`, `default`, and relevant
  active interfaces (including `tailscale0`), while an inactive host receives
  strict mode `1` only after a simple-routing check. Policy routing or multiple
  default paths are retained and reported rather than overwritten. This is a
  documented compatibility exception, not a Lynis score change.
- Repeated systemd hardening treats an already-current, health-tested drop-in
  with identical exposure as unchanged/already hardened rather than warning
  that exposure did not decrease.
- `PROC-3614` now records repeated PID, unit, stat, wait-channel, command, IO,
  and file-descriptor snapshots, classifies transient versus persistent waits,
  and never kills a D-state process.
- Deleted-open-file handling now writes a normalized PID/process/user/FD/type/link-count/path inventory with systemd-unit attribution. Only a small explicit service allowlist is restarted once; SSH, Tailscale, networking, firewall, system, dbus, and unknown owners are default-denied and remain visible in the report.
- UEFI Memory Overwrite Request (MOR) is now inspected conservatively against
  the standard control and lock variables. The implementation is detection-only:
  it never creates, changes, or deletes an EFI variable, because support and
  safe lifecycle semantics are firmware-owned.
- Failed-login auditing now reports the separate Shadow/Lynis `FAILLOG_ENAB` /
  optional `faillog` and utmp `btmp`/`lastb` mechanisms without conflating
  them. It preserves `btmp` records, stores metadata only (never its content),
  never restores or deletes audit history, and leaves the existing `pam_faillock`
  lockout policy as the only lockout mechanism. On modern Ubuntu without
  `lastb`, the active journald plus effective SSH `LogLevel`/`SyslogFacility`
  configuration is validated instead; legacy `btmp`/`lastb` is reported as N/A
  and no synthetic failed login is created. Interactive shells receive an
  override-safe 900-second `TMOUT` through a managed profile; non-interactive
  commands are unaffected.

### Added

- Klassifizierte Rückgabecode-Behandlung für `pwck` und `grpck`; bekannte
  fehlende Home-Verzeichnisse von Systemaccounts werden protokolliert, ohne
  den Lauf abzubrechen.
- Strikte Phasenfolge 01–18, Completion-Gates und synchron sichtbarer
  EXIT-Trap bei unvollständigen Läufen.
- Verifikation deaktivierter oder maskierter Dienste sowie gezielte
  systemd-Drop-ins mit Vorher-/Nachher-Exposure-Bericht.
- AIDE-Runtime-Validierung mit SHA256/SHA512, Baseline, Datenbankprüfung und
  Timer erst nach einem lesbaren Check.
- Tailscale-kompatible `rp_filter`-Ausnahme, erweiterte Compiler-Erkennung,
  BOOT-5180-Startdienst-Inventar, LOGG-2190-Remediation und
  PROC-3614-IO-Wait-Diagnose.

### Changed

- Kein SSH-Port-Write und keine GRUB-Passwortlogik.
- `systemd-analyze verify` prüft einen zusammengeführten Kandidaten vor der
  Installation sowie die installierte Unit vor `daemon-reload`.

### Validation status

- Ubuntu 26.04.1 Target-System-Abnahme bestanden.
- Fresh Lynis 63 -> 87; konvergiert 87 -> 87.
- AIDE baseline rebuilt 1 -> 0.
- Gepatchter Reboot: Tailscale/Netfilter/NAT gesund; `kernel.modules_disabled=1`
  erst nach dem Runtime-Gate.
- Finaler konvergierter Lauf: keine Packages installed/removed, keine Failed
  Services/Rollbacks, Reboot required NO.
