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
- CI prüft den committed Base-to-Head-Diff auf Whitespace und testet den
  Installer in einem temporären Zielpfad.
- `--install-path` bezeichnet jetzt die ausführbare Zieldatei statt eines
  Verzeichnisses.
- AIDE writes its validated `HardenSHA2` group into the effective primary
  runtime configuration. This matches what AIDE executes and what Lynis 3.1.6
  actually inspects for `FINT-4402`; included path rules, database activation,
  service-context validation, and the timer remain unchanged.
- Headless PackageKit is unmasked and removed only when an APT purge simulation
  contains no other package. APT and unattended-upgrades are validated before
  and after; unsafe dependency graphs retain PackageKit unmasked.
- Aggressive compiler handling inventories the exact Lynis 3.1.6 detector set
  (`as`, `cc`, `clang`, `g++`, `gcc`) and owning packages. A simulated purge is
  allowed only for a narrow toolchain set and is blocked by DKMS, kernel-header,
  guest, boot, SSH, or network dependencies; the fallback remains root-only.
- `binfmt_misc` registrations, persistent definitions, and qemu/Wine/JVM
  consumers are inventoried. Only an empty, consumer-free aggressive host gets
  the runtime facility and `systemd-binfmt` persistently disabled.
- Final Lynis score/warning/suggestion parsing now accepts real 3.1.6 console
  output and falls back to the saved structured report. Fail2ban status is
  refreshed from service, server ping, and the live `sshd` jail after a bounded
  readiness check.
- `PROC-3614` now records repeated PID, unit, stat, wait-channel, command, IO,
  and file-descriptor snapshots, classifies transient versus persistent waits,
  and never kills a D-state process.

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

- Lokale Syntax-, statische und simulierte Regressionstests bestanden.
- Ein vollständiger Ubuntu-26.04.1-Zielsystemtest und die Bestätigung des
  Zielwerts Hardening Index >= 90 stehen noch aus.
- Der beobachtete interne Score 86 gegenüber einem späteren manuellen Score 87
  ist aus den vorhandenen Konsolenauszügen nicht testgenau rekonstruierbar. Die
  Scans waren zeitlich verschiedene Snapshots und der alte Summary-Parser
  verlor strukturierte Werte. Künftige Retests bewahren Console und
  `lynis-report.dat` je Pass auf; ein Punktunterschied darf erst anhand der
  konkreten Test-ID-Differenz erklärt werden, nicht durch Profil-Skipping.
