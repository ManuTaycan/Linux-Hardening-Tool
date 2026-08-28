# Changelog

Alle relevanten Änderungen werden in dieser Datei dokumentiert. Ein Release-Tag
für 1.1.3 wird erst nach dem vollständigen Zielsystemtest erstellt.

## Unreleased — Repository-Aufnahme von 1.1.3

### Changed

- CI prüft den committed Base-to-Head-Diff auf Whitespace und testet den
  Installer in einem temporären Zielpfad.
- `--install-path` bezeichnet jetzt die ausführbare Zieldatei statt eines
  Verzeichnisses.

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
