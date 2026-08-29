# Zielsystemtest

Der reale Test für Version 1.1.3 auf Ubuntu 26.04.1 steht aus. Führe ihn nur in
einem genehmigten Wartungsfenster durch.

1. Snapshot oder vollständiges Backup erstellen.
2. Zweite SSH-Sitzung öffnen und Recovery-Zugang prüfen.
3. Repository klonen oder kontrolliert aktualisieren.
4. `sha256sum -c SHA256SUMS` ausführen.
5. `bash -n harden.sh` ausführen.
6. Dry-Run prüfen.
7. Apply bewusst starten.
8. SSH erneut verbinden.
9. Reboot und Rückkehr prüfen.
10. Dienste, Firewall und Remote Logging prüfen.
11. Lynis ausführen.
12. Artefakte sammeln.
13. Sensible Daten entfernen.
14. Jedes Finding als einzelnes Issue anlegen.

```bash
sudo ./harden.sh \
  --apply \
  --aggressive \
  --remote-log-server 10.0.0.9 \
  --remote-log-port 5140 \
  --remote-log-protocol tcp

sudo cp /var/log/server-hardening.log ./hardening-apply.log
sudo cp /root/lynis-before-hardening.txt ./lynis-before.log
sudo cp /root/lynis-before-hardening-report.dat ./lynis-before-report.dat
sudo cp /root/lynis-after-hardening.txt ./lynis-after.log
```

Für die Findings #4, #12, #17, #18, #19 und #20 zusätzlich prüfen:

- `aide-lynis-FINT-4402-evidence.txt`, AIDE-Konfigurationsprüfung,
  aktive Datenbank, erfolgreicher Check-Service und aktiver Timer;
- die Summary zeigt den tatsächlich gemessenen Baseline-Wert aus
  `lynis-before-hardening.txt`/`lynis-before-hardening-report.dat`; beim
  Zweitlauf entspricht Before dem bereits gehärteten Ausgangszustand, während
  Dry-Run `N/A (dry-run; NOT RUN)` zeigt und keinen Lynis-Report schreibt;
- die Ubuntu-26.04-PackageKit-Fixture `Purg ubuntu-server`,
  `Purg software-properties-common`, `Purg packagekit` führt zu keinem Purge;
  PackageKit bleibt unmaskiert und beide Abhängigkeiten stehen im Skip-Grund.
  `apt-get check` und `unattended-upgrade --dry-run` funktionieren;
- `compiler-toolchain-inventory.txt` nennt Lynis-Binary und Paket; ein Purge
  mit `Purg rkhunter`, `Purg crash`, `Purg binutils` und
  `Purg binutils-x86-64-linux-gnu` wird mit konkretem Dependency-Grund
  abgebrochen. Kernel-Headers allein verhindern die Simulation nicht, aktive
  DKMS-Nutzung bleibt geschützt und es läuft kein Autoremove;
- für `registration=python3.14` und `/usr/lib/binfmt.d/python3.14.conf` ohne
  geschützte Verbraucher existiert der gezielte reversible
  `/etc/binfmt.d/python3.14.conf -> /dev/null`-Override. `python3`,
  `apt-get check`, `systemctl daemon-reload` und alle anderen benötigten
  Registrierungen bleiben funktionsfähig; es gibt keinen globalen Blind-Block;
- Summary-Werte stimmen mit `lynis-after-hardening-report.dat` überein und
  `fail2ban-client ping/status sshd` bestätigt den angezeigten Status;
- `hardening-iowait-processes.txt` enthält Vorher-/Nachher-Snapshots. D-State-
  Prozesse dürfen transient verschwinden und werden niemals automatisch
  beendet;
- im idempotenten Zweitlauf bleibt `AIDE baseline rebuilt: 0`, ein bereits
  aktives `kernel.modules_disabled=1` passiert das finale Gate sauber, und
  gleiche systemd-Exposure-Werte (z. B. `3.4 -> 3.4`) erscheinen bei aktuellem,
  gesundem Drop-in als unchanged/already hardened statt als Warnung.

Falls ein unmittelbar anschließender manueller Lynis-Lauf einen anderen Index
liefert, beide Console-Reports und beide `lynis-report.dat`-Dateien sichern und
die `suggestion[]`, `warning[]` sowie Test-Ergebnisse vergleichen. Ein bloßer
Indexunterschied ist kein belastbarer Root-Cause-Nachweis.

Der offizielle Apply-/Zielsystemtest wird direkt und ohne externe Pipe oder
`tee` gestartet. Nur so bleibt die automatische TTY-Farberkennung aktiv; das
Skript schreibt den vollständigen ANSI-freien Lauf selbst nach
`/var/log/server-hardening.log`. `--no-color` oder `NO_COLOR` deaktivieren die
interaktive Farbausgabe. Prüfe vor dem Hochladen
`scripts/collect-test-artifacts.sh`-Archive auf sensible Informationen.
