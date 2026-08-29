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

### Ubuntu-26.04.1-Retest des Tailscale-/Kernelmodul-Locks

Der bestätigte Boot-Race gilt erst nach einem vollständigen Apply plus Reboot
als behoben. Verwende den geprüften PR-Commit und führe danach exakt diese
Abnahme aus; `<TAILSCALE-PEER>` ist durch einen genehmigten Peer zu ersetzen.

1. Gepatchten Commit bereitstellen, `sha256sum -c SHA256SUMS` prüfen und den
   Apply direkt ohne externe `tee`-Pipe bis Phase 18 ausführen.
2. System neu starten und die Rückkehr über die zweite SSH-/Recovery-Sitzung
   bestätigen.
3. `sysctl kernel.modules_disabled` muss `1` liefern; außerdem
   `systemctl status kernel-module-lockdown.service --no-pager` prüfen.
4. `lsmod | grep -E '(^|_)(nf_nat|nft_nat|nft_chain_nat|nft_masq|xt_MASQUERADE|iptable_nat|ip6table_nat)([[:space:]_]|$)'`
   und `/root/kernel-module-lockdown-report.txt` mit der laufenden
   Kernel-Konfiguration abgleichen.
5. `iptables --version`, `ip6tables --version`,
   `iptables -t nat -S POSTROUTING`, `ip6tables -t nat -S POSTROUTING` sowie
   beide `-t nat -S ts-postrouting`-Ausgaben prüfen.
6. `tailscale status` und
   `tailscale status --json | jq '{BackendState,Health}'` müssen ohne aktuelle
   Router-/Netfilter-Healthwarnung sein.
7. `tailscale ping <TAILSCALE-PEER>` ausführen; keine `tailscale up/set`-
   oder Preference-Änderung gehört zu diesem Test.
8. `nft list table inet hardening_filter` und die Tailscale-eigenen Tabellen/
   Chains prüfen.
9. `systemctl --failed --no-pager` muss auf neue Hardening-/Tailscale-Fehler
   geprüft werden.
10. AIDE mit dem tatsächlich konfigurierten Check-Service und anschließendem
    Timerstatus prüfen, z. B. `systemctl start dailyaidecheck.service` und
    `systemctl status dailyaidecheck.service dailyaidecheck.timer --no-pager`.
11. `apt-get check` muss erfolgreich sein.
12. Den Apply direkt und erneut ohne externe `tee`-Pipe ausführen. Er muss
    Phase 18 erreichen, `Before 87 -> After 87`, `AIDE baseline rebuilt: 0`
    und den bereits gesetzten Kernel-Lock ohne `modprobe` melden; die
    dokumentierten No-op-Pfade dürfen keine unnötigen Änderungen auslösen.

Schlägt das Netfilter-/Tailscale-Gate fehl, muss der Lock beim Apply bzw. beim
nächsten Boot mit noch schreibbarem Control bei 0 bleiben und die Unit darf
nicht erfolgreich erscheinen. Sichere dann Diagnosebericht und Journal, ohne
Tailscale-Prefs automatisch zu verändern.

### Ubuntu-26.04.1-Retest der rp_filter-Routingpolicy (#7)

Führe den Apply direkt aus (ohne externes `tee`) und prüfe den vom Script
geschriebenen Bericht `/root/tailscale-rp-filter-report.txt`:

```bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/tailscale-rp-filter-report.txt
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter \
  net.ipv4.conf.tailscale0.rp_filter
ip -4 route show default
ip -4 rule show
tailscale status --json
tailscale ping <TAILSCALE-PEER>
```

Bei aktivem Tailscale müssen die aufgeführten `rp_filter`-Werte `2` sein und
der Bericht die akzeptierte Overlay-Ausnahme nennen. Eine Healthmeldung allein
zu `--accept-routes is false` ist dabei kein Fehler; Router-/Netfilter-Meldungen
bleiben sichtbar. Prüfe zusätzlich Erreichbarkeit und die bestehenden
Tailscale-/NAT-Checks. Auf einem Vergleichssystem ohne aktives Tailscale muss
bei einer einzelnen Default-Route und Standard-`ip rule` der Wert `1` gelten.
Bei mehreren Default-Routen oder nichtstandardmäßigen Regeln darf der Lauf
nicht blind auf `1` umstellen, sondern muss WARN/SKIP mit Grund und effektiven
Werten reporten. Wiederhole den Apply: Die persistente sysctl-Datei und das
gezielte Reload dürfen dann unverändert bleiben.

### Ubuntu-26.04.1-Retest deleted-open files (#13)

Nach einem Apply prüfe den vollständigen, ANSI-freien Inventarbericht. Er darf
nie automatisch rebooten, Prozesse beenden oder SSH/Tailscale/Netzwerkdienste
restartieren:

```bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/deleted-open-files-report.txt
sudo lsof -nP +L1
sudo ./harden.sh --apply --aggressive
```

Ein leerer Inventarbestand ist ein No-op. Für verbleibende Einträge müssen PID,
Prozess, Unit, Datei und Default-deny-Entscheidung nachvollziehbar sein. Nur
explizit erlaubte aktive Dienste dürfen höchstens einmal neu starten; der
nachfolgende `lsof +L1`-Scan muss den Erfolg belegen. Prüfe insbesondere, dass
SSH, Tailscale, Netzwerk, Firewall und systemd/dbus nicht neu gestartet wurden.

Ein Eintrag wie `/memfd:systemd-udevd (deleted)` mit Link-Count `0` ist eine
anonyme, volatile RAM-Datei und kein verwaister persistenter Dateisystem-Inode.
Sie bleibt vollständig sichtbar, wird als `anonymous-memfd` reportet und löst
weder Restart noch Reboot aus. Normale `/var/... (deleted)`-Einträge bleiben
dagegen weiterhin actionable bzw. manual-review-required.

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
