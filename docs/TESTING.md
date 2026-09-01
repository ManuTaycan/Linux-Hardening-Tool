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

### Ubuntu-26.04.1-Retest systemd-Service-Exposure (#11)

Führe den Apply aus einer bestätigten zweiten SSH-/Recovery-Sitzung direkt ohne
externe `tee`-Pipe aus. Der Report muss für jeden aktiven Dienst Activity,
Before-/After-Score, Delta, Controls, Klassifikation, Unit-Validierung und
Health-Resultat enthalten. Ein neuer Drop-in bleibt nur bei messbar kleinerem
Exposure bestehen; ein Verify- oder Health-Fehler muss den vorherigen Drop-in
vollständig wiederherstellen.

Die Phase-03-Reihenfolge muss im Log `Backup -> SSH-Kontext -> needrestart
list-only -> frühe SSH-Migration -> apt-get update -> kontrolliertes Upgrade`
zeigen. Der Batch-Report `/root/needrestart-pending-report.txt` muss alle
ausstehenden Service-Restarts nennen; während des Laufs dürfen insbesondere
SSH, Tailscale und Netzwerk-/Firewall-Dienste nicht automatisch neu gestartet
werden.

```bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/systemd-hardening-report.txt
systemctl is-active fail2ban.service ssh.service tailscaled.service
sudo fail2ban-client ping
sudo fail2ban-client status sshd
sudo systemd-analyze security fail2ban.service unattended-upgrades.service networkd-dispatcher.service
systemctl --failed --no-pager
sudo ./harden.sh --apply --aggressive
```

### Ubuntu-26.04.1-Retest acct monthly report (#35)

Vor der Abnahme die Vendor-Dateien und den tatsächlich benötigten Schreibpfad
prüfen. Das Ubuntu/Debian-Skript `/usr/share/acct/reporting/monthly` liest die
wtmp-Historie und schreibt den Bericht `/var/log/wtmp.report`; ein pauschales
`/var/log`-Write-Allowlisting ist nicht erforderlich.

```bash
sudo systemctl cat acct-monthly-report.service
sudo systemctl cat acct-monthly-report.timer
sudo sed -n '1,240p' /usr/share/acct/reporting/monthly
sudo systemctl show -p ProtectSystem -p ReadWritePaths acct-monthly-report.service
sudo systemctl status --no-pager acct-monthly-report.service
sudo stat -c '%U:%G %a %n' /var/log/wtmp.report
sudo cat /root/systemd-hardening-report.txt
sudo ./harden.sh --apply --aggressive
sudo stat -c '%U:%G %a %n' /var/log/wtmp.report
sudo systemctl start --wait acct-monthly-report.service
sudo ./harden.sh --apply --aggressive
sudo systemctl start --wait acct-monthly-report.service
sudo apt-get check
systemctl --failed --no-pager
```

Der erste Lauf muss die gemergte Unit vor Installation validieren, die fehlende
Reportdatei eng als `root:adm`/`0640` anlegen und erst dann den One-shot
ausführen; `ReadWritePaths` muss exakt `/var/log/wtmp.report` ohne optionales
`-` enthalten. Ein bereits fehlgeschlagener Dienst wird nur nach erfolgreichem
Lauf per `reset-failed` bereinigt. Der zweite Apply ist bei unveränderter Policy
ein vollständiger No-op ohne erneute Dateierstellung, Start oder Reload.
Ein unveränderter `systemd-analyze security`-Wert ist für diesen einen Dienst
akzeptabel, wenn der präzise Pfad, Unit-Validierung, One-shot und
`root:adm`/`0640` nachweislich erfolgreich sind; andere Service-Drop-ins
behalten weiterhin ihr messbares Score-Gate.

### Ubuntu-26.04.1-Retest AppArmor service coverage (#15)

Der Lauf darf keine automatisch erzeugten Profile oder pauschales Enforcing
aller Profile vornehmen. Er inventarisiert unconfined Prozesse vor und nach dem
Apply und bewertet ausschließlich aktive `fail2ban.service`- und
`rsyslog.service`-Prozesse, sofern zu deren tatsächlichem `ExecStart` ein
paketiertes, nicht deaktiviertes Profil existiert. SSH, Tailscale, systemd,
Netzwerk, Firewall, Paketmanagement und Recovery bleiben sichtbar ausgeschlossen.

```bash
sudo aa-status
sudo ./harden.sh --apply --aggressive
sudo cat /root/apparmor-service-coverage-report.txt
sudo systemctl is-active fail2ban.service rsyslog.service ssh.service tailscaled.service
sudo fail2ban-client ping
sudo fail2ban-client status sshd
sudo ./harden.sh --apply --aggressive
```

Für jeden tatsächlich profilierten Dienst prüfe den gemergten Profilpfad mit
`apparmor_parser -Q`, den Healthcheck und `/proc/<PID>/attr/current`. Für
`rsyslog.service` gehören außerdem `rsyslogd -N1`, ein echter `logger`-Probe
und – soweit der Kernel-Journalzugriff verfügbar ist – eine Prüfung neuer
AppArmor-`DENIED`-Ereignisse dazu. Schlägt eine Transition fehl, darf der
Bericht `rolled-back` nur nach nachgewiesenem Profil-Unload, genau einem
Service-Restart, positivem Healthcheck und wieder unconfined laufendem Prozess
ausweisen; andernfalls muss er `rollback-failed` und manuellen Recovery-Bedarf
melden. Der zweite Lauf darf bei unverändertem Inventar weder ein Profil laden
noch einen Dienst neu starten.

Der zweite Lauf darf bei gültigen Drop-ins weder `systemctl daemon-reload` noch
einen Service-Restart auslösen; die Scores bleiben stabil. SSH wird mit
`UMask=0027` allein behandelt: `PrivateTmp` ist wegen der beschriebenen
Sitzungs-Sicherheitsausnahme ausdrücklich entfernt. Tailscale, dbus, cron, auditd,
open-vm-tools, snapd, systemd-Units, polkit, cloud-init sowie weitere
Netzwerk-/Storage-kritische Dienste bleiben ohne generisches Sandbox-Profil.

Prüfe die SSH-Safety-Migration aus einer bestätigten zweiten SSH- oder
Recovery-Sitzung. Ein `ssh.service`-Restart kann ältere Sessions mit einem
verwaisten PrivateTmp-Mount-Namespace zurücklassen, daher ist ausschließlich ein
Reload zulässig:

```bash
sudo systemctl cat ssh.service
sudo sshd -t
sudo systemctl is-active ssh.service
findmnt -T /tmp
mktemp
sudo grep -A9 '^\[ssh\.service\]' /root/systemd-hardening-report.txt
sudo cat /root/needrestart-pending-report.txt
sudo grep -E 'SSH systemd safety|needrestart|Reboot required' /var/log/server-hardening.log
```

Bei Validierungs- oder Health-Fehlern muss der vorherige Drop-in wiederhergestellt
werden; das Script darf dabei niemals `systemctl restart ssh.service` verwenden.

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

### Ubuntu-26.04.1-Retest failed-login audit und Shell-Timeout (#14)

Führe den Apply aus einer zweiten, bestätigten SSH-/Recovery-Sitzung direkt
ohne externe Pipe aus. Dabei werden keine absichtlichen Fehlversuche gegen den
Remote-Admin-Account durchgeführt:

```bash
sudo ./harden.sh --apply --aggressive
grep -E '^[[:space:]]*FAILLOG_ENAB' /etc/login.defs
grep -E '^[[:space:]]*FTMP_FILE' /etc/login.defs || true
command -v faillog >/dev/null && sudo faillog -a
sudo stat -c '%U:%G %a %s %n' /var/log/btmp
if command -v lastb >/dev/null; then sudo lastb -f /var/log/btmp | head; fi
systemctl is-active systemd-journald.service
sudo sshd -T | grep -E '^(loglevel|syslogfacility) '
sudo cat /root/failed-login-logging-report.txt
sudo env -i HOME=/root PATH="$PATH" bash -lic 'printf "login-shell TMOUT=%s\\n" "$TMOUT"'
sudo env -i HOME=/root PATH="$PATH" bash -lc 'printf "noninteractive TMOUT=%s\\n" "${TMOUT-}"'
```

Der Bericht muss `FAILLOG_ENAB`/`faillog` als Shadow-/Lynis-Nachweis und
`btmp`/`lastb` als separaten utmp-Verlauf zeigen. Auf Ubuntu 26.04 ohne
`lastb` ist dieser Legacy-Pfad ausdrücklich `N/A`; `systemd-journald` aktiv
sowie `sshd -T` mit `LogLevel` mindestens `INFO` und dokumentierter
`SyslogFacility` bilden dann den modernen Konfigurationsnachweis. Es wird
keine tatsächlich geschriebene fehlgeschlagene Anmeldung behauptet. `FTMP_FILE`
wird nur auf Distributionen geprüft, die diese vorhandene `login.defs`-Option verwenden.
Unter Ubuntu 26.04 ist der Gesamtstatus dabei `OK`, wenn `FAILLOG_ENAB=yes`
und dieser moderne Pfad valide sind; ein fehlendes `lastb` oder `faillog` bleibt
jeweils `N/A`.
Der interaktive Login-Shell-Befehl muss `TMOUT=900` ausgeben (oder einen bewusst
gesetzten Admin-Override), der nichtinteraktive Befehl keinen neuen Wert. Prüfe
eine echte fehlgeschlagene Anmeldung ausschließlich auf einer lokalen,
entbehrlichen Test-VM oder einem ausdrücklich freigegebenen Testkonto; niemals
gegen Manu oder den Remote-Admin. Dabei muss die bestehende `pam_faillock`-
Schwelle eingehalten werden. Anschließend `lastb -f /var/log/btmp` erneut
prüfen. Wiederhole den Apply: `btmp`-Inhalt und Metadaten sowie die Timeout-Datei
müssen unverändert bleiben. Das Projekt verwendet ausschließlich metadata-only
capture; ein btmp-Inhalts-Restore oder -Rollback findet nicht statt. SSH-Remote-Kommandos dürfen weiterhin nicht durch
`TMOUT` beeinflusst werden.

### Ubuntu-26.04.1-Retest IPv6, Banner und dynamisches MOTD (#9, #24, #25)

Führe den Apply aus einer zweiten bestätigten SSH-/Recovery-Sitzung direkt
ohne externe `tee`-Pipe aus. Eine IPv6-Deaktivierung ist kein Standardtest:
zuerst wird nur die erkannte Policy geprüft. Tailscale-Prefs, SSH und die
Firewall dürfen dabei unverändert bleiben.

```bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/ipv6-policy-report.txt
cmp -s /etc/issue /etc/issue.net
stat -c '%U:%G:%a %n' /etc/issue /etc/issue.net
cat /etc/issue
find /etc/update-motd.d -maxdepth 1 -type f -printf '%m %f\n' | sort
systemctl cat motd-news.service
stat -c '%a %n' /etc/update-motd.d/50-motd-news
grep -E '^ENABLED=' /etc/default/motd-news
systemctl show -p Result -p ExecMainStatus motd-news.service
sudo ./harden.sh --apply --aggressive
```

Der IPv6-Bericht muss Policy, Grund sowie effektive `all`-/`default`-/Interface-
Werte nennen. Bei aktivem Tailscale, globaler Adresse, IPv6-Default- oder
Policy-Route, Listener oder Forwarding bleibt IPv6 aktiviert und die sicheren
Redirect-/Source-Route-Sysctls werden validiert. Auf dem normalen nicht
forwardenden Host müssen `all` und `default` bei `accept_source_route=-1` und
`forwarding=0` stehen; ein aktiver oder unklarer Forwarding-Zustand wird
erhalten und blockiert eine Deaktivierung. Prüfe danach SSH und Tailscale
einschließlich eines genehmigten `tailscale ping <TAILSCALE-PEER>`.

Die beiden Pre-Login-Banner müssen byte-identisch, `root:root` und `0644` sein.
Der bewusst ausführliche Text gehört ausschließlich in `/etc/issue` und
`/etc/issue.net`, nicht in das Post-Login-MOTD. `accept_source_route=-1` ist
eine absichtlich strengere Linux-Policy als Lynis 3.1.6 `prefval=0`: sie lehnt
alle Routing-Header ab, während `>=0` noch Type 2 zulässt. Diese Abweichung
wird dokumentiert, nicht durch ein Profil-Skip verborgen.

Auf Ubuntu muss `50-motd-news` ausführbar bleiben, da `motd-news.service` den
Hook direkt mit `--force` ausführt. News werden stattdessen mit dem offiziellen
`ENABLED=0`-Schalter in `/etc/default/motd-news` deaktiviert. Ein zuvor
vorhandener `203/EXEC`-Status darf nach einer vom Tool reparierten Berechtigung
gezielt zurückgesetzt werden; der Apply startet oder startet den Dienst nicht neu.

Für die verbleibenden Paket-/Firewall-Findings zusätzlich prüfen:

```bash
sudo apt-get check
sudo cat /root/firewall-rule-inventory.txt
dpkg-query -W -f='${binary:Package}\t${Status}\n' | awk -F '\t' '$2 == "deinstall ok config-files"'
test -e /var/run/reboot-required && cat /var/run/reboot-required.pkgs || true
```

Der Paketpfad darf nur `apt-get upgrade` ohne Removal oder Downgrade ausführen;
ein Full-/Dist-Upgrade ist kein Testfall. FIRE-4513 bleibt sichtbar, wenn die
Inventur keine eindeutig redundante, vom Tool selbst verantwortete Regel
beweist. `LOGG-2190` mit ausschließlich `/memfd:* (deleted)` bleibt eine
sichtbare akzeptierte Ausnahme; Tailscale-, SSH-, Fail2ban-, NAT- und
Forwarding-Regeln sowie Automationspakete werden niemals zur Score-Optimierung
gelöscht bzw. installiert.

Bei verbliebenen `PKGS-7346`-Konfigurationen darf der finale Sweep nur
eindeutig alte rc-Kernelpakete ohne installierten Eigentümer, `/boot`-Artefakt
oder Boot-Symlink purgen. Auf UEFI darf rc-only `grub-pc` nur bei bestätigtem
EFI-GRUB-Stack verschwinden; `grub2-common`, EFI-GRUB- und Shim-Pakete bleiben
installiert. Vor und nach dem Apply daher gezielt prüfen:

```bash
uname -r
dpkg-query -W -f='${binary:Package}\t${Status}\n' \
  'linux-*' 'grub*' 'shim*' 2>/dev/null || true
find /boot -maxdepth 1 -type f \( -name 'vmlinuz-*' -o -name 'initrd.img-*' -o -name 'System.map-*' -o -name 'config-*' \) -printf '%f\n' | sort
test -d /sys/firmware/efi && find /boot/efi/EFI -type f -name '*.efi' -print
sudo apt-get check
```

Ein Purge dieser reinen Konfigurationsreste darf weder den laufenden Kernel
noch die aktuellen `/boot`-Artefakte ändern, `update-grub` auslösen oder für
sich allein einen Reboot verlangen. Bei nicht eindeutiger Bootart oder
Abhängigkeit muss `PKGS-7346` sichtbar bleiben.

Nur auf einer nachweislich IPv6-unbenutzten Test-VM darf zusätzlich der
explizite Opt-in geprüft werden:

```bash
sudo ./harden.sh --dry-run --aggressive --disable-ipv6
sudo ./harden.sh --apply --aggressive --disable-ipv6
sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6
sudo ./harden.sh --apply --aggressive --disable-ipv6
```

Der erste Dry-run muss die Deaktivierung nur planen. Der Apply darf keine
GRUB-Parameter setzen und muss die persistente sysctl-Policy sowie den
kontrollierten Rückkehrweg dokumentieren. Prüfe für `all`, `default`, `lo` und
jede weitere vorhandene IPv6-Instanz jeweils `disable_ipv6=1`. Ein späterer
normaler Apply darf diesen vom Tool gesetzten Zustand nicht überraschend
aufheben, sondern muss `disabled-preserved-existing` reporten. Der Zweitlauf
muss konvergieren.

`/etc/issue` und `/etc/issue.net` müssen exakt `Authorized access only.
Disconnect if you are not authorized.` enthalten und mode `0644` haben;
die vorhandene SSH-Banner-Konfiguration bleibt unangetastet. Auf Ubuntu dürfen
nur Präsentations-Hooks wie Header, Inventar, Update-/Pro-/News-Hinweise nicht
mehr ausführbar sein. Der `98-reboot-required`-Hook bleibt ausführbar. Es
werden weder APT-/Ubuntu-Pro-/unattended-upgrades-Pakete noch Services entfernt.
Ein zweiter Apply darf weder Banner noch Hook-Zustände erneut verändern.

### Ubuntu-26.04.1-Retest UEFI Memory Overwrite Request (#8)

Der MOR-Pfad ist bewusst rein lesend. Die TCG-Spezifikation definiert
`MemoryOverwriteRequestControl` und dessen Lock als von der Firmware
bereitgestellte Variablen; Linux `efivarfs` erlaubt grundsätzlich auch
Änderungen. Deshalb erzeugt, löscht oder überschreibt dieses Tool keine
EFI-Variable. Starte den Apply direkt, ohne externe Pipe, und prüfe nur den
Inspektionsbericht:

Technische Grundlage: [TCG PC Client Platform Reset Attack Mitigation
Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Reset-Attack-Mitigation-Specification-Version-1.2-Revision-10_1April24.pdf)
und die [Linux-efivarfs-Dokumentation](https://docs.kernel.org/filesystems/efivarfs.html).

```bash
sudo ./harden.sh --apply --aggressive
sudo cat /root/uefi-mor-report.txt
test -d /sys/firmware/efi && stat -f -c '%T' /sys/firmware/efi/efivars || true
sudo ./harden.sh --apply --aggressive
```

Auf dem aktuellen Ubuntu-26.04.1-Zielsystem darf `UEFI MOR` nur dann als
`UNSUPPORTED` erscheinen, wenn `efivarfs` verfügbar ist und weder die
standardisierte Control- noch die Lock-Variable exponiert wird. Meldet Lynis
weiterhin `MOR variable not found [ WEAK ]`, ist dies dann ein Firmware-/
Plattformlimit, kein Skriptfehler und wird nicht zur Score-Manipulation
verborgen. Bei vorhandenem UEFI ohne verfügbare `efivarfs`-Runtime muss der
Bericht stattdessen `FAILED-TO-INSPECT` mit dem Hinweis ausgeben, dass der MOR-
Support nicht bestimmt werden kann. Control und Lock müssen jeweils die
Attribute `0x00000007` ausweisen. Sichere bei UEFI-Systemen den Bericht sowie
die unveränderten vorhandenen Variablen-Listings; führe keinerlei manuelle
`echo`, `dd` oder Dateischreiboperation unter `efivars` aus. Wenn die Firmware
MOR bereitstellt, muss der Bericht `SUPPORTED_ACTIVE`, `SUPPORTED_INACTIVE`
oder bei dokumentiertem Lock `LOCKED/firmware-controlled` ausweisen; der
Zweitlauf bleibt dabei ein No-op.

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
