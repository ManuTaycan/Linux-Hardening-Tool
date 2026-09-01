# Linux Hardening Tool

> **WORK IN PROGRESS / PRE-RELEASE / NOT PRODUCTION READY**
>
> Real target validation is currently incomplete. The Ubuntu 26.04.1 Apply
> path still requires a fresh full-system retest through phase 18, and open
> issues remain. No stability or release readiness is promised. Use only on a
> disposable test system or with a verified snapshot and recovery access.

[![CI](https://github.com/ManuTaycan/Linux-Hardening-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/ManuTaycan/Linux-Hardening-Tool/actions/workflows/ci.yml)

Idempotentes Bash-Werkzeug zur aggressiven, überprüfbaren Härtung frischer
Ubuntu- und Debian-Server mit Dry-Run, Backups, Rollback, Lynis-Auswertung und
systemd-Service-Sandboxing.

**Version:** 1.1.3
**Status:** Pre-Release / Zielsystemtest ausstehend

## Wichtiger Sicherheitshinweis

Das Skript verändert systemweite Sicherheitskonfigurationen. Erstelle vorher
einen Snapshot oder ein vollständiges Backup, halte eine zweite SSH-Sitzung
offen und starte immer mit einem Dry-Run. `--aggressive` kann die Kompatibilität
einschränken. Das Werkzeug ist primär für frische Server gedacht.

Es wird kein Lynis-Score garantiert. Ein hoher Lynis-Score ersetzt keine
Bedrohungsanalyse, keine Rollenprüfung und keine Abnahme auf dem Zielsystem.

## Aktueller Validierungsstatus

Version 1.1.3:

- `bash -n` bestanden
- statische Regressionstests bestanden
- simulierte pwck-/Phasen-/AIDE-/systemd-Pfade bestanden
- realer vollständiger Ubuntu-26.04.1-Lauf noch ausstehend
- Ziel Hardening Index >= 90 noch nicht bestätigt

Letzter realer Stand mit Version 1.1.2: Lynis Hardening Index **86**.

## Funktionen

- Ubuntu-/Debian-Erkennung, Dry-Run, Apply und aggressiver Modus
- Backups, transaktionale Rollbacks und farbige Phasenanzeige
- SSH-Hardening ohne Portänderung, nftables mit Tailscale-Rücksicht und
  optionales Remote-rsyslog
- auditd, AIDE, AppArmor, Fail2ban, PAM-/Passwortregeln sowie Kernel-/sysctl-
  Hardening und Modulblockierung
- Paket-/Update-Hardening, gezielte Service-Deaktivierung und systemd-
  Sandboxing mit gemessener Exposure vor/nach der Änderung
- gemessene Lynis-Baseline plus zwei Post-Hardening-Läufe, offene Findings und
  Abschlussberichte; im Dry-Run wird kein schreibender Lynis-Scan gestartet
- nachvollziehbare AIDE-/PackageKit-/Compiler-/binfmt-Entscheidungsartefakte
  sowie zeitlich wiederholte, rein diagnostische PROC-3614-Snapshots
- ein spätes Tailscale-/Netfilter-aware Kernelmodul-Gate, das benötigte
  modulare NAT-Komponenten vorlädt und den irreversiblen Lock bei unbewiesener
  Dual-Stack-/Tailscale-Gesundheit sicher blockiert

## Installation per Git

```bash
git clone https://github.com/ManuTaycan/Linux-Hardening-Tool.git
cd Linux-Hardening-Tool
git pull --ff-only
chmod +x harden.sh
sha256sum -c SHA256SUMS
sudo ./harden.sh --dry-run --aggressive
```

## Aktualisierung

```bash
cd Linux-Hardening-Tool
git status
git pull --ff-only
sha256sum -c SHA256SUMS
bash -n harden.sh
```

`git pull --ff-only` überschreibt keine lokalen Änderungen automatisch.

## Direkter Download per curl

Lade herunter, prüfe die Prüfsumme und führe erst dann bewusst aus:

```bash
mkdir -p ~/Linux-Hardening-Tool
cd ~/Linux-Hardening-Tool

curl -fsSLO https://raw.githubusercontent.com/ManuTaycan/Linux-Hardening-Tool/main/harden.sh
curl -fsSLO https://raw.githubusercontent.com/ManuTaycan/Linux-Hardening-Tool/main/SHA256SUMS

sha256sum -c SHA256SUMS
chmod +x harden.sh
sudo ./harden.sh --dry-run --aggressive
```

## Installer

Der Installer installiert nur das geprüfte Skript; er startet kein Hardening.

```bash
curl -fsSLO https://raw.githubusercontent.com/ManuTaycan/Linux-Hardening-Tool/main/install.sh
less install.sh
sudo bash install.sh --ref main
```

`main` ist der Entwicklungsstand. Für einen späteren geprüften Tag verwende
`--ref <tag>`. `--install-path` bezeichnet immer die Zieldatei, nicht ein
Verzeichnis; angelegt wird nur der übergeordnete Pfad. Für einen späteren
geprüften Tag verwende beispielsweise `--ref v1.1.3`.

```bash
sudo bash install.sh --ref main \
  --install-path /usr/local/sbin/linux-hardening-tool
linux-hardening-tool --help
sudo linux-hardening-tool --dry-run --aggressive
```

## Nutzung

```bash
sudo ./harden.sh --dry-run
sudo ./harden.sh --dry-run --aggressive
sudo ./harden.sh --apply
sudo ./harden.sh --apply --aggressive
# Only on an unequivocally unused IPv6 host, after reviewing the dry-run:
sudo ./harden.sh --apply --aggressive --disable-ipv6
# Optional reversible SSH port stage; the old port remains active:
sudo ./harden.sh --apply --aggressive --ssh-port 52022
# Only after a separately verified new SSH session:
sudo ./harden.sh --apply --aggressive --non-interactive --retire-ssh-port
```

Nicht-interaktives Remote Logging:

```bash
sudo ./harden.sh \
  --apply \
  --aggressive \
  --remote-log-server 10.0.0.9 \
  --remote-log-port 5140 \
  --remote-log-protocol tcp
```

## Absichtlich unveränderte Bereiche

- Der SSH-Port bleibt standardmäßig unverändert.
- Eine Portänderung ist ausschließlich eine optionale, zweistufige Migration:
  `--ssh-port PORT` hält den bisherigen Port zunächst parallel aktiv. Ein anderer
  Port verringert nur Scan- und Log-Noise; starke Authentifizierung, Firewall
  und Fail2ban bleiben die tatsächlichen Schutzmaßnahmen. Der alte Port wird
  erst in einem späteren Lauf nach bestätigter neuer SSH-Sitzung mit
  `--retire-ssh-port` entfernt.
- Es wird kein GRUB-Passwort eingerichtet.
- `/home` und `/var` werden nicht automatisch live repartitioniert.
- Für den Admin-Account wird kein festes Ablaufdatum erzwungen.
- Fehlgeschlagene Anmeldungen werden mit getrennten Nachweisen geprüft:
  `FAILLOG_ENAB`/gegebenenfalls `faillog` für Shadow `login(1)` sowie
  `btmp`/`lastb` für die utmp-Historie. Die bestehende `pam_faillock`-Policy
  wird dabei nicht durch eine zweite Lockout-Policy ersetzt.
- Interaktive Login-Shells erhalten standardmäßig `TMOUT=900`. Nichtinteraktive
  SSH-Kommandos, scp/sftp, Cron, systemd und Skripte werden nicht beeinflusst;
  ein bereits gesetztes `TMOUT` oder `HARDEN_SHELL_TMOUT` bleibt maßgeblich.
- IPv6 bleibt standardmäßig aktiviert. `--disable-ipv6` ist nur zusammen mit
  `--aggressive` ein explizites Opt-in und wird bei Tailscale, IPv6-Nutzung
  oder einer unklaren Routing-Situation sicher verweigert.
- Der aggressive Modus entfernt keine dynamischen-MOTD-Pakete oder Dienste;
  er schaltet nur ausgewählte Ubuntu-Präsentations-Hooks ab und erhält die
  technisch getrennte Reboot-Benachrichtigung.
- Kein Lynis-Test wird deaktiviert; es gibt keine kosmetische Score-Manipulation.

## Ergebnisdateien

Nach einem Apply-Lauf sind unter anderem folgende Dateien relevant:

```text
/var/log/server-hardening.log
/root/hardening-open-findings.txt
/root/systemd-hardening-report.txt
/root/lynis-after-hardening-pass1.txt
/root/lynis-after-hardening.txt
/root/lynis-after-hardening-report.dat
/root/lynis-summary-parse-diagnostics.txt (nur bei Parsefehler)
/root/hardening-iowait-processes.txt
/root/kernel-module-lockdown-report.txt
/root/hardening-backup-YYYYMMDD-HHMMSS/
```

## Tests und Issues

Der vollständige Zielsystemablauf steht in [docs/TESTING.md](docs/TESTING.md).
Nach einem Zielsystemtest wird jedes Finding als einzelnes, begrenztes Issue
angelegt. Prüfe Logs vor einer Veröffentlichung auf sensible Daten; poste niemals
Sicherheitsgeheimnisse in einem öffentlichen Issue.

## Lizenz

Für dieses Repository ist noch keine Lizenz festgelegt.
