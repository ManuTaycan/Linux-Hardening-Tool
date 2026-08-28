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
sudo cp /root/lynis-after-hardening.txt ./lynis-after.log
```

Der offizielle Apply-/Zielsystemtest wird direkt und ohne externe Pipe oder
`tee` gestartet. Nur so bleibt die automatische TTY-Farberkennung aktiv; das
Skript schreibt den vollständigen ANSI-freien Lauf selbst nach
`/var/log/server-hardening.log`. `--no-color` oder `NO_COLOR` deaktivieren die
interaktive Farbausgabe. Prüfe vor dem Hochladen
`scripts/collect-test-artifacts.sh`-Archive auf sensible Informationen.
