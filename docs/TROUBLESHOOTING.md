# Troubleshooting

## Execute-Bit oder `Permission denied`

Prüfe `ls -l harden.sh`, kopiere das Repository nicht auf ein Dateisystem mit
`noexec` und setze gegebenenfalls `chmod +x harden.sh`.

## SSH, nftables und Tailscale

Halte die zweite SSH-Sitzung offen. Prüfe vor einem Reload `sshd -t`, kontrolliere
die nftables-Regeln und teste Tailscale-Routing separat. Bei einem Problem den
gesicherten Backup-Zustand oder Snapshot wiederherstellen.

## rsyslog oder Remote-Ziel nicht erreichbar

Prüfe Ziel, Port, Transport, DNS, Firewall und bei TLS die CA-Datei. Der lokale
Logging-Pfad muss unabhängig vom Remote-Ziel weiter funktionieren.

## systemd-Drop-in wurde zurückgerollt

Sieh in `/root/systemd-hardening-report.txt`, die vor/nach gespeicherten
`systemd-analyze`-Ausgaben und `journalctl -u NAME.service`. Entferne keine
Schutzoptionen blind; teste den Dienstzweck und erstelle einen gezielten Fix.

## AIDE dauert lange

Eine Baseline liest viele Dateien und kann I/O-intensiv sein. Nicht abbrechen,
ohne den Zustand von Datenbank, Timer und Backup zu prüfen.

## `kernel.modules_disabled=1`

Diese aggressive Einstellung ist bis zum Reboot irreversibel. Teste benötigte
Kernelmodule vorher und stelle bei Problemen per Reboot/Snapshot wieder her.

## Lauf endet vor Phase 18

Der EXIT-Trap meldet die aktuelle Phase. Lies `/var/log/server-hardening.log`,
das Backup und die konkrete Fehlermeldung; starte keinen neuen Apply-Lauf, bevor
die Ursache und der Rollback-Stand geklärt sind.
