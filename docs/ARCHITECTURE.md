# Architektur

`harden.sh` ist ein idempotentes Bash-Werkzeug mit getrenntem Dry-Run- und
Apply-Modell. Managed Files werden atomar erstellt; vor Änderungen werden
Konfigurationen und relevante Zustände in einem Backup-Verzeichnis gesichert.
Einzelne riskante Änderungen verwenden zusätzlich transaktionale Rollbacks.

## Ablauf

Nur `main()` steuert die Phasenfolge:

1. Preflight
2. Backup
3. Package Security
4. Logging
5. Kernel Hardening
6. Authentication
7. Firewall
8. SSH
9. Audit
10. Filesystems
11. Services
12. AppArmor
13. Validation
14. Lynis Pass 1
15. Optimization Pass
16. AIDE
17. Lynis Final
18. Summary

`CURRENT_PHASE` verhindert doppelte oder gemischte Aufrufe. Der EXIT-Trap
meldet einen unvollständigen Lauf sichtbar und liefert dann keinen Exit 0.

## Validierung und Abschluss

Phase 13 sammelt Validierungsdaten. Phase 14 und 17 führen Lynis aus; Phase 16
stellt sicher, dass die AIDE-Konfiguration, eine nichtleere Datenbank, ein
lesbarer Check und der Timer vor dem finalen Lynis-Lauf vorhanden sind. Ein
erfolgreicher Apply-Lauf benötigt Phase 18 sowie erfolgreiche Validation-,
Final-Lynis- und Summary-Gates.

## Dienste

Deaktivierte Dienste und gehärtete Dienste sind getrennte Konzepte. Eine
Deaktivierung wird über enabled-, active- und mask-Zustand geprüft. Ein
Sandbox-Drop-in wird als zusammengeführte Kandidaten-Unit vor der Installation
und anschließend nochmals als installierte Unit geprüft. Nur nach
`daemon-reload`, Dienst-Healthcheck und Exposure-Messung bleibt es erhalten;
bei Fehlern wird der vorherige Zustand wiederhergestellt.
