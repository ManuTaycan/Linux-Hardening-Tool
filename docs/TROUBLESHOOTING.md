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

`FINT-4402` liest in Lynis 3.1.6 nur die erkannte primäre AIDE-Konfiguration;
Lynis expandiert deren Include-Dateien für diesen Test nicht. Das Skript hält
deshalb die tatsächlich wirksame `HardenSHA2`-Gruppendefinition in der primären
Runtime-Konfiguration und die überwachten Pfade im Include. Prüfe bei einem
Restbefund `aide-lynis-FINT-4402-evidence.txt` und `aide --config-check`; füge
keine wirkungslose Kommentarzeile nur für den Score ein.

## PackageKit, Compiler und binfmt

Die Entscheidungsartefakte liegen im Lauf-Backup. Ein unsicherer PackageKit-
oder Compiler-Purge wird abgebrochen, nicht erzwungen. Wiederherstellung eines
bewusst entfernten Pakets erfolgt aus den konfigurierten Distributionsquellen
mit `apt-get install PAKET`; anschließend APT und die zugehörigen Dienste
validieren. Erhaltene Compiler werden nach Paketupdates erneut root-only
gesetzt. Kernel-Headers allein sind kein Purge-Veto; aktive DKMS-Nutzung und
jede simulierte nicht zur Toolchain gehörende Abhängigkeit bleiben es.

Die distributionsseitige `python3.X`-binfmt-Regel dient nur dem direkten Start
versionsspezifischer kompilierter `.pyc`-Dateien. Auf einem Host ohne geschützte
Fremdformat-Verbraucher kann das Skript genau diese Vendor-Datei über den von
systemd vorgesehenen gleichnamigen `/etc/binfmt.d/... -> /dev/null`-Override
maskieren und nur die passende Laufzeitregistrierung entfernen. Normales
Python, APT, systemd und andere Registrierungen werden danach geprüft. Unbekannte
oder qemu-/Wine-/JVM-Formate werden weiterhin erhalten; sie lösen keinen blinden
globalen Modul-Blacklist-Pfad aus.

## Lynis-Summary oder Fail2ban widersprüchlich

Prüfe `lynis-after-hardening-report.dat`,
`lynis-summary-parse-diagnostics.txt` und das Backup-Artefakt
`fail2ban-runtime.txt`. Der Fail2ban-Status setzt einen aktiven Dienst, eine
erfolgreiche Server-Ping-Antwort und den live abfragbaren `sshd`-Jail voraus.

## `PROC-3614`

`/root/hardening-iowait-processes.txt` enthält wiederholte D-State-Snapshots
mit Unit und Wait-Channel. Kurzlebige I/O-Waits sind erwartbar; wiederholt
gleiche PIDs erfordern Storage-/Filesystem-Diagnose. D-State-Prozesse nicht
blind killen oder Storage zurücksetzen.

## `kernel.modules_disabled=1`

Diese aggressive Einstellung ist bis zum Reboot irreversibel. Teste benötigte
Kernelmodule vorher und stelle bei Problemen per Reboot/Snapshot wieder her.

Bei aktivem Tailscale setzt der späte Lock den Wert nur nach erfolgreicher
Netfilter-/NAT-Vorladung und Dual-Stack-Runtimeprüfung. Prüfe bei einer
fehlgeschlagenen `kernel-module-lockdown.service` zuerst
`/root/kernel-module-lockdown-report.txt` und
`journalctl -u kernel-module-lockdown.service -b`. Ein fehlgeschlagenes Gate
ist absichtlich kein Erfolg: `kernel.modules_disabled` bleibt 0, damit der
Systemzugriff erhalten und eine gezielte Reparatur möglich bleibt. Das Gate
ändert keine Tailscale-Routen, Exit-Node-, Accept-Routes- oder Advertise-Routes-
Einstellungen. Ist der Wert bereits 1, erfolgen keine `modprobe`-Versuche.
Auf einem bereits fehlerhaft gesperrten Host installiert ein aktualisierter
Apply-Lauf zwar den korrigierten Helper, die Preload-/Lock-Units und das
Tailscale-Drop-in, kann fehlende Module im laufenden Kernel aber absichtlich
nicht nachladen. Die Runtime-Reparatur wird erst nach einem kontrollierten
Reboot wirksam: Die neue Preload-Unit läuft vor `tailscaled.service`, danach
validiert die späte Lock-Unit denselben Gate-Pfad. Ein anschließender zweiter
Apply-Lauf muss den bereits gesetzten Wert ohne `modprobe` idempotent
bestätigen.

## Lauf endet vor Phase 18

Der EXIT-Trap meldet die aktuelle Phase. Lies `/var/log/server-hardening.log`,
das Backup und die konkrete Fehlermeldung; starte keinen neuen Apply-Lauf, bevor
die Ursache und der Rollback-Stand geklärt sind.
