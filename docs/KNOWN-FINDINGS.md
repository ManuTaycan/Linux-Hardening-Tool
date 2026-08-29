# Bewusst offene Lynis-Findings

Diese Punkte werden nicht durch kosmetische Änderungen verborgen. Sie benötigen
eine konkrete Betreiberentscheidung oder ein Wartungsfenster.

| Finding | Begründung und Sicherheitsauswirkung | Mögliche manuelle Alternative |
| --- | --- | --- |
| DEB-0810 | `apt-listbugs` ist Debian-orientiert; ein erzwungener Ubuntu-Einsatz kann Update-Abläufe stören. | Nur aus einer vertrauenswürdigen, passenden Quelle einsetzen. |
| BOOT-5122 | Kein GRUB-Passwort, damit unbeaufsichtigter Reboot und Remote-Recovery möglich bleiben. | Konsolenprozess und Recovery-Verfahren für Boot-Authentifizierung planen. |
| SSH-7408: Port | Eine Portänderung ist keine belastbare Sicherheitsgrenze und kann Lockout verursachen. | Zugriff über Firewall, Schlüssel, MFA/Bastion und Monitoring absichern. |
| FILE-6310 | `/home` und `/var` werden nicht live repartitioniert. | Geplante LVM-/Partitionsmigration mit getesteter Rückkehrstrategie. |
| AUTH-9230 | YESCRYPT wird nicht mit Legacy-SHA-Runden „optimiert“. | Lynis-/Profilunterstützung prüfen, nicht wirkungslose SHA-Werte setzen. |
| NAME-4028 | Keine erfundene DNS-Domain. | Gültiges Forward-/Reverse-DNS mit dem Betreiber einrichten. |
| AUTH-9282 | Kein pauschales Account-Ablaufdatum; das könnte Recovery oder Dienstkonten sperren. | Kontospezifische Ablaufdaten nach Eigentümerfreigabe setzen. |
| Failed-login audit | `FAILLOG_ENAB=yes` ist der Lynis-/Shadow-Indikator für `login(1)`/`faillog`; `/var/log/btmp` und `lastb` sind ein separater utmp-basierter Verlauf. Bestehendes `pam_faillock` ist die einzige Lockout-Policy. | Keine absichtlichen Fehlversuche gegen Remote-Admin-Konten; nur in einer lokalen, entbehrlichen Testumgebung prüfen. |
| Tailscale/rp_filter | Bei aktivem Tailscale ist `rp_filter=2` für `all`, `default`, relevante aktive Interfaces und `tailscale0` eine bewusste Kompatibilitäts-/Sicherheitsabwägung für asymmetrische Overlay-Routen. Ohne Tailscale wird `1` nur bei eindeutig einfachem IPv4-Routing gesetzt; Policy-Routing oder mehrere Default-Pfade bleiben mit Diagnosebericht unverändert. | Tailscale entfernen oder Routing so vereinfachen, dass striktes Filtering nachweislich sicher ist. |
| MOR variable not found | Nur bei verfügbarer `efivarfs`-Runtime und fehlenden standardisierten MOR-Variablen ist dies ein bestätigtes Firmware-Limit. Fehlt der UEFI-Runtime-Variablen-Zugriff, bleibt der Support unbekannt. Das Tool erzeugt oder überschreibt keine EFI-Variable. | Firmware-/Plattformdokumentation prüfen und nur eine vom Hersteller unterstützte MOR-Konfiguration verwenden. |

Jede Zeile ist eine dokumentierte Risikoabwägung, keine Score-Manipulation.
