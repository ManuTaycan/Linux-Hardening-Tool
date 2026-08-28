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
| Tailscale/rp_filter | `rp_filter=2` bleibt bei aktivem Tailscale für asymmetrische Overlay-Routen erhalten. | Tailscale entfernen oder Routing so ändern, dass striktes Filtering sicher ist. |

Jede Zeile ist eine dokumentierte Risikoabwägung, keine Score-Manipulation.
