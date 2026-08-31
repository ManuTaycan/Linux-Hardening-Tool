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
| IPv6 policy | IPv6 wird nicht allein für einen Lynis-Wert deaktiviert. Tailscale, globale Adressen, Default-/Policy-Routes, Listener oder Forwarding blockieren eine Deaktivierung; ohne explizites `--disable-ipv6` bleibt IPv6 aktiviert. | Nur auf einem nachweislich ungenutzten IPv6-Host `--apply --aggressive --disable-ipv6` wählen und den IPv6-Bericht prüfen. |
| KRNL-6000: IPv6 source routing | Lynis 3.1.6 erwartet `accept_source_route=0`; Linux behandelt `-1` jedoch strenger, weil damit alle IPv6-Routing-Header abgelehnt werden, während Werte ab `0` noch Type 2 zulassen. | Die validierte `-1`-Policy beibehalten; keine Lynis-Profile oder Tests überspringen. |
| FIRE-4513 | iptables-nft/nftables können Regeln enthalten, die Lynis als ungenutzt einordnet. Das Tool inventarisiert sie, löscht aber keine fremden, Tailscale-, SSH-, Fail2ban-, NAT- oder Forwarding-Regeln. | `/root/firewall-rule-inventory.txt` während eines Wartungsfensters prüfen und nur nachweislich redundante, lokal verantwortete Regeln entfernen. |
| LOGG-2190 anonymous memfd | `/memfd:* (deleted)` mit Link-Count 0 sind volatile anonyme RAM-Objekte, keine verwaisten persistenten Dateien. Sie bleiben sichtbar und lösen keine Restart-/Reboot-Schleife aus. | Nur echte actionable deleted-open files gemäß Report und Service-Klassifikation behandeln. |
| TOOL-5002 | Ein fehlendes Automationswerkzeug ist deploymentspezifisch. Ansible/Puppet/Chef/Salt werden nicht allein für eine Lynis-Heuristik installiert. | Ein vorhandenes, betriebenes Configuration-Management-System bewusst einführen und absichern. |
| MOR variable not found | Nur bei verfügbarer `efivarfs`-Runtime und fehlenden standardisierten MOR-Variablen ist dies ein bestätigtes Firmware-Limit. Fehlt der UEFI-Runtime-Variablen-Zugriff, bleibt der Support unbekannt. Das Tool erzeugt oder überschreibt keine EFI-Variable. | Firmware-/Plattformdokumentation prüfen und nur eine vom Hersteller unterstützte MOR-Konfiguration verwenden. |

Jede Zeile ist eine dokumentierte Risikoabwägung, keine Score-Manipulation.
