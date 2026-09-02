# Known findings and deliberate exceptions

These findings are not hidden by cosmetic changes. Each requires an operator
decision, a maintenance window, or a platform capability outside the tool.

| Finding | Rationale and security impact | Manual alternative |
| --- | --- | --- |
| DEB-0810 | apt-listbugs is Debian-oriented; forcing it on Ubuntu can disrupt updates. | Use a trusted, distribution-appropriate source only. |
| BOOT-5122 | No GRUB password is configured so unattended reboot and remote recovery remain possible. | Design a console and recovery process for boot authentication. |
| SSH-7408: Port | Changing the port is not a strong security boundary and can cause lockout. | Protect access with keys, firewalling, MFA/bastion, and monitoring. |
| FILE-6310 | /home and /var are never repartitioned live. | Plan and test an LVM or partition migration. |
| AUTH-9230 | YESCRYPT is not “optimized” with legacy SHA rounds. | Use supported Lynis/profile behavior; do not add ineffective SHA settings. |
| NAME-4028 | The tool does not invent a DNS domain. | Configure valid forward and reverse DNS. |
| AUTH-9282 | No blanket account-expiration date is set because it can lock out recovery or service accounts. | Set account-specific expiry after owner approval. |
| Failed-login audit | FAILLOG_ENAB=yes is the Lynis/Shadow indicator for login(1)/faillog; btmp/lastb is separate history. Existing pam_faillock remains the only lockout policy. | Test failures only on a disposable local VM or approved test account. |
| Tailscale / rp_filter | Active Tailscale uses loose mode 2 for compatible asymmetric overlay routes. Without Tailscale, strict mode 1 is set only after simple-routing proof. | Remove Tailscale or simplify routing before enforcing strict filtering. |
| IPv6 policy | IPv6 is not disabled merely for a Lynis value. Tailscale, addresses, routes, listeners, or forwarding block disable. | Use explicit disable only on a proven-unused IPv6 host. |
| KRNL-6000 | Linux accept_source_route=-1 is stricter than Lynis 3.1.6 prefval=0: it rejects all routing headers. | Keep the validated -1 policy; do not skip Lynis tests. |
| FIRE-4513 | Foreign nftables/iptables rules are inventoried but not deleted without ownership proof. | Review /root/firewall-rule-inventory.txt in a maintenance window. |
| LOGG-2190 anonymous memfd | /memfd:* (deleted) with link count 0 is volatile anonymous RAM, not an orphaned persistent file. | Act only on actionable deleted-open files in the report. |
| TOOL-5002 | A configuration-management tool is deployment-specific. | Introduce an operated CM system deliberately. |
| MOR variable not found | With available efivarfs and absent standardized MOR variables, this is a firmware limit. The tool never writes EFI variables. | Follow firmware vendor guidance only. |

These entries document risk decisions; they are not score manipulation.
