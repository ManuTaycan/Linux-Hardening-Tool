# Linux Hardening Tool

> **WORK IN PROGRESS · PRE-RELEASE · NOT PRODUCTION READY**
>
> This repository changes system-wide security configuration. It is intended
> for fresh Ubuntu and Debian servers, only with a verified snapshot or backup
> and a tested recovery path. Target-system acceptance exists for bounded
> changes, but the current development branch has not received release
> approval. Do not treat a Lynis score as a security guarantee.

harden.sh is an idempotent Bash tool for observable Ubuntu/Debian server
hardening. It separates planning from mutation, records a backup before
changes, validates high-risk transitions, and reports decisions instead of
hiding unresolved findings.

**Version:** 1.1.3

**Release status:** pre-release; not production-ready

**Supported families:** Ubuntu and Debian with systemd and APT

## What it does

- Supports --dry-run, --apply, and an explicit --aggressive mode.
- Takes a pre-change backup and uses transaction-backed rollback for risky
  changes.
- Runs a measured Lynis baseline during Apply, then validates and records
  post-hardening results. Dry-run does not start a write-producing Lynis scan.
- Hardens package handling, logging, authentication, SSH, firewalling,
  filesystems, selected services, AppArmor, AIDE, kernel/sysctl settings, and
  audit paths.
- Treats Tailscale, IPv6, boot state, systemd service health, and kernel module
  locking as runtime policies with safety gates.
- Preserves deliberate exceptions such as anonymous memfd entries and
  Tailscale-compatible rp_filter=2 in reports instead of score gaming.

## Hardening flow

~~~mermaid
flowchart LR
    O[Operator] --> D[Dry run]
    O --> A[Apply]
    D --> P[Plan and diagnostics only]
    A --> B[Phase 01: preflight and Lynis baseline]
    B --> K[Phase 02: backup]
    K --> H[Phases 03-12: controlled hardening]
    H --> V[Phase 13: validation]
    V --> L[Phases 14-17: Lynis, AIDE, final gates]
    L --> S[Phase 18: summary]
    H -. failed validation .-> R[Targeted rollback and visible failure]
~~~

The phase order is fixed. An incomplete Apply is reported by the EXIT trap and
cannot exit successfully before Phase 18.

## Recorded validation evidence

The following is historical target-system acceptance evidence, not a release
promise or a guarantee for another server role:

| Environment | Recorded outcome |
| --- | --- |
| Ubuntu 26.04.1 fresh aggressive Apply | Lynis 63 → 87; AIDE baseline rebuilt 1 |
| Ubuntu 26.04.1 converged Apply | Lynis 87 → 87; AIDE baseline rebuilt 0; no package changes, failed services, rollbacks, or reboot request |
| Failed-login and shell-timeout acceptance | Lynis recorded failed-login logging enabled and session timeout found; interactive TMOUT=900, non-interactive shell unchanged |
| UEFI MOR acceptance | efivarfs was available but firmware exposed neither standardized MOR variable; status UNSUPPORTED, detection-only, no EFI write |

~~~mermaid
flowchart LR
    F[Fresh Ubuntu 26.04.1] --> L1[Lynis 63 → 87]
    F --> A1[AIDE baseline rebuilt: 1]
    C[Converged second Apply] --> L2[Lynis 87 → 87]
    C --> A2[AIDE baseline rebuilt: 0]
    C --> N[No package changes · no failed services · no rollbacks · reboot NO]
~~~

Scores are run-specific observations. The tool does not skip Lynis checks,
tune profiles, or claim a target score.

## Before you run it

1. Create a tested snapshot or full backup.
2. Keep a second SSH session and a recovery method available.
3. Review the dry-run before Apply.
4. Use a maintenance window for any real server.
5. Read [Testing](docs/TESTING.md), [Known findings](docs/KNOWN-FINDINGS.md),
   and [Troubleshooting](docs/TROUBLESHOOTING.md).

--aggressive can reduce compatibility. Do not use it as a substitute for threat
modeling, role-specific review, access control, monitoring, or a tested
rollback plan.

## Quick start

~~~bash
git clone https://github.com/ManuTaycan/Linux-Hardening-Tool.git
cd Linux-Hardening-Tool
sha256sum -c SHA256SUMS
bash -n harden.sh
sudo ./harden.sh --dry-run --aggressive
~~~

After reviewing the plan:

~~~bash
sudo ./harden.sh --apply --aggressive
~~~

Run the official Apply directly in a TTY; do not wrap it in external tee. The
script preserves interactive color output and writes an ANSI-free complete log
to /var/log/server-hardening.log itself.

## Installation

The installer verifies the checksum and installs the executable; it never runs
hardening automatically.

~~~bash
curl -fsSLO https://raw.githubusercontent.com/ManuTaycan/Linux-Hardening-Tool/main/install.sh
less install.sh
sudo bash install.sh --ref main \
  --install-path /usr/local/sbin/linux-hardening-tool

linux-hardening-tool --help
sudo linux-hardening-tool --dry-run --aggressive
~~~

main is a development branch. --ref <tag> is intended for a future reviewed tag.
--install-path is always the target executable file; only its parent directory
is created when missing.

## Common commands

~~~bash
sudo ./harden.sh --dry-run
sudo ./harden.sh --dry-run --aggressive
sudo ./harden.sh --apply
sudo ./harden.sh --apply --aggressive

# Only after a dry-run proves IPv6 is unused and safe to disable:
sudo ./harden.sh --apply --aggressive --disable-ipv6

# Optional, staged SSH port migration; the old port remains active:
sudo ./harden.sh --apply --aggressive --ssh-port 2222

# Only after proving a new SSH session on the staged port:
sudo ./harden.sh --apply --aggressive --non-interactive --retire-ssh-port
~~~

For remote logging:

~~~bash
sudo ./harden.sh --apply --aggressive \
  --remote-log-server 10.0.0.9 \
  --remote-log-port 5140 \
  --remote-log-protocol tcp
~~~

## Safety boundaries

- SSH port 22 remains the default. A different port only reduces scan and log
  noise; it is not an authentication control. The two-stage migration keeps
  the old port until a separately verified new session exists.
- No GRUB password is created, and /home or /var are never live repartitioned.
- IPv6 remains enabled by default. Disabling it is an aggressive explicit
  opt-in and is blocked when Tailscale, addresses, routes, listeners,
  forwarding, or ambiguous routing make it unsafe.
- Tailscale preferences, routes, exit-node state, and owned firewall rules are
  not changed merely to satisfy a scanner.
- kernel.modules_disabled=1 is only written after the final runtime gate.
- FAILLOG_ENAB/optional faillog, legacy btmp/lastb, and the modern
  journald/SSH path are distinct forms of failed-login evidence. Existing
  pam_faillock remains the only lockout policy.
- Interactive login shells receive TMOUT=900 by default. Non-interactive SSH
  commands, scp/sftp, cron, systemd, and scripts are not affected.
- Aggressive Ubuntu MOTD handling changes presentation hooks only. It does not
  remove APT, unattended-upgrades, Ubuntu Pro, network, or monitoring packages.

## Reports and backups

Important outputs include:

~~~text
/var/log/server-hardening.log
/root/hardening-open-findings.txt
/root/systemd-hardening-report.txt
/root/lynis-before-hardening.txt
/root/lynis-after-hardening.txt
/root/lynis-after-hardening-report.dat
/root/kernel-module-lockdown-report.txt
/root/hardening-backup-YYYYMMDD-HHMMSS/
~~~

Inspect and redact logs before sharing them. Never publish credentials, tokens,
private keys, IP-sensitive production data, or unredacted diagnostic archives.

## Documentation

- [Architecture and hardening flow](docs/ARCHITECTURE.md)
- [Target-system and local testing](docs/TESTING.md)
- [Known findings and deliberate exceptions](docs/KNOWN-FINDINGS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Release procedure](docs/RELEASING.md)

## License

No license has been selected. This repository does not grant a license by
implication; release and licensing decisions remain outside this change.
