# Architecture

harden.sh is an idempotent Bash tool with separate Dry-run and Apply models.
Managed files are installed atomically. Apply captures a backup before mutation,
and high-risk operations add transaction-backed rollback and runtime validation.

## Phase model

Only main() controls the fixed 18-phase order:

1. Preflight and Lynis baseline
2. Backup
3. Package security
4. Logging
5. Kernel hardening
6. Authentication
7. Firewall
8. SSH
9. Audit
10. Filesystems
11. Services
12. AppArmor
13. Validation
14. Lynis pass 1
15. Optimisation pass
16. AIDE
17. Final Lynis and final kernel gate
18. Summary

CURRENT_PHASE rejects skipped, duplicated, or out-of-order calls. The EXIT trap
reports incomplete runs and prevents a successful exit before Phase 18.

## Validation gates

In Apply mode, Phase 01 captures a separate pre-hardening Lynis console report
and report.dat. Dry-run reports N/A / NOT RUN and does not launch that
write-producing scan. Phase 13 validates the configured system state; phases
14 and 17 collect post-hardening Lynis evidence. Phase 16 requires a valid AIDE
runtime configuration, non-empty active database, successful check-service run,
and enabled timer before final completion.

The aggressive kernel-module lock is intentionally last. On Tailscale hosts,
the shared runtime helper classifies required netfilter/NAT features, loads only
available modular components, and proves firewall, NAT, Tailscale chain,
backend, and router/netfilter health before writing kernel.modules_disabled=1.
Failed prerequisites leave module loading enabled, fail visibly, and record
/root/kernel-module-lockdown-report.txt.

The helper does not change Tailscale preferences and never calls tailscale up
or tailscale set.

## Service controls

Service disabling and service sandboxing are different operations. Disabled
services are checked for enabled, active, and masked state. A sandbox drop-in
is rendered as a merged candidate and validated before installation; the
installed unit is validated again. It is retained only after daemon-reload,
service-specific health checks, and the relevant exposure or compatibility
gate. Otherwise the prior state is restored.
