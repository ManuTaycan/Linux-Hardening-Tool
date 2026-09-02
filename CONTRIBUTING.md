# Contributing

Use one focused branch and pull request per issue. Keep the change bounded,
describe its security effect and rollback path, and do not mix unrelated
cleanup into a hardening fix.

Changes to harden.sh require reproducible evidence, idempotency coverage, and a
documented rollback path. A change must not exist solely to improve a Lynis
score. Preserve explicit project policies unless the issue changes them:
default SSH port 22, no GRUB password, no live repartitioning, and no hidden
Tailscale preference changes.

Bash code must remain compatible with set -Eeuo pipefail, quote inputs, clean
up temporary files, and keep failure paths visible. Before opening a PR, run
make check, verify SHA256SUMS if harden.sh changed, and redact all logs. Never
commit secrets, access tokens, private keys, production IP details, or
unredacted test archives.
