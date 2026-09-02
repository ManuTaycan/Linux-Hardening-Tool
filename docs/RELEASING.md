# Releasing

This repository is currently pre-release. No tag or GitHub Release is created
by this document.

Before proposing a release:

1. Complete target-system acceptance for the exact release commit.
2. Review open findings, accepted exceptions, and their risk decisions.
3. Update VERSION, CHANGELOG.md, README.md, and SHA256SUMS as required.
4. Run make check and wait for green CI.
5. Test installation from the pinned candidate tag with install.sh --ref TAG.
6. Review public logs and artifacts for secrets or production-sensitive data.
7. Obtain the project decision on release readiness and licensing.

Version 1.1.3 remains an unreleased development version. A release tag and
licensing decision require separate explicit approval.
