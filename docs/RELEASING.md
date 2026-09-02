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
7. Re-run the [third-party software review](../THIRD_PARTY.md): verify the
   exact release does not add vendored code, plugins, reports, logos,
   screenshots, copied control text, or other third-party material without the
   required attribution and license review. On the release target, record the
   actual Lynis package version and inspect its package copyright/license data,
   including any distribution-shipped plugin.
8. Obtain separate project decisions on release readiness and the repository's
   own license. The GPLv3 status of external Lynis Community/Client software
   does not select a license for this project.

Version 1.1.3 remains an unreleased development version. A release tag and
licensing decision require separate explicit approval. Release remains blocked
until the project's own license is explicitly decided.
