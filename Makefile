SHELL := /bin/bash
.DEFAULT_GOAL := check

.PHONY: syntax shellcheck static regression checksum check

syntax:
	bash -n harden.sh
	bash -n install.sh
	bash -n scripts/*.sh

shellcheck:
	# harden.sh is checksum-pinned for 1.1.3; SC2066 is the intentional literal .rhosts loop.
	shellcheck --severity=error --exclude=SC2066 harden.sh
	shellcheck --severity=error install.sh scripts/*.sh

static:
	./scripts/ci-static-checks.sh

regression:
	./scripts/regression-tests.sh

checksum:
	sha256sum -c SHA256SUMS

check: syntax shellcheck static regression checksum
