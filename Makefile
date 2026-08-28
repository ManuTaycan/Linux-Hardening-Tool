SHELL := /bin/bash
.DEFAULT_GOAL := check

.PHONY: syntax shellcheck static checksum check

syntax:
	bash -n harden.sh
	bash -n install.sh
	bash -n scripts/*.sh

shellcheck:
	shellcheck --severity=error harden.sh install.sh scripts/*.sh

static:
	./scripts/ci-static-checks.sh

checksum:
	sha256sum -c SHA256SUMS

check: syntax shellcheck static checksum
