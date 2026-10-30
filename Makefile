# AI Continuity Platform — Core
# Makefile for local development. CI runs the same targets via vault-gate.yml.
#
# See 00_CI_Security_Policy.md for the authoritative definition of every check.
# This Makefile mirrors the CI so that a passing local run predicts a passing CI.

SHELL := /bin/bash
GO    ?= go
PKG   := ./...

# --- metadata -----------------------------------------------------------------

BINARIES := sagvd acp-compute acpctl acp-bootstrap acp-keygen acp-demo vgconsole
VERSION  ?= 0.0.0-dev
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# Reproducible-build flags. Two builds from the same source on the same
# Go version produce byte-identical output. SLSA L3-style guarantee.
#
#   -X main.version / main.commit   stamp version metadata into the binary
#   -buildid=                       remove the random build ID Go links by default
#   -s -w                           strip symbol table + DWARF
# `-trimpath` (a `go build` flag, not an ldflag) removes absolute paths
# from the binary so the build is location-independent.
#
# DEBUG=1 keeps the symbol table and DWARF (no -s -w) for a debugger or a
# profiler; everything else, -trimpath included, stays the same, so the
# debug build is as reproducible as the stripped one, only larger.
# Release binaries are always the stripped build.
DEBUG ?= 0
ifeq ($(DEBUG),1)
LDFLAGS       := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -buildid=
else
LDFLAGS       := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -buildid= -s -w
endif
GOFLAGS_REPRO := -trimpath -ldflags '$(LDFLAGS)'

# The FIPS build (ADR 0030): the same binaries on the certified Go
# Cryptographic Module, named by its version — never `certified` or
# `latest`, which move. GOFIPS140 selects the module snapshot at build
# time and makes fips140=on the binary's default; `version` and
# `identity` print it. `make build-fips` writes bin/<name>-fips.
FIPS_MODULE := v1.0.0

.PHONY: all
all: fmt vet build test

# --- build --------------------------------------------------------------------

.PHONY: build
build: $(BINARIES:%=bin/%)

.PHONY: build-fips
build-fips: $(BINARIES:%=bin/%-fips)

# CGO_ENABLED=0: static binaries that run on any linux/amd64 without a
# libc to match, and that anyone rebuilds byte for byte from any host with
# the pinned Go (docs/operator/05_release_procedure.md §5). Nothing in the
# tree imports "C"; the TEE drivers are reached through ioctls.
bin/%: cmd/%
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(GOFLAGS_REPRO) -o $@ ./$<

# The same, on the certified module (the shorter stem wins the pattern).
bin/%-fips: cmd/%
	@mkdir -p bin
	CGO_ENABLED=0 GOFIPS140=$(FIPS_MODULE) $(GO) build $(GOFLAGS_REPRO) -o $@ ./$<

# The tools a person runs on their own machine — acpctl, acp-keygen and the
# console, vgconsole (ADR 0039), which is also built for linux/amd64 here —
# are also built for the platforms a laptop or a workstation is: macOS and
# Windows on both architectures, Linux on arm64 (bin/<tool>-<os>-<arch>, a
# .exe on Windows), with the same flags, so they rebuild byte for byte like
# the others. The daemons stay linux/amd64: they attest with hardware no
# other platform has, and a binary that has not run on that hardware is
# not released (KNOWN_ISSUES #1 names what a release runs on).
CROSS_TOOLS     := acpctl acp-keygen vgconsole
CROSS_PLATFORMS := linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
cross_name       = $(1)-$(2)$(if $(findstring windows,$(2)),.exe,)
CROSS_BINARIES  := $(foreach t,$(CROSS_TOOLS),$(foreach p,$(CROSS_PLATFORMS),$(call cross_name,$(t),$(p)))) vgconsole-linux-amd64

.PHONY: build-cross
build-cross: $(CROSS_BINARIES:%=bin/%)

# One rule per tool and platform, so `make bin/acpctl-darwin-arm64` works
# and the pattern rules above never see these stems.
define cross_rule
bin/$(call cross_name,$(1),$(2)): cmd/$(1)
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=$(word 1,$(subst -, ,$(2))) GOARCH=$(word 2,$(subst -, ,$(2))) $$(GO) build $$(GOFLAGS_REPRO) -o $$@ ./$$<
endef
$(foreach t,$(CROSS_TOOLS),$(foreach p,$(CROSS_PLATFORMS),$(eval $(call cross_rule,$(t),$(p)))))
$(eval $(call cross_rule,vgconsole,linux-amd64))

# release.yml reads the list from here, so the workflow and the Makefile
# cannot disagree about what a release carries.
.PHONY: cross-binaries
cross-binaries:
	@echo $(CROSS_BINARIES)

# verify-reproducible builds every binary twice — the default build, the
# FIPS build and the cross builds — with identical flags and diffs the
# resulting bytes. Failure means a non-determinism source crept in (random
# build IDs, embedded timestamps, GOPATH leakage, CGO non-determinism). CI
# runs this as sub-check 18 in vault-gate.yml.
.PHONY: verify-reproducible
verify-reproducible:
	@$(MAKE) --no-print-directory clean-bin
	@$(MAKE) --no-print-directory build build-fips build-cross
	@mkdir -p dist/repro
	@for b in $(BINARIES) $(BINARIES:%=%-fips) $(CROSS_BINARIES); do cp bin/$$b dist/repro/$$b.first; done
	@$(MAKE) --no-print-directory clean-bin
	@$(MAKE) --no-print-directory build build-fips build-cross
	@for b in $(BINARIES) $(BINARIES:%=%-fips) $(CROSS_BINARIES); do \
	  if cmp -s dist/repro/$$b.first bin/$$b; then \
	    echo "  $$b: byte-identical across two builds"; \
	  else \
	    echo "  $$b: BUILDS DIFFER — non-determinism source present"; \
	    sha256sum dist/repro/$$b.first bin/$$b; \
	    exit 1; \
	  fi; \
	done
	@rm -rf dist/repro
	@echo "reproducible-build check: PASS"

.PHONY: clean-bin
clean-bin:
	@rm -rf bin

# --- format / vet / lint ------------------------------------------------------

.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || { echo "gofmt: files are not formatted"; exit 1; }

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: lint
lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run $(PKG)

# --- tests --------------------------------------------------------------------

.PHONY: test
test:
	$(GO) test -count=1 $(PKG)

.PHONY: test-race
test-race:
	$(GO) test -count=1 -race $(PKG)

# The assessment of ADR 0030: the unit tests on the certified Go
# Cryptographic Module (GOFIPS140=v1.0.0, CMVP #5247) with enforcement on
# (fips140=only) — every non-approved algorithm fails instead of running.
# Not a production mode; the record that the fips and cnsa profiles reach
# only approved services.
.PHONY: test-fips140-only
test-fips140-only:
	GOFIPS140=v1.0.0 GODEBUG=fips140=only $(GO) test -count=1 $(PKG)

.PHONY: test-integration
test-integration:
	$(GO) test -count=1 -tags=integration ./test/integration/...

.PHONY: test-doctrine
test-doctrine:
	$(GO) test -count=1 ./test/doctrine/...

# coverage writes a cross-package profile: a statement counts as covered
# when any test in the module executes it (policy: ci-security-policy.md §8).
.PHONY: coverage
coverage:
	$(GO) test -count=1 -coverpkg=./... -coverprofile=coverage.out $(PKG)

# --- benchmarks ---------------------------------------------------------------

# bench runs every Go benchmark across the module and writes results
# to dist/bench.out. The CI workflow .github/workflows/bench.yml uses
# this file as the "current PR" side of the benchstat comparison;
# the "main branch" baseline is restored from a cached upstream run.
.PHONY: bench
bench:
	@mkdir -p dist
	$(GO) test -bench=. -benchmem -run=^$$ -count=5 -benchtime=1s $(PKG) | tee dist/bench.out

# bench-quick runs benchmarks at lower count for local iteration.
.PHONY: bench-quick
bench-quick:
	$(GO) test -bench=. -benchmem -run=^$$ -count=1 -benchtime=300ms $(PKG)

# bench-compare runs benchstat against two bench output files. Usage:
#   make bench-compare BASE=baseline.out HEAD=current.out
.PHONY: bench-compare
bench-compare:
	@command -v benchstat >/dev/null || { echo "benchstat not installed: go install golang.org/x/perf/cmd/benchstat@latest"; exit 1; }
	@test -f "$(BASE)" || { echo "BASE=$(BASE) does not exist"; exit 1; }
	@test -f "$(HEAD)" || { echo "HEAD=$(HEAD) does not exist"; exit 1; }
	benchstat $(BASE) $(HEAD)

# --- mutation testing ---------------------------------------------------------

# Mutation testing exercises our test suite by automatically introducing
# small bugs (mutations) into source code and checking whether tests
# catch them. A mutation that survives means tests are weak in that
# region — the fix is to add a test, not to suppress the mutation.
#
# Tool: github.com/avito-tech/go-mutesting (fork of zimmski's). Install:
#   go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest
#
# The Make targets below scope mutation testing to security-critical
# packages because full-tree mutation is multi-hour. Run nightly via
# .github/workflows/mutation.yml; manual on-demand via these targets.

# Packages we mutation-test. Order matters only insofar as failures
# in earlier packs are surfaced first.
MUTATION_PACKAGES := \
	./internal/shared/crypto/... \
	./internal/audit/chain/... \
	./internal/vault/keys/... \
	./internal/recvvalidator/... \
	./internal/shared/tee/...

.PHONY: mutation
mutation:
	@command -v go-mutesting >/dev/null || { \
	  echo "go-mutesting not installed: go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest"; \
	  exit 1; \
	}
	@mkdir -p dist
	@for pkg in $(MUTATION_PACKAGES); do \
	  echo "==> mutating $$pkg"; \
	  go-mutesting $$pkg --debug=false --do-not-remove-tmp-folder=false 2>&1 | tee -a dist/mutation.out; \
	  echo; \
	done

# mutation-quick: run on a single package for fast iteration.
# Usage: make mutation-quick PKG=./internal/audit/chain/...
.PHONY: mutation-quick
mutation-quick:
	@command -v go-mutesting >/dev/null || { \
	  echo "go-mutesting not installed: go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest"; \
	  exit 1; \
	}
	@test -n "$(PKG)" || { echo "PKG argument required, e.g. PKG=./internal/audit/chain/..."; exit 1; }
	go-mutesting $(PKG)

# --- security -----------------------------------------------------------------

.PHONY: vuln
vuln:
	@command -v govulncheck >/dev/null || { echo "govulncheck not installed"; exit 1; }
	govulncheck $(PKG)
	cd scripts/hardware-test/aws-nitro/vsock-attest && GOOS=linux GOARCH=amd64 govulncheck ./...

.PHONY: secrets
secrets:
	@command -v gitleaks >/dev/null || { echo "gitleaks not installed"; exit 1; }
	gitleaks detect --no-git -v

.PHONY: sbom
sbom:
	@command -v syft >/dev/null || { echo "syft not installed"; exit 1; }
	@mkdir -p dist
	syft dir:. -o spdx-json=dist/sbom.spdx.json

# --- doctrine / policy --------------------------------------------------------

.PHONY: terminology
terminology:
	bash scripts/terminology_check.sh

# The formal models (ADR 0032): the models are what formal/gen.py writes, and ProVerif 2.05
# gives the recorded verdicts. ProVerif 2.05 on PATH or in PROVERIF (built from
# https://proverif.inria.fr/proverif2.05.tar.gz with ./build -nointeract); not part of
# vault-gate, so that the gate needs no ProVerif on a developer's machine.
PROVERIF ?= proverif
.PHONY: formal-check formal
formal-check:
	cd formal && python3 gen.py && git diff --exit-code -- '*.pv'
	python3 formal/check_results.py --proverif $(PROVERIF)

formal:
	python3 formal/check_results.py --proverif $(PROVERIF) --out formal/results/proverif-$$(date -u +%Y%m%dT%H%M%SZ).txt

# The differential test (ADR 0034): the product's SEV-SNP verifier against Google's
# go-sev-guest (tools/oracle, a module of its own) and VirTEE's snpguest (VG_SNPGUEST,
# Linux x86-64) on every genuine report in test/corpus/sev-snp. Not part of vault-gate.
.PHONY: differential
differential:
	$(GO) test -tags differential ./internal/shared/tee/ -run TestDifferential -count=1 -v
	$(GO) test -tags differential ./internal/audit/chain/ -run TestDifferential_Auditor -count=1 -v

.PHONY: cli-reference
cli-reference:
	bash scripts/gen_cli_reference.sh

.PHONY: license-headers
license-headers:
	bash scripts/license_header_check.sh

# dco checks the commits under review (origin/main..HEAD by default) for the
# Developer Certificate of Origin sign-off (CONTRIBUTING.md); CI passes the
# pull request's or push's own range.
.PHONY: dco
dco:
	bash scripts/dco_check.sh $(DCO_RANGE)

.PHONY: coverage-thresholds
coverage-thresholds: coverage
	bash scripts/coverage_check.sh

# branch-coverage measures branch coverage of the wire contracts with gobco
# (pinned in .github/workflows/branch-coverage.yml) and writes the report to
# dist/branch-coverage/; docs/doctrine/ci-security-policy.md §8. No threshold.
.PHONY: branch-coverage
branch-coverage:
	bash scripts/branch_coverage.sh

.PHONY: dep-allowlist
dep-allowlist:
	bash scripts/check_dep_allowlist.sh

.PHONY: dep-depth
dep-depth:
	bash scripts/check_dep_depth.sh

# --- demo ---------------------------------------------------------------------

# Narrated end-to-end walkthrough of the vertical slice. Useful for onboarding
# a new operator or for a live pilot demo. The demo runs the existing
# integration test as a guided flow and prints one-line commentary per stage.
.PHONY: demo
demo:
	bash scripts/demo.sh

# regen-demo runs the self-contained cross-hardware regeneration flagship
# (cmd/acp-demo): no compose, no config, no TEE hardware. This is the
# "one command" showcase — also the default entrypoint of the root Dockerfile
# (docker run --rm vaultgenome).
.PHONY: regen-demo
regen-demo:
	$(GO) run ./cmd/acp-demo

# ---- Phase-1 Docker Compose demo --------------------------------------------
#
# Five targets that turn a fresh clone into a running sagvd + acp-compute pair
# and back again. Authoritative layout + design notes live in
# ../deploy/compose/README.md; this section only wires the Makefile surface.
#
# Pathing: the Makefile sits at /core, the deploy tree at /deploy/compose.
# All targets set their working directory to DEMO_DIR so a `make demo-up`
# from anywhere under /core does the right thing.

DEMO_DIR            := $(CURDIR)/deploy/compose
DEMO_COMPOSE        := $(DEMO_DIR)/docker-compose.yml
DEMO_SECRETS_DIR    := $(DEMO_DIR)/secrets
DEMO_COMPOSE_CMD    ?= docker compose
DEMO_SAGVD_URL      ?= http://127.0.0.1:9080
DEMO_SAGVD_HEALTH   ?= http://127.0.0.1:9091
DEMO_WORKER_HEALTH  ?= http://127.0.0.1:9092
DEMO_READY_TIMEOUT  ?= 30

.PHONY: demo-certs
demo-certs:
	@echo "==> generating demo secrets under $(DEMO_SECRETS_DIR)"
	@$(GO) run ./cmd/acp-keygen -out $(DEMO_SECRETS_DIR)

.PHONY: demo-certs-force
demo-certs-force:
	@echo "==> regenerating demo secrets (force) under $(DEMO_SECRETS_DIR)"
	@$(GO) run ./cmd/acp-keygen -out $(DEMO_SECRETS_DIR) -force

# demo-genome fine-tunes a tiny model with the real vg_genome worker and
# seals its genome into deploy/compose/genomes (with the base model under
# deploy/compose/models): what `make demo-submit` asks the worker to
# restore. Needs the worker runtime on the host (workers/genome/README.md).
.PHONY: demo-genome
demo-genome: bin/acpctl
	@ACPCTL=$(CURDIR)/bin/acpctl bash $(DEMO_DIR)/scripts/make_genome.sh

# demo-up needs somewhere for sagvd to keep its Return Path audit log.
$(DEMO_DIR)/audit:
	@mkdir -p $@

.PHONY: demo-up
demo-up: demo-certs $(DEMO_DIR)/audit
	@echo "==> building + starting compose stack"
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) up -d --build
	@echo "==> waiting for sagvd /readyz (up to $(DEMO_READY_TIMEOUT)s)"
	@end=$$(( $$(date +%s) + $(DEMO_READY_TIMEOUT) )); \
	while : ; do \
	    if curl -fsS $(DEMO_SAGVD_HEALTH)/readyz >/dev/null 2>&1 ; then \
	        echo "==> sagvd ready at $(DEMO_SAGVD_HEALTH)"; break; \
	    fi; \
	    if [ $$(date +%s) -ge $$end ]; then \
	        echo "demo-up: sagvd did not become ready within $(DEMO_READY_TIMEOUT)s" >&2; \
	        cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) logs sagvd >&2; \
	        exit 1; \
	    fi; \
	    sleep 1; \
	done
	@echo "==> stack up. Try 'make demo-submit'."

.PHONY: demo-down
demo-down:
	@echo "==> stopping compose stack"
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) down --remove-orphans

.PHONY: demo-submit
demo-submit:
	@SAGVD_URL=$(DEMO_SAGVD_URL) bash $(DEMO_DIR)/scripts/submit_job.sh

# demo-test is the automated version of demo-submit + health probe.
# It's what CI could run once a Docker-enabled runner is available;
# manual operators normally reach for `demo-submit` instead.
.PHONY: demo-test
demo-test:
	@echo "==> probing sagvd /readyz"
	@curl -fsS $(DEMO_SAGVD_HEALTH)/readyz >/dev/null || { echo "sagvd not ready" >&2; exit 1; }
	@echo "==> probing acp-compute /healthz"
	@curl -fsS $(DEMO_WORKER_HEALTH)/healthz >/dev/null || { echo "acp-compute not alive" >&2; exit 1; }
	@echo "==> submitting a job (should succeed)"
	@SAGVD_URL=$(DEMO_SAGVD_URL) bash $(DEMO_DIR)/scripts/submit_job.sh >/dev/null
	@echo "==> demo-test: PASS"

.PHONY: demo-logs
demo-logs:
	@cd $(DEMO_DIR) && $(DEMO_COMPOSE_CMD) -f $(DEMO_COMPOSE) logs --tail=200 -f

# --- aggregate gates ----------------------------------------------------------

.PHONY: vault-gate
vault-gate: fmt-check vet build test test-race test-fips140-only test-doctrine lint terminology license-headers dco vuln secrets coverage-thresholds dep-allowlist dep-depth
	@echo "vault-gate: PASS"

# --- housekeeping -------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf bin dist coverage.out coverage.html
