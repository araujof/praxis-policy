# Praxis Policy Engine — Rust workspace Makefile
# =============================================================================
# Targets mirror CI (.github/workflows/) so a green `make ci` locally means a
# green pipeline.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo

# `make release LEVEL=patch` or `make release VERSION=0.1.1`. VERSION wins.
RELEASE_ARG = $(if $(VERSION),$(VERSION),$(if $(LEVEL),$(LEVEL),patch))

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo "Praxis Policy Engine — Makefile"
	@echo ""
	@echo "Build:"
	@echo "  build             Build the workspace (debug)"
	@echo "  build-release     Build the workspace (release)"
	@echo "  check             cargo check the workspace"
	@echo "  clean             Remove the target/ directory"
	@echo ""
	@echo "Lint & format:"
	@echo "  fmt               Format Rust code (cargo fmt --all)"
	@echo "  lint              CI lint gate: fmt --check + clippy -D warnings"
	@echo "  clippy            Run clippy on the workspace (-D warnings)"
	@echo "  lint-fix          Auto-fix: cargo fmt + clippy --fix"
	@echo "  machete           Report unused dependencies (advisory)"
	@echo ""
	@echo "Test:"
	@echo "  test              Run all workspace tests"
	@echo ""
	@echo "Supply chain & coverage:"
	@echo "  audit             cargo deny check (advisories, licenses, bans, sources)"
	@echo "  coverage          Coverage summary, gated at COVERAGE_FLOOR percent"
	@echo ""
	@echo "Docs:"
	@echo "  doc               cargo doc with warnings denied"
	@echo ""
	@echo "CI:"
	@echo "  ci                What CI runs: lint + test"
	@echo ""
	@echo "Release:"
	@echo "  release-dry       Preview a release (no changes)"
	@echo "  release-version   Rewrite versions only; no commit, no tag"
	@echo "  release           Bump + commit + tag, then stop"
	@echo "  publish-dry       Package every publishable crate without uploading"
	@echo "  tag               Tag VERSION and push it to trigger the CI publish"

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build:
	@$(CARGO) build --workspace

.PHONY: build-release
build-release:
	@$(CARGO) build --release --workspace

.PHONY: check
check:
	@$(CARGO) check --workspace

.PHONY: clean
clean:
	@$(CARGO) clean

# =============================================================================
# Lint & format
# =============================================================================

.PHONY: fmt
fmt:
	@$(CARGO) fmt --all

.PHONY: clippy
clippy:
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

# CI-safe gate: read-only fmt check plus clippy. Lint levels come from the
# [workspace.lints] wall in Cargo.toml, including the parked seed entries.
.PHONY: lint
lint:
	@echo "fmt --check + clippy -D warnings ..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "lint passed"

.PHONY: lint-fix
lint-fix:
	@$(CARGO) fmt --all
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

# Advisory: cargo-machete false-positives on macro- and derive-only crates, so
# it is not part of the blocking lint gate.
.PHONY: machete
machete:
	@command -v cargo-machete >/dev/null 2>&1 || $(CARGO) install cargo-machete --locked
	@cargo machete || true

# =============================================================================
# Test
# =============================================================================

# Two passes, because a single one cannot see everything.
#
# The default pass is the configuration a host gets with no features named. The
# all-features pass is the only way to reach `#[cfg(feature = ...)]` test
# modules, and the facade's are gated that way because its `default` is empty by
# design: the bare dependency is the engine alone.
#
# The second pass is not optional politeness. Folding the builtins aggregator
# into the facade silently stopped three tests from running, because the
# aggregator had a non-empty `default` and the facade does not. A green
# single-pass run said nothing was wrong.
.PHONY: test
test:
	@$(CARGO) test --workspace
	@$(CARGO) test --workspace --all-features

# =============================================================================
# Supply chain & coverage
# =============================================================================

.PHONY: audit
audit:
	@command -v cargo-deny >/dev/null 2>&1 || $(CARGO) install cargo-deny --locked
	@cargo deny check

# The target is met: the imported tree measured just under 90, it now measures a
# little over 95, and the floor sits at the target. The gate rose as the tests
# landed rather than ahead of them, because a red required check that nobody can
# make green teaches people to ignore it.
#
# Raise this line, do not lower it: a drop means coverage regressed. There is no
# headroom left below the target, so a platform or ordering difference of a few
# lines can turn the gate red. Fix that by covering something, not by lowering
# the floor. (Two unrelated files moved by a line each between consecutive local
# runs during this work, so the variance is real but small.)
#
# Note when reading a delta: test-module lines count toward the denominator, so a
# new test adds total lines as well as covered ones. Test code is close to fully
# covered, so this lifts the ratio by slightly more than retiring the same number
# of uncovered lines alone would.
#
# What is still uncovered, for anyone pushing higher. About 1,615 lines, and the
# two files holding most of it are both there by decision rather than oversight:
#
#   * The policy parser, roughly 265 lines across ~90 separate error-return
#     sites of median three lines. Each needs its own hand-written bad-input
#     case. Tractable, just long.
#   * The manager, of which about 112 lines are duplicated mock-plugin
#     scaffolding in its own test module rather than production code.
#     Consolidating those mocks was considered and declined: each mock's name is
#     what tells a reader what its test exercises.
#
# Also uncovered by design: about 25 production lines are provably unreachable
# defensive guards, annotated as such in-source. cargo-llvm-cov cannot exclude
# lines on stable, so they stay counted, costing roughly 0.08 percent.
#
# This is the only copy of the number. The coverage workflow calls `make
# coverage` rather than repeating the threshold, so there is nothing to keep in
# sync.
COVERAGE_FLOOR ?= 95
COVERAGE_TARGET := 95

# `--include-ignored` so the Valkey integration tests are measured. Most of what
# they cover needs no Valkey at all (the unreachable-endpoint case), which is
# worth having rather than reading that file as 0 percent.
#
# `VALKEY_TESTS_OPTIONAL=1` because this target measures, it does not assert. The
# tests fail loudly without an endpoint under `make test`, which is the gate;
# making coverage fail for a missing container would only stop the measurement
# from running at all. Supply `VALKEY_TEST_URL` to measure the container paths
# too, which takes that file from 75 to about 92 percent.
.PHONY: coverage
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@VALKEY_TESTS_OPTIONAL=1 cargo llvm-cov --workspace --summary-only \
		--fail-under-lines $(COVERAGE_FLOOR) -- --include-ignored

# =============================================================================
# Docs
# =============================================================================

.PHONY: doc
doc:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps

# =============================================================================
# CI
# =============================================================================

.PHONY: ci
ci: lint test

# =============================================================================
# Release
# =============================================================================
#
# CI publishes on tag push. The local mechanics stop at the tag.

.PHONY: release-tool
release-tool:
	@command -v cargo-release >/dev/null 2>&1 || $(CARGO) install cargo-release --locked

# Preview only. cargo-release makes no changes without --execute.
.PHONY: release-dry
release-dry: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace

# Rewrite the version in [workspace.package] and [workspace.dependencies] only;
# no commit, no tag. For a manual, reviewed bump.
.PHONY: release-version
release-version: release-tool
	@$(CARGO) release version $(RELEASE_ARG) --workspace --execute --no-confirm

# Bump, commit, tag, then stop. --no-publish and --no-push enforce the
# "CI publishes on tag push" model at the CLI level as well, so the guarantee
# does not depend on release.toml being parsed as expected. Afterwards run
# `make tag` or push the tag directly.
.PHONY: release
release: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace --no-publish --no-push --execute

# Build and verify a .crate for every publishable member without uploading, the
# same check the release workflow's dry run performs. CI runs this on a clean
# checkout; --allow-dirty lets it run locally with work in progress.
.PHONY: publish-dry
publish-dry:
	@$(CARGO) package --workspace --locked --allow-dirty

# Tag the current commit and push it. The tag is what the release workflow
# triggers on. VERSION must be semver with no leading `v`.
#   make tag VERSION=0.1.0
.PHONY: tag
tag:
	@test -n "$(VERSION)" || { echo "usage: make tag VERSION=X.Y.Z[-prerelease]"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' \
		|| { echo "error: VERSION '$(VERSION)' is not semver (e.g. 0.1.0; no leading 'v')"; exit 1; }
	git tag v$(VERSION)
	git push origin v$(VERSION)
