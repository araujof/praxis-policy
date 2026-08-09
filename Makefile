# Praxis Policy Engine — Rust workspace Makefile
# =============================================================================
# Targets mirror CI (.github/workflows/) so a green `make ci` locally means a
# green pipeline.
#
# Until the engine crates are imported this is a virtual manifest with no
# members, so every compile-shaped target below aborts with "the workspace has
# no members". That is expected at this stage. `make fmt` and `make help` work.

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
	@echo "  coverage          Coverage summary (no threshold yet; see target)"
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

.PHONY: test
test:
	@$(CARGO) test --workspace

# =============================================================================
# Supply chain & coverage
# =============================================================================

.PHONY: audit
audit:
	@command -v cargo-deny >/dev/null 2>&1 || $(CARGO) install cargo-deny --locked
	@cargo deny check

# Report-only for now. The floor is set from a measurement of the imported tree
# rather than inherited from another project, whose threshold is calibrated to a
# different codebase. Add `--fail-under-lines N` here and in the coverage
# workflow together.
.PHONY: coverage
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@cargo llvm-cov --workspace --summary-only

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
