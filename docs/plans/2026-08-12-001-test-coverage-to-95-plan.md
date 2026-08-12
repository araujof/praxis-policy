# Raise line coverage from 90.4% to 95%

Created: 2026-08-12
Status: in progress, paused at 93.27%

## Context

The engine port set 95% line coverage as its target. The imported tree measured
just under 90, so `COVERAGE_FLOOR` in the Makefile started at 89 with a point of
headroom and the 95 target was recorded as tracked work. The Makefile comment is
explicit about why the gate was not simply set to 95 up front: a red required
check that nobody can make green teaches people to ignore it. The floor rises as
tests land, never ahead of them.

CI calls the Makefile target, so the floor lives in exactly one place.

## Where this stopped

Nine commits, `c61e084` through `b4a5bca`. Coverage went **90.36% to 93.27%**
(30,906 counted lines, 2,080 uncovered). `COVERAGE_FLOOR` rose 89 to 92 to
**93**, and `make coverage` passes at it, so the gain cannot silently regress.

| phase | state |
|---|---|
| 1, cleanup | **Partial, by decision.** Four dead zero-caller functions deleted, and 24 duplicated `let ... else { panic!() }` blocks in the parser replaced by two shared helpers, `expect_rule` and `expect_delegate`. Deliberately **not** done: consolidating manager.rs's 28 purpose-built mock plugins (105 uncoverable lines) and the remaining ~44 parser panic arms. Those mock names are what tell a reader what each test exercises, and the arms carry specific failure messages. Collapsing them trades diagnosis for a metric, which is the wrong trade even though it would lift the number. |
| 2, builtins | **Done**, all eleven files. Found and fixed a real bug on the way (`2099bcb`): Cedar's value model has no floating-point type, so `attributes: { score: 1.5 }` in a `cedar:()` step made the entity fail to build, the resolver failed closed, and every request through that step was denied with the opaque message "error during entity deserialization". Both the operator-authored path and the `claim.*` bag path now name the offending key. |
| 3, core cheap wins | **Done.** `filter.rs` 83.99 to 99.85 (the slot-policy invariants, the single best win in the effort), `error.rs` 45.57 to 100, `plugin.rs` to 97.40, plus `trait_def`, `core/visitor`, `factory`, `delegation_invoker` and `cmf/view`. |
| 4, core logic | **Partial.** Done: the evaluator's pipeline type guards and its pure classifiers, plus config.rs load failures. Not done: the executor's concurrent outcome matrix, manager.rs production error paths, apl-runtime/visitor.rs, and route.rs `evaluate_post`. |

## Remaining work to 95%

About **535 uncovered lines to retire**, and fewer in practice because each new
test also adds covered lines to the denominator. The cheap work is gone; what is
left is the tail, ranked by size:

| lines | target | notes |
|---:|---|---|
| 390 | `crates/ppe-apl-core/src/parser.rs` | Not a few big functions: roughly 90 separate error-return sites, median 3 lines, each needing its own hand-written bad-input case. ~88 of the 390 are uncoverable test panic arms. This is the grind the plan set out to avoid. |
| 274 | `crates/ppe-core/src/manager.rs` | ~105 is the mock scaffolding named above. The rest is production error paths, including `remove_route_annotation` (17 lines, zero callers anywhere) and the `load_config_yaml` visitor-failure arms, which need one always-failing `ConfigVisitor`. |
| 100 | `crates/ppe-core/src/executor.rs` | The `{Error, TimedOut, Panicked}` by `{Fail, Ignore, Disable}` outcome matrix, 8 of 9 cells uncovered. Needs mock plugins in `mode: concurrent`; this file has only 7 narrow tests and no mock fixtures. Excludes the 12-line invariant guard at 903-914, which the source itself documents as unreachable. |
| 71 | `builtins/plugins/identity-jwt/src/resolver.rs` | Header-resolution denies and mapping failures. `cfg_with_config` and `jwt_with_payload` already exist in the in-file module. Skip the `TokenRole::Custom` and non-exhaustive arms: `new()` rejects `Custom`, so reaching them means constructing state the public API forbids. |
| 54 | `crates/ppe-apl-runtime/src/visitor.rs` | Config error paths, all reachable with malformed YAML. Follow `response_subblock_malformed_is_none_not_propagated`. |
| 53 | `builtins/pdps/cedar-direct/src/resolver.rs` | Eight more `from_config` YAML shapes. `policy_file` and `schema_file` need a file on disk: use a checked-in fixture under `tests/fixtures/` following the `crates/ppe-core/tests/fixtures/` precedent rather than adding a `tempfile` dev-dependency the workspace does not have. |
| 53 | `crates/ppe-apl-runtime/src/route_handler.rs` | `with_pdp_router` (zero callers), `approved_peek_violation`, `extensions_changed`. |
| 48 | `builtins/plugins/identity-jwt/src/config.rs` | The JWKS-document rejection cases are the cheap half: take `build_jwks` and strip the `kid`, flip `use` to `enc`, serve `{"keys":[]}`, serve garbage. Leave the EC/Ed25519 PEM fallbacks, which want test keys the crate has no dependency for. |
| 38 | `crates/ppe-apl-core/src/route.rs` | `evaluate_post`'s `Replace`/`Omit`/`Deny` result-pipeline arms. The args-phase equivalents are covered, so mirror `result_pipeline_redacts_field`. |
| 36 | `builtins/session/valkey/src/store.rs` | **Mostly free, no test writing.** Five integration tests exist and pass but never run, because the coverage job does not pass `--include-ignored`. Measured: `--include-ignored` alone takes this file 0 to 75 percent, and that comes entirely from the one test needing no container; with a real endpoint via `VALKEY_TEST_URL` it reaches 91.67 percent. So most of the gain needs no Valkey service in CI, and a service adds the last few lines. |

Everything except the parser and the manager totals about 415 lines, which lands
near 94.7%. **Reaching 95% requires touching one of those two.** The Makefile
comment records this so it is not rediscovered.

## Constraints carried forward

- About 25 production lines are provably unreachable defensive guards, annotated
  as such in the source (`executor.rs:903-914`, `evaluator.rs:1125-1129`,
  `manager.rs:1583` and `:1626`, `route.rs:349` and `:374`, `parser.rs:502`).
  cargo-llvm-cov cannot exclude lines on stable, so they stay uncovered. They
  cost 0.09%.
- Test-module lines count toward the denominator, so a new test adds total lines
  as well as covered ones. Because test code is close to fully covered this still
  lifts the ratio, and by slightly more than retiring the same number of
  uncovered lines alone would.

## Traps this effort actually hit

Recorded because each one cost time or produced a wrong number.

- **Measure with the tool, never by reading source.** An earlier panic-site count
  in this project was recorded as 58 from a text scan when clippy measured 28.
  A text scan cannot tell a production site from a scope-allowed test module.
- **clippy caches hard.** A second invocation that prints only "Finished in
  0.3s" recompiled nothing and proves nothing. `touch` the file or
  `cargo clean -p <crate>` first. A lint was wrongly believed absent for exactly
  this reason.
- **`clippy::missing_assert_message` does not fire inside `#[test]` functions.**
  Verified three ways. Do not treat bare asserts in tests as a lint gap.
- **Watch for tests that pass whatever the code does.** A coverage target
  actively incentivises this failure mode, and an audit of the tree found four
  distinct instances:
  - A test comparing `Pattern::default()` to itself, which would have passed for
    any default. Rewritten to assert that the default matches nothing.
  - Two JWKS rejection tests that mutated their fixture with a string replace
    looking for `"use": "sig"`, while `json!().to_string()` emits compact JSON
    with no space. The replace missed, the document stayed valid, the endpoint
    was accepted, and the tests passed. Rebuilt structurally from a `Value`.
  - Two parser tests keyed on `when: true`, which YAML parses as a boolean and
    the parser rejects before reaching the field-op logic they claimed to test.
    One always took its `Err(_) => {}` arm, so its only assertion was dead; the
    other asserted nothing at all despite being named `..._rejected`.
  - The Valkey integration tests, which skipped and reported `ok` when no
    endpoint was available. See the note in that file: the previous mitigation
    was a printed SKIPPED line, and cargo captures stderr from passing tests.
  The generalisable checks: does the negative test still fail when you break its
  setup, and does a test whose name asserts a rejection actually assert one.
  Breaking each mock path and re-running is a cheap way to find the first class.
- **Widening a test module's `#[allow]` list is often required.** New tests here
  tripped `err_expect`, `indexing_slicing`, `redundant_closure`,
  `field_reassign_with_default`, and the workspace ban on `unreachable!` that
  this project tightened earlier.

## Verification

Per increment:

```
make lint          # workspace lints are deny-heavy
make test
make coverage      # cargo llvm-cov --workspace --fail-under-lines $(COVERAGE_FLOOR)
```

Confirm the number moved before raising the floor:

```
cargo llvm-cov --workspace --summary-only | tail -3
cargo llvm-cov --workspace --summary-only | grep <path>   # per-file, while working
```

Raise `COVERAGE_FLOOR` only after the suite is green at the new value, and never
lower it: a drop means coverage regressed. Keep the Makefile comment at lines
125-133 in step with reality; it has already gone stale once.
