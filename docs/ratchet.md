# Lint ratchet

The gate adopted from Praxis denies a great deal this tree does not yet enforce.
Every non-enforced entry in `[workspace.lints]` carries one of two tags:

- `gate:` must reach deny before publish, with a measured production site count.
- `parked:` not scheduled, with a reason that has to explain why the lint cannot
  silently change an enforcement decision.

## How the counts are produced

From the compiler, not from reading the source:

```
cargo clippy --workspace --all-targets --all-features -- -W <lint>
```

A hit inside a `#[cfg(test)]` region, or in a `tests/`, `examples/`, or `benches/`
target, is not a production site. Test code is scope-allowed at the module or
crate level, so these numbers describe the library's own surface.

Three measurement traps, all of which produced wrong numbers here before:

- **A text scan cannot tell production from a scope-allowed test module.** The
  first inventory recorded 58 production panic sites by scanning. The real number
  under the same six lints is 28.
- **Some clippy lints suppress each other.** Measured as a group,
  `needless_raw_string_hashes` reports zero because `needless_raw_strings` covers
  the same spans. On its own it fires 12 times. Measure one lint at a time when
  the number will be relied on.
- **Clippy does not check `rustdoc::` lints.** Passing them to clippy reports zero
  for every one. They need `cargo doc` with `RUSTDOCFLAGS`.

Worth re-checking whenever these numbers are refreshed: an allow attribute placed
above a file's `#[cfg(test)]` boundary would suppress production hits and make the
surface look clean. All 462 such attributes in `src` currently sit inside a test
region. A gate that reports green because its suppressions are misplaced is worse
than one that reports a large number.

## Where the tree stands against Praxis

Of Praxis's 171 rules, 94 are enforced identically here, 75 are weaker, and 2 are
stricter (`empty_line_after_outer_attr` and `rustdoc::private_doc_tests`, both of
which Praxis allows). This tree also adds `unexpected_cfgs` at deny, which Praxis
does not configure, as a guard against a feature rename silently disabling a gated
export.

Parking the remainder was necessary to import 192 files under a gate none of them
had been compiled against. It is not a claim that the bar is equal, and this
document exists so the gap is a number rather than an impression.

## The publish gate

Publishing a version Praxis depends on requires the panic sources green. The gate
is defined by what a lint can do, not by a fixed list of names: `string_slice` and
`unreachable` were both outside the original six and both abort on reachable
input, so both are in.

| Lint | Production sites |
|---|---:|
| `string_slice` | 37 |
| `indexing_slicing` | 17 |
| `expect_used` | 10 |
| `unreachable` | 3 |
| `print_stderr` | 1 |
| `get_unwrap` | 0 (30 in tests, needs scoped allows in 8 files) |
| **Total** | **68** |

Already closed and enforced: `unwrap_used`, `panic`, `print_stdout`, `exit`,
`mem_forget`, and the rustdoc link lints. `integer_division` and
`modulo_arithmetic` measure zero, which retires divide-by-zero without work.

By file, the concentration is what makes this tractable:

| File | Sites |
|---|---:|
| `crates/ppe-apl-core/src/parser.rs` | 44 |
| `builtins/plugins/elicitation-ciba/src/approver.rs` | 4 |
| `crates/ppe-apl-core/src/attributes.rs` | 4 |
| `crates/ppe-core/src/extensions/routing.rs` | 3 |
| `builtins/session/valkey/src/config.rs` | 3 |
| `crates/ppe-core/src/manager.rs` | 2 |
| `builtins/plugins/identity-jwt/src/resolver.rs` | 2 |
| `crates/ppe-core/src/executor.rs` | 2 |
| `crates/ppe-orchestration/src/lib.rs` | 2 |
| `builtins/plugins/audit-logger/src/logger.rs` | 1 |
| `crates/ppe-apl-core/src/evaluator.rs` | 1 |

## Why this is not a mechanical pass

The sites split into classes, and the class decides both the fix and whether a
test is even possible.

| Class | Sites | Fix | Test |
|---|---:|---|---|
| Structurally eliminable | 62 | Restructure so the panic cannot be expressed | Existing tests, unchanged |
| Fail-open hazard | 2 | Explicit deny; a silent skip loses a Deny | Injection test per site |
| Type-level | 1 | Narrow the operand type so the arm cannot exist | Compile-time |
| Reachable through a published type | 2 | Enforce the invariant in a constructor | Regression test |
| Intentional | 1 | Scoped allow with a reason | None |

Most sites carry their bound check on the adjacent line, so the right fix removes
the branch rather than adding an error path. That adds nothing to test, and
forcing a test would mean widening a crate's public surface to reach provably dead
code.

The two that matter are `executor.rs` and `ppe-orchestration/src/lib.rs`, which
index one collection by a position derived from a parallel one. Converting those
to a silent skip would drop a Deny and yield an Allow: fail-open, and worse than
the abort it replaced. They convert to an explicit deny with a test that injects
the divergence.

## Correctness-relevant parked classes

Most parked entries are cosmetic. Two are not, and they are the strongest
candidates for the next gate after this one:

- `parked: numeric-cast`, 23 sites across five clippy lints, plus 12 more under
  rustc `trivial_casts`. A truncation or sign change can alter a comparison, and a
  comparison can be a policy decision.
- `parked: unsafe`, 5 sites, including two hand-written `Send`/`Sync` impls.

## Coverage

Separate target, tracked here because it lands near the same work: 95 percent
lines against 89.98 measured, roughly 1,400 more covered lines out of about
27,900. The gate sits at 89 and is deliberately not raised ahead of the tests,
because a required check nobody can make green teaches people to ignore it.

Closing the sites above will not close that gap. The structurally-eliminable class
adds no branches, so it moves coverage by close to nothing. The largest single
block of uncovered behavior is the six ignored session-store integration tests,
which need a running service rather than more test code. The acceptance demo
exercises that store for real, including taint across a restart, so the behavior
is validated even though the unit tests skip.
