# Lint ratchet

The gate adopted from Praxis denies a great deal this tree parks. Entries in
`[workspace.lints]` carrying a `ratchet:` reason are the open ones.

## Bounded publish gate

Publishing a version Praxis depends on requires the panic-safety lints and the
rustdoc link lints green. Documentation and complexity entries stay parked on
their own schedule: they are the expensive classes and none of them can silently
change an enforcement decision.

## Where the panic-safety classes stand

Measured, not estimated. The starting point was 1,952 violations across six lints.
The split turned out to be almost entirely test code:

| Population | Count | How it closed |
|---|---|---|
| `#[cfg(test)]` modules in `src` | 1,291 | Module-scoped allow with a reason, 77 modules. Praxis's own convention |
| Integration tests and examples | 603 | Crate-level allow with a reason, 31 files |
| **Production source** | **58** | **Open. Needs conversion, see below** |

## The 58 that remain

These are real production paths, not test helpers: every one sits above its
file's `#[cfg(test)]` boundary.

| Lint | Count | Where |
|---|---|---|
| `indexing_slicing` | 36 | policy parser, routing extension, executor |
| `expect_used` | 20 | same, plus the manager and the JWT resolver |
| `print_stderr` | 2 | audit logger |

Concentration matters: 32 of the 58 are in the policy parser alone.

## Why these are not a mechanical pass

Each one converts an abort into an error return, and the error has to reach a deny
at the decision boundary. An invariant that becomes a permit when it turns out to
be reachable is a policy bypass, not a cleanup, so a bulk rewrite is the wrong
tool. The requirement is a boundary test per converted site asserting the
resulting decision, which means understanding what each site's failure means to
the caller.

The parser concentration is the useful lever: those 32 share a small number of
shapes, so a shape at a time with its own boundary test converts a batch without
losing the per-site reasoning.

## Coverage

Separate target, tracked here because it lands with the same work: 95 percent
lines, against 89.98 measured. That is roughly 1,400 more covered lines out of
about 27,900. The gate sits at 89 and is deliberately not raised ahead of the
tests.

The six ignored session-store integration tests are the largest single block of
uncovered behavior and they need a running service rather than more test code.
Worth knowing that the acceptance demo exercises that store for real, including
taint across a restart, so the behavior is validated even though the unit tests
skip.
