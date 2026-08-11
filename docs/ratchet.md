# Lint ratchet

The gate adopted from Praxis denies a great deal this tree does not yet enforce.
Every non-enforced entry in `[workspace.lints]` carries a `parked:` tag naming a
category, and the reason has to explain why the lint cannot silently change an
enforcement decision. That is the only defensible ground for parking one.

A `gate:` tag marks an entry that must reach deny before publish, carrying a
measured production site count. There are none left; the section below records
what closing them found.

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

Of Praxis's 171 rules, 98 are enforced identically here, 71 are weaker, and 2 are
stricter (`empty_line_after_outer_attr` and `rustdoc::private_doc_tests`, both of
which Praxis allows). This tree also adds `unexpected_cfgs` at deny, which Praxis
does not configure, as a guard against a feature rename silently disabling a
gated export.

The 71 that remain weaker, by the tag each carries:

| Category | Lints |
|---|---:|
| style | 23 |
| hygiene | 10 |
| perf | 10 |
| docs | 6 |
| numeric-cast | 6 |
| api | 4 |
| complexity | 4 |
| unsafe | 3 |
| attributes | 2 |
| concurrency, diagnostics, test-hygiene | 1 each |

## The publish gate: closed

Every panic source is enforced. There are no `gate:` entries left.

Now at deny: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
`string_slice`, `unreachable`, `get_unwrap`, `print_stdout`, `print_stderr`,
`exit`, `mem_forget`, and the rustdoc link lints. `integer_division` and
`modulo_arithmetic` measured zero from the start, which retired divide-by-zero
without work.

68 production sites were closed. Two of them were live bugs rather than
provably-safe indexing:

- **`regex(")` and `enum(")` aborted the parser.** A lone quote satisfies both
  `starts_with('"')` and `ends_with('"')`, and the follow-up `s[1..s.len() - 1]`
  slices from index 1 to 0. Two of five hand-rolled quote strippers were missing
  the length guard the other three had. `parse_pipeline` is public and policy text
  is operator input, so this was reachable, not theoretical. All five now share one
  `strip_prefix`/`strip_suffix` helper, which cannot take that shape.
- **An empty issuer algorithm list aborted token validation.** Config validation
  blocks it, so it was only reachable by emptying the public field after a valid
  build. It now denies: an empty list read as "any algorithm acceptable" hands
  algorithm choice to whoever minted the token.

The rest were structurally eliminable, with the bound check sitting next to the
index. Those were restructured so the panic cannot be expressed rather than given
an error path, which is why most carry no new test: there is no new branch to
test, and reaching one would have meant widening a crate's public surface to get
at provably dead code.

Three fixes were checked against their previous implementations rather than
trusted to review, because a silent behavior change in any of them would be a
routing, disclosure, or decision bug: `glob_match` (116,345 pattern/text pairs),
`redact_endpoint` and `parse_duration_secs` (11,111 cases). Zero mismatches,
including multi-byte input on paths that indexed bytes.

Two fail-open hazards were closed by restructuring rather than by bounds checks,
because a bounds-checked positional write has no safe failure branch. In the
orchestrator, dropping an outcome left its slot unset, which becomes `Aborted`,
and an `Aborted` that was really a `Deny` is a bypass; outcomes are now keyed, and
map insertion is total. In the executor, pairing an outcome with the wrong entry
would apply the wrong plugin's `on_error` and turn a configured `Fail` into an
`Ignore`; it now zips and denies on a length mismatch.

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
