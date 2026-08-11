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

Of Praxis's 171 rules, 118 are enforced identically here, 51 are weaker, and 2
are stricter (`empty_line_after_outer_attr` and `rustdoc::private_doc_tests`,
both of which Praxis allows). This tree also denies three rules Praxis does not
configure: `unexpected_cfgs`, `clippy::unreachable`, and `clippy::get_unwrap`.

Started at 55 identical and 113 weaker. Both tables now cover the same lint set,
so every remaining difference is a level rather than an omission.

The 51 that remain weaker, by the tag each carries:

| Category | Lints |
|---|---:|
| style | 16 |
| perf | 9 |
| hygiene | 8 |
| docs | 6 |
| api | 4 |
| complexity | 4 |
| attributes | 2 |
| concurrency, test-hygiene | 1 each |

Nothing correctness-relevant is parked. What is left is documentation, cosmetic
preference, or a deliberate complexity decision.

**Docs is the one category worth spending on despite being parked.** Its 6 lints
cover roughly 970 undocumented items, `missing_docs` alone accounting for 664
public ones, and this crate publishes to docs.rs. That is a documentation
project, not a lint gate: generating filler sentences to satisfy the lint would
hide where real documentation is missing.

## What the machine-applicable sweep taught

Clippy reported 718 sites across 22 lints as `MachineApplicable`. Fourteen lints
closed cleanly. The other eight did not, and the reasons are worth recording
because the applicability flag is not a promise:

- **`unused_qualifications` (130 sites).** Reported applicable, but rustfix
  cannot apply the suggestions: they overlap within single statements. Applying
  them by hand at that volume is churn with no reader gain.
- **`let_underscore_drop` (12).** The rewrite spans several edits per site, and
  applying them mechanically produced syntactically broken code. `let _ =` on a
  droppable value is also often the deliberate spelling.
- **`wildcard_imports` (4).** The fix expanded a glob into a 48-name import list
  and still missed three names a test module used. All four globs are sibling
  modules of one logical unit split across files, where the glob is the better
  code. They keep their globs with per-site reasons, and the lint is enforced.
- **`allow_attributes` (58).** Converting `#[allow]` to `#[expect]` turns a
  suppression into an assertion that the lint still fires. Two suppressions here
  cannot satisfy that under every feature set: `register_builtins` and
  `builtin_pdps` have bodies that are entirely `#[cfg(feature)]`-gated, so
  `unused_variables` and `unused_mut` fire with no features enabled and not with
  all of them. No single attribute is correct for both, so the lint stays parked.

That last one paid for itself anyway. Because `#[expect]` fails when a lint stops
firing, the conversion surfaced **63 stale suppression entries** in test-module
blocks: lints listed in an allow list that no longer occur in that module, so a
future real violation would have gone unflagged. Those were removed and stay
removed.

Two smaller lessons from the same sweep. A fix can violate an already-enforced
lint, as one `single_match_else` rewrite left a tail expression that tripped
`semicolon_if_nothing_returned`. And `derivable_impls` appends a second
`#[derive]` rather than merging into the existing one, which compiles but reads
badly.

## The numeric-cast and unsafe classes: closed

Three of the 35 cast sites were live defects rather than provably-safe
conversions.

- **A valkey `ttl_seconds` past `i64::MAX` wrapped negative**, and `EXPIRE` with
  a non-positive TTL deletes the key at once. Because this store carries session
  taint, an absurd TTL made taint quietly fail to persist between requests: a
  downgrade, not an outage, and invisible in logs. Now rejected at config load,
  and saturating at the call site as a second guard.
- **The evaluator compared integer pairs through `f64`.** Above 2^53 distinct
  i64 values collapse onto one double, so an ordering test answers wrongly.
  Integer pairs now compare exactly; mixed int/float still needs a common type
  and carries a reason.
- **Delegation depth and a delegated-token TTL hint wrapped.** Both now
  saturate, so an overflow reads as maximally deep or unshortened rather than
  shallow or negative. `delegation.depth > N` is a rule operators write, so a
  wrapped depth was a bypass.

The unsafe class closed by deletion. The crate's only unsafe code was two
hand-written `Send`/`Sync` impls on a zero-sized capability token, justified by a
comment claiming a private zero-sized field suppresses auto traits. That is not
how auto traits work: the sole field is `()`, which is already `Send + Sync`, so
the impls bought nothing. A compile-time assertion stands in their place, so a
future non-`Send` field fails there with a clear message.

Two related classes were checked and needed no work. `await_holding_lock` and
`await_holding_refcell_ref` are clean: no synchronous guard is held across an
`await` anywhere, which is the case that actually deadlocks.
`integer_division` and `modulo_arithmetic` measured zero from the start, which
retires divide-by-zero.

`significant_drop_tightening` stays parked at 9 sites, deliberately. The scopes
where tightening removed a real hazard are closed: the plugin factory lookup no
longer holds the registry read lock across host-supplied `create` code, which
could re-enter the manager and deadlock, and the CEL compile cache now logs
outside its guard while keeping the capacity check and the insert under one lock
so the cap cannot be exceeded by two threads racing. The rest hold a guard across
a synchronous call on purpose and document why.

## The panic gate: closed

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
