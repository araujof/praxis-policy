# Import provenance

Most of this tree did not originate here. It was imported from the engine's
previous home with its commit history intact, so `git log` and `git blame` reach
back before this repository existed.

## Snapshot

| | |
|---|---|
| Source repository | `contextforge-org/cpex` |
| Source commit | `aed0f15cda34a9b46e087e7ce337f78579146e12` |
| Extraction tool | `git-filter-repo` |
| Directives | [`tools/port-paths.txt`](../tools/port-paths.txt) |
| Commits before filtering | 256 |
| Commits after filtering | 37 |
| Files imported | 192 |

The source commit is the anchor for any later comparison between the two trees.
Recording it is the whole obligation this import carries toward the eventual
convergence work. How the trees are kept in step, and in which direction, is
decided by that effort, not this one.

## How the import was performed

A fresh clone of the source repository was rewritten with `git-filter-repo`
driven by the directive file, with path selection and path renames applied in a
single pass. Doing the rename as a later commit would have terminated blame at
the move, which is the outcome the single pass exists to avoid.

The rewritten history was then merged here with unrelated histories allowed.
Nothing on this side was rewritten: this repository's initial commit is still
reachable.

## What was verified before the merge

The merge was gated on a mechanical comparison against the source rather than a
spot check. A sampled `git log --follow` test would have passed regardless of
correctness, because a single-pass rewrite leaves no trace of the old path
anywhere in the result, so there is no rename left to cross.

- File count identical: 192 in the source's ported paths, 192 here.
- No file missing and none unexpected under the path mapping.
- Every blob hash and file mode identical.
- Per-file commit counts identical for all 192 files.
- No excluded path present at any of the 37 commits, checked by walking every
  commit rather than only the tip.
- Full-history secret scan clean across all 37 commits.

## What is deliberately absent

Excluded from the import, and therefore absent from history rather than merely
deleted at the tip: the FFI crate, the language bindings, the out-of-process
Python plugin host, the Rego decision point, the Biscuit delegator, and the
example crates.

Two exclusions required code changes, not just path filtering. The
bundled-extensions crate listed the Rego decision point in its default feature
set and declared it as an optional dependency, so the feature, the dependency,
the re-export, the registration site, and the factory-count assertion that
derived its expected value from that feature were all removed. Without that the
workspace does not resolve at all.

## Consequences worth knowing

**Commits do not correspond one-to-one with the source.** Commits touching both
ported and excluded paths were rewritten to their ported portion, and commits
touching only excluded paths were pruned, which is why 256 became 37. Comparison
between the trees works by path and content, not by commit identity.

**Imported commit messages reference the source repository's pull requests.**
GitHub will autolink those numbers to unrelated numbers here. They are preserved
as written, because rewriting them would cost more traceability than the autolink
noise costs.

**Package names lag the directory names.** The import moved directories. Renaming
the published packages is a separate change, so for one commit the directory
names and the package names disagree.

## Test reconciliation

Reconciled on tests actually executed, not declared, against the same package set
in the source at the snapshot commit:

| | Source | Here |
|---|---|---|
| Passed | 1116 | 1116 |
| Failed | 0 | 0 |
| Ignored | 25 | 25 |

Exact match. No test was dropped, and no assertion was weakened to make the suite
pass.

### The 25 ignored tests

Recorded rather than counted as passing, because an ignored test proves nothing.
They are not one category:

- **19 are documentation examples** marked as non-compiling in doc comments. They
  are illustrative, not skipped coverage.
- **6 are the session-store integration tests** and are the real gap. They need a
  running service, so they never execute in a normal run:
  `cross_node_concurrent_append_unions`, `live_dispatch_then_pending`,
  `ttl_set_on_append_and_refreshed_on_load`, `unknown_session_returns_empty_ok`,
  `unreachable_endpoint_fails_closed`, `wrongtype_reply_fails_closed`.

That second group matters more than its size suggests. The session store is what
makes session taint survive a reload or span more than one replica, so the
component carrying the weakest automated coverage here is the one the data-flow
control depends on. Exercising it for real is the acceptance demo's job, not this
suite's.

## The lint seed

The gate adopted here denies a good deal that the source tree parks, including
five rustc lints where a deny is a hard compile error rather than a warning.
Shipping the gate bare would have made the imported tree impossible to build.

The bootstrap commit therefore carried a seed allow-list derived by hand from the
difference between the two configurations. That seed was incomplete: building the
imported tree surfaced four further lints Praxis denies and the source never
configured, so had never been compiled against. Those were added from the
measurement rather than from another reading of the configs.

The lesson is recorded here because it will recur when the parked entries are
closed: the delta between two lint configurations is not reliably computed by
reading them. Compile and measure.
