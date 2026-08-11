# Contributing

## Toolchain

The toolchain is pinned in `rust-toolchain.toml` and is also the project MSRV.
`cargo` picks it up automatically. Formatting and coverage both run on that
pinned stable toolchain, so nothing here needs nightly.

## Before opening a pull request

```
make lint
make test
make audit
```

`make ci` runs the same set CI does.

## Durable text carries no planning identifiers

Commit messages, code comments, rustdoc, changelog entries, and pull-request
descriptions must stand on their own. Do not cite requirement or plan document
identifiers such as `R12` or `U3` in any of them.

Those documents do not ship with the code. An identifier is meaningless to
someone reading the commit a year from now, and it rots the moment the document
changes or moves. Describe the behavior or the reason instead:

```
# no
fix: address R24 fail-closed requirement in parser

# yes
fix: return a deny when the parser hits an unreachable branch

    An invariant that becomes a permit if it turns out to be reachable is a
    policy bypass, so the error path maps to deny at the decision boundary.
```

This applies to commits authored here. It does not apply to the commit history
imported from the engine's previous home, which is preserved as written.

## Imported history

Most of this tree was imported from another repository with its history intact,
so `git log` and `git blame` reach back before this repository existed. Two
consequences are worth knowing:

- Imported commit messages reference pull-request numbers from the original
  repository. GitHub will autolink them to unrelated numbers here. They are not
  rewritten, because rewriting them would cost more traceability than the
  autolink noise costs.
- Imported commits that touched both ported and excluded paths were rewritten to
  their ported portion, so they do not correspond one-to-one with commits in the
  original repository. Cross-tree comparison works by path and content, not by
  commit identity.

`docs/port-provenance.md` records the exact source commit the import was taken
from.

## Lints

`[workspace.lints]` in `Cargo.toml` is the authority. Most rules are denied; the
ones that are not sit at the end of each section, grouped by why, with a comment
per group. That list is a settled decision rather than a backlog: every lint that
could silently change an enforcement decision is already denied.

Two rules for contributors:

- **Do not add new violations of a non-enforced lint.** It is not enforced
  because the existing violations were judged not worth the churn, which is not
  an invitation to add more.
- **Do not suppress a lint at a wider scope than the code that needs it.** A
  module-level allow that covers lints the module does not violate hides the next
  real one. Sixty-three such entries were removed once; prefer the narrowest
  scope, with a `reason`.

Closing a group is welcome as a focused change, one lint at a time, separate from
feature work. Read `docs/lints.md` first: it records which lints clippy reports as
machine-fixable but cannot actually fix, and where a lint's suggested rewrite is
worse than the code it replaces.
