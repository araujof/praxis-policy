# Praxis Policy Engine

<i>Policy enforcement for AI agent traffic.</i>

[![CI](https://github.com/praxis-proxy/policy/actions/workflows/ci.yml/badge.svg)](https://github.com/praxis-proxy/policy/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/praxis-policy.svg)](https://crates.io/crates/praxis-policy)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)

Policy engine for [Praxis](https://github.com/praxis-proxy/praxis).

A typed, phased plugin runtime and policy evaluator for agent traffic. It decides
who may call which tool, what data comes back, and where that data is allowed to
go next.

## What it does

- **Identity** from multiple sources, each validated independently, so a user, an
  agent, and a workload can be distinguished within one request.
- **Authorization** through a policy language with pluggable decision points,
  including relationship-based authorization.
- **Delegation** via RFC 8693 token exchange, so an upstream receives a token
  scoped to it rather than the caller's own credential.
- **Data control** on the wire: field-level redaction, PII scanning, and session
  taint that follows data across tool calls and requests.
- **Human approval** out of band, for decisions that should not be automatic.
- **Audit** emission for every decision.

## Using it

One dependency gets the engine and every bundled extension:

```toml
praxis-policy = { version = "0.1", features = ["builtins"] }
```

Without `builtins` you get the engine alone and no extensions compiled in. Name a
subset instead if you want one: `jwt`, `oauth`, `elicitation-ciba`, `cedar`, `cel`,
`opa`, `valkey`.

The crates are versioned together and released together, so a single `0.1`
requirement covers the set. Rust 1.96 or newer.

## Status

0.1.x. The public API will move between minor versions while the shape settles; a
breaking change gets a minor bump, not a patch. What is already settled: the
policy document format, the `kind:` strings an operator writes, and the violation
codes a client sees. Those are the surface deployments depend on, and there are
characterization tests holding them in place.

## Layout

    crates/             the engine, its policy language, and the host facade
    builtins/           bundled plugins, decision points, and session stores
    reference/          worked examples, not published and not bundled

A host does not have to use a bundled plugin. Implement `PluginFactory` against
`praxis_policy_core::prelude` and register it with
`PolicyEngine::register_factory` under the `kind:` your policy names. An
unrecognised `kind` fails at load, so a missing registration surfaces at startup
rather than as a plugin that silently never runs.

`reference/plugins/` holds two worked examples: a PII scanner and an audit logger.
Neither is published or bundled, because neither is production-grade — the scanner
is regex matching with no Luhn check, and the logger writes to stderr. Both are
built, linted and tested here, and the reference HR demo registers them as host
plugins.

## Building

The toolchain is pinned and is also the MSRV, so `cargo build` picks the right
one. `make help` lists the available targets.

## License

Apache-2.0. See [LICENSE](LICENSE).
