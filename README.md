# Praxis Policy Engine

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

## Status

Early. The crates are not yet published, the version series starts at 0.1.0, and
the public API should be expected to move.

## Layout

    crates/             the engine, its policy language, and the host facade
    builtins/           bundled plugins, decision points, and session stores
    reference-plugins/  worked examples, not published and not bundled

A host does not have to use a bundled plugin. Implement `PluginFactory` against
`praxis_policy_core::prelude` and register it with
`PluginManager::register_factory` under the `kind:` your policy names. An
unrecognised `kind` fails at load, so a missing registration surfaces at startup
rather than as a plugin that silently never runs.

`reference-plugins/` holds two worked examples: a PII scanner and an audit logger.
Neither is published or bundled, because neither is production-grade — the scanner
is regex matching with no Luhn check, and the logger writes to stderr. Both are
built, linted and tested here, and the reference HR demo registers them as host
plugins.

## Building

The toolchain is pinned and is also the MSRV, so `cargo build` picks the right
one. `make help` lists the available targets.

## License

Apache-2.0. See [LICENSE](LICENSE).
