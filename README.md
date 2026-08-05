# evgl-libs

Shared, runtime-light libraries for **Evento Globolo**.

- `crates/contracts` — stable event, actor, and request metadata contracts
- `crates/routing` — deterministic routing and priority classification
- `src/` — JavaScript reference implementation for Workers and web tooling
- `schemas/` — JSON Schema documents for language-neutral validation

The Rust crates deliberately use only the standard library in this bootstrap, keeping audits and downstream embedding straightforward.

```bash
./scripts/test.sh
```
