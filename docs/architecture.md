# Architecture

`evgl-libs` contains reusable event, venue, attendee, provider, cross-posting, policy, serialization, and routing helpers.

## Canonical package boundary

- `evgl-interfaces` owns wire formats and generated contract types.
- `evgl-libs` consumes interfaces and owns reusable, runtime-light behavior.
- `evgl-clients` exposes versioned SDKs built on the interface contracts.
- `evgl-sync` owns offline-first reconciliation.
- API, web, and CLI repositories compose these packages rather than copying their source.

The long `evento-globolo-libs` repository is a historical bootstrap alias, not a package source. Its generic two-field `Record` scaffold is intentionally not migrated because it duplicates neither the canonical domain model nor production behavior.

## Zed and Git submodules

Use `evento-globolo/evgl-libs` as the only Zed coordinate. A retained Git submodule must have an explicit editable-workspace, inventory, embedded-source, experiment-reference, or legacy role; do not resolve the same repository through both Zed and a gitlink in one composition.

A root `.zpkg.toml` allows `zed overtake --git-submodules` to adopt an exact gitlink while preserving `.gitmodules` and the pinned commit.
