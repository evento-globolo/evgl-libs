# Contracts

- `Lead`: normalized contact plus product-specific intent.
- `Event`: immutable audit fact emitted by UI, CLI, Worker, or backend service.
- `Alert`: operator-visible signal with severity, routing, and closeout evidence.
- `Integration`: external system contract and sync status.

Libraries are shared by `evgl-clients`, `evgl-infra`, and `evgl-monorepo`; schema changes should land here first.
