#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
node --test tests/*.test.mjs
node --check src/index.mjs
python3 -m json.tool schemas/event-envelope.schema.json >/dev/null
if command -v cargo >/dev/null 2>&1; then
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace --all-targets
fi
