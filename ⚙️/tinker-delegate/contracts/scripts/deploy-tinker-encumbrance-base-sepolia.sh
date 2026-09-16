#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CANONICAL_HELPER="$ROOT_DIR/⚙️/tinker-delegate/contracts/scripts/deploy-base-sepolia.sh"

cat >&2 <<EOF
The standalone Base TinkerAccountEncumbrance deployment path is retired.

TinkerAccountEncumbrance is one member of the canonical seven-contract release.
A missing or replacement contract requires a new full release; it must not repair
or overwrite only the Tinker entry in a partial deployment ledger.

This compatibility shim never deploys, broadcasts, or mutates the deployment ledger.

Review a full-suite dry run first:
  env BROADCAST=false "$CANONICAL_HELPER"

Only after reviewing the complete release, broadcast explicitly:
  env BROADCAST=true "$CANONICAL_HELPER"

The canonical helper is restricted to the encrypted Foundry account named dev.
EOF

exit 1
