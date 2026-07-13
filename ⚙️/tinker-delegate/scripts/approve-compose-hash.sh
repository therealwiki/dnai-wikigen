#!/usr/bin/env bash
# Approve a new compose hash on-chain in TinkerAccountEncumbrance (owner-only).
#
# This is the governance gate for a governed CVM redeploy: Phala rejects the
# compose-file commit until the new compose hash is approved here. Run it after
# staging the new compose (image digest + flags) and computing its hash with:
#   uv run python -m tinker_delegate.main verify-compose-hash \
#     --compose docker-compose.all.phala.yaml --phala-raw-compose
#
# Usage:
#   scripts/approve-compose-hash.sh <compose-hash-without-0x>
#   scripts/approve-compose-hash.sh            # uses DEFAULT_COMPOSE_HASH below
#
# Requires: Foundry `cast`, a `.env` at repo root with BASE_SEPOLIA_RPC_URL,
# and the `dev` Foundry keystore account (prompts for its password).
set -euo pipefail

# The staged compose hash (verify-compose-hash output for the current
# docker-compose.all.phala.yaml). Override by passing an argument.
DEFAULT_COMPOSE_HASH="a487a398856e6cc36b51c1cdfc5b0060f3ec4de151daa7f9831d39e588b819c0"

ENCUMBRANCE_CONTRACT="0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e"

# Resolve paths relative to this script so it works from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

COMPOSE_HASH="${1:-$DEFAULT_COMPOSE_HASH}"
COMPOSE_HASH="${COMPOSE_HASH#0x}"  # normalize: strip any 0x prefix

if ! [[ "$COMPOSE_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: compose hash must be 64 hex chars (32 bytes), got: $COMPOSE_HASH" >&2
  exit 1
fi

# Load BASE_SEPOLIA_RPC_URL (and other vars) from the repo-root .env.
set -a
# shellcheck disable=SC1091
. "$REPO_ROOT/.env"
set +a

if [[ -z "${BASE_SEPOLIA_RPC_URL:-}" ]]; then
  echo "error: BASE_SEPOLIA_RPC_URL not set (check $REPO_ROOT/.env)" >&2
  exit 1
fi

echo "Approving compose hash on-chain:"
echo "  contract : $ENCUMBRANCE_CONTRACT"
echo "  hash     : 0x$COMPOSE_HASH"
echo "  account  : dev (Foundry keystore)"
echo

cast send "$ENCUMBRANCE_CONTRACT" \
  "approveComposeHash(bytes32)" \
  "0x$COMPOSE_HASH" \
  --account dev \
  --rpc-url "$BASE_SEPOLIA_RPC_URL"

echo
echo "Submitted. Verify with:"
echo "  cast call $ENCUMBRANCE_CONTRACT \"approvedComposeHashes(bytes32)(bool)\" 0x$COMPOSE_HASH --rpc-url \"\$BASE_SEPOLIA_RPC_URL\""
