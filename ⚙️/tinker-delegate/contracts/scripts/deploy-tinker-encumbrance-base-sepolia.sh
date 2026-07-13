#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/base-sepolia.json}"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

RPC_URL="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
ACCOUNT="${FOUNDRY_KEYSTORE_ACCOUNT:-dev}"
CHAIN_ID="${CHAIN_ID:-84532}"
DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD}"
BROADCAST="${BROADCAST:-false}"

if [ "$CHAIN_ID" != "84532" ]; then
  echo "Refusing to deploy: this helper is only for Base Sepolia chainId 84532." >&2
  exit 1
fi

for required in forge cast jq; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required" >&2
    exit 1
  fi
done

if [ ! -f "$MANIFEST_PATH" ]; then
  echo "Deployment manifest not found: $MANIFEST_PATH" >&2
  exit 1
fi

manifest_compose_hash="$(jq -r '.phala.composeHash // empty' "$MANIFEST_PATH")"
manifest_oracle_email_hash="$(
  jq -r '
    .phala.mainMailboxGenesisEvidence.publicHealthEvidence.oracleEmailHash
    // .phala.tinkerBootstrapEvidence.oracleHealthEvidence.oracleEmailHash
    // .phala.credentialProvisioningEvidence.oracleEmailHash
    // empty
  ' "$MANIFEST_PATH"
)"

normalize_bytes32() {
  local name="$1"
  local value="$2"
  local raw="${value#0x}"
  if [[ ! "$raw" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "$name must be a non-zero bytes32 hex value." >&2
    exit 1
  fi
  if [[ "$raw" =~ ^0+$ ]]; then
    echo "$name must not be zero." >&2
    exit 1
  fi
  printf '0x%s' "$raw"
}

TINKER_ENCUMBRANCE_OWNER="${TINKER_ENCUMBRANCE_OWNER:-$DEPLOYER_ADDRESS}"
TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH="${TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH:-$manifest_compose_hash}"
TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI="${TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI:-10000000000000000000}"
TINKER_ENCUMBRANCE_MAX_SPEND_WEI="${TINKER_ENCUMBRANCE_MAX_SPEND_WEI:-10000000000000000000}"
TINKER_ENCUMBRANCE_POLICY_UNITS_PER_USD_WEI="${TINKER_ENCUMBRANCE_POLICY_UNITS_PER_USD_WEI:-1000000000000000000}"
TINKER_ENCUMBRANCE_FREEZE_MEASUREMENTS="${TINKER_ENCUMBRANCE_FREEZE_MEASUREMENTS:-false}"
TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT="${TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT:-$manifest_oracle_email_hash}"

validate_bytes32() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "$name must be a non-zero bytes32 hex value." >&2
    exit 1
  fi
  if [ "$value" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo "$name must not be zero." >&2
    exit 1
  fi
}

validate_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an unsigned integer." >&2
    exit 1
  fi
}

TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT="$(
  normalize_bytes32 TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT"
)"
TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH="$(
  normalize_bytes32 TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH"
)"
validate_bytes32 TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT "$TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT"
validate_bytes32 TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH"
validate_uint TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI "$TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI"
validate_uint TINKER_ENCUMBRANCE_MAX_SPEND_WEI "$TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
validate_uint TINKER_ENCUMBRANCE_POLICY_UNITS_PER_USD_WEI "$TINKER_ENCUMBRANCE_POLICY_UNITS_PER_USD_WEI"

export TINKER_ENCUMBRANCE_OWNER
export TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
export TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH
export TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI
export TINKER_ENCUMBRANCE_MAX_SPEND_WEI
export TINKER_ENCUMBRANCE_FREEZE_MEASUREMENTS

cd "$CONTRACTS_DIR"

echo "== TinkerAccountEncumbrance Base Sepolia deploy preflight =="
echo "RPC:                 $RPC_URL"
echo "Account:             $ACCOUNT"
echo "Deployer:            $DEPLOYER_ADDRESS"
echo "Owner:               $TINKER_ENCUMBRANCE_OWNER"
echo "Account commitment:  $TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT"
echo "Compose hash:        $TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH"
echo "Max add balance:     $TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI"
echo "Max spend:           $TINKER_ENCUMBRANCE_MAX_SPEND_WEI"
echo "Freeze measurements: $TINKER_ENCUMBRANCE_FREEZE_MEASUREMENTS"
echo "Manifest:            $MANIFEST_PATH"
echo

echo -n "Chain ID:            "
cast chain-id --rpc-url "$RPC_URL"
echo -n "Balance:             "
cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" --ether
echo -n "Nonce:               "
cast nonce "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL"
echo

echo "== Build and tests =="
forge build --sizes
forge test --match-path test/TinkerAccountEncumbrance.t.sol

echo
echo "== Dry run =="
forge script script/TinkerAccountEncumbrance.s.sol --rpc-url "$RPC_URL" --sender "$DEPLOYER_ADDRESS"

if [ "$BROADCAST" != "true" ]; then
  echo
  echo "Dry run complete. Set BROADCAST=true to deploy with Foundry --account $ACCOUNT."
  exit 0
fi

echo
echo "== Broadcast TinkerAccountEncumbrance =="
forge script script/TinkerAccountEncumbrance.s.sol \
  --rpc-url "$RPC_URL" \
  --sender "$DEPLOYER_ADDRESS" \
  --account "$ACCOUNT" \
  --broadcast \
  --slow

ENCUMBRANCE_RUN="broadcast/TinkerAccountEncumbrance.s.sol/$CHAIN_ID/run-latest.json"
ENCUMBRANCE_ADDRESS="$(jq -r '.transactions[] | select(.contractName == "TinkerAccountEncumbrance") | .contractAddress' "$ENCUMBRANCE_RUN" | tail -1)"
ENCUMBRANCE_TX="$(jq -r '.transactions[] | select(.contractName == "TinkerAccountEncumbrance") | .hash // .transactionHash // empty' "$ENCUMBRANCE_RUN" | tail -1)"

if [ -z "$ENCUMBRANCE_ADDRESS" ]; then
  echo "Could not parse deployed TinkerAccountEncumbrance address from broadcast artifact." >&2
  exit 1
fi

echo
echo "== On-chain verification reads =="
ENCUMBRANCE_OWNER_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "owner()(address)" --rpc-url "$RPC_URL")"
ENCUMBRANCE_ACCOUNT_COMMITMENT_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "accountCommitment()(bytes32)" --rpc-url "$RPC_URL")"
ENCUMBRANCE_MAX_ADD_BALANCE_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "maxAddBalanceWei()(uint256)" --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_MAX_SPEND_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "maxSpendWei()(uint256)" --rpc-url "$RPC_URL" | awk '{print $1}')"
ENCUMBRANCE_COMPOSE_APPROVED_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "approvedComposeHashes(bytes32)(bool)" "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" --rpc-url "$RPC_URL")"
ENCUMBRANCE_HALTED_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "emergencyHalted()(bool)" --rpc-url "$RPC_URL")"
ENCUMBRANCE_FROZEN_READ="$(cast call "$ENCUMBRANCE_ADDRESS" "measurementsFrozen()(bool)" --rpc-url "$RPC_URL")"

echo "TinkerAccountEncumbrance: $ENCUMBRANCE_ADDRESS"
echo "  owner:                  $ENCUMBRANCE_OWNER_READ"
echo "  accountCommitment:      $ENCUMBRANCE_ACCOUNT_COMMITMENT_READ"
echo "  initialComposeHash:     $TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH"
echo "  composeApproved:        $ENCUMBRANCE_COMPOSE_APPROVED_READ"
echo "  maxAddBalanceWei:       $ENCUMBRANCE_MAX_ADD_BALANCE_READ"
echo "  maxSpendWei:            $ENCUMBRANCE_MAX_SPEND_READ"
echo "  emergencyHalted:        $ENCUMBRANCE_HALTED_READ"
echo "  measurementsFrozen:     $ENCUMBRANCE_FROZEN_READ"
echo "  tx:                     $ENCUMBRANCE_TX"

tmp_manifest="$(mktemp)"
jq \
  --arg reviewedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg address "$ENCUMBRANCE_ADDRESS" \
  --arg tx "$ENCUMBRANCE_TX" \
  --arg owner "$ENCUMBRANCE_OWNER_READ" \
  --arg accountCommitment "$ENCUMBRANCE_ACCOUNT_COMMITMENT_READ" \
  --arg initialComposeHash "$TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH" \
  --argjson composeApproved "$ENCUMBRANCE_COMPOSE_APPROVED_READ" \
  --arg maxAddBalanceWei "$ENCUMBRANCE_MAX_ADD_BALANCE_READ" \
  --arg maxSpendWei "$ENCUMBRANCE_MAX_SPEND_READ" \
  --arg policyUnitsPerUsdWei "$TINKER_ENCUMBRANCE_POLICY_UNITS_PER_USD_WEI" \
  --argjson emergencyHalted "$ENCUMBRANCE_HALTED_READ" \
  --argjson measurementsFrozen "$ENCUMBRANCE_FROZEN_READ" \
  --arg helper "⚙️/tinker-delegate/contracts/scripts/deploy-tinker-encumbrance-base-sepolia.sh" \
  '.lastReviewedAt = $reviewedAt
    | .contracts.tinkerAccountEncumbrance = {
        status: "deployed_current_operator_controlled",
        address: $address,
        baseScanUrl: ("https://sepolia.basescan.org/address/" + $address),
        deploymentTx: $tx,
        transactionUrl: (if $tx == "" then null else "https://sepolia.basescan.org/tx/" + $tx end),
        owner: $owner,
        accountCommitment: $accountCommitment,
        initialComposeHash: $initialComposeHash,
        initialComposeHashApproved: $composeApproved,
        maxAddBalanceWei: ($maxAddBalanceWei | tonumber),
        maxSpendWei: ($maxSpendWei | tonumber),
        policyUnitsPerUsdWei: ($policyUnitsPerUsdWei | tonumber),
        emergencyHalted: $emergencyHalted,
        measurementsFrozen: $measurementsFrozen,
        currentOperatorControlled: true
      }
    | .freshDeployment.tinkerAccountEncumbrance = {
        status: "broadcast_complete",
        helper: $helper
      }' "$MANIFEST_PATH" > "$tmp_manifest"
mv "$tmp_manifest" "$MANIFEST_PATH"

echo
echo "Wrote manifest: $MANIFEST_PATH"
