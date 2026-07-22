#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
BASE_SEPOLIA_USDC=0x036CbD53842c5426634e7929541eC2318f3dCF7e
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
MAX_SAFE_JSON_INTEGER=9007199254740991
MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/base-sepolia.json}"
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-compute-release-manifest.jq"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; compute release identity is never inferred." >&2
    exit 1
  fi
}

normalize_address() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

validate_address() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || [[ "$value" =~ ^0x0{40}$ ]]; then
    echo "$name must be a nonzero Ethereum address." >&2
    exit 1
  fi
}

validate_bytes32() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [ "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" = "$ZERO_BYTES32" ]; then
    echo "$name must be a nonzero bytes32 value." >&2
    exit 1
  fi
}

validate_bool() {
  local name="$1"
  local value="$2"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    echo "$name must be true or false." >&2
    exit 1
  fi
}

validate_sha256_digest() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [[ "$value" =~ ^sha256:0{64}$ ]]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

validate_safe_uint() {
  local name="$1"
  local value="$2"
  local LC_ALL=C
  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "$name must be a canonical unsigned base-10 integer." >&2
    exit 1
  fi
  if [ "${#value}" -gt "${#MAX_SAFE_JSON_INTEGER}" ] \
    || { [ "${#value}" -eq "${#MAX_SAFE_JSON_INTEGER}" ] && [[ "$value" > "$MAX_SAFE_JSON_INTEGER" ]]; }; then
    echo "$name exceeds the exact JSON integer range." >&2
    exit 1
  fi
}

canonical_receipt_uint() {
  local name="$1"
  local value="$2"
  local canonical
  value="$(printf '%s\n' "$value" | awk 'NF { print $1; exit }')"
  if [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]]; then
    canonical="$(cast to-dec "$value")"
  else
    canonical="$value"
  fi
  validate_safe_uint "$name" "$canonical"
  printf '%s\n' "$canonical"
}

read_value() {
  local signature="$1"
  shift
  cast call "$COMPUTE_VAULT_ADDRESS" "$signature" "$@" --rpc-url "$BASE_SEPOLIA_RPC_URL"
}

read_uint() {
  local value
  value="$(read_value "$@" | awk 'NR == 1 && $1 ~ /^(0|[1-9][0-9]*)$/ { print $1; found = 1 } END { if (!found) exit 1 }')"
  validate_safe_uint "on-chain uint" "$value"
  printf '%s\n' "$value"
}

deployment_ledger_blob() {
  git hash-object --no-filters "$MANIFEST_PATH"
}

validate_existing_deployment_ledger() {
  if [ ! -f "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be an existing non-symlink regular file at $MANIFEST_PATH." >&2
    exit 1
  fi
  if [ ! -r "$MANIFEST_PATH" ] || [ ! -w "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be readable and writable." >&2
    exit 1
  fi
  if ! jq -e \
    --arg vault "$COMPUTE_VAULT_ADDRESS" \
    --arg runtime "$COMPUTE_VAULT_RUNTIME_CODE_HASH" \
    --arg source "$RELEASE_SHA" \
    '
      type == "object"
      and .network.chainId == 84532
      and ((.contracts.computeCreditVault.address // "") | ascii_downcase) == ($vault | ascii_downcase)
      and ((.contracts.computeCreditVault.runtimeCodeHash // "") | ascii_downcase) == ($runtime | ascii_downcase)
      and .contracts.computeCreditVault.sourceCommit == $source
      and .freshDeployment.contractSuite.sourceCommit == $source
      and ((.computeReleaseHistory // []) | type) == "array"
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger address, runtime, or source does not match this ComputeCreditVault release." >&2
    exit 1
  fi
}

check_release_provenance() {
  require_env RELEASE_SHA
  if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$RELEASE_SHA" != "$(git -C "$ROOT_DIR" rev-parse HEAD)" ]; then
    echo "RELEASE_SHA must equal the exact lowercase checked-out commit." >&2
    exit 1
  fi
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]; then
    echo "Refusing governance broadcast from a dirty source tree." >&2
    exit 1
  fi
}

for required in forge cast git jq node; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  DEPLOYMENT_OPERATOR \
  COMPUTE_VAULT_DEVELOPER \
  COMPUTE_VAULT_DEVELOPER_FEE_BPS \
  COMPUTE_VAULT_ADDRESS \
  COMPUTE_VAULT_RUNTIME_CODE_HASH \
  COMPUTE_VAULT_TEE_IDENTITY \
  COMPUTE_VAULT_COMPOSE_HASH \
  COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_NATIVE_PROVIDER \
  COMPUTE_VAULT_ERC20_PROVIDER \
  COMPUTE_VAULT_METERING_VERIFIER \
  COMPUTE_VAULT_METERING_QVL_VERIFIER \
  COMPUTE_METERING_POLICY_SET_HASH \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  COMPUTE_RELEASE_PHASE; do
  require_env "$name"
done

BROADCAST="${BROADCAST:-false}"
validate_bool BROADCAST "$BROADCAST"
if [[ ! "$COMPUTE_RELEASE_PHASE" =~ ^[123]$ ]]; then
  echo "COMPUTE_RELEASE_PHASE must be exactly 1, 2, or 3." >&2
  exit 1
fi
for name in \
  DEPLOYMENT_OPERATOR \
  COMPUTE_VAULT_DEVELOPER \
  COMPUTE_VAULT_ADDRESS \
  COMPUTE_VAULT_TEE_IDENTITY \
  COMPUTE_VAULT_NATIVE_PROVIDER \
  COMPUTE_VAULT_ERC20_PROVIDER \
  COMPUTE_VAULT_METERING_VERIFIER \
  COMPUTE_VAULT_METERING_QVL_VERIFIER; do
  validate_address "$name" "${!name}"
done
for name in \
  COMPUTE_VAULT_COMPOSE_HASH \
  COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT \
  COMPUTE_METERING_POLICY_SET_HASH; do
  validate_bytes32 "$name" "${!name}"
done
validate_bytes32 COMPUTE_VAULT_RUNTIME_CODE_HASH "$COMPUTE_VAULT_RUNTIME_CODE_HASH"
validate_safe_uint COMPUTE_VAULT_DEVELOPER_FEE_BPS "$COMPUTE_VAULT_DEVELOPER_FEE_BPS"
validate_sha256_digest OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"
validate_sha256_digest OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
if [ "$COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT" = "$COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT" ]; then
  echo "Native and USDC rate-policy commitments must differ." >&2
  exit 1
fi
if [ "$(normalize_address "$COMPUTE_VAULT_METERING_VERIFIER")" = "$(normalize_address "$COMPUTE_VAULT_METERING_QVL_VERIFIER")" ]; then
  echo "Metering and metering-QVL verifiers must be distinct." >&2
  exit 1
fi

operator_policy_project_and_validate
operator_policy_assert_public_env contractEnv COMPUTE_VAULT_DEVELOPER
operator_policy_assert_public_env contractEnv COMPUTE_VAULT_DEVELOPER_FEE_BPS
operator_policy_assert_public_env contractEnv COMPUTE_VAULT_METERING_VERIFIER
operator_policy_assert_public_env contractEnv COMPUTE_VAULT_METERING_QVL_VERIFIER
for policy_env_name in \
  COMPUTE_VAULT_TEE_IDENTITY \
  COMPUTE_VAULT_COMPOSE_HASH \
  COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT \
  COMPUTE_VAULT_NATIVE_PROVIDER \
  COMPUTE_VAULT_ERC20_PROVIDER \
  COMPUTE_METERING_POLICY_SET_HASH; do
  operator_policy_assert_public_env postDeployEnv "$policy_env_name"
done

if [ "$BROADCAST" = "true" ]; then
  # Refuse an irreversible governance transaction when its append-only
  # evidence target is absent or belongs to another deployment. The same
  # binding is rechecked immediately before unlock and after post-state reads.
  validate_existing_deployment_ledger
fi

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Compute release governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing compute release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi

live_vault_code_hash="$(cast codehash "$COMPUTE_VAULT_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(printf '%s' "$live_vault_code_hash" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$COMPUTE_VAULT_RUNTIME_CODE_HASH" | tr '[:upper:]' '[:lower:]')" ]; then
  echo "ComputeCreditVault runtime code does not match the reviewed release hash." >&2
  exit 1
fi

vault_owner="$(cast call "$COMPUTE_VAULT_ADDRESS" 'owner()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_address "$vault_owner")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ]; then
  echo "DEPLOYMENT_OPERATOR is not the live ComputeCreditVault owner." >&2
  exit 1
fi
vault_developer="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developer()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
vault_developer_fee_bps="$(cast call "$COMPUTE_VAULT_ADDRESS" 'developerFeeBps()(uint16)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
if [ "$(normalize_address "$vault_developer")" != "$(normalize_address "$COMPUTE_VAULT_DEVELOPER")" ] \
  || [ "$vault_developer_fee_bps" != "$COMPUTE_VAULT_DEVELOPER_FEE_BPS" ]; then
  echo "ComputeCreditVault developer or fee does not match the reviewed operator policy." >&2
  exit 1
fi

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== ComputeCreditVault release phase $COMPUTE_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Keystore account:  dev"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "Vault:             $COMPUTE_VAULT_ADDRESS"
echo "Metering verifier: $COMPUTE_VAULT_METERING_VERIFIER"
echo "Metering QVL:      $COMPUTE_VAULT_METERING_QVL_VERIFIER"
echo "Policy-set hash:    $COMPUTE_METERING_POLICY_SET_HASH"
echo "Broadcast:         $BROADCAST"

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --match-path test/ConfigureComputeRelease.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureComputeRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock compute_release

# Build, tests, and simulation can take long enough for the checkout to change.
# Re-bind the broadcast to the reviewed clean commit immediately before the
# keystore is unlocked and any governance transaction can be signed.
check_release_provenance
validate_existing_deployment_ledger
unlocked_signer="$(cast wallet address --account dev)"
if [ "$(normalize_address "$unlocked_signer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi
# Refuse source or ledger drift between unlock and signing.
check_release_provenance
validate_existing_deployment_ledger

echo
echo "== Broadcast exact timelocked phase =="
forge script script/ConfigureComputeRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

allowed_count="$(read_uint 'allowedAssetCount()(uint256)')"
rate_count="$(read_uint 'activeRatePolicyCount()(uint256)')"
compose_count="$(read_uint 'approvedComposeCount()(uint256)')"
tee_count="$(read_uint 'approvedTeeIdentityCount()(uint256)')"
pending_asset_count="$(read_uint 'pendingAssetCount()(uint256)')"
pending_rate_count="$(read_uint 'pendingRatePolicyCount()(uint256)')"
pending_compose_count="$(read_uint 'pendingComposeCount()(uint256)')"
pending_tee_count="$(read_uint 'pendingTeeIdentityCount()(uint256)')"
metering_verifier="$(read_value 'meteringVerifier()(address)')"
metering_qvl_verifier="$(read_value 'meteringQvlVerifier()(address)')"
metering_policy_set_hash="$(read_value 'meteringPolicySetHash()(bytes32)')"
pending_metering_verifier="$(read_value 'pendingMeteringVerifier()(address)')"
pending_metering_qvl_verifier="$(read_value 'pendingMeteringQvlVerifier()(address)')"
pending_metering_policy_set_hash="$(read_value 'pendingMeteringPolicySetHash()(bytes32)')"
pending_metering_activates_at="$(read_uint 'pendingMeteringBindingActivatesAt()(uint64)')"
metering_binding_frozen="$(read_value 'meteringBindingFrozen()(bool)')"
vault_paused="$(read_value 'paused()(bool)')"
developer_fee_bps="$(read_uint 'developerFeeBps()(uint16)')"
developer_fee_frozen="$(read_value 'developerFeeFrozen()(bool)')"
asset_additions_frozen="$(read_value 'assetAdditionsFrozen()(bool)')"
rate_policy_additions_frozen="$(read_value 'ratePolicyAdditionsFrozen()(bool)')"
compose_policy_frozen="$(read_value 'composePolicyFrozen()(bool)')"
tee_identity_additions_frozen="$(read_value 'teeIdentityAdditionsFrozen()(bool)')"
usdc_allowed="$(read_value 'allowedAssets(address)(bool)' "$BASE_SEPOLIA_USDC")"
pending_asset_activates_at="$(read_uint 'pendingAssetActivations(address)(uint64)' "$BASE_SEPOLIA_USDC")"
compose_approved="$(read_value 'approvedComposeHashes(bytes32)(bool)' "$COMPUTE_VAULT_COMPOSE_HASH")"
pending_compose_activates_at="$(read_uint 'pendingComposeActivations(bytes32)(uint64)' "$COMPUTE_VAULT_COMPOSE_HASH")"
active_tee_compose_hash="$(read_value 'teeIdentityComposeHash(address)(bytes32)' "$COMPUTE_VAULT_TEE_IDENTITY")"
pending_tee_compose_hash="$(read_value 'pendingTeeIdentityComposeHash(address)(bytes32)' "$COMPUTE_VAULT_TEE_IDENTITY")"
pending_tee_activates_at="$(read_uint 'pendingTeeIdentityActivations(address)(uint64)' "$COMPUTE_VAULT_TEE_IDENTITY")"

case "$COMPUTE_RELEASE_PHASE" in
  1)
    expected="0 0 0 0 1 1 1 0"
    if [ "$(normalize_address "$pending_metering_verifier")" != "$(normalize_address "$COMPUTE_VAULT_METERING_VERIFIER")" ] \
      || [ "$(normalize_address "$pending_metering_qvl_verifier")" != "$(normalize_address "$COMPUTE_VAULT_METERING_QVL_VERIFIER")" ] \
      || [ "$(printf '%s' "$pending_metering_policy_set_hash" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$COMPUTE_METERING_POLICY_SET_HASH" | tr '[:upper:]' '[:lower:]')" ] \
      || [ "$pending_metering_activates_at" = "0" ] || [ "$metering_binding_frozen" != "false" ] \
      || [ "$vault_paused" != "true" ]; then
      echo "Phase 1 did not stage the exact paused metering binding." >&2
      exit 1
    fi
    ;;
  2)
    expected="1 1 1 0 0 1 0 1"
    ;;
  3)
    expected="1 2 1 1 0 0 0 0"
    for frozen_getter in assetAdditionsFrozen ratePolicyAdditionsFrozen composePolicyFrozen teeIdentityAdditionsFrozen meteringBindingFrozen; do
      if [ "$(cast call "$COMPUTE_VAULT_ADDRESS" "$frozen_getter()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL")" != "true" ]; then
        echo "$frozen_getter did not become true." >&2
        exit 1
      fi
    done
    bound_compose="$(cast call "$COMPUTE_VAULT_ADDRESS" 'teeIdentityComposeHash(address)(bytes32)' "$COMPUTE_VAULT_TEE_IDENTITY" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    if [ "$(printf '%s' "$bound_compose" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$COMPUTE_VAULT_COMPOSE_HASH" | tr '[:upper:]' '[:lower:]')" ]; then
      echo "The final TEE identity compose binding does not match." >&2
      exit 1
    fi
    ;;
esac

actual="$allowed_count $rate_count $compose_count $tee_count $pending_asset_count $pending_rate_count $pending_compose_count $pending_tee_count"
if [ "$actual" != "$expected" ]; then
  echo "Post-broadcast active/pending admission counts mismatch: expected $expected, received $actual." >&2
  exit 1
fi

if [ "$COMPUTE_RELEASE_PHASE" = "2" ] || [ "$COMPUTE_RELEASE_PHASE" = "3" ]; then
  if [ "$(normalize_address "$metering_verifier")" != "$(normalize_address "$COMPUTE_VAULT_METERING_VERIFIER")" ] \
    || [ "$(normalize_address "$metering_qvl_verifier")" != "$(normalize_address "$COMPUTE_VAULT_METERING_QVL_VERIFIER")" ] \
    || [ "$(printf '%s' "$metering_policy_set_hash" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$COMPUTE_METERING_POLICY_SET_HASH" | tr '[:upper:]' '[:lower:]')" ] \
    || [ "$(normalize_address "$pending_metering_verifier")" != "0x0000000000000000000000000000000000000000" ] \
    || [ "$(normalize_address "$pending_metering_qvl_verifier")" != "0x0000000000000000000000000000000000000000" ] \
    || [ "$(printf '%s' "$pending_metering_policy_set_hash" | tr '[:upper:]' '[:lower:]')" != "$ZERO_BYTES32" ] \
    || [ "$pending_metering_activates_at" != "0" ] || [ "$metering_binding_frozen" != "true" ]; then
    echo "The active metering signer/policy-set binding is not exact and frozen." >&2
    exit 1
  fi
fi

if { [ "$COMPUTE_RELEASE_PHASE" = "1" ] || [ "$COMPUTE_RELEASE_PHASE" = "2" ]; } && [ "$vault_paused" != "true" ]; then
  echo "ComputeCreditVault must remain paused through phase 2." >&2
  exit 1
fi
if [ "$COMPUTE_RELEASE_PHASE" = "3" ] && [ "$vault_paused" != "false" ]; then
  echo "ComputeCreditVault did not unpause only after the complete frozen release." >&2
  exit 1
fi

native_policy_json="$(read_value 'ratePolicies(bytes32)(address,address,uint16,bool)' "$COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT" --json)"
native_pending_json="$(read_value 'pendingRatePolicies(bytes32)(address,address,uint16,uint64)' "$COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT" --json)"
erc20_policy_json="$(read_value 'ratePolicies(bytes32)(address,address,uint16,bool)' "$COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT" --json)"
erc20_pending_json="$(read_value 'pendingRatePolicies(bytes32)(address,address,uint16,uint64)' "$COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT" --json)"

for tuple_json in "$native_policy_json" "$native_pending_json" "$erc20_policy_json" "$erc20_pending_json"; do
  if ! printf '%s' "$tuple_json" | jq -e 'type == "array" and length == 4' >/dev/null; then
    echo "ComputeCreditVault returned an invalid rate-policy tuple." >&2
    exit 1
  fi
done

tuple_address() {
  local tuple="$1"
  local index="$2"
  printf '%s' "$tuple" | jq -er --argjson index "$index" \
    '.[$index] | select(type == "string" and test("^0x[0-9a-fA-F]{40}$"))'
}

tuple_uint() {
  local tuple="$1"
  local index="$2"
  local value
  value="$(printf '%s' "$tuple" | jq -er --argjson index "$index" \
    '.[$index] | if type == "number" then tostring else . end | select(type == "string" and test("^(0|[1-9][0-9]*)$"))')"
  validate_safe_uint "rate-policy tuple uint" "$value"
  printf '%s\n' "$value"
}

tuple_bool() {
  local tuple="$1"
  local index="$2"
  printf '%s' "$tuple" | jq -er --argjson index "$index" '.[$index] | select(type == "boolean")'
}

native_active_asset="$(tuple_address "$native_policy_json" 0)"
native_active_provider="$(tuple_address "$native_policy_json" 1)"
native_active_fee_bps="$(tuple_uint "$native_policy_json" 2)"
native_active="$(tuple_bool "$native_policy_json" 3)"
native_pending_asset="$(tuple_address "$native_pending_json" 0)"
native_pending_provider="$(tuple_address "$native_pending_json" 1)"
native_pending_fee_bps="$(tuple_uint "$native_pending_json" 2)"
native_pending_activates_at="$(tuple_uint "$native_pending_json" 3)"
erc20_active_asset="$(tuple_address "$erc20_policy_json" 0)"
erc20_active_provider="$(tuple_address "$erc20_policy_json" 1)"
erc20_active_fee_bps="$(tuple_uint "$erc20_policy_json" 2)"
erc20_active="$(tuple_bool "$erc20_policy_json" 3)"
erc20_pending_asset="$(tuple_address "$erc20_pending_json" 0)"
erc20_pending_provider="$(tuple_address "$erc20_pending_json" 1)"
erc20_pending_fee_bps="$(tuple_uint "$erc20_pending_json" 2)"
erc20_pending_activates_at="$(tuple_uint "$erc20_pending_json" 3)"

case "$COMPUTE_RELEASE_PHASE" in
  1)
    expected_functions_json='["proposeAsset(address)","proposeRatePolicy(bytes32,address,address,uint16)","proposeComposeHash(bytes32)","proposeMeteringBinding(address,address,bytes32)"]'
    ;;
  2)
    expected_functions_json='["activateAsset(address)","activateRatePolicy(bytes32)","activateComposeHash(bytes32)","activateMeteringBinding()","freezeMeteringBinding()","proposeRatePolicy(bytes32,address,address,uint16)","proposeTeeIdentity(address,bytes32)"]'
    ;;
  3)
    expected_functions_json='["activateRatePolicy(bytes32)","activateTeeIdentity(address)","freezeAssetAdditions()","freezeRatePolicyAdditions()","freezeComposePolicy()","freezeTeeIdentityAdditions()","setPaused(bool)"]'
    ;;
esac

run_path="$CONTRACTS_DIR/broadcast/ConfigureComputeRelease.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$run_path" ] || [ -L "$run_path" ]; then
  echo "Missing non-symlink Forge broadcast receipt at $run_path." >&2
  exit 1
fi

if ! broadcast_transactions="$(jq -cer \
  --arg vault "$COMPUTE_VAULT_ADDRESS" \
  --argjson expectedFunctions "$expected_functions_json" \
  '
    def require($condition; $message):
      if $condition then . else error($message) end;
    def hex_digit:
      if . >= 48 and . <= 57 then . - 48
      elif . >= 97 and . <= 102 then . - 87
      else error("invalid hexadecimal digit")
      end;
    def safe_block_number:
      (if type == "number" then .
       elif type == "string" and test("^(0|[1-9][0-9]*)$") then tonumber
       elif type == "string" and test("^0x[0-9a-fA-F]+$") then
         (ascii_downcase | ltrimstr("0x") | explode
          | reduce .[] as $digit (0; . * 16 + ($digit | hex_digit)))
       else error("invalid block number")
       end)
      | if . >= 0 and . <= 9007199254740991 and floor == . then .
        else error("block number exceeds exact JSON integer range")
        end;
    (.transactions // null) as $transactions
    | (.receipts // null) as $receipts
    | require((.chain | tostring) == "84532"; "broadcast receipt chainId mismatch")
    | require(($transactions | type) == "array"
        and ($transactions | length) == ($expectedFunctions | length);
        "unexpected broadcast transaction count")
    | require(($receipts | type) == "array"
        and ($receipts | length) == ($expectedFunctions | length);
        "unexpected broadcast receipt count")
    | [range(0; ($expectedFunctions | length)) as $index
        | ($transactions[$index]) as $transaction
        | ($transaction.hash // $transaction.transactionHash // "") as $hash
        | require($transaction.transactionType == "CALL";
            "broadcast evidence contains a non-CALL transaction")
        | require((($transaction.contractAddress // "") | ascii_downcase) == ($vault | ascii_downcase);
            "broadcast transaction targets a different contract")
        | require($transaction.function == $expectedFunctions[$index];
            "broadcast transaction function order mismatch")
        | require(($hash | type) == "string" and ($hash | test("^0x[0-9a-fA-F]{64}$"))
            and (($hash | ascii_downcase) != ("0x" + ("0" * 64)));
            "broadcast transaction hash is invalid")
        | ([$receipts[]
            | select(((.transactionHash // "") | ascii_downcase) == ($hash | ascii_downcase))]) as $matches
        | require(($matches | length) == 1;
            "broadcast transaction does not have one exact receipt")
        | ($matches[0]) as $receipt
        | require($receipt.status == "0x1" or $receipt.status == "1" or $receipt.status == 1;
            "broadcast transaction was not accepted")
        | {
            transactionHash: ($hash | ascii_downcase),
            blockNumber: ($receipt.blockNumber | safe_block_number)
          }]
    | require(([.[].transactionHash] | unique | length) == length;
        "broadcast transaction hashes are duplicated")
  ' "$run_path")"; then
  echo "Forge broadcast evidence is missing, stale, malformed, or unsuccessful." >&2
  exit 1
fi

confirmed_transactions='[]'
while IFS=$'\t' read -r transaction_hash forge_block_number; do
  receipt_status="$(canonical_receipt_uint receipt_status \
    "$(cast receipt "$transaction_hash" status --confirmations 1 --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
  if [ "$receipt_status" != "1" ]; then
    echo "Compute release transaction $transaction_hash was not accepted on Base Sepolia." >&2
    exit 1
  fi
  confirmed_block_number="$(canonical_receipt_uint receipt_block_number \
    "$(cast receipt "$transaction_hash" blockNumber --confirmations 1 --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
  if [ "$confirmed_block_number" = "0" ] || [ "$confirmed_block_number" != "$forge_block_number" ]; then
    echo "Compute release transaction block does not match its Forge receipt." >&2
    exit 1
  fi
  confirmed_block_timestamp="$(canonical_receipt_uint receipt_block_timestamp \
    "$(cast block "$confirmed_block_number" timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")")"
  if [ "$confirmed_block_timestamp" = "0" ]; then
    echo "Compute release transaction block has an invalid zero timestamp." >&2
    exit 1
  fi
  confirmed_transactions="$(jq -cn \
    --argjson current "$confirmed_transactions" \
    --arg transactionHash "$transaction_hash" \
    --argjson blockNumber "$confirmed_block_number" \
    --argjson blockTimestamp "$confirmed_block_timestamp" \
    '$current + [{
      transactionHash: $transactionHash,
      blockNumber: $blockNumber,
      blockTimestamp: $blockTimestamp
    }]')"
done < <(printf '%s' "$broadcast_transactions" | jq -r '.[] | [.transactionHash, .blockNumber] | @tsv')
broadcast_transactions="$confirmed_transactions"

# The append-only evidence target is intentionally revalidated only after all
# phase-specific chain reads succeed. Final authority and the renewable review
# envelope are ceremony evidence, not claims about the immutable fresh deploy.
validate_existing_deployment_ledger
manifest_before_blob="$(deployment_ledger_blob)"
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmp_manifest="$(mktemp "${MANIFEST_PATH}.tmp.XXXXXX")"

cleanup_compute_manifest_temp() {
  if [ -n "${tmp_manifest:-}" ]; then
    rm -f -- "$tmp_manifest"
    tmp_manifest=""
  fi
}
trap 'cleanup_compute_manifest_temp; cleanup_operator_policy_projection' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! jq -e \
  --argjson chainId "$CHAIN_ID" \
  --arg vaultAddress "$COMPUTE_VAULT_ADDRESS" \
  --arg runtimeCodeHash "$COMPUTE_VAULT_RUNTIME_CODE_HASH" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --argjson phase "$COMPUTE_RELEASE_PHASE" \
  --argjson transactions "$broadcast_transactions" \
  --arg recordedAt "$recorded_at" \
  --arg teeIdentity "$COMPUTE_VAULT_TEE_IDENTITY" \
  --arg composeHash "$COMPUTE_VAULT_COMPOSE_HASH" \
  --arg nativePolicyCommitment "$COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT" \
  --arg erc20PolicyCommitment "$COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT" \
  --arg nativeProvider "$COMPUTE_VAULT_NATIVE_PROVIDER" \
  --arg erc20Provider "$COMPUTE_VAULT_ERC20_PROVIDER" \
  --arg meteringVerifierExpected "$COMPUTE_VAULT_METERING_VERIFIER" \
  --arg meteringQvlVerifierExpected "$COMPUTE_VAULT_METERING_QVL_VERIFIER" \
  --arg meteringPolicySetHashExpected "$COMPUTE_METERING_POLICY_SET_HASH" \
  --arg baseSepoliaUsdc "$BASE_SEPOLIA_USDC" \
  --argjson developerFeeBps "$developer_fee_bps" \
  --argjson developerFeeFrozen "$developer_fee_frozen" \
  --arg meteringVerifier "$metering_verifier" \
  --arg meteringQvlVerifier "$metering_qvl_verifier" \
  --arg meteringPolicySetHash "$metering_policy_set_hash" \
  --arg pendingMeteringVerifier "$pending_metering_verifier" \
  --arg pendingMeteringQvlVerifier "$pending_metering_qvl_verifier" \
  --arg pendingMeteringPolicySetHash "$pending_metering_policy_set_hash" \
  --argjson pendingMeteringActivatesAt "$pending_metering_activates_at" \
  --argjson meteringBindingFrozen "$metering_binding_frozen" \
  --argjson paused "$vault_paused" \
  --argjson allowedAssetCount "$allowed_count" \
  --argjson activeRatePolicyCount "$rate_count" \
  --argjson approvedComposeCount "$compose_count" \
  --argjson approvedTeeCount "$tee_count" \
  --argjson pendingAssetCount "$pending_asset_count" \
  --argjson pendingRatePolicyCount "$pending_rate_count" \
  --argjson pendingComposeCount "$pending_compose_count" \
  --argjson pendingTeeCount "$pending_tee_count" \
  --argjson assetAdditionsFrozen "$asset_additions_frozen" \
  --argjson ratePolicyAdditionsFrozen "$rate_policy_additions_frozen" \
  --argjson composePolicyFrozen "$compose_policy_frozen" \
  --argjson teeIdentityAdditionsFrozen "$tee_identity_additions_frozen" \
  --argjson usdcAllowed "$usdc_allowed" \
  --argjson pendingAssetActivatesAt "$pending_asset_activates_at" \
  --argjson composeApproved "$compose_approved" \
  --argjson pendingComposeActivatesAt "$pending_compose_activates_at" \
  --arg activeTeeComposeHash "$active_tee_compose_hash" \
  --arg pendingTeeComposeHash "$pending_tee_compose_hash" \
  --argjson pendingTeeActivatesAt "$pending_tee_activates_at" \
  --arg nativeActiveAsset "$native_active_asset" \
  --arg nativeActiveProvider "$native_active_provider" \
  --argjson nativeActiveFeeBps "$native_active_fee_bps" \
  --argjson nativeActive "$native_active" \
  --arg nativePendingAsset "$native_pending_asset" \
  --arg nativePendingProvider "$native_pending_provider" \
  --argjson nativePendingFeeBps "$native_pending_fee_bps" \
  --argjson nativePendingActivatesAt "$native_pending_activates_at" \
  --arg erc20ActiveAsset "$erc20_active_asset" \
  --arg erc20ActiveProvider "$erc20_active_provider" \
  --argjson erc20ActiveFeeBps "$erc20_active_fee_bps" \
  --argjson erc20Active "$erc20_active" \
  --arg erc20PendingAsset "$erc20_pending_asset" \
  --arg erc20PendingProvider "$erc20_pending_provider" \
  --argjson erc20PendingFeeBps "$erc20_pending_fee_bps" \
  --argjson erc20PendingActivatesAt "$erc20_pending_activates_at" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" > "$tmp_manifest"; then
  echo "Compute release evidence did not satisfy the exact ledger merge policy." >&2
  exit 1
fi

if [ "$manifest_before_blob" != "$(deployment_ledger_blob)" ]; then
  echo "Deployment ledger changed concurrently; refusing to replace it." >&2
  exit 1
fi
if ! jq -e 'type == "object"' "$tmp_manifest" >/dev/null; then
  echo "Compute release ledger merge did not produce one JSON object." >&2
  exit 1
fi
operator_policy_durably_replace_release_ledger "$tmp_manifest" "$MANIFEST_PATH"
rm -f -- "$tmp_manifest"
tmp_manifest=""
operator_policy_release_release_ceremony_lock

echo "Compute release phase $COMPUTE_RELEASE_PHASE completed with exact post-state and atomic append-only ledger evidence."
