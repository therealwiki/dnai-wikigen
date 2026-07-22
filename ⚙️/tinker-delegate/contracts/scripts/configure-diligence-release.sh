#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
MAX_SAFE_JSON_INTEGER=9007199254740991
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
MANIFEST_PATH="${DEPLOYMENT_MANIFEST_PATH:-$ROOT_DIR/deployments/base-sepolia.json}"
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-diligence-release-manifest.jq"
DILIGENCE_MANIFEST_TEMP_PATH=""

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

cleanup_diligence_release() {
  if [ -n "${DILIGENCE_MANIFEST_TEMP_PATH:-}" ]; then
    rm -f -- "$DILIGENCE_MANIFEST_TEMP_PATH"
    DILIGENCE_MANIFEST_TEMP_PATH=""
  fi
  cleanup_operator_policy_projection
}

trap cleanup_diligence_release EXIT
trap 'cleanup_diligence_release; exit 1' HUP INT TERM

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "$name is required; diligence release identity is never inferred." >&2
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
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]] || [ "$(normalize_address "$value")" = "$ZERO_BYTES32" ]; then
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
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || [ "$value" = "sha256:$(printf '0%.0s' {1..64})" ]; then
    echo "$name must be a nonzero lowercase sha256:<64-hex> digest." >&2
    exit 1
  fi
}

validate_safe_json_uint() {
  local name="$1"
  local value="$2"
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
    --arg room "$DILIGENCE_ROOM_ADDRESS" \
    --arg runtime "$DILIGENCE_RUNTIME_CODE_HASH" \
    --arg source "$RELEASE_SHA" \
    '
      type == "object"
      and .network.chainId == 84532
      and ((.contracts.diligenceRoom.address // "") | ascii_downcase) == ($room | ascii_downcase)
      and ((.contracts.diligenceRoom.runtimeCodeHash // "") | ascii_downcase) == ($runtime | ascii_downcase)
      and .contracts.diligenceRoom.sourceCommit == $source
      and .freshDeployment.contractSuite.sourceCommit == $source
      and ((.diligenceReleaseHistory // []) | type) == "array"
    ' "$MANIFEST_PATH" >/dev/null; then
    echo "Deployment ledger chain, DiligenceRoom address, runtime, or source does not match this release." >&2
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
  DILIGENCE_RESULT_VERIFIER \
  DILIGENCE_ROOM_ADDRESS \
  DILIGENCE_RUNTIME_CODE_HASH \
  DILIGENCE_TEE_IDENTITY \
  DILIGENCE_COMPOSE_HASH \
  DILIGENCE_ATTESTATION_VERIFIER \
  DILIGENCE_QVL_RELEASE_POLICY_HASH \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3 \
  DILIGENCE_EVALUATOR_POLICY_SET_ROOT \
  OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  DILIGENCE_RELEASE_PHASE; do
  require_env "$name"
done

BROADCAST="${BROADCAST:-false}"
validate_bool BROADCAST "$BROADCAST"
if [[ ! "$DILIGENCE_RELEASE_PHASE" =~ ^[123]$ ]]; then
  echo "DILIGENCE_RELEASE_PHASE must be exactly 1, 2, or 3." >&2
  exit 1
fi
for name in DEPLOYMENT_OPERATOR DILIGENCE_RESULT_VERIFIER DILIGENCE_ROOM_ADDRESS DILIGENCE_TEE_IDENTITY DILIGENCE_ATTESTATION_VERIFIER; do
  validate_address "$name" "${!name}"
done
validate_bytes32 DILIGENCE_RUNTIME_CODE_HASH "$DILIGENCE_RUNTIME_CODE_HASH"
validate_bytes32 DILIGENCE_COMPOSE_HASH "$DILIGENCE_COMPOSE_HASH"
validate_bytes32 DILIGENCE_QVL_RELEASE_POLICY_HASH "$DILIGENCE_QVL_RELEASE_POLICY_HASH"
for name in \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2 \
  DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3 \
  DILIGENCE_EVALUATOR_POLICY_SET_ROOT; do
  validate_bytes32 "$name" "${!name}"
  if [ "${!name}" != "$(normalize_address "${!name}")" ]; then
    echo "$name must use canonical lowercase hex." >&2
    exit 1
  fi
done
if [ "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" = "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" ] \
  || [ "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" = "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" ] \
  || [ "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" = "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" ]; then
  echo "Diligence evaluator policy commitments must be distinct." >&2
  exit 1
fi
if [[ "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" > "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" ]] \
  || [[ "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" > "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" ]]; then
  echo "Diligence evaluator policy commitments must be in canonical ascending order." >&2
  exit 1
fi
validate_sha256_digest OPERATOR_POLICY_FINAL_AUTHORITY_SHA256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256"
validate_sha256_digest OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256"

operator_policy_project_and_validate
operator_policy_assert_public_env contractEnv DILIGENCE_RESULT_VERIFIER
operator_policy_assert_public_env postDeployEnv DILIGENCE_TEE_IDENTITY
operator_policy_assert_public_env postDeployEnv DILIGENCE_COMPOSE_HASH
operator_policy_assert_public_env postDeployEnv DILIGENCE_ATTESTATION_VERIFIER
operator_policy_assert_public_env postDeployEnv DILIGENCE_QVL_RELEASE_POLICY_HASH
operator_policy_assert_public_env postDeployEnv DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1
operator_policy_assert_public_env postDeployEnv DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2
operator_policy_assert_public_env postDeployEnv DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3
operator_policy_assert_public_env postDeployEnv DILIGENCE_EVALUATOR_POLICY_SET_ROOT

if [ "$BROADCAST" = "true" ]; then
  # Refuse an irreversible transaction when its append-only evidence target is
  # absent or belongs to another deployment. Rechecked after the chain writes.
  validate_existing_deployment_ledger
fi

if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  echo "Diligence release governance is restricted to the Foundry keystore account named dev." >&2
  exit 1
fi
if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
  echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
  exit 1
fi

live_chain_id="$(cast chain-id --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$live_chain_id" != "$CHAIN_ID" ]; then
  echo "Refusing diligence release: RPC chainId $live_chain_id is not Base Sepolia $CHAIN_ID." >&2
  exit 1
fi
live_code_hash="$(cast codehash "$DILIGENCE_ROOM_ADDRESS" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_address "$live_code_hash")" != "$(normalize_address "$DILIGENCE_RUNTIME_CODE_HASH")" ]; then
  echo "DiligenceRoom runtime code does not match the reviewed release hash." >&2
  exit 1
fi
live_developer="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'developer()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_address "$live_developer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ]; then
  echo "DEPLOYMENT_OPERATOR is not the live DiligenceRoom developer." >&2
  exit 1
fi
calculated_evaluator_policy_root="$(cast call \
  "$DILIGENCE_ROOM_ADDRESS" \
  'computeEvaluatorPolicySetRoot(bytes32[3])(bytes32)' \
  "[$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1,$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2,$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3]" \
  --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$(normalize_address "$calculated_evaluator_policy_root")" != "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT" ]; then
  echo "Diligence evaluator policy-set root does not match the exact three commitments." >&2
  exit 1
fi
for required_gate in \
  'feeBpsFrozen()(bool)' \
  'computeSettlementPolicyEnabled()(bool)' \
  'composeApprovalRequired()(bool)' \
  'teeIdentityApprovalRequired()(bool)' \
  'approvalRequirementsFrozen()(bool)'; do
  if [ "$(cast call "$DILIGENCE_ROOM_ADDRESS" "$required_gate" --rpc-url "$BASE_SEPOLIA_RPC_URL")" != "true" ]; then
    echo "$required_gate is not true on the live DiligenceRoom." >&2
    exit 1
  fi
done

# Validate the exact pre-state before even simulating the requested phase. The
# Forge script repeats these checks at the transaction boundary; keeping them
# here makes operator errors fail before any wallet unlock or broadcast prompt.
pre_result_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'resultVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_pending_result_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingResultVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_pending_result_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingResultVerifierActivatesAt()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_result_verifier_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'resultVerifierFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_approved_evaluator="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicyCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_pending_evaluator="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_evaluator_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'evaluatorPolicySetFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_evaluator_root="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'evaluatorPolicySetRoot()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_pending_evaluator_1="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_pending_evaluator_2="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_pending_evaluator_3="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pre_approved_evaluator_1="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_approved_evaluator_2="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_approved_evaluator_3="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
for numeric_state in \
  pre_pending_result_activates_at \
  pre_approved_evaluator \
  pre_pending_evaluator \
  pre_pending_evaluator_1 \
  pre_pending_evaluator_2 \
  pre_pending_evaluator_3; do
  validate_safe_json_uint "$numeric_state" "${!numeric_state}"
done
for boolean_state in \
  pre_result_verifier_frozen \
  pre_evaluator_frozen \
  pre_approved_evaluator_1 \
  pre_approved_evaluator_2 \
  pre_approved_evaluator_3; do
  validate_bool "$boolean_state" "${!boolean_state}"
done

case "$DILIGENCE_RELEASE_PHASE" in
  1)
    if [ "$(normalize_address "$pre_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$(normalize_address "$pre_pending_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$pre_pending_result_activates_at" != "0" ] \
      || [ "$pre_result_verifier_frozen" != "false" ] \
      || [ "$pre_approved_evaluator" != "0" ] \
      || [ "$pre_pending_evaluator" != "0" ] \
      || [ "$pre_evaluator_frozen" != "false" ] \
      || [ "$(normalize_address "$pre_evaluator_root")" != "$ZERO_BYTES32" ] \
      || [ "$pre_pending_evaluator_1" != "0" ] \
      || [ "$pre_pending_evaluator_2" != "0" ] \
      || [ "$pre_pending_evaluator_3" != "0" ] \
      || [ "$pre_approved_evaluator_1" != "false" ] \
      || [ "$pre_approved_evaluator_2" != "false" ] \
      || [ "$pre_approved_evaluator_3" != "false" ]; then
      echo "Phase 1 requires an empty result-verifier and evaluator-policy pre-state." >&2
      exit 1
    fi
    ;;
  2)
    if [ "$(normalize_address "$pre_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$(normalize_address "$pre_pending_result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$pre_pending_result_activates_at" = "0" ] \
      || [ "$pre_result_verifier_frozen" != "false" ] \
      || [ "$pre_approved_evaluator" != "0" ] \
      || [ "$pre_pending_evaluator" != "3" ] \
      || [ "$pre_evaluator_frozen" != "false" ] \
      || [ "$(normalize_address "$pre_evaluator_root")" != "$ZERO_BYTES32" ] \
      || [ "$pre_pending_evaluator_1" = "0" ] \
      || [ "$pre_pending_evaluator_2" = "0" ] \
      || [ "$pre_pending_evaluator_3" = "0" ] \
      || [ "$pre_approved_evaluator_1" != "false" ] \
      || [ "$pre_approved_evaluator_2" != "false" ] \
      || [ "$pre_approved_evaluator_3" != "false" ]; then
      echo "Phase 2 requires the exact pending result-verifier and three-policy pre-state." >&2
      exit 1
    fi
    ;;
  3)
    if [ "$(normalize_address "$pre_result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$(normalize_address "$pre_pending_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$pre_pending_result_activates_at" != "0" ] \
      || [ "$pre_result_verifier_frozen" != "true" ] \
      || [ "$pre_approved_evaluator" != "3" ] \
      || [ "$pre_pending_evaluator" != "0" ] \
      || [ "$pre_evaluator_frozen" != "false" ] \
      || [ "$(normalize_address "$pre_evaluator_root")" != "$ZERO_BYTES32" ] \
      || [ "$pre_pending_evaluator_1" != "0" ] \
      || [ "$pre_pending_evaluator_2" != "0" ] \
      || [ "$pre_pending_evaluator_3" != "0" ] \
      || [ "$pre_approved_evaluator_1" != "true" ] \
      || [ "$pre_approved_evaluator_2" != "true" ] \
      || [ "$pre_approved_evaluator_3" != "true" ]; then
      echo "Phase 3 requires the exact frozen result-verifier and active three-policy pre-state." >&2
      exit 1
    fi
    ;;
esac

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "DEPLOYMENT_OPERATOR has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== DiligenceRoom release phase $DILIGENCE_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Keystore account:  dev"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "DiligenceRoom:     $DILIGENCE_ROOM_ADDRESS"
echo "Attestation QVL:   $DILIGENCE_ATTESTATION_VERIFIER"
echo "QVL policy hash:   $DILIGENCE_QVL_RELEASE_POLICY_HASH"
echo "Broadcast:         $BROADCAST"

cd "$CONTRACTS_DIR"
forge build --sizes
forge test --match-path test/ConfigureDiligenceRelease.t.sol

echo
echo "== Dry run =="
forge script script/ConfigureDiligenceRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR"

if [ "$BROADCAST" != "true" ]; then
  echo "Dry run complete; no chain state changed."
  exit 0
fi

operator_policy_acquire_release_ceremony_lock diligence_release

check_release_provenance
validate_existing_deployment_ledger
unlocked_signer="$(cast wallet address --account dev)"
if [ "$(normalize_address "$unlocked_signer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ]; then
  echo "The unlocked dev keystore does not match DEPLOYMENT_OPERATOR." >&2
  exit 1
fi

echo
echo "== Broadcast exact timelocked phase =="
forge script script/ConfigureDiligenceRelease.s.sol \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" \
  --sender "$DEPLOYMENT_OPERATOR" \
  --account dev \
  --broadcast \
  --slow

approved_compose="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedComposeCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
approved_tee="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedTeeIdentityCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_compose="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingComposeCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_tee="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingTeeIdentityCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
attestation_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'attestationVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
attestation_policy="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'attestationReleasePolicyHash()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_attestation_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingAttestationVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_attestation_policy="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingAttestationReleasePolicyHash()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_attestation_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingAttestationBindingActivatesAt()(uint64)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
attestation_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'attestationBindingFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
compose_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'composeAdditionsFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
tee_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'teeIdentityAdditionsFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_compose_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingComposeActivations(bytes32)(uint256)' "$DILIGENCE_COMPOSE_HASH" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_tee_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingTeeIdentityActivations(address)(uint256)' "$DILIGENCE_TEE_IDENTITY" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
active_tee_compose_hash="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'teeIdentityComposeHash(address)(bytes32)' "$DILIGENCE_TEE_IDENTITY" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_tee_compose_hash="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingTeeIdentityComposeHash(address)(bytes32)' "$DILIGENCE_TEE_IDENTITY" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
result_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'resultVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_result_verifier="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingResultVerifier()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_result_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingResultVerifierActivatesAt()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
result_verifier_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'resultVerifierFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
approved_evaluator="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicyCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_evaluator="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyCount()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
evaluator_frozen="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'evaluatorPolicySetFrozen()(bool)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
active_evaluator_root="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'evaluatorPolicySetRoot()(bytes32)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_evaluator_1="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_evaluator_2="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
pending_evaluator_3="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingEvaluatorPolicyActivations(bytes32)(uint256)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
approved_evaluator_1="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
approved_evaluator_2="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
approved_evaluator_3="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'approvedEvaluatorPolicies(bytes32)(bool)' "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
for numeric_state in \
  approved_compose \
  approved_tee \
  pending_compose \
  pending_tee \
  pending_attestation_activates_at \
  pending_compose_activates_at \
  pending_tee_activates_at \
  pending_result_activates_at \
  approved_evaluator \
  pending_evaluator \
  pending_evaluator_1 \
  pending_evaluator_2 \
  pending_evaluator_3; do
  validate_safe_json_uint "$numeric_state" "${!numeric_state}"
done
for boolean_state in \
  attestation_frozen \
  compose_frozen \
  tee_frozen \
  result_verifier_frozen \
  evaluator_frozen \
  approved_evaluator_1 \
  approved_evaluator_2 \
  approved_evaluator_3; do
  validate_bool "$boolean_state" "${!boolean_state}"
done

case "$DILIGENCE_RELEASE_PHASE" in
  1)
    expected="0 0 1 0"
    if [ "$(normalize_address "$result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$(normalize_address "$pending_result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$pending_result_activates_at" = "0" ] \
      || [ "$result_verifier_frozen" != "false" ] \
      || [ "$approved_evaluator" != "0" ] \
      || [ "$pending_evaluator" != "3" ] \
      || [ "$evaluator_frozen" != "false" ] \
      || [ "$(normalize_address "$active_evaluator_root")" != "$ZERO_BYTES32" ] \
      || [ "$pending_evaluator_1" = "0" ] \
      || [ "$pending_evaluator_2" = "0" ] \
      || [ "$pending_evaluator_3" = "0" ] \
      || [ "$approved_evaluator_1" != "false" ] \
      || [ "$approved_evaluator_2" != "false" ] \
      || [ "$approved_evaluator_3" != "false" ]; then
      echo "Phase 1 did not stage the exact result verifier and three evaluator policies." >&2
      exit 1
    fi
    ;;
  2)
    expected="1 0 0 1"
    if [ "$(normalize_address "$result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$(normalize_address "$pending_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$pending_result_activates_at" != "0" ] \
      || [ "$result_verifier_frozen" != "true" ] \
      || [ "$approved_evaluator" != "3" ] \
      || [ "$pending_evaluator" != "0" ] \
      || [ "$evaluator_frozen" != "false" ] \
      || [ "$(normalize_address "$active_evaluator_root")" != "$ZERO_BYTES32" ] \
      || [ "$pending_evaluator_1" != "0" ] \
      || [ "$pending_evaluator_2" != "0" ] \
      || [ "$pending_evaluator_3" != "0" ] \
      || [ "$approved_evaluator_1" != "true" ] \
      || [ "$approved_evaluator_2" != "true" ] \
      || [ "$approved_evaluator_3" != "true" ]; then
      echo "Phase 2 did not activate and freeze the exact result verifier or activate the three evaluator policies." >&2
      exit 1
    fi
    ;;
  3)
    expected="1 1 0 0"
    if [ "$(normalize_address "$result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$(normalize_address "$pending_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$pending_result_activates_at" != "0" ] \
      || [ "$result_verifier_frozen" != "true" ] \
      || [ "$approved_evaluator" != "3" ] \
      || [ "$pending_evaluator" != "0" ] \
      || [ "$evaluator_frozen" != "true" ] \
      || [ "$(normalize_address "$active_evaluator_root")" != "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT" ] \
      || [ "$pending_evaluator_1" != "0" ] \
      || [ "$pending_evaluator_2" != "0" ] \
      || [ "$pending_evaluator_3" != "0" ] \
      || [ "$approved_evaluator_1" != "true" ] \
      || [ "$approved_evaluator_2" != "true" ] \
      || [ "$approved_evaluator_3" != "true" ]; then
      echo "Phase 3 did not freeze the exact three-policy evaluator set root." >&2
      exit 1
    fi
    ;;
esac
actual="$approved_compose $approved_tee $pending_compose $pending_tee"
if [ "$actual" != "$expected" ]; then
  echo "Post-broadcast admission counts mismatch: expected $expected, received $actual." >&2
  exit 1
fi

if [ "$DILIGENCE_RELEASE_PHASE" = "1" ]; then
  if [ "$(normalize_address "$attestation_verifier")" != "$ZERO_ADDRESS" ] \
    || [ "$(normalize_address "$attestation_policy")" != "$ZERO_BYTES32" ] \
    || [ "$(normalize_address "$pending_attestation_verifier")" != "$(normalize_address "$DILIGENCE_ATTESTATION_VERIFIER")" ] \
    || [ "$(normalize_address "$pending_attestation_policy")" != "$(normalize_address "$DILIGENCE_QVL_RELEASE_POLICY_HASH")" ] \
    || [ "$pending_attestation_activates_at" = "0" ] \
    || [ "$attestation_frozen" != "false" ]; then
    echo "Phase 1 did not stage the exact Diligence QVL binding." >&2
    exit 1
  fi
else
  if [ "$(normalize_address "$attestation_verifier")" != "$(normalize_address "$DILIGENCE_ATTESTATION_VERIFIER")" ] \
    || [ "$(normalize_address "$attestation_policy")" != "$(normalize_address "$DILIGENCE_QVL_RELEASE_POLICY_HASH")" ] \
    || [ "$(normalize_address "$pending_attestation_verifier")" != "0x0000000000000000000000000000000000000000" ] \
    || [ "$(normalize_address "$pending_attestation_policy")" != "$ZERO_BYTES32" ] \
    || [ "$pending_attestation_activates_at" != "0" ] \
    || [ "$attestation_frozen" != "true" ]; then
    echo "The active frozen Diligence QVL binding does not match the release inputs." >&2
    exit 1
  fi
fi

if [ "$DILIGENCE_RELEASE_PHASE" = "3" ]; then
  if [ "$compose_frozen" != "true" ] || [ "$tee_frozen" != "true" ]; then
    echo "Diligence admission additions did not become permanently frozen." >&2
    exit 1
  fi
  if [ "$(normalize_address "$active_tee_compose_hash")" != "$(normalize_address "$DILIGENCE_COMPOSE_HASH")" ]; then
    echo "The final TEE identity compose binding does not match." >&2
    exit 1
  fi
fi

case "$DILIGENCE_RELEASE_PHASE" in
  1)
    expected_transaction_count=3
    expected_functions='["proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","proposeResultVerifier(address)","proposeAttestationBinding(address,bytes32)"]'
    ledger_status='deployed_diligence_compose_and_qvl_pending_timelock'
    ledger_policy_state='fail_closed_pending_compose_and_attestation_timelocks'
    ;;
  2)
    expected_transaction_count=6
    expected_functions='["activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","activateResultVerifier()","freezeResultVerifier()","activateAttestationBinding()","freezeAttestationBinding()","proposeTeeIdentity(address,bytes32)"]'
    ledger_status='deployed_diligence_tee_identity_pending_timelock'
    ledger_policy_state='fail_closed_pending_tee_identity_timelock'
    ;;
  3)
    expected_transaction_count=3
    expected_functions='["activateTeeIdentity(address)","freezeComposeAndEvaluatorPolicySets()","freezeTeeIdentityAdditions()"]'
    ledger_status='deployed_exact_diligence_release_policy_frozen_active'
    ledger_policy_state='exact_timelocked_diligence_release_policy_frozen_active'
    ;;
esac

RUN_PATH="$CONTRACTS_DIR/broadcast/ConfigureDiligenceRelease.s.sol/$CHAIN_ID/run-latest.json"
if [ ! -f "$RUN_PATH" ] || [ -L "$RUN_PATH" ]; then
  echo "Missing non-symlink Forge broadcast receipt at $RUN_PATH." >&2
  exit 1
fi
if ! release_tx="$(jq -er \
  --arg room "$DILIGENCE_ROOM_ADDRESS" \
  --arg operator "$DEPLOYMENT_OPERATOR" \
  --argjson expectedFunctions "$expected_functions" \
  --argjson expectedCount "$expected_transaction_count" \
  '
    .transactions
    | select(type == "array" and length == $expectedCount)
    | select(all(.[];
        .transactionType == "CALL"
        and (.hash | type) == "string"
        and (.hash | test("^0x[0-9a-fA-F]{64}$"))
        and (.hash | ascii_downcase) != ("0x" + ("0" * 64))
        and ((.transaction.to // "") | ascii_downcase) == ($room | ascii_downcase)
        and ((.transaction.from // "") | ascii_downcase) == ($operator | ascii_downcase)
        and .transaction.chainId == "0x14a34"
      ))
    | select(([.[].hash | ascii_downcase] | unique | length) == $expectedCount)
    | select([.[].function] == $expectedFunctions)
    | .[-1]
    | .hash
  ' "$RUN_PATH")"; then
  echo "Forge broadcast artifact does not contain the exact ordered Diligence phase transactions." >&2
  exit 1
fi
release_tx="$(normalize_address "$release_tx")"
validate_bytes32 release_tx "$release_tx"

receipt_status="$(cast receipt "$release_tx" status --rpc-url "$BASE_SEPOLIA_RPC_URL")"
receipt_hash="$(cast receipt "$release_tx" transactionHash --rpc-url "$BASE_SEPOLIA_RPC_URL")"
receipt_to="$(cast receipt "$release_tx" to --rpc-url "$BASE_SEPOLIA_RPC_URL")"
release_block="$(cast receipt "$release_tx" blockNumber --rpc-url "$BASE_SEPOLIA_RPC_URL")"
if [ "$receipt_status" != "1" ] && [ "$receipt_status" != "0x1" ]; then
  echo "The recorded Diligence phase transaction was not accepted on-chain." >&2
  exit 1
fi
if [ "$(normalize_address "$receipt_hash")" != "$release_tx" ] \
  || [ "$(normalize_address "$receipt_to")" != "$(normalize_address "$DILIGENCE_ROOM_ADDRESS")" ]; then
  echo "The accepted transaction receipt does not target the reviewed DiligenceRoom." >&2
  exit 1
fi
validate_safe_json_uint release_block "$release_block"
if [ "$release_block" = "0" ]; then
  echo "The accepted Diligence transaction must have a nonzero block number." >&2
  exit 1
fi
release_block_timestamp="$(cast block "$release_block" --field timestamp --rpc-url "$BASE_SEPOLIA_RPC_URL")"
validate_safe_json_uint release_block_timestamp "$release_block_timestamp"
if [ "$release_block_timestamp" = "0" ]; then
  echo "The accepted Diligence transaction block must have a nonzero timestamp." >&2
  exit 1
fi
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Recheck ledger identity after every on-chain post-state read. The filter also
# enforces phase ordering and repeats every identity check before emitting JSON.
validate_existing_deployment_ledger
ledger_blob_before="$(deployment_ledger_blob)"
manifest_dir="$(dirname "$MANIFEST_PATH")"
manifest_base="$(basename "$MANIFEST_PATH")"
DILIGENCE_MANIFEST_TEMP_PATH="$(mktemp "$manifest_dir/.${manifest_base}.diligence-release.XXXXXX")"

jq \
  --argjson chainId "$CHAIN_ID" \
  --arg roomAddress "$DILIGENCE_ROOM_ADDRESS" \
  --arg runtimeCodeHash "$live_code_hash" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --argjson phase "$DILIGENCE_RELEASE_PHASE" \
  --arg tx "$release_tx" \
  --argjson block "$release_block" \
  --argjson blockTimestamp "$release_block_timestamp" \
  --arg recordedAt "$recorded_at" \
  --arg status "$ledger_status" \
  --arg policyState "$ledger_policy_state" \
  --arg teeIdentity "$DILIGENCE_TEE_IDENTITY" \
  --arg composeHash "$DILIGENCE_COMPOSE_HASH" \
  --arg resultVerifier "$DILIGENCE_RESULT_VERIFIER" \
  --arg evaluatorPolicy1 "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1" \
  --arg evaluatorPolicy2 "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2" \
  --arg evaluatorPolicy3 "$DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3" \
  --arg evaluatorPolicySetRoot "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT" \
  --arg attestationVerifier "$DILIGENCE_ATTESTATION_VERIFIER" \
  --arg attestationPolicyHash "$DILIGENCE_QVL_RELEASE_POLICY_HASH" \
  --arg activeResultVerifier "$result_verifier" \
  --arg pendingResultVerifier "$pending_result_verifier" \
  --argjson pendingResultVerifierActivatesAt "$pending_result_activates_at" \
  --argjson resultVerifierFrozen "$result_verifier_frozen" \
  --arg activeAttestationVerifier "$attestation_verifier" \
  --arg activeAttestationPolicyHash "$attestation_policy" \
  --arg pendingAttestationVerifier "$pending_attestation_verifier" \
  --arg pendingAttestationPolicyHash "$pending_attestation_policy" \
  --argjson pendingAttestationActivatesAt "$pending_attestation_activates_at" \
  --argjson attestationFrozen "$attestation_frozen" \
  --argjson approvedComposeCount "$approved_compose" \
  --argjson approvedTeeCount "$approved_tee" \
  --argjson pendingComposeCount "$pending_compose" \
  --argjson pendingTeeCount "$pending_tee" \
  --argjson approvedEvaluatorPolicyCount "$approved_evaluator" \
  --argjson pendingEvaluatorPolicyCount "$pending_evaluator" \
  --argjson pendingComposeActivatesAt "$pending_compose_activates_at" \
  --argjson pendingTeeActivatesAt "$pending_tee_activates_at" \
  --argjson pendingEvaluatorPolicy1ActivatesAt "$pending_evaluator_1" \
  --argjson pendingEvaluatorPolicy2ActivatesAt "$pending_evaluator_2" \
  --argjson pendingEvaluatorPolicy3ActivatesAt "$pending_evaluator_3" \
  --arg activeTeeComposeHash "$active_tee_compose_hash" \
  --arg pendingTeeComposeHash "$pending_tee_compose_hash" \
  --arg activeEvaluatorPolicySetRoot "$active_evaluator_root" \
  --argjson composeFrozen "$compose_frozen" \
  --argjson teeFrozen "$tee_frozen" \
  --argjson evaluatorPolicySetFrozen "$evaluator_frozen" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" > "$DILIGENCE_MANIFEST_TEMP_PATH"

if ! jq -e 'type == "object"' "$DILIGENCE_MANIFEST_TEMP_PATH" >/dev/null; then
  echo "Diligence release ledger update did not produce one valid JSON object." >&2
  exit 1
fi
if [ "$(deployment_ledger_blob)" != "$ledger_blob_before" ]; then
  echo "Deployment ledger changed concurrently; refusing to overwrite it." >&2
  exit 1
fi
operator_policy_durably_replace_release_ledger "$DILIGENCE_MANIFEST_TEMP_PATH" "$MANIFEST_PATH"
rm -f -- "$DILIGENCE_MANIFEST_TEMP_PATH"
DILIGENCE_MANIFEST_TEMP_PATH=""
operator_policy_release_release_ceremony_lock

echo "Diligence release phase $DILIGENCE_RELEASE_PHASE completed with exact post-state and append-only ledger evidence."
