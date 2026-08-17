#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
MAX_SAFE_JSON_INTEGER=9007199254740991
ZERO_ADDRESS=0x0000000000000000000000000000000000000000
ZERO_BYTES32=0x0000000000000000000000000000000000000000000000000000000000000000
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-diligence-release-manifest.jq"
LEDGER_PREFLIGHT_FILTER="$CONTRACTS_DIR/scripts/preflight-diligence-release-ledger.jq"
GOVERNANCE_ACCEPTANCE_FILTER="$CONTRACTS_DIR/scripts/verify-diligence-governance-acceptance.jq"
DILIGENCE_MANIFEST_TEMP_PATH=""
DILIGENCE_ACCEPTANCE_TX_TEMP_PATH=""
DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH=""
DILIGENCE_ACCEPTANCE_EVIDENCE_TEMP_PATH=""

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# DEPLOYMENT_MANIFEST_PATH and RELEASE_CEREMONY_LEDGER_PATH are resolved only
# after .env; repository history is never a ceremony fallback.
# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

cleanup_diligence_release() {
  if [ -n "${DILIGENCE_MANIFEST_TEMP_PATH:-}" ]; then
    rm -f -- "$DILIGENCE_MANIFEST_TEMP_PATH"
    DILIGENCE_MANIFEST_TEMP_PATH=""
  fi
  for temp_name in \
    DILIGENCE_ACCEPTANCE_TX_TEMP_PATH \
    DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH \
    DILIGENCE_ACCEPTANCE_EVIDENCE_TEMP_PATH; do
    if [ -n "${!temp_name:-}" ]; then
      rm -f -- "${!temp_name}"
      printf -v "$temp_name" '%s' ""
    fi
  done
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

normalize_rpc_uint() {
  local value="$1"
  if [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]]; then
    cast to-dec "$value"
  else
    printf '%s\n' "$value"
  fi
}

address_topic() {
  local address
  address="$(normalize_address "$1")"
  printf '0x000000000000000000000000%s\n' "${address#0x}"
}

transaction_input_sha256() {
  local value="$1"
  if [[ ! "$value" =~ ^0x([0-9a-f][0-9a-f])+$ ]]; then
    echo "Transaction input must be nonempty canonical lowercase byte-aligned hex." >&2
    return 1
  fi
  printf '%s' "$value" | node -e '
    const fs = require("node:fs");
    const crypto = require("node:crypto");
    const value = fs.readFileSync(0, "utf8");
    if (!/^0x(?:[0-9a-f]{2})+$/.test(value)) process.exit(2);
    process.stdout.write(`sha256:${crypto.createHash("sha256")
      .update(Buffer.from(value.slice(2), "hex")).digest("hex")}`);
  '
}

deployment_ledger_blob() {
  git hash-object --no-filters "$MANIFEST_PATH"
}

validate_existing_deployment_ledger() {
  local require_writable="${1:-true}"
  if [ ! -f "$MANIFEST_PATH" ] || [ -L "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be an existing non-symlink regular file at $MANIFEST_PATH." >&2
    exit 1
  fi
  if [ ! -r "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be readable." >&2
    exit 1
  fi
  if [ "$require_writable" = "true" ] && [ ! -w "$MANIFEST_PATH" ]; then
    echo "Deployment ledger must be writable for evidence recording." >&2
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

preflight_diligence_release_ledger() {
  if ! jq \
    --argjson chainId "$CHAIN_ID" \
    --argjson phase "$DILIGENCE_RELEASE_PHASE" \
    --arg roomAddress "$DILIGENCE_ROOM_ADDRESS" \
    --arg runtimeCodeHash "$DILIGENCE_RUNTIME_CODE_HASH" \
    --arg sourceCommit "$RELEASE_SHA" \
    --arg deploymentIntentSha256Expected "$DEPLOYMENT_INTENT_SHA256" \
    --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --arg deploymentOperator "$DEPLOYMENT_OPERATOR" \
    --arg governanceController "$DILIGENCE_GOVERNANCE_CONTROLLER" \
    -f "$LEDGER_PREFLIGHT_FILTER" \
    "$MANIFEST_PATH" >/dev/null; then
    echo "Diligence release ledger failed exact immutable-lineage and phase-order preflight." >&2
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

for required in forge cast git jq node shasum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required." >&2
    exit 1
  fi
done

for name in \
  BASE_SEPOLIA_RPC_URL \
  DEPLOYMENT_OPERATOR \
  DILIGENCE_GOVERNANCE_CONTROLLER \
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
if [[ ! "$DILIGENCE_RELEASE_PHASE" =~ ^[1234]$ ]]; then
  echo "DILIGENCE_RELEASE_PHASE must be exactly 1, 2, 3, or 4." >&2
  exit 1
fi
governance_acceptance_record="${DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD:-false}"
validate_bool DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD "$governance_acceptance_record"
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  require_env DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE
  require_env DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH
  if [ "$BROADCAST" != "false" ]; then
    echo "Phase 4 never broadcasts: execute acceptDeveloper() through the reviewed governance controller, then verify its receipt here." >&2
    exit 1
  fi
  if [ "$DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE" != "eoa_direct_call" ] \
    && [ "$DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE" != "contract_event_and_state" ]; then
    echo "DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE must be eoa_direct_call or contract_event_and_state." >&2
    exit 1
  fi
  validate_bytes32 DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH "$DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH"
  DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH="$(normalize_address "$DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH")"
elif [ "$governance_acceptance_record" != "false" ] \
  || [ -n "${DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE:-}" ] \
  || [ -n "${DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH:-}" ]; then
  echo "Governance acceptance receipt inputs are valid only for DILIGENCE_RELEASE_PHASE=4." >&2
  exit 1
fi
for name in DEPLOYMENT_OPERATOR DILIGENCE_GOVERNANCE_CONTROLLER DILIGENCE_RESULT_VERIFIER DILIGENCE_ROOM_ADDRESS DILIGENCE_TEE_IDENTITY DILIGENCE_ATTESTATION_VERIFIER; do
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
operator_policy_assert_public_env contractEnv DILIGENCE_GOVERNANCE_CONTROLLER
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
  preflight_diligence_release_ledger
elif [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  # Phase 4 is an on-chain read-only verifier for a controller-executed
  # transaction. It always consumes the exact phase-3 ledger; writable access
  # is required only when the operator explicitly records the verified result.
  validate_existing_deployment_ledger false
  preflight_diligence_release_ledger
fi

if [ "$DILIGENCE_RELEASE_PHASE" != "4" ]; then
  if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
    echo "Diligence release governance is restricted to the Foundry keystore account named dev." >&2
    exit 1
  fi
  if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
    echo "Foundry keystore account dev was not found. Use /cast-wallet first." >&2
    exit 1
  fi
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
live_initial_developer="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'initialDeveloper()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
live_release_governance_controller="$(
  cast call "$DILIGENCE_ROOM_ADDRESS" 'releaseGovernanceController()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL"
)"
live_protocol_fee_recipient="$(
  cast call "$DILIGENCE_ROOM_ADDRESS" 'protocolFeeRecipient()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL"
)"
pre_pending_developer="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingDeveloper()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pre_pending_developer_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingDeveloperActivatesAt()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
developer_transfer_delay="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'DEVELOPER_TRANSFER_DELAY()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
validate_safe_json_uint pre_pending_developer_activates_at "$pre_pending_developer_activates_at"
validate_safe_json_uint developer_transfer_delay "$developer_transfer_delay"
if [ "$developer_transfer_delay" != "172800" ]; then
  echo "DiligenceRoom developer transfer delay is not the reviewed two-day governance delay." >&2
  exit 1
fi
if [ "$(normalize_address "$live_initial_developer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ] \
  || [ "$(normalize_address "$live_release_governance_controller")" != "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" ] \
  || [ "$(normalize_address "$live_protocol_fee_recipient")" != "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" ]; then
  echo "DiligenceRoom immutable operator, release controller, or fee recipient does not match reviewed authority." >&2
  exit 1
fi
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  if [ "$(normalize_address "$live_developer")" != "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" ] \
    || [ "$(normalize_address "$pre_pending_developer")" != "$ZERO_ADDRESS" ] \
    || [ "$pre_pending_developer_activates_at" != "0" ]; then
    echo "Phase 4 requires the controller-executed handoff to be complete before receipt verification." >&2
    exit 1
  fi
  phase_sender="$DILIGENCE_GOVERNANCE_CONTROLLER"
else
  if [ "$(normalize_address "$live_developer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ] \
    || [ "$(normalize_address "$pre_pending_developer")" != "$ZERO_ADDRESS" ] \
    || [ "$pre_pending_developer_activates_at" != "0" ]; then
    echo "Phases 1-3 require the deployment operator to control an unstaged DiligenceRoom." >&2
    exit 1
  fi
  phase_sender="$DEPLOYMENT_OPERATOR"
fi
phase_three_pending_developer_activates_at=0
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  if ! phase_three_pending_developer_activates_at="$(jq -er \
    --arg room "$DILIGENCE_ROOM_ADDRESS" \
    --arg runtime "$DILIGENCE_RUNTIME_CODE_HASH" \
    --arg source "$RELEASE_SHA" \
    --arg finalAuthority "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
    --arg operator "$DEPLOYMENT_OPERATOR" \
    --arg controller "$DILIGENCE_GOVERNANCE_CONTROLLER" \
    '
      select(.contracts.diligenceRoom.latestReleasePhase == 3)
      | select((.diligenceReleaseHistory | type) == "array"
          and (.diligenceReleaseHistory | length) == 3)
      | .diligenceReleaseHistory[-1]
      | select(.phase == 3
          and ((.diligenceRoomAddress // "") | ascii_downcase) == ($room | ascii_downcase)
          and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtime | ascii_downcase)
          and .sourceCommit == $source
          and .finalAuthoritySha256 == $finalAuthority
          and ((.deploymentOperator // "") | ascii_downcase) == ($operator | ascii_downcase)
          and ((.governanceController // "") | ascii_downcase) == ($controller | ascii_downcase)
          and ((.postState.developer // "") | ascii_downcase) == ($operator | ascii_downcase)
          and ((.postState.pendingDeveloper // "") | ascii_downcase) == ($controller | ascii_downcase)
          and .postState.developerTransferDelaySeconds == 172800)
      | .postState.pendingDeveloperActivatesAt
      | select(type == "number" and . > 0 and floor == .)
    ' "$MANIFEST_PATH")"; then
    echo "Phase 4 requires the exact append-only phase-3 pending governance evidence." >&2
    exit 1
  fi
  validate_safe_json_uint \
    phase_three_pending_developer_activates_at \
    "$phase_three_pending_developer_activates_at"
fi
for conflicting_role in \
  "$DEPLOYMENT_OPERATOR" \
  "$DILIGENCE_ROOM_ADDRESS" \
  "$DILIGENCE_RESULT_VERIFIER" \
  "$DILIGENCE_TEE_IDENTITY" \
  "$DILIGENCE_ATTESTATION_VERIFIER"; do
  if [ "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" = "$(normalize_address "$conflicting_role")" ]; then
    echo "DILIGENCE_GOVERNANCE_CONTROLLER must be distinct from every deployment, room, verifier, and TEE role." >&2
    exit 1
  fi
done
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
  4)
    if [ "$(normalize_address "$pre_result_verifier")" != "$(normalize_address "$DILIGENCE_RESULT_VERIFIER")" ] \
      || [ "$(normalize_address "$pre_pending_result_verifier")" != "$ZERO_ADDRESS" ] \
      || [ "$pre_pending_result_activates_at" != "0" ] \
      || [ "$pre_result_verifier_frozen" != "true" ] \
      || [ "$pre_approved_evaluator" != "3" ] \
      || [ "$pre_pending_evaluator" != "0" ] \
      || [ "$pre_evaluator_frozen" != "true" ] \
      || [ "$(normalize_address "$pre_evaluator_root")" != "$DILIGENCE_EVALUATOR_POLICY_SET_ROOT" ] \
      || [ "$pre_pending_evaluator_1" != "0" ] \
      || [ "$pre_pending_evaluator_2" != "0" ] \
      || [ "$pre_pending_evaluator_3" != "0" ] \
      || [ "$pre_approved_evaluator_1" != "true" ] \
      || [ "$pre_approved_evaluator_2" != "true" ] \
      || [ "$pre_approved_evaluator_3" != "true" ]; then
      echo "Phase 4 requires the exact closed phase-3 release policy and pending governance handoff." >&2
      exit 1
    fi
    ;;
esac

if [ "$BROADCAST" = "true" ]; then
  check_release_provenance
  if [ "$(cast balance "$phase_sender" --rpc-url "$BASE_SEPOLIA_RPC_URL")" = "0" ]; then
    echo "The phase signer has no Base Sepolia ETH for governance gas." >&2
    exit 1
  fi
fi

echo "== DiligenceRoom release phase $DILIGENCE_RELEASE_PHASE =="
echo "Chain ID:          $live_chain_id"
echo "Operator:          $DEPLOYMENT_OPERATOR"
echo "Governance target: $DILIGENCE_GOVERNANCE_CONTROLLER"
echo "DiligenceRoom:     $DILIGENCE_ROOM_ADDRESS"
echo "Attestation QVL:   $DILIGENCE_ATTESTATION_VERIFIER"
echo "QVL policy hash:   $DILIGENCE_QVL_RELEASE_POLICY_HASH"
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  echo "Acceptance mode:    $DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE"
  echo "Acceptance record:  $governance_acceptance_record"
  echo "On-chain action:    none (receipt and state verification only)"
  check_release_provenance
  if [ "$governance_acceptance_record" = "true" ]; then
    operator_policy_acquire_release_ceremony_lock diligence_release
    check_release_provenance
    validate_existing_deployment_ledger
    preflight_diligence_release_ledger
  fi
else
  echo "Keystore account:  dev"
  echo "Phase signer:      $phase_sender"
  echo "Broadcast:         $BROADCAST"

  cd "$CONTRACTS_DIR"
  forge build --sizes
  forge test --match-path test/ConfigureDiligenceRelease.t.sol

  echo
  echo "== Dry run =="
  forge script script/ConfigureDiligenceRelease.s.sol \
    --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    --sender "$phase_sender"

  if [ "$BROADCAST" != "true" ]; then
    echo "Dry run complete; no chain state changed."
    exit 0
  fi

  operator_policy_acquire_release_ceremony_lock diligence_release

  check_release_provenance
  validate_existing_deployment_ledger
  preflight_diligence_release_ledger
  unlocked_signer="$(cast wallet address --account dev)"
  if [ "$(normalize_address "$unlocked_signer")" != "$(normalize_address "$phase_sender")" ]; then
    echo "The unlocked dev keystore does not match the exact phase signer." >&2
    exit 1
  fi

  echo
  echo "== Broadcast exact timelocked phase =="
  forge script script/ConfigureDiligenceRelease.s.sol \
    --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    --sender "$phase_sender" \
    --account dev \
    --broadcast \
    --slow
fi

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
developer="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'developer()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_developer="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingDeveloper()(address)' --rpc-url "$BASE_SEPOLIA_RPC_URL")"
pending_developer_activates_at="$(cast call "$DILIGENCE_ROOM_ADDRESS" 'pendingDeveloperActivatesAt()(uint256)' --rpc-url "$BASE_SEPOLIA_RPC_URL" | awk '{print $1}')"
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
  pending_evaluator_3 \
  pending_developer_activates_at; do
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
  4)
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
      echo "Phase 4 did not preserve the exact closed diligence release policy." >&2
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

if [ "$DILIGENCE_RELEASE_PHASE" = "3" ] || [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
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
  1|2)
    if [ "$(normalize_address "$developer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ] \
      || [ "$(normalize_address "$pending_developer")" != "$ZERO_ADDRESS" ] \
      || [ "$pending_developer_activates_at" != "0" ]; then
      echo "Phases 1-2 must leave developer governance entirely unstaged." >&2
      exit 1
    fi
    ;;
  3)
    if [ "$(normalize_address "$developer")" != "$(normalize_address "$DEPLOYMENT_OPERATOR")" ] \
      || [ "$(normalize_address "$pending_developer")" != "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" ] \
      || [ "$pending_developer_activates_at" = "0" ]; then
      echo "Phase 3 did not stage the exact delayed governance controller." >&2
      exit 1
    fi
    ;;
  4)
    if [ "$(normalize_address "$developer")" != "$(normalize_address "$DILIGENCE_GOVERNANCE_CONTROLLER")" ] \
      || [ "$(normalize_address "$pending_developer")" != "$ZERO_ADDRESS" ] \
      || [ "$pending_developer_activates_at" != "0" ]; then
      echo "Phase 4 did not complete the exact governance-controller handoff." >&2
      exit 1
    fi
    ;;
esac

case "$DILIGENCE_RELEASE_PHASE" in
  1)
    expected_transaction_count=3
    expected_functions='["proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","proposeResultVerifier(address)","proposeAttestationBinding(address,bytes32)"]'
    ledger_status='deployed_diligence_compose_and_qvl_pending_timelock'
    ledger_policy_state='fail_closed_pending_compose_and_attestation_timelocks'
    governance_acceptance_evidence_mode=not_applicable
    governance_acceptance_evidence_claim=operator_forge_broadcast_receipt
    ;;
  2)
    expected_transaction_count=6
    expected_functions='["activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])","activateResultVerifier()","freezeResultVerifier()","activateAttestationBinding()","freezeAttestationBinding()","proposeTeeIdentity(address,bytes32)"]'
    ledger_status='deployed_diligence_tee_identity_pending_timelock'
    ledger_policy_state='fail_closed_pending_tee_identity_timelock'
    governance_acceptance_evidence_mode=not_applicable
    governance_acceptance_evidence_claim=operator_forge_broadcast_receipt
    ;;
  3)
    expected_transaction_count=4
    expected_functions='["activateTeeIdentity(address)","freezeComposeAndEvaluatorPolicySets()","freezeTeeIdentityAdditions()","proposeDeveloper(address)"]'
    ledger_status='deployed_exact_diligence_release_policy_frozen_pending_governance_timelock'
    ledger_policy_state='fail_closed_exact_policy_pending_governance_acceptance'
    governance_acceptance_evidence_mode=not_applicable
    governance_acceptance_evidence_claim=operator_forge_broadcast_receipt
    ;;
  4)
    ledger_status='deployed_exact_diligence_release_policy_frozen_active'
    ledger_policy_state='exact_timelocked_diligence_release_policy_frozen_active'
    governance_acceptance_evidence_mode="$DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE"
    ;;
esac

finalized_through_block=0
operator_transactions='[]'
operator_transactions_sha256_json=null
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ]; then
  release_tx="$DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH"
  DILIGENCE_ACCEPTANCE_TX_TEMP_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-diligence-acceptance-tx.XXXXXX")"
  DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-diligence-acceptance-receipt.XXXXXX")"
  DILIGENCE_ACCEPTANCE_EVIDENCE_TEMP_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-diligence-acceptance-evidence.XXXXXX")"
  cast tx "$release_tx" --json --rpc-url "$BASE_SEPOLIA_RPC_URL" > "$DILIGENCE_ACCEPTANCE_TX_TEMP_PATH"
  cast receipt "$release_tx" --json --rpc-url "$BASE_SEPOLIA_RPC_URL" > "$DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH"

  controller_code="$(cast code "$DILIGENCE_GOVERNANCE_CONTROLLER" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  if [ "$DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE" = "eoa_direct_call" ]; then
    if [ "$(normalize_address "$controller_code")" != "0x" ]; then
      echo "EOA acceptance mode requires the governance controller to have no live runtime code." >&2
      exit 1
    fi
  elif [[ ! "$controller_code" =~ ^0x[0-9a-fA-F]{2,}$ ]]; then
    echo "Contract acceptance mode requires live runtime code at the governance controller." >&2
    exit 1
  fi

  developer_transferred_topic="$(cast keccak 'DeveloperTransferred(address,address)')"
  accept_developer_selector="$(cast sig 'acceptDeveloper()')"
  operator_topic="$(address_topic "$DEPLOYMENT_OPERATOR")"
  controller_topic="$(address_topic "$DILIGENCE_GOVERNANCE_CONTROLLER")"
  if ! jq -n \
    --slurpfile transaction "$DILIGENCE_ACCEPTANCE_TX_TEMP_PATH" \
    --slurpfile receipt "$DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH" \
    '{transaction: $transaction[0], receipt: $receipt[0]}' \
    | jq \
      --arg mode "$DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE" \
      --arg txHash "$release_tx" \
      --arg room "$DILIGENCE_ROOM_ADDRESS" \
      --arg operator "$DEPLOYMENT_OPERATOR" \
      --arg controller "$DILIGENCE_GOVERNANCE_CONTROLLER" \
      --arg developerTransferredTopic "$developer_transferred_topic" \
      --arg operatorTopic "$operator_topic" \
      --arg controllerTopic "$controller_topic" \
      --arg acceptDeveloperSelector "$accept_developer_selector" \
      -f "$GOVERNANCE_ACCEPTANCE_FILTER" \
      > "$DILIGENCE_ACCEPTANCE_EVIDENCE_TEMP_PATH"; then
    echo "Governance acceptance receipt failed exact mode-specific event and transaction verification." >&2
    exit 1
  fi
  governance_acceptance_evidence_claim="$(jq -er '.claim' "$DILIGENCE_ACCEPTANCE_EVIDENCE_TEMP_PATH")"
  release_block_raw="$(jq -er '.blockNumber' "$DILIGENCE_ACCEPTANCE_RECEIPT_TEMP_PATH")"
  release_block="$(normalize_rpc_uint "$release_block_raw")"
  finalized_through_block_raw="$(cast block finalized --field number --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  finalized_through_block="$(normalize_rpc_uint "$finalized_through_block_raw")"
  validate_safe_json_uint finalized_through_block "$finalized_through_block"
  if [ "$finalized_through_block" = "0" ] || [ "$release_block" -gt "$finalized_through_block" ]; then
    echo "Governance acceptance transaction is not included at or below the finalized Base Sepolia block." >&2
    exit 1
  fi
else
  RUN_PATH="$CONTRACTS_DIR/broadcast/ConfigureDiligenceRelease.s.sol/$CHAIN_ID/run-latest.json"
  if [ ! -f "$RUN_PATH" ] || [ -L "$RUN_PATH" ]; then
    echo "Missing non-symlink Forge broadcast receipt at $RUN_PATH." >&2
    exit 1
  fi
  if ! jq -e \
    --arg room "$DILIGENCE_ROOM_ADDRESS" \
    --arg phaseSigner "$phase_sender" \
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
          and ((.transaction.from // "") | ascii_downcase) == ($phaseSigner | ascii_downcase)
          and .transaction.chainId == "0x14a34"
        ))
      | select(([.[].hash | ascii_downcase] | unique | length) == $expectedCount)
      | select([.[].function] == $expectedFunctions)
    ' "$RUN_PATH" >/dev/null; then
    echo "Forge broadcast artifact does not contain the exact ordered Diligence phase transactions." >&2
    exit 1
  fi

  for ((sequence = 0; sequence < expected_transaction_count; sequence++)); do
    artifact_entry="$(jq -cer --argjson sequence "$sequence" '.transactions[$sequence]' "$RUN_PATH")"
    artifact_hash="$(jq -er '.hash | ascii_downcase' <<<"$artifact_entry")"
    artifact_function="$(jq -er '.function' <<<"$artifact_entry")"
    artifact_from="$(jq -er '.transaction.from | ascii_downcase' <<<"$artifact_entry")"
    artifact_to="$(jq -er '.transaction.to | ascii_downcase' <<<"$artifact_entry")"
    artifact_input="$(jq -er '(.transaction.input // .transaction.data) | ascii_downcase' <<<"$artifact_entry")"
    if [[ ! "$artifact_input" =~ ^0x([0-9a-f][0-9a-f])+$ ]]; then
      echo "Forge broadcast artifact contains malformed transaction input at sequence $sequence." >&2
      exit 1
    fi

    transaction_json="$(cast tx "$artifact_hash" --json --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    receipt_json="$(cast receipt "$artifact_hash" --json --rpc-url "$BASE_SEPOLIA_RPC_URL")"
    transaction_hash="$(jq -er '.hash | ascii_downcase' <<<"$transaction_json")"
    transaction_from="$(jq -er '.from | ascii_downcase' <<<"$transaction_json")"
    transaction_to="$(jq -er '.to | ascii_downcase' <<<"$transaction_json")"
    transaction_input="$(jq -er '(.input // .data) | ascii_downcase' <<<"$transaction_json")"
    transaction_chain_id="$(normalize_rpc_uint "$(jq -er '.chainId' <<<"$transaction_json")")"
    transaction_block="$(normalize_rpc_uint "$(jq -er '.blockNumber' <<<"$transaction_json")")"
    transaction_block_hash="$(jq -er '.blockHash | ascii_downcase' <<<"$transaction_json")"
    receipt_hash="$(jq -er '.transactionHash | ascii_downcase' <<<"$receipt_json")"
    receipt_from="$(jq -er '.from | ascii_downcase' <<<"$receipt_json")"
    receipt_to="$(jq -er '.to | ascii_downcase' <<<"$receipt_json")"
    receipt_block="$(normalize_rpc_uint "$(jq -er '.blockNumber' <<<"$receipt_json")")"
    receipt_block_hash="$(jq -er '.blockHash | ascii_downcase' <<<"$receipt_json")"

    if ! jq -e '(.status == "0x1") or (.status == "0x01") or (.status == "1") or (.status == 1)' \
      <<<"$receipt_json" >/dev/null; then
      echo "Diligence phase transaction $sequence does not have a successful receipt." >&2
      exit 1
    fi
    validate_safe_json_uint "transaction_block_$sequence" "$transaction_block"
    validate_safe_json_uint "receipt_block_$sequence" "$receipt_block"
    if [ "$transaction_chain_id" != "$CHAIN_ID" ] \
      || [ "$transaction_hash" != "$artifact_hash" ] \
      || [ "$receipt_hash" != "$artifact_hash" ] \
      || [ "$transaction_from" != "$artifact_from" ] \
      || [ "$receipt_from" != "$artifact_from" ] \
      || [ "$transaction_to" != "$artifact_to" ] \
      || [ "$receipt_to" != "$artifact_to" ] \
      || [ "$artifact_from" != "$(normalize_address "$phase_sender")" ] \
      || [ "$artifact_to" != "$(normalize_address "$DILIGENCE_ROOM_ADDRESS")" ] \
      || [ "$transaction_input" != "$artifact_input" ] \
      || [ "$transaction_block" != "$receipt_block" ] \
      || [ "$transaction_block_hash" != "$receipt_block_hash" ] \
      || [ "$receipt_block" = "0" ]; then
      echo "Diligence phase transaction $sequence artifact, RPC transaction, and receipt are not exactly linked." >&2
      exit 1
    fi
    validate_bytes32 "transaction_hash_$sequence" "$transaction_hash"
    validate_bytes32 "transaction_block_hash_$sequence" "$transaction_block_hash"
    calldata_sha256="$(transaction_input_sha256 "$transaction_input")"
    validate_sha256_digest "calldata_sha256_$sequence" "$calldata_sha256"

    operator_transactions="$(jq -cn \
      --argjson transactions "$operator_transactions" \
      --argjson sequence "$sequence" \
      --arg transactionHash "$transaction_hash" \
      --arg sender "$transaction_from" \
      --arg target "$transaction_to" \
      --arg functionSignature "$artifact_function" \
      --arg calldataSha256 "$calldata_sha256" \
      --argjson blockNumber "$receipt_block" \
      --arg blockHash "$receipt_block_hash" '
        $transactions + [{
          sequence: $sequence,
          transactionHash: $transactionHash,
          sender: $sender,
          target: $target,
          functionSignature: $functionSignature,
          calldataSha256: $calldataSha256,
          receiptStatus: "success",
          blockNumber: $blockNumber,
          blockHash: $blockHash
        }]
      ')"
  done
  release_tx="$(jq -er '.[-1].transactionHash' <<<"$operator_transactions")"
  release_block="$(jq -er '.[-1].blockNumber' <<<"$operator_transactions")"
  operator_transactions_sha256="sha256:$(jq -cS . <<<"$operator_transactions" \
    | shasum -a 256 | awk '{print $1}')"
  validate_sha256_digest operator_transactions_sha256 "$operator_transactions_sha256"
  operator_transactions_sha256_json="$(jq -cn --arg value "$operator_transactions_sha256" '$value')"
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
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ] \
  && [ "$release_block_timestamp" -lt "$phase_three_pending_developer_activates_at" ]; then
  echo "Governance acceptance transaction predates the exact phase-3 activation deadline." >&2
  exit 1
fi
if [ "$DILIGENCE_RELEASE_PHASE" = "4" ] \
  && [ "$governance_acceptance_record" != "true" ]; then
  echo "Phase 4 receipt and live state verified; no chain action or ledger write was performed."
  exit 0
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
  --arg deploymentIntentSha256Expected "$DEPLOYMENT_INTENT_SHA256" \
  --arg reviewEnvelopeSha256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256" \
  --arg finalAuthoritySha256 "$OPERATOR_POLICY_FINAL_AUTHORITY_SHA256" \
  --argjson phase "$DILIGENCE_RELEASE_PHASE" \
  --arg tx "$release_tx" \
  --argjson block "$release_block" \
  --argjson blockTimestamp "$release_block_timestamp" \
  --arg recordedAt "$recorded_at" \
  --arg status "$ledger_status" \
  --arg policyState "$ledger_policy_state" \
  --arg governanceAcceptanceEvidenceMode "$governance_acceptance_evidence_mode" \
  --arg governanceAcceptanceEvidenceClaim "$governance_acceptance_evidence_claim" \
  --argjson finalizedThroughBlock "$finalized_through_block" \
  --argjson operatorTransactions "$operator_transactions" \
  --argjson operatorTransactionsSha256 "$operator_transactions_sha256_json" \
  --arg deploymentOperator "$DEPLOYMENT_OPERATOR" \
  --arg governanceController "$DILIGENCE_GOVERNANCE_CONTROLLER" \
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
  --arg activeDeveloper "$developer" \
  --arg pendingDeveloper "$pending_developer" \
  --argjson pendingDeveloperActivatesAt "$pending_developer_activates_at" \
  --argjson developerTransferDelaySeconds "$developer_transfer_delay" \
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
