#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/⚙️/tinker-delegate/contracts"
CHAIN_ID=84532
ACCOUNT=dev
ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER=130
ROYALTY_RELEASE_BALANCE_SAFETY_MULTIPLIER=2
PHASE_PLAN="$CONTRACTS_DIR/scripts/royalty-release-phase-plan.mjs"
FINALITY_HELPER="$CONTRACTS_DIR/scripts/royalty-release-finality.mjs"
LEDGER_BINDING_HELPER="$CONTRACTS_DIR/scripts/royalty-release-ledger-binding.mjs"
MANIFEST_FILTER="$CONTRACTS_DIR/scripts/update-royalty-release-manifest.jq"
FORGE_TARGET="script/ConfigureRoyaltyRelease.s.sol:ConfigureRoyaltyReleaseScript"
PLAN_RECEIPT_PATH=""
SECOND_PLAN_RECEIPT_PATH=""
CLASSIFICATION_PATH=""
DRY_RUN_RECEIPT_PATH=""
DRY_RUN_OUTPUT_PATH=""
LEDGER_REPLAY_PATH=""
PHASE_ONE_BINDING_PATH=""
FINALITY_PATH=""
LEDGER_CANDIDATE_PATH=""
LOCK_MAY_BE_RELEASED=false

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/.env"
  set +a
fi

# Ceremony paths are resolved only after the operator's untracked environment.
# Repository history is never used as a post-authority ledger fallback.
# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/release-ceremony-paths.sh"
operator_policy_resolve_release_ceremony_paths

# shellcheck disable=SC1091
. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"

cleanup_royalty_release() {
  rm -f -- \
    "${PLAN_RECEIPT_PATH:-}" \
    "${SECOND_PLAN_RECEIPT_PATH:-}" \
    "${CLASSIFICATION_PATH:-}" \
    "${DRY_RUN_RECEIPT_PATH:-}" \
    "${DRY_RUN_OUTPUT_PATH:-}" \
    "${LEDGER_REPLAY_PATH:-}" \
    "${PHASE_ONE_BINDING_PATH:-}" \
    "${FINALITY_PATH:-}" \
    "${LEDGER_CANDIDATE_PATH:-}"
  if [ "$LOCK_MAY_BE_RELEASED" = "true" ]; then
    operator_policy_release_release_ceremony_lock
  elif [ -n "${RELEASE_CEREMONY_LOCK_OWNER_TOKEN:-}" ]; then
    echo "Royalty release may have touched chain state; the release lock remains fail closed for explicit reviewed recovery." >&2
  fi
  cleanup_operator_policy_projection
}

trap cleanup_royalty_release EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "$*" >&2
  exit 1
}

for raw_key_name in \
  PRIVATE_KEY \
  DEPLOYER_PRIVATE_KEY \
  FOUNDRY_PRIVATE_KEY \
  ETH_PRIVATE_KEY \
  ROYALTY_PRIVATE_KEY; do
  if [ -n "${!raw_key_name:-}" ]; then
    fail "$raw_key_name is forbidden for Royalty release; use only the encrypted Foundry account dev."
  fi
done

require_env() {
  local name="$1"
  [ -n "${!name:-}" ] || fail "$name is required; Royalty release authority is never inferred."
}

require_absolute_file() {
  local name="$1" value
  value="${!name:-}"
  require_env "$name"
  if [[ "$value" != /* ]] || [ ! -f "$value" ] || [ -L "$value" ] || [ ! -r "$value" ]; then
    fail "$name must be an absolute, readable, non-symlink regular file."
  fi
}

require_external_directory() {
  local name="$1" value real
  value="${!name:-}"
  require_env "$name"
  if [[ "$value" != /* ]] || [ ! -d "$value" ] || [ -L "$value" ] || [ ! -r "$value" ] || [ ! -w "$value" ]; then
    fail "$name must be an absolute, readable, writable, non-symlink directory."
  fi
  real="$(cd "$value" && pwd -P)"
  if [ "$real" != "$value" ] || [[ "$real" == "$ROOT_DIR" || "$real" == "$ROOT_DIR/"* ]]; then
    fail "$name must be canonical and outside the reviewed repository."
  fi
}

validate_bool() {
  local name="$1" value="$2"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    fail "$name must be exactly true or false."
  fi
}

sha256_file() {
  printf 'sha256:%s' "$(shasum -a 256 "$1" | awk '{print $1}')"
}

derive_dry_run_gas_requirement() {
  local output_path="$1"
  local estimate_json
  local estimated_gas_units
  local estimated_gas_price_gwei
  local estimated_amount_eth
  if [ ! -f "$output_path" ] || [ -L "$output_path" ] \
    || [ "$(wc -c < "$output_path" | tr -d '[:space:]')" -gt 2097152 ]; then
    fail "Royalty Forge dry-run output is missing, unsafe, or exceeds the 2 MiB bound."
  fi
  if ! estimate_json="$(jq -sc '
    [ .[] | select(
        type == "object"
        and keys == [
          "chain",
          "estimated_amount_required",
          "estimated_gas_price",
          "estimated_total_gas_used",
          "token_symbol"
        ]
      ) ] as $estimates
    | if ($estimates | length) == 1
        and $estimates[0].chain == 84532
        and ($estimates[0].estimated_total_gas_used | type == "number")
        and ($estimates[0].estimated_total_gas_used | floor)
          == $estimates[0].estimated_total_gas_used
        and $estimates[0].estimated_total_gas_used > 0
        and $estimates[0].estimated_total_gas_used <= 9007199254740991
        and ($estimates[0].estimated_gas_price
          | type == "string" and test("^(0|[1-9][0-9]*)(\\.[0-9]{1,9})?$"))
        and ($estimates[0].estimated_amount_required
          | type == "string" and test("^(0|[1-9][0-9]*)(\\.[0-9]{1,18})?$"))
        and $estimates[0].token_symbol == "ETH"
      then $estimates[0]
      else error("missing or malformed unique Base Sepolia gas estimate")
      end
  ' "$output_path")"; then
    fail "Forge did not emit one canonical Base Sepolia Royalty gas estimate."
  fi
  estimated_gas_units="$(jq -r '.estimated_total_gas_used' <<<"$estimate_json")"
  estimated_gas_price_gwei="$(jq -r '.estimated_gas_price' <<<"$estimate_json")"
  estimated_amount_eth="$(jq -r '.estimated_amount_required' <<<"$estimate_json")"
  node --input-type=module - \
    "$estimated_gas_units" \
    "$estimated_gas_price_gwei" \
    "$estimated_amount_eth" \
    "$ROYALTY_RELEASE_BALANCE_SAFETY_MULTIPLIER" <<'NODE'
const [gasText, priceText, amountText, safetyText] = process.argv.slice(2);
function decimalUnits(value, decimals) {
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(value);
  if (!match || (match[2] || "").length > decimals) throw new Error("invalid decimal units");
  const fraction = (match[2] || "").padEnd(decimals, "0");
  return BigInt(match[1]) * (10n ** BigInt(decimals)) + BigInt(fraction || "0");
}
try {
  if (!/^[1-9][0-9]*$/.test(gasText) || !/^[1-9][0-9]*$/.test(safetyText)) {
    throw new Error("invalid gas projection integers");
  }
  const gas = BigInt(gasText);
  const gasPriceWei = decimalUnits(priceText, 9);
  const forgeAmountWei = decimalUnits(amountText, 18);
  if (gasPriceWei === 0n || gas * gasPriceWei !== forgeAmountWei) {
    throw new Error("Forge gas projection is internally inconsistent");
  }
  const requiredBalanceWei = forgeAmountWei * BigInt(safetyText);
  if (requiredBalanceWei === 0n) throw new Error("gas requirement is zero");
  process.stdout.write(`${requiredBalanceWei}\t${priceText}\t${forgeAmountWei}\n`);
} catch {
  process.exitCode = 1;
}
NODE
}

require_royalty_balance_at_least() {
  local actual_wei="$1"
  local required_wei="$2"
  if ! node --input-type=module - "$actual_wei" "$required_wei" <<'NODE'
const [actual, required] = process.argv.slice(2);
if (!/^(0|[1-9][0-9]*)$/.test(actual)
  || !/^[1-9][0-9]*$/.test(required)
  || BigInt(actual) < BigInt(required)) process.exitCode = 1;
NODE
  then
    fail "Royalty owner balance does not cover the exact classified dry-run gas requirement plus the code-owned safety margin."
  fi
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

assert_optional_env_matches() {
  local name="$1" expected="$2" current="${!name:-}"
  if [ -n "$current" ] && [ "$(lower "$current")" != "$(lower "$expected")" ]; then
    fail "$name differs from the exact reviewed Royalty phase plan."
  fi
  printf -v "$name" '%s' "$expected"
  export "$name"
}

for name in \
  DEPLOYMENT_INTENT_PATH \
  ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH \
  ROYALTY_RELEASE_PHASE_PLAN_PATH \
  ROYALTY_RELEASE_REVIEWER_GENESIS_PATH \
  ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH \
  ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH \
  ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH; do
  require_absolute_file "$name"
done

for path in "$PHASE_PLAN" "$FINALITY_HELPER" "$LEDGER_BINDING_HELPER" "$MANIFEST_FILTER"; do
  [ -f "$path" ] && [ ! -L "$path" ] || fail "Missing or unsafe Royalty release verifier: $path"
done

require_env TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256
if [[ ! "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || [[ "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" =~ ^sha256:0{64}$ ]]; then
  fail "TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256 must be a nonzero lowercase digest."
fi

BROADCAST="${BROADCAST:-false}"
validate_bool BROADCAST "$BROADCAST"
ROYALTY_RELEASE_OPERATION="${ROYALTY_RELEASE_OPERATION:-execute}"
case "$ROYALTY_RELEASE_OPERATION" in
  execute|inspect|reconcile) ;;
  *) fail "ROYALTY_RELEASE_OPERATION must be exactly execute, inspect, or reconcile." ;;
esac
if [ "${FOUNDRY_KEYSTORE_ACCOUNT:-dev}" != "$ACCOUNT" ]; then
  fail "Royalty release is restricted to the Foundry keystore account named dev."
fi

# This is the first authority-bearing executable invocation. It must complete
# before chain reads, keystore inspection, compilation, or Forge simulation.
PLAN_RECEIPT_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-phase-plan.XXXXXX")"
chmod 600 "$PLAN_RECEIPT_PATH"
if ! node "$PHASE_PLAN" verify \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH" \
  --fresh-deployment-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH" \
  --reviewer-genesis "$ROYALTY_RELEASE_REVIEWER_GENESIS_PATH" \
  --reviewer-genesis-acceptance "$ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH" \
  --reviewer-current-status "$ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH" \
  --reviewer-status-history "$ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH" \
  --royalty-release-prescription "$ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH" \
  --tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" \
  --plan "$ROYALTY_RELEASE_PHASE_PLAN_PATH" >"$PLAN_RECEIPT_PATH"; then
  fail "Royalty phase-plan verification failed before all wallet, RPC, and Forge access."
fi

if ! jq -e '
  keys == [
    "authority",
    "chain_id",
    "deployment_intent_sha256",
    "execution_mode",
    "expires_at",
    "fresh_contract_deployment_receipt_sha256",
    "phase",
    "phase_one_prerequisite",
    "phase_two_recovery",
    "plan_sha256",
    "release_sha",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "royalty_release_prescriptive_authority_sha256",
    "schema",
    "signing_payload_sha256",
    "status",
    "transactions",
    "truth_status",
    "valid_after",
    "verified_signers"
  ]
  and .schema == "dnai.royalty-release-phase-plan-verification-receipt.v2"
  and .status == "valid_current_two_reviewer_exact_royalty_phase_plan"
  and .truth_status == "reviewer_signatures_and_exact_plan_validated_not_onchain_execution_finality_or_tdx_evidence"
  and .chain_id == 84532
  and (.release_sha | test("^[0-9a-f]{40}$") and . != ("0" * 40))
  and (.plan_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.deployment_intent_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.fresh_contract_deployment_receipt_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.royalty_release_prescriptive_authority_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.phase == 1 or .phase == 2)
  and (
    if .phase == 1 then
      .execution_mode == "stage_authority"
      and .phase_one_prerequisite == null
      and .phase_two_recovery == null
      and (.transactions | length) == 1
    elif .execution_mode == "activate_and_unpause" then
      (.phase_one_prerequisite | type) == "object"
      and .phase_two_recovery == null
      and (.transactions | length) == 2
    else
      .execution_mode == "recover_reverted_unpause"
      and (.phase_one_prerequisite | type) == "object"
      and (.phase_two_recovery | type) == "object"
      and (.transactions | length) == 1
    end
  )
  and ([.transactions[] |
    .signer_address == $root.authority.owner
    and .to == $root.authority.distributor_address
    and .value_wei == "0"
    and (.nonce | test("^(0|[1-9][0-9]*)$"))
    and (.calldata | test("^0x([0-9a-f]{2})+$"))
    and (.calldata_sha256 | test("^sha256:[0-9a-f]{64}$"))
  ] | all)
  | . as $ok
  | $ok
' --argjson root "$(jq -c '.' "$PLAN_RECEIPT_PATH")" "$PLAN_RECEIPT_PATH" >/dev/null; then
  fail "Royalty phase-plan verifier returned an unexpected receipt."
fi

RELEASE_SHA="$(jq -r '.release_sha' "$PLAN_RECEIPT_PATH")"
DEPLOYMENT_INTENT_SHA256="$(jq -r '.deployment_intent_sha256' "$PLAN_RECEIPT_PATH")"
ROYALTY_RELEASE_PLAN_SHA256="$(jq -r '.plan_sha256' "$PLAN_RECEIPT_PATH")"
ROYALTY_RELEASE_PHASE="$(jq -r '.phase' "$PLAN_RECEIPT_PATH")"
ROYALTY_RELEASE_EXECUTION_MODE="$(jq -r '.execution_mode' "$PLAN_RECEIPT_PATH")"
export RELEASE_SHA DEPLOYMENT_INTENT_SHA256
export ROYALTY_RELEASE_PLAN_SHA256 ROYALTY_RELEASE_PHASE ROYALTY_RELEASE_EXECUTION_MODE

assert_optional_env_matches DEPLOYMENT_OPERATOR \
  "$(jq -r '.authority.owner' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches ROYALTY_DISTRIBUTOR_ADDRESS \
  "$(jq -r '.authority.distributor_address' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH \
  "$(jq -r '.authority.distributor_runtime_code_hash' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches ROYALTY_SETTLEMENT_VERIFIER \
  "$(jq -r '.authority.settlement_verifier' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches ROYALTY_QVL_VERIFIER \
  "$(jq -r '.authority.qvl_verifier' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches EXECUTION_POLICY_ANCHOR_ADDRESS \
  "$(jq -r '.authority.anchor_address' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH \
  "$(jq -r '.authority.anchor_runtime_code_hash' "$PLAN_RECEIPT_PATH")"
assert_optional_env_matches EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT \
  "$(jq -r '.authority.anchor_writer_release_commitment' "$PLAN_RECEIPT_PATH")"

echo "== Reviewed Royalty release plan =="
echo "Release:         $RELEASE_SHA"
echo "Plan:            $ROYALTY_RELEASE_PLAN_SHA256"
echo "Phase:           $ROYALTY_RELEASE_PHASE"
echo "Execution mode:  $ROYALTY_RELEASE_EXECUTION_MODE"
echo "Distributor:     $ROYALTY_DISTRIBUTOR_ADDRESS"
echo "Operator:        $DEPLOYMENT_OPERATOR"
echo "Broadcast:       $BROADCAST"

if [ "$ROYALTY_RELEASE_OPERATION" = "inspect" ]; then
  jq '{
    schema,
    status,
    truth_status,
    plan_sha256,
    release_sha,
    phase,
    execution_mode,
    valid_after,
    expires_at,
    authority,
    transactions,
    verified_signers
  }' "$PLAN_RECEIPT_PATH"
  exit 0
fi

# The phase verifier above is the pre-ceremony authority: it independently
# rebuilds the deployment-rooted current reviewer lineage, immutable fresh
# receipt, and prescriptive Royalty binding. Requiring the post-ceremony v4/H
# authority here would create an authorization cycle. We use only the shared
# ledger replay, source, lock, and durable-commit primitives before execution.
OPERATOR_POLICY_REVIEWER_GENESIS_ACCEPTANCE_SHA256="$(jq -er \
  '.core.reviewer_authority_genesis_acceptance_sha256' \
  "$ROYALTY_RELEASE_PHASE_PLAN_PATH")"
export OPERATOR_POLICY_REVIEWER_GENESIS_ACCEPTANCE_SHA256

capture_and_validate_phase_ledger() {
  if [ -z "$LEDGER_REPLAY_PATH" ]; then
    LEDGER_REPLAY_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-ledger-replay.XXXXXX")"
    chmod 600 "$LEDGER_REPLAY_PATH"
  fi
  if ! node "$ROOT_DIR/scripts/release-ceremony-ledger-cli.mjs" replay \
    --repository-root "$ROOT_DIR" \
    --source-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH" \
    --ledger "$MANIFEST_PATH" \
    --evidence-root "$RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT" \
    --lock-root "$RELEASE_CEREMONY_LOCK_ROOT" \
    --release-sha "$RELEASE_SHA" \
    --deployment-intent-sha256 "$DEPLOYMENT_INTENT_SHA256" \
    --reviewer-genesis-acceptance-sha256 "$OPERATOR_POLICY_REVIEWER_GENESIS_ACCEPTANCE_SHA256" \
    --tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" \
      >"$LEDGER_REPLAY_PATH"; then
    fail "Royalty release could not replay the complete external ledger revision chain."
  fi
  if ! jq -e --slurpfile plan "$ROYALTY_RELEASE_PHASE_PLAN_PATH" \
    --slurpfile replay "$LEDGER_REPLAY_PATH" '
      ($plan[0].core) as $core
      | ($replay[0]) as $revision
      | [(.royaltyReleaseHistory // [])[]
          | select(.royaltyDistributorAddress == $core.authority.distributor_address)] as $history
      | if any($history[]; .phasePlanSha256 == $plan[0].plan_sha256) then
          true
        elif $core.phase == 1 then
          ($history | length) == 0
          and ((.contracts.royaltyDistributor.latestReleasePhase // 0) == 0)
        else
          ($history | length) == 1
          and $history[0].phase == 1
          and $history[0].executionMode == "stage_authority"
          and ((.contracts.royaltyDistributor.latestReleasePhase // 0) == 1)
          and $core.phase_one_prerequisite.phase_one_plan_sha256
            == $history[0].phasePlanSha256
          and $core.phase_one_prerequisite.proposal_tx_hash
            == $history[0].transactionReceipts[0].transactionHash
          and $core.phase_one_prerequisite.proposal_block_number
            == ($history[0].transactionReceipts[0].blockNumber | tostring)
          and $core.phase_one_prerequisite.proposal_block_hash
            == $history[0].transactionReceipts[0].blockHash
          and $core.phase_one_prerequisite.pending_authority_activates_at
            == ($history[0].postState.pendingAuthorityActivatesAt | tostring)
          and $core.phase_one_prerequisite.ledger_sha256
            == $revision.current_ledger_sha256
          and $core.phase_one_prerequisite.ledger_revision
            == $revision.revision_count
          and $core.phase_one_prerequisite.ledger_revision_receipt_sha256
            == $revision.last_revision_receipt_sha256
        end
  ' "$MANIFEST_PATH" >/dev/null; then
    fail "Royalty phase plan skips, reorders, or differs from the exact durable prior-phase ledger revision."
  fi

  if [ -z "$PHASE_ONE_BINDING_PATH" ]; then
    PHASE_ONE_BINDING_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-phase-one-binding.XXXXXX")"
    chmod 600 "$PHASE_ONE_BINDING_PATH"
  fi
  if ! node "$LEDGER_BINDING_HELPER" verify \
    --plan "$ROYALTY_RELEASE_PHASE_PLAN_PATH" \
    --ledger "$MANIFEST_PATH" >"$PHASE_ONE_BINDING_PATH"; then
    fail "Royalty phase plan does not bind the canonical phase-one history, finality receipt, and common-finalized timestamp."
  fi
  if ! jq -e --slurpfile plan "$ROYALTY_RELEASE_PHASE_PLAN_PATH" '
    keys == [
      "distributorAddress",
      "finalizedAuthorityReceiptSha256",
      "phase",
      "phaseOneFinalizedAt",
      "phaseOneHistoryRecordSha256",
      "planSha256",
      "schema",
      "status",
      "truthStatus"
    ]
    and .schema == "dnai.royalty-phase-one-ledger-binding-verification-receipt.v1"
    and .phase == $plan[0].core.phase
    and .planSha256 == $plan[0].plan_sha256
    and .distributorAddress == $plan[0].core.authority.distributor_address
    and (
      if .phase == 1 then
        .status == "phase_one_exact_empty_history_validated"
        and .truthStatus
          == "external_ledger_history_only_not_rpc_execution_finality_or_tdx_evidence"
        and .phaseOneHistoryRecordSha256 == null
        and .finalizedAuthorityReceiptSha256 == null
        and .phaseOneFinalizedAt == null
      else
        .status == "phase_two_exact_phase_one_record_and_finality_validated"
        and .truthStatus
          == "canonical_external_ledger_record_and_embedded_finality_only_not_fresh_rpc_or_tdx_evidence"
        and .phaseOneHistoryRecordSha256
          == $plan[0].core.phase_one_prerequisite.phase_one_history_record_sha256
        and .finalizedAuthorityReceiptSha256
          == $plan[0].core.phase_one_prerequisite.finalized_authority_receipt_sha256
        and .phaseOneFinalizedAt
          == $plan[0].core.phase_one_prerequisite.phase_one_finalized_at
      end
    )
  ' "$PHASE_ONE_BINDING_PATH" >/dev/null; then
    fail "Royalty phase-one ledger-binding verifier returned an unexpected receipt."
  fi
}

operator_policy_require_fresh_release_ledger
capture_and_validate_phase_ledger
operator_policy_assert_current_source

prior_plan_count="$(jq -r --arg plan "$ROYALTY_RELEASE_PLAN_SHA256" \
  '[.royaltyReleaseHistory[]? | select(.phasePlanSha256 == $plan)] | length' "$MANIFEST_PATH")"
if [ "$prior_plan_count" -gt 1 ]; then
  fail "Royalty phase plan appears more than once in the append-only ledger."
fi
if [ "$ROYALTY_RELEASE_OPERATION" = "execute" ] && [ "$prior_plan_count" != "0" ]; then
  fail "Royalty phase plan replay detected; use inspect, never rerun it."
fi

for name in BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_SECONDARY_RPC_URL; do
  require_env "$name"
done

CLASSIFICATION_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-classification.XXXXXX")"
chmod 600 "$CLASSIFICATION_PATH"
classify_release_state() {
  local prior_broadcast="${1:-}"
  local -a command
  command=(
    node "$FINALITY_HELPER" classify
    --plan-receipt "$PLAN_RECEIPT_PATH"
    --primary-rpc "$BASE_SEPOLIA_RPC_URL"
    --secondary-rpc "$BASE_SEPOLIA_SECONDARY_RPC_URL"
  )
  if [ -n "$prior_broadcast" ]; then
    command+=(--broadcast "$prior_broadcast")
  fi
  if ! "${command[@]}" >"$CLASSIFICATION_PATH"; then
    fail "Royalty state classification failed closed before Forge or keystore access."
  fi
  if ! jq -e '
    .schema == "dnai.base-sepolia-royalty-state-classification.v1"
    and .status == "valid_dual_rpc_common_finalized_state"
    and .chainId == 84532
    and (.classification == "fresh_empty"
      or .classification == "phase1_exact_pending"
      or .classification == "phase2_exact_active_paused"
      or .classification == "phase2_exact_active_unpaused")
    and (.executionScope == "full_plan"
      or .executionScope == "reviewed_unpause_suffix"
      or .executionScope == "already_complete"
      or .executionScope == "none")
    and (.remainingTransactions | type == "array")
    and (.finalizedBlockNumber | type == "number" and . > 0 and floor == .)
    and (.finalizedBlockHash | test("^0x[0-9a-f]{64}$"))
    and (.finalizedBlockTimestamp | type == "number" and . > 0 and floor == .)
    and (.signerNonce | test("^(0|[1-9][0-9]*)$"))
    and (.providerConfirmations | type == "array" and length == 2)
  ' "$CLASSIFICATION_PATH" >/dev/null; then
    fail "Royalty state classifier returned malformed or divergent evidence."
  fi
}

PRIOR_BROADCAST_RECEIPT_PATH=""
initial_classification_artifact=""
if [ "$ROYALTY_RELEASE_OPERATION" = "execute" ] \
  && [ -n "${ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH:-}" ]; then
  require_absolute_file ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH
  initial_classification_artifact="$ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH"
fi
classify_release_state "$initial_classification_artifact"
classification="$(jq -r '.classification' "$CLASSIFICATION_PATH")"
execution_scope="$(jq -r '.executionScope' "$CLASSIFICATION_PATH")"
signer_nonce="$(jq -r '.signerNonce' "$CLASSIFICATION_PATH")"
reviewed_first_nonce="$(jq -r '.transactions[0].nonce' "$PLAN_RECEIPT_PATH")"

expected_prestate=""
expected_poststate=""
case "$ROYALTY_RELEASE_PHASE:$ROYALTY_RELEASE_EXECUTION_MODE" in
  1:stage_authority)
    expected_prestate=fresh_empty
    expected_poststate=phase1_exact_pending
    ;;
  2:activate_and_unpause)
    expected_prestate=phase1_exact_pending
    expected_poststate=phase2_exact_active_unpaused
    ;;
  2:recover_reverted_unpause)
    expected_prestate=phase2_exact_active_paused
    expected_poststate=phase2_exact_active_unpaused
    ;;
  *) fail "Verified plan exposed an unsupported phase/execution-mode pair." ;;
esac

if [ "$ROYALTY_RELEASE_OPERATION" = "reconcile" ]; then
  if [ "$classification" != "$expected_poststate" ]; then
    fail "Reconciliation requires exact finalized poststate $expected_poststate; observed $classification."
  fi
  if [ "$prior_plan_count" = "1" ]; then
    echo "Royalty release plan is already recorded and its finalized state is exact; no transaction was sent."
    exit 0
  fi
  require_absolute_file ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH
  BROADCAST_RECEIPT_PATH="$ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH"
  if [ -n "${ROYALTY_RELEASE_PRIOR_BROADCAST_RECEIPT_PATH:-}" ]; then
    require_absolute_file ROYALTY_RELEASE_PRIOR_BROADCAST_RECEIPT_PATH
    PRIOR_BROADCAST_RECEIPT_PATH="$ROYALTY_RELEASE_PRIOR_BROADCAST_RECEIPT_PATH"
  fi
  operator_policy_acquire_release_ceremony_lock royalty_release
  LOCK_MAY_BE_RELEASED=true
  operator_policy_require_fresh_release_ledger
  capture_and_validate_phase_ledger
  operator_policy_assert_current_source
  classify_release_state
  if [ "$(jq -r '.classification' "$CLASSIFICATION_PATH")" != "$expected_poststate" ]; then
    fail "Royalty finalized poststate changed while entering reconciliation."
  fi
else
  if [ "$classification" = "phase2_exact_active_paused" ] \
    && [ "$ROYALTY_RELEASE_EXECUTION_MODE" = "activate_and_unpause" ]; then
    require_absolute_file ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH
    PRIOR_BROADCAST_RECEIPT_PATH="$ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH"
    classify_release_state "$PRIOR_BROADCAST_RECEIPT_PATH"
    classification="$(jq -r '.classification' "$CLASSIFICATION_PATH")"
    execution_scope="$(jq -r '.executionScope' "$CLASSIFICATION_PATH")"
    signer_nonce="$(jq -r '.signerNonce' "$CLASSIFICATION_PATH")"
    reviewed_first_nonce="$(jq -r '.transactions[1].nonce' "$PLAN_RECEIPT_PATH")"
    if [ "$execution_scope" != "reviewed_unpause_suffix" ] \
      || ! jq -e --slurpfile plan "$PLAN_RECEIPT_PATH" \
        '.remainingTransactions == [$plan[0].transactions[1]]
         and (.reviewedActivationReceipt | type) == "object"' \
        "$CLASSIFICATION_PATH" >/dev/null; then
      fail "Active-paused state lacks exact activation-only evidence. A never-submitted unpause requires a future signed recover_missing_unpause mode; a finalized reverted unpause requires recover_reverted_unpause."
    fi
  elif [ "$classification" != "$expected_prestate" ] \
    || [ "$execution_scope" != "full_plan" ] \
    || ! jq -e --slurpfile plan "$PLAN_RECEIPT_PATH" \
      '.remainingTransactions == $plan[0].transactions' "$CLASSIFICATION_PATH" >/dev/null; then
    fail "Reviewed execution requires exact full-plan prestate $expected_prestate; observed $classification/$execution_scope. Blind resume is forbidden."
  fi
  if [ "$signer_nonce" != "$reviewed_first_nonce" ]; then
    fail "Finalized operator nonce differs from the first reviewed transaction nonce."
  fi
  if [ "$ROYALTY_RELEASE_PHASE" = "2" ]; then
    finalized_timestamp="$(jq -r '.finalizedBlockTimestamp' "$CLASSIFICATION_PATH")"
    activation_timestamp="$(jq -r '.phase_one_prerequisite.pending_authority_activates_at' "$PLAN_RECEIPT_PATH")"
    if [ "$finalized_timestamp" -lt "$activation_timestamp" ]; then
      fail "Royalty phase-two timelock has not elapsed at the common finalized checkpoint."
    fi
  fi

  for name in FOUNDRY_BROADCAST FOUNDRY_OUT FOUNDRY_CACHE_PATH; do
    require_external_directory "$name"
  done

  cd "$CONTRACTS_DIR"
  forge build --sizes
  forge test --threads 1 --match-path test/ConfigureRoyaltyRelease.t.sol

  echo "== Simulate exact reviewed Royalty phase (no keystore) =="
  DRY_RUN_OUTPUT_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-dry-run-output.XXXXXX.jsonl")"
  chmod 600 "$DRY_RUN_OUTPUT_PATH"
  forge script "$FORGE_TARGET" \
    --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    --sender "$DEPLOYMENT_OPERATOR" \
    --gas-estimate-multiplier "$ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER" \
    --json >"$DRY_RUN_OUTPUT_PATH"

  DRY_RUN_ARTIFACT_PATH="$FOUNDRY_BROADCAST/ConfigureRoyaltyRelease.s.sol/$CHAIN_ID/dry-run/run-latest.json"
  require_absolute_file DRY_RUN_ARTIFACT_PATH
  dry_run_artifact_sha256="$(sha256_file "$DRY_RUN_ARTIFACT_PATH")"
  dry_run_output_sha256="$(sha256_file "$DRY_RUN_OUTPUT_PATH")"
  if ! gas_projection="$(derive_dry_run_gas_requirement "$DRY_RUN_OUTPUT_PATH")"; then
    fail "Royalty dry run did not yield an internally consistent bounded gas projection."
  fi
  IFS=$'\t' read -r \
    required_operator_balance_wei \
    dry_run_gas_price_gwei \
    forge_estimated_amount_wei <<<"$gas_projection"
  for value in "$required_operator_balance_wei" "$forge_estimated_amount_wei"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] \
      || fail "Royalty dry-run gas projection returned a noncanonical wei amount."
  done
  [[ "$dry_run_gas_price_gwei" =~ ^(0|[1-9][0-9]*)(\.[0-9]{1,9})?$ ]] \
    || fail "Royalty dry-run gas projection returned a noncanonical gwei price."
  echo "Forge gas estimate: $forge_estimated_amount_wei wei (130% gas-unit multiplier)"
  echo "Required balance:   $required_operator_balance_wei wei (2x balance safety margin)"
  DRY_RUN_RECEIPT_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-dry-run.XXXXXX")"
  chmod 600 "$DRY_RUN_RECEIPT_PATH"
  if ! node "$FINALITY_HELPER" verify-dry-run \
    --plan-receipt "$PLAN_RECEIPT_PATH" \
    --classification "$CLASSIFICATION_PATH" \
    --broadcast "$DRY_RUN_ARTIFACT_PATH" >"$DRY_RUN_RECEIPT_PATH"; then
    fail "Forge dry run differs from the exact classified reviewed transaction scope."
  fi
  if ! jq -e --arg plan "$ROYALTY_RELEASE_PLAN_SHA256" \
    --arg scope "$execution_scope" '
      .schema == "dnai.royalty-release-dry-run-verification-receipt.v1"
      and .status == "dry_run_exactly_matches_classified_remaining_transactions"
      and .planSha256 == $plan
      and .executionScope == $scope
      and .truthStatus == "local_forge_dry_run_structure_only_not_onchain_execution_or_finality"
    ' "$DRY_RUN_RECEIPT_PATH" >/dev/null; then
    fail "Royalty dry-run verifier returned a malformed or mismatched receipt."
  fi

  # The deterministic script re-reads the exact state above. Reconfirm that the
  # reviewed transaction scope did not change during simulation; in particular,
  # an activation-only crash may authorize only the still-current unpause at
  # reviewed nonce N+1, never the original full script or recovery mode.
  classify_release_state "$PRIOR_BROADCAST_RECEIPT_PATH"
  if [ "$(jq -r '.classification' "$CLASSIFICATION_PATH")" != "$classification" ] \
    || [ "$(jq -r '.executionScope' "$CLASSIFICATION_PATH")" != "$execution_scope" ] \
    || [ "$(jq -r '.signerNonce' "$CLASSIFICATION_PATH")" != "$reviewed_first_nonce" ]; then
    fail "Royalty reviewed transaction scope changed during simulation."
  fi

  if [ "$BROADCAST" != "true" ]; then
    echo "Royalty phase simulation completed; no wallet was unlocked and no chain state changed."
    exit 0
  fi

  operator_policy_acquire_release_ceremony_lock royalty_release
  LOCK_MAY_BE_RELEASED=true

  # Revalidate all mutable/current facts under the release-wide lock. There is
  # deliberately no Forge resume path: state and nonces decide what is safe.
  operator_policy_require_fresh_release_ledger
  capture_and_validate_phase_ledger
  operator_policy_assert_current_source
  SECOND_PLAN_RECEIPT_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-phase-plan-recheck.XXXXXX")"
  chmod 600 "$SECOND_PLAN_RECEIPT_PATH"
  node "$PHASE_PLAN" verify \
    --deployment-intent "$DEPLOYMENT_INTENT_PATH" \
    --fresh-deployment-manifest "$FRESH_DEPLOYMENT_MANIFEST_PATH" \
    --reviewer-genesis "$ROYALTY_RELEASE_REVIEWER_GENESIS_PATH" \
    --reviewer-genesis-acceptance "$ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH" \
    --reviewer-current-status "$ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH" \
    --reviewer-status-history "$ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH" \
    --royalty-release-prescription "$ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH" \
    --tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" \
    --plan "$ROYALTY_RELEASE_PHASE_PLAN_PATH" >"$SECOND_PLAN_RECEIPT_PATH"
  if ! cmp -s "$PLAN_RECEIPT_PATH" "$SECOND_PLAN_RECEIPT_PATH"; then
    fail "Royalty plan verification receipt changed before keystore unlock."
  fi
  classify_release_state "$PRIOR_BROADCAST_RECEIPT_PATH"
  if [ "$(jq -r '.classification' "$CLASSIFICATION_PATH")" != "$classification" ] \
    || [ "$(jq -r '.executionScope' "$CLASSIFICATION_PATH")" != "$execution_scope" ] \
    || [ "$(jq -r '.signerNonce' "$CLASSIFICATION_PATH")" != "$reviewed_first_nonce" ]; then
    fail "Royalty finalized state or signer nonce changed after simulation."
  fi
  if [ "$dry_run_output_sha256" != "$(sha256_file "$DRY_RUN_OUTPUT_PATH")" ]; then
    fail "The bounded Royalty Forge gas projection changed before keystore access."
  fi
  pre_unlock_operator_balance_wei="$(cast balance \
    "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  require_royalty_balance_at_least \
    "$pre_unlock_operator_balance_wei" "$required_operator_balance_wei"

  if ! cast wallet list | awk '{print $1}' | grep -qx "$ACCOUNT"; then
    fail "Foundry keystore account dev was not found. Use /cast-wallet first."
  fi
  unlocked_signer="$(cast wallet address --account dev)"
  if [ "$(lower "$unlocked_signer")" != "$(lower "$DEPLOYMENT_OPERATOR")" ]; then
    fail "The unlocked dev keystore does not control the reviewed Royalty owner."
  fi

  operator_policy_require_fresh_release_ledger
  capture_and_validate_phase_ledger
  operator_policy_assert_current_source
  classify_release_state "$PRIOR_BROADCAST_RECEIPT_PATH"
  if [ "$(jq -r '.classification' "$CLASSIFICATION_PATH")" != "$classification" ] \
    || [ "$(jq -r '.executionScope' "$CLASSIFICATION_PATH")" != "$execution_scope" ] \
    || [ "$(jq -r '.signerNonce' "$CLASSIFICATION_PATH")" != "$reviewed_first_nonce" ]; then
    fail "Royalty state changed after keystore unlock; no transaction was sent."
  fi
  if [ "$dry_run_artifact_sha256" != "$(sha256_file "$DRY_RUN_ARTIFACT_PATH")" ]; then
    fail "The exact reviewed Forge dry-run artifact changed before broadcast."
  fi
  if [ "$dry_run_output_sha256" != "$(sha256_file "$DRY_RUN_OUTPUT_PATH")" ]; then
    fail "The bounded Royalty Forge gas projection changed before broadcast."
  fi
  node "$FINALITY_HELPER" verify-dry-run \
    --plan-receipt "$PLAN_RECEIPT_PATH" \
    --classification "$CLASSIFICATION_PATH" \
    --broadcast "$DRY_RUN_ARTIFACT_PATH" >"$DRY_RUN_RECEIPT_PATH"
  pre_broadcast_operator_balance_wei="$(cast balance \
    "$DEPLOYMENT_OPERATOR" --rpc-url "$BASE_SEPOLIA_RPC_URL")"
  require_royalty_balance_at_least \
    "$pre_broadcast_operator_balance_wei" "$required_operator_balance_wei"

  ledger_sha256="$(sha256_file "$MANIFEST_PATH")"
  classification_sha256="$(sha256_file "$CLASSIFICATION_PATH")"
  verification_sha256="$(sha256_file "$PLAN_RECEIPT_PATH")"
  dry_run_sha256="$(sha256_file "$DRY_RUN_RECEIPT_PATH")"
  capsule_root="$RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT/royalty-release-capsules/$RELEASE_SHA"
  mkdir -p "$capsule_root"
  chmod 700 "$RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT/royalty-release-capsules" "$capsule_root"
  prior_broadcast_sha256=""
  if [ -n "$PRIOR_BROADCAST_RECEIPT_PATH" ]; then
    prior_broadcast_sha256="$(sha256_file "$PRIOR_BROADCAST_RECEIPT_PATH")"
    prior_archive_path="$capsule_root/${ROYALTY_RELEASE_PLAN_SHA256#sha256:}.activation-only.json"
    [ ! -e "$prior_archive_path" ] || fail "The activation-only Forge artifact was already archived; reconcile it instead of replaying."
    node -e '
      const fs = require("node:fs"); const path = require("node:path");
      const source = fs.openSync(process.argv[1], fs.constants.O_RDONLY);
      const output = fs.openSync(process.argv[2], fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
      try { fs.writeFileSync(output, fs.readFileSync(source)); fs.fsyncSync(output); }
      finally { fs.closeSync(source); fs.closeSync(output); }
      const parent = fs.openSync(path.dirname(process.argv[2]), fs.constants.O_RDONLY);
      try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    ' "$PRIOR_BROADCAST_RECEIPT_PATH" "$prior_archive_path"
    if [ "$prior_broadcast_sha256" != "$(sha256_file "$prior_archive_path")" ]; then
      fail "The durable activation-only Forge artifact copy differs from its reviewed source."
    fi
    PRIOR_BROADCAST_RECEIPT_PATH="$prior_archive_path"
  fi
  capsule_path="$capsule_root/${ROYALTY_RELEASE_PLAN_SHA256#sha256:}.json"
  [ ! -e "$capsule_path" ] || fail "A pre-broadcast capsule already exists for this Royalty plan; reconcile it instead of replaying."
  capsule_tmp="$(mktemp "$capsule_root/.capsule.XXXXXX")"
  jq -S -n \
    --arg schema "dnai.royalty-release-pre-broadcast-capsule.v1" \
    --arg truthStatus "durable_exact_reviewed_plan_and_prestate_not_transaction_submission_mining_finality_or_tdx_evidence" \
    --arg releaseSha "$RELEASE_SHA" \
    --arg planSha256 "$ROYALTY_RELEASE_PLAN_SHA256" \
    --arg verificationReceiptSha256 "$verification_sha256" \
    --arg classificationSha256 "$classification_sha256" \
    --arg ledgerSha256 "$ledger_sha256" \
    --arg dryRunReceiptSha256 "$dry_run_sha256" \
    --arg dryRunArtifactSha256 "$dry_run_artifact_sha256" \
    --arg dryRunOutputSha256 "$dry_run_output_sha256" \
    --arg forgeEstimatedAmountWei "$forge_estimated_amount_wei" \
    --arg requiredOperatorBalanceWei "$required_operator_balance_wei" \
    --arg operatorBalanceWei "$pre_broadcast_operator_balance_wei" \
    --arg dryRunGasPriceGwei "$dry_run_gas_price_gwei" \
    --argjson gasEstimateMultiplier "$ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER" \
    --argjson balanceSafetyMultiplier "$ROYALTY_RELEASE_BALANCE_SAFETY_MULTIPLIER" \
    --arg priorBroadcastReceiptSha256 "$prior_broadcast_sha256" \
    --arg operation "$ROYALTY_RELEASE_OPERATION" \
    --argjson phase "$ROYALTY_RELEASE_PHASE" \
    --arg executionMode "$ROYALTY_RELEASE_EXECUTION_MODE" \
    --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson transactions "$(jq -c '.remainingTransactions' "$CLASSIFICATION_PATH")" '
      {
        schema: $schema,
        truthStatus: $truthStatus,
        releaseSha: $releaseSha,
        planSha256: $planSha256,
        verificationReceiptSha256: $verificationReceiptSha256,
        classificationSha256: $classificationSha256,
        ledgerSha256: $ledgerSha256,
        dryRunReceiptSha256: $dryRunReceiptSha256,
        dryRunArtifactSha256: $dryRunArtifactSha256,
        dryRunOutputSha256: $dryRunOutputSha256,
        gasProjection: {
          forgeEstimatedAmountWei: $forgeEstimatedAmountWei,
          requiredOperatorBalanceWei: $requiredOperatorBalanceWei,
          operatorBalanceWei: $operatorBalanceWei,
          gasPriceGwei: $dryRunGasPriceGwei,
          gasEstimateMultiplier: $gasEstimateMultiplier,
          balanceSafetyMultiplier: $balanceSafetyMultiplier
        },
        priorBroadcastReceiptSha256: (
          if $priorBroadcastReceiptSha256 == "" then null
          else $priorBroadcastReceiptSha256 end
        ),
        operation: $operation,
        phase: $phase,
        executionMode: $executionMode,
        createdAt: $createdAt,
        transactions: $transactions
      }
    ' >"$capsule_tmp"
  chmod 600 "$capsule_tmp"
  mv "$capsule_tmp" "$capsule_path"
  node -e '
    const fs = require("node:fs"); const path = require("node:path");
    for (const value of [process.argv[1], path.dirname(process.argv[1])]) {
      const fd = fs.openSync(value, fs.statSync(value).isDirectory() ? fs.constants.O_RDONLY : fs.constants.O_RDWR);
      try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    }
  ' "$capsule_path"

  echo "== Broadcast exact reviewed Royalty phase =="
  # From this point onward, failures leave the lock fail closed. Recovery uses
  # the durable capsule plus explicit reconcile mode, never blind Forge resume.
  LOCK_MAY_BE_RELEASED=false
  forge script "$FORGE_TARGET" \
    --rpc-url "$BASE_SEPOLIA_RPC_URL" \
    --sender "$DEPLOYMENT_OPERATOR" \
    --account dev \
    --with-gas-price "${dry_run_gas_price_gwei}gwei" \
    --gas-estimate-multiplier "$ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER" \
    --broadcast \
    --slow

  BROADCAST_RECEIPT_PATH="$FOUNDRY_BROADCAST/ConfigureRoyaltyRelease.s.sol/$CHAIN_ID/run-latest.json"
  require_absolute_file BROADCAST_RECEIPT_PATH
fi

# Both a fresh broadcast and explicit reconciliation converge here. The fixed
# collector proves the exact reviewed transactions and poststate through two
# distinct HTTPS providers at one common finalized numeric block.
FINALITY_PATH="$(mktemp "${TMPDIR:-/tmp}/dnai-royalty-finality.XXXXXX")"
rm -f -- "$FINALITY_PATH"
finality_command=(
  node "$FINALITY_HELPER" collect
  --plan-receipt "$PLAN_RECEIPT_PATH"
  --broadcast "$BROADCAST_RECEIPT_PATH"
  --primary-rpc "$BASE_SEPOLIA_RPC_URL"
  --secondary-rpc "$BASE_SEPOLIA_SECONDARY_RPC_URL"
  --out "$FINALITY_PATH"
)
if [ -n "$PRIOR_BROADCAST_RECEIPT_PATH" ]; then
  finality_command+=(--prior-broadcast "$PRIOR_BROADCAST_RECEIPT_PATH")
fi
"${finality_command[@]}" >/dev/null
chmod 600 "$FINALITY_PATH"

transaction_receipts="$(jq -c '.transactionReceipts' "$FINALITY_PATH")"
finalized_authority="$(jq -c '.' "$FINALITY_PATH")"
phase_plan="$(jq -c '.' "$ROYALTY_RELEASE_PHASE_PLAN_PATH")"
ledger_before_sha256="$(sha256_file "$MANIFEST_PATH")"
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LEDGER_CANDIDATE_PATH="$(mktemp "$(dirname "$MANIFEST_PATH")/.royalty-release-ledger.XXXXXX")"
chmod 600 "$LEDGER_CANDIDATE_PATH"
if ! jq -e \
  --argjson chainId "$CHAIN_ID" \
  --arg sourceCommit "$RELEASE_SHA" \
  --arg recordedAt "$recorded_at" \
  --argjson phasePlan "$phase_plan" \
  --argjson transactionReceipts "$transaction_receipts" \
  --argjson finalizedAuthority "$finalized_authority" \
  -f "$MANIFEST_FILTER" "$MANIFEST_PATH" >"$LEDGER_CANDIDATE_PATH"; then
  fail "Finalized Royalty evidence did not satisfy the append-only ledger policy."
fi
if [ "$ledger_before_sha256" != "$(sha256_file "$MANIFEST_PATH")" ]; then
  fail "Release ceremony ledger changed concurrently before Royalty publication."
fi

operator_policy_durably_replace_release_ledger "$LEDGER_CANDIDATE_PATH" "$MANIFEST_PATH"
rm -f -- "$LEDGER_CANDIDATE_PATH"
LEDGER_CANDIDATE_PATH=""
LOCK_MAY_BE_RELEASED=true
operator_policy_release_release_ceremony_lock

echo "Royalty release phase $ROYALTY_RELEASE_PHASE is finalized through both RPC authorities and durably recorded."
