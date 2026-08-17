#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_HELPER="$SCRIPT_DIR/deploy-base-sepolia.sh"
OPERATOR_CONFIGURE_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
TINKER_HELPER="$SCRIPT_DIR/deploy-tinker-encumbrance-base-sepolia.sh"
FILTER="$SCRIPT_DIR/merge-base-sepolia-suite-manifest.jq"
FRESH_SUITE="$SCRIPT_DIR/../script/DeployFreshSuite.s.sol"
STANDALONE_EMAIL_ORACLE="$SCRIPT_DIR/../script/EmailOracleAuth.s.sol"
STANDALONE_TINKER="$SCRIPT_DIR/../script/TinkerAccountEncumbrance.s.sol"
FUNDING_COMMAND_PLAN="$SCRIPT_DIR/../../tinker_delegate/funding_command_plan.py"

bash -n "$DEPLOY_HELPER"
bash -n "$OPERATOR_CONFIGURE_GUARD"
bash -n "$TINKER_HELPER"

if grep -Eq '0x[0-9a-fA-F]{40}([^0-9a-fA-F]|$)' "$DEPLOY_HELPER" "$TINKER_HELPER"; then
  echo "Deployment helpers must not contain hardcoded Ethereum addresses." >&2
  exit 1
fi

if grep -q -- '--private-key' "$DEPLOY_HELPER" "$TINKER_HELPER"; then
  echo "Raw private-key flags are forbidden." >&2
  exit 1
fi

if grep -Eq -- '--account[[:space:]]+"?\$' "$DEPLOY_HELPER" "$TINKER_HELPER"; then
  echo "Deployment helpers must use the literal --account dev safety boundary." >&2
  exit 1
fi

if ! grep -q -- '--account dev' "$DEPLOY_HELPER"; then
  echo "The canonical fresh-suite helper must use the literal --account dev safety boundary." >&2
  exit 1
fi

for operator_policy_env in \
  DEPLOYMENT_INTENT_PATH \
  DEPLOYMENT_INTENT_SHA256 \
  OPERATOR_POLICY_REVIEW_ENVELOPE_PATH \
  OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256 \
  RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH \
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH \
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH \
  RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH \
  DILIGENCE_GOVERNANCE_CONTROLLER \
  RELEASE_SHA; do
  if ! grep -q "require_env $operator_policy_env" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment must require explicit $operator_policy_env configuration." >&2
    exit 1
  fi
done

if [ "$(grep -Fc 'operator-policy-packet.mjs' "$DEPLOY_HELPER")" -ne 2 ] \
  || ! grep -q 'require_absolute_authority_file DEPLOYMENT_INTENT_PATH' "$DEPLOY_HELPER" \
  || ! grep -q 'require_absolute_authority_file OPERATOR_POLICY_REVIEW_ENVELOPE_PATH' "$DEPLOY_HELPER" \
  || ! grep -q 'check-intent' "$DEPLOY_HELPER" \
  || ! grep -q 'check-review' "$DEPLOY_HELPER" \
  || ! grep -q -- '--subject "$DEPLOYMENT_INTENT_PATH"' "$DEPLOY_HELPER" \
  || ! grep -q 'subjectKind == "deployment_intent"' "$DEPLOY_HELPER" \
  || ! grep -q 'canonicalCvmCount == 7' "$DEPLOY_HELPER" \
  || ! grep -q 'qvlNumericPolicyCount == 5' "$DEPLOY_HELPER" \
  || ! grep -q 'dynamicRuntimeAuthorityCount == 0' "$DEPLOY_HELPER" \
  || ! grep -q 'staticContractInputCount == 3' "$DEPLOY_HELPER" \
  || ! grep -q 'dnai.deployment-intent-validation-receipt.v6' "$DEPLOY_HELPER" \
  || ! grep -q 'reviewerAuthorityCurrentStatusEpoch' "$DEPLOY_HELPER" \
  || ! grep -q 'reviewerAuthorityCurrentStatusSha256' "$DEPLOY_HELPER"; then
  echo "Fresh-suite deployment must validate the canonical empty-authority intent and its exact review envelope before execution." >&2
  exit 1
fi

if ! grep -q 'canonicalCvmCount == 7' "$OPERATOR_CONFIGURE_GUARD" \
  || ! grep -q 'qvlNumericPolicyCount == 5' "$OPERATOR_CONFIGURE_GUARD" \
  || ! grep -q 'dnai.deployment-intent-validation-receipt.v6' "$OPERATOR_CONFIGURE_GUARD" \
  || ! grep -q 'reviewerAuthorityCurrentStatusEpoch' "$OPERATOR_CONFIGURE_GUARD" \
  || ! grep -q 'reviewerAuthorityCurrentStatusSha256' "$OPERATOR_CONFIGURE_GUARD" \
  || grep -q 'canonicalCvmCount == 6' "$DEPLOY_HELPER" "$OPERATOR_CONFIGURE_GUARD" \
  || grep -q 'qvlNumericPolicyCount == 4' "$DEPLOY_HELPER" "$OPERATOR_CONFIGURE_GUARD" \
  || grep -Eq 'dnai\.deployment-intent-validation-receipt\.v(3|4|5)' "$DEPLOY_HELPER" "$OPERATOR_CONFIGURE_GUARD"; then
  echo "Deployment and configuration guards must require exactly seven CVMs and five QVL policy domains." >&2
  exit 1
fi

for reviewed_intent_binding in \
  DILIGENCE_GOVERNANCE_CONTROLLER \
  COMPUTE_VAULT_DEVELOPER \
  COMPUTE_VAULT_DEVELOPER_FEE_BPS \
  DEPLOYMENT_OPERATOR \
  EMAIL_ORACLE_UPGRADE_DELAY \
  RELEASE_SHA \
  TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT \
  TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI \
  TINKER_ENCUMBRANCE_MAX_SPEND_WEI; do
  if ! grep -Eq "assert_intent_(string|number)_equal $reviewed_intent_binding " "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment does not compare reviewed deployment-intent field $reviewed_intent_binding." >&2
    exit 1
  fi
done

if ! grep -q 'Legacy operator-policy packet and projection inputs are retired and rejected' "$DEPLOY_HELPER" \
  || ! grep -q 'Final-release authority cannot exist before fresh contract and CVM measurements' "$DEPLOY_HELPER" \
  || grep -Eq '^[[:space:]]*(project|--arg operatorPolicyPacketSha256)|operatorPolicyPacketSha256:' "$DEPLOY_HELPER" "$FILTER"; then
  echo "Fresh deployment must reject the retired packet/projection path and all premature final-authority claims." >&2
  exit 1
fi

policy_validation_line="$(grep -n -m1 'check-intent' "$DEPLOY_HELPER" | cut -d: -f1)"
binding_ceremony_line="$(grep -n -m1 'ceremony-check' "$DEPLOY_HELPER" | cut -d: -f1)"
wallet_access_line="$(grep -n -m1 'cast wallet list' "$DEPLOY_HELPER" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '== Dry run ==' "$DEPLOY_HELPER" | cut -d: -f1)"
broadcast_line="$(grep -n -m1 '== Broadcast reviewed-scope suite ==' "$DEPLOY_HELPER" | cut -d: -f1)"
if [ -z "$binding_ceremony_line" ] \
  || [ "$policy_validation_line" -ge "$binding_ceremony_line" ] \
  || [ "$binding_ceremony_line" -ge "$wallet_access_line" ] \
  || [ "$binding_ceremony_line" -ge "$dry_run_line" ] \
  || [ "$binding_ceremony_line" -ge "$broadcast_line" ] \
  || [ "$policy_validation_line" -ge "$wallet_access_line" ] \
  || [ "$policy_validation_line" -ge "$dry_run_line" ] \
  || [ "$policy_validation_line" -ge "$broadcast_line" ]; then
  echo "Operator-policy and Tinker account-binding ceremony validation must happen before wallet access, dry-run, or broadcast paths." >&2
  exit 1
fi

for binding_boundary in \
  'tinker-account-binding-ceremony.mjs' \
  'require_absolute_authority_file RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH' \
  'require_absolute_authority_file RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH' \
  'require_absolute_authority_file RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH' \
  'require_absolute_authority_file RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH' \
  '--genesis-acceptance "$RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH"' \
  'tinker_account_binding_ceremony_receipt_sha256' \
  '.historical_replay == false' \
  '.deployment_intent_matched == true' \
  '.environment_commitment_matched == true' \
  '.verified_signature_count == 2' \
  '.network_request_performed == false' \
  '.remote_state_mutated == false'; do
  if ! grep -Fq -- "$binding_boundary" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment is missing account-binding ceremony proof: $binding_boundary" >&2
    exit 1
  fi
done

for toolchain_boundary in \
  'assert_release_toolchain_exact' \
  'assert_contract_build_metadata_exact' \
  'forge Version: $expected_forge_version' \
  'cast Version: $expected_cast_version' \
  '.compiler.version == $compiler' \
  '.settings.optimizer == {enabled: true, runs: 200}' \
  '.settings.viaIR == true' \
  'export FOUNDRY_PROFILE=default'; do
  if ! grep -Fq "$toolchain_boundary" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment is missing reviewed toolchain proof: $toolchain_boundary" >&2
    exit 1
  fi
done

if grep -Eq '(^|[[:space:]])eval([[:space:]]|$)' "$DEPLOY_HELPER"; then
  echo "Authority artifacts must never be evaluated as shell source." >&2
  exit 1
fi

if ! grep -q 'require_env EMAIL_ORACLE_UPGRADE_DELAY' "$DEPLOY_HELPER"; then
  echo "Fresh-suite deployment must require an explicit email-oracle upgrade delay." >&2
  exit 1
fi

for tinker_cap_boundary in \
  'MAX_TINKER_POLICY_UNITS_PER_OPERATION=10000000000000000000' \
  'validate_tinker_policy_caps' \
  'not ETH or cumulative'; do
  if ! grep -Fq "$tinker_cap_boundary" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment is missing the Tinker policy-unit boundary: $tinker_cap_boundary" >&2
    exit 1
  fi
done

for required_compute_env in \
  COMPUTE_VAULT_DEVELOPER \
  COMPUTE_VAULT_DEVELOPER_FEE_BPS; do
  if ! grep -q "require_env $required_compute_env" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment must require explicit $required_compute_env configuration." >&2
    exit 1
  fi
done

if ! grep -Fq 'MAX_COMPUTE_VAULT_DEVELOPER_FEE_BPS=100' "$DEPLOY_HELPER" \
  || ! grep -Fq 'MAX_FRESH_RELEASE_DEVELOPER_FEE_BPS = 100' "$FRESH_SUITE" \
  || ! grep -Fq 'compute developer fee exceeds fresh-release cap' "$FRESH_SUITE"; then
  echo "Fresh-suite deployment must reject a Compute developer fee above 100 bps." >&2
  exit 1
fi

for gas_boundary in \
  'FRESH_DEPLOYMENT_GAS_ESTIMATE_MULTIPLIER=130' \
  'FRESH_DEPLOYMENT_BALANCE_SAFETY_MULTIPLIER=2' \
  'derive_dry_run_gas_requirement' \
  'assert_exact_fresh_suite_transaction_plan "$DRY_RUN_PATH"' \
  'require_balance_at_least "$pre_broadcast_operator_balance_wei" "$required_operator_balance_wei"' \
  '--with-gas-price "${dry_run_gas_price_gwei}gwei"' \
  '--gas-estimate-multiplier "$FRESH_DEPLOYMENT_GAS_ESTIMATE_MULTIPLIER"'; do
  if ! grep -Fq -- "$gas_boundary" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment is missing the exact simulated gas-sufficiency boundary: $gas_boundary" >&2
    exit 1
  fi
done
gas_plan_line="$(grep -n -m1 '^assert_exact_fresh_suite_transaction_plan "$DRY_RUN_PATH"' "$DEPLOY_HELPER" | cut -d: -f1)"
gas_balance_line="$(grep -n -m1 '^require_balance_at_least "$pre_broadcast_operator_balance_wei"' "$DEPLOY_HELPER" | cut -d: -f1)"
initial_binding_recheck_line="$(grep -n -m1 'verify_current_tinker_account_binding_ceremony "initial wallet-access gate"' "$DEPLOY_HELPER" | cut -d: -f1)"
pre_broadcast_binding_recheck_line="$(grep -n -m1 'verify_current_tinker_account_binding_ceremony "immediate pre-broadcast gate"' "$DEPLOY_HELPER" | cut -d: -f1)"
keystore_unlock_line="$(grep -n -m1 'cast wallet address --account dev' "$DEPLOY_HELPER" | cut -d: -f1)"
if [ "$gas_plan_line" -ge "$keystore_unlock_line" ] \
  || [ "$gas_balance_line" -ge "$pre_broadcast_binding_recheck_line" ] \
  || [ "$pre_broadcast_binding_recheck_line" -ge "$keystore_unlock_line" ] \
  || [ "$initial_binding_recheck_line" -ge "$gas_plan_line" ] \
  || [ "$(grep -Fc 'verify_current_tinker_account_binding_ceremony "' "$DEPLOY_HELPER")" -ne 2 ] \
  || ! grep -Fq '!= "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT"' "$DEPLOY_HELPER"; then
  echo "Exact transaction-plan gas projection and balance sufficiency must pass before keystore unlock." >&2
  exit 1
fi

if ! grep -q 'new EmailOracleAuth' "$FRESH_SUITE"; then
  echo "Fresh-suite deployment must include a new EmailOracleAuth contract." >&2
  exit 1
fi

if ! grep -q 'new ComputeCreditVault' "$FRESH_SUITE" \
  || ! grep -q 'computeVault.freezeDeveloperFee()' "$FRESH_SUITE"; then
  echo "Fresh-suite deployment must include ComputeCreditVault with a frozen developer fee." >&2
  exit 1
fi

if ! grep -q 'new ExecutionPolicyAnchor' "$FRESH_SUITE"; then
  echo "Fresh-suite deployment must include a fail-closed ExecutionPolicyAnchor." >&2
  exit 1
fi

if ! grep -q 'require_env BASE_SEPOLIA_SECONDARY_RPC_URL' "$DEPLOY_HELPER" \
  || ! grep -q 'validate_rpc_authority_pair "$RPC_URL" "$SECONDARY_RPC_URL"' "$DEPLOY_HELPER" \
  || ! grep -q 'endpoint.protocol !== "https:"' "$DEPLOY_HELPER" \
  || ! grep -q 'primary.origin.toLowerCase() === secondary.origin.toLowerCase()' "$DEPLOY_HELPER" \
  || ! grep -q 'PRIMARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH' "$DEPLOY_HELPER" \
  || ! grep -q 'SECONDARY_EXECUTION_POLICY_ANCHOR_BLOCK_HASH' "$DEPLOY_HELPER" \
  || ! grep -q 'REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256_BYTES32' "$DEPLOY_HELPER" \
  || ! grep -q "'deploymentIntentSha256()(bytes32)'" "$DEPLOY_HELPER" \
  || ! grep -q "'reviewerAuthorityGenesisAcceptanceSha256()(bytes32)'" "$DEPLOY_HELPER" \
  || ! grep -q 'primary_and_secondary_rpc_exact_getter_match_at_deployment_block' "$DEPLOY_HELPER" "$FILTER"; then
  echo "Fresh-suite deployment must bind and independently read the intent and signed reviewer-genesis acceptance commitments." >&2
  exit 1
fi

for required_call in \
  'room.setComposeApprovalRequired(true)' \
  'room.setTeeIdentityApprovalRequired(true)' \
  'room.freezeApprovalRequirements()'; do
  if ! grep -Fq "$required_call" "$FRESH_SUITE"; then
    echo "Fresh DiligenceRoom must enable and freeze both TEE approval requirements." >&2
    exit 1
  fi
done

for diligence_authority_boundary in \
  'diligence result-verifier authority must start empty' \
  'diligence QVL authority must start empty' \
  'diligence evaluator-policy authority must start empty' \
  "'evaluatorPolicies()'" \
  "'approvedEvaluatorPolicyCount()(uint256)'" \
  "'pendingEvaluatorPolicyCount()(uint256)'" \
  "'evaluatorPolicySetRoot()(bytes32)'" \
  "'evaluatorPolicySetFrozen()(bool)'" \
  'fresh DiligenceRoom signer, QVL, or evaluator-policy authority is not exactly empty'; do
  if ! grep -Fq "$diligence_authority_boundary" "$FRESH_SUITE" "$DEPLOY_HELPER" "$FILTER"; then
    echo "Fresh DiligenceRoom authority proof is missing: $diligence_authority_boundary" >&2
    exit 1
  fi
done

for runtime_hash_var in \
  DILIGENCE_RUNTIME_CODE_HASH \
  ENCUMBRANCE_RUNTIME_CODE_HASH \
  ROYALTY_RUNTIME_CODE_HASH \
  CHALLENGE_RUNTIME_CODE_HASH \
  COMPUTE_VAULT_RUNTIME_CODE_HASH \
  EMAIL_ORACLE_RUNTIME_CODE_HASH \
  EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH; do
  if ! grep -q "^${runtime_hash_var}=" "$DEPLOY_HELPER"; then
    echo "Fresh-suite deployment must prove and record every contract runtime hash." >&2
    exit 1
  fi
done

if ! grep -q 'src/EmailOracleAuth.sol:EmailOracleAuth' "$DEPLOY_HELPER" \
  || ! grep -q 'src/ComputeCreditVault.sol:ComputeCreditVault' "$DEPLOY_HELPER" \
  || ! grep -q 'src/ExecutionPolicyAnchor.sol:ExecutionPolicyAnchor' "$DEPLOY_HELPER" \
  || ! grep -q 'dnai.basescan-verification-submission-receipt.v1' "$DEPLOY_HELPER" \
  || ! grep -q 'submitted_not_confirmed' "$DEPLOY_HELPER"; then
  echo "Fresh contract BaseScan submission evidence must remain separate from the immutable deployment manifest." >&2
  exit 1
fi

royalty_constructor_block="$(sed -n '/^  ROYALTY_CONSTRUCTOR_ARGS="\$(/,/^  )"/p' "$DEPLOY_HELPER")"
if [ "$(grep -Fc 'ROYALTY_CONSTRUCTOR_ARGS="$(' "$DEPLOY_HELPER")" -ne 1 ] \
  || [ "$(grep -Fc -- '--constructor-args "$ROYALTY_CONSTRUCTOR_ARGS"' "$DEPLOY_HELPER")" -ne 1 ] \
  || ! grep -Fq 'cast abi-encode '\''constructor(address)'\'' "$DEPLOYMENT_OPERATOR"' \
    <<<"$royalty_constructor_block" \
  || ! awk '
    /^[[:space:]]*forge verify-contract[[:space:]]*\\$/ {
      in_verification = 1
      royalty_args = 0
      next
    }
    in_verification && /--constructor-args "\$ROYALTY_CONSTRUCTOR_ARGS"/ {
      royalty_args = 1
    }
    in_verification && /src\/RoyaltyDistributor\.sol:RoyaltyDistributor/ {
      found = 1
      if (!royalty_args) exit 1
      in_verification = 0
    }
    END { if (!found) exit 1 }
  ' "$DEPLOY_HELPER"; then
  echo "RoyaltyDistributor BaseScan verification must bind constructor(address) to DEPLOYMENT_OPERATOR." >&2
  exit 1
fi

if [ "$(grep -Fc 'collect_broadcast_transaction ' "$DEPLOY_HELPER")" -ne 13 ] \
  || ! grep -Fq 'cast tx "$transaction_hash" --rpc-url "$RPC_URL" --json' "$DEPLOY_HELPER" \
  || ! grep -Fq 'cast receipt "$transaction_hash" --rpc-url "$RPC_URL" --json' "$DEPLOY_HELPER" \
  || ! grep -Fq -- '--argjson deploymentReceipts "$DEPLOYMENT_RECEIPTS"' "$DEPLOY_HELPER" \
  || ! grep -Fq -- '--argjson broadcastTransactions "$BROADCAST_TRANSACTIONS"' "$DEPLOY_HELPER"; then
  echo "Fresh-suite deployment must collect and pass all 13 mined transactions plus seven CREATE receipts." >&2
  exit 1
fi

if [ "$(grep -Ec '^[A-Z_]+_ADDRESS="\$\(artifact_contract_address [0-9]+ ' "$DEPLOY_HELPER")" -ne 7 ] \
  || [ "$(grep -Ec '^[A-Z_]+_TX="\$\(artifact_transaction_hash [0-9]+\)"' "$DEPLOY_HELPER")" -ne 7 ]; then
  echo "Fresh-suite CREATE addresses and transaction hashes must use exact ordered artifact indices." >&2
  exit 1
fi

dry_exit_line="$(grep -n -m1 'if \[ "$BROADCAST" != "true" \]' "$DEPLOY_HELPER" | cut -d: -f1)"
receipt_collection_line="$(grep -n -m1 '^collect_broadcast_transaction 0 diligenceRoom ' "$DEPLOY_HELPER" | cut -d: -f1)"
manifest_mutation_line="$(grep -n -m1 '^mkdir -p "$(dirname "$MANIFEST_PATH")"' "$DEPLOY_HELPER" | cut -d: -f1)"
if [ "$receipt_collection_line" -le "$dry_exit_line" ] \
  || [ "$receipt_collection_line" -ge "$manifest_mutation_line" ]; then
  echo "Confirmed receipts must be collected after the dry-run exit and before any manifest mutation." >&2
  exit 1
fi

for immutable_receipt_field in \
  deploymentTxFrom \
  deploymentReceiptStatus \
  deploymentReceiptContractAddress \
  deploymentBlock \
  deploymentBlockHash \
  creationInputSha256; do
  if [ "$(grep -Fc "$immutable_receipt_field:" "$FILTER")" -ne 14 ]; then
    echo "Fresh deployment ledger must record $immutable_receipt_field in history and current entries for seven contracts." >&2
    exit 1
  fi
done

for exact_release_boundary in \
  'git -C "$ROOT_DIR" worktree add --detach --quiet' \
  'status --porcelain=v1 --untracked-files=all --ignore-submodules=none' \
  'rev-parse --abbrev-ref HEAD' \
  'assert_source_checkout_exact "immediate pre-broadcast"' \
  'assert_source_checkout_exact "immediate post-broadcast"' \
  'fresh-contract-suites/$RELEASE_SHA/base-sepolia.json' \
  'historical deployments/base-sepolia.json ledger is not a fresh deployment authority' \
  'pre_broadcast_checkpoint_recovery_chain_inspection_required' \
  'inspect the signer nonce and Base Sepolia transaction history' \
  'abandoned_after_broadcast_validation_failure' \
  'validated_manifest_committed'; do
  if ! grep -Fq "$exact_release_boundary" "$DEPLOY_HELPER"; then
    echo "Fresh-suite helper is missing release snapshot, immutable output, or durable journal boundary: $exact_release_boundary" >&2
    exit 1
  fi
done

nonce_recheck_line="$(grep -n -m1 '^pre_broadcast_operator_nonce=' "$DEPLOY_HELPER" | cut -d: -f1)"
journal_init_line="$(grep -n -m1 '^initialize_broadcast_journal$' "$DEPLOY_HELPER" | cut -d: -f1)"
broadcast_started_line="$(grep -n -m1 '^BROADCAST_STARTED=true$' "$DEPLOY_HELPER" | cut -d: -f1)"
forge_broadcast_line="$(grep -n -m1 '^forge script script/DeployFreshSuite.s.sol:DeployFreshSuiteScript' "$DEPLOY_HELPER" | cut -d: -f1)"
manifest_publish_line="$(grep -n -m1 'durably_publish_json "$tmp_manifest" "$MANIFEST_PATH" create 0444' "$DEPLOY_HELPER" | cut -d: -f1)"
final_journal_line="$(grep -n -m1 '"validated_manifest_committed"' "$DEPLOY_HELPER" | cut -d: -f1)"
validated_flag_line="$(grep -n -m1 '^BROADCAST_VALIDATED=true$' "$DEPLOY_HELPER" | cut -d: -f1)"
if [ "$nonce_recheck_line" -ge "$journal_init_line" ] \
  || [ "$journal_init_line" -ge "$broadcast_started_line" ] \
  || [ "$broadcast_started_line" -ge "$forge_broadcast_line" ] \
  || [ "$manifest_publish_line" -ge "$final_journal_line" ] \
  || [ "$final_journal_line" -ge "$validated_flag_line" ] \
  || ! grep -Fq 'DEPLOYMENT_DURABILITY_FAULT_STAGE' "$DEPLOY_HELPER" \
  || ! grep -Fq 'durable-json-write.mjs' "$DEPLOY_HELPER"; then
  echo "Fresh-suite broadcast ordering must durably checkpoint before mutation and commit the immutable manifest before validation." >&2
  exit 1
fi

if ! grep -q 'use DeployFreshSuite for Base EmailOracleAuth releases' "$STANDALONE_EMAIL_ORACLE"; then
  echo "The standalone EmailOracleAuth script must reject Base release deployments." >&2
  exit 1
fi

if ! grep -q 'use DeployFreshSuite for Base TinkerAccountEncumbrance releases' "$STANDALONE_TINKER"; then
  echo "The standalone TinkerAccountEncumbrance script must reject Base release deployments." >&2
  exit 1
fi

if ! grep -q 'This compatibility shim never deploys, broadcasts, or mutates the deployment ledger.' "$TINKER_HELPER" \
  || ! grep -q 'exit 1' "$TINKER_HELPER"; then
  echo "The retired standalone Tinker Base helper must remain a fail-closed compatibility shim." >&2
  exit 1
fi

if grep -Eq 'forge[[:space:]]+script|cast[[:space:]]+send' "$TINKER_HELPER"; then
  echo "The retired standalone Tinker Base helper must not contain a deployment or transaction path." >&2
  exit 1
fi

if grep -q 'deploy-tinker-encumbrance-base-sepolia.sh' "$FUNDING_COMMAND_PLAN" \
  || ! grep -q 'deploy-base-sepolia.sh' "$FUNDING_COMMAND_PLAN" \
  || ! grep -q 'fresh_contract_suite_required' "$FUNDING_COMMAND_PLAN"; then
  echo "Funding command plans must route a missing Tinker contract through the canonical fresh suite." >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/input.json" <<'JSON'
{
  "schemaVersion": 2,
  "customField": {"mustSurvive": true},
  "network": {"chainId": 1, "customNetworkField": "must-survive"},
  "phala": {"cvmId": "preserve-me", "evidence": {"quote": "preserve-me-too"}},
  "contracts": {
    "emailOracleAuth": {"address": "preserve-email-auth"},
    "executionPolicyAnchor": {"address": "preserve-policy-anchor"},
    "computeCreditVault": {"address": "preserve-compute-vault"},
    "diligenceRoom": {"address": "previous-diligence"}
  },
  "freshDeployment": {"otherHelper": {"status": "preserve"}}
}
JSON

DEPLOYMENT_RECEIPTS_FIXTURE='{
  "diligenceRoom": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x3333333333333333333333333333333333333333",
    "deploymentBlock": 101,
    "deploymentBlockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "creationInputSha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "tinkerAccountEncumbrance": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x4444444444444444444444444444444444444444",
    "deploymentBlock": 102,
    "deploymentBlockHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "creationInputSha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  },
  "royaltyDistributor": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x5555555555555555555555555555555555555555",
    "deploymentBlock": 103,
    "deploymentBlockHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
    "creationInputSha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  },
  "challengeRegistry": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x6666666666666666666666666666666666666666",
    "deploymentBlock": 104,
    "deploymentBlockHash": "0x4444444444444444444444444444444444444444444444444444444444444444",
    "creationInputSha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  },
  "computeCreditVault": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x8888888888888888888888888888888888888888",
    "deploymentBlock": 105,
    "deploymentBlockHash": "0x5555555555555555555555555555555555555555555555555555555555555555",
    "creationInputSha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  },
  "emailOracleAuth": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x7777777777777777777777777777777777777777",
    "deploymentBlock": 106,
    "deploymentBlockHash": "0x6666666666666666666666666666666666666666666666666666666666666666",
    "creationInputSha256": "sha256:6666666666666666666666666666666666666666666666666666666666666666"
  },
  "executionPolicyAnchor": {
    "deploymentTxFrom": "0x1111111111111111111111111111111111111111",
    "deploymentReceiptStatus": "success",
    "deploymentReceiptContractAddress": "0x1212121212121212121212121212121212121212",
    "deploymentBlock": 107,
    "deploymentBlockHash": "0x7777777777777777777777777777777777777777777777777777777777777777",
    "creationInputSha256": "sha256:7777777777777777777777777777777777777777777777777777777777777777"
  }
}'

BROADCAST_TRANSACTIONS_FIXTURE="$(jq -cn '
  def tx($sequence; $key; $name; $type; $function; $hashByte; $to; $receiptAddress; $nonce; $inputNibble; $block; $blockHashByte):
    {
      sequence: $sequence,
      contractKey: $key,
      contractName: $name,
      transactionType: $type,
      functionSignature: $function,
      transactionHash: ("0x" + ($hashByte * 32)),
      transactionFrom: "0x1111111111111111111111111111111111111111",
      transactionTo: $to,
      transactionNonce: $nonce,
      transactionInputSha256: ("sha256:" + ($inputNibble * 64)),
      receiptStatus: "success",
      receiptContractAddress: $receiptAddress,
      blockNumber: $block,
      blockHash: ("0x" + ($blockHashByte * 32))
    };
  [
    tx(0;"diligenceRoom";"DiligenceRoom";"CREATE";"constructor(bool,address)";"01";null;"0x3333333333333333333333333333333333333333";20;"a";101;"11"),
    tx(1;"diligenceRoom";"DiligenceRoom";"CALL";"freezeFeeBps()";"08";"0x3333333333333333333333333333333333333333";null;21;"b";108;"88"),
    tx(2;"diligenceRoom";"DiligenceRoom";"CALL";"enableComputeSettlementPolicy()";"09";"0x3333333333333333333333333333333333333333";null;22;"c";109;"99"),
    tx(3;"diligenceRoom";"DiligenceRoom";"CALL";"setComposeApprovalRequired(bool)";"0a";"0x3333333333333333333333333333333333333333";null;23;"d";110;"aa"),
    tx(4;"diligenceRoom";"DiligenceRoom";"CALL";"setTeeIdentityApprovalRequired(bool)";"0b";"0x3333333333333333333333333333333333333333";null;24;"e";111;"bb"),
    tx(5;"diligenceRoom";"DiligenceRoom";"CALL";"freezeApprovalRequirements()";"0c";"0x3333333333333333333333333333333333333333";null;25;"f";112;"cc"),
    tx(6;"tinkerAccountEncumbrance";"TinkerAccountEncumbrance";"CREATE";"constructor(address,bytes32,bytes32,uint256,uint256)";"02";null;"0x4444444444444444444444444444444444444444";26;"1";102;"22"),
    tx(7;"royaltyDistributor";"RoyaltyDistributor";"CREATE";"constructor(address)";"03";null;"0x5555555555555555555555555555555555555555";27;"2";103;"33"),
    tx(8;"challengeRegistry";"ChallengeRegistry";"CREATE";"constructor(address)";"04";null;"0x6666666666666666666666666666666666666666";28;"3";104;"44"),
    tx(9;"computeCreditVault";"ComputeCreditVault";"CREATE";"constructor(address,address,uint16)";"06";null;"0x8888888888888888888888888888888888888888";29;"4";105;"55"),
    tx(10;"computeCreditVault";"ComputeCreditVault";"CALL";"freezeDeveloperFee()";"0d";"0x8888888888888888888888888888888888888888";null;30;"5";113;"dd"),
    tx(11;"emailOracleAuth";"EmailOracleAuth";"CREATE";"constructor(address,uint256,bool,bytes32,bytes32,bool)";"05";null;"0x7777777777777777777777777777777777777777";31;"6";106;"66"),
    tx(12;"executionPolicyAnchor";"ExecutionPolicyAnchor";"CREATE";"constructor(address,bytes32,bytes32)";"07";null;"0x1212121212121212121212121212121212121212";32;"7";107;"77")
  ]
')"

jq \
  --arg deployedAt "2026-01-01T00:00:00Z" \
  --arg operator "0x1111111111111111111111111111111111111111" \
  --arg verifier "0x0000000000000000000000000000000000000000" \
  --arg sourceCommit "0123456789abcdef" \
  --arg deploymentIntentSha256 "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" \
  --arg reviewerAuthorityGenesisAcceptanceSha256 "sha256:e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1" \
  --arg tinkerAccountBindingCeremonyReceiptSha256 "sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1" \
  --arg deploymentReviewEnvelopeSha256 "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1" \
  --arg deploymentReviewEvidenceSha256 "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1" \
  --argjson deploymentReceipts "$DEPLOYMENT_RECEIPTS_FIXTURE" \
  --argjson broadcastTransactions "$BROADCAST_TRANSACTIONS_FIXTURE" \
  --arg broadcastTransactionsSha256 "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" \
  --arg diligence "0x3333333333333333333333333333333333333333" \
  --arg diligenceTx "0x0101010101010101010101010101010101010101010101010101010101010101" \
  --arg diligenceRuntimeCodeHash "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" \
  --arg diligenceDeveloper "0x1111111111111111111111111111111111111111" \
  --arg diligenceInitialDeveloper "0x1111111111111111111111111111111111111111" \
  --arg diligenceGovernanceController "0x2222222222222222222222222222222222222222" \
  --arg diligenceReleaseGovernanceController "0x2222222222222222222222222222222222222222" \
  --arg diligenceProtocolFeeRecipient "0x2222222222222222222222222222222222222222" \
  --arg diligencePendingDeveloper "0x0000000000000000000000000000000000000000" \
  --arg diligencePendingDeveloperAt "0" \
  --arg diligenceDeveloperTransferDelay "172800" \
  --argjson diligenceProductionRelease true \
  --arg diligenceDealCount "0" \
  --arg diligencePendingVerifier "0x0000000000000000000000000000000000000000" \
  --arg diligencePendingVerifierAt "0" \
  --argjson diligenceVerifierFrozen false \
  --arg diligenceAttestationVerifier "0x0000000000000000000000000000000000000000" \
  --arg diligenceAttestationPolicyHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg diligencePendingAttestationVerifier "0x0000000000000000000000000000000000000000" \
  --arg diligencePendingAttestationPolicyHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg diligencePendingAttestationAt "0" \
  --argjson diligenceAttestationBindingFrozen false \
  --arg diligenceEvaluatorPoliciesAbi "0x$(printf '0%.0s' {1..192})" \
  --arg diligenceApprovedEvaluatorPolicyCount "0" \
  --arg diligencePendingEvaluatorPolicyCount "0" \
  --arg diligenceEvaluatorPolicySetRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson diligenceEvaluatorPolicySetFrozen false \
  --arg diligenceRequiredEvaluatorPolicyCount "3" \
  --argjson diligenceComposeRequired true \
  --argjson diligenceIdentityRequired true \
  --argjson diligenceApprovalRequirementsFrozen true \
  --arg diligenceApprovedComposeCount "0" \
  --arg diligenceApprovedTeeCount "0" \
  --arg diligencePendingComposeCount "0" \
  --arg diligencePendingTeeCount "0" \
  --argjson diligenceComposeAdditionsFrozen false \
  --argjson diligenceTeeAdditionsFrozen false \
  --arg diligenceFeeBps "100" \
  --argjson diligenceFeeBpsFrozen true \
  --arg diligenceComputeSettlementBps "100" \
  --argjson diligenceComputeSettlementPolicyEnabled true \
  --arg encumbrance "0x4444444444444444444444444444444444444444" \
  --arg encumbranceTx "0x0202020202020202020202020202020202020202020202020202020202020202" \
  --arg encumbranceRuntimeCodeHash "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" \
  --arg encumbrancePendingOwner "0x0000000000000000000000000000000000000000" \
  --arg accountCommitment "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --arg maxAddBalanceWei "9007199254740993" \
  --arg maxSpendWei "115792089237316195423570985008687907853269984665640564039457584007913129639935" \
  --arg encumbranceComposeRoot "0xc1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1" \
  --arg encumbranceComposeCount "0" \
  --arg encumbranceManagerRoot "0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" \
  --arg encumbranceManagerCount "0" \
  --arg encumbranceReleaseCommitment "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbranceReleaseMaxAddBalanceWei "0" \
  --arg encumbranceReleaseMaxSpendWei "0" \
  --arg encumbranceReleaseComposeRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbranceReleaseComposeCount "0" \
  --arg encumbranceReleaseManagerRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbranceReleaseManagerCount "0" \
  --arg encumbrancePendingAccountCommitment "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbrancePendingMaxAddBalanceWei "0" \
  --arg encumbrancePendingMaxSpendWei "0" \
  --arg encumbrancePendingComposeRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbrancePendingManagerRoot "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbrancePendingCommitment "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg encumbrancePendingAt "0" \
  --arg encumbrancePendingComposeCount "0" \
  --arg encumbrancePendingManagerCount "0" \
  --argjson encumbranceReleasePolicyFrozen false \
  --argjson encumbranceEmergencyHalted true \
  --arg royalty "0x5555555555555555555555555555555555555555" \
  --arg royaltyTx "0x0303030303030303030303030303030303030303030303030303030303030303" \
  --arg royaltyRuntimeCodeHash "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  --arg royaltyOwner "0x1111111111111111111111111111111111111111" \
  --arg royaltyPendingOwner "0x0000000000000000000000000000000000000000" \
  --argjson royaltyPaused true \
  --arg royaltySettlementVerifier "0x0000000000000000000000000000000000000000" \
  --arg royaltyQvlVerifier "0x0000000000000000000000000000000000000000" \
  --arg royaltyExecutionPolicyAnchor "0x0000000000000000000000000000000000000000" \
  --arg royaltyAnchorWriterRelease "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg royaltyReleasePolicy "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg royaltyAuthorityNonce "0" \
  --arg royaltyPendingAuthorityAt "0" \
  --arg challenge "0x6666666666666666666666666666666666666666" \
  --arg challengeTx "0x0404040404040404040404040404040404040404040404040404040404040404" \
  --arg challengeRuntimeCodeHash "0x9999999999999999999999999999999999999999999999999999999999999999" \
  --arg challengePendingOwner "0x0000000000000000000000000000000000000000" \
  --arg challengeNextId "1" \
  --arg challengeMinVersionReviewDelay "172800" \
  --arg computeVault "0x8888888888888888888888888888888888888888" \
  --arg computeVaultTx "0x0606060606060606060606060606060606060606060606060606060606060606" \
  --arg computeVaultRuntimeCodeHash "0xabababababababababababababababababababababababababababababababab" \
  --arg computeVaultOwner "0x1111111111111111111111111111111111111111" \
  --arg computeVaultDeveloper "0x9999999999999999999999999999999999999999" \
  --arg computeVaultMeteringVerifier "0x0000000000000000000000000000000000000000" \
  --arg computeVaultMeteringQvlVerifier "0x0000000000000000000000000000000000000000" \
  --arg computeVaultMeteringPolicySetHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg computeVaultPendingMeteringVerifier "0x0000000000000000000000000000000000000000" \
  --arg computeVaultPendingMeteringQvlVerifier "0x0000000000000000000000000000000000000000" \
  --arg computeVaultPendingMeteringPolicySetHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg computeVaultPendingMeteringAt "0" \
  --argjson computeVaultMeteringBindingFrozen false \
  --argjson computeVaultPaused true \
  --arg computeVaultFeeBps "100" \
  --argjson computeVaultFeeFrozen true \
  --arg computeVaultAllowedAssetCount "0" \
  --arg computeVaultActiveRateCount "0" \
  --arg computeVaultApprovedComposeCount "0" \
  --arg computeVaultApprovedTeeCount "0" \
  --arg computeVaultPendingAssetCount "0" \
  --arg computeVaultPendingRateCount "0" \
  --arg computeVaultPendingComposeCount "0" \
  --arg computeVaultPendingTeeCount "0" \
  --argjson computeVaultComposePolicyFrozen false \
  --argjson computeVaultTeeAdditionsFrozen false \
  --argjson computeVaultRateAdditionsFrozen false \
  --argjson computeVaultAssetAdditionsFrozen false \
  --arg emailOracle "0x7777777777777777777777777777777777777777" \
  --arg emailOracleTx "0x0505050505050505050505050505050505050505050505050505050505050505" \
  --arg emailOracleOwner "0x1111111111111111111111111111111111111111" \
  --arg emailOraclePendingOwner "0x0000000000000000000000000000000000000000" \
  --argjson emailOracleProductionRelease true \
  --arg emailOracleDelay "172800" \
  --argjson emailOracleAllowAny false \
  --argjson emailOracleCodeFrozen false \
  --argjson emailOracleConsumersFrozen false \
  --argjson emailOracleManagerAdditionsFrozen false \
  --argjson emailOracleKmsFrozen false \
  --arg emailOracleAllowedComposeCount "0" \
  --arg emailOraclePendingComposeCount "0" \
  --arg emailOracleAllowedDeviceCount "0" \
  --arg emailOracleManagerCount "0" \
  --arg emailOracleConsumerComposeCount "0" \
  --arg emailOracleReleaseCompose "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleReleaseDevice "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleReleaseManager "0x0000000000000000000000000000000000000000" \
  --arg emailOracleReleaseApp "0x0000000000000000000000000000000000000000" \
  --arg emailOracleReleaseConsumerCompose "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleKmsContract "0x0000000000000000000000000000000000000000" \
  --arg emailOracleKmsRuntimeHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleKmsImplementation "0x0000000000000000000000000000000000000000" \
  --arg emailOracleKmsImplementationRuntimeHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleKmsRegistrationTx "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleKmsRegistrationBlock "0" \
  --arg emailOracleKmsRegistrationBlockHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleBootInfoHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg emailOracleRestartProofHash "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson emailOracleReleaseReady false \
  --arg emailOracleRuntimeCodeHash "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
  --arg executionPolicyAnchor "0x1212121212121212121212121212121212121212" \
  --arg executionPolicyAnchorTx "0x0707070707070707070707070707070707070707070707070707070707070707" \
  --arg executionPolicyAnchorRuntimeCodeHash "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" \
  --arg executionPolicyAnchorDeploymentIntentSha256Bytes32 "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" \
  --arg executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32 "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1" \
  --arg executionPolicyAnchorAuthorityCommitmentReadProof "primary_and_secondary_rpc_exact_getter_match_at_deployment_block" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlock "107" \
  --arg executionPolicyAnchorAuthorityCommitmentReadBlockHash "0x7777777777777777777777777777777777777777777777777777777777777777" \
  --arg executionPolicyAnchorOwner "0x1111111111111111111111111111111111111111" \
  --arg executionPolicyAnchorWriter "0x0000000000000000000000000000000000000000" \
  --arg executionPolicyAnchorWriterRelease "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg executionPolicyAnchorPendingWriter "0x0000000000000000000000000000000000000000" \
  --arg executionPolicyAnchorPendingRelease "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg executionPolicyAnchorPendingAt "0" \
  --argjson executionPolicyAnchorRotationsFrozen false \
  --argjson executionPolicyAnchorPaused true \
  --arg executionPolicyAnchorGlobalSequence "0" \
  --arg executionPolicyAnchorGlobalHead "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --argjson verificationRequested false \
  -f "$FILTER" \
  "$tmp_dir/input.json" > "$tmp_dir/output.json"

jq -e \
  --argjson deploymentReceipts "$DEPLOYMENT_RECEIPTS_FIXTURE" \
  --argjson broadcastTransactions "$BROADCAST_TRANSACTIONS_FIXTURE" '
  def receipt_fields: {
    deploymentTxFrom,
    deploymentReceiptStatus,
    deploymentReceiptContractAddress,
    deploymentBlock,
    deploymentBlockHash,
    creationInputSha256
  };
  . as $manifest
  | .schemaVersion == 2
  and (.notAuthorityForFreshRelease // false) == false
  and (.supersededBoundary? == null)
  and .customField.mustSurvive == true
  and .network.chainId == 84532
  and .network.customNetworkField == "must-survive"
  and .phala.cvmId == "preserve-me"
  and .phala.evidence.quote == "preserve-me-too"
  and .deploymentHistory[-1].previousCurrentContracts.diligenceRoom.address == "previous-diligence"
  and .deploymentHistory[-1].previousCurrentContracts.emailOracleAuth.address == "preserve-email-auth"
  and .deploymentHistory[-1].previousCurrentContracts.computeCreditVault.address == "preserve-compute-vault"
  and .deploymentHistory[-1].previousCurrentContracts.executionPolicyAnchor.address == "preserve-policy-anchor"
  and .deploymentHistory[-1].exactCreationInputProof == "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts"
  and .deploymentHistory[-1].broadcastTransactionProof == "exact_ordered_13_transaction_receipts_with_consecutive_nonces"
  and .deploymentHistory[-1].broadcastTransactionCount == 13
  and .deploymentHistory[-1].broadcastTransactionsSha256 == "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  and .deploymentHistory[-1].broadcastTransactions == $broadcastTransactions
  and ([
    $deploymentReceipts
    | to_entries[]
    | . as $expected
    | ($manifest.contracts[$expected.key] | receipt_fields) == $expected.value
  ] | all)
  and ([
    $deploymentReceipts
    | to_entries[]
    | . as $expected
    | ($manifest.deploymentHistory[-1].deployedContracts[$expected.key] | receipt_fields) == $expected.value
  ] | all)
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.feeBps == 100
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.productionRelease == true
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.dealCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.feeBpsFrozen == true
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.runtimeCodeHash == "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.initialDeveloper == "0x1111111111111111111111111111111111111111"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.releaseGovernanceController == "0x2222222222222222222222222222222222222222"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.protocolFeeRecipient == "0x2222222222222222222222222222222222222222"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.resultVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingResultVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingResultVerifierActivatesAt == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.resultVerifierFrozen == false
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.attestationVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.attestationReleasePolicyHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingAttestationVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingAttestationReleasePolicyHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingAttestationBindingActivatesAt == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.attestationBindingFrozen == false
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.evaluatorPolicyCommitments == []
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.evaluatorPolicySetRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.approvedEvaluatorPolicyCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingEvaluatorPolicyCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.evaluatorPolicySetFrozen == false
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingEvaluatorPolicyProposals == []
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.requiredEvaluatorPolicyCount == 3
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.composeApprovalRequired == true
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.teeIdentityApprovalRequired == true
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.approvalRequirementsFrozen == true
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.approvedComposeCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.approvedTeeIdentityCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingComposeCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.pendingTeeIdentityCount == 0
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.composeAdditionsFrozen == false
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.teeIdentityAdditionsFrozen == false
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.initialApprovedComposeHashes == []
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.initialApprovedTeeIdentities == []
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.policyState == "fail_closed_pending_cvm_binding"
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.computeSettlementBps == 100
  and .deploymentHistory[-1].deployedContracts.diligenceRoom.computeSettlementPolicyEnabled == true
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.runtimeCodeHash == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.status == "deployed_halted_draft_pending_timelocked_release_policy"
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.maxAddBalanceWei == "9007199254740993"
  and (.deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.maxSpendWei | type) == "string"
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.approvedComposeHashes == []
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.approvedComposeCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.managerCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.releaseComposeCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.releaseManagerCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.pendingComposeCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.pendingManagerCount == 0
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.releasePolicyFrozen == false
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.emergencyHalted == true
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.perOperationCaps == true
  and .deploymentHistory[-1].deployedContracts.tinkerAccountEncumbrance.custodiesFunds == false
  and .deploymentHistory[-1].deployedContracts.royaltyDistributor.runtimeCodeHash == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  and .deploymentHistory[-1].deployedContracts.challengeRegistry.runtimeCodeHash == "0x9999999999999999999999999999999999999999999999999999999999999999"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.address == "0x8888888888888888888888888888888888888888"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.runtimeCodeHash == "0xabababababababababababababababababababababababababababababababab"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.meteringVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.meteringQvlVerifier == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.meteringPolicySetHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.meteringBindingFrozen == false
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.paused == true
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.developerFeeBps == 100
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.developerFeeFrozen == true
  and .deploymentHistory[-1].deployedContracts.computeCreditVault.policyState == "execution_fail_closed_pending_timelocked_release_binding"
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.address == "0x7777777777777777777777777777777777777777"
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.productionRelease == true
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.status == "deployed_deny_all_pending_cvm_binding"
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.oracleUpgradeDelaySeconds == 172800
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.allowAnyDevice == false
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.consumerManagerAdditionsFrozen == false
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.kmsBindingFrozen == false
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.releaseConfigurationReady == false
  and .deploymentHistory[-1].deployedContracts.emailOracleAuth.runtimeCodeHash == "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.address == "0x1212121212121212121212121212121212121212"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.runtimeCodeHash == "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.deploymentIntentSha256Bytes32 == "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.reviewerAuthorityGenesisAcceptanceSha256Bytes32 == "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.authorityCommitmentReadProof == "primary_and_secondary_rpc_exact_getter_match_at_deployment_block"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.authorityCommitmentReadBlock == 107
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.authorityCommitmentReadBlockHash == "0x7777777777777777777777777777777777777777777777777777777777777777"
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.paused == true
  and .deploymentHistory[-1].deployedContracts.executionPolicyAnchor.globalSequence == 0
  and .contracts.diligenceRoom.feeBps == 100
  and .contracts.diligenceRoom.productionRelease == true
  and .contracts.diligenceRoom.dealCount == 0
  and .contracts.diligenceRoom.status == "deployed_fail_closed_pending_tee_binding"
  and .contracts.diligenceRoom.feeBpsFrozen == true
  and .contracts.diligenceRoom.runtimeCodeHash == "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  and .contracts.diligenceRoom.developer == "0x1111111111111111111111111111111111111111"
  and .contracts.diligenceRoom.initialDeveloper == "0x1111111111111111111111111111111111111111"
  and .contracts.diligenceRoom.releaseGovernanceController == "0x2222222222222222222222222222222222222222"
  and .contracts.diligenceRoom.protocolFeeRecipient == "0x2222222222222222222222222222222222222222"
  and .contracts.diligenceRoom.pendingDeveloper == "0x0000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingDeveloperActivatesAt == 0
  and .contracts.diligenceRoom.developerTransferDelaySeconds == 172800
  and .contracts.diligenceRoom.governanceHandoffStatus == "pending_final_authority_and_release_ceremony"
  and .contracts.diligenceRoom.resultVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingResultVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingResultVerifierActivatesAt == 0
  and .contracts.diligenceRoom.resultVerifierFrozen == false
  and .contracts.diligenceRoom.attestationVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.attestationReleasePolicyHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingAttestationVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingAttestationReleasePolicyHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.pendingAttestationBindingActivatesAt == 0
  and .contracts.diligenceRoom.attestationBindingFrozen == false
  and .contracts.diligenceRoom.evaluatorPolicyCommitments == []
  and .contracts.diligenceRoom.evaluatorPolicySetRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.diligenceRoom.approvedEvaluatorPolicyCount == 0
  and .contracts.diligenceRoom.pendingEvaluatorPolicyCount == 0
  and .contracts.diligenceRoom.evaluatorPolicySetFrozen == false
  and .contracts.diligenceRoom.pendingEvaluatorPolicyProposals == []
  and .contracts.diligenceRoom.requiredEvaluatorPolicyCount == 3
  and .contracts.diligenceRoom.composeApprovalRequired == true
  and .contracts.diligenceRoom.teeIdentityApprovalRequired == true
  and .contracts.diligenceRoom.approvalRequirementsFrozen == true
  and .contracts.diligenceRoom.approvedComposeCount == 0
  and .contracts.diligenceRoom.approvedTeeIdentityCount == 0
  and .contracts.diligenceRoom.pendingComposeCount == 0
  and .contracts.diligenceRoom.pendingTeeIdentityCount == 0
  and .contracts.diligenceRoom.composeAdditionsFrozen == false
  and .contracts.diligenceRoom.teeIdentityAdditionsFrozen == false
  and .contracts.diligenceRoom.initialApprovedComposeHashes == []
  and .contracts.diligenceRoom.initialApprovedTeeIdentities == []
  and .contracts.diligenceRoom.policyState == "fail_closed_pending_cvm_binding"
  and .contracts.diligenceRoom.computeSettlementBps == 100
  and .contracts.diligenceRoom.computeSettlementPolicyEnabled == true
  and .contracts.tinkerAccountEncumbrance.runtimeCodeHash == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  and .contracts.tinkerAccountEncumbrance.status == "deployed_halted_draft_pending_timelocked_release_policy"
  and .contracts.tinkerAccountEncumbrance.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.maxAddBalanceWei == "9007199254740993"
  and (.contracts.tinkerAccountEncumbrance.maxAddBalanceWei | type) == "string"
  and .contracts.tinkerAccountEncumbrance.maxSpendWei == "115792089237316195423570985008687907853269984665640564039457584007913129639935"
  and (.contracts.tinkerAccountEncumbrance.maxSpendWei | type) == "string"
  and .contracts.tinkerAccountEncumbrance.initialComposeHash == null
  and .contracts.tinkerAccountEncumbrance.initialComposeHashApproved == false
  and .contracts.tinkerAccountEncumbrance.approvedComposeHashes == []
  and .contracts.tinkerAccountEncumbrance.approvedComposeRoot == "0xc1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
  and .contracts.tinkerAccountEncumbrance.approvedComposeCount == 0
  and .contracts.tinkerAccountEncumbrance.managerRoot == "0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
  and .contracts.tinkerAccountEncumbrance.managerCount == 0
  and .contracts.tinkerAccountEncumbrance.managers == []
  and .contracts.tinkerAccountEncumbrance.releasePolicyCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.releaseMaxAddBalanceWei == "0"
  and .contracts.tinkerAccountEncumbrance.releaseMaxSpendWei == "0"
  and .contracts.tinkerAccountEncumbrance.releaseComposeHashes == []
  and .contracts.tinkerAccountEncumbrance.releaseComposeRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.releaseComposeCount == 0
  and .contracts.tinkerAccountEncumbrance.releaseManagers == []
  and .contracts.tinkerAccountEncumbrance.releaseManagerRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.releaseManagerCount == 0
  and .contracts.tinkerAccountEncumbrance.pendingAccountCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.pendingMaxAddBalanceWei == "0"
  and .contracts.tinkerAccountEncumbrance.pendingMaxSpendWei == "0"
  and .contracts.tinkerAccountEncumbrance.pendingComposeHashes == []
  and .contracts.tinkerAccountEncumbrance.pendingComposeRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.pendingComposeCount == 0
  and .contracts.tinkerAccountEncumbrance.pendingManagers == []
  and .contracts.tinkerAccountEncumbrance.pendingManagerRoot == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.pendingManagerCount == 0
  and .contracts.tinkerAccountEncumbrance.pendingReleasePolicyCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.tinkerAccountEncumbrance.pendingReleasePolicyActivatesAt == 0
  and .contracts.tinkerAccountEncumbrance.releasePolicyFrozen == false
  and .contracts.tinkerAccountEncumbrance.emergencyHalted == true
  and .contracts.tinkerAccountEncumbrance.perOperationCaps == true
  and .contracts.tinkerAccountEncumbrance.custodiesFunds == false
  and .contracts.tinkerAccountEncumbrance.policyState == "operations_fail_closed_pending_exact_timelocked_release_policy"
  and .contracts.challengeRegistry.userCustody == false
  and .contracts.challengeRegistry.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .contracts.challengeRegistry.nextChallengeId == 1
  and .contracts.challengeRegistry.minimumVersionReviewDelaySeconds == 172800
  and .contracts.challengeRegistry.runtimeCodeHash == "0x9999999999999999999999999999999999999999999999999999999999999999"
  and .contracts.computeCreditVault.status == "deployed_paused_fee_frozen_unbound_pending_release_binding"
  and .contracts.computeCreditVault.address == "0x8888888888888888888888888888888888888888"
  and .contracts.computeCreditVault.owner == "0x1111111111111111111111111111111111111111"
  and .contracts.computeCreditVault.developer == "0x9999999999999999999999999999999999999999"
  and .contracts.computeCreditVault.meteringVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.meteringQvlVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.meteringPolicySetHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.pendingMeteringVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.pendingMeteringQvlVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.pendingMeteringPolicySetHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.computeCreditVault.pendingMeteringBindingActivatesAt == 0
  and .contracts.computeCreditVault.meteringBindingFrozen == false
  and .contracts.computeCreditVault.paused == true
  and .contracts.computeCreditVault.developerFeeBps == 100
  and .contracts.computeCreditVault.developerFeeFrozen == true
  and .contracts.computeCreditVault.approvedComposeCount == 0
  and .contracts.computeCreditVault.approvedTeeIdentityCount == 0
  and .contracts.computeCreditVault.pendingAssetCount == 0
  and .contracts.computeCreditVault.pendingRatePolicyCount == 0
  and .contracts.computeCreditVault.pendingComposeCount == 0
  and .contracts.computeCreditVault.pendingTeeIdentityCount == 0
  and .contracts.computeCreditVault.approvedComposeHashes == []
  and .contracts.computeCreditVault.approvedTeeIdentities == []
  and .contracts.computeCreditVault.activeRatePolicies == []
  and .contracts.computeCreditVault.enabledErc20Assets == []
  and .contracts.computeCreditVault.nativeFundingSupported == true
  and .contracts.computeCreditVault.creditsTransferable == false
  and .contracts.computeCreditVault.priceOracle == false
  and .contracts.computeCreditVault.policyState == "execution_fail_closed_pending_timelocked_release_binding"
  and .contracts.computeCreditVault.runtimeCodeHash == "0xabababababababababababababababababababababababababababababababab"
  and .contracts.royaltyDistributor.status == "deployed_paused_unbound_pending_royalty_release"
  and .contracts.royaltyDistributor.owner == "0x1111111111111111111111111111111111111111"
  and .contracts.royaltyDistributor.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .contracts.royaltyDistributor.paused == true
  and .contracts.royaltyDistributor.settlementVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.royaltyDistributor.qvlVerifier == "0x0000000000000000000000000000000000000000"
  and .contracts.royaltyDistributor.executionPolicyAnchor == "0x0000000000000000000000000000000000000000"
  and .contracts.royaltyDistributor.releasePolicyCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.royaltyDistributor.authorityNonce == 0
  and .contracts.royaltyDistributor.pendingAuthorityActivatesAt == 0
  and .contracts.royaltyDistributor.settlementReplayDomain == "global_settlement_id_and_global_settlement_nonce"
  and .contracts.royaltyDistributor.runtimeCodeHash == "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  and .contracts.emailOracleAuth.status == "deployed_deny_all_pending_cvm_binding"
  and .contracts.emailOracleAuth.productionRelease == true
  and .contracts.emailOracleAuth.owner == "0x1111111111111111111111111111111111111111"
  and .contracts.emailOracleAuth.oracleUpgradeDelaySeconds == 172800
  and .contracts.emailOracleAuth.allowAnyDevice == false
  and .contracts.emailOracleAuth.oracleCodeFrozen == false
  and .contracts.emailOracleAuth.consumerRegistryFrozen == false
  and .contracts.emailOracleAuth.pendingOwner == "0x0000000000000000000000000000000000000000"
  and .contracts.emailOracleAuth.consumerManagerAdditionsFrozen == false
  and .contracts.emailOracleAuth.kmsBindingFrozen == false
  and .contracts.emailOracleAuth.allowedOracleComposeHashCount == 0
  and .contracts.emailOracleAuth.pendingOracleComposeHashCount == 0
  and .contracts.emailOracleAuth.allowedDeviceIdCount == 0
  and .contracts.emailOracleAuth.consumerManagerCount == 0
  and .contracts.emailOracleAuth.totalConsumerComposeHashCount == 0
  and .contracts.emailOracleAuth.releaseOracleComposeHash == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.emailOracleAuth.kmsContract == "0x0000000000000000000000000000000000000000"
  and .contracts.emailOracleAuth.kmsRegistrationBlock == 0
  and .contracts.emailOracleAuth.releaseConfigurationReady == false
  and .contracts.emailOracleAuth.initialOracleComposeHash == null
  and .contracts.emailOracleAuth.initialDeviceId == null
  and .contracts.emailOracleAuth.initialConsumerBindings == []
  and .contracts.emailOracleAuth.policyState == "deny_all_pending_cvm_binding"
  and .contracts.emailOracleAuth.runtimeCodeHash == "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  and .contracts.emailOracleAuth.sourceCommit == "0123456789abcdef"
  and .contracts.executionPolicyAnchor.status == "deployed_paused_writer_unset_pending_timelocked_release_binding"
  and .contracts.executionPolicyAnchor.address == "0x1212121212121212121212121212121212121212"
  and .contracts.executionPolicyAnchor.owner == "0x1111111111111111111111111111111111111111"
  and .contracts.executionPolicyAnchor.writer == "0x0000000000000000000000000000000000000000"
  and .contracts.executionPolicyAnchor.writerReleaseCommitment == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.executionPolicyAnchor.writerRotationDelaySeconds == 172800
  and .contracts.executionPolicyAnchor.writerRotationsFrozen == false
  and .contracts.executionPolicyAnchor.paused == true
  and .contracts.executionPolicyAnchor.globalSequence == 0
  and .contracts.executionPolicyAnchor.globalHead == "0x0000000000000000000000000000000000000000000000000000000000000000"
  and .contracts.executionPolicyAnchor.opaqueCommitmentsOnly == true
  and .contracts.executionPolicyAnchor.resourceAndDecisionPayloadsOnChain == false
  and .contracts.executionPolicyAnchor.policyState == "anchoring_fail_closed_pending_timelocked_release_writer"
  and .contracts.executionPolicyAnchor.runtimeCodeHash == "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  and .contracts.executionPolicyAnchor.deploymentIntentSha256Bytes32 == "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
  and .contracts.executionPolicyAnchor.reviewerAuthorityGenesisAcceptanceSha256Bytes32 == "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
  and .contracts.executionPolicyAnchor.authorityCommitmentReadProof == "primary_and_secondary_rpc_exact_getter_match_at_deployment_block"
  and .contracts.executionPolicyAnchor.authorityCommitmentReadBlock == 107
  and .contracts.executionPolicyAnchor.authorityCommitmentReadBlockHash == "0x7777777777777777777777777777777777777777777777777777777777777777"
  and .freshDeployment.otherHelper.status == "preserve"
  and .freshDeployment.contractSuite.keystoreAccount == "dev"
  and .freshDeployment.contractSuite.exactCreationInputProof == "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts"
  and .freshDeployment.contractSuite.broadcastTransactionProof == "exact_ordered_13_transaction_receipts_with_consecutive_nonces"
  and .freshDeployment.contractSuite.broadcastTransactionCount == 13
  and .freshDeployment.contractSuite.broadcastTransactionsSha256 == "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  and .freshDeployment.contractSuite.broadcastTransactions == $broadcastTransactions
  and .freshDeployment.contractSuite.deploymentIntentSha256 == "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
  and .freshDeployment.contractSuite.reviewerAuthorityGenesisAcceptanceSha256 == "sha256:e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
  and .freshDeployment.contractSuite.tinkerAccountBindingCeremonyReceiptSha256 == "sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
  and .freshDeployment.contractSuite.deploymentReviewEnvelopeSha256 == "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
  and .freshDeployment.contractSuite.deploymentReviewEvidenceSha256 == "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
  and .freshDeployment.contractSuite.authorityStage == "deployment_intent_review_only"
  and .freshDeployment.contractSuite.deploymentReviewSemantics == "out_of_band_review_declaration_not_signature_verified"
  and .freshDeployment.contractSuite.cvmEvidenceStatus == "not_available_at_fresh_contract_broadcast"
  and (.freshDeployment.contractSuite | has("operatorPolicyPacketSha256") | not)
  and (.freshDeployment.contractSuite | has("finalAuthoritySha256") | not)
  and (.freshDeployment.contractSuite | has("reviewEnvelopeSha256") | not)
  and .freshDeployment.contractSuite.emailOraclePolicyState == "deny_all_pending_cvm_binding"
  and .freshDeployment.contractSuite.diligencePolicyState == "fail_closed_pending_cvm_binding"
  and .freshDeployment.contractSuite.computeVaultPolicyState == "execution_fail_closed_pending_timelocked_release_binding"
  and .freshDeployment.contractSuite.executionPolicyAnchorState == "anchoring_fail_closed_pending_timelocked_release_writer"
  and .freshDeployment.contractSuite.includesReviewedComputeCreditVault == true
  and .freshDeployment.contractSuite.excludesChallengePrizeAndCandidateCustodyContracts == true
  and .freshDeployment.contractSuite.runtimeCodeProof == "exact_creation_reexecution_match_all_contracts"
  and .freshDeployment.contractSuite.verificationStatus == "not_requested"
  and .deploymentHistory[-1].deploymentIntentSha256 == "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
  and .deploymentHistory[-1].reviewerAuthorityGenesisAcceptanceSha256 == "sha256:e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
  and .deploymentHistory[-1].tinkerAccountBindingCeremonyReceiptSha256 == "sha256:f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
  and .deploymentHistory[-1].deploymentReviewEnvelopeSha256 == "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
  and .deploymentHistory[-1].deploymentReviewEvidenceSha256 == "sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
  and .deploymentHistory[-1].authorityStage == "deployment_intent_review_only"
  and .deploymentHistory[-1].deploymentReviewSemantics == "out_of_band_review_declaration_not_signature_verified"
  and .deploymentHistory[-1].cvmEvidenceStatus == "not_available_at_fresh_contract_broadcast"
  and (.deploymentHistory[-1] | has("operatorPolicyPacketSha256") | not)
  and (.deploymentHistory[-1] | has("finalAuthoritySha256") | not)
  and (.deploymentHistory[-1] | has("reviewEnvelopeSha256") | not)
  and .deploymentHistory[-1].verificationStatus == "not_requested"
' "$tmp_dir/output.json" >/dev/null

echo "Deployment helper syntax, keystore policy, and merge preservation checks passed."
