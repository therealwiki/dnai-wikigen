#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
HELPER="$SCRIPT_DIR/configure-royalty-release.sh"
PHASE_PLAN="$SCRIPT_DIR/royalty-release-phase-plan.mjs"
FINALITY_HELPER="$SCRIPT_DIR/royalty-release-finality.mjs"
LEDGER_BINDING_HELPER="$SCRIPT_DIR/royalty-release-ledger-binding.mjs"
LEDGER_BINDING_TEST="$SCRIPT_DIR/royalty-release-ledger-binding.test.mjs"
MANIFEST_FILTER="$SCRIPT_DIR/update-royalty-release-manifest.jq"
GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
INITIALIZER="$SCRIPT_DIR/initialize-release-ceremony-ledger.sh"
LEDGER_CLI="$ROOT_DIR/scripts/release-ceremony-ledger-cli.mjs"
FINALIZED_HISTORY_COLLECTOR="$ROOT_DIR/scripts/royalty-release-finalized-history-evidence.mjs"
FINALIZED_HISTORY_COLLECTOR_TEST="$ROOT_DIR/scripts/royalty-release-finalized-history-evidence.test.mjs"
H_CLI="$ROOT_DIR/scripts/royalty-release-history-receipt.mjs"
H_CLI_TEST="$ROOT_DIR/scripts/royalty-release-history-receipt.test.mjs"
RUNBOOK="$SCRIPT_DIR/../../docs/DEPLOYMENT-RUNBOOK.md"

for path in \
  "$HELPER" \
  "$PHASE_PLAN" \
  "$FINALITY_HELPER" \
  "$LEDGER_BINDING_HELPER" \
  "$LEDGER_BINDING_TEST" \
  "$MANIFEST_FILTER" \
  "$GUARD" \
  "$INITIALIZER" \
  "$LEDGER_CLI" \
  "$FINALIZED_HISTORY_COLLECTOR" \
  "$FINALIZED_HISTORY_COLLECTOR_TEST" \
  "$H_CLI" \
  "$H_CLI_TEST" \
  "$RUNBOOK"; do
  if [ ! -f "$path" ]; then
    echo "Missing Royalty release safety input: $path" >&2
    exit 1
  fi
done

bash -n "$HELPER"
bash -n "$GUARD"
bash -n "$INITIALIZER"
node --check "$FINALIZED_HISTORY_COLLECTOR"
node --check "$H_CLI"
node --test "$LEDGER_BINDING_TEST"

for required in \
  'replayReleaseCeremonyLedgerRevisionChain' \
  'replay.finalized !== true || replay.ledger_mode !== "0444"' \
  'BASE_SEPOLIA_RPC_URL' \
  'BASE_SEPOLIA_SECONDARY_RPC_URL' \
  'ROYALTY_HISTORY_CONFIGURATION_GETTERS' \
  'latest_state_recheck_sha256' \
  'dnai.base-sepolia-royalty-finalized-history-evidence.v1' \
  'observed_dual_archive_rpc_finalized_history_not_signed_live_authority'; do
  if ! grep -Fq -- "$required" "$FINALIZED_HISTORY_COLLECTOR"; then
    echo "Royalty finalized-history collector is missing safety binding: $required" >&2
    exit 1
  fi
done

for required in \
  'canonicalRoyaltyReleaseHistoryReceiptText' \
  'projectRoyaltyReleaseHistoryReceipt' \
  'verifyRoyaltyFinalizedHistoryEvidenceAgainstFrozenLedger' \
  '"--repository-root", "--source-manifest", "--ledger", "--evidence-root"' \
  'production evidence did not project canonical Royalty H v2' \
  'fs.constants.O_NOFOLLOW' \
  'fs.linkSync(staging, filePath)' \
  'canonical_h_structure_digest_and_replayed_frozen_ledger_lineage_verified_not_fresh_rpc_or_signed_live_authority' \
  'finalized_history_evidence_sha256' \
  'raw_finalized_history_evidence_sha256' \
  'canonical_royalty_release_history_receipt_v2_written_create_only' \
  'canonical_royalty_release_history_receipt_v2_verified'; do
  if ! grep -Fq -- "$required" "$H_CLI"; then
    echo "Royalty H materializer is missing safety binding: $required" >&2
    exit 1
  fi
done

if grep -Eq -- '--(rpc-url|primary-rpc|secondary-rpc)([[:space:]]|$)' \
  "$FINALIZED_HISTORY_COLLECTOR"; then
  echo "Royalty finalized-history RPC credentials must come only from the fixed environment variables." >&2
  exit 1
fi
if grep -Eqi -- '--private-key|--account|cast[[:space:]]+wallet|forge[[:space:]]+script|FINAL_RELEASE_AUTHORITY_CORE_PATH|final-release-authority-v4' \
  "$FINALIZED_HISTORY_COLLECTOR" "$H_CLI"; then
  echo "Royalty H collection/materialization must not depend on a wallet, Forge broadcast, or post-ceremony final-v4 authority." >&2
  exit 1
fi

for required in \
  '"initialize", "replay", "commit", "finalize", "recover"' \
  'finalizeReleaseCeremonyLedger' \
  'recoverPendingReleaseCeremonyLedgerOperation' \
  '--lock-recovery-receipt' \
  '--onchain-signer-nonce-finalized-state-reconciliation-sha256'; do
  if ! grep -Fq -- "$required" "$LEDGER_CLI"; then
    echo "Release ceremony ledger CLI is missing finalization/recovery binding: $required" >&2
    exit 1
  fi
done

for required in \
  'royalty-release-finalized-history-evidence.mjs" collect' \
  'royalty-release-history-receipt.mjs" create' \
  'royalty-release-history-receipt.mjs" verify' \
  'release-ceremony-ledger-cli.mjs" finalize' \
  'royalty-release-phase-plan.mjs"' \
  '  reconcile \' \
  'H is produced before, and is an input to, the new final-authority v4' \
  'must never authorize the transactions whose history' \
  'it records.'; do
  if ! grep -Fq -- "$required" "$RUNBOOK"; then
    echo "Royalty runbook is missing post-ceremony H boundary: $required" >&2
    exit 1
  fi
done

for required in \
  'fs.realpathSync.native(filePath)' \
  'before.nlink !== 1' \
  '(before.mode & 0o022) !== 0' \
  'fs.constants.O_NOFOLLOW' \
  'afterFd.mtimeMs !== opened.mtimeMs' \
  'canonicalJsonSha256(record)' \
  'canonicalJsonSha256(record.finalizedAuthority)' \
  'record.finalizedAuthority.finalizedBlockTimestamp'; do
  if ! grep -Fq -- "$required" "$LEDGER_BINDING_HELPER"; then
    echo "Royalty phase-one ledger-binding helper is missing custody check: $required" >&2
    exit 1
  fi
done

if grep -Eqi -- '--private-key' "$HELPER" \
  || grep -Eqi -- '(^|[[:space:]])forge[[:space:]].*--private-key|(^|[[:space:]])export[[:space:]]+[A-Za-z_]*PRIVATE_KEY=' "$RUNBOOK"; then
  echo "Royalty release must not expose a raw-key signing path." >&2
  exit 1
fi
if grep -Eq -- '--resume([[:space:]]|$)' "$HELPER" "$RUNBOOK"; then
  echo "Royalty release must not use blind Forge resume." >&2
  exit 1
fi

for required in \
  'BROADCAST="${BROADCAST:-false}"' \
  'ROYALTY_RELEASE_OPERATION="${ROYALTY_RELEASE_OPERATION:-execute}"' \
  'ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER=130' \
  'ROYALTY_RELEASE_BALANCE_SAFETY_MULTIPLIER=2' \
  'for raw_key_name in' \
  'fail "$raw_key_name is forbidden for Royalty release; use only the encrypted Foundry account dev."' \
  '--account dev' \
  'FOUNDRY_KEYSTORE_ACCOUNT' \
  'node "$PHASE_PLAN" verify' \
  '--royalty-release-prescription "$ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH"' \
  'dnai.royalty-release-phase-plan-verification-receipt.v2' \
  'valid_current_two_reviewer_exact_royalty_phase_plan' \
  'assert_optional_env_matches ROYALTY_DISTRIBUTOR_ADDRESS' \
  'assert_optional_env_matches ROYALTY_DISTRIBUTOR_RUNTIME_CODE_HASH' \
  'assert_optional_env_matches ROYALTY_SETTLEMENT_VERIFIER' \
  'assert_optional_env_matches ROYALTY_QVL_VERIFIER' \
  'assert_optional_env_matches EXECUTION_POLICY_ANCHOR_ADDRESS' \
  'assert_optional_env_matches EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH' \
  'assert_optional_env_matches EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT' \
  'operator_policy_require_fresh_release_ledger' \
  'capture_and_validate_phase_ledger' \
  'node "$LEDGER_BINDING_HELPER" verify' \
  'dnai.royalty-phase-one-ledger-binding-verification-receipt.v1' \
  'phase_one_history_record_sha256' \
  'finalized_authority_receipt_sha256' \
  'phase_one_finalized_at' \
  'Royalty phase plan does not bind the canonical phase-one history, finality receipt, and common-finalized timestamp' \
  'phase_one_prerequisite.ledger_revision_receipt_sha256' \
  'Royalty phase plan skips, reorders, or differs from the exact durable prior-phase ledger revision' \
  'operator_policy_assert_current_source' \
  'node "$FINALITY_HELPER" classify' \
  'node "$FINALITY_HELPER" verify-dry-run' \
  'derive_dry_run_gas_requirement "$DRY_RUN_OUTPUT_PATH"' \
  'require_royalty_balance_at_least' \
  '--gas-estimate-multiplier "$ROYALTY_RELEASE_GAS_ESTIMATE_MULTIPLIER"' \
  '--with-gas-price "${dry_run_gas_price_gwei}gwei"' \
  'dryRunOutputSha256: $dryRunOutputSha256' \
  'requiredOperatorBalanceWei: $requiredOperatorBalanceWei' \
  'gasEstimateMultiplier: $gasEstimateMultiplier' \
  'balanceSafetyMultiplier: $balanceSafetyMultiplier' \
  'dry-run/run-latest.json' \
  'Forge dry run differs from the exact classified reviewed transaction scope' \
  'phase1_exact_pending' \
  'phase2_exact_active_paused' \
  'phase2_exact_active_unpaused' \
  'reviewed_unpause_suffix' \
  'never-submitted unpause requires a future signed recover_missing_unpause mode' \
  '--prior-broadcast "$PRIOR_BROADCAST_RECEIPT_PATH"' \
  'Royalty phase-two timelock has not elapsed at the common finalized checkpoint' \
  'Royalty phase plan replay detected' \
  'Blind resume is forbidden' \
  'operator_policy_acquire_release_ceremony_lock royalty_release' \
  'dnai.royalty-release-pre-broadcast-capsule.v1' \
  'LOCK_MAY_BE_RELEASED=false' \
  'node "$FINALITY_HELPER" collect' \
  'operator_policy_durably_replace_release_ledger' \
  'operator_policy_release_release_ceremony_lock'; do
  if ! grep -Fq -- "$required" "$HELPER"; then
    echo "Royalty release helper is missing safety binding: $required" >&2
    exit 1
  fi
done

env_load_line="$(grep -n -m1 '^if \[ -f "\$ROOT_DIR/\.env" \]; then' "$HELPER" | cut -d: -f1)"
path_resolve_line="$(grep -n -m1 '^operator_policy_resolve_release_ceremony_paths$' "$HELPER" | cut -d: -f1)"
verify_line="$(grep -n -m1 '^if ! node "\$PHASE_PLAN" verify' "$HELPER" | cut -d: -f1)"
guard_line="$(grep -n -m1 '^operator_policy_require_fresh_release_ledger$' "$HELPER" | cut -d: -f1)"
classify_line="$(grep -n -m1 '^classify_release_state "\$initial_classification_artifact"$' "$HELPER" | cut -d: -f1)"
forge_line="$(grep -n -m1 '^  forge build --sizes$' "$HELPER" | cut -d: -f1)"
dry_exit_line="$(grep -n -m1 '^  if \[ "\$BROADCAST" != "true" \]; then' "$HELPER" | cut -d: -f1)"
lock_line="$(grep -n '^  operator_policy_acquire_release_ceremony_lock royalty_release$' "$HELPER" | tail -n 1 | cut -d: -f1)"
wallet_line="$(grep -n -m1 '^  if ! cast wallet list' "$HELPER" | cut -d: -f1)"
balance_line="$(grep -n -m1 '^  require_royalty_balance_at_least' "$HELPER" | cut -d: -f1)"
capsule_line="$(grep -n -m1 '^  mv "\$capsule_tmp" "\$capsule_path"$' "$HELPER" | cut -d: -f1)"
account_line="$(grep -n -m1 '^    --account dev' "$HELPER" | cut -d: -f1)"
collect_line="$(grep -n -m1 '^  node "\$FINALITY_HELPER" collect$' "$HELPER" | cut -d: -f1)"
commit_line="$(grep -n -m1 '^operator_policy_durably_replace_release_ledger' "$HELPER" | cut -d: -f1)"
release_line="$(grep -n -m1 '^operator_policy_release_release_ceremony_lock$' "$HELPER" | cut -d: -f1)"

if [ -z "$env_load_line" ] || [ -z "$path_resolve_line" ] \
  || [ "$env_load_line" -ge "$path_resolve_line" ]; then
  echo "Royalty helper must load .env before resolving ceremony paths." >&2
  exit 1
fi
if [ -z "$verify_line" ] || [ -z "$guard_line" ] || [ -z "$classify_line" ] \
  || [ -z "$forge_line" ] || [ "$verify_line" -ge "$guard_line" ] \
  || [ "$guard_line" -ge "$classify_line" ] || [ "$classify_line" -ge "$forge_line" ]; then
  echo "Reviewed plan and shared authority must fail closed before RPC classification and Forge." >&2
  exit 1
fi
if [ -z "$dry_exit_line" ] || [ -z "$lock_line" ] || [ -z "$balance_line" ] \
  || [ -z "$wallet_line" ] || [ "$dry_exit_line" -ge "$lock_line" ] \
  || [ "$lock_line" -ge "$balance_line" ] || [ "$balance_line" -ge "$wallet_line" ]; then
  echo "Simulation must exit before the lock; broadcast must prove gas margin before wallet access." >&2
  exit 1
fi
if [ -z "$capsule_line" ] || [ -z "$account_line" ] \
  || [ "$capsule_line" -ge "$account_line" ]; then
  echo "Durable recovery capsule must precede the only keystore broadcast invocation." >&2
  exit 1
fi
if [ -z "$collect_line" ] || [ -z "$commit_line" ] || [ -z "$release_line" ] \
  || [ "$collect_line" -ge "$commit_line" ] || [ "$commit_line" -ge "$release_line" ]; then
  echo "Dual-RPC finality and durable ledger publication must precede normal lock release." >&2
  exit 1
fi

if grep -Eq 'deployments/base-sepolia\.json|(^|[[:space:]])(cp|mv)[[:space:]].*"\$MANIFEST_PATH"|>[[:space:]]*"\$MANIFEST_PATH"' "$HELPER"; then
  echo "Royalty helper must not use repository history or write the ceremony ledger directly." >&2
  exit 1
fi
if [ "$(grep -Fc -- '--tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256"' "$GUARD")" -ne 2 ]; then
  echo "Shared guard must pass the Tinker ceremony receipt to both replay and commit." >&2
  exit 1
fi
grep -Fq -- '--tinker-account-binding-ceremony-receipt-sha256 "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256"' "$INITIALIZER"
grep -Fq 'operator_policy_require_absolute_regular_file CVM_LAUNCH_INTENT_PATH' "$GUARD"
grep -Fq -- '--deployment-intent "$DEPLOYMENT_INTENT_PATH"' "$GUARD"
grep -Fq -- '--cvm-launch-intent "$CVM_LAUNCH_INTENT_PATH"' "$GUARD"

parser_output="$(node "$LEDGER_CLI" replay \
  --repository-root /tmp/repository \
  --source-manifest /tmp/source.json \
  --ledger /tmp/ledger.json \
  --evidence-root /tmp/evidence \
  --lock-root /tmp/lock \
  --release-sha "$(printf 'a%.0s' {1..40})" \
  --deployment-intent-sha256 "sha256:$(printf 'b%.0s' {1..64})" \
  --reviewer-genesis-acceptance-sha256 "sha256:$(printf 'c%.0s' {1..64})" 2>&1 || true)"
if ! grep -Fq -- '--tinker-account-binding-ceremony-receipt-sha256 is required for replay' <<<"$parser_output"; then
  echo "Release-ledger CLI parser did not fail closed on the missing Tinker receipt digest." >&2
  exit 1
fi

if grep -Fq 'ROYALTY_RELEASE_PHASE=1 forge script' "$RUNBOOK"; then
  echo "Runbook still bypasses reviewed Royalty plan verification with direct Forge." >&2
  exit 1
fi
grep -Fq './scripts/configure-royalty-release.sh' "$RUNBOOK"

echo "Royalty release wrapper and shared ceremony compatibility safety checks passed."
