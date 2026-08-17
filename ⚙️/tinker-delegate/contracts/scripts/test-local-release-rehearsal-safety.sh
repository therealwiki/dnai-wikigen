#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REHEARSAL="$SCRIPT_DIR/rehearse-fresh-suite-anvil.sh"

bash -n "$REHEARSAL"

for required_boundary in \
  '[[ ! "$RPC_URL" =~ ^http://127[.]0[.]0[.]1:[0-9]+$ ]]' \
  'cast rpc anvil_nodeInfo' \
  'assert_equal "local chain id" "$CHAIN_ID" "$LIVE_CHAIN_ID"' \
  'export FOUNDRY_BROADCAST="$EVIDENCE_DIR/broadcast"' \
  'export FOUNDRY_OUT="$EVIDENCE_DIR/out"' \
  --unlocked \
  'merge-base-sepolia-suite-manifest.jq' \
  'dnai/local-rehearsal/no-account-binding-ceremony/v1' \
  '--arg tinkerAccountBindingCeremonyReceiptSha256 "$LOCAL_TINKER_ACCOUNT_BINDING_PLACEHOLDER_SHA256"' \
  'syntheticAccountBindingPlaceholderSha256: $localTinkerAccountBindingPlaceholderSha256' \
  'notCeremonyEvidence: true' \
  'accountBindingCeremonyPerformed: false' \
  'local_domain_separated_placeholder_not_ceremony_evidence_or_signed_reviewer_authority' \
  '.deploymentHistory[-1].tinkerAccountBindingCeremonyReceiptSha256 = null' \
  '.freshDeployment.contractSuite.tinkerAccountBindingCeremonyReceiptSha256 = null' \
  'and .deploymentHistory[-1].tinkerAccountBindingCeremonyReceiptSha256 == null' \
  'and .freshDeployment.contractSuite.tinkerAccountBindingCeremonyReceiptSha256 == null' \
  'local_ephemeral_anvil_only' \
  'rawSigningMaterialReadOrSupplied: false' \
  'select(.transactionType == "CREATE" and .contractName == $name)' \
  'expected exactly one CREATE transaction for ' \
  "'constructor(bool,address)'" \
  '"$DILIGENCE_GOVERNANCE_CONTROLLER"' \
  "'constructor(address,uint256,bool,bytes32,bytes32,bool)'" \
  'constructor re-execution failed' \
  'constructor re-execution returned malformed or empty runtime bytecode' \
  'freshBroadcastTransactionEvidenceFromLedger' \
  'collect_broadcast_transaction 12' \
  'DILIGENCE_CREATE_INPUT="$(' \
  '--argjson broadcastTransactions "$BROADCAST_TRANSACTIONS"' \
  'broadcastTransactionsSha256' \
  'transaction input digest' \
  'fresh deployment evidence must contain exactly 13 distinct mined transactions' \
  'forge test' \
  'contractTests: "full_forge_test_suite_passed"' \
  'rm -f "$PRODUCTION_SHAPE_MANIFEST"' \
  'rm -rf "$FOUNDRY_CACHE_PATH" "$FOUNDRY_OUT"' \
  'Synthetic DiligenceRoom accepted lifecycle' \
  'proposeDeveloper(address)' \
  'acceptDeveloper()' \
  'proposeEvaluatorPolicySet(bytes32[3])' \
  'activateEvaluatorPolicySet(bytes32[3])' \
  'freezeEvaluatorPolicySet()' \
  'fundDeal(uint256,bytes32)' \
  'submitResult(uint256,uint8,uint256,bytes32,uint256,bytes32,uint256,bytes,bytes)' \
  'attestationAuthorizationDigest(uint256,bytes32,uint8,uint256,bytes32,uint256)(bytes32)' \
  'approvedEvaluatorPolicyCount()(uint256)' \
  'pendingEvaluatorPolicyCount()(uint256)' \
  'evaluatorPolicySetRoot()(bytes32)' \
  'evaluatorPolicySetFrozen()(bool)' \
  'post_deployment_pre_synthetic_lifecycle' \
  'postDeploymentBindingState' \
  'syntheticLocalOnly: true' \
  'DiligenceRoom exact compose admission count' \
  'DiligenceRoom exact TEE identity count' \
  'Synthetic ChallengeRegistry version/freeze/open behavior' \
  'Challenge Phase A published version 2' \
  'reviewEligibleAt(uint256)(uint64)' \
  'anvil_setNextBlockTimestamp "$CHALLENGE_REVIEW_ELIGIBLE_AT"' \
  'phaseB.freezeBlock > .rehearsalEvidence.challengeRegistry.phaseA.publishBlock' \
  'Synthetic Tinker exact release and per-operation witness' \
  'proposeReleasePolicy(bytes32,uint256,uint256,bytes32[],address[])' \
  'activateAndFreezeReleasePolicy()' \
  'anvil_setNextBlockTimestamp "$TINKER_RELEASE_ELIGIBLE_AT"' \
  'fullCapOperationsAuthorized: 2' \
  'Tinker encumbrance remains non-custodial' \
  'releasePolicyFrozen: true' \
  'releaseMaxAddBalanceWei: $tinkerReleaseMaxAddBalanceWei' \
  'releaseMaxSpendWei: $tinkerReleaseMaxSpendWei' \
  'releaseComposeHashes: [$tinkerComposeHash]' \
  'releaseComposeRoot: $tinkerReleaseComposeRoot' \
  'releaseManagers: [$tinkerReleaseManager]' \
  'releaseManagerRoot: $tinkerReleaseManagerRoot' \
  'pendingMaxAddBalanceWei: "0"' \
  'pendingMaxSpendWei: "0"' \
  'pendingComposeHashes: []' \
  'pendingManagers: []' \
  '(.contracts.tinkerAccountEncumbrance.maxAddBalanceWei | type) == "string"' \
  'consumerManagerAdditionsFrozen()(bool)' \
  'kmsBindingFrozen()(bool)' \
  'releaseConfigurationReady()(bool)' \
  'Synthetic ExecutionPolicyAnchor monotonic witness' \
  'ComputeCreditVault empty compose admission' \
  'ComputeCreditVault:        $COMPUTE_VAULT_ADDRESS' \
  'ExecutionPolicyAnchor:     $EXECUTION_POLICY_ANCHOR_ADDRESS'; do
  if ! grep -Fq -- "$required_boundary" "$REHEARSAL"; then
    echo "Local rehearsal is missing required safety boundary: $required_boundary" >&2
    exit 1
  fi
done

if [ "$(grep -Fc -- \
  '--arg tinkerAccountBindingCeremonyReceiptSha256' \
  "$REHEARSAL")" -ne 1 ]; then
  echo "Local rehearsal must pass exactly one account-binding placeholder to the shared manifest filter." >&2
  exit 1
fi

if [ "$(grep -Fc -- \
  'tinkerAccountBindingCeremonyReceiptSha256 = null' \
  "$REHEARSAL")" -ne 2 ]; then
  echo "Local rehearsal must null both production account-binding receipt fields." >&2
  exit 1
fi

forbidden_signing_flag="--private""-key"
if grep -Fq -- "$forbidden_signing_flag" "$REHEARSAL"; then
  echo "Local rehearsal must use Anvil's unlocked JSON-RPC signer boundary." >&2
  exit 1
fi

if grep -Fq 'BASE_SEPOLIA_RPC_URL' "$REHEARSAL"; then
  echo "Local rehearsal must never read the Base Sepolia RPC setting." >&2
  exit 1
fi

if grep -Eq '(^|[[:space:]])(source|\.)[[:space:]].*\.env' "$REHEARSAL"; then
  echo "Local rehearsal must never source repository environment secrets." >&2
  exit 1
fi

echo "Local release rehearsal safety checks passed."
