#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/configure-email-oracle-release.sh"
FORGE_SCRIPT="$SCRIPT_DIR/../script/ConfigureEmailOracleRelease.s.sol"
CONTRACT="$SCRIPT_DIR/../src/EmailOracleAuth.sol"
POLICY_GUARD="$SCRIPT_DIR/operator-policy-configure-guard.sh"
MANIFEST_FILTER="$SCRIPT_DIR/update-email-oracle-release-manifest.jq"

for path in "$HELPER" "$FORGE_SCRIPT" "$CONTRACT" "$MANIFEST_FILTER"; do
  if [ ! -f "$path" ]; then
    echo "Missing Email release safety input: $path" >&2
    exit 1
  fi
done

bash -n "$HELPER"
bash -n "$POLICY_GUARD"
grep -Fq '. "$CONTRACTS_DIR/scripts/operator-policy-configure-guard.sh"' "$HELPER"
test "$(grep -Ec '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER")" -eq 1
policy_line="$(grep -n -m1 '^[[:space:]]*operator_policy_project_and_validate$' "$HELPER" | cut -d: -f1)"
external_chain_check_line="$(grep -n -m1 '^[[:space:]]*verify_live_kms_registration$' "$HELPER" | cut -d: -f1)"
wallet_line="$(grep -n -m1 'cast wallet list' "$HELPER" | cut -d: -f1)"
dry_run_line="$(grep -n -m1 '^forge script' "$HELPER" | cut -d: -f1)"
if [ "$policy_line" -ge "$external_chain_check_line" ] \
  || [ "$policy_line" -ge "$wallet_line" ] \
  || [ "$policy_line" -ge "$dry_run_line" ]; then
  echo "Email operator policy must fail closed before chain access or simulation." >&2
  exit 1
fi
for policy_binding in \
  'EMAIL_ORACLE_CONSUMER_APP_ID \' \
  'TINKER_ENCUMBRANCE_RELEASE_MANAGER' \
  'EMAIL_ORACLE_COMPOSE_HASH \' \
  'EMAIL_ORACLE_CONSUMER_COMPOSE_HASH \' \
  'TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH'; do
  grep -Fq "$policy_binding" "$HELPER"
done
grep -Fq 'operator_policy_assert_public_env contractEnv EMAIL_ORACLE_UPGRADE_DELAY' "$HELPER"
grep -Fq 'OPERATOR_POLICY_FINAL_AUTHORITY_SHA256' "$HELPER"
grep -Fq 'FINAL_RELEASE_AUTHORITY_CORE_PATH' "$HELPER"
grep -Fq 'OPERATOR_POLICY_REVIEW_ENVELOPE_PATH' "$HELPER"
grep -Fq 'OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256' "$HELPER"
grep -Fq 'shasum -a 256 "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH"' "$HELPER"
grep -Fq 'check-review' "$HELPER"
grep -Fq -- '--subject "$FINAL_RELEASE_AUTHORITY_CORE_PATH"' "$HELPER"
grep -Fq 'dnai.authority-review-envelope-validation-receipt.v1' "$HELPER"
grep -Fq '.subjectKind == "final_release_authority"' "$HELPER"
grep -Fq '.checkpoint == "after_measured_cvms_before_any_release_ceremony_transaction"' "$HELPER"
grep -Fq '.status == "valid"' "$HELPER"
grep -Fq '.actionScopeCount == 6' "$HELPER"
grep -Fq '.subjectSemanticValidation == "final_release_authority_validated"' "$HELPER"
if grep -Fq 'freshDeployment' "$HELPER" "$MANIFEST_FILTER"; then
  echo "Email final-authority evidence must not be read from or written into freshDeployment." >&2
  exit 1
fi
grep -Fq "ORACLE_UPGRADE_DELAY()(uint256)" "$HELPER"
if grep -Eq '(^|[[:space:]])eval[[:space:]]|^[[:space:]]*(source|\.)[[:space:]]+.*OPERATOR_POLICY_PROJECTION' "$POLICY_GUARD" "$HELPER"; then
  echo "Email release must never evaluate or source operator-policy projection JSON." >&2
  exit 1
fi
if grep -Eq 'EMAIL_ORACLE_EXTERNAL_EVIDENCE_PATH|EMAIL_ORACLE_BOOT_MR_|raw_key|raw_secret|transaction\.input' "$MANIFEST_FILTER"; then
  echo "Email release ledger filter must never ingest external evidence bodies, boot details, raw material, or calldata." >&2
  exit 1
fi

if grep -Eq -- '--private-key|PRIVATE_KEY' "$HELPER" "$FORGE_SCRIPT"; then
  echo "Email release ceremony must never accept a raw private key." >&2
  exit 1
fi
for required in \
  '--account dev' \
  'FOUNDRY_KEYSTORE_ACCOUNT' \
  'Refusing email governance broadcast from a dirty source tree' \
  'EMAIL_ORACLE_RELEASE_PHASE must be exactly 1, 2, 3, or 4' \
  'dnai.email-oracle-external-release-evidence.v1' \
  'external_evidence_verified' \
  'verified_after_real_cvm_restart' \
  'raw_key_egress == false' \
  'raw_secret_egress == false' \
  'qvl_verification.status == "verified"' \
  'eth_getTransactionReceipt' \
  'eth_getTransactionByHash' \
  'eth_getBlockByNumber' \
  'registeredApps(address)(bool)' \
  'AppRegistered(address)' \
  'registerApp(address)' \
  'EIP1967_IMPLEMENTATION_SLOT' \
  'cast codehash' \
  'EMAIL_ORACLE_RESTART_KEY_DERIVATION_PROOF_SHA256' \
  'validate_deployment_ledger' \
  'validate_deployment_ledger_phase_history' \
  'Deployment ledger is missing the exact ordered evidence required before this Email release phase' \
  'LEDGER_PRE_BROADCAST_SHA256' \
  'Deployment ledger changed while rendering Email release evidence' \
  'collect_accepted_release_actions' \
  'eth_getTransactionReceipt' \
  'eth_getTransactionByHash' \
  'eth_getBlockByNumber' \
  'update-email-oracle-release-manifest.jq' \
  'mktemp "${MANIFEST_PATH}.tmp.XXXXXX"' \
  'operator_policy_durably_replace_release_ledger "$LEDGER_TEMP_PATH" "$MANIFEST_PATH"' \
  'Missing real external evidence always remains a hard phase-3/4 blocker'; do
  if ! grep -Fq -- "$required" "$HELPER"; then
    echo "Email release helper is missing safety binding: $required" >&2
    exit 1
  fi
done

first_ledger_check_line="$(grep -n -m1 '^validate_deployment_ledger$' "$HELPER" | cut -d: -f1)"
first_chain_read_line="$(grep -n -m1 '^[[:space:]]*verify_live_kms_registration$' "$HELPER" | cut -d: -f1)"
if [ -z "$first_ledger_check_line" ] || [ "$first_ledger_check_line" -ge "$first_chain_read_line" ]; then
  echo "Email deployment ledger identity must fail closed before chain access." >&2
  exit 1
fi
if [ "$(grep -Ec '^validate_deployment_ledger$' "$HELPER")" -ne 3 ]; then
  echo "Email deployment ledger must be validated before chain access and immediately before and after broadcast." >&2
  exit 1
fi
dry_exit_line="$(grep -n -m1 '^if \[ "\$BROADCAST" != "true" \]; then' "$HELPER" | cut -d: -f1)"
ledger_temp_line="$(grep -n -m1 '^LEDGER_TEMP_PATH="\$(mktemp' "$HELPER" | cut -d: -f1)"
if [ -z "$dry_exit_line" ] || [ -z "$ledger_temp_line" ] || [ "$dry_exit_line" -ge "$ledger_temp_line" ]; then
  echo "Email dry runs must exit before any deployment-ledger temporary output is created." >&2
  exit 1
fi

for action in \
  proposeOracleComposeHash \
  addDevice \
  setConsumerManager \
  addConsumerComposeHash \
  activateOracleComposeHash \
  freezeOracleCodeAuth \
  proposeKmsBinding \
  activateAndFreezeKmsBinding \
  freezeConsumerManagerAdditions \
  freezeConsumerRegistry; do
  if ! grep -Fq "$action" "$HELPER" || ! grep -Fq "$action" "$MANIFEST_FILTER"; then
    echo "Email release action is not mapped into exact receipt evidence: $action" >&2
    exit 1
  fi
done

for required in \
  '_phaseOne(inputs)' \
  '_phaseTwo(inputs)' \
  '_phaseThree(inputs)' \
  '_phaseFour(inputs)' \
  'proposeKmsBinding' \
  'activateAndFreezeKmsBinding' \
  'freezeConsumerManagerAdditions' \
  'freezeConsumerRegistry' \
  'releaseConfigurationReady' \
  'KMS binding timelock has not elapsed'; do
  if ! grep -Fq -- "$required" "$FORGE_SCRIPT"; then
    echo "Email Forge ceremony is missing exact phase binding: $required" >&2
    exit 1
  fi
done

for required in \
  'pendingOwner' \
  'consumerManagerAdditionsFrozen' \
  'allowedOracleComposeHashCount' \
  'pendingOracleComposeHashCount' \
  'allowedDeviceIdCount' \
  'totalConsumerComposeHashCount' \
  'kmsRegistrationTxHash' \
  'kmsRegistrationBlockHash' \
  'targetBootInfoHash' \
  'restartKeyDerivationProofHash' \
  'releaseConfigurationReady'; do
  if ! grep -Fq -- "$required" "$CONTRACT"; then
    echo "EmailOracleAuth is missing release-readiness field: $required" >&2
    exit 1
  fi
done

fixture_input="$(mktemp)"
fixture_output="$(mktemp)"
fixture_bad="$(mktemp)"
trap 'rm -f "$fixture_input" "$fixture_output" "$fixture_bad"' EXIT

jq -n '
def prior($phase; $action; $tx; $block; $blockHash; $review): {
  kind: "email_oracle_exact_release_action",
  chainId: 84532,
  emailOracleAuthAddress: "0x1111111111111111111111111111111111111111",
  runtimeCodeHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  sourceCommit: "0123456789abcdef0123456789abcdef01234567",
  finalAuthoritySha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  reviewEnvelopeSha256: $review,
  phase: $phase,
  actionIndex: (
    if $action == "proposeOracleComposeHash" or $action == "activateOracleComposeHash" or $action == "proposeKmsBinding" then 0
    elif $action == "addDevice" or $action == "freezeOracleCodeAuth" then 1
    elif $action == "setConsumerManager" then 2
    else 3
    end
  ),
  action: $action,
  transactionHash: $tx,
  blockNumber: $block,
  blockHash: $blockHash,
  blockTimestamp: (1700000000 + $block),
  recordedAt: "2026-01-01T00:00:00Z",
  postState: {
    status: (
      if $phase == 1 then "deployed_oracle_policy_pending_timelock_consumer_bound"
      elif $phase == 2 then "deployed_oracle_policy_frozen_kms_unbound"
      else "deployed_kms_binding_pending_timelock"
      end
    )
  }
};
{
  network: {chainId: 84532, preserveNetwork: true},
  contracts: {
    emailOracleAuth: {
      address: "0x1111111111111111111111111111111111111111",
      runtimeCodeHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      deploymentTx: "preserve-deployment-transaction",
      unrelatedEmailField: {preserve: true}
    },
    unrelatedContract: {preserve: true}
  },
  unrelatedTopLevel: {preserve: true},
  emailOracleReleaseHistory: [
    {kind: "older-email-release-record", preserve: true},
    prior(1; "proposeOracleComposeHash"; "0x4141414141414141414141414141414141414141414141414141414141414141"; 101; "0x5151515151515151515151515151515151515151515151515151515151515151"; "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    prior(1; "addDevice"; "0x4242424242424242424242424242424242424242424242424242424242424242"; 102; "0x5252525252525252525252525252525252525252525252525252525252525252"; "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    prior(1; "setConsumerManager"; "0x4343434343434343434343434343434343434343434343434343434343434343"; 103; "0x5353535353535353535353535353535353535353535353535353535353535353"; "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    prior(1; "addConsumerComposeHash"; "0x4444444444444444444444444444444444444444444444444444444444444444"; 104; "0x5454545454545454545454545454545454545454545454545454545454545454"; "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    prior(2; "activateOracleComposeHash"; "0x4545454545454545454545454545454545454545454545454545454545454545"; 105; "0x5555555555555555555555555555555555555555555555555555555555555555"; "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
    prior(2; "freezeOracleCodeAuth"; "0x4646464646464646464646464646464646464646464646464646464646464646"; 106; "0x5656565656565656565656565656565656565656565656565656565656565656"; "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
    prior(3; "proposeKmsBinding"; "0x4747474747474747474747474747474747474747474747474747474747474747"; 107; "0x5757575757575757575757575757575757575757575757575757575757575757"; "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
  ]
}' > "$fixture_input"

post_state="$(jq -cn '{
  status: "deployed_exact_email_release_frozen_ready",
  policyState: "exact_email_release_frozen_ready",
  owner: "0x2222222222222222222222222222222222222222",
  pendingOwner: "0x0000000000000000000000000000000000000000",
  oracleUpgradeDelaySeconds: 172800,
  allowAnyDevice: false,
  oracleCodeFrozen: true,
  consumerRegistryFrozen: true,
  consumerManagerAdditionsFrozen: true,
  kmsBindingFrozen: true,
  allowedOracleComposeHashCount: 1,
  pendingOracleComposeHashCount: 0,
  allowedDeviceIdCount: 1,
  consumerManagerCount: 1,
  totalConsumerComposeHashCount: 1,
  releaseOracleComposeHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  releaseDeviceId: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  releaseConsumerManager: "0x3333333333333333333333333333333333333333",
  releaseConsumerAppId: "0x3333333333333333333333333333333333333333",
  releaseConsumerComposeHash: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  oracleComposeHashAllowed: true,
  oracleComposeHashPendingActivatesAt: 0,
  deviceIdAllowed: true,
  consumerManagerAllowed: true,
  consumerComposeHashCount: 1,
  consumerAuthorized: true,
  consumerEmergencyRevoked: false,
  kmsContract: "0x4444444444444444444444444444444444444444",
  kmsRuntimeCodeHash: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  kmsImplementation: "0x5555555555555555555555555555555555555555",
  kmsImplementationRuntimeCodeHash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  kmsRegistrationTxHash: "0x1212121212121212121212121212121212121212121212121212121212121212",
  kmsRegistrationBlock: 123,
  kmsRegistrationBlockHash: "0x1313131313131313131313131313131313131313131313131313131313131313",
  targetBootInfoHash: "0x1414141414141414141414141414141414141414141414141414141414141414",
  restartKeyDerivationProofHash: "0x1515151515151515151515151515151515151515151515151515151515151515",
  pendingKmsContract: "0x0000000000000000000000000000000000000000",
  pendingKmsRuntimeCodeHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingKmsImplementation: "0x0000000000000000000000000000000000000000",
  pendingKmsImplementationRuntimeCodeHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingKmsRegistrationTxHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingKmsRegistrationBlock: 0,
  pendingKmsRegistrationBlockHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingTargetBootInfoHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingRestartKeyDerivationProofHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
  pendingKmsBindingActivatesAt: 0,
  releaseConfigurationReady: true
}')"

action_records="$(jq -cn '[
  {
    action: "activateAndFreezeKmsBinding",
    transactionHash: "0x2121212121212121212121212121212121212121212121212121212121212121",
    blockNumber: 201,
    blockHash: "0x3131313131313131313131313131313131313131313131313131313131313131"
  },
  {
    action: "freezeConsumerManagerAdditions",
    transactionHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
    blockNumber: 202,
    blockHash: "0x3232323232323232323232323232323232323232323232323232323232323232"
  },
  {
    action: "freezeConsumerRegistry",
    transactionHash: "0x2323232323232323232323232323232323232323232323232323232323232323",
    blockNumber: 203,
    blockHash: "0x3333333333333333333333333333333333333333333333333333333333333333"
  }
] | map(. + {blockTimestamp: (1700000000 + .blockNumber)})')"

run_manifest_merge() {
  local input="$1" phase="$2" state="$3" actions="$4"
  jq \
    --arg emailOracleAuthAddress "0x1111111111111111111111111111111111111111" \
    --arg runtimeCodeHash "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --arg sourceCommit "0123456789abcdef0123456789abcdef01234567" \
    --arg finalAuthoritySha256 "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --arg reviewEnvelopeSha256 "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    --argjson phase "$phase" \
    --arg recordedAt "2026-01-01T00:00:00Z" \
    --argjson postState "$state" \
    --argjson actionRecords "$actions" \
    -f "$MANIFEST_FILTER" "$input"
}

zero_address="0x0000000000000000000000000000000000000000"
zero_hash="0x0000000000000000000000000000000000000000000000000000000000000000"
phase_one_state="$(jq -c \
  --arg za "$zero_address" --arg zh "$zero_hash" '
  .status = "deployed_oracle_policy_pending_timelock_consumer_bound" |
  .policyState = "oracle_policy_pending_timelock_consumer_bound" |
  .oracleCodeFrozen = false | .kmsBindingFrozen = false |
  .consumerManagerAdditionsFrozen = false | .consumerRegistryFrozen = false |
  .allowedOracleComposeHashCount = 0 | .pendingOracleComposeHashCount = 1 |
  .oracleComposeHashAllowed = false | .oracleComposeHashPendingActivatesAt = 999 |
  .releaseConfigurationReady = false |
  .releaseOracleComposeHash = $zh | .releaseDeviceId = $zh |
  .releaseConsumerManager = $za | .releaseConsumerAppId = $za | .releaseConsumerComposeHash = $zh |
  .kmsContract = $za | .kmsRuntimeCodeHash = $zh | .kmsImplementation = $za |
  .kmsImplementationRuntimeCodeHash = $zh | .kmsRegistrationTxHash = $zh |
  .kmsRegistrationBlock = 0 | .kmsRegistrationBlockHash = $zh |
  .targetBootInfoHash = $zh | .restartKeyDerivationProofHash = $zh
' <<<"$post_state")"
phase_one_actions="$(jq -cn '[
  {action:"proposeOracleComposeHash",transactionHash:"0x6161616161616161616161616161616161616161616161616161616161616161",blockNumber:301,blockHash:"0x7171717171717171717171717171717171717171717171717171717171717171"},
  {action:"addDevice",transactionHash:"0x6262626262626262626262626262626262626262626262626262626262626262",blockNumber:302,blockHash:"0x7272727272727272727272727272727272727272727272727272727272727272"},
  {action:"setConsumerManager",transactionHash:"0x6363636363636363636363636363636363636363636363636363636363636363",blockNumber:303,blockHash:"0x7373737373737373737373737373737373737373737373737373737373737373"},
  {action:"addConsumerComposeHash",transactionHash:"0x6464646464646464646464646464646464646464646464646464646464646464",blockNumber:304,blockHash:"0x7474747474747474747474747474747474747474747474747474747474747474"}
] | map(. + {blockTimestamp: (1700000000 + .blockNumber)})')"
jq '.emailOracleReleaseHistory = [.emailOracleReleaseHistory[0]]' "$fixture_input" > "$fixture_bad"
run_manifest_merge "$fixture_bad" 1 "$phase_one_state" "$phase_one_actions" >/dev/null

phase_two_state="$(jq -c \
  --arg za "$zero_address" --arg zh "$zero_hash" '
  .status = "deployed_oracle_policy_frozen_kms_unbound" |
  .policyState = "oracle_policy_frozen_kms_unbound" |
  .kmsBindingFrozen = false | .consumerManagerAdditionsFrozen = false | .consumerRegistryFrozen = false |
  .releaseConfigurationReady = false |
  .releaseConsumerManager = $za | .releaseConsumerAppId = $za | .releaseConsumerComposeHash = $zh |
  .kmsContract = $za | .kmsRuntimeCodeHash = $zh | .kmsImplementation = $za |
  .kmsImplementationRuntimeCodeHash = $zh | .kmsRegistrationTxHash = $zh |
  .kmsRegistrationBlock = 0 | .kmsRegistrationBlockHash = $zh |
  .targetBootInfoHash = $zh | .restartKeyDerivationProofHash = $zh
' <<<"$post_state")"
phase_two_actions="$(jq -cn '[
  {action:"activateOracleComposeHash",transactionHash:"0x6565656565656565656565656565656565656565656565656565656565656565",blockNumber:305,blockHash:"0x7575757575757575757575757575757575757575757575757575757575757575"},
  {action:"freezeOracleCodeAuth",transactionHash:"0x6666666666666666666666666666666666666666666666666666666666666666",blockNumber:306,blockHash:"0x7676767676767676767676767676767676767676767676767676767676767676"}
] | map(. + {blockTimestamp: (1700000000 + .blockNumber)})')"
jq '.emailOracleReleaseHistory = .emailOracleReleaseHistory[0:5]' "$fixture_input" > "$fixture_bad"
run_manifest_merge "$fixture_bad" 2 "$phase_two_state" "$phase_two_actions" >/dev/null

phase_three_state="$(jq -c '
  .status = "deployed_kms_binding_pending_timelock" |
  .policyState = "oracle_policy_frozen_kms_binding_pending_timelock" |
  .kmsBindingFrozen = false | .consumerManagerAdditionsFrozen = false | .consumerRegistryFrozen = false |
  .releaseConfigurationReady = false |
  .kmsContract = "0x0000000000000000000000000000000000000000" |
  .kmsRuntimeCodeHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .kmsImplementation = "0x0000000000000000000000000000000000000000" |
  .kmsImplementationRuntimeCodeHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .kmsRegistrationTxHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .kmsRegistrationBlock = 0 |
  .kmsRegistrationBlockHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .targetBootInfoHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .restartKeyDerivationProofHash = "0x0000000000000000000000000000000000000000000000000000000000000000" |
  .pendingKmsContract = "0x4444444444444444444444444444444444444444" |
  .pendingKmsRuntimeCodeHash = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
  .pendingKmsImplementation = "0x5555555555555555555555555555555555555555" |
  .pendingKmsImplementationRuntimeCodeHash = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
  .pendingKmsRegistrationTxHash = "0x1212121212121212121212121212121212121212121212121212121212121212" |
  .pendingKmsRegistrationBlock = 123 |
  .pendingKmsRegistrationBlockHash = "0x1313131313131313131313131313131313131313131313131313131313131313" |
  .pendingTargetBootInfoHash = "0x1414141414141414141414141414141414141414141414141414141414141414" |
  .pendingRestartKeyDerivationProofHash = "0x1515151515151515151515151515151515151515151515151515151515151515" |
  .pendingKmsBindingActivatesAt = 999
' <<<"$post_state")"
phase_three_actions="$(jq -cn '[{
  action:"proposeKmsBinding",
  transactionHash:"0x6767676767676767676767676767676767676767676767676767676767676767",
  blockNumber:307,
  blockHash:"0x7777777777777777777777777777777777777777777777777777777777777777"
}] | map(. + {blockTimestamp: (1700000000 + .blockNumber)})')"
jq '.emailOracleReleaseHistory = .emailOracleReleaseHistory[0:7]' "$fixture_input" > "$fixture_bad"
run_manifest_merge "$fixture_bad" 3 "$phase_three_state" "$phase_three_actions" >/dev/null

run_manifest_merge "$fixture_input" 4 "$post_state" "$action_records" > "$fixture_output"
jq -e '
  .network.preserveNetwork == true and
  .contracts.unrelatedContract.preserve == true and
  .unrelatedTopLevel.preserve == true and
  .contracts.emailOracleAuth.deploymentTx == "preserve-deployment-transaction" and
  .contracts.emailOracleAuth.unrelatedEmailField.preserve == true and
  .contracts.emailOracleAuth.sourceCommit == "0123456789abcdef0123456789abcdef01234567" and
  .contracts.emailOracleAuth.runtimeCodeHash == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .contracts.emailOracleAuth.latestReleasePhase == 4 and
  (.contracts.emailOracleAuth.latestReleaseActions | length) == 3 and
  .contracts.emailOracleAuth.latestReleaseFinalAuthoritySha256 == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .contracts.emailOracleAuth.latestReleaseReviewEnvelopeSha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
  (.contracts.emailOracleAuth | has("latestReleaseOperatorPolicyPacketSha256") | not) and
  .contracts.emailOracleAuth.releaseConfigurationReady == true and
  .contracts.emailOracleAuth.pendingKmsBindingActivatesAt == 0 and
  (.emailOracleReleaseHistory | length) == 11 and
  .emailOracleReleaseHistory[0].preserve == true and
  [.emailOracleReleaseHistory[8:][] | .action] == [
    "activateAndFreezeKmsBinding",
    "freezeConsumerManagerAdditions",
    "freezeConsumerRegistry"
  ] and
  [.emailOracleReleaseHistory[8:][] | .actionIndex] == [0, 1, 2] and
  .emailOracleReleaseHistory[1].reviewEnvelopeSha256 != .emailOracleReleaseHistory[8].reviewEnvelopeSha256 and
  all(.emailOracleReleaseHistory[8:][];
    .chainId == 84532 and
    .emailOracleAuthAddress == "0x1111111111111111111111111111111111111111" and
    .runtimeCodeHash == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
    .sourceCommit == "0123456789abcdef0123456789abcdef01234567" and
    .finalAuthoritySha256 == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
    .reviewEnvelopeSha256 == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
    (has("operatorPolicyPacketSha256") | not) and
    (has("input") | not) and
    (.blockTimestamp | type == "number" and . > 0) and
    .postState.releaseConfigurationReady == true
  )
' "$fixture_output" >/dev/null

expect_merge_failure() {
  local label="$1" input="$2" phase="$3" state="$4" actions="$5"
  if run_manifest_merge "$input" "$phase" "$state" "$actions" >/dev/null 2>&1; then
    echo "Email ledger merge accepted adversarial input: $label" >&2
    exit 1
  fi
}

jq '.contracts.emailOracleAuth.address = "0x9999999999999999999999999999999999999999"' "$fixture_input" > "$fixture_bad"
expect_merge_failure wrong-address "$fixture_bad" 4 "$post_state" "$action_records"
jq '.contracts.emailOracleAuth.runtimeCodeHash = "0x9999999999999999999999999999999999999999999999999999999999999999"' "$fixture_input" > "$fixture_bad"
expect_merge_failure wrong-runtime "$fixture_bad" 4 "$post_state" "$action_records"
jq '.contracts.emailOracleAuth.sourceCommit = "ffffffffffffffffffffffffffffffffffffffff"' "$fixture_input" > "$fixture_bad"
expect_merge_failure wrong-source "$fixture_bad" 4 "$post_state" "$action_records"
jq '.emailOracleReleaseHistory = {}' "$fixture_input" > "$fixture_bad"
expect_merge_failure malformed-history "$fixture_bad" 4 "$post_state" "$action_records"
jq '.emailOracleReleaseHistory = [.emailOracleReleaseHistory[0]]' "$fixture_input" > "$fixture_bad"
expect_merge_failure missing-prior-phases "$fixture_bad" 4 "$post_state" "$action_records"
jq '.emailOracleReleaseHistory[4].finalAuthoritySha256 = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$fixture_input" > "$fixture_bad"
expect_merge_failure changed-final-authority "$fixture_bad" 4 "$post_state" "$action_records"
duplicate_actions="$(jq '.[1].transactionHash = .[0].transactionHash' <<<"$action_records")"
expect_merge_failure duplicate-transaction "$fixture_input" 4 "$post_state" "$duplicate_actions"
replayed_action="$(jq '.[0].transactionHash = "0x4141414141414141414141414141414141414141414141414141414141414141"' <<<"$action_records")"
expect_merge_failure replayed-transaction "$fixture_input" 4 "$post_state" "$replayed_action"
wrong_order_actions="$(jq '[.[1], .[0], .[2]]' <<<"$action_records")"
expect_merge_failure wrong-action-order "$fixture_input" 4 "$post_state" "$wrong_order_actions"
extra_state="$(jq '.externalEvidenceBody = "must-not-be-written"' <<<"$post_state")"
expect_merge_failure unexpected-post-state "$fixture_input" 4 "$extra_state" "$action_records"
incoherent_state="$(jq '.kmsBindingFrozen = false' <<<"$post_state")"
expect_merge_failure incoherent-phase-state "$fixture_input" 4 "$incoherent_state" "$action_records"

echo "Email oracle release ceremony safety checks passed."
