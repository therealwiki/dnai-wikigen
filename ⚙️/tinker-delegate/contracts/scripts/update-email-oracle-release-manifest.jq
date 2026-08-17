def fail($message): error($message);
def is_address:
  type == "string" and test("^0x[0-9a-f]{40}$") and . != ("0x" + ("0" * 40));
def is_address_or_zero:
  type == "string" and test("^0x[0-9a-f]{40}$");
def is_bytes32:
  type == "string" and test("^0x[0-9a-f]{64}$");
def is_nonzero_bytes32:
  is_bytes32 and . != ("0x" + ("0" * 64));
def is_uint:
  type == "number" and . >= 0 and . == floor;

def expected_actions($phase):
  if $phase == 1 then
    ["proposeOracleComposeHash", "addDevice", "setConsumerManager", "addConsumerComposeHash"]
  elif $phase == 2 then
    ["activateOracleComposeHash", "freezeOracleCodeAuth"]
  elif $phase == 3 then
    ["proposeKmsBinding"]
  elif $phase == 4 then
    ["activateAndFreezeKmsBinding", "freezeConsumerManagerAdditions", "freezeConsumerRegistry"]
  else
    fail("email release phase is invalid")
  end;

def expected_prior_actions($phase):
  if $phase == 1 then []
  elif $phase == 2 then [
    {phase: 1, actionIndex: 0, action: "proposeOracleComposeHash"},
    {phase: 1, actionIndex: 1, action: "addDevice"},
    {phase: 1, actionIndex: 2, action: "setConsumerManager"},
    {phase: 1, actionIndex: 3, action: "addConsumerComposeHash"}
  ]
  elif $phase == 3 then (expected_prior_actions(2) + [
    {phase: 2, actionIndex: 0, action: "activateOracleComposeHash"},
    {phase: 2, actionIndex: 1, action: "freezeOracleCodeAuth"}
  ])
  elif $phase == 4 then (expected_prior_actions(3) + [
    {phase: 3, actionIndex: 0, action: "proposeKmsBinding"}
  ])
  else fail("email release phase is invalid")
  end;

def validate_post_state:
  if keys != [
    "allowAnyDevice",
    "allowedDeviceIdCount",
    "allowedOracleComposeHashCount",
    "consumerAuthorized",
    "consumerComposeHashCount",
    "consumerEmergencyRevoked",
    "consumerManagerAdditionsFrozen",
    "consumerManagerAllowed",
    "consumerManagerCount",
    "consumerRegistryFrozen",
    "deviceIdAllowed",
    "kmsBindingFrozen",
    "kmsContract",
    "kmsImplementation",
    "kmsImplementationRuntimeCodeHash",
    "kmsRegistrationBlock",
    "kmsRegistrationBlockHash",
    "kmsRegistrationTxHash",
    "kmsRuntimeCodeHash",
    "oracleCodeFrozen",
    "oracleComposeHashAllowed",
    "oracleComposeHashPendingActivatesAt",
    "oracleUpgradeDelaySeconds",
    "owner",
    "pendingKmsBindingActivatesAt",
    "pendingKmsContract",
    "pendingKmsImplementation",
    "pendingKmsImplementationRuntimeCodeHash",
    "pendingKmsRegistrationBlock",
    "pendingKmsRegistrationBlockHash",
    "pendingKmsRegistrationTxHash",
    "pendingKmsRuntimeCodeHash",
    "pendingOracleComposeHashCount",
    "pendingOwner",
    "pendingRestartKeyDerivationProofHash",
    "pendingTargetBootInfoHash",
    "policyState",
    "releaseConfigurationReady",
    "releaseConsumerAppId",
    "releaseConsumerComposeHash",
    "releaseConsumerManager",
    "releaseDeviceId",
    "releaseOracleComposeHash",
    "restartKeyDerivationProofHash",
    "status",
    "targetBootInfoHash",
    "totalConsumerComposeHashCount"
  ] then
    fail("email release post-state has unexpected fields")
  elif ([
    .allowAnyDevice,
    .consumerAuthorized,
    .consumerEmergencyRevoked,
    .consumerManagerAdditionsFrozen,
    .consumerManagerAllowed,
    .consumerRegistryFrozen,
    .deviceIdAllowed,
    .kmsBindingFrozen,
    .oracleCodeFrozen,
    .oracleComposeHashAllowed,
    .releaseConfigurationReady
  ] | all(type == "boolean") | not) then
    fail("email release post-state boolean field is invalid")
  elif ([
    .allowedDeviceIdCount,
    .allowedOracleComposeHashCount,
    .consumerComposeHashCount,
    .consumerManagerCount,
    .kmsRegistrationBlock,
    .oracleComposeHashPendingActivatesAt,
    .oracleUpgradeDelaySeconds,
    .pendingKmsBindingActivatesAt,
    .pendingKmsRegistrationBlock,
    .pendingOracleComposeHashCount,
    .totalConsumerComposeHashCount
  ] | all(is_uint) | not) then
    fail("email release post-state integer field is invalid")
  elif ([
    .owner,
    .kmsContract,
    .kmsImplementation,
    .pendingKmsContract,
    .pendingKmsImplementation,
    .releaseConsumerAppId,
    .releaseConsumerManager
  ] | all(is_address_or_zero) | not) then
    fail("email release post-state address field is invalid")
  elif (.owner | is_address | not) then
    fail("email release owner is invalid")
  elif (.pendingOwner | is_address_or_zero | not) then
    fail("email release pending owner is invalid")
  elif ([
    .kmsImplementationRuntimeCodeHash,
    .kmsRegistrationBlockHash,
    .kmsRegistrationTxHash,
    .kmsRuntimeCodeHash,
    .pendingKmsImplementationRuntimeCodeHash,
    .pendingKmsRegistrationBlockHash,
    .pendingKmsRegistrationTxHash,
    .pendingKmsRuntimeCodeHash,
    .pendingRestartKeyDerivationProofHash,
    .pendingTargetBootInfoHash,
    .releaseConsumerComposeHash,
    .releaseDeviceId,
    .releaseOracleComposeHash,
    .restartKeyDerivationProofHash,
    .targetBootInfoHash
  ] | all(is_bytes32) | not) then
    fail("email release post-state bytes32 field is invalid")
  elif (.status | type != "string" or length == 0 or length > 120) then
    fail("email release status is invalid")
  elif (.policyState | type != "string" or length == 0 or length > 160) then
    fail("email release policy state is invalid")
  else
    .
  end;

def active_kms_is_zero:
  .kmsContract == ("0x" + ("0" * 40)) and
  .kmsRuntimeCodeHash == ("0x" + ("0" * 64)) and
  .kmsImplementation == ("0x" + ("0" * 40)) and
  .kmsImplementationRuntimeCodeHash == ("0x" + ("0" * 64)) and
  .kmsRegistrationTxHash == ("0x" + ("0" * 64)) and
  .kmsRegistrationBlock == 0 and
  .kmsRegistrationBlockHash == ("0x" + ("0" * 64)) and
  .targetBootInfoHash == ("0x" + ("0" * 64)) and
  .restartKeyDerivationProofHash == ("0x" + ("0" * 64));

def pending_kms_is_zero:
  .pendingKmsContract == ("0x" + ("0" * 40)) and
  .pendingKmsRuntimeCodeHash == ("0x" + ("0" * 64)) and
  .pendingKmsImplementation == ("0x" + ("0" * 40)) and
  .pendingKmsImplementationRuntimeCodeHash == ("0x" + ("0" * 64)) and
  .pendingKmsRegistrationTxHash == ("0x" + ("0" * 64)) and
  .pendingKmsRegistrationBlock == 0 and
  .pendingKmsRegistrationBlockHash == ("0x" + ("0" * 64)) and
  .pendingTargetBootInfoHash == ("0x" + ("0" * 64)) and
  .pendingRestartKeyDerivationProofHash == ("0x" + ("0" * 64)) and
  .pendingKmsBindingActivatesAt == 0;

def valid_phase_post_state($phase):
  (.pendingOwner == ("0x" + ("0" * 40))) and
  (.oracleUpgradeDelaySeconds > 0) and
  (.allowAnyDevice == false) and
  (.allowedDeviceIdCount == 1) and
  (.consumerManagerCount == 1) and
  (.totalConsumerComposeHashCount == 1) and
  (.deviceIdAllowed == true) and
  (.consumerManagerAllowed == true) and
  (.consumerComposeHashCount == 1) and
  (.consumerAuthorized == true) and
  (.consumerEmergencyRevoked == false) and
  if $phase == 1 then
    .status == "deployed_oracle_policy_pending_timelock_consumer_bound" and
    .policyState == "oracle_policy_pending_timelock_consumer_bound" and
    .allowedOracleComposeHashCount == 0 and
    .pendingOracleComposeHashCount == 1 and
    .oracleComposeHashAllowed == false and
    .oracleComposeHashPendingActivatesAt > 0 and
    .oracleCodeFrozen == false and .kmsBindingFrozen == false and
    .consumerManagerAdditionsFrozen == false and .consumerRegistryFrozen == false and
    .releaseConfigurationReady == false and
    .releaseOracleComposeHash == ("0x" + ("0" * 64)) and
    .releaseDeviceId == ("0x" + ("0" * 64)) and
    .releaseConsumerManager == ("0x" + ("0" * 40)) and
    .releaseConsumerAppId == ("0x" + ("0" * 40)) and
    .releaseConsumerComposeHash == ("0x" + ("0" * 64)) and
    active_kms_is_zero and pending_kms_is_zero
  elif $phase == 2 then
    .status == "deployed_oracle_policy_frozen_kms_unbound" and
    .policyState == "oracle_policy_frozen_kms_unbound" and
    .allowedOracleComposeHashCount == 1 and
    .pendingOracleComposeHashCount == 0 and
    .oracleComposeHashAllowed == true and
    .oracleComposeHashPendingActivatesAt == 0 and
    .oracleCodeFrozen == true and .kmsBindingFrozen == false and
    .consumerManagerAdditionsFrozen == false and .consumerRegistryFrozen == false and
    .releaseConfigurationReady == false and
    (.releaseOracleComposeHash | is_nonzero_bytes32) and
    (.releaseDeviceId | is_nonzero_bytes32) and
    .releaseConsumerManager == ("0x" + ("0" * 40)) and
    .releaseConsumerAppId == ("0x" + ("0" * 40)) and
    .releaseConsumerComposeHash == ("0x" + ("0" * 64)) and
    active_kms_is_zero and pending_kms_is_zero
  elif $phase == 3 then
    .status == "deployed_kms_binding_pending_timelock" and
    .policyState == "oracle_policy_frozen_kms_binding_pending_timelock" and
    .allowedOracleComposeHashCount == 1 and
    .pendingOracleComposeHashCount == 0 and
    .oracleComposeHashAllowed == true and
    .oracleComposeHashPendingActivatesAt == 0 and
    .oracleCodeFrozen == true and .kmsBindingFrozen == false and
    .consumerManagerAdditionsFrozen == false and .consumerRegistryFrozen == false and
    .releaseConfigurationReady == false and
    active_kms_is_zero and
    (.pendingKmsContract | is_address) and
    (.pendingKmsRuntimeCodeHash | is_nonzero_bytes32) and
    (.pendingKmsImplementation | is_address) and
    (.pendingKmsImplementationRuntimeCodeHash | is_nonzero_bytes32) and
    (.pendingKmsRegistrationTxHash | is_nonzero_bytes32) and
    .pendingKmsRegistrationBlock > 0 and
    (.pendingKmsRegistrationBlockHash | is_nonzero_bytes32) and
    (.pendingTargetBootInfoHash | is_nonzero_bytes32) and
    (.pendingRestartKeyDerivationProofHash | is_nonzero_bytes32) and
    .pendingKmsBindingActivatesAt > 0
  elif $phase == 4 then
    .status == "deployed_exact_email_release_frozen_ready" and
    .policyState == "exact_email_release_frozen_ready" and
    .allowedOracleComposeHashCount == 1 and
    .pendingOracleComposeHashCount == 0 and
    .oracleComposeHashAllowed == true and
    .oracleComposeHashPendingActivatesAt == 0 and
    .oracleCodeFrozen == true and .kmsBindingFrozen == true and
    .consumerManagerAdditionsFrozen == true and .consumerRegistryFrozen == true and
    .releaseConfigurationReady == true and
    (.releaseOracleComposeHash | is_nonzero_bytes32) and
    (.releaseDeviceId | is_nonzero_bytes32) and
    (.releaseConsumerManager | is_address) and
    (.releaseConsumerAppId | is_address) and
    (.releaseConsumerComposeHash | is_nonzero_bytes32) and
    (.kmsContract | is_address) and
    (.kmsRuntimeCodeHash | is_nonzero_bytes32) and
    (.kmsImplementation | is_address) and
    (.kmsImplementationRuntimeCodeHash | is_nonzero_bytes32) and
    (.kmsRegistrationTxHash | is_nonzero_bytes32) and
    .kmsRegistrationBlock > 0 and
    (.kmsRegistrationBlockHash | is_nonzero_bytes32) and
    (.targetBootInfoHash | is_nonzero_bytes32) and
    (.restartKeyDerivationProofHash | is_nonzero_bytes32) and
    pending_kms_is_zero
  else false
  end;

if (.network.chainId != 84532) then
  fail("deployment ledger is not Base Sepolia")
elif (.contracts.emailOracleAuth | type) != "object" then
  fail("deployment ledger EmailOracleAuth entry is missing")
elif ((.contracts.emailOracleAuth.address | ascii_downcase) != ($emailOracleAuthAddress | ascii_downcase)) then
  fail("deployment ledger EmailOracleAuth address mismatch")
elif ((.contracts.emailOracleAuth.runtimeCodeHash | ascii_downcase) != ($runtimeCodeHash | ascii_downcase)) then
  fail("deployment ledger EmailOracleAuth runtime mismatch")
elif .contracts.emailOracleAuth.sourceCommit != $sourceCommit then
  fail("deployment ledger EmailOracleAuth source mismatch")
elif (($emailOracleAuthAddress | is_address) | not) then
  fail("EmailOracleAuth address is invalid")
elif (($runtimeCodeHash | is_nonzero_bytes32) | not) then
  fail("EmailOracleAuth runtime hash is invalid")
elif ($sourceCommit | test("^[0-9a-f]{40}$") | not) or ($sourceCommit == ("0" * 40)) then
  fail("email release source commit is invalid")
elif ($finalAuthoritySha256 | test("^sha256:[0-9a-f]{64}$") | not)
  or ($finalAuthoritySha256 == ("sha256:" + ("0" * 64))) then
  fail("email release final authority hash is invalid")
elif ($reviewEnvelopeSha256 | test("^sha256:[0-9a-f]{64}$") | not)
  or ($reviewEnvelopeSha256 == ("sha256:" + ("0" * 64))) then
  fail("email release review envelope hash is invalid")
elif ($recordedAt | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") | not) then
  fail("email release timestamp is invalid")
elif (($postState | validate_post_state) == null) then
  fail("email release post-state is invalid")
elif (($postState | valid_phase_post_state($phase)) | not) then
  fail("email release post-state does not match the exact phase")
elif (($actionRecords | type) != "array")
  or (($actionRecords | length) != (expected_actions($phase) | length)) then
  fail("email release action count is invalid")
elif ([$actionRecords[].action] != expected_actions($phase)) then
  fail("email release actions do not match the phase")
elif ([$actionRecords[].transactionHash] | unique | length) != ($actionRecords | length) then
  fail("email release transaction hashes are not unique")
elif ($actionRecords | all(
  keys == ["action", "blockHash", "blockNumber", "blockTimestamp", "transactionHash"]
  and (.action | type == "string" and length > 0 and length <= 80)
  and (.transactionHash | is_nonzero_bytes32)
  and (.blockHash | is_nonzero_bytes32)
  and (.blockNumber | is_uint and . > 0)
  and (.blockTimestamp | is_uint and . > 0)
) | not) then
  fail("email release action receipt is invalid")
elif ((.emailOracleReleaseHistory // []) | type) != "array" then
  fail("email release history is not an array")
elif (
  [(.emailOracleReleaseHistory // [])[]
    | select(
        type == "object" and
        .kind == "email_oracle_exact_release_action" and
        (.emailOracleAuthAddress | type) == "string" and
        (.emailOracleAuthAddress | ascii_downcase) == ($emailOracleAuthAddress | ascii_downcase) and
        .sourceCommit == $sourceCommit
      )
  ] as $prior |
  ([$prior[] | {phase, actionIndex, action}] != expected_prior_actions($phase)) or
  ($prior | any(
    keys != [
      "action",
      "actionIndex",
      "blockHash",
      "blockNumber",
      "blockTimestamp",
      "chainId",
      "emailOracleAuthAddress",
      "finalAuthoritySha256",
      "kind",
      "phase",
      "postState",
      "recordedAt",
      "reviewEnvelopeSha256",
      "runtimeCodeHash",
      "sourceCommit",
      "transactionHash"
    ] or
    .chainId != 84532 or
    ((.runtimeCodeHash // "") | ascii_downcase) != ($runtimeCodeHash | ascii_downcase) or
    .finalAuthoritySha256 != $finalAuthoritySha256 or
    (.reviewEnvelopeSha256 | type != "string" or test("^sha256:[0-9a-f]{64}$") | not) or
    (.transactionHash | type != "string" or test("^0x[0-9a-f]{64}$") | not) or
    (.blockHash | type != "string" or test("^0x[0-9a-f]{64}$") | not) or
    (.blockNumber | is_uint | not) or .blockNumber == 0 or
    (.blockTimestamp | is_uint | not) or .blockTimestamp == 0 or
    (.recordedAt | type != "string" or test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") | not) or
    (.postState | type) != "object" or
    (.phase == 1 and .postState.status != "deployed_oracle_policy_pending_timelock_consumer_bound") or
    (.phase == 2 and .postState.status != "deployed_oracle_policy_frozen_kms_unbound") or
    (.phase == 3 and .postState.status != "deployed_kms_binding_pending_timelock")
  )) or
  (([$prior[].transactionHash] + [$actionRecords[].transactionHash]) | unique | length)
    != (($prior | length) + ($actionRecords | length))
) then
  fail("email release history is missing, reordered, replayed, or bound to another final authority")
else
  .contracts.emailOracleAuth += ($postState + {
    latestReleasePhase: $phase,
    latestReleaseActions: $actionRecords,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleaseFinalAuthoritySha256: $finalAuthoritySha256,
    latestReleaseReviewEnvelopeSha256: $reviewEnvelopeSha256
  })
  | .emailOracleReleaseHistory = ((.emailOracleReleaseHistory // []) + (
      $actionRecords
      | to_entries
      | map({
          kind: "email_oracle_exact_release_action",
          chainId: 84532,
          emailOracleAuthAddress: $emailOracleAuthAddress,
          runtimeCodeHash: $runtimeCodeHash,
          sourceCommit: $sourceCommit,
          finalAuthoritySha256: $finalAuthoritySha256,
          reviewEnvelopeSha256: $reviewEnvelopeSha256,
          phase: $phase,
          actionIndex: .key,
          action: .value.action,
          transactionHash: .value.transactionHash,
          blockNumber: .value.blockNumber,
          blockHash: .value.blockHash,
          blockTimestamp: .value.blockTimestamp,
          recordedAt: $recordedAt,
          postState: $postState
        })
    ))
end
