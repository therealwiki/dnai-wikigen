def require($condition; $message):
  if $condition then . else error($message) end;

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and (ascii_downcase != ("0x" + ("0" * 64)));

def is_tx_hash:
  is_nonzero_bytes32;

def is_source_commit:
  type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40);

def is_sha256_digest:
  type == "string" and test("^sha256:[0-9a-f]{64}$") and . != ("sha256:" + ("0" * 64));

def is_safe_uint:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;

def is_utc_timestamp:
  type == "string"
  and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");

def zero_address: "0x0000000000000000000000000000000000000000";
def zero_bytes32: "0x0000000000000000000000000000000000000000000000000000000000000000";

def expected_phase_functions($releasePhase):
  if $releasePhase == 1 then
    [
      "proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
      "proposeResultVerifier(address)",
      "proposeAttestationBinding(address,bytes32)"
    ]
  elif $releasePhase == 2 then
    [
      "activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
      "activateResultVerifier()",
      "freezeResultVerifier()",
      "activateAttestationBinding()",
      "freezeAttestationBinding()",
      "proposeTeeIdentity(address,bytes32)"
    ]
  elif $releasePhase == 3 then
    [
      "activateTeeIdentity(address)",
      "freezeComposeAndEvaluatorPolicySets()",
      "freezeTeeIdentityAdditions()",
      "proposeDeveloper(address)"
    ]
  else []
  end;

def valid_recorded_operator_transactions($entry; $operator; $room):
  if $entry.phase < 4 then
    ($entry.operatorTransactions | type) == "array"
    and ($entry.operatorTransactions | length)
      == (expected_phase_functions($entry.phase) | length)
    and $entry.operatorTransactionCount == ($entry.operatorTransactions | length)
    and ($entry.operatorTransactionsSha256 | is_sha256_digest)
    and ([$entry.operatorTransactions[].sequence]
      == [range(0; ($entry.operatorTransactions | length))])
    and ([$entry.operatorTransactions[].functionSignature]
      == expected_phase_functions($entry.phase))
    and ([$entry.operatorTransactions[].transactionHash] | unique | length)
      == ($entry.operatorTransactions | length)
    and all($entry.operatorTransactions[];
      (.transactionHash | is_tx_hash)
      and ((.sender // "") | ascii_downcase) == ($operator | ascii_downcase)
      and ((.target // "") | ascii_downcase) == ($room | ascii_downcase)
      and (.calldataSha256 | is_sha256_digest)
      and .receiptStatus == "success"
      and (.blockNumber | is_safe_uint)
      and .blockNumber > 0
      and (.blockHash | is_nonzero_bytes32)
    )
    and (($entry.operatorTransactions[-1].transactionHash // "") | ascii_downcase)
      == (($entry.transactionHash // "") | ascii_downcase)
    and $entry.operatorTransactions[-1].blockNumber == $entry.blockNumber
  else
    $entry.operatorTransactionCount == 0
    and $entry.operatorTransactions == []
    and $entry.operatorTransactionsSha256 == null
  end;

. as $root
| (.freshDeployment.contractSuite.deploymentIntentSha256 // null) as $deploymentIntentSha256
| (.contracts.diligenceRoom.deploymentTx // null) as $diligenceRoomDeploymentTx
| (.diligenceReleaseHistory // []) as $releaseHistory
| require(type == "object"; "deployment ledger must be a JSON object")
| require((.network | type) == "object" and .network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((.contracts | type) == "object" and (.contracts.diligenceRoom | type) == "object";
    "deployment ledger is missing contracts.diligenceRoom")
| require((.freshDeployment.contractSuite | type) == "object";
    "deployment ledger is missing freshDeployment.contractSuite")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "release chainId must be Base Sepolia")
| require(($roomAddress | is_address) and ($roomAddress | ascii_downcase) != zero_address;
    "DiligenceRoom address is invalid")
| require(($deploymentOperator | is_address)
    and ($deploymentOperator | ascii_downcase) != zero_address;
    "deployment operator is invalid")
| require(($governanceController | is_address)
    and ($governanceController | ascii_downcase) != zero_address;
    "DiligenceRoom governance controller is invalid")
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "DiligenceRoom runtime code hash is invalid")
| require(($sourceCommit | is_source_commit);
    "release source commit is invalid")
| require(($reviewEnvelopeSha256 | is_sha256_digest);
    "review envelope hash is invalid")
| require(($finalAuthoritySha256 | is_sha256_digest);
    "final authority hash is invalid")
| require(($deploymentIntentSha256 | is_sha256_digest);
    "deployment intent lineage hash is invalid")
| require(($deploymentIntentSha256Expected | is_sha256_digest)
    and $deploymentIntentSha256 == $deploymentIntentSha256Expected;
    "deployment ledger does not match the reviewed deployment intent")
| require(($diligenceRoomDeploymentTx | is_tx_hash);
    "DiligenceRoom deployment transaction lineage is invalid")
| require(
    (.freshDeployment.contractSuite.broadcastTransactions | type) == "array"
    and ((.freshDeployment.contractSuite.broadcastTransactions[0].transactionHash // "")
      | ascii_downcase) == ($diligenceRoomDeploymentTx | ascii_downcase)
    and .freshDeployment.contractSuite.broadcastTransactions[0].sequence == 0
    and .freshDeployment.contractSuite.broadcastTransactions[0].contractKey
      == "diligenceRoom"
    and .freshDeployment.contractSuite.broadcastTransactions[0].contractName
      == "DiligenceRoom"
    and .freshDeployment.contractSuite.broadcastTransactions[0].transactionType
      == "CREATE"
    and .freshDeployment.contractSuite.broadcastTransactions[0].functionSignature
      == "constructor(bool,address)"
    and ((.freshDeployment.contractSuite.broadcastTransactions[0].transactionFrom // "")
      | ascii_downcase) == ($deploymentOperator | ascii_downcase)
    and ((.freshDeployment.contractSuite.broadcastTransactions[0].receiptContractAddress // "")
      | ascii_downcase) == ($roomAddress | ascii_downcase);
    "DiligenceRoom deployment transaction is not cross-bound to fresh broadcast evidence")
| require(($phase | is_safe_uint)
    and ($phase == 1 or $phase == 2 or $phase == 3 or $phase == 4);
    "diligence release phase is invalid")
| require(($tx | is_tx_hash); "release transaction hash is invalid")
| require(($block | is_safe_uint) and $block > 0; "release block number is invalid")
| require(($blockTimestamp | is_safe_uint) and $blockTimestamp > 0;
    "release block timestamp is invalid")
| require(($recordedAt | is_utc_timestamp); "release timestamp is invalid")
| require(($teeIdentity | is_address) and ($teeIdentity | ascii_downcase) != zero_address;
    "diligence TEE identity is invalid")
| require(($composeHash | is_nonzero_bytes32); "diligence compose hash is invalid")
| require(($resultVerifier | is_address)
    and ($resultVerifier | ascii_downcase) != zero_address;
    "diligence result verifier is invalid")
| require(
    ([$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3]
      | all(is_nonzero_bytes32)
      and all(. == ascii_downcase)
      and . == sort
      and (unique | length) == 3);
    "diligence evaluator policy commitments must be exact, lowercase, distinct, and sorted")
| require(($evaluatorPolicySetRoot | is_nonzero_bytes32)
    and $evaluatorPolicySetRoot == ($evaluatorPolicySetRoot | ascii_downcase);
    "diligence evaluator policy-set root is invalid")
| require(($attestationVerifier | is_address)
    and ($attestationVerifier | ascii_downcase) != zero_address;
    "diligence attestation verifier is invalid")
| require(($resultVerifier | ascii_downcase) != ($attestationVerifier | ascii_downcase)
    and ($resultVerifier | ascii_downcase) != ($teeIdentity | ascii_downcase)
    and ($attestationVerifier | ascii_downcase) != ($teeIdentity | ascii_downcase);
    "diligence signer and TEE roles must be distinct")
| require(
    ([$deploymentOperator, $governanceController, $roomAddress, $resultVerifier,
      $attestationVerifier, $teeIdentity]
      | map(ascii_downcase) | unique | length) == 6;
    "diligence governance, operator, room, verifier, and TEE roles must be distinct")
| require(($attestationPolicyHash | is_nonzero_bytes32);
    "diligence attestation policy hash is invalid")
| require(($activeResultVerifier | is_address)
    and ($pendingResultVerifier | is_address);
    "result verifier post-state is invalid")
| require(($activeDeveloper | is_address)
    and ($pendingDeveloper | is_address);
    "developer governance post-state is invalid")
| require(($activeAttestationVerifier | is_address)
    and ($pendingAttestationVerifier | is_address);
    "attestation verifier post-state is invalid")
| require(($activeAttestationPolicyHash | is_bytes32)
    and ($pendingAttestationPolicyHash | is_bytes32)
    and ($activeTeeComposeHash | is_bytes32)
    and ($pendingTeeComposeHash | is_bytes32)
    and ($activeEvaluatorPolicySetRoot | is_bytes32);
    "bytes32 post-state is invalid")
| require(($approvedComposeCount | is_safe_uint)
    and ($approvedTeeCount | is_safe_uint)
    and ($pendingComposeCount | is_safe_uint)
    and ($pendingTeeCount | is_safe_uint)
    and ($approvedEvaluatorPolicyCount | is_safe_uint)
    and ($pendingEvaluatorPolicyCount | is_safe_uint)
    and ($pendingComposeActivatesAt | is_safe_uint)
    and ($pendingTeeActivatesAt | is_safe_uint)
    and ($pendingAttestationActivatesAt | is_safe_uint)
    and ($pendingResultVerifierActivatesAt | is_safe_uint)
    and ($pendingEvaluatorPolicy1ActivatesAt | is_safe_uint)
    and ($pendingEvaluatorPolicy2ActivatesAt | is_safe_uint)
    and ($pendingEvaluatorPolicy3ActivatesAt | is_safe_uint)
    and ($pendingDeveloperActivatesAt | is_safe_uint)
    and ($developerTransferDelaySeconds | is_safe_uint)
    and $developerTransferDelaySeconds == 172800;
    "numeric diligence post-state is invalid")
| require(($composeFrozen | type) == "boolean"
    and ($teeFrozen | type) == "boolean"
    and ($attestationFrozen | type) == "boolean"
    and ($resultVerifierFrozen | type) == "boolean"
    and ($evaluatorPolicySetFrozen | type) == "boolean";
    "boolean diligence post-state is invalid")
| require(
    if $phase == 1 then
      $status == "deployed_diligence_compose_and_qvl_pending_timelock"
      and $policyState == "fail_closed_pending_compose_and_attestation_timelocks"
    elif $phase == 2 then
      $status == "deployed_diligence_tee_identity_pending_timelock"
      and $policyState == "fail_closed_pending_tee_identity_timelock"
    elif $phase == 3 then
      $status == "deployed_exact_diligence_release_policy_frozen_pending_governance_timelock"
      and $policyState == "fail_closed_exact_policy_pending_governance_acceptance"
    else
      $status == "deployed_exact_diligence_release_policy_frozen_active"
      and $policyState == "exact_timelocked_diligence_release_policy_frozen_active"
    end;
    "diligence release status does not match the phase")
| require(
    if $phase < 4 then
      $governanceAcceptanceEvidenceMode == "not_applicable"
      and $governanceAcceptanceEvidenceClaim == "operator_forge_broadcast_receipt"
      and $finalizedThroughBlock == 0
    elif $governanceAcceptanceEvidenceMode == "eoa_direct_call" then
      $governanceAcceptanceEvidenceClaim
        == "finalized_direct_eoa_call_event_and_state"
      and ($finalizedThroughBlock | is_safe_uint)
      and $finalizedThroughBlock >= $block
    else
      $governanceAcceptanceEvidenceMode == "contract_event_and_state"
      and $governanceAcceptanceEvidenceClaim
        == "finalized_contract_controller_event_and_state_no_trace_claim"
      and ($finalizedThroughBlock | is_safe_uint)
      and $finalizedThroughBlock >= $block
    end;
    "governance acceptance evidence mode, claim, or finality is invalid")
| require(
    if $phase < 4 then
      ($operatorTransactions | type) == "array"
      and ($operatorTransactions | length)
        == (expected_phase_functions($phase) | length)
      and ($operatorTransactionsSha256 | is_sha256_digest)
      and ([$operatorTransactions[].sequence]
        == [range(0; ($operatorTransactions | length))])
      and ([$operatorTransactions[].functionSignature]
        == expected_phase_functions($phase))
      and ([$operatorTransactions[].transactionHash] | unique | length)
        == ($operatorTransactions | length)
      and all($operatorTransactions[];
        (keys) == [
          "blockHash",
          "blockNumber",
          "calldataSha256",
          "functionSignature",
          "receiptStatus",
          "sender",
          "sequence",
          "target",
          "transactionHash"
        ]
        and (.transactionHash | is_tx_hash)
        and ((.sender // "") | ascii_downcase)
          == ($deploymentOperator | ascii_downcase)
        and ((.target // "") | ascii_downcase)
          == ($roomAddress | ascii_downcase)
        and (.calldataSha256 | is_sha256_digest)
        and .receiptStatus == "success"
        and (.blockNumber | is_safe_uint)
        and .blockNumber > 0
        and (.blockHash | is_nonzero_bytes32)
      )
      and ($operatorTransactions[-1].transactionHash | ascii_downcase)
        == ($tx | ascii_downcase)
      and $operatorTransactions[-1].blockNumber == $block
    else
      $operatorTransactions == []
      and $operatorTransactionsSha256 == null
    end;
    "ordered operator transaction evidence is incomplete or inconsistent")
| require((.contracts.diligenceRoom.address | type) == "string"
    and (.contracts.diligenceRoom.address | ascii_downcase) == ($roomAddress | ascii_downcase);
    "deployment ledger DiligenceRoom address mismatch")
| require((.contracts.diligenceRoom.runtimeCodeHash | type) == "string"
    and (.contracts.diligenceRoom.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger DiligenceRoom runtime code hash mismatch")
| require(.contracts.diligenceRoom.sourceCommit == $sourceCommit
    and .freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger release source commit mismatch")
| require((($root.contracts.diligenceRoom.initialDeveloper // "") | ascii_downcase)
    == ($deploymentOperator | ascii_downcase);
    "deployment ledger initial DiligenceRoom developer mismatch")
| require((($root.contracts.diligenceRoom.releaseGovernanceController // "") | ascii_downcase)
    == ($governanceController | ascii_downcase)
    and (($root.contracts.diligenceRoom.protocolFeeRecipient // "") | ascii_downcase)
      == ($governanceController | ascii_downcase);
    "deployment ledger immutable DiligenceRoom controller or fee recipient mismatch")
| require(($releaseHistory | type) == "array";
    "diligenceReleaseHistory must be an array")
| require(($releaseHistory | length) == ($phase - 1)
    and [$releaseHistory[].phase] == [range(1; $phase)];
    "diligence release history is missing, duplicated, or out of order")
| require(all($releaseHistory[];
    .kind == "diligence_exact_release_policy_phase"
    and .chainId == $chainId
    and ((.diligenceRoomAddress // "") | ascii_downcase)
      == ($roomAddress | ascii_downcase)
    and ((.runtimeCodeHash // "") | ascii_downcase)
      == ($runtimeCodeHash | ascii_downcase)
    and .sourceCommit == $sourceCommit
    and (.reviewEnvelopeSha256 | is_sha256_digest)
    and .finalAuthoritySha256 == $finalAuthoritySha256
    and .deploymentIntentSha256 == $deploymentIntentSha256
    and ((.diligenceRoomDeploymentTx // "") | ascii_downcase)
      == ($diligenceRoomDeploymentTx | ascii_downcase)
    and ((.deploymentOperator // "") | ascii_downcase)
      == ($deploymentOperator | ascii_downcase)
    and ((.governanceController // "") | ascii_downcase)
      == ($governanceController | ascii_downcase)
    and valid_recorded_operator_transactions(.; $deploymentOperator; $roomAddress)
  ); "diligence release history immutable lineage mismatch")
| require((.contracts.diligenceRoom.latestReleasePhase // 0) == ($phase - 1);
    "current DiligenceRoom release phase is out of order")
| require(
    if $phase == 1 or $phase == 2 then
      ($activeDeveloper | ascii_downcase) == ($deploymentOperator | ascii_downcase)
      and ($pendingDeveloper | ascii_downcase) == zero_address
      and $pendingDeveloperActivatesAt == 0
    elif $phase == 3 then
      ($activeDeveloper | ascii_downcase) == ($deploymentOperator | ascii_downcase)
      and ($pendingDeveloper | ascii_downcase) == ($governanceController | ascii_downcase)
      and $pendingDeveloperActivatesAt == ($blockTimestamp + $developerTransferDelaySeconds)
    else
      ($activeDeveloper | ascii_downcase) == ($governanceController | ascii_downcase)
      and ($pendingDeveloper | ascii_downcase) == zero_address
      and $pendingDeveloperActivatesAt == 0
      and (($root.diligenceReleaseHistory[-1].postState.pendingDeveloperActivatesAt // 0)
        <= $blockTimestamp)
    end;
    "developer governance post-state is inconsistent with the release phase")
| require(
    if $phase == 1 then
      $approvedComposeCount == 0 and $approvedTeeCount == 0
      and $pendingComposeCount == 1 and $pendingTeeCount == 0
      and $pendingComposeActivatesAt > 0 and $pendingTeeActivatesAt == 0
      and ($activeResultVerifier | ascii_downcase) == zero_address
      and ($pendingResultVerifier | ascii_downcase) == ($resultVerifier | ascii_downcase)
      and $pendingResultVerifierActivatesAt > 0 and ($resultVerifierFrozen | not)
      and $approvedEvaluatorPolicyCount == 0 and $pendingEvaluatorPolicyCount == 3
      and ($evaluatorPolicySetFrozen | not)
      and ($activeEvaluatorPolicySetRoot | ascii_downcase) == zero_bytes32
      and $pendingEvaluatorPolicy1ActivatesAt > 0
      and $pendingEvaluatorPolicy2ActivatesAt > 0
      and $pendingEvaluatorPolicy3ActivatesAt > 0
      and $activeAttestationVerifier == zero_address
      and $activeAttestationPolicyHash == zero_bytes32
      and ($pendingAttestationVerifier | ascii_downcase) == ($attestationVerifier | ascii_downcase)
      and ($pendingAttestationPolicyHash | ascii_downcase) == ($attestationPolicyHash | ascii_downcase)
      and $pendingAttestationActivatesAt > 0
      and $activeTeeComposeHash == zero_bytes32 and $pendingTeeComposeHash == zero_bytes32
      and ($composeFrozen | not) and ($teeFrozen | not) and ($attestationFrozen | not)
    elif $phase == 2 then
      $approvedComposeCount == 1 and $approvedTeeCount == 0
      and $pendingComposeCount == 0 and $pendingTeeCount == 1
      and $pendingComposeActivatesAt == 0 and $pendingTeeActivatesAt > 0
      and ($activeResultVerifier | ascii_downcase) == ($resultVerifier | ascii_downcase)
      and ($pendingResultVerifier | ascii_downcase) == zero_address
      and $pendingResultVerifierActivatesAt == 0 and $resultVerifierFrozen
      and $approvedEvaluatorPolicyCount == 3 and $pendingEvaluatorPolicyCount == 0
      and ($evaluatorPolicySetFrozen | not)
      and ($activeEvaluatorPolicySetRoot | ascii_downcase) == zero_bytes32
      and $pendingEvaluatorPolicy1ActivatesAt == 0
      and $pendingEvaluatorPolicy2ActivatesAt == 0
      and $pendingEvaluatorPolicy3ActivatesAt == 0
      and ($activeAttestationVerifier | ascii_downcase) == ($attestationVerifier | ascii_downcase)
      and ($activeAttestationPolicyHash | ascii_downcase) == ($attestationPolicyHash | ascii_downcase)
      and $pendingAttestationVerifier == zero_address
      and $pendingAttestationPolicyHash == zero_bytes32
      and $pendingAttestationActivatesAt == 0
      and $activeTeeComposeHash == zero_bytes32
      and ($pendingTeeComposeHash | ascii_downcase) == ($composeHash | ascii_downcase)
      and ($composeFrozen | not) and ($teeFrozen | not) and $attestationFrozen
    else
      $approvedComposeCount == 1 and $approvedTeeCount == 1
      and $pendingComposeCount == 0 and $pendingTeeCount == 0
      and $pendingComposeActivatesAt == 0 and $pendingTeeActivatesAt == 0
      and ($activeResultVerifier | ascii_downcase) == ($resultVerifier | ascii_downcase)
      and ($pendingResultVerifier | ascii_downcase) == zero_address
      and $pendingResultVerifierActivatesAt == 0 and $resultVerifierFrozen
      and $approvedEvaluatorPolicyCount == 3 and $pendingEvaluatorPolicyCount == 0
      and $evaluatorPolicySetFrozen
      and ($activeEvaluatorPolicySetRoot | ascii_downcase) == ($evaluatorPolicySetRoot | ascii_downcase)
      and $pendingEvaluatorPolicy1ActivatesAt == 0
      and $pendingEvaluatorPolicy2ActivatesAt == 0
      and $pendingEvaluatorPolicy3ActivatesAt == 0
      and ($activeAttestationVerifier | ascii_downcase) == ($attestationVerifier | ascii_downcase)
      and ($activeAttestationPolicyHash | ascii_downcase) == ($attestationPolicyHash | ascii_downcase)
      and $pendingAttestationVerifier == zero_address
      and $pendingAttestationPolicyHash == zero_bytes32
      and $pendingAttestationActivatesAt == 0
      and ($activeTeeComposeHash | ascii_downcase) == ($composeHash | ascii_downcase)
      and $pendingTeeComposeHash == zero_bytes32
      and $composeFrozen and $teeFrozen and $attestationFrozen
    end;
    "diligence release post-state is inconsistent with the phase")
| .contracts.diligenceRoom += {
    status: $status,
    policyState: $policyState,
    approvedComposeHashes: (if $approvedComposeCount == 0 then [] else [$composeHash] end),
    approvedTeeIdentities: (if $approvedTeeCount == 0 then [] else [$teeIdentity] end),
    teeIdentityComposeBindings: (
      if $approvedTeeCount == 0 then []
      else [{teeIdentity: $teeIdentity, composeHash: $composeHash}]
      end
    ),
    pendingComposeProposals: (
      if $pendingComposeCount == 0 then []
      else [{composeHash: $composeHash, activatesAt: $pendingComposeActivatesAt}]
      end
    ),
    pendingTeeIdentityProposals: (
      if $pendingTeeCount == 0 then []
      else [{teeIdentity: $teeIdentity, composeHash: $pendingTeeComposeHash, activatesAt: $pendingTeeActivatesAt}]
      end
    ),
    developer: $activeDeveloper,
    pendingDeveloper: $pendingDeveloper,
    pendingDeveloperActivatesAt: $pendingDeveloperActivatesAt,
    developerTransferDelaySeconds: $developerTransferDelaySeconds,
    governanceController: $governanceController,
    governanceHandoffStatus: (
      if $phase < 3 then "not_staged"
      elif $phase == 3 then "pending_delayed_acceptance_fail_closed"
      else "accepted_complete"
      end
    ),
    governanceAcceptanceEvidenceMode: $governanceAcceptanceEvidenceMode,
    governanceAcceptanceEvidenceClaim: $governanceAcceptanceEvidenceClaim,
    governanceAcceptanceFinalizedThroughBlock: $finalizedThroughBlock,
    latestReleaseOperatorTransactionCount: ($operatorTransactions | length),
    latestReleaseOperatorTransactionsSha256: $operatorTransactionsSha256,
    currentOperatorControlled: ($phase < 4),
    resultVerifier: $activeResultVerifier,
    pendingResultVerifier: $pendingResultVerifier,
    pendingResultVerifierActivatesAt: $pendingResultVerifierActivatesAt,
    resultVerifierFrozen: $resultVerifierFrozen,
    evaluatorPolicyCommitments: [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3],
    evaluatorPolicySetRoot: $activeEvaluatorPolicySetRoot,
    approvedEvaluatorPolicyCount: $approvedEvaluatorPolicyCount,
    pendingEvaluatorPolicyCount: $pendingEvaluatorPolicyCount,
    evaluatorPolicySetFrozen: $evaluatorPolicySetFrozen,
    pendingEvaluatorPolicyProposals: (
      if $pendingEvaluatorPolicyCount == 0 then []
      else [
        {policyCommitment: $evaluatorPolicy1, activatesAt: $pendingEvaluatorPolicy1ActivatesAt},
        {policyCommitment: $evaluatorPolicy2, activatesAt: $pendingEvaluatorPolicy2ActivatesAt},
        {policyCommitment: $evaluatorPolicy3, activatesAt: $pendingEvaluatorPolicy3ActivatesAt}
      ]
      end
    ),
    attestationVerifier: $activeAttestationVerifier,
    attestationReleasePolicyHash: $activeAttestationPolicyHash,
    pendingAttestationVerifier: $pendingAttestationVerifier,
    pendingAttestationReleasePolicyHash: $pendingAttestationPolicyHash,
    pendingAttestationBindingActivatesAt: $pendingAttestationActivatesAt,
    attestationBindingFrozen: $attestationFrozen,
    approvedComposeCount: $approvedComposeCount,
    approvedTeeIdentityCount: $approvedTeeCount,
    pendingComposeCount: $pendingComposeCount,
    pendingTeeIdentityCount: $pendingTeeCount,
    composeAdditionsFrozen: $composeFrozen,
    teeIdentityAdditionsFrozen: $teeFrozen,
    latestReleasePhase: $phase,
    latestReleaseTx: $tx,
    latestReleaseBlock: $block,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleaseReviewEnvelopeSha256: $reviewEnvelopeSha256,
    latestReleaseFinalAuthoritySha256: $finalAuthoritySha256
  }
| .diligenceReleaseHistory = ((.diligenceReleaseHistory // []) + [{
    kind: "diligence_exact_release_policy_phase",
    chainId: $chainId,
    diligenceRoomAddress: $roomAddress,
    runtimeCodeHash: $runtimeCodeHash,
    sourceCommit: $sourceCommit,
    deploymentIntentSha256: $deploymentIntentSha256,
    diligenceRoomDeploymentTx: $diligenceRoomDeploymentTx,
    reviewEnvelopeSha256: $reviewEnvelopeSha256,
    finalAuthoritySha256: $finalAuthoritySha256,
    phase: $phase,
    transactionHash: $tx,
    blockNumber: $block,
    blockTimestamp: $blockTimestamp,
    recordedAt: $recordedAt,
    status: $status,
    policyState: $policyState,
    governanceAcceptanceEvidenceMode: $governanceAcceptanceEvidenceMode,
    governanceAcceptanceEvidenceClaim: $governanceAcceptanceEvidenceClaim,
    governanceAcceptanceFinalizedThroughBlock: $finalizedThroughBlock,
    operatorTransactionCount: ($operatorTransactions | length),
    operatorTransactionsSha256: $operatorTransactionsSha256,
    operatorTransactions: $operatorTransactions,
    deploymentOperator: $deploymentOperator,
    governanceController: $governanceController,
    teeIdentity: $teeIdentity,
    composeHash: $composeHash,
    resultVerifier: $resultVerifier,
    evaluatorPolicyCommitments: [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3],
    evaluatorPolicySetRoot: $evaluatorPolicySetRoot,
    attestationVerifier: $attestationVerifier,
    attestationReleasePolicyHash: $attestationPolicyHash,
    postState: {
      developer: $activeDeveloper,
      pendingDeveloper: $pendingDeveloper,
      pendingDeveloperActivatesAt: $pendingDeveloperActivatesAt,
      developerTransferDelaySeconds: $developerTransferDelaySeconds,
      approvedComposeCount: $approvedComposeCount,
      approvedTeeIdentityCount: $approvedTeeCount,
      pendingComposeCount: $pendingComposeCount,
      pendingTeeIdentityCount: $pendingTeeCount,
      pendingComposeActivatesAt: $pendingComposeActivatesAt,
      pendingTeeIdentityActivatesAt: $pendingTeeActivatesAt,
      activeTeeIdentityComposeHash: $activeTeeComposeHash,
      pendingTeeIdentityComposeHash: $pendingTeeComposeHash,
      resultVerifier: $activeResultVerifier,
      pendingResultVerifier: $pendingResultVerifier,
      pendingResultVerifierActivatesAt: $pendingResultVerifierActivatesAt,
      resultVerifierFrozen: $resultVerifierFrozen,
      evaluatorPolicyCommitments: [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3],
      evaluatorPolicySetRoot: $activeEvaluatorPolicySetRoot,
      approvedEvaluatorPolicyCount: $approvedEvaluatorPolicyCount,
      pendingEvaluatorPolicyCount: $pendingEvaluatorPolicyCount,
      evaluatorPolicySetFrozen: $evaluatorPolicySetFrozen,
      pendingEvaluatorPolicy1ActivatesAt: $pendingEvaluatorPolicy1ActivatesAt,
      pendingEvaluatorPolicy2ActivatesAt: $pendingEvaluatorPolicy2ActivatesAt,
      pendingEvaluatorPolicy3ActivatesAt: $pendingEvaluatorPolicy3ActivatesAt,
      attestationVerifier: $activeAttestationVerifier,
      attestationReleasePolicyHash: $activeAttestationPolicyHash,
      pendingAttestationVerifier: $pendingAttestationVerifier,
      pendingAttestationReleasePolicyHash: $pendingAttestationPolicyHash,
      pendingAttestationBindingActivatesAt: $pendingAttestationActivatesAt,
      attestationBindingFrozen: $attestationFrozen,
      composeAdditionsFrozen: $composeFrozen,
      teeIdentityAdditionsFrozen: $teeFrozen
    }
  }])
