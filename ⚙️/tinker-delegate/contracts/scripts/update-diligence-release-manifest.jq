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

. as $root
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
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "DiligenceRoom runtime code hash is invalid")
| require(($sourceCommit | is_source_commit);
    "release source commit is invalid")
| require(($reviewEnvelopeSha256 | is_sha256_digest);
    "review envelope hash is invalid")
| require(($finalAuthoritySha256 | is_sha256_digest);
    "final authority hash is invalid")
| require(($phase | is_safe_uint) and ($phase == 1 or $phase == 2 or $phase == 3);
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
| require(($attestationPolicyHash | is_nonzero_bytes32);
    "diligence attestation policy hash is invalid")
| require(($activeResultVerifier | is_address)
    and ($pendingResultVerifier | is_address);
    "result verifier post-state is invalid")
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
    and ($pendingEvaluatorPolicy3ActivatesAt | is_safe_uint);
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
    else
      $status == "deployed_exact_diligence_release_policy_frozen_active"
      and $policyState == "exact_timelocked_diligence_release_policy_frozen_active"
    end;
    "diligence release status does not match the phase")
| require((.contracts.diligenceRoom.address | type) == "string"
    and (.contracts.diligenceRoom.address | ascii_downcase) == ($roomAddress | ascii_downcase);
    "deployment ledger DiligenceRoom address mismatch")
| require((.contracts.diligenceRoom.runtimeCodeHash | type) == "string"
    and (.contracts.diligenceRoom.runtimeCodeHash | ascii_downcase) == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger DiligenceRoom runtime code hash mismatch")
| require(.contracts.diligenceRoom.sourceCommit == $sourceCommit
    and .freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger release source commit mismatch")
| require((.diligenceReleaseHistory // []) | type == "array";
    "diligenceReleaseHistory must be an array")
| [(.diligenceReleaseHistory // [])[]
    | select(
        .chainId == $chainId
        and ((.diligenceRoomAddress // "") | ascii_downcase) == ($roomAddress | ascii_downcase)
        and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
        and .sourceCommit == $sourceCommit
        and .reviewEnvelopeSha256 == $reviewEnvelopeSha256
        and .finalAuthoritySha256 == $finalAuthoritySha256
      )
    | .phase] as $recordedPhases
| require($recordedPhases == [range(1; $phase)];
    "diligence release history is missing, duplicated, or out of order")
| require((.contracts.diligenceRoom.latestReleasePhase // 0) == ($phase - 1);
    "current DiligenceRoom release phase is out of order")
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
    reviewEnvelopeSha256: $reviewEnvelopeSha256,
    finalAuthoritySha256: $finalAuthoritySha256,
    phase: $phase,
    transactionHash: $tx,
    blockNumber: $block,
    blockTimestamp: $blockTimestamp,
    recordedAt: $recordedAt,
    status: $status,
    policyState: $policyState,
    teeIdentity: $teeIdentity,
    composeHash: $composeHash,
    resultVerifier: $resultVerifier,
    evaluatorPolicyCommitments: [$evaluatorPolicy1, $evaluatorPolicy2, $evaluatorPolicy3],
    evaluatorPolicySetRoot: $evaluatorPolicySetRoot,
    attestationVerifier: $attestationVerifier,
    attestationReleasePolicyHash: $attestationPolicyHash,
    postState: {
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
