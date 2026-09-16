def require($condition; $message):
  if $condition then . else error($message) end;

def is_address:
  type == "string" and test("^0x[0-9a-fA-F]{40}$");

def is_nonzero_address:
  is_address and ascii_downcase != "0x0000000000000000000000000000000000000000";

def is_bytes32:
  type == "string" and test("^0x[0-9a-fA-F]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and ascii_downcase != ("0x" + ("0" * 64));

def is_source_commit:
  type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40);

def is_sha256_digest:
  type == "string"
  and test("^sha256:[0-9a-f]{64}$")
  and . != ("sha256:" + ("0" * 64));

def is_safe_uint:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;

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

. as $root
| ($root.freshDeployment.contractSuite.deploymentIntentSha256 // null) as $deploymentIntentSha256
| ($root.contracts.diligenceRoom.deploymentTx // null) as $roomDeploymentTx
| ($root.diligenceReleaseHistory // []) as $history
| require(type == "object"; "deployment ledger must be a JSON object")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "diligence release preflight chainId must be Base Sepolia")
| require(($phase | is_safe_uint)
    and ($phase == 1 or $phase == 2 or $phase == 3 or $phase == 4);
    "diligence release preflight phase is invalid")
| require(($roomAddress | is_nonzero_address);
    "diligence release preflight room address is invalid")
| require(($runtimeCodeHash | is_nonzero_bytes32);
    "diligence release preflight runtime hash is invalid")
| require(($sourceCommit | is_source_commit);
    "diligence release preflight source commit is invalid")
| require(($finalAuthoritySha256 | is_sha256_digest);
    "diligence release preflight final authority is invalid")
| require(($deploymentIntentSha256Expected | is_sha256_digest)
    and $deploymentIntentSha256 == $deploymentIntentSha256Expected;
    "deployment ledger does not match the reviewed deployment intent")
| require(($deploymentOperator | is_nonzero_address)
    and ($governanceController | is_nonzero_address)
    and ($deploymentOperator | ascii_downcase) != ($governanceController | ascii_downcase);
    "diligence release preflight governance roles are invalid")
| require($root.network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((($root.contracts.diligenceRoom.address // "") | ascii_downcase)
    == ($roomAddress | ascii_downcase);
    "deployment ledger DiligenceRoom address mismatch")
| require((($root.contracts.diligenceRoom.runtimeCodeHash // "") | ascii_downcase)
    == ($runtimeCodeHash | ascii_downcase);
    "deployment ledger DiligenceRoom runtime hash mismatch")
| require($root.contracts.diligenceRoom.sourceCommit == $sourceCommit
    and $root.freshDeployment.contractSuite.sourceCommit == $sourceCommit;
    "deployment ledger source lineage mismatch")
| require(($deploymentIntentSha256 | is_sha256_digest);
    "deployment ledger deployment-intent lineage is invalid")
| require(($roomDeploymentTx | is_nonzero_bytes32);
    "deployment ledger DiligenceRoom deployment transaction is invalid")
| require(
    ($root.freshDeployment.contractSuite.broadcastTransactions | type) == "array"
    and (($root.freshDeployment.contractSuite.broadcastTransactions[0].transactionHash // "")
      | ascii_downcase) == ($roomDeploymentTx | ascii_downcase)
    and $root.freshDeployment.contractSuite.broadcastTransactions[0].sequence == 0
    and $root.freshDeployment.contractSuite.broadcastTransactions[0].contractKey
      == "diligenceRoom"
    and $root.freshDeployment.contractSuite.broadcastTransactions[0].contractName
      == "DiligenceRoom"
    and $root.freshDeployment.contractSuite.broadcastTransactions[0].transactionType
      == "CREATE"
    and $root.freshDeployment.contractSuite.broadcastTransactions[0].functionSignature
      == "constructor(bool,address)"
    and (($root.freshDeployment.contractSuite.broadcastTransactions[0].transactionFrom // "")
      | ascii_downcase) == ($deploymentOperator | ascii_downcase)
    and (($root.freshDeployment.contractSuite.broadcastTransactions[0].receiptContractAddress // "")
      | ascii_downcase) == ($roomAddress | ascii_downcase);
    "DiligenceRoom deployment transaction is not cross-bound to fresh broadcast evidence")
| require((($root.contracts.diligenceRoom.initialDeveloper // "") | ascii_downcase)
    == ($deploymentOperator | ascii_downcase);
    "deployment ledger initial developer mismatch")
| require((($root.contracts.diligenceRoom.releaseGovernanceController // "") | ascii_downcase)
    == ($governanceController | ascii_downcase);
    "deployment ledger immutable release controller mismatch")
| require((($root.contracts.diligenceRoom.protocolFeeRecipient // "") | ascii_downcase)
    == ($governanceController | ascii_downcase);
    "deployment ledger immutable fee recipient mismatch")
| require(($history | type) == "array" and ($history | length) == ($phase - 1);
    "diligence release history length is not the exact phase predecessor count")
| require(([$history[].phase] == [range(1; $phase)]);
    "diligence release history phases are missing, duplicated, or out of order")
| require(all($history[];
    .kind == "diligence_exact_release_policy_phase"
    and .chainId == $chainId
    and ((.diligenceRoomAddress // "") | ascii_downcase) == ($roomAddress | ascii_downcase)
    and ((.runtimeCodeHash // "") | ascii_downcase) == ($runtimeCodeHash | ascii_downcase)
    and .sourceCommit == $sourceCommit
    and (.reviewEnvelopeSha256 | is_sha256_digest)
    and .finalAuthoritySha256 == $finalAuthoritySha256
    and .deploymentIntentSha256 == $deploymentIntentSha256
    and ((.diligenceRoomDeploymentTx // "") | ascii_downcase)
      == ($roomDeploymentTx | ascii_downcase)
    and ((.deploymentOperator // "") | ascii_downcase)
      == ($deploymentOperator | ascii_downcase)
    and ((.governanceController // "") | ascii_downcase)
      == ($governanceController | ascii_downcase)
    and (
      if .phase < 4 then
        (.operatorTransactions | type) == "array"
        and (.operatorTransactions | length)
          == (expected_phase_functions(.phase) | length)
        and (.operatorTransactionCount == (.operatorTransactions | length))
        and (.operatorTransactionsSha256 | is_sha256_digest)
        and ([.operatorTransactions[].sequence]
          == [range(0; (.operatorTransactions | length))])
        and ([.operatorTransactions[].functionSignature]
          == expected_phase_functions(.phase))
        and ([.operatorTransactions[].transactionHash] | unique | length)
          == (.operatorTransactions | length)
        and all(.operatorTransactions[];
          (.transactionHash | is_nonzero_bytes32)
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
        and ((.operatorTransactions[-1].transactionHash // "") | ascii_downcase)
          == ((.transactionHash // "") | ascii_downcase)
        and .operatorTransactions[-1].blockNumber == .blockNumber
      else
        .operatorTransactionCount == 0
        and .operatorTransactions == []
        and .operatorTransactionsSha256 == null
      end
    )
  ); "diligence release history immutable lineage mismatch")
| require(($root.contracts.diligenceRoom.latestReleasePhase // 0) == ($phase - 1);
    "current DiligenceRoom release phase is out of order")
| require(
    if $phase == 4 then
      $history[-1].phase == 3
      and (($history[-1].postState.developer // "") | ascii_downcase)
        == ($deploymentOperator | ascii_downcase)
      and (($history[-1].postState.pendingDeveloper // "") | ascii_downcase)
        == ($governanceController | ascii_downcase)
      and ($history[-1].postState.pendingDeveloperActivatesAt | is_safe_uint)
      and $history[-1].postState.pendingDeveloperActivatesAt > 0
      and $history[-1].postState.developerTransferDelaySeconds == 172800
    else true
    end;
    "phase 4 is missing the exact phase-3 pending governance handoff")
| {
    schema: "dnai.diligence-release-ledger-preflight.v1",
    status: "exact_phase_predecessor_lineage_verified",
    chainId: $chainId,
    phase: $phase,
    diligenceRoomAddress: $roomAddress,
    runtimeCodeHash: $runtimeCodeHash,
    sourceCommit: $sourceCommit,
    deploymentIntentSha256: $deploymentIntentSha256,
    diligenceRoomDeploymentTx: $roomDeploymentTx,
    finalAuthoritySha256: $finalAuthoritySha256,
    recordedPhaseCount: ($history | length),
    reviewEnvelopeSemantics:
      "each_phase_independently_reviewed_renewable_envelope_not_lineage_identity"
  }
