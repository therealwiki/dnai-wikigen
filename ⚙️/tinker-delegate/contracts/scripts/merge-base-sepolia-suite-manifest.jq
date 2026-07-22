def address_url($address):
  "https://sepolia.basescan.org/address/" + $address;

def tx_url($tx):
  if $tx == "" then null else "https://sepolia.basescan.org/tx/" + $tx end;

def zero_address: "0x0000000000000000000000000000000000000000";
def zero_bytes32: "0x0000000000000000000000000000000000000000000000000000000000000000";

def exact_fresh_diligence_authority:
  ($verifier | ascii_downcase) == zero_address
  and ($diligencePendingVerifier | ascii_downcase) == zero_address
  and ($diligencePendingVerifierAt | tonumber) == 0
  and $diligenceVerifierFrozen == false
  and ($diligenceAttestationVerifier | ascii_downcase) == zero_address
  and ($diligenceAttestationPolicyHash | ascii_downcase) == zero_bytes32
  and ($diligencePendingAttestationVerifier | ascii_downcase) == zero_address
  and ($diligencePendingAttestationPolicyHash | ascii_downcase) == zero_bytes32
  and ($diligencePendingAttestationAt | tonumber) == 0
  and $diligenceAttestationBindingFrozen == false
  and $diligenceEvaluatorPoliciesAbi == ("0x" + ("0" * 192))
  and ($diligenceApprovedEvaluatorPolicyCount | tonumber) == 0
  and ($diligencePendingEvaluatorPolicyCount | tonumber) == 0
  and ($diligenceEvaluatorPolicySetRoot | ascii_downcase) == zero_bytes32
  and $diligenceEvaluatorPolicySetFrozen == false
  and ($diligenceRequiredEvaluatorPolicyCount | tonumber) == 3;

def confirmed_deployment_receipt($receipts; $key; $operator; $address):
  ($receipts[$key] // null) as $receipt
  | if (
      ($receipt | type) == "object"
      and ($receipt | keys) == [
        "creationInputSha256",
        "deploymentBlock",
        "deploymentBlockHash",
        "deploymentReceiptContractAddress",
        "deploymentReceiptStatus",
        "deploymentTxFrom"
      ]
      and $receipt.deploymentTxFrom == $operator
      and $receipt.deploymentReceiptStatus == "success"
      and $receipt.deploymentReceiptContractAddress == $address
      and ($receipt.deploymentBlock | type) == "number"
      and ($receipt.deploymentBlock | floor) == $receipt.deploymentBlock
      and $receipt.deploymentBlock > 0
      and ($receipt.deploymentBlockHash | type) == "string"
      and ($receipt.deploymentBlockHash | test("^0x[0-9a-f]{64}$"))
      and $receipt.deploymentBlockHash != "0x" + ("0" * 64)
      and ($receipt.creationInputSha256 | type) == "string"
      and ($receipt.creationInputSha256 | test("^sha256:[0-9a-f]{64}$"))
      and $receipt.creationInputSha256 != "sha256:" + ("0" * 64)
    ) then $receipt
    else error("missing or invalid confirmed deployment receipt for " + $key)
    end;

def confirmed_broadcast_transactions($transactions; $digest; $operator):
  if (
    ($transactions | type) == "array"
    and ($transactions | length) == 13
    and ($digest | type) == "string"
    and ($digest | test("^sha256:[0-9a-f]{64}$"))
    and $digest != "sha256:" + ("0" * 64)
    and ([$transactions[] | {contractName, transactionType, functionSignature}] == [
      {contractName:"DiligenceRoom",transactionType:"CREATE",functionSignature:"constructor(bool)"},
      {contractName:"DiligenceRoom",transactionType:"CALL",functionSignature:"freezeFeeBps()"},
      {contractName:"DiligenceRoom",transactionType:"CALL",functionSignature:"enableComputeSettlementPolicy()"},
      {contractName:"DiligenceRoom",transactionType:"CALL",functionSignature:"setComposeApprovalRequired(bool)"},
      {contractName:"DiligenceRoom",transactionType:"CALL",functionSignature:"setTeeIdentityApprovalRequired(bool)"},
      {contractName:"DiligenceRoom",transactionType:"CALL",functionSignature:"freezeApprovalRequirements()"},
      {contractName:"TinkerAccountEncumbrance",transactionType:"CREATE",functionSignature:"constructor(address,bytes32,bytes32,uint256,uint256)"},
      {contractName:"RoyaltyDistributor",transactionType:"CREATE",functionSignature:"constructor()"},
      {contractName:"ChallengeRegistry",transactionType:"CREATE",functionSignature:"constructor(address)"},
      {contractName:"ComputeCreditVault",transactionType:"CREATE",functionSignature:"constructor(address,address,uint16)"},
      {contractName:"ComputeCreditVault",transactionType:"CALL",functionSignature:"freezeDeveloperFee()"},
      {contractName:"EmailOracleAuth",transactionType:"CREATE",functionSignature:"constructor(address,uint256,bool,bytes32,bytes32,bool)"},
      {contractName:"ExecutionPolicyAnchor",transactionType:"CREATE",functionSignature:"constructor(address,bytes32,bytes32)"}
    ])
    and all($transactions[];
      (keys) == [
        "blockHash",
        "blockNumber",
        "contractKey",
        "contractName",
        "functionSignature",
        "receiptContractAddress",
        "receiptStatus",
        "sequence",
        "transactionFrom",
        "transactionHash",
        "transactionInputSha256",
        "transactionNonce",
        "transactionTo",
        "transactionType"
      ]
      and .transactionFrom == $operator
      and .receiptStatus == "success"
      and (.sequence | type) == "number"
      and (.transactionNonce | type) == "number"
      and .transactionNonce >= 0
      and .transactionNonce <= 9007199254740991
      and (.blockNumber | type) == "number"
      and .blockNumber > 0
      and .blockNumber <= 9007199254740991
      and (.transactionHash | test("^0x[0-9a-f]{64}$"))
      and (.blockHash | test("^0x[0-9a-f]{64}$"))
      and (.transactionInputSha256 | test("^sha256:[0-9a-f]{64}$"))
    )
    and ([range(0; 13) as $index | $transactions[$index].sequence == $index] | all)
    and ([range(1; 13) as $index |
      $transactions[$index].transactionNonce == ($transactions[$index - 1].transactionNonce + 1)
    ] | all)
    and ([$transactions[].transactionHash] | unique | length) == 13
  ) then $transactions
  else error("missing or invalid exact ordered 13-transaction broadcast evidence")
  end;

. as $root
| confirmed_deployment_receipt($deploymentReceipts; "diligenceRoom"; $operator; $diligence) as $diligenceReceipt
| confirmed_deployment_receipt($deploymentReceipts; "tinkerAccountEncumbrance"; $operator; $encumbrance) as $encumbranceReceipt
| confirmed_deployment_receipt($deploymentReceipts; "royaltyDistributor"; $operator; $royalty) as $royaltyReceipt
| confirmed_deployment_receipt($deploymentReceipts; "challengeRegistry"; $operator; $challenge) as $challengeReceipt
| confirmed_deployment_receipt($deploymentReceipts; "computeCreditVault"; $operator; $computeVault) as $computeVaultReceipt
| confirmed_deployment_receipt($deploymentReceipts; "emailOracleAuth"; $operator; $emailOracle) as $emailOracleReceipt
| confirmed_deployment_receipt($deploymentReceipts; "executionPolicyAnchor"; $operator; $executionPolicyAnchor) as $executionPolicyAnchorReceipt
| confirmed_broadcast_transactions($broadcastTransactions; $broadcastTransactionsSha256; $operator) as $confirmedBroadcastTransactions
| if exact_fresh_diligence_authority then .
  else error("fresh DiligenceRoom signer, QVL, or evaluator-policy authority is not exactly empty")
  end
| ($root.contracts // {}) as $previousContracts
| .schemaVersion = 2
| del(.notAuthorityForFreshRelease, .supersededBoundary)
| .network = (
    (.network // {}) * {
      name: "Base Sepolia",
      chainId: 84532,
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
      explorerBaseUrl: "https://sepolia.basescan.org"
    }
  )
| .status = "fresh_contract_suite_deployed_pending_cvm_binding"
| .lastReviewedAt = $deployedAt
| .currentOperatorDeployer = {
    address: $operator,
    keystoreAccount: "dev",
    fundingStatus: "verified_during_deployment_preflight",
    privateKeyMaterial: "not_used"
  }
| .deploymentHistory = ((.deploymentHistory // []) + [{
    kind: "fresh_reviewed_scope_contract_suite",
    deployedAt: $deployedAt,
    operator: $operator,
    resultVerifier: $verifier,
    sourceCommit: $sourceCommit,
    deploymentIntentSha256: $deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256: $reviewerAuthorityGenesisAcceptanceSha256,
    deploymentReviewEnvelopeSha256: $deploymentReviewEnvelopeSha256,
    deploymentReviewEvidenceSha256: $deploymentReviewEvidenceSha256,
    authorityStage: "deployment_intent_review_only",
    deploymentReviewSemantics: "out_of_band_review_declaration_not_signature_verified",
    cvmEvidenceStatus: "not_available_at_fresh_contract_broadcast",
    exactCreationInputProof: "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts",
    broadcastTransactionProof: "exact_ordered_13_transaction_receipts_with_consecutive_nonces",
    broadcastTransactionCount: 13,
    broadcastTransactionsSha256: $broadcastTransactionsSha256,
    broadcastTransactions: $confirmedBroadcastTransactions,
    verificationRequested: $verificationRequested,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    previousCurrentContracts: {
      diligenceRoom: ($previousContracts.diligenceRoom // null),
      tinkerAccountEncumbrance: ($previousContracts.tinkerAccountEncumbrance // null),
      royaltyDistributor: ($previousContracts.royaltyDistributor // null),
      challengeRegistry: ($previousContracts.challengeRegistry // null),
      computeCreditVault: ($previousContracts.computeCreditVault // null),
      emailOracleAuth: ($previousContracts.emailOracleAuth // null),
      executionPolicyAnchor: ($previousContracts.executionPolicyAnchor // null)
    },
    deployedContracts: {
      diligenceRoom: {
        address: $diligence,
        deploymentTx: $diligenceTx,
        deploymentTxFrom: $diligenceReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $diligenceReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $diligenceReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $diligenceReceipt.deploymentBlock,
        deploymentBlockHash: $diligenceReceipt.deploymentBlockHash,
        creationInputSha256: $diligenceReceipt.creationInputSha256,
        runtimeCodeHash: $diligenceRuntimeCodeHash,
        resultVerifier: $verifier,
        pendingResultVerifier: $diligencePendingVerifier,
        pendingResultVerifierActivatesAt: ($diligencePendingVerifierAt | tonumber),
        resultVerifierFrozen: $diligenceVerifierFrozen,
        composeApprovalRequired: $diligenceComposeRequired,
        teeIdentityApprovalRequired: $diligenceIdentityRequired,
        approvalRequirementsFrozen: $diligenceApprovalRequirementsFrozen,
        attestationVerifier: $diligenceAttestationVerifier,
        attestationReleasePolicyHash: $diligenceAttestationPolicyHash,
        pendingAttestationVerifier: $diligencePendingAttestationVerifier,
        pendingAttestationReleasePolicyHash: $diligencePendingAttestationPolicyHash,
        pendingAttestationBindingActivatesAt: ($diligencePendingAttestationAt | tonumber),
        attestationBindingFrozen: $diligenceAttestationBindingFrozen,
        evaluatorPolicyCommitments: [],
        evaluatorPolicySetRoot: $diligenceEvaluatorPolicySetRoot,
        approvedEvaluatorPolicyCount: ($diligenceApprovedEvaluatorPolicyCount | tonumber),
        pendingEvaluatorPolicyCount: ($diligencePendingEvaluatorPolicyCount | tonumber),
        evaluatorPolicySetFrozen: $diligenceEvaluatorPolicySetFrozen,
        pendingEvaluatorPolicyProposals: [],
        requiredEvaluatorPolicyCount: ($diligenceRequiredEvaluatorPolicyCount | tonumber),
        approvedComposeCount: ($diligenceApprovedComposeCount | tonumber),
        approvedTeeIdentityCount: ($diligenceApprovedTeeCount | tonumber),
        pendingComposeCount: ($diligencePendingComposeCount | tonumber),
        pendingTeeIdentityCount: ($diligencePendingTeeCount | tonumber),
        composeAdditionsFrozen: $diligenceComposeAdditionsFrozen,
        teeIdentityAdditionsFrozen: $diligenceTeeAdditionsFrozen,
        initialApprovedComposeHashes: [],
        initialApprovedTeeIdentities: [],
        policyState: "fail_closed_pending_cvm_binding",
        feeBps: ($diligenceFeeBps | tonumber),
        feeBpsFrozen: $diligenceFeeBpsFrozen,
        computeSettlementBps: ($diligenceComputeSettlementBps | tonumber),
        computeSettlementPolicyEnabled: $diligenceComputeSettlementPolicyEnabled
        ,productionRelease: $diligenceProductionRelease
        ,dealCount: ($diligenceDealCount | tonumber)
      },
      tinkerAccountEncumbrance: {
        status: "deployed_halted_draft_pending_timelocked_release_policy",
        address: $encumbrance,
        deploymentTx: $encumbranceTx,
        deploymentTxFrom: $encumbranceReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $encumbranceReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $encumbranceReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $encumbranceReceipt.deploymentBlock,
        deploymentBlockHash: $encumbranceReceipt.deploymentBlockHash,
        creationInputSha256: $encumbranceReceipt.creationInputSha256,
        runtimeCodeHash: $encumbranceRuntimeCodeHash,
        owner: $operator,
        pendingOwner: $encumbrancePendingOwner,
        accountCommitment: $accountCommitment,
        maxAddBalanceWei: $maxAddBalanceWei,
        maxSpendWei: $maxSpendWei,
        perOperationCaps: true,
        custodiesFunds: false,
        approvedComposeHashes: [],
        approvedComposeRoot: $encumbranceComposeRoot,
        approvedComposeCount: ($encumbranceComposeCount | tonumber),
        managers: [],
        managerRoot: $encumbranceManagerRoot,
        managerCount: ($encumbranceManagerCount | tonumber),
        releasePolicyCommitment: $encumbranceReleaseCommitment,
        releaseMaxAddBalanceWei: $encumbranceReleaseMaxAddBalanceWei,
        releaseMaxSpendWei: $encumbranceReleaseMaxSpendWei,
        releaseComposeHashes: [],
        releaseComposeRoot: $encumbranceReleaseComposeRoot,
        releaseComposeCount: ($encumbranceReleaseComposeCount | tonumber),
        releaseManagers: [],
        releaseManagerRoot: $encumbranceReleaseManagerRoot,
        releaseManagerCount: ($encumbranceReleaseManagerCount | tonumber),
        pendingAccountCommitment: $encumbrancePendingAccountCommitment,
        pendingMaxAddBalanceWei: $encumbrancePendingMaxAddBalanceWei,
        pendingMaxSpendWei: $encumbrancePendingMaxSpendWei,
        pendingComposeHashes: [],
        pendingComposeRoot: $encumbrancePendingComposeRoot,
        pendingComposeCount: ($encumbrancePendingComposeCount | tonumber),
        pendingManagers: [],
        pendingManagerRoot: $encumbrancePendingManagerRoot,
        pendingManagerCount: ($encumbrancePendingManagerCount | tonumber),
        pendingReleasePolicyCommitment: $encumbrancePendingCommitment,
        pendingReleasePolicyActivatesAt: ($encumbrancePendingAt | tonumber),
        releasePolicyFrozen: $encumbranceReleasePolicyFrozen,
        emergencyHalted: $encumbranceEmergencyHalted,
        policyState: "operations_fail_closed_pending_exact_timelocked_release_policy"
      },
      royaltyDistributor: {
        address: $royalty,
        deploymentTx: $royaltyTx,
        deploymentTxFrom: $royaltyReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $royaltyReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $royaltyReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $royaltyReceipt.deploymentBlock,
        deploymentBlockHash: $royaltyReceipt.deploymentBlockHash,
        creationInputSha256: $royaltyReceipt.creationInputSha256,
        runtimeCodeHash: $royaltyRuntimeCodeHash
      },
      challengeRegistry: {
        address: $challenge,
        deploymentTx: $challengeTx,
        deploymentTxFrom: $challengeReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $challengeReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $challengeReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $challengeReceipt.deploymentBlock,
        deploymentBlockHash: $challengeReceipt.deploymentBlockHash,
        creationInputSha256: $challengeReceipt.creationInputSha256,
        owner: $operator,
        pendingOwner: $challengePendingOwner,
        registryPaused: false,
        challengeCount: 0,
        nextChallengeId: ($challengeNextId | tonumber),
        minimumVersionReviewDelaySeconds: ($challengeMinVersionReviewDelay | tonumber),
        runtimeCodeHash: $challengeRuntimeCodeHash
      },
      computeCreditVault: {
        status: "deployed_paused_fee_frozen_unbound_pending_release_binding",
        address: $computeVault,
        deploymentTx: $computeVaultTx,
        deploymentTxFrom: $computeVaultReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $computeVaultReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $computeVaultReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $computeVaultReceipt.deploymentBlock,
        deploymentBlockHash: $computeVaultReceipt.deploymentBlockHash,
        creationInputSha256: $computeVaultReceipt.creationInputSha256,
        runtimeCodeHash: $computeVaultRuntimeCodeHash,
        owner: $computeVaultOwner,
        developer: $computeVaultDeveloper,
        meteringVerifier: $computeVaultMeteringVerifier,
        meteringQvlVerifier: $computeVaultMeteringQvlVerifier,
        meteringPolicySetHash: $computeVaultMeteringPolicySetHash,
        pendingMeteringVerifier: $computeVaultPendingMeteringVerifier,
        pendingMeteringQvlVerifier: $computeVaultPendingMeteringQvlVerifier,
        pendingMeteringPolicySetHash: $computeVaultPendingMeteringPolicySetHash,
        pendingMeteringBindingActivatesAt: ($computeVaultPendingMeteringAt | tonumber),
        meteringBindingFrozen: $computeVaultMeteringBindingFrozen,
        paused: $computeVaultPaused,
        developerFeeBps: ($computeVaultFeeBps | tonumber),
        developerFeeFrozen: $computeVaultFeeFrozen,
        allowedAssetCount: ($computeVaultAllowedAssetCount | tonumber),
        activeRatePolicyCount: ($computeVaultActiveRateCount | tonumber),
        approvedComposeCount: ($computeVaultApprovedComposeCount | tonumber),
        approvedTeeIdentityCount: ($computeVaultApprovedTeeCount | tonumber),
        pendingAssetCount: ($computeVaultPendingAssetCount | tonumber),
        pendingRatePolicyCount: ($computeVaultPendingRateCount | tonumber),
        pendingComposeCount: ($computeVaultPendingComposeCount | tonumber),
        pendingTeeIdentityCount: ($computeVaultPendingTeeCount | tonumber),
        composePolicyFrozen: $computeVaultComposePolicyFrozen,
        teeIdentityAdditionsFrozen: $computeVaultTeeAdditionsFrozen,
        ratePolicyAdditionsFrozen: $computeVaultRateAdditionsFrozen,
        assetAdditionsFrozen: $computeVaultAssetAdditionsFrozen,
        policyState: "execution_fail_closed_pending_timelocked_release_binding"
      },
      emailOracleAuth: {
        status: "deployed_deny_all_pending_cvm_binding",
        address: $emailOracle,
        deploymentTx: $emailOracleTx,
        deploymentTxFrom: $emailOracleReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $emailOracleReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $emailOracleReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $emailOracleReceipt.deploymentBlock,
        deploymentBlockHash: $emailOracleReceipt.deploymentBlockHash,
        creationInputSha256: $emailOracleReceipt.creationInputSha256,
        owner: $emailOracleOwner,
        pendingOwner: $emailOraclePendingOwner,
        productionRelease: $emailOracleProductionRelease,
        oracleUpgradeDelaySeconds: ($emailOracleDelay | tonumber),
        allowAnyDevice: $emailOracleAllowAny,
        oracleCodeFrozen: $emailOracleCodeFrozen,
        consumerRegistryFrozen: $emailOracleConsumersFrozen,
        consumerManagerAdditionsFrozen: $emailOracleManagerAdditionsFrozen,
        kmsBindingFrozen: $emailOracleKmsFrozen,
        allowedOracleComposeHashCount: ($emailOracleAllowedComposeCount | tonumber),
        pendingOracleComposeHashCount: ($emailOraclePendingComposeCount | tonumber),
        allowedDeviceIdCount: ($emailOracleAllowedDeviceCount | tonumber),
        consumerManagerCount: ($emailOracleManagerCount | tonumber),
        totalConsumerComposeHashCount: ($emailOracleConsumerComposeCount | tonumber),
        releaseOracleComposeHash: $emailOracleReleaseCompose,
        releaseDeviceId: $emailOracleReleaseDevice,
        releaseConsumerManager: $emailOracleReleaseManager,
        releaseConsumerAppId: $emailOracleReleaseApp,
        releaseConsumerComposeHash: $emailOracleReleaseConsumerCompose,
        kmsContract: $emailOracleKmsContract,
        kmsRuntimeCodeHash: $emailOracleKmsRuntimeHash,
        kmsImplementation: $emailOracleKmsImplementation,
        kmsImplementationRuntimeCodeHash: $emailOracleKmsImplementationRuntimeHash,
        kmsRegistrationTxHash: $emailOracleKmsRegistrationTx,
        kmsRegistrationBlock: ($emailOracleKmsRegistrationBlock | tonumber),
        kmsRegistrationBlockHash: $emailOracleKmsRegistrationBlockHash,
        targetBootInfoHash: $emailOracleBootInfoHash,
        restartKeyDerivationProofHash: $emailOracleRestartProofHash,
        releaseConfigurationReady: $emailOracleReleaseReady,
        runtimeCodeHash: $emailOracleRuntimeCodeHash,
        policyState: "deny_all_pending_cvm_binding"
      },
      executionPolicyAnchor: {
        status: "deployed_paused_writer_unset_pending_timelocked_release_binding",
        address: $executionPolicyAnchor,
        deploymentTx: $executionPolicyAnchorTx,
        deploymentTxFrom: $executionPolicyAnchorReceipt.deploymentTxFrom,
        deploymentReceiptStatus: $executionPolicyAnchorReceipt.deploymentReceiptStatus,
        deploymentReceiptContractAddress: $executionPolicyAnchorReceipt.deploymentReceiptContractAddress,
        deploymentBlock: $executionPolicyAnchorReceipt.deploymentBlock,
        deploymentBlockHash: $executionPolicyAnchorReceipt.deploymentBlockHash,
        creationInputSha256: $executionPolicyAnchorReceipt.creationInputSha256,
        runtimeCodeHash: $executionPolicyAnchorRuntimeCodeHash,
        deploymentIntentSha256Bytes32: $executionPolicyAnchorDeploymentIntentSha256Bytes32,
        reviewerAuthorityGenesisAcceptanceSha256Bytes32: $executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32,
        authorityCommitmentReadProof: $executionPolicyAnchorAuthorityCommitmentReadProof,
        authorityCommitmentReadBlock: ($executionPolicyAnchorAuthorityCommitmentReadBlock | tonumber),
        authorityCommitmentReadBlockHash: $executionPolicyAnchorAuthorityCommitmentReadBlockHash,
        owner: $executionPolicyAnchorOwner,
        writer: $executionPolicyAnchorWriter,
        writerReleaseCommitment: $executionPolicyAnchorWriterRelease,
        pendingWriter: $executionPolicyAnchorPendingWriter,
        pendingWriterReleaseCommitment: $executionPolicyAnchorPendingRelease,
        pendingWriterActivatesAt: ($executionPolicyAnchorPendingAt | tonumber),
        writerRotationsFrozen: $executionPolicyAnchorRotationsFrozen,
        paused: $executionPolicyAnchorPaused,
        globalSequence: ($executionPolicyAnchorGlobalSequence | tonumber),
        globalHead: $executionPolicyAnchorGlobalHead,
        policyState: "anchoring_fail_closed_pending_timelocked_release_writer"
      }
    }
  }])
| .contracts = (.contracts // {})
| .contracts.diligenceRoom = {
    status: "deployed_fail_closed_pending_tee_binding",
    address: $diligence,
    baseScanUrl: address_url($diligence),
    deploymentTx: $diligenceTx,
    deploymentTxFrom: $diligenceReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $diligenceReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $diligenceReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $diligenceReceipt.deploymentBlock,
    deploymentBlockHash: $diligenceReceipt.deploymentBlockHash,
    creationInputSha256: $diligenceReceipt.creationInputSha256,
    transactionUrl: tx_url($diligenceTx),
    runtimeCodeHash: $diligenceRuntimeCodeHash,
    developer: $operator,
    productionRelease: $diligenceProductionRelease,
    dealCount: ($diligenceDealCount | tonumber),
    resultVerifier: $verifier,
    pendingResultVerifier: $diligencePendingVerifier,
    pendingResultVerifierActivatesAt: ($diligencePendingVerifierAt | tonumber),
    resultVerifierFrozen: $diligenceVerifierFrozen,
    composeApprovalRequired: $diligenceComposeRequired,
    teeIdentityApprovalRequired: $diligenceIdentityRequired,
    approvalRequirementsFrozen: $diligenceApprovalRequirementsFrozen,
    attestationVerifier: $diligenceAttestationVerifier,
    attestationReleasePolicyHash: $diligenceAttestationPolicyHash,
    pendingAttestationVerifier: $diligencePendingAttestationVerifier,
    pendingAttestationReleasePolicyHash: $diligencePendingAttestationPolicyHash,
    pendingAttestationBindingActivatesAt: ($diligencePendingAttestationAt | tonumber),
    attestationBindingFrozen: $diligenceAttestationBindingFrozen,
    evaluatorPolicyCommitments: [],
    evaluatorPolicySetRoot: $diligenceEvaluatorPolicySetRoot,
    approvedEvaluatorPolicyCount: ($diligenceApprovedEvaluatorPolicyCount | tonumber),
    pendingEvaluatorPolicyCount: ($diligencePendingEvaluatorPolicyCount | tonumber),
    evaluatorPolicySetFrozen: $diligenceEvaluatorPolicySetFrozen,
    pendingEvaluatorPolicyProposals: [],
    requiredEvaluatorPolicyCount: ($diligenceRequiredEvaluatorPolicyCount | tonumber),
    approvedComposeCount: ($diligenceApprovedComposeCount | tonumber),
    approvedTeeIdentityCount: ($diligenceApprovedTeeCount | tonumber),
    pendingComposeCount: ($diligencePendingComposeCount | tonumber),
    pendingTeeIdentityCount: ($diligencePendingTeeCount | tonumber),
    composeAdditionsFrozen: $diligenceComposeAdditionsFrozen,
    teeIdentityAdditionsFrozen: $diligenceTeeAdditionsFrozen,
    initialApprovedComposeHashes: [],
    initialApprovedTeeIdentities: [],
    policyState: "fail_closed_pending_cvm_binding",
    feeBps: ($diligenceFeeBps | tonumber),
    feeBpsFrozen: $diligenceFeeBpsFrozen,
    computeSettlementBps: ($diligenceComputeSettlementBps | tonumber),
    computeSettlementPolicyEnabled: $diligenceComputeSettlementPolicyEnabled,
    currentOperatorControlled: true,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.tinkerAccountEncumbrance = {
    status: "deployed_halted_draft_pending_timelocked_release_policy",
    address: $encumbrance,
    baseScanUrl: address_url($encumbrance),
    deploymentTx: $encumbranceTx,
    deploymentTxFrom: $encumbranceReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $encumbranceReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $encumbranceReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $encumbranceReceipt.deploymentBlock,
    deploymentBlockHash: $encumbranceReceipt.deploymentBlockHash,
    creationInputSha256: $encumbranceReceipt.creationInputSha256,
    transactionUrl: tx_url($encumbranceTx),
    runtimeCodeHash: $encumbranceRuntimeCodeHash,
    owner: $operator,
    pendingOwner: $encumbrancePendingOwner,
    accountCommitment: $accountCommitment,
    initialComposeHash: null,
    initialComposeHashApproved: false,
    approvedComposeHashes: [],
    approvedComposeRoot: $encumbranceComposeRoot,
    approvedComposeCount: ($encumbranceComposeCount | tonumber),
    managers: [],
    managerRoot: $encumbranceManagerRoot,
    managerCount: ($encumbranceManagerCount | tonumber),
    maxAddBalanceWei: $maxAddBalanceWei,
    maxSpendWei: $maxSpendWei,
    perOperationCaps: true,
    custodiesFunds: false,
    releasePolicyCommitment: $encumbranceReleaseCommitment,
    releaseMaxAddBalanceWei: $encumbranceReleaseMaxAddBalanceWei,
    releaseMaxSpendWei: $encumbranceReleaseMaxSpendWei,
    releaseComposeHashes: [],
    releaseComposeRoot: $encumbranceReleaseComposeRoot,
    releaseComposeCount: ($encumbranceReleaseComposeCount | tonumber),
    releaseManagers: [],
    releaseManagerRoot: $encumbranceReleaseManagerRoot,
    releaseManagerCount: ($encumbranceReleaseManagerCount | tonumber),
    pendingAccountCommitment: $encumbrancePendingAccountCommitment,
    pendingMaxAddBalanceWei: $encumbrancePendingMaxAddBalanceWei,
    pendingMaxSpendWei: $encumbrancePendingMaxSpendWei,
    pendingComposeHashes: [],
    pendingComposeRoot: $encumbrancePendingComposeRoot,
    pendingComposeCount: ($encumbrancePendingComposeCount | tonumber),
    pendingManagers: [],
    pendingManagerRoot: $encumbrancePendingManagerRoot,
    pendingManagerCount: ($encumbrancePendingManagerCount | tonumber),
    pendingReleasePolicyCommitment: $encumbrancePendingCommitment,
    pendingReleasePolicyActivatesAt: ($encumbrancePendingAt | tonumber),
    releasePolicyFrozen: $encumbranceReleasePolicyFrozen,
    emergencyHalted: $encumbranceEmergencyHalted,
    policyState: "operations_fail_closed_pending_exact_timelocked_release_policy",
    currentOperatorControlled: true,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.royaltyDistributor = {
    status: "deployed_ownerless_pull_payment_rail",
    address: $royalty,
    baseScanUrl: address_url($royalty),
    deploymentTx: $royaltyTx,
    deploymentTxFrom: $royaltyReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $royaltyReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $royaltyReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $royaltyReceipt.deploymentBlock,
    deploymentBlockHash: $royaltyReceipt.deploymentBlockHash,
    creationInputSha256: $royaltyReceipt.creationInputSha256,
    transactionUrl: tx_url($royaltyTx),
    runtimeCodeHash: $royaltyRuntimeCodeHash,
    queryReplayProtection: true,
    queryReplayDomain: "distributor_address_and_query_ref",
    challengePrizeOrBondCustody: false,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.challengeRegistry = {
    status: "deployed_empty_active_registry",
    address: $challenge,
    baseScanUrl: address_url($challenge),
    deploymentTx: $challengeTx,
    deploymentTxFrom: $challengeReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $challengeReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $challengeReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $challengeReceipt.deploymentBlock,
    deploymentBlockHash: $challengeReceipt.deploymentBlockHash,
    creationInputSha256: $challengeReceipt.creationInputSha256,
    transactionUrl: tx_url($challengeTx),
    runtimeCodeHash: $challengeRuntimeCodeHash,
    owner: $operator,
    pendingOwner: $challengePendingOwner,
    registryPaused: false,
    challengeCount: 0,
    nextChallengeId: ($challengeNextId | tonumber),
    minimumVersionReviewDelaySeconds: ($challengeMinVersionReviewDelay | tonumber),
    userCustody: false,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.computeCreditVault = {
    status: "deployed_paused_fee_frozen_unbound_pending_release_binding",
    address: $computeVault,
    baseScanUrl: address_url($computeVault),
    deploymentTx: $computeVaultTx,
    deploymentTxFrom: $computeVaultReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $computeVaultReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $computeVaultReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $computeVaultReceipt.deploymentBlock,
    deploymentBlockHash: $computeVaultReceipt.deploymentBlockHash,
    creationInputSha256: $computeVaultReceipt.creationInputSha256,
    transactionUrl: tx_url($computeVaultTx),
    runtimeCodeHash: $computeVaultRuntimeCodeHash,
    owner: $computeVaultOwner,
    developer: $computeVaultDeveloper,
    meteringVerifier: $computeVaultMeteringVerifier,
    meteringQvlVerifier: $computeVaultMeteringQvlVerifier,
    meteringPolicySetHash: $computeVaultMeteringPolicySetHash,
    pendingMeteringVerifier: $computeVaultPendingMeteringVerifier,
    pendingMeteringQvlVerifier: $computeVaultPendingMeteringQvlVerifier,
    pendingMeteringPolicySetHash: $computeVaultPendingMeteringPolicySetHash,
    pendingMeteringBindingActivatesAt: ($computeVaultPendingMeteringAt | tonumber),
    meteringBindingFrozen: $computeVaultMeteringBindingFrozen,
    paused: $computeVaultPaused,
    developerFeeBps: ($computeVaultFeeBps | tonumber),
    developerFeeFrozen: $computeVaultFeeFrozen,
    allowedAssetCount: ($computeVaultAllowedAssetCount | tonumber),
    activeRatePolicyCount: ($computeVaultActiveRateCount | tonumber),
    approvedComposeCount: ($computeVaultApprovedComposeCount | tonumber),
    approvedTeeIdentityCount: ($computeVaultApprovedTeeCount | tonumber),
    pendingAssetCount: ($computeVaultPendingAssetCount | tonumber),
    pendingRatePolicyCount: ($computeVaultPendingRateCount | tonumber),
    pendingComposeCount: ($computeVaultPendingComposeCount | tonumber),
    pendingTeeIdentityCount: ($computeVaultPendingTeeCount | tonumber),
    approvedComposeHashes: [],
    approvedTeeIdentities: [],
    activeRatePolicies: [],
    enabledErc20Assets: [],
    nativeFundingSupported: true,
    creditsTransferable: false,
    priceOracle: false,
    composePolicyFrozen: $computeVaultComposePolicyFrozen,
    teeIdentityAdditionsFrozen: $computeVaultTeeAdditionsFrozen,
    ratePolicyAdditionsFrozen: $computeVaultRateAdditionsFrozen,
    assetAdditionsFrozen: $computeVaultAssetAdditionsFrozen,
    policyState: "execution_fail_closed_pending_timelocked_release_binding",
    currentOperatorControlled: true,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.emailOracleAuth = {
    status: "deployed_deny_all_pending_cvm_binding",
    address: $emailOracle,
    baseScanUrl: address_url($emailOracle),
    deploymentTx: $emailOracleTx,
    deploymentTxFrom: $emailOracleReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $emailOracleReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $emailOracleReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $emailOracleReceipt.deploymentBlock,
    deploymentBlockHash: $emailOracleReceipt.deploymentBlockHash,
    creationInputSha256: $emailOracleReceipt.creationInputSha256,
    transactionUrl: tx_url($emailOracleTx),
    owner: $emailOracleOwner,
    pendingOwner: $emailOraclePendingOwner,
    productionRelease: $emailOracleProductionRelease,
    oracleUpgradeDelaySeconds: ($emailOracleDelay | tonumber),
    allowAnyDevice: $emailOracleAllowAny,
    oracleCodeFrozen: $emailOracleCodeFrozen,
    consumerRegistryFrozen: $emailOracleConsumersFrozen,
    consumerManagerAdditionsFrozen: $emailOracleManagerAdditionsFrozen,
    kmsBindingFrozen: $emailOracleKmsFrozen,
    allowedOracleComposeHashCount: ($emailOracleAllowedComposeCount | tonumber),
    pendingOracleComposeHashCount: ($emailOraclePendingComposeCount | tonumber),
    allowedDeviceIdCount: ($emailOracleAllowedDeviceCount | tonumber),
    consumerManagerCount: ($emailOracleManagerCount | tonumber),
    totalConsumerComposeHashCount: ($emailOracleConsumerComposeCount | tonumber),
    releaseOracleComposeHash: $emailOracleReleaseCompose,
    releaseDeviceId: $emailOracleReleaseDevice,
    releaseConsumerManager: $emailOracleReleaseManager,
    releaseConsumerAppId: $emailOracleReleaseApp,
    releaseConsumerComposeHash: $emailOracleReleaseConsumerCompose,
    kmsContract: $emailOracleKmsContract,
    kmsRuntimeCodeHash: $emailOracleKmsRuntimeHash,
    kmsImplementation: $emailOracleKmsImplementation,
    kmsImplementationRuntimeCodeHash: $emailOracleKmsImplementationRuntimeHash,
    kmsRegistrationTxHash: $emailOracleKmsRegistrationTx,
    kmsRegistrationBlock: ($emailOracleKmsRegistrationBlock | tonumber),
    kmsRegistrationBlockHash: $emailOracleKmsRegistrationBlockHash,
    targetBootInfoHash: $emailOracleBootInfoHash,
    restartKeyDerivationProofHash: $emailOracleRestartProofHash,
    releaseConfigurationReady: $emailOracleReleaseReady,
    initialOracleComposeHash: null,
    initialDeviceId: null,
    initialConsumerBindings: [],
    policyState: "deny_all_pending_cvm_binding",
    currentOperatorControlled: true,
    runtimeCodeHash: $emailOracleRuntimeCodeHash,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .contracts.executionPolicyAnchor = {
    status: "deployed_paused_writer_unset_pending_timelocked_release_binding",
    address: $executionPolicyAnchor,
    baseScanUrl: address_url($executionPolicyAnchor),
    deploymentTx: $executionPolicyAnchorTx,
    deploymentTxFrom: $executionPolicyAnchorReceipt.deploymentTxFrom,
    deploymentReceiptStatus: $executionPolicyAnchorReceipt.deploymentReceiptStatus,
    deploymentReceiptContractAddress: $executionPolicyAnchorReceipt.deploymentReceiptContractAddress,
    deploymentBlock: $executionPolicyAnchorReceipt.deploymentBlock,
    deploymentBlockHash: $executionPolicyAnchorReceipt.deploymentBlockHash,
    creationInputSha256: $executionPolicyAnchorReceipt.creationInputSha256,
    transactionUrl: tx_url($executionPolicyAnchorTx),
    runtimeCodeHash: $executionPolicyAnchorRuntimeCodeHash,
    deploymentIntentSha256Bytes32: $executionPolicyAnchorDeploymentIntentSha256Bytes32,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32: $executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32,
    authorityCommitmentReadProof: $executionPolicyAnchorAuthorityCommitmentReadProof,
    authorityCommitmentReadBlock: ($executionPolicyAnchorAuthorityCommitmentReadBlock | tonumber),
    authorityCommitmentReadBlockHash: $executionPolicyAnchorAuthorityCommitmentReadBlockHash,
    owner: $executionPolicyAnchorOwner,
    writer: $executionPolicyAnchorWriter,
    writerReleaseCommitment: $executionPolicyAnchorWriterRelease,
    pendingWriter: $executionPolicyAnchorPendingWriter,
    pendingWriterReleaseCommitment: $executionPolicyAnchorPendingRelease,
    pendingWriterActivatesAt: ($executionPolicyAnchorPendingAt | tonumber),
    writerRotationDelaySeconds: 172800,
    writerRotationsFrozen: $executionPolicyAnchorRotationsFrozen,
    paused: $executionPolicyAnchorPaused,
    globalSequence: ($executionPolicyAnchorGlobalSequence | tonumber),
    globalHead: $executionPolicyAnchorGlobalHead,
    resourceAndDecisionPayloadsOnChain: false,
    opaqueCommitmentsOnly: true,
    policyState: "anchoring_fail_closed_pending_timelocked_release_writer",
    currentOperatorControlled: true,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    sourceCommit: $sourceCommit
  }
| .freshDeployment = (.freshDeployment // {})
| .freshDeployment.contractSuite = {
    status: "broadcast_complete_pending_cvm_binding",
    deployedAt: $deployedAt,
    helper: "⚙️/tinker-delegate/contracts/scripts/deploy-base-sepolia.sh",
    forgeScript: "script/DeployFreshSuite.s.sol",
    keystoreAccount: "dev",
    sourceCommit: $sourceCommit,
    deploymentIntentSha256: $deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256: $reviewerAuthorityGenesisAcceptanceSha256,
    deploymentReviewEnvelopeSha256: $deploymentReviewEnvelopeSha256,
    deploymentReviewEvidenceSha256: $deploymentReviewEvidenceSha256,
    authorityStage: "deployment_intent_review_only",
    deploymentReviewSemantics: "out_of_band_review_declaration_not_signature_verified",
    cvmEvidenceStatus: "not_available_at_fresh_contract_broadcast",
    verificationRequested: $verificationRequested,
    verificationStatus: (if $verificationRequested then "pending_submission" else "not_requested" end),
    includesReviewedComputeCreditVault: true,
    excludesChallengePrizeAndCandidateCustodyContracts: true,
    runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
    exactCreationInputProof: "mined_transaction_input_equals_release_snapshot_creation_input_all_contracts",
    broadcastTransactionProof: "exact_ordered_13_transaction_receipts_with_consecutive_nonces",
    broadcastTransactionCount: 13,
    broadcastTransactionsSha256: $broadcastTransactionsSha256,
    broadcastTransactions: $confirmedBroadcastTransactions,
    diligencePolicyState: "fail_closed_pending_cvm_binding",
    computeVaultPolicyState: "execution_fail_closed_pending_timelocked_release_binding",
    emailOraclePolicyState: "deny_all_pending_cvm_binding",
    executionPolicyAnchorState: "anchoring_fail_closed_pending_timelocked_release_writer"
  }
