def require($condition; $message):
  if $condition then . else error($message) end;

def zero_address: "0x0000000000000000000000000000000000000000";
def zero_bytes32: "0x0000000000000000000000000000000000000000000000000000000000000000";

def exact_object($fields):
  type == "object" and keys == ($fields | sort);

def is_address:
  type == "string" and test("^0x[0-9a-f]{40}$");

def is_nonzero_address:
  is_address and . != zero_address;

def is_bytes32:
  type == "string" and test("^0x[0-9a-f]{64}$");

def is_nonzero_bytes32:
  is_bytes32 and . != zero_bytes32;

def is_sha256_digest:
  type == "string"
  and test("^sha256:[0-9a-f]{64}$")
  and . != ("sha256:" + ("0" * 64));

def is_bare_sha256:
  type == "string"
  and test("^[0-9a-f]{64}$")
  and . != ("0" * 64);

def is_source_commit:
  type == "string" and test("^[0-9a-f]{40}$") and . != ("0" * 40);

def is_safe_uint:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;

def is_decimal_uint:
  type == "string" and test("^(0|[1-9][0-9]{0,77})$");

def is_positive_decimal_uint:
  type == "string" and test("^[1-9][0-9]{0,77}$");

def is_utc_timestamp:
  type == "string"
  and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");

def is_millisecond_utc_timestamp:
  type == "string"
  and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$");

def is_calldata:
  type == "string" and test("^0x([0-9a-f]{2})+$") and length >= 10;

def is_controller_id:
  type == "string" and test("^[a-z0-9][a-z0-9._-]{7,63}$");

def is_signature:
  type == "string" and test("^0x[0-9a-f]{130}$");

def is_https_origin:
  type == "string"
  and test("^https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[1-9][0-9]{0,4})?$");

def phase_status($phase):
  if $phase == 1 then "deployed_paused_phase_1_pending_exact_royalty_authority"
  else "deployed_active_exact_royalty_release"
  end;

def phase_policy_state($phase):
  if $phase == 1 then "settlements_fail_closed_pending_timelocked_dual_signer_anchor_release"
  else "exact_dual_signer_anchor_release_active"
  end;

def expected_transaction_count($phase; $executionMode):
  if $phase == 1 and $executionMode == "stage_authority" then 1
  elif $phase == 2 and $executionMode == "activate_and_unpause" then 2
  elif $phase == 2 and $executionMode == "recover_reverted_unpause" then 1
  else 0
  end;

def expected_action($phase; $executionMode; $index):
  if $phase == 1 and $executionMode == "stage_authority" and $index == 0 then
    "propose_authority_binding"
  elif $phase == 2 and $executionMode == "activate_and_unpause" and $index == 0 then
    "activate_authority_proposal"
  elif $phase == 2 and $executionMode == "activate_and_unpause" and $index == 1 then
    "unpause"
  elif $phase == 2 and $executionMode == "recover_reverted_unpause" and $index == 0 then
    "unpause"
  else null
  end;

def abi_address_word($address):
  ("0" * 24) + ($address | ltrimstr("0x"));

def expected_calldata($action; $authority):
  if $action == "propose_authority_binding" then
    "0x2e974627"
      + abi_address_word($authority.settlement_verifier)
      + abi_address_word($authority.qvl_verifier)
      + abi_address_word($authority.anchor_address)
      + ($authority.anchor_writer_release_commitment | ltrimstr("0x"))
  elif $action == "activate_authority_proposal" then "0x552d3bd4"
  elif $action == "unpause" then
    "0x16c38b3c0000000000000000000000000000000000000000000000000000000000000000"
  else null
  end;

def valid_signature_verifier:
  exact_object([
    "build_profile",
    "commit_sha",
    "executable_sha256",
    "executable_user_relative_path",
    "tool",
    "version"
  ])
  and .build_profile == "maxperf"
  and .commit_sha == "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2"
  and .executable_sha256 == "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d"
  and .executable_user_relative_path == ".foundry/bin/cast"
  and .tool == "cast wallet verify"
  and .version == "1.5.1-stable";

def valid_authority:
  exact_object([
    "anchor_address",
    "anchor_runtime_code_hash",
    "anchor_writer",
    "anchor_writer_release_commitment",
    "authority_nonce",
    "distributor_address",
    "distributor_runtime_code_hash",
    "owner",
    "qvl_verifier",
    "release_policy_commitment",
    "settlement_verifier"
  ])
  and (.distributor_address | is_nonzero_address)
  and (.distributor_runtime_code_hash | is_nonzero_bytes32)
  and (.owner | is_nonzero_address)
  and (.settlement_verifier | is_nonzero_address)
  and (.qvl_verifier | is_nonzero_address)
  and (.anchor_address | is_nonzero_address)
  and (.anchor_runtime_code_hash | is_nonzero_bytes32)
  and (.anchor_writer | is_nonzero_address)
  and (.anchor_writer_release_commitment | is_nonzero_bytes32)
  and .authority_nonce == "1"
  and (.release_policy_commitment | is_nonzero_bytes32)
  and ([
    .distributor_address,
    .owner,
    .settlement_verifier,
    .qvl_verifier,
    .anchor_address,
    .anchor_writer
  ] | unique | length) == 6;

def valid_phase_one_prerequisite:
  exact_object([
    "finalized_authority_receipt_sha256",
    "ledger_revision",
    "ledger_revision_receipt_sha256",
    "ledger_sha256",
    "pending_authority_activates_at",
    "phase_one_history_record_sha256",
    "phase_one_finalized_at",
    "phase_one_plan_sha256",
    "proposal_block_hash",
    "proposal_block_number",
    "proposal_tx_hash"
  ])
  and (.phase_one_plan_sha256 | is_sha256_digest)
  and (.phase_one_history_record_sha256 | is_sha256_digest)
  and (.phase_one_finalized_at | is_millisecond_utc_timestamp)
  and (.finalized_authority_receipt_sha256 | is_sha256_digest)
  and (.ledger_sha256 | is_sha256_digest)
  and (.ledger_revision | is_safe_uint)
  and .ledger_revision >= 1 and .ledger_revision <= 4294967295
  and (.ledger_revision_receipt_sha256 | is_sha256_digest)
  and (.proposal_tx_hash | is_nonzero_bytes32)
  and (.proposal_block_number | is_positive_decimal_uint)
  and (.proposal_block_hash | is_nonzero_bytes32)
  and (.pending_authority_activates_at | is_positive_decimal_uint);

def valid_phase_two_recovery:
  exact_object([
    "activation_block_hash",
    "activation_block_number",
    "activation_tx_hash",
    "finalized_recovery_evidence_sha256",
    "prior_phase_two_plan_sha256",
    "prior_unpause_nonce",
    "reverted_unpause_block_hash",
    "reverted_unpause_block_number",
    "reverted_unpause_tx_hash"
  ])
  and (.prior_phase_two_plan_sha256 | is_sha256_digest)
  and (.finalized_recovery_evidence_sha256 | is_sha256_digest)
  and (.activation_tx_hash | is_nonzero_bytes32)
  and (.activation_block_number | is_positive_decimal_uint)
  and (.activation_block_hash | is_nonzero_bytes32)
  and (.reverted_unpause_tx_hash | is_nonzero_bytes32)
  and (.reverted_unpause_block_number | is_positive_decimal_uint)
  and (.reverted_unpause_block_hash | is_nonzero_bytes32)
  and (.prior_unpause_nonce | is_decimal_uint)
  and .activation_tx_hash != .reverted_unpause_tx_hash;

def valid_execution_evidence($phase; $executionMode):
  if $phase == 1 then
    $executionMode == "stage_authority"
    and .phase_one_prerequisite == null
    and .phase_two_recovery == null
  elif $executionMode == "activate_and_unpause" then
    (.phase_one_prerequisite | valid_phase_one_prerequisite)
    and .phase_two_recovery == null
  elif $executionMode == "recover_reverted_unpause" then
    (.phase_one_prerequisite | valid_phase_one_prerequisite)
    and (.phase_two_recovery | valid_phase_two_recovery)
  else false
  end;

def valid_reviewed_transaction($phase; $executionMode; $index; $authority):
  expected_action($phase; $executionMode; $index) as $action
  |
  exact_object([
    "action",
    "calldata",
    "calldata_sha256",
    "nonce",
    "sequence",
    "signer_address",
    "to",
    "value_wei"
  ])
  and .sequence == $index
  and .action == $action
  and .signer_address == $authority.owner
  and .to == $authority.distributor_address
  and .value_wei == "0"
  and (.nonce | is_decimal_uint)
  and .calldata == expected_calldata($action; $authority)
  and (.calldata_sha256 | is_sha256_digest)
  and (
    if $action == "activate_authority_proposal" then
      .calldata_sha256
        == "sha256:121da2d6091ae01d0a21eb03956de5fe8642babcf8134727e1ce265c9f3deac9"
    elif $action == "unpause" then
      .calldata_sha256
        == "sha256:8ee19acc401145c6b99643561186700e09db3d978937442d134be39de863e254"
    else true
    end
  );

def valid_reviewed_transactions($phase; $executionMode; $authority):
  . as $transactions
  | expected_transaction_count($phase; $executionMode) as $count
  | type == "array"
    and $count > 0
    and length == $count
    and ([range(0; $count) as $index
      | ($transactions[$index]
          | valid_reviewed_transaction($phase; $executionMode; $index; $authority))] | all);

def valid_external_signature:
  exact_object(["address", "controller_id", "signature"])
  and (.address | is_nonzero_address)
  and (.controller_id | is_controller_id)
  and (.signature | is_signature);

def valid_verified_signer:
  exact_object(["address", "controller_id", "signature_sha256"])
  and (.address | is_nonzero_address)
  and (.controller_id | is_controller_id)
  and (.signature_sha256 | is_sha256_digest);

def exact_phase_plan($chain; $source):
  . as $plan
  | exact_object(["core", "plan_sha256", "review", "schema", "status"])
    and .schema == "dnai.royalty-release-phase-plan.v2"
    and .status == "reviewed_for_exact_phase"
    and (.plan_sha256 | is_sha256_digest)
    and (.core | exact_object([
      "authority",
      "chain_id",
      "deployment_intent_sha256",
      "expires_at",
      "execution_mode",
      "fresh_contract_deployment_receipt_sha256",
      "phase",
      "phase_one_prerequisite",
      "phase_two_recovery",
      "release_sha",
      "reviewer_authority_current_status_epoch",
      "reviewer_authority_current_status_sha256",
      "reviewer_authority_genesis_acceptance_sha256",
      "reviewer_authority_genesis_sha256",
      "reviewer_root_hash",
      "reviewer_set_sha256",
      "royalty_release_prescriptive_authority_sha256",
      "schema",
      "status",
      "transactions",
      "valid_after"
    ]))
    and .core.schema == "dnai.royalty-release-phase-plan-core.v2"
    and .core.status == "proposed_for_review"
    and .core.chain_id == $chain
    and .core.release_sha == $source
    and (.core.phase == 1 or .core.phase == 2)
    and (.core.execution_mode == "stage_authority"
      or .core.execution_mode == "activate_and_unpause"
      or .core.execution_mode == "recover_reverted_unpause")
    and ($plan.core
      | valid_execution_evidence($plan.core.phase; $plan.core.execution_mode))
    and (.core.valid_after | is_millisecond_utc_timestamp)
    and (.core.expires_at | is_millisecond_utc_timestamp)
    and .core.valid_after < .core.expires_at
    and (.core.deployment_intent_sha256 | is_sha256_digest)
    and (.core.fresh_contract_deployment_receipt_sha256 | is_sha256_digest)
    and (.core.royalty_release_prescriptive_authority_sha256 | is_sha256_digest)
    and (.core.reviewer_authority_genesis_sha256 | is_sha256_digest)
    and (.core.reviewer_authority_genesis_acceptance_sha256 | is_sha256_digest)
    and (.core.reviewer_authority_current_status_epoch | is_safe_uint)
    and .core.reviewer_authority_current_status_epoch > 0
    and (.core.reviewer_authority_current_status_sha256 | is_sha256_digest)
    and (.core.reviewer_root_hash | is_bare_sha256)
    and (.core.reviewer_set_sha256 | is_sha256_digest)
    and (.core.authority | valid_authority)
    and ($plan.core.transactions
      | valid_reviewed_transactions(
          $plan.core.phase;
          $plan.core.execution_mode;
          $plan.core.authority
        ))
    and (.review | exact_object([
      "schema",
      "signature_scheme",
      "signature_verifier",
      "signatures",
      "signing_payload_sha256",
      "verified_signers"
    ]))
    and .review.schema == "dnai.royalty-release-phase-plan-review.v2"
    and .review.signature_scheme == "eip191_personal_sign_secp256k1_low_s_65_byte"
    and (.review.signature_verifier | valid_signature_verifier)
    and (.review.signing_payload_sha256 | is_sha256_digest)
    and (.review.signatures | type == "array" and length == 2)
    and ([.review.signatures[] | valid_external_signature] | all)
    and ([.review.signatures[].address] | unique | length) == 2
    and ([.review.signatures[].controller_id] | unique | length) == 2
    and (.review.verified_signers | type == "array" and length == 2)
    and ([.review.verified_signers[] | valid_verified_signer] | all)
    and ([.review.verified_signers[].address] | unique | length) == 2
    and ([.review.verified_signers[].controller_id] | unique | length) == 2
    and ([.review.verified_signers[] as $verified
      | any($plan.review.signatures[];
          .address == $verified.address and .controller_id == $verified.controller_id)] | all);

def valid_transaction_receipt($phase; $executionMode; $index; $reviewed):
  exact_object([
    "action",
    "blockHash",
    "blockNumber",
    "blockTimestamp",
    "calldata",
    "calldataSha256",
    "nonce",
    "sender",
    "sequence",
    "status",
    "target",
    "transactionHash",
    "transactionIndex",
    "valueWei"
  ])
  and .sequence == $index
  and .action == expected_action($phase; $executionMode; $index)
  and .sender == $reviewed.signer_address
  and .target == $reviewed.to
  and .nonce == $reviewed.nonce
  and .valueWei == $reviewed.value_wei
  and .calldata == $reviewed.calldata
  and .calldataSha256 == $reviewed.calldata_sha256
  and (.transactionHash | is_nonzero_bytes32)
  and .status == "success"
  and (.blockNumber | is_safe_uint) and .blockNumber > 0
  and (.blockHash | is_nonzero_bytes32)
  and (.blockTimestamp | is_safe_uint) and .blockTimestamp > 0
  and (.transactionIndex | is_safe_uint);

def transaction_occurs_before($left; $right):
  ($left.blockNumber < $right.blockNumber)
  or (
    $left.blockNumber == $right.blockNumber
    and $left.transactionIndex < $right.transactionIndex
  );

def valid_transaction_receipts($phase; $executionMode; $reviewedTransactions):
  . as $receipts
  | expected_transaction_count($phase; $executionMode) as $count
  | type == "array"
    and $count > 0
    and length == $count
    and ([range(0; $count) as $index
      | ($receipts[$index]
          | valid_transaction_receipt(
              $phase;
              $executionMode;
              $index;
              $reviewedTransactions[$index]
            ))] | all)
    and ([.[] | .transactionHash] | unique | length) == $count
    and (if $count == 1 then true
      else transaction_occurs_before($receipts[0]; $receipts[1])
      end);

def valid_anchor_state($authority; $deploymentIntentSha256; $reviewerAcceptanceSha256):
  exact_object([
    "address",
    "deploymentIntentSha256",
    "globalHead",
    "globalSequence",
    "owner",
    "paused",
    "pendingOwner",
    "pendingWriter",
    "pendingWriterActivatesAt",
    "pendingWriterReleaseCommitment",
    "reviewerAuthorityGenesisAcceptanceSha256",
    "runtimeCodeHash",
    "writer",
    "writerReleaseCommitment",
    "writerRotationsFrozen"
  ])
  and .address == $authority.anchor_address
  and .runtimeCodeHash == $authority.anchor_runtime_code_hash
  and .owner == $authority.owner
  and .pendingOwner == zero_address
  and .deploymentIntentSha256
    == ("0x" + ($deploymentIntentSha256 | ltrimstr("sha256:")))
  and .reviewerAuthorityGenesisAcceptanceSha256
    == ("0x" + ($reviewerAcceptanceSha256 | ltrimstr("sha256:")))
  and .writer == $authority.anchor_writer
  and .writerReleaseCommitment == $authority.anchor_writer_release_commitment
  and .pendingWriter == zero_address
  and .pendingWriterReleaseCommitment == zero_bytes32
  and .pendingWriterActivatesAt == 0
  and .writerRotationsFrozen
  and (.paused | not)
  and (.globalSequence | is_safe_uint)
  and (.globalHead | is_bytes32);

def valid_royalty_state($phase; $authority):
  exact_object([
    "address",
    "anchorWriterEverConfigured",
    "anchorWriterReleaseCommitment",
    "authorityNonce",
    "executionPolicyAnchor",
    "owner",
    "paused",
    "pendingAnchorWriterReleaseCommitment",
    "pendingAuthorityActivatesAt",
    "pendingAuthorityNonce",
    "pendingAuthorityRevocation",
    "pendingExecutionPolicyAnchor",
    "pendingOwner",
    "pendingQvlVerifier",
    "pendingReleasePolicyCommitment",
    "pendingSettlementVerifier",
    "qvlVerifier",
    "qvlVerifierEverConfigured",
    "releasePolicyCommitment",
    "runtimeCodeHash",
    "settlementVerifier",
    "settlementVerifierEverConfigured"
  ])
  and .address == $authority.distributor_address
  and .runtimeCodeHash == $authority.distributor_runtime_code_hash
  and .owner == $authority.owner
  and .pendingOwner == zero_address
  and (
    if $phase == 1 then
      .paused
      and .settlementVerifier == zero_address
      and .qvlVerifier == zero_address
      and .executionPolicyAnchor == zero_address
      and .anchorWriterReleaseCommitment == zero_bytes32
      and .releasePolicyCommitment == zero_bytes32
      and .authorityNonce == 0
      and .pendingSettlementVerifier == $authority.settlement_verifier
      and .pendingQvlVerifier == $authority.qvl_verifier
      and .pendingExecutionPolicyAnchor == $authority.anchor_address
      and .pendingAnchorWriterReleaseCommitment == $authority.anchor_writer_release_commitment
      and .pendingReleasePolicyCommitment == $authority.release_policy_commitment
      and .pendingAuthorityNonce == 1
      and (.pendingAuthorityActivatesAt | is_safe_uint)
      and .pendingAuthorityActivatesAt > 0
      and (.pendingAuthorityRevocation | not)
      and (.settlementVerifierEverConfigured | not)
      and (.qvlVerifierEverConfigured | not)
      and (.anchorWriterEverConfigured | not)
    else
      (.paused | not)
      and .settlementVerifier == $authority.settlement_verifier
      and .qvlVerifier == $authority.qvl_verifier
      and .executionPolicyAnchor == $authority.anchor_address
      and .anchorWriterReleaseCommitment == $authority.anchor_writer_release_commitment
      and .releasePolicyCommitment == $authority.release_policy_commitment
      and .authorityNonce == 1
      and .pendingSettlementVerifier == zero_address
      and .pendingQvlVerifier == zero_address
      and .pendingExecutionPolicyAnchor == zero_address
      and .pendingAnchorWriterReleaseCommitment == zero_bytes32
      and .pendingReleasePolicyCommitment == zero_bytes32
      and .pendingAuthorityNonce == 0
      and .pendingAuthorityActivatesAt == 0
      and (.pendingAuthorityRevocation | not)
      and .settlementVerifierEverConfigured
      and .qvlVerifierEverConfigured
      and .anchorWriterEverConfigured
    end
  );

def valid_prior_attempt_receipt(
  $action;
  $sequence;
  $status;
  $authority;
  $calldata;
  $calldataSha256
):
  exact_object([
    "action",
    "blockHash",
    "blockNumber",
    "blockTimestamp",
    "calldata",
    "calldataSha256",
    "nonce",
    "sender",
    "sequence",
    "status",
    "target",
    "transactionHash",
    "transactionIndex",
    "valueWei"
  ])
  and .action == $action
  and .sequence == $sequence
  and .status == $status
  and .sender == $authority.owner
  and .target == $authority.distributor_address
  and .valueWei == "0"
  and (.nonce | is_decimal_uint)
  and .calldata == $calldata
  and .calldataSha256 == $calldataSha256
  and (.transactionHash | is_nonzero_bytes32)
  and (.blockNumber | is_safe_uint) and .blockNumber > 0
  and (.blockHash | is_nonzero_bytes32)
  and (.blockTimestamp | is_safe_uint) and .blockTimestamp > 0
  and (.transactionIndex | is_safe_uint);

def valid_phase_two_recovery_evidence(
  $recovery;
  $authority;
  $currentReviewedTransactions;
  $currentTransactionReceipts;
  $finalizedBlockNumber;
  $finalizedBlockTimestamp
):
  . as $evidence
  | exact_object([
      "activationReceipt",
      "evidenceSha256",
      "priorPhaseTwoPlanSha256",
      "revertedUnpauseReceipt",
      "schema"
    ])
    and .schema == "dnai.base-sepolia-royalty-unpause-recovery-evidence.v1"
    and .evidenceSha256 == $recovery.finalized_recovery_evidence_sha256
    and .priorPhaseTwoPlanSha256 == $recovery.prior_phase_two_plan_sha256
    and (.activationReceipt | valid_prior_attempt_receipt(
      "activate_authority_proposal";
      0;
      "success";
      $authority;
      "0x552d3bd4";
      "sha256:121da2d6091ae01d0a21eb03956de5fe8642babcf8134727e1ce265c9f3deac9"
    ))
    and (.revertedUnpauseReceipt | valid_prior_attempt_receipt(
      "unpause";
      1;
      "reverted";
      $authority;
      $currentReviewedTransactions[0].calldata;
      $currentReviewedTransactions[0].calldata_sha256
    ))
    and .activationReceipt.transactionHash == $recovery.activation_tx_hash
    and (.activationReceipt.blockNumber | tostring) == $recovery.activation_block_number
    and .activationReceipt.blockHash == $recovery.activation_block_hash
    and .revertedUnpauseReceipt.transactionHash == $recovery.reverted_unpause_tx_hash
    and (.revertedUnpauseReceipt.blockNumber | tostring)
      == $recovery.reverted_unpause_block_number
    and .revertedUnpauseReceipt.blockHash == $recovery.reverted_unpause_block_hash
    and .revertedUnpauseReceipt.nonce == $recovery.prior_unpause_nonce
    and transaction_occurs_before(.activationReceipt; .revertedUnpauseReceipt)
    and .revertedUnpauseReceipt.blockNumber <= $finalizedBlockNumber
    and .revertedUnpauseReceipt.blockTimestamp <= $finalizedBlockTimestamp
    and ([
      .activationReceipt.transactionHash,
      .revertedUnpauseReceipt.transactionHash,
      $currentTransactionReceipts[0].transactionHash
    ] | unique | length) == 3;

def valid_provider_confirmation(
  $label;
  $finalizedBlockNumber;
  $finalizedBlockHash;
  $finalizedBlockTimestamp;
  $authorityStateSha256;
  $transactionReceiptsSha256;
  $phaseTwoRecoveryEvidenceSha256;
  $authority
):
  exact_object([
    "anchorRuntimeCodeHash",
    "authorityStateSha256",
    "chainId",
    "distributorRuntimeCodeHash",
    "finalizedBlockHash",
    "finalizedBlockNumber",
    "finalizedBlockTimestamp",
    "label",
    "phaseTwoRecoveryEvidenceSha256",
    "rpcOrigin",
    "transactionReceiptsSha256"
  ])
  and .label == $label
  and (.rpcOrigin | is_https_origin)
  and .chainId == 84532
  and .finalizedBlockNumber == $finalizedBlockNumber
  and .finalizedBlockHash == $finalizedBlockHash
  and .finalizedBlockTimestamp == $finalizedBlockTimestamp
  and .distributorRuntimeCodeHash == $authority.distributor_runtime_code_hash
  and .anchorRuntimeCodeHash == $authority.anchor_runtime_code_hash
  and .authorityStateSha256 == $authorityStateSha256
  and .transactionReceiptsSha256 == $transactionReceiptsSha256
  and .phaseTwoRecoveryEvidenceSha256 == $phaseTwoRecoveryEvidenceSha256;

def valid_finalized_authority(
  $phase;
  $executionMode;
  $authority;
  $reviewedTransactions;
  $transactionReceipts;
  $phaseTwoRecovery;
  $deploymentIntentSha256;
  $reviewerAcceptanceSha256
):
  . as $receipt
  | exact_object([
      "authorityState",
      "authorityStateSha256",
      "chainId",
      "finalizedBlockHash",
      "finalizedBlockNumber",
      "finalizedBlockTimestamp",
      "phaseTwoRecoveryEvidence",
      "proof",
      "providerConfirmations",
      "schema",
      "transactionReceipts",
      "transactionReceiptsSha256"
    ])
    and .schema == "dnai.base-sepolia-royalty-finalized-authority.v1"
    and .proof
      == "two_distinct_https_rpcs_exact_same_finalized_numeric_block_runtime_eth_call_and_transaction_receipt_agreement"
    and .chainId == 84532
    and (.finalizedBlockNumber | is_safe_uint) and .finalizedBlockNumber > 0
    and (.finalizedBlockHash | is_nonzero_bytes32)
    and (.finalizedBlockTimestamp | is_safe_uint) and .finalizedBlockTimestamp > 0
    and (.authorityStateSha256 | is_sha256_digest)
    and (.transactionReceiptsSha256 | is_sha256_digest)
    and .transactionReceipts == $transactionReceipts
    and (.transactionReceipts
      | valid_transaction_receipts($phase; $executionMode; $reviewedTransactions))
    and ([.transactionReceipts[].blockNumber] | max) <= .finalizedBlockNumber
    and ([.transactionReceipts[].blockTimestamp] | max) <= .finalizedBlockTimestamp
    and (.authorityState | exact_object(["executionPolicyAnchor", "royaltyDistributor"]))
    and (.authorityState.executionPolicyAnchor
      | valid_anchor_state($authority; $deploymentIntentSha256; $reviewerAcceptanceSha256))
    and (.authorityState.royaltyDistributor | valid_royalty_state($phase; $authority))
    and (
      if $executionMode == "recover_reverted_unpause" then
        (.phaseTwoRecoveryEvidence | valid_phase_two_recovery_evidence(
          $phaseTwoRecovery;
          $authority;
          $reviewedTransactions;
          $transactionReceipts;
          $receipt.finalizedBlockNumber;
          $receipt.finalizedBlockTimestamp
        ))
      else .phaseTwoRecoveryEvidence == null
      end
    )
    and (.providerConfirmations | type == "array" and length == 2)
    and (.providerConfirmations[0] | valid_provider_confirmation(
      "primary";
      $receipt.finalizedBlockNumber;
      $receipt.finalizedBlockHash;
      $receipt.finalizedBlockTimestamp;
      $receipt.authorityStateSha256;
      $receipt.transactionReceiptsSha256;
      (if $executionMode == "recover_reverted_unpause"
        then $phaseTwoRecovery.finalized_recovery_evidence_sha256 else null end);
      $authority
    ))
    and (.providerConfirmations[1] | valid_provider_confirmation(
      "secondary";
      $receipt.finalizedBlockNumber;
      $receipt.finalizedBlockHash;
      $receipt.finalizedBlockTimestamp;
      $receipt.authorityStateSha256;
      $receipt.transactionReceiptsSha256;
      (if $executionMode == "recover_reverted_unpause"
        then $phaseTwoRecovery.finalized_recovery_evidence_sha256 else null end);
      $authority
    ))
    and .providerConfirmations[0].rpcOrigin != .providerConfirmations[1].rpcOrigin;

def reviewer_authority_evidence($plan):
  {
    deploymentIntentSha256: $plan.core.deployment_intent_sha256,
    genesisSha256: $plan.core.reviewer_authority_genesis_sha256,
    genesisAcceptanceSha256: $plan.core.reviewer_authority_genesis_acceptance_sha256,
    currentStatusEpoch: $plan.core.reviewer_authority_current_status_epoch,
    currentStatusSha256: $plan.core.reviewer_authority_current_status_sha256,
    reviewerRootHash: $plan.core.reviewer_root_hash,
    reviewerSetSha256: $plan.core.reviewer_set_sha256
  };

def review_evidence($plan):
  {
    schema: $plan.review.schema,
    signingPayloadSha256: $plan.review.signing_payload_sha256,
    signatureScheme: $plan.review.signature_scheme,
    signatureVerifier: $plan.review.signature_verifier,
    verifiedSigners: $plan.review.verified_signers
  };

def valid_reviewer_authority_evidence:
  exact_object([
    "currentStatusEpoch",
    "currentStatusSha256",
    "deploymentIntentSha256",
    "genesisAcceptanceSha256",
    "genesisSha256",
    "reviewerRootHash",
    "reviewerSetSha256"
  ])
  and (.deploymentIntentSha256 | is_sha256_digest)
  and (.genesisSha256 | is_sha256_digest)
  and (.genesisAcceptanceSha256 | is_sha256_digest)
  and (.currentStatusEpoch | is_safe_uint) and .currentStatusEpoch > 0
  and (.currentStatusSha256 | is_sha256_digest)
  and (.reviewerRootHash | is_bare_sha256)
  and (.reviewerSetSha256 | is_sha256_digest);

def valid_review_evidence:
  exact_object([
    "schema",
    "signatureScheme",
    "signatureVerifier",
    "signingPayloadSha256",
    "verifiedSigners"
  ])
  and .schema == "dnai.royalty-release-phase-plan-review.v2"
  and .signatureScheme == "eip191_personal_sign_secp256k1_low_s_65_byte"
  and (.signatureVerifier | valid_signature_verifier)
  and (.signingPayloadSha256 | is_sha256_digest)
  and (.verifiedSigners | type == "array" and length == 2)
  and ([.verifiedSigners[] | valid_verified_signer] | all)
  and ([.verifiedSigners[].address] | unique | length) == 2
  and ([.verifiedSigners[].controller_id] | unique | length) == 2;

def valid_basic_history_entry:
  . as $entry
  | exact_object([
    "chainId",
    "executionMode",
    "finalizedAuthority",
    "freshContractDeploymentReceiptSha256",
    "kind",
    "phase",
    "phasePlanSha256",
    "phaseOnePrerequisite",
    "phaseTwoRecovery",
    "planExpiresAt",
    "planValidAfter",
    "policyState",
    "postState",
    "recordedAt",
    "releaseAuthority",
    "reviewEvidence",
    "reviewedTransactions",
    "reviewerAuthority",
    "royaltyReleasePrescriptiveAuthoritySha256",
    "royaltyDistributorAddress",
    "runtimeCodeHash",
    "sourceCommit",
    "status",
    "transactionReceipts"
  ])
  and .kind == "royalty_distributor_exact_authority_release_phase"
  and .chainId == 84532
  and (.royaltyDistributorAddress | is_nonzero_address)
  and (.runtimeCodeHash | is_nonzero_bytes32)
  and (.sourceCommit | is_source_commit)
  and (.freshContractDeploymentReceiptSha256 | is_sha256_digest)
  and (.royaltyReleasePrescriptiveAuthoritySha256 | is_sha256_digest)
  and (.phase == 1 or .phase == 2)
  and (.executionMode == "stage_authority"
    or .executionMode == "activate_and_unpause"
    or .executionMode == "recover_reverted_unpause")
  and (
    if .phase == 1 then
      .executionMode == "stage_authority"
      and .phaseOnePrerequisite == null
      and .phaseTwoRecovery == null
    elif .executionMode == "activate_and_unpause" then
      (.phaseOnePrerequisite | valid_phase_one_prerequisite)
      and .phaseTwoRecovery == null
    elif .executionMode == "recover_reverted_unpause" then
      (.phaseOnePrerequisite | valid_phase_one_prerequisite)
      and (.phaseTwoRecovery | valid_phase_two_recovery)
    else false
    end
  )
  and (.phasePlanSha256 | is_sha256_digest)
  and (.planValidAfter | is_millisecond_utc_timestamp)
  and (.planExpiresAt | is_millisecond_utc_timestamp)
  and .planValidAfter < .planExpiresAt
  and (.recordedAt | is_utc_timestamp)
  and .status == phase_status(.phase)
  and .policyState == phase_policy_state(.phase)
  and (.releaseAuthority | valid_authority)
  and .royaltyDistributorAddress == .releaseAuthority.distributor_address
  and .runtimeCodeHash == .releaseAuthority.distributor_runtime_code_hash
  and (.reviewerAuthority | valid_reviewer_authority_evidence)
  and (.reviewEvidence | valid_review_evidence)
  and ($entry.reviewedTransactions
    | valid_reviewed_transactions($entry.phase; $entry.executionMode; $entry.releaseAuthority))
  and ($entry.transactionReceipts
    | valid_transaction_receipts(
        $entry.phase;
        $entry.executionMode;
        $entry.reviewedTransactions
      ));

def valid_complete_history_entry:
  . as $entry
  | valid_basic_history_entry
    and (.postState | valid_royalty_state($entry.phase; $entry.releaseAuthority))
    and .postState == .finalizedAuthority.authorityState.royaltyDistributor
    and (.finalizedAuthority | valid_finalized_authority(
      $entry.phase;
      $entry.executionMode;
      $entry.releaseAuthority;
      $entry.reviewedTransactions;
      $entry.transactionReceipts;
      $entry.phaseTwoRecovery;
      $entry.reviewerAuthority.deploymentIntentSha256;
      $entry.reviewerAuthority.genesisAcceptanceSha256
    ));

def royalty_state_projection($contract):
  {
    address: $contract.address,
    runtimeCodeHash: $contract.runtimeCodeHash,
    owner: $contract.owner,
    pendingOwner: ($contract.pendingOwner // zero_address),
    paused: $contract.paused,
    settlementVerifier: ($contract.settlementVerifier // zero_address),
    qvlVerifier: ($contract.qvlVerifier // zero_address),
    executionPolicyAnchor: ($contract.executionPolicyAnchor // zero_address),
    anchorWriterReleaseCommitment: ($contract.anchorWriterReleaseCommitment // zero_bytes32),
    releasePolicyCommitment: ($contract.releasePolicyCommitment // zero_bytes32),
    authorityNonce: ($contract.authorityNonce // 0),
    pendingSettlementVerifier: ($contract.pendingSettlementVerifier // zero_address),
    pendingQvlVerifier: ($contract.pendingQvlVerifier // zero_address),
    pendingExecutionPolicyAnchor: ($contract.pendingExecutionPolicyAnchor // zero_address),
    pendingAnchorWriterReleaseCommitment:
      ($contract.pendingAnchorWriterReleaseCommitment // zero_bytes32),
    pendingReleasePolicyCommitment: ($contract.pendingReleasePolicyCommitment // zero_bytes32),
    pendingAuthorityNonce: ($contract.pendingAuthorityNonce // 0),
    pendingAuthorityActivatesAt: ($contract.pendingAuthorityActivatesAt // 0),
    pendingAuthorityRevocation: ($contract.pendingAuthorityRevocation // false),
    settlementVerifierEverConfigured: ($contract.settlementVerifierEverConfigured // false),
    qvlVerifierEverConfigured: ($contract.qvlVerifierEverConfigured // false),
    anchorWriterEverConfigured: ($contract.anchorWriterEverConfigured // false)
  };

def valid_fresh_royalty_ledger_state($authority):
  .address == $authority.distributor_address
  and .runtimeCodeHash == $authority.distributor_runtime_code_hash
  and .owner == $authority.owner
  and .pendingOwner == zero_address
  and .paused
  and .settlementVerifier == zero_address
  and .qvlVerifier == zero_address
  and .executionPolicyAnchor == zero_address
  and .anchorWriterReleaseCommitment == zero_bytes32
  and .releasePolicyCommitment == zero_bytes32
  and .authorityNonce == 0
  and .pendingSettlementVerifier == zero_address
  and .pendingQvlVerifier == zero_address
  and .pendingExecutionPolicyAnchor == zero_address
  and .pendingAnchorWriterReleaseCommitment == zero_bytes32
  and .pendingReleasePolicyCommitment == zero_bytes32
  and .pendingAuthorityNonce == 0
  and .pendingAuthorityActivatesAt == 0
  and (.pendingAuthorityRevocation | not)
  and (.settlementVerifierEverConfigured | not)
  and (.qvlVerifierEverConfigured | not)
  and (.anchorWriterEverConfigured | not);

def valid_phase_one_prerequisite_binding($prerequisite; $phaseOneHistory):
  ($prerequisite | valid_phase_one_prerequisite)
  and $phaseOneHistory.phase == 1
  and $phaseOneHistory.executionMode == "stage_authority"
  and $prerequisite.phase_one_plan_sha256 == $phaseOneHistory.phasePlanSha256
  and $prerequisite.proposal_tx_hash
    == $phaseOneHistory.transactionReceipts[0].transactionHash
  and $prerequisite.proposal_block_number
    == ($phaseOneHistory.transactionReceipts[0].blockNumber | tostring)
  and $prerequisite.proposal_block_hash
    == $phaseOneHistory.transactionReceipts[0].blockHash
  and $prerequisite.pending_authority_activates_at
    == ($phaseOneHistory.postState.pendingAuthorityActivatesAt | tostring);

. as $ledger
| require(type == "object" and .schemaVersion == 2;
    "deployment ledger must be a schemaVersion 2 JSON object")
| require(($chainId | is_safe_uint) and $chainId == 84532;
    "Royalty release chainId must be Base Sepolia")
| require(($sourceCommit | is_source_commit);
    "Royalty release source commit is invalid")
| require(($recordedAt | is_utc_timestamp);
    "Royalty release timestamp is invalid")
| require(($phasePlan | exact_phase_plan($chainId; $sourceCommit));
    "reviewed Royalty phase plan is invalid")
| $phasePlan.core.phase as $phase
| $phasePlan.core.execution_mode as $executionMode
| $phasePlan.core.authority as $authority
| require((.network | type) == "object" and .network.chainId == $chainId;
    "deployment ledger chainId mismatch")
| require((.contracts | type) == "object"
    and (.contracts.royaltyDistributor | type) == "object"
    and (.contracts.executionPolicyAnchor | type) == "object";
    "deployment ledger is missing RoyaltyDistributor or ExecutionPolicyAnchor")
| require((.freshDeployment.contractSuite | type) == "object";
    "deployment ledger is missing freshDeployment.contractSuite")
| require(.freshDeployment.contractSuite.sourceCommit == $sourceCommit
    and .contracts.royaltyDistributor.sourceCommit == $sourceCommit
    and .contracts.executionPolicyAnchor.sourceCommit == $sourceCommit;
    "Royalty release source commit does not match the fresh contract suite")
| require((.contracts.royaltyDistributor.address | ascii_downcase)
      == $authority.distributor_address
    and (.contracts.royaltyDistributor.runtimeCodeHash | ascii_downcase)
      == $authority.distributor_runtime_code_hash;
    "deployment ledger RoyaltyDistributor identity mismatch")
| require((.contracts.executionPolicyAnchor.address | ascii_downcase)
      == $authority.anchor_address
    and (.contracts.executionPolicyAnchor.runtimeCodeHash | ascii_downcase)
      == $authority.anchor_runtime_code_hash;
    "deployment ledger ExecutionPolicyAnchor identity mismatch")
| require(($transactionReceipts
      | valid_transaction_receipts(
          $phase;
          $executionMode;
          $phasePlan.core.transactions
        ));
    "Royalty release transaction receipts differ from the reviewed exact plan")
| require(($finalizedAuthority | valid_finalized_authority(
      $phase;
      $executionMode;
      $authority;
      $phasePlan.core.transactions;
      $transactionReceipts;
      $phasePlan.core.phase_two_recovery;
      $phasePlan.core.deployment_intent_sha256;
      $phasePlan.core.reviewer_authority_genesis_acceptance_sha256
    ));
    "Royalty release dual-RPC finalized authority receipt is invalid")
| require((.royaltyReleaseHistory // []) | type == "array";
    "royaltyReleaseHistory must be an array")
| require([(.royaltyReleaseHistory // [])[] | valid_basic_history_entry] | all;
    "royaltyReleaseHistory contains a malformed record")
| [(.royaltyReleaseHistory // [])[]
    | select(.royaltyDistributorAddress == $authority.distributor_address)] as $contractHistory
| require(($contractHistory | length) == ($phase - 1)
    and ([$contractHistory[].phase] == [range(1; $phase)])
    and ([$contractHistory[]
      | valid_complete_history_entry
        and .chainId == $chainId
        and .sourceCommit == $sourceCommit
        and .runtimeCodeHash == $authority.distributor_runtime_code_hash
        and .releaseAuthority == $authority] | all);
    "Royalty release history is missing, dirty, duplicated, or out of order")
| require(
    if $phase == 1 then true
    else valid_phase_one_prerequisite_binding(
      $phasePlan.core.phase_one_prerequisite;
      $contractHistory[0]
    )
    end;
    "phase-two Royalty plan is not bound to the exact recorded phase-one release")
| require((.contracts.royaltyDistributor.latestReleasePhase // 0) == ($phase - 1);
    "current RoyaltyDistributor release phase is out of order")
| (royalty_state_projection(.contracts.royaltyDistributor)) as $currentRoyaltyState
| require(
    if $phase == 1 then
      ($currentRoyaltyState | valid_fresh_royalty_ledger_state($authority))
    else
      $currentRoyaltyState == $contractHistory[-1].postState
    end;
    "current RoyaltyDistributor ledger state does not match the required prior phase")
| [(.royaltyReleaseHistory // [])[]
    | .transactionReceipts[]?.transactionHash] as $priorTransactionHashes
| require(([$transactionReceipts[].transactionHash] + $priorTransactionHashes
      | unique | length)
      == (($transactionReceipts | length) + ($priorTransactionHashes | length));
    "Royalty release transaction receipt replay detected")
| require(
    if $executionMode == "recover_reverted_unpause" then
      ([$phasePlan.core.phase_two_recovery.activation_tx_hash,
        $phasePlan.core.phase_two_recovery.reverted_unpause_tx_hash,
        $transactionReceipts[0].transactionHash] + $priorTransactionHashes
        | unique | length)
        == (3 + ($priorTransactionHashes | length))
      and $phasePlan.core.phase_two_recovery.prior_phase_two_plan_sha256
        != $phasePlan.plan_sha256
      and $phasePlan.core.phase_two_recovery.prior_phase_two_plan_sha256
        != $contractHistory[0].phasePlanSha256
    else true
    end;
    "Royalty recovery evidence replays a prior plan or transaction")
| require([(.royaltyReleaseHistory // [])[].phasePlanSha256]
      | index($phasePlan.plan_sha256) == null;
    "Royalty release phase plan replay detected")
| $finalizedAuthority.authorityState.royaltyDistributor as $postState
| .contracts.royaltyDistributor += ($postState + {
    status: phase_status($phase),
    policyState: phase_policy_state($phase),
    latestReleasePhase: $phase,
    latestReleaseExecutionMode: $executionMode,
    latestReleasePlanSha256: $phasePlan.plan_sha256,
    latestReleasePlanValidAfter: $phasePlan.core.valid_after,
    latestReleasePlanExpiresAt: $phasePlan.core.expires_at,
    latestReleaseTransactions: $transactionReceipts,
    latestReleaseFinalizedAuthority: $finalizedAuthority,
    latestReleaseRecordedAt: $recordedAt,
    latestReleaseSourceCommit: $sourceCommit,
    latestReleasePhaseOnePrerequisite: $phasePlan.core.phase_one_prerequisite,
    latestReleasePhaseTwoRecovery: $phasePlan.core.phase_two_recovery,
    latestFreshContractDeploymentReceiptSha256:
      $phasePlan.core.fresh_contract_deployment_receipt_sha256,
    latestRoyaltyReleasePrescriptiveAuthoritySha256:
      $phasePlan.core.royalty_release_prescriptive_authority_sha256,
    latestReleaseReviewerAuthority: reviewer_authority_evidence($phasePlan),
    latestReleaseReviewEvidence: review_evidence($phasePlan)
  })
| .royaltyReleaseHistory = ((.royaltyReleaseHistory // []) + [{
    kind: "royalty_distributor_exact_authority_release_phase",
    chainId: $chainId,
    royaltyDistributorAddress: $authority.distributor_address,
    runtimeCodeHash: $authority.distributor_runtime_code_hash,
    sourceCommit: $sourceCommit,
    phase: $phase,
    executionMode: $executionMode,
    freshContractDeploymentReceiptSha256:
      $phasePlan.core.fresh_contract_deployment_receipt_sha256,
    royaltyReleasePrescriptiveAuthoritySha256:
      $phasePlan.core.royalty_release_prescriptive_authority_sha256,
    phaseOnePrerequisite: $phasePlan.core.phase_one_prerequisite,
    phaseTwoRecovery: $phasePlan.core.phase_two_recovery,
    phasePlanSha256: $phasePlan.plan_sha256,
    planValidAfter: $phasePlan.core.valid_after,
    planExpiresAt: $phasePlan.core.expires_at,
    recordedAt: $recordedAt,
    status: phase_status($phase),
    policyState: phase_policy_state($phase),
    reviewerAuthority: reviewer_authority_evidence($phasePlan),
    reviewEvidence: review_evidence($phasePlan),
    releaseAuthority: $authority,
    reviewedTransactions: $phasePlan.core.transactions,
    transactionReceipts: $transactionReceipts,
    finalizedAuthority: $finalizedAuthority,
    postState: $postState
  }])
