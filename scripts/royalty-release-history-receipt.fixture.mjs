// Synthetic deterministic fixture only. It is never live Base Sepolia,
// ceremony-ledger, reviewer, CVM, QVL, or release authority evidence.

import {
  ROYALTY_HISTORY_CONFIGURATION_GETTERS,
  ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA,
  ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS,
  normalizeRoyaltyFinalizedHistoryEvidence,
  royaltyHistoryContractConfigurationSha256,
  royaltyHistoryFrozenLedgerContractSha256,
  royaltyHistoryFullSuiteStateSha256,
  royaltyHistoryLatestStateRecheckSha256,
} from "./royalty-release-finalized-history-evidence.mjs";
import {
  normalizeRoyaltyReleasePrescriptiveAuthority,
  royaltyReleasePrescriptiveAuthoritySha256,
} from "../⚙️/tinker-delegate/contracts/scripts/royalty-release-phase-plan.mjs";
import { syntheticReleaseAuthorityStagesFixture } from "./release-authority-stages.fixture.mjs";

const pin = (byte) => `sha256:${byte.repeat(64)}`;
const word = (byte) => `0x${byte.repeat(64)}`;
const addressWord = (value) => `0x${value.slice(2).padStart(64, "0")}`;
const LEDGER_CONTRACTS = Object.freeze([
  ["diligenceRoom", "developer"],
  ["tinkerAccountEncumbrance", "owner"],
  ["royaltyDistributor", "owner"],
  ["challengeRegistry", "owner"],
  ["computeCreditVault", "owner"],
  ["emailOracleAuth", "owner"],
  ["executionPolicyAnchor", "owner"],
]);

function syntheticLedgerContractRecord(contract, index, history) {
  const [, controlRole] = LEDGER_CONTRACTS[index];
  const record = {
    address: contract.address,
    runtimeCodeHash: contract.runtime_code_hash,
    [controlRole]: contract.control_address,
    syntheticFixtureIndex: index,
  };
  if (index === 2) {
    record.deploymentBlock = history.fresh_state.primary_rpc_block.block_number;
    record.deploymentBlockHash = history.fresh_state.primary_rpc_block.block_hash;
  }
  return record;
}

export async function syntheticRoyaltyFinalizedHistoryEvidence({
  executionMode = "activate_and_unpause",
} = {}) {
  const stages = await syntheticReleaseAuthorityStagesFixture({
    royaltyExecutionMode: executionMode,
  });
  const state = stages.stageTwo.contract_state;
  const history = structuredClone(state.royalty_release_history);
  const sourceContracts = structuredClone(state.contracts);
  const authority = history.authority;
  const releaseSha = stages.stageTwo.release_sha;
  const deploymentIntentSha256 = state.deployment_intent_sha256;
  const reviewerAcceptanceSha256 =
    state.reviewer_authority_genesis_acceptance_sha256;
  const freshReceiptSha256 = pin("a");
  const qvlKeyId = word("b");
  const main = stages.stageTwo.post_ceremony_evidence.final_cvms[0];
  const prescription = normalizeRoyaltyReleasePrescriptiveAuthority({
    schema: "dnai.royalty-release-prescriptive-authority.v1",
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    fresh_contract_deployment_receipt_sha256: freshReceiptSha256,
    authority: {
      distributor_address: authority.distributor_address,
      distributor_runtime_code_hash: sourceContracts[2].runtime_code_hash,
      owner: authority.owner,
      settlement_verifier: authority.settlement_verifier,
      qvl_verifier: authority.qvl_verifier,
      anchor_address: authority.execution_policy_anchor,
      anchor_runtime_code_hash: sourceContracts[6].runtime_code_hash,
      anchor_writer: authority.anchor_writer,
      anchor_writer_release_commitment:
        authority.anchor_writer_release_commitment,
      release_policy_commitment: authority.release_policy_commitment,
      authority_nonce: String(authority.authority_nonce),
    },
    royalty_settlement_release_binding_template: {
      schema: "dnai.royalty-settlement-release-binding-template.v1",
      chain_id: 84_532,
      distributor_address: authority.distributor_address,
      distributor_runtime_code_hash: sourceContracts[2].runtime_code_hash,
      authority_nonce: authority.authority_nonce,
      settlement_verifier_address: authority.settlement_verifier,
      settlement_verifier_key_path:
        "tinker/collaboration_royalty_settlement_signer",
      settlement_verifier_custody:
        "dstack_derived_main_runtime_royalty_settlement_signer",
      royalty_qvl_verifier_address: authority.qvl_verifier,
      royalty_qvl_signer_key_id: qvlKeyId,
      royalty_qvl_signer_key_path:
        `dnai-wikigen/attestation-qvl/royalty-settlement-signer/v1/${qvlKeyId.slice(2)}`,
      royalty_qvl_signer_custody:
        "dstack_derived_diligence_qvl_royalty_settlement_signer",
      royalty_qvl_policy_template_sha256: pin("c"),
      qvl_release_policy_hash: word("d"),
      measurement_policy_sha256: pin("e"),
      execution_policy_anchor_address: authority.execution_policy_anchor,
      anchor_writer_release_commitment:
        authority.anchor_writer_release_commitment,
      release_policy_commitment: authority.release_policy_commitment,
      main_runtime_cvm_id: main.cvm_id,
      deployment_intent_sha256: deploymentIntentSha256,
      ceremony_nonce: word("f"),
      compose_hash: word("1"),
      app_id: main.app_id,
      os_image_hash: "2".repeat(64),
      max_authorization_lifetime_seconds: 600,
    },
  });
  const configurations = sourceContracts.map((contract, index) => {
    const signatures = ROYALTY_HISTORY_CONFIGURATION_GETTERS[contract.contract_key];
    const getters = signatures.map((signature, getterIndex) => ({
      signature,
      result: signature === `${contract.control_role}()`
        ? addressWord(contract.control_address)
        : `0x${((index * 40 + getterIndex + 10) % 245)
          .toString(16).padStart(64, "0")}`,
    }));
    const core = {
      schema: "dnai.base-sepolia-frozen-ledger-contract-configuration.v1",
      contract_key: contract.contract_key,
      address: contract.address,
      runtime_code_hash: contract.runtime_code_hash,
      control_role: contract.control_role,
      control_address: contract.control_address,
      frozen_ledger_contract_sha256:
        royaltyHistoryFrozenLedgerContractSha256(
          syntheticLedgerContractRecord(contract, index, history),
        ),
      getter_observations: getters,
    };
    return {
      ...core,
      configuration_sha256: royaltyHistoryContractConfigurationSha256(core),
    };
  });
  const contracts = sourceContracts.map((contract, index) => ({
    ...contract,
    configuration_sha256: configurations[index].configuration_sha256,
  }));
  const common = structuredClone(stages.stageTwo.common_finalized_state);
  const fullSuite = {
    schema: "dnai.base-sepolia-royalty-full-suite-state.v1",
    chain_id: 84_532,
    block_number: common.primary_rpc_block.block_number,
    block_hash: common.primary_rpc_block.block_hash,
    contracts,
    contract_configurations: configurations,
    royalty_release_active_state:
      structuredClone(history.phase_two.poststate.primary_rpc_state),
  };
  const fullSuiteSha256 = royaltyHistoryFullSuiteStateSha256(fullSuite);
  const primaryFinalizedHead = structuredClone(common.primary_rpc_block);
  const secondaryFinalizedHead = structuredClone(common.secondary_rpc_block);
  const recheckSha256 = royaltyHistoryLatestStateRecheckSha256(
    fullSuite,
    fullSuite,
    primaryFinalizedHead,
    secondaryFinalizedHead,
  );
  Object.assign(common, {
    primary_state_sha256: fullSuiteSha256,
    secondary_state_sha256: fullSuiteSha256,
    canonical_state_sha256: fullSuiteSha256,
    latest_state_recheck_sha256: recheckSha256,
  });
  const evidence = {
    schema: ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA,
    truth_status: ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS,
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    fresh_contract_deployment_receipt_sha256: freshReceiptSha256,
    reviewer_authority_genesis_acceptance_sha256: reviewerAcceptanceSha256,
    tinker_account_binding_ceremony_receipt_sha256: pin("3"),
    frozen_final_ledger_sha256: pin("4"),
    ledger_finalization_receipt_sha256: pin("5"),
    ledger_revision_chain_sha256: pin("6"),
    royalty_release_prescriptive_authority: prescription,
    royalty_release_prescriptive_authority_sha256:
      royaltyReleasePrescriptiveAuthoritySha256(prescription),
    execution_mode: executionMode,
    contracts,
    common_finalized_state: common,
    royalty_release_history: history,
    collection_proof: {
      schema: "dnai.base-sepolia-royalty-history-collection-proof.v1",
      primary_rpc_id_sha256: common.primary_rpc_id_sha256,
      secondary_rpc_id_sha256: common.secondary_rpc_id_sha256,
      primary_finalized_head: primaryFinalizedHead,
      primary_finalized_head_sha256:
        common.primary_rpc_block_sha256,
      secondary_finalized_head: secondaryFinalizedHead,
      secondary_finalized_head_sha256:
        common.secondary_rpc_block_sha256,
      primary_full_suite_state: fullSuite,
      primary_full_suite_state_sha256: fullSuiteSha256,
      secondary_full_suite_state: structuredClone(fullSuite),
      secondary_full_suite_state_sha256: fullSuiteSha256,
      latest_primary_full_suite_state: structuredClone(fullSuite),
      latest_secondary_full_suite_state: structuredClone(fullSuite),
      latest_state_recheck_sha256: recheckSha256,
    },
  };
  return normalizeRoyaltyFinalizedHistoryEvidence(evidence);
}

export function syntheticRoyaltyFrozenLedgerContext(evidence) {
  const contracts = Object.fromEntries(evidence.contracts.map((contract, index) => [
    LEDGER_CONTRACTS[index][0],
    syntheticLedgerContractRecord(contract, index, evidence.royalty_release_history),
  ]));
  const prescriptionSha256 =
    evidence.royalty_release_prescriptive_authority_sha256;
  const lineage = {
    sourceCommit: evidence.release_sha,
    royaltyDistributorAddress:
      evidence.royalty_release_prescriptive_authority.authority.distributor_address,
    runtimeCodeHash:
      evidence.royalty_release_prescriptive_authority.authority
        .distributor_runtime_code_hash,
    freshContractDeploymentReceiptSha256:
      evidence.fresh_contract_deployment_receipt_sha256,
    royaltyReleasePrescriptiveAuthoritySha256: prescriptionSha256,
    reviewerAuthority: {
      deploymentIntentSha256: evidence.deployment_intent_sha256,
      genesisAcceptanceSha256:
        evidence.reviewer_authority_genesis_acceptance_sha256,
    },
  };
  const history = evidence.royalty_release_history;
  const phaseOne = {
    ...lineage,
    phase: 1,
    executionMode: "stage_authority",
    transactionReceipts: [{
      transactionHash: history.phase_one.proposal_transaction
        .primary_rpc_transaction.transaction_hash,
    }],
  };
  const phaseTwo = {
    ...lineage,
    phase: 2,
    executionMode: evidence.execution_mode,
    transactionReceipts: evidence.execution_mode === "activate_and_unpause"
      ? [
        {
          transactionHash: history.phase_two.activation_transaction
            .primary_rpc_transaction.transaction_hash,
        },
        {
          transactionHash: history.phase_two.unpause_transaction
            .primary_rpc_transaction.transaction_hash,
        },
      ]
      : [{
        transactionHash: history.phase_two.unpause_transaction
          .primary_rpc_transaction.transaction_hash,
      }],
  };
  if (evidence.execution_mode === "recover_reverted_unpause") {
    phaseTwo.phaseTwoRecovery = {
      activation_tx_hash: history.phase_two.activation_transaction
        .primary_rpc_transaction.transaction_hash,
      reverted_unpause_tx_hash: history.phase_two.reverted_unpause_transaction
        .primary_rpc_transaction.transaction_hash,
    };
  }
  return {
    replay: {
      finalized: true,
      ledger_mode: "0444",
      finalization_receipt_sha256:
        evidence.ledger_finalization_receipt_sha256,
      current_ledger_sha256: evidence.frozen_final_ledger_sha256,
      revision_chain_sha256: evidence.ledger_revision_chain_sha256,
      revision_count: 2,
    },
    ledger: {
      contracts,
      royaltyReleaseHistory: [phaseOne, phaseTwo],
    },
  };
}
