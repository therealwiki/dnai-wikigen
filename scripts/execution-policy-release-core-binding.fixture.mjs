// Test-only structural fixtures. No production brands, observed evidence, or
// external calls are created here, even where a synthetic record has a mode.
import { knownVector, rebindKnownVectorV4AuthorityFixture } from "./execution-policy-release-core.fixture.mjs";
import { normalizeFinalReleaseAuthorityCore } from "./execution-policy-release-core.mjs";
import { syntheticReleaseAuthorityStagesFixture } from "./release-authority-current-stages.fixture.mjs";
import {
  normalizeRoyaltyReleaseHistoryReceipt,
  projectRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "./royalty-release-history-receipt-core.mjs";
import { royaltyReleaseStateSha256 } from "./royalty-release-authority-core.mjs";
import {
  syntheticPostMeasurementActivationPlanFixture,
  syntheticPreCeremonyRuntimeAuthorityFromPlanFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture as legacyReleaseFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import { syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture } from "./current-cvm-authority-v5.fixture.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v5-core.mjs";

const pin = (byte) => `sha256:${byte.repeat(32)}`;

function currentRuntimeFixture(core) {
  const settings = {
    releaseSha: core.release_sha,
    deploymentIntentSha256: core.deployment_intent_sha256,
    ceremonyNonce: core.royalty_settlement_release_binding_template.ceremony_nonce,
    diligenceRoom: core.contracts.diligence_room.address,
    computeCreditVault: core.contracts.compute_credit_vault.address,
    computeCreditVaultRuntimeCodeHash: core.contracts.compute_credit_vault.runtime_code_hash,
    releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
      mainRuntime: {
        descriptor_sha256: pin("aa"),
        app_id: core.cvm.app_id,
        cvm_id: core.cvm.cvm_id,
        compose_hash: core.cvm.compose_hash,
        os_image_hash: core.cvm.os_image_hash,
      },
    }),
  };
  // Reuse the exact plan fixture, then replace its historical embedded shape
  // with the current v5 shape and recompute the actual plan/R commitments.
  const plan = structuredClone(syntheticPostMeasurementActivationPlanFixture({
    releaseSha: core.release_sha,
    deploymentIntentSha256: core.deployment_intent_sha256,
    cvmLaunchIntentSha256: core.cvm_launch_intent_sha256,
    releaseVerificationAuthority: legacyReleaseFixture(settings),
  }));
  const release = normalizePhalaSevenCvmReleaseVerificationAuthority({
    ...structuredClone(syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture(settings)),
    evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  });
  const releaseSha = phalaSevenCvmReleaseVerificationAuthoritySha256(release);
  plan.release_verification_authority = release;
  plan.release_verification_authority_sha256 = releaseSha;
  plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256 = releaseSha;
  return syntheticPreCeremonyRuntimeAuthorityFromPlanFixture({ postMeasurementActivationPlan: plan });
}

/**
 * The candidate is the normalized shared-fact input to the binding helper,
 * not a synthetic substitute for full trust-domain/signature verification.
 * candidateBase allows an orchestration test's complete candidate to supply
 * its independently prepared downstream evidence. Overrides must stay in the
 * same H writer-release lineage; this helper never rewrites transaction proof.
 */
export async function syntheticCurrentReleaseCoreBindingFixture({
  runtimeAuthority: runtimeOverride,
  royaltyReleaseHistoryReceipt: historyOverride,
  candidateBase = {},
} = {}) {
  let history = historyOverride;
  if (!history) {
    const stages = await syntheticReleaseAuthorityStagesFixture();
    history = projectRoyaltyReleaseHistoryReceipt({
      contracts: stages.stageTwo.contract_state.contracts,
      commonFinalizedState: stages.stageTwo.common_finalized_state,
      royaltyReleaseHistory: stages.stageTwo.contract_state.royalty_release_history,
    });
  }
  history = normalizeRoyaltyReleaseHistoryReceipt(history);
  const core = knownVector();
  const runtimeAuthority = normalizePreCeremonyRuntimeAuthority(
    runtimeOverride ?? currentRuntimeFixture(core),
  );
  const plan = runtimeAuthority.post_measurement_activation_plan;
  const release = plan.release_verification_authority;
  if (history.royalty_release_authority.anchor_writer_release_commitment
    !== `0x${runtimeAuthority.cvm_launch_intent_sha256.slice(7)}`) {
    throw new Error("synthetic R override requires H from the same writer-release lineage");
  }
  core.release_sha = runtimeAuthority.release_sha;
  for (const key of ["app_id", "cvm_id", "compose_hash", "os_image_hash"]) {
    core.cvm[key] = plan.target[key];
  }
  for (const image of core.cvm.images) image.source_digest = core.release_sha;
  core.contracts.diligence_room.address = release.contracts.diligence_room;
  Object.assign(core.contracts.diligence_room.release_admission, {
    compose_hash: core.cvm.compose_hash,
    tee_identity: core.cvm.tee_identity,
  });
  Object.assign(core.contracts.compute_credit_vault, {
    address: release.contracts.compute_credit_vault,
    runtime_code_hash: release.contracts.compute_credit_vault_runtime_code_hash,
    compose_hash: core.cvm.compose_hash,
  });
  core.contracts.tinker_account_encumbrance.approved_compose_hashes = [`0x${core.cvm.compose_hash}`];
  Object.assign(core.contracts.email_oracle_auth.release, {
    oracle_compose_hash: `0x${core.cvm.compose_hash}`,
    consumer_compose_hash: `0x${core.cvm.compose_hash}`,
  });
  core.contracts.email_oracle_auth.release.target_boot.os_image_hash = `0x${core.cvm.os_image_hash}`;
  const royalty = history.contracts.find((entry) => entry.contract_key === "royalty_distributor");
  const anchor = history.contracts.find((entry) => entry.contract_key === "execution_policy_anchor");
  core.contracts.royalty_distributor = { address: royalty.address, runtime_code_hash: royalty.runtime_code_hash };
  Object.assign(core.execution_policy.rollback_anchor_target, {
    contract_address: anchor.address,
    runtime_code_hash: anchor.runtime_code_hash,
    writer_address: history.royalty_release_authority.anchor_writer,
  });
  core.royalty_release_authority = structuredClone(history.royalty_release_authority);
  core.royalty_release_active_state = structuredClone(history.royalty_release_active_state);
  core.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
    core.royalty_release_active_state,
    { authority: core.royalty_release_authority, phase: "phase_two_active" },
  );
  core.royalty_release_history_sha256 = history.royalty_release_history_sha256;
  core.royalty_release_history_receipt_sha256 = royaltyReleaseHistoryReceiptSha256(history);
  core.seven_cvm_release_verification_authority_sha256 = runtimeAuthority.release_verification_authority_sha256;
  Object.assign(core.royalty_settlement_release_binding_template, {
    distributor_address: royalty.address,
    distributor_runtime_code_hash: royalty.runtime_code_hash,
    authority_nonce: core.royalty_release_authority.authority_nonce,
    settlement_verifier_address: core.royalty_release_authority.settlement_verifier,
    royalty_qvl_verifier_address: core.royalty_release_authority.qvl_verifier,
    execution_policy_anchor_address: anchor.address,
    ceremony_nonce: release.ceremony_nonce,
  });
  rebindKnownVectorV4AuthorityFixture(core, {
    deploymentIntentSha256: runtimeAuthority.deployment_intent_sha256,
    cvmLaunchIntentSha256: runtimeAuthority.cvm_launch_intent_sha256,
  });
  const normalizedCore = normalizeFinalReleaseAuthorityCore(core);
  const candidate = { ...structuredClone(candidateBase), ...structuredClone(normalizedCore) };
  candidate.execution_policy = {
    ...structuredClone(candidateBase.execution_policy ?? {}),
    ...candidate.execution_policy,
  };
  candidate.schema = "dnai.web-release.v4";
  for (const key of [
    "seven_cvm_release_verification_authority_sha256", "shared_release_lineage",
    "royalty_release_authority", "royalty_release_active_state", "royalty_release_active_state_sha256",
    "royalty_release_history_sha256", "royalty_release_history_receipt_sha256",
    "royalty_settlement_release_binding_template", "collaboration_execution", "compute_workload_wallet_adoption",
  ]) delete candidate[key];
  for (const key of ["collaboration_execution", "royalty_settlement", "compute_workload_wallet_adoption"]) {
    delete candidate.requested_features[key];
  }
  delete candidate.contracts.diligence_room.release_admission;
  const compute = candidate.contracts.compute_credit_vault;
  Object.assign(compute, {
    native_rate_policy_commitment: compute.rate_policies.native.commitment,
    native_provider: compute.rate_policies.native.provider,
    erc20_rate_policy_commitment: compute.rate_policies.erc20.commitment,
    erc20_provider: compute.rate_policies.erc20.provider,
    erc20_asset_address: compute.rate_policies.erc20.asset,
  });
  delete compute.rate_policies;
  delete candidate.contracts.email_oracle_auth.release.oracle_compose_hash;
  delete candidate.contracts.email_oracle_auth.release.consumer_compose_hash;
  const runtimeSha = preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  candidate.operator_policy = {
    schema: "dnai.pre-live-activation-authority-evidence.v1",
    ceremony_authorization_sha256: pin("bc"),
    runtime_authority_dependency_sha256: runtimeSha,
  };
  const policy = candidate.execution_policy;
  policy.rollback_anchor = {
    ...policy.rollback_anchor_target,
    schema: "dnai.execution-policy-rollback-anchor.v1",
    status: "verified_active_frozen_release_writer",
    release_manifest_commitment: runtimeSha.slice(7),
    evidence_sha256: pin("bd"),
  };
  delete policy.rollback_anchor.writer_gas_reserve_policy;
  delete policy.rollback_anchor_target;
  delete policy.store_contract;
  delete policy.release_marker_genesis;
  return {
    candidate,
    core: normalizedCore,
    runtimeAuthority,
    royaltyReleaseHistoryReceipt: history,
    authenticatedRuntimeAuthoritySha256: runtimeSha,
  };
}
