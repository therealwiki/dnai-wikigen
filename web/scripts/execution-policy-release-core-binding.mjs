import {
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";
import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "../../scripts/canonical-authority-graph.mjs";
import {
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "../../scripts/pre-ceremony-runtime-authority-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
} from "../../scripts/phala-seven-cvm-release-verification-authority-v5-core.mjs";
import {
  normalizeRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "../../scripts/royalty-release-history-receipt-core.mjs";
import { projectRoyaltyReleaseBrowserEnv } from "./royalty-release-env-core.mjs";

export const LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.live-activation-authority-evidence.v1";
export const PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.pre-live-activation-authority-evidence.v1";

const CANDIDATE_FEATURE_KEYS = Object.freeze([
  "contract_writes", "artifact_upload", "compute_console", "tinker_customer",
  "collaboration", "compute_vault_funding", "compute_vault_authorization",
  "compute_workload_upload", "arena_submission",
]);

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort()
      .map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function same(value, expected, label) {
  if (JSON.stringify(canonical(value)) !== JSON.stringify(canonical(expected))) {
    throw new Error(`${label} does not match`);
  }
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function exactRecord(value, keys, label) {
  const parsed = record(value, label);
  const actual = Object.keys(parsed).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} fields are not exact`);
  }
  return parsed;
}

function sha256Pin(value, label) {
  if (
    typeof value !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(value)
    || value === `sha256:${"0".repeat(64)}`
  ) {
    throw new Error(`${label} must be a nonzero lowercase SHA-256 pin`);
  }
  return value;
}

function projectContracts(contractsValue, cvmValue) {
  const contracts = record(contractsValue, "release candidate contracts");
  const cvm = record(cvmValue, "release candidate CVM");
  const diligence = record(contracts.diligence_room, "DiligenceRoom descriptor");
  const challenge = record(contracts.challenge_registry, "ChallengeRegistry descriptor");
  const royalty = record(contracts.royalty_distributor, "RoyaltyDistributor descriptor");
  const encumbrance = record(
    contracts.tinker_account_encumbrance,
    "TinkerAccountEncumbrance descriptor",
  );
  const compute = record(contracts.compute_credit_vault, "ComputeCreditVault descriptor");
  const email = record(contracts.email_oracle_auth, "EmailOracleAuth descriptor");
  const usdc = record(contracts.usdc, "USDC descriptor");
  return {
    diligence_room: {
      address: diligence.address,
      runtime_code_hash: diligence.runtime_code_hash,
      developer: diligence.developer,
      result_verifier: diligence.result_verifier,
      attestation_verifier: diligence.attestation_verifier,
      attestation_release_policy_hash: diligence.attestation_release_policy_hash,
      attestation_binding_frozen: diligence.attestation_binding_frozen,
      evaluator_policy_commitments: diligence.evaluator_policy_commitments,
      evaluator_policy_set_root: diligence.evaluator_policy_set_root,
      release_admission: {
        tee_identity: cvm.tee_identity,
        compose_hash: cvm.compose_hash,
        approved_tee_identity_count: 1,
        approved_compose_count: 1,
        additions_frozen: true,
      },
    },
    challenge_registry: {
      address: challenge.address,
      runtime_code_hash: challenge.runtime_code_hash,
      owner: challenge.owner,
      pending_owner: challenge.pending_owner,
      registry_paused: challenge.registry_paused,
      minimum_version_review_delay_seconds:
        challenge.minimum_version_review_delay_seconds,
      expected_challenge_count: challenge.expected_challenge_count,
    },
    royalty_distributor: {
      address: royalty.address,
      runtime_code_hash: royalty.runtime_code_hash,
    },
    tinker_account_encumbrance: {
      address: encumbrance.address,
      runtime_code_hash: encumbrance.runtime_code_hash,
      owner: encumbrance.owner,
      account_commitment: encumbrance.account_commitment,
      max_add_balance_wei: encumbrance.max_add_balance_wei,
      max_spend_wei: encumbrance.max_spend_wei,
      approved_compose_hashes: encumbrance.approved_compose_hashes,
      approved_compose_root: encumbrance.approved_compose_root,
      approved_compose_count: encumbrance.approved_compose_count,
      managers: encumbrance.managers,
      manager_root: encumbrance.manager_root,
      manager_count: encumbrance.manager_count,
      release_policy_commitment: encumbrance.release_policy_commitment,
      release_max_add_balance_wei: encumbrance.release_max_add_balance_wei,
      release_max_spend_wei: encumbrance.release_max_spend_wei,
      release_compose_root: encumbrance.release_compose_root,
      release_compose_count: encumbrance.release_compose_count,
      release_manager_root: encumbrance.release_manager_root,
      release_manager_count: encumbrance.release_manager_count,
      release_policy_frozen: encumbrance.release_policy_frozen,
      emergency_halted: encumbrance.emergency_halted,
      per_operation_caps: encumbrance.per_operation_caps,
      custodies_funds: encumbrance.custodies_funds,
    },
    compute_credit_vault: {
      address: compute.address,
      runtime_code_hash: compute.runtime_code_hash,
      owner: compute.owner,
      developer: compute.developer,
      metering_verifier: compute.metering_verifier,
      metering_qvl_verifier: compute.metering_qvl_verifier,
      metering_policy_set_hash: compute.metering_policy_set_hash,
      metering_binding_frozen: compute.metering_binding_frozen,
      developer_fee_bps: compute.developer_fee_bps,
      tee_identity: compute.tee_identity,
      compose_hash: compute.compose_hash,
      rate_policies: {
        native: {
          commitment: compute.native_rate_policy_commitment,
          asset: "0x0000000000000000000000000000000000000000",
          provider: compute.native_provider,
          developer_fee_bps: compute.developer_fee_bps,
        },
        erc20: {
          commitment: compute.erc20_rate_policy_commitment,
          asset: compute.erc20_asset_address,
          provider: compute.erc20_provider,
          developer_fee_bps: compute.developer_fee_bps,
        },
      },
    },
    email_oracle_auth: {
      address: email.address,
      runtime_code_hash: email.runtime_code_hash,
      owner: email.owner,
      consumer_address: email.consumer_address,
      upgrade_delay_seconds: email.upgrade_delay_seconds,
      release: {
        ...record(email.release, "EmailOracleAuth release descriptor"),
        oracle_compose_hash: `0x${cvm.compose_hash}`,
        consumer_compose_hash: `0x${cvm.compose_hash}`,
      },
    },
    usdc: {
      address: usdc.address,
      runtime_code_hash: usdc.runtime_code_hash,
      symbol: usdc.symbol,
      decimals: usdc.decimals,
    },
  };
}

function projectCvm(cvmValue) {
  const cvm = record(cvmValue, "release candidate CVM");
  return {
    app_id: cvm.app_id,
    cvm_id: cvm.cvm_id,
    compose_hash: cvm.compose_hash,
    local_compose_hash: cvm.local_compose_hash,
    rendered_compose_sha256: cvm.rendered_compose_sha256,
    os_image_hash: cvm.os_image_hash,
    os_is_dev: cvm.os_is_dev,
    public_logs: cvm.public_logs,
    public_sysinfo: cvm.public_sysinfo,
    public_tcbinfo: cvm.public_tcbinfo,
    tee_identity: cvm.tee_identity,
    delegate_url: cvm.delegate_url,
    images: [...cvm.images].sort((a, b) => a.service.localeCompare(b.service)),
    allowed_browser_origins: [...cvm.allowed_browser_origins].sort(),
    compute_workload_ingress: cvm.compute_workload_ingress,
    runtime_controls: cvm.runtime_controls,
  };
}

function projectExecutionPolicy(policyValue, { fromCore = false } = {}) {
  const policy = record(policyValue, "release candidate execution policy");
  const anchor = record(
    fromCore ? policy.rollback_anchor_target : policy.rollback_anchor,
    "release candidate rollback anchor",
  );
  if (!fromCore && anchor.schema !== "dnai.execution-policy-rollback-anchor.v1") {
    throw new Error("release candidate rollback anchor must use its exact v1 shared-fact schema");
  }
  return {
    canonicalization_version: policy.canonicalization_version,
    approval_schema: policy.approval_schema,
    api_schema_version: policy.api_schema_version,
    store_schema_version: policy.store_schema_version,
    approver_hashes: policy.approver_hashes,
    approver_root_hash: policy.approver_root_hash,
    rollback_anchor_target: {
      chain_id: anchor.chain_id,
      contract_address: anchor.contract_address,
      runtime_code_hash: anchor.runtime_code_hash,
      writer_address: anchor.writer_address,
      writer_release_commitment: anchor.writer_release_commitment,
      writer_custody: anchor.writer_custody,
      writer_key_path: anchor.writer_key_path,
      confirmations: anchor.confirmations,
      max_block_age_seconds: anchor.max_block_age_seconds,
      max_future_block_skew_seconds: anchor.max_future_block_skew_seconds,
      verification_model: anchor.verification_model,
      independent_rpc_quorum_verified: anchor.independent_rpc_quorum_verified,
      consensus_proof_verified: anchor.consensus_proof_verified,
    },
  };
}

/**
 * Bind stable candidate facts to a separately supplied, exact current core.
 *
 * The final approval domain, anchor evidence, anchor status, trust-domain
 * verdicts and the live ledger are omitted on purpose: they are downstream of
 * this non-cyclic commitment. The exact Arena genesis catalog is included as
 * prescriptive ceremony authority and is proved against live chain state only
 * at the later activation gate. The candidate deliberately has only nine
 * feature flags and a v1 anchor projection. It cannot manufacture current core
 * extensions, the v2 gas-reserve policy, or their authority. Those prescriptions
 * remain in the normalized reviewed core and its subsequent D/C commitment.
 * This projection alone does not authenticate R, H, B, C, or the supplied core.
 */
export function finalReleaseAuthorityCoreFromCandidate(candidateValue, coreValue) {
  assertCanonicalPlainDataGraph(candidateValue, { label: "normalized release candidate" });
  assertCanonicalPlainDataGraph(coreValue, { label: "reviewed current release core" });
  const candidate = record(candidateValue, "normalized release candidate");
  const core = normalizeFinalReleaseAuthorityCore(coreValue);
  const features = exactRecord(candidate.requested_features, CANDIDATE_FEATURE_KEYS,
    "release candidate shared feature flags");
  const projected = {
    release_sha: candidate.release_sha,
    network: candidate.network,
    operator_address: candidate.operator_address,
    deployment_intent_sha256: candidate.deployment_intent_sha256,
    cvm_launch_intent_sha256: candidate.cvm_launch_intent_sha256,
    contracts: projectContracts(candidate.contracts, candidate.cvm),
    cvm: projectCvm(candidate.cvm),
    arena_registry_bindings: candidate.arena_registry_bindings,
    wallet_auth: candidate.wallet_auth,
    requested_features: features,
    execution_policy: projectExecutionPolicy(candidate.execution_policy),
  };
  const expected = {
    release_sha: core.release_sha,
    network: core.network,
    operator_address: core.operator_address,
    deployment_intent_sha256: core.deployment_intent_sha256,
    cvm_launch_intent_sha256: core.cvm_launch_intent_sha256,
    contracts: core.contracts,
    cvm: projectCvm(core.cvm),
    arena_registry_bindings: core.arena_registry_bindings,
    wallet_auth: core.wallet_auth,
    requested_features: Object.fromEntries(CANDIDATE_FEATURE_KEYS
      .map((key) => [key, core.requested_features[key]])),
    execution_policy: projectExecutionPolicy(core.execution_policy, { fromCore: true }),
  };
  same(projected, expected, "current release core and candidate shared pre-anchor facts");
  return core;
}

/**
 * Bind the canonical pre-ceremony runtime dependency to the final release
 * candidate and the one-shot anchor-writer release commitment. Separately
 * signed Stage 1 and Stage 2 hashes remain exact candidate pins but never
 * substitute for signature checks. The caller must supply the R digest from
 * authenticated B, not derive an expected digest from the candidate or R here.
 * H proves the Royalty post-transaction state, not live authority. Additional
 * current feature/QVL prescriptions are retained in the exact core digest for
 * D semantic lineage and subsequent signed C, not upgraded to R observations.
 */
export function validateFinalReleaseAuthorityCoreBinding(
  candidateValue,
  coreValue,
  runtimeAuthorityValue,
  optionsValue,
) {
  assertCanonicalPlainDataGraph(candidateValue, { label: "normalized release candidate" });
  assertCanonicalPlainDataGraph(optionsValue, { label: "release core binding options" });
  const options = exactRecord(optionsValue, [
    "authorityStage", "authenticatedRuntimeAuthoritySha256", "royaltyReleaseHistoryReceipt",
  ], "release core binding options");
  if (!["prebuild", "live"].includes(options.authorityStage)) {
    throw new Error("release core binding authorityStage must be prebuild or live");
  }
  const authenticatedRuntimeAuthoritySha256 = sha256Pin(
    options.authenticatedRuntimeAuthoritySha256, "authenticated runtime authority SHA-256",
  );
  const candidate = record(candidateValue, "normalized release candidate");
  const suppliedCore = finalReleaseAuthorityCoreFromCandidate(candidate, coreValue);
  const runtimeAuthority = normalizePreCeremonyRuntimeAuthority(
    runtimeAuthorityValue,
  );
  const digest = finalReleaseAuthorityCoreDigest(suppliedCore);
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(
    runtimeAuthority,
  );
  same(runtimeAuthoritySha256, authenticatedRuntimeAuthoritySha256,
    "canonical runtime authority and authenticated B dependency");
  if (runtimeAuthority.release_sha !== suppliedCore.release_sha
    || runtimeAuthority.chain_id !== suppliedCore.network.chain_id
    || runtimeAuthority.deployment_intent_sha256
      !== suppliedCore.deployment_intent_sha256
    || runtimeAuthority.cvm_launch_intent_sha256
      !== suppliedCore.cvm_launch_intent_sha256) {
    throw new Error(
      "pre-ceremony runtime authority does not match the release/deployment/CVM-launch lineage",
    );
  }
  const plan = runtimeAuthority.post_measurement_activation_plan;
  const releaseAuthority = plan.release_verification_authority;
  same(releaseAuthority.schema, PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
    "current runtime release-verification authority schema");
  same(suppliedCore.seven_cvm_release_verification_authority_sha256,
    runtimeAuthority.release_verification_authority_sha256,
    "core seven-CVM authority and authenticated runtime authority");
  for (const key of ["app_id", "cvm_id", "compose_hash", "os_image_hash"]) {
    same(suppliedCore.cvm[key], plan.target[key], `core main-runtime ${key}`);
  }
  same(suppliedCore.contracts.diligence_room.address,
    releaseAuthority.contracts.diligence_room, "runtime DiligenceRoom address");
  same(suppliedCore.contracts.compute_credit_vault.address,
    releaseAuthority.contracts.compute_credit_vault, "runtime ComputeCreditVault address");
  same(suppliedCore.contracts.compute_credit_vault.runtime_code_hash,
    releaseAuthority.contracts.compute_credit_vault_runtime_code_hash,
    "runtime ComputeCreditVault runtime hash");
  same(suppliedCore.royalty_settlement_release_binding_template.ceremony_nonce,
    releaseAuthority.ceremony_nonce, "Royalty template ceremony nonce");

  const history = normalizeRoyaltyReleaseHistoryReceipt(options.royaltyReleaseHistoryReceipt);
  const anchor = suppliedCore.execution_policy.rollback_anchor_target;
  projectRoyaltyReleaseBrowserEnv(history, {
    royaltyDistributorAddress: suppliedCore.contracts.royalty_distributor.address,
    royaltyDistributorCodeHash: suppliedCore.contracts.royalty_distributor.runtime_code_hash,
    executionPolicyAnchorAddress: anchor.contract_address,
    executionPolicyAnchorWriter: anchor.writer_address,
    executionPolicyAnchorWriterReleaseCommitment: anchor.writer_release_commitment,
  });
  same(history.contracts.find((entry) => entry.contract_key === "execution_policy_anchor")
    .runtime_code_hash, anchor.runtime_code_hash, "Royalty H anchor runtime hash");
  same(suppliedCore.royalty_release_history_receipt_sha256,
    royaltyReleaseHistoryReceiptSha256(history), "core Royalty H receipt digest");
  same(suppliedCore.royalty_release_history_sha256,
    history.royalty_release_history_sha256, "core Royalty history digest");
  same(suppliedCore.royalty_release_authority,
    history.royalty_release_authority, "core Royalty authority and H");
  same(suppliedCore.royalty_release_active_state,
    history.royalty_release_active_state, "core Royalty active state and H");
  if (runtimeAuthoritySha256 === `sha256:${digest}`) {
    throw new Error(
      "release core and pre-ceremony runtime authority must remain distinct domain roots",
    );
  }
  const authorityEvidence = exactRecord(
    candidate.operator_policy,
    [
      "schema",
      "ceremony_authorization_sha256",
      ...(options.authorityStage === "live" ? ["live_activation_authority_sha256"] : []),
      "runtime_authority_dependency_sha256",
    ],
    `release candidate ${options.authorityStage} authority evidence`,
  );
  const expectedAuthoritySchema = options.authorityStage === "live"
    ? LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA
    : PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  if (authorityEvidence.schema !== expectedAuthoritySchema) {
    throw new Error(
      `release candidate ${options.authorityStage} authority evidence schema must be ${expectedAuthoritySchema}`,
    );
  }
  if (
    sha256Pin(
      authorityEvidence.runtime_authority_dependency_sha256,
      "release candidate runtime authority dependency SHA-256",
    ) !== runtimeAuthoritySha256
  ) {
    throw new Error(
      "release candidate runtime-authority dependency does not equal the canonical pre-ceremony runtime digest",
    );
  }
  sha256Pin(
    authorityEvidence.ceremony_authorization_sha256,
    "release candidate ceremony-authorization SHA-256",
  );
  if (options.authorityStage === "live") {
    sha256Pin(authorityEvidence.live_activation_authority_sha256,
      "release candidate live-activation-authority SHA-256");
  }
  const rollbackAnchor = record(
    record(candidate.execution_policy, "release candidate execution policy").rollback_anchor,
    "release candidate rollback anchor",
  );
  if (rollbackAnchor.release_manifest_commitment
      !== runtimeAuthoritySha256.slice("sha256:".length)) {
    throw new Error(
      "execution-policy rollback anchor release-manifest commitment does not equal the canonical pre-ceremony runtime digest",
    );
  }
  const launchIntentDigest = suppliedCore.cvm_launch_intent_sha256.slice(
    "sha256:".length,
  );
  if (rollbackAnchor.writer_release_commitment !== `0x${launchIntentDigest}`) {
    throw new Error(
      "execution-policy anchor writer release does not equal the reviewed CVM launch-intent digest",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    core: suppliedCore,
    digest,
    coreSha256: `sha256:${digest}`,
    runtimeAuthority,
    runtimeAuthoritySha256,
  });
}

// Compatibility aliases while release ceremony filenames and imports migrate.
export const executionPolicyReleaseCoreFromCandidate =
  finalReleaseAuthorityCoreFromCandidate;
export const validateExecutionPolicyReleaseCoreBinding =
  validateFinalReleaseAuthorityCoreBinding;

// Additive compatibility exports only. The historical path takes an explicit
// authenticated R digest and never imports the effectful current-R facade.
export {
  finalReleaseAuthorityCoreFromHistoricalCandidate,
  historicalFinalReleaseAuthorityCoreSha256,
  validateHistoricalFinalReleaseAuthorityCoreBinding,
} from "./frontend-release-historical-core.mjs";
