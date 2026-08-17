import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY,
  EXECUTION_POLICY_STORE_V6_CONTRACT,
  canonicalFinalReleaseAuthorityCoreBytes,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";
import {
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "../../scripts/pre-ceremony-runtime-authority-core.mjs";

export const LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.live-activation-authority-evidence.v1";

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
    images: cvm.images,
    allowed_browser_origins: cvm.allowed_browser_origins,
    compute_workload_ingress: cvm.compute_workload_ingress,
    runtime_controls: cvm.runtime_controls,
  };
}

function projectExecutionPolicy(policyValue) {
  const policy = record(policyValue, "release candidate execution policy");
  const anchor = record(policy.rollback_anchor, "release candidate rollback anchor");
  return {
    canonicalization_version: policy.canonicalization_version,
    approval_schema: policy.approval_schema,
    api_schema_version: policy.api_schema_version,
    store_schema_version: policy.store_schema_version,
    store_contract: {
      ...EXECUTION_POLICY_STORE_V6_CONTRACT,
      payload_fields: [...EXECUTION_POLICY_STORE_V6_CONTRACT.payload_fields],
    },
    release_marker_genesis: {
      ...EXECUTION_POLICY_RELEASE_MARKER_GENESIS_POLICY,
    },
    approver_hashes: policy.approver_hashes,
    approver_root_hash: policy.approver_root_hash,
    rollback_anchor_target: {
      schema: anchor.schema,
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
 * Project only stable pre-anchor facts from a normalized web release candidate.
 *
 * The final approval domain, anchor evidence, anchor status, trust-domain
 * verdicts and the live ledger are omitted on purpose: they are downstream of
 * this non-cyclic commitment. The exact Arena genesis catalog is included as
 * prescriptive ceremony authority and is proved against live chain state only
 * at the later activation gate.
 */
export function finalReleaseAuthorityCoreFromCandidate(candidateValue) {
  const candidate = record(candidateValue, "normalized release candidate");
  return normalizeFinalReleaseAuthorityCore({
    schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    release_sha: candidate.release_sha,
    network: candidate.network,
    operator_address: candidate.operator_address,
    deployment_intent_sha256: candidate.deployment_intent_sha256,
    cvm_launch_intent_sha256: candidate.cvm_launch_intent_sha256,
    contracts: projectContracts(candidate.contracts, candidate.cvm),
    cvm: projectCvm(candidate.cvm),
    arena_registry_bindings: candidate.arena_registry_bindings,
    wallet_auth: candidate.wallet_auth,
    requested_features: candidate.requested_features,
    execution_policy: projectExecutionPolicy(candidate.execution_policy),
  });
}

/**
 * Bind the canonical pre-ceremony runtime dependency to the final release
 * candidate and the one-shot anchor-writer release commitment. Separately
 * signed Stage 1 and Stage 2 hashes remain exact candidate pins but never
 * substitute for this runtime dependency or for their own signature checks.
 */
export function validateFinalReleaseAuthorityCoreBinding(
  candidateValue,
  coreValue,
  runtimeAuthorityValue,
) {
  const candidate = record(candidateValue, "normalized release candidate");
  const suppliedCore = normalizeFinalReleaseAuthorityCore(coreValue);
  const runtimeAuthority = normalizePreCeremonyRuntimeAuthority(
    runtimeAuthorityValue,
  );
  const projectedCore = finalReleaseAuthorityCoreFromCandidate(candidate);
  const suppliedBytes = canonicalFinalReleaseAuthorityCoreBytes(suppliedCore);
  const projectedBytes = canonicalFinalReleaseAuthorityCoreBytes(projectedCore);
  if (!suppliedBytes.equals(projectedBytes)) {
    throw new Error(
      "final release authority core does not exactly match the final release candidate's pre-anchor facts",
    );
  }

  const digest = finalReleaseAuthorityCoreDigest(suppliedCore);
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(
    runtimeAuthority,
  );
  if (runtimeAuthority.release_sha !== suppliedCore.release_sha
    || runtimeAuthority.deployment_intent_sha256
      !== suppliedCore.deployment_intent_sha256
    || runtimeAuthority.cvm_launch_intent_sha256
      !== suppliedCore.cvm_launch_intent_sha256) {
    throw new Error(
      "pre-ceremony runtime authority does not match the release/deployment/CVM-launch lineage",
    );
  }
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
      "live_activation_authority_sha256",
      "runtime_authority_dependency_sha256",
    ],
    "release candidate live activation authority evidence",
  );
  if (authorityEvidence.schema !== LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA) {
    throw new Error(
      `release candidate authority evidence schema must be ${LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA}`,
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
  sha256Pin(
    authorityEvidence.live_activation_authority_sha256,
    "release candidate live-activation-authority SHA-256",
  );
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
  return {
    core: suppliedCore,
    digest,
    runtimeAuthority,
    runtimeAuthoritySha256,
  };
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
