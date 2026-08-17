import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  freshContractDeploymentReceiptDigest,
  historicalFreshContractDeploymentReceiptV3Digest,
  normalizeHistoricalFreshContractDeploymentReceiptV3,
  normalizeFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  assertCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256 as
    historicalCvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt as
    normalizeHistoricalCvmReleaseDescriptorSetReceipt,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assertProvenanceVerifiedCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-production-executor-core.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  productionCvmPostureVerificationReceiptSha256,
} from "./phala-production-posture-receipt.mjs";
import {
  assertBrandedPhalaSevenCvmReleaseVerificationAuthority,
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority,
  assertHistoricallyVerifiedProductionPhalaSevenCvmEvidenceSet,
  assertProductionPhalaSevenCvmEvidenceSet,
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    currentPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA as
    LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";
import {
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  assertPreparedProductionPhalaSevenCvmHistoricalTranscriptPersistence,
  assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt,
  persistPreparedProductionPhalaSevenCvmHistoricalTranscriptFiles,
  prepareProductionPhalaSevenCvmHistoricalTranscriptPersistence,
  phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256,
} from "./phala-seven-cvm-historical-transcript-persistence.mjs";
import {
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationReceiptSha256,
} from "./release-manifest-sigstore-verifier.mjs";
import * as launchCompletionCore from "./phala-seven-cvm-launch-completion-core.mjs";

export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA =
  launchCompletionCore.PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA;
export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS =
  launchCompletionCore.PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS;
export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH =
  launchCompletionCore.PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH;
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA =
  launchCompletionCore.PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA;
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN =
  launchCompletionCore.PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN;
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS =
  launchCompletionCore.PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS;
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH =
  launchCompletionCore.PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH;
export const PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA =
  launchCompletionCore.PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA;
export const PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH =
  launchCompletionCore.PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH;
export const PHALA_SEVEN_CVM_COMPLETION_ORDER =
  launchCompletionCore.PHALA_SEVEN_CVM_COMPLETION_ORDER;
export const REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA =
  launchCompletionCore.REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA;
export const REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_AUTHORITY =
  launchCompletionCore.REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_AUTHORITY;

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BRANDED_COMPLETIONS = new WeakMap();

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function ownSchema(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be one versioned object`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, "schema");
  if (!descriptor || !Object.hasOwn(descriptor, "value")
    || typeof descriptor.value !== "string") {
    throw new TypeError(`${label} must carry one own data schema`);
  }
  return descriptor.value;
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function expectedAuthorityFromOptions(value, optionsValue) {
  assertCanonicalPlainDataGraph(optionsValue, {
    label: "seven-CVM completion facade options",
  });
  const keys = Object.keys(optionsValue);
  if (keys.length === 0) return BRANDED_COMPLETIONS.get(value);
  if (keys.length !== 1 || keys[0] !== "expectedAuthority") {
    throw new TypeError(
      "seven-CVM completion facade options must be empty or contain only expectedAuthority",
    );
  }
  return optionsValue.expectedAuthority;
}

function contractBinding(domain, diligenceRoomAddress, computeCreditVaultAddress) {
  if (domain === "main_runtime_cvm") {
    return {
      bound_contract_name: "DiligenceRoom",
      bound_contract_address: diligenceRoomAddress,
    };
  }
  if (domain === "independent_metering_cvm") {
    return {
      bound_contract_name: "ComputeCreditVault",
      bound_contract_address: computeCreditVaultAddress,
    };
  }
  return { bound_contract_name: null, bound_contract_address: null };
}

function contractAddress(receipt, name) {
  const found = receipt.contracts.find((entry) => entry.name === name);
  if (!found) throw new TypeError(`fresh contract receipt omits ${name}`);
  return found.address;
}

function externalAuthorityFromDependencies({
  signedAReceipt,
  freshContractDeploymentReceipt,
  reviewerAuthorityGenesisAcceptanceSha256,
  releaseManifestSigstoreVerificationReceipt,
  descriptorSetReceipt,
  executorFinalState,
  productionPostureReceipts,
  releaseVerificationAuthority,
  verifiedEvidenceSet,
  historicalTranscriptPersistenceReceipt,
} = {}, {
  historicalEvidence = false,
  transcriptPersistencePreflight = null,
} = {}) {
  if (transcriptPersistencePreflight !== null
    && historicalTranscriptPersistenceReceipt !== undefined) {
    throw new TypeError(
      "seven-CVM completion accepts either a pre-write transcript preflight or one durable receipt",
    );
  }
  if (historicalEvidence && transcriptPersistencePreflight !== null) {
    throw new TypeError(
      "historical seven-CVM reconstruction cannot use a pre-persistence authority",
    );
  }
  const signedA =
    assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
      signedAReceipt,
    );
  const reviewerAcceptance = digest(
    reviewerAuthorityGenesisAcceptanceSha256,
    "seven-CVM completion reviewer genesis acceptance",
  );
  const descriptorReceiptSchema = ownSchema(
    descriptorSetReceipt,
    "seven-CVM completion descriptor-set receipt",
  );
  const descriptors = descriptorReceiptSchema
      === CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    ? normalizeCvmReleaseDescriptorSetReceipt(descriptorSetReceipt)
    : historicalEvidence
        && descriptorReceiptSchema
          === HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
      ? normalizeHistoricalCvmReleaseDescriptorSetReceipt(descriptorSetReceipt)
      : (() => {
          throw new TypeError(
            "seven-CVM completion descriptor-set receipt version is unsupported",
          );
        })();
  const descriptorSetSha256 = descriptorReceiptSchema
      === CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    ? cvmReleaseDescriptorSetReceiptSha256(descriptors)
    : historicalCvmReleaseDescriptorSetReceiptSha256(descriptors);
  const contractReceiptPins = {
    expectedDeploymentIntentSha256: signedA.deployment_intent_sha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256: reviewerAcceptance,
    ...(descriptorReceiptSchema
        === CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
      ? {
          expectedTinkerAccountBindingCeremonyReceiptSha256:
            descriptors
              .tinker_account_binding_ceremony_receipt_sha256,
        }
      : {}),
  };
  const contractReceipt = descriptorReceiptSchema
      === CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    ? normalizeFreshContractDeploymentReceipt(
      freshContractDeploymentReceipt,
      contractReceiptPins,
    )
    : normalizeHistoricalFreshContractDeploymentReceiptV3(
      freshContractDeploymentReceipt,
      contractReceiptPins,
    );
  const contractReceiptSha256 = `sha256:${
    descriptorReceiptSchema === CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
      ? freshContractDeploymentReceiptDigest(
        contractReceipt,
        contractReceiptPins,
      )
      : historicalFreshContractDeploymentReceiptV3Digest(
        contractReceipt,
        contractReceiptPins,
      )
  }`;
  const sigstore = assertProductionReleaseManifestSigstoreVerificationReceipt(
    releaseManifestSigstoreVerificationReceipt,
  );
  const sigstoreSha256 =
    releaseManifestSigstoreVerificationReceiptSha256(sigstore);
  const executor = assertProvenanceVerifiedCompletedPhalaExecutorState(
    executorFinalState,
  );
  const signedASha256 =
    phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA);
  const executorSha256 = phalaExecutorStateDigest(executor);
  const proofSet = historicalEvidence
    ? assertHistoricallyVerifiedProductionPhalaSevenCvmEvidenceSet(
      verifiedEvidenceSet,
    )
    : assertProductionPhalaSevenCvmEvidenceSet(verifiedEvidenceSet);
  const proofSetSha256 = phalaSevenCvmVerifiedEvidenceSetSha256(proofSet);
  const releaseAuthoritySchema = ownSchema(
    releaseVerificationAuthority,
    "seven-CVM completion release-verification authority",
  );
  const releaseAuthority = releaseAuthoritySchema
      === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
    ? historicalEvidence
      ? assertBrandedPhalaSevenCvmReleaseVerificationAuthority(
        releaseVerificationAuthority,
      )
      : assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
        releaseVerificationAuthority,
      )
    : historicalEvidence
        && releaseAuthoritySchema
          === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
      ? assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
        releaseVerificationAuthority,
      )
      : (() => {
          throw new TypeError(
            "seven-CVM completion release-verification authority version is unsupported",
          );
        })();
  if ((releaseAuthoritySchema
        === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
      && descriptorReceiptSchema
        !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)
    || (releaseAuthoritySchema
        === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
      && descriptorReceiptSchema
        !== HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA)) {
    throw new TypeError(
      "seven-CVM completion release and descriptor authority versions are crossed",
    );
  }
  const releaseAuthoritySha256 = releaseAuthoritySchema
      === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
    ? currentPhalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority)
    : legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const transcriptPersistence = transcriptPersistencePreflight === null
    ? assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(
      historicalTranscriptPersistenceReceipt,
    )
    : null;
  const preparedTranscriptPersistence = transcriptPersistencePreflight === null
    ? null
    : assertPreparedProductionPhalaSevenCvmHistoricalTranscriptPersistence(
      transcriptPersistencePreflight,
    );
  const transcriptPersistenceSha256 = transcriptPersistence === null
    ? preparedTranscriptPersistence.anticipated_persistence_receipt_sha256
    : phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(
      transcriptPersistence,
    );
  const transcriptFileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    (transcriptPersistence ?? preparedTranscriptPersistence).transcript_file_set,
  );
  const transcriptFileSetSha256 =
    phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet);
  const transcriptDirectoryIdentityAnchorSha256 =
    (transcriptPersistence ?? preparedTranscriptPersistence)
      .phala_recovery_directory_identity_anchor_sha256;
  const transcriptEvidenceSetSha256 =
    (transcriptPersistence ?? preparedTranscriptPersistence)
      .seven_cvm_verified_evidence_set_sha256;
  const transcriptAuthorityFileSetSha256 =
    (transcriptPersistence ?? preparedTranscriptPersistence)
      .historical_transcript_file_set_sha256;

  if (!Array.isArray(productionPostureReceipts)
    || productionPostureReceipts.length !== 7) {
    throw new TypeError(
      "seven-CVM completion requires seven branded posture receipts",
    );
  }
  const postureMap = new Map(productionPostureReceipts.map((value) => {
    const posture = assertVerifiedProductionCvmPostureReceipt(value);
    return [posture.domain, posture];
  }));
  if (postureMap.size !== 7
    || PHALA_SEVEN_CVM_COMPLETION_ORDER.some(
      (domain) => !postureMap.has(domain),
    )) {
    throw new TypeError(
      "seven-CVM branded posture receipts are omitted or duplicated",
    );
  }

  if (contractReceiptSha256
      !== signedA.fresh_contract_deployment_receipt_sha256
    || sigstoreSha256
      !== signedA.image_release_sigstore_verification_receipt_sha256
    || contractReceipt.release_sha !== signedA.release_sha
    || sigstore.release_sha !== signedA.release_sha
    || descriptors.release_sha !== signedA.release_sha
    || executor.release_sha !== signedA.release_sha
    || executor.launch_intent_sha256 !== signedA.cvm_launch_intent_sha256
    || executor.batch_id !== signedA.batch_id
    || executor.bootstrap_authorization_id !== signedA.authorization_id
    || executor.bootstrap_authorization_receipt_sha256 !== signedASha256
    || executor.target_authority_sha256
      !== signedA.production_target_authority_sha256
    || descriptors.image_manifest_sha256 !== sigstore.release_manifest_sha256
    || descriptors.image_manifest_sigstore_bundle_sha256
      !== sigstore.release_manifest_sigstore_bundle_sha256
    || signedA.image_release_manifest_sha256
      !== descriptors.image_manifest_sha256
    || signedA.topology_sha256 !== descriptors.topology_sha256
    || !same(
      signedA.descriptor_sha256_by_domain,
      descriptors.descriptor_sha256_by_domain,
    )
    || !same(proofSet.execution_order, PHALA_SEVEN_CVM_COMPLETION_ORDER)
    || proofSet.release_authority_sha256 !== releaseAuthoritySha256
    || releaseAuthority.release_sha !== signedA.release_sha
    || releaseAuthority.deployment_intent_sha256
      !== signedA.deployment_intent_sha256
    || releaseAuthority.bootstrap_authorization_receipt_sha256 !== signedASha256
    || releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256
      !== contractReceiptSha256
    || (releaseAuthoritySchema
        === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA
      && (releaseAuthority
        .tinker_account_binding_ceremony_receipt_sha256
          !== descriptors
            .tinker_account_binding_ceremony_receipt_sha256
        || contractReceipt
          .tinker_account_binding_ceremony_receipt_sha256
            !== descriptors
              .tinker_account_binding_ceremony_receipt_sha256))
    || transcriptDirectoryIdentityAnchorSha256
      !== executor.phala_recovery_directory_identity_anchor_sha256
    || transcriptEvidenceSetSha256
      !== proofSetSha256
    || transcriptAuthorityFileSetSha256
      !== transcriptFileSetSha256
    || proofSet.historical_transcript_file_set_sha256
      !== transcriptFileSetSha256) {
    throw new TypeError(
      "seven-CVM completion dependencies do not form one signed A lineage",
    );
  }

  const diligenceRoomAddress = contractAddress(contractReceipt, "DiligenceRoom");
  const computeCreditVaultAddress = contractAddress(
    contractReceipt,
    "ComputeCreditVault",
  );
  if (releaseAuthority.contracts.diligence_room !== diligenceRoomAddress
    || releaseAuthority.contracts.compute_credit_vault
      !== computeCreditVaultAddress) {
    throw new TypeError(
      "seven-CVM release verification contract authority drifted from signed A",
    );
  }

  const proofMap = new Map(
    proofSet.domains.map((entry) => [entry.domain, entry]),
  );
  const domainCompletionAuthority = Object.fromEntries(
    PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => {
      const reservation = executor.reservations.find(
        (entry) => entry.domain === domain,
      );
      const preparation = executor.preparations.find(
        (entry) => entry.domain === domain,
      );
      const committed = executor.committed_prefix.find(
        (entry) => entry.domain === domain,
      );
      const executorPosture = executor.posture_receipts.find(
        (entry) => entry.domain === domain,
      );
      const posture = postureMap.get(domain);
      const proof = proofMap.get(domain);
      const releaseDescriptor = releaseAuthority.descriptors.find(
        (entry) => entry.domain === domain,
      );
      const postureSha256 =
        productionCvmPostureVerificationReceiptSha256(posture);
      const binding = contractBinding(
        domain,
        diligenceRoomAddress,
        computeCreditVaultAddress,
      );
      if (!reservation || !preparation || !committed || !executorPosture
        || !proof || !releaseDescriptor
        || reservation.app_id !== posture.app_id
        || reservation.app_id !== proof.app_id
        || committed.cvm_id !== posture.cvm_id
        || committed.cvm_id !== proof.cvm_id
        || posture.compose_hash !== proof.compose_hash
        || posture.os_image_hash !== proof.os_image_hash
        || executorPosture.receipt_sha256 !== postureSha256
        || releaseDescriptor.descriptor_sha256
          !== descriptors.descriptor_sha256_by_domain[domain]
        || releaseDescriptor.app_id !== posture.app_id
        || releaseDescriptor.cvm_id !== posture.cvm_id
        || releaseDescriptor.compose_hash !== posture.compose_hash
        || releaseDescriptor.os_image_hash !== posture.os_image_hash
        || releaseDescriptor.posture_receipt_sha256 !== postureSha256
        || releaseDescriptor.posture_observed_at !== posture.observed_at
        || releaseDescriptor.kms_id !== posture.kms_id
        || releaseDescriptor.instance_type !== posture.instance_type
        || releaseDescriptor.disk_size !== posture.disk_size
        || proof.contract_address !== binding.bound_contract_address
        || proof.verified_at
          < Math.floor(Date.parse(posture.observed_at) / 1_000)) {
        throw new TypeError(
          `${domain} executor, posture, proof, or contract authority drifted`,
        );
      }
      for (const value of [
        preparation.attempted_at,
        preparation.observed_at,
        committed.attempted_at,
        committed.observed_at,
      ]) {
        if (Date.parse(value) < Date.parse(signedA.issued_at)
          || Date.parse(value) >= Date.parse(signedA.expires_at)) {
          throw new TypeError(
            `${domain} mutation evidence is outside signed A's window`,
          );
        }
      }
      return [domain, {
        domain,
        descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[domain],
        descriptor_sha256: descriptors.descriptor_sha256_by_domain[domain],
        app_id: reservation.app_id,
        cvm_id: committed.cvm_id,
        committed_compose_hash: posture.compose_hash,
        kms_id: posture.kms_id,
        instance_type: posture.instance_type,
        disk_size: posture.disk_size,
        os_image_hash: posture.os_image_hash,
        provision_attempted_at: preparation.attempted_at,
        provision_observed_at: preparation.observed_at,
        commit_attempted_at: committed.attempted_at,
        commit_observed_at: committed.observed_at,
        production_posture_verified_at: posture.observed_at,
        machine_evidence_verified_at: proof.verified_at,
        activation_evidence_lease_expires_at:
          proof.activation_evidence_lease_expires_at,
        provision_observation_sha256: preparation.observation_sha256,
        commit_observation_sha256: committed.observation_sha256,
        production_posture_verification_receipt_sha256: postureSha256,
        machine_evidence_kind: proof.evidence_kind,
        machine_evidence_sha256: proof.evidence_sha256,
        tdx_attestation_evidence_sha256:
          proof.tdx_attestation_evidence_sha256,
        tdx_attestation_verification_receipt_sha256:
          proof.tdx_attestation_verification_receipt_sha256,
        tdx_measurements_sha256: proof.tdx_measurements_sha256,
        tdx_measurement_authority_sha256:
          proof.tdx_measurement_policy_sha256,
        qvl_release_policy_sha256: proof.qvl_release_policy_sha256,
        qvl_verification_receipt_sha256:
          proof.qvl_verification_receipt_sha256,
        qvl_identity_sha256: proof.qvl_identity_sha256,
        tee_identity: proof.tee_identity,
        ...binding,
        private_historical_transcript_contains_quote_bytes:
          proof.evidence_kind === "qvl_identity_local_dcap_verification",
        raw_quote_external_egress: false,
        raw_secret_egress: false,
      }];
    }),
  );

  return launchCompletionCore
    .normalizePhalaSevenCvmLaunchCompletionExpectedAuthority({
      release_sha: signedA.release_sha,
      deployment_intent_sha256: signedA.deployment_intent_sha256,
      reviewer_authority_genesis_acceptance_sha256: reviewerAcceptance,
      fresh_contract_deployment_receipt_sha256: contractReceiptSha256,
      diligence_room_address: diligenceRoomAddress,
      compute_credit_vault_address: computeCreditVaultAddress,
      cvm_launch_intent_sha256: signedA.cvm_launch_intent_sha256,
      nonlive_bootstrap_authorization_receipt_sha256: signedASha256,
      bootstrap_authorization_id: signedA.authorization_id,
      batch_id: signedA.batch_id,
      bootstrap_authorization_issued_at: signedA.issued_at,
      bootstrap_authorization_expires_at: signedA.expires_at,
      production_target_authority_sha256:
        signedA.production_target_authority_sha256,
      image_release_manifest_sha256: sigstore.release_manifest_sha256,
      image_release_sigstore_verification_receipt_sha256: sigstoreSha256,
      image_release_sigstore_bundle_sha256:
        sigstore.release_manifest_sigstore_bundle_sha256,
      topology_sha256: descriptors.topology_sha256,
      descriptor_set_receipt_sha256: descriptorSetSha256,
      executor_final_state_sha256: executorSha256,
      phala_recovery_directory_identity_anchor_sha256:
        executor.phala_recovery_directory_identity_anchor_sha256,
      machine_verifier_evidence_set_sha256: proofSetSha256,
      release_verification_authority: releaseAuthority,
      release_verification_authority_sha256: releaseAuthoritySha256,
      machine_verifier_evidence_mode: proofSet.evidence_mode,
      machine_verifier_evidence_issued_at: proofSet.issued_at,
      machine_verifier_verified_at: proofSet.verified_at,
      activation_evidence_lease_expires_at:
        proofSet.minimum_activation_evidence_lease_expires_at,
      historical_transcript_persistence_receipt_sha256:
        transcriptPersistenceSha256,
      historical_transcript_file_set_sha256: transcriptFileSetSha256,
      transcript_file_set: transcriptFileSet,
      descriptor_sha256_by_domain: descriptors.descriptor_sha256_by_domain,
      domain_completion_authority_by_domain: domainCompletionAuthority,
    });
}

export function normalizePhalaCvmDomainLaunchCompletionEvidence(
  value,
  options = {},
) {
  return launchCompletionCore.normalizePhalaCvmDomainLaunchCompletionEvidence(
    value,
    options,
  );
}

export function normalizePhalaSevenCvmHistoricalRuntimeBinding(value) {
  return launchCompletionCore.normalizePhalaSevenCvmHistoricalRuntimeBinding(
    value,
  );
}

export function createPhalaSevenCvmLaunchCompletionReceipt(options = {}) {
  const expected = externalAuthorityFromDependencies(options);
  return createBrandedCompletionFromExpectedAuthority(expected);
}

function createBrandedCompletionFromExpectedAuthority(expected) {
  const receipt =
    launchCompletionCore.createPhalaSevenCvmLaunchCompletionReceiptCandidate(
      expected,
    );
  BRANDED_COMPLETIONS.set(receipt, expected);
  return receipt;
}

export async function createPersistedPhalaSevenCvmLaunchCompletionReceipt({
  recoveryDirectory,
  qvlIdentityEvidence,
  workloadVerdictEvidence,
  ...dependencies
} = {}) {
  const executor = assertProvenanceVerifiedCompletedPhalaExecutorState(
    dependencies.executorFinalState,
  );
  const transcriptPersistencePreflight =
    await prepareProductionPhalaSevenCvmHistoricalTranscriptPersistence({
      directory: recoveryDirectory,
      directoryIdentityAnchorSha256:
        executor.phala_recovery_directory_identity_anchor_sha256,
      verifiedEvidenceSet: dependencies.verifiedEvidenceSet,
      qvlIdentityEvidence,
      workloadVerdictEvidence,
    });
  // Validate the complete signed-A -> descriptor -> executor -> posture ->
  // verifier -> release-authority lineage before the first create-only write.
  // The preflight carries only exact file identities and the anticipated
  // durable-receipt digest; it does not claim that persistence happened.
  const expected = externalAuthorityFromDependencies(dependencies, {
    transcriptPersistencePreflight,
  });
  const historicalTranscriptPersistenceReceipt =
    persistPreparedProductionPhalaSevenCvmHistoricalTranscriptFiles({
      preflight: transcriptPersistencePreflight,
    });

  // Everything after the durable commit boundary is deterministic. Recheck
  // only the returned durable receipt against the already-frozen preflight,
  // then mint L from the precomputed authority. No live proof, clock, network,
  // descriptor, or signer input is interpreted after persistence.
  const durable =
    assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(
      historicalTranscriptPersistenceReceipt,
    );
  if (phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(durable)
      !== transcriptPersistencePreflight
        .anticipated_persistence_receipt_sha256
    || durable.phala_recovery_directory_identity_anchor_sha256
      !== transcriptPersistencePreflight
        .phala_recovery_directory_identity_anchor_sha256
    || durable.seven_cvm_verified_evidence_set_sha256
      !== transcriptPersistencePreflight.seven_cvm_verified_evidence_set_sha256
    || durable.historical_transcript_file_set_sha256
      !== transcriptPersistencePreflight.historical_transcript_file_set_sha256
    || !same(
      durable.transcript_file_set,
      transcriptPersistencePreflight.transcript_file_set,
    )) {
    throw new Error(
      "durable exact-14 transcript differs from the complete pre-write launch preflight; explicit recovery is required",
    );
  }
  return createBrandedCompletionFromExpectedAuthority(expected);
}

export function assertBrandedPhalaSevenCvmLaunchCompletionReceipt(value) {
  if (value?.schema
      === REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA) {
    throw new TypeError(
      "the retired six-CVM launch completion schema is explicitly revoked",
    );
  }
  const expected = BRANDED_COMPLETIONS.get(value);
  if (!expected) {
    throw new TypeError(
      "seven-CVM completion was not reconstructed from production dependencies",
    );
  }
  launchCompletionCore.normalizePhalaSevenCvmLaunchCompletionReceipt(
    value,
    { expectedAuthority: expected },
  );
  return value;
}

export function assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(value) {
  const receipt = assertBrandedPhalaSevenCvmLaunchCompletionReceipt(value);
  const expected = BRANDED_COMPLETIONS.get(receipt);
  if (Math.floor(Date.now() / 1_000)
      >= expected.activation_evidence_lease_expires_at) {
    throw new TypeError(
      "seven-CVM launch completion activation-evidence lease expired and cannot mint fresh ceremony authority",
    );
  }
  return receipt;
}

export function assertHistoricallyVerifiedPhalaSevenCvmLaunchCompletionReceipt(
  value,
) {
  return assertBrandedPhalaSevenCvmLaunchCompletionReceipt(value);
}

export function normalizePhalaSevenCvmLaunchCompletionReceipt(
  value,
  optionsValue = {},
) {
  const expected = expectedAuthorityFromOptions(value, optionsValue);
  if (!expected) {
    throw new TypeError(
      "seven-CVM completion normalization requires external authority",
    );
  }
  return launchCompletionCore.normalizePhalaSevenCvmLaunchCompletionReceipt(
    value,
    { expectedAuthority: expected },
  );
}

export function canonicalPhalaSevenCvmLaunchCompletionReceiptText(
  value,
  optionsValue = {},
) {
  const expected = expectedAuthorityFromOptions(value, optionsValue);
  if (!expected) {
    throw new TypeError(
      "seven-CVM completion normalization requires external authority",
    );
  }
  return launchCompletionCore.canonicalPhalaSevenCvmLaunchCompletionReceiptText(
    value,
    { expectedAuthority: expected },
  );
}

export function phalaSevenCvmLaunchCompletionReceiptSha256(
  value,
  optionsValue = {},
) {
  const expected = expectedAuthorityFromOptions(value, optionsValue);
  if (!expected) {
    throw new TypeError(
      "seven-CVM completion normalization requires external authority",
    );
  }
  return launchCompletionCore.phalaSevenCvmLaunchCompletionReceiptSha256(
    value,
    { expectedAuthority: expected },
  );
}

export function assertPersistedPhalaSevenCvmLaunchCompletionReceipt({
  persistedReceipt,
  ...rawDependencies
} = {}) {
  if (persistedReceipt?.schema
      === REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA) {
    throw new TypeError(
      "the retired six-CVM launch completion schema is explicitly revoked",
    );
  }
  const expected = externalAuthorityFromDependencies(rawDependencies, {
    historicalEvidence: true,
  });
  const reconstructed =
    launchCompletionCore.createPhalaSevenCvmLaunchCompletionReceiptCandidate(
      expected,
    );
  const persisted =
    launchCompletionCore.normalizePhalaSevenCvmLaunchCompletionReceipt(
      persistedReceipt,
      { expectedAuthority: expected },
    );
  const persistedText =
    launchCompletionCore.canonicalPhalaSevenCvmLaunchCompletionReceiptText(
      persisted,
      { expectedAuthority: expected },
    );
  const reconstructedText =
    launchCompletionCore.canonicalPhalaSevenCvmLaunchCompletionReceiptText(
      reconstructed,
      { expectedAuthority: expected },
    );
  if (persistedText !== reconstructedText) {
    throw new TypeError(
      "persisted seven-CVM completion differs from raw dependencies",
    );
  }
  BRANDED_COMPLETIONS.set(reconstructed, expected);
  return reconstructed;
}

export async function reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency(
  input = {},
) {
  return launchCompletionCore
    .reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency(input);
}
