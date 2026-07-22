import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  BASE_SEPOLIA_CHAIN_ID,
  CVM_LAUNCH_DESCRIPTOR_FILES,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
} from "./phala-production-posture-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER,
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

/**
 * Deterministic, unbranded launch-completion evidence.
 *
 * This leaf verifies carried structure and cross-commitments only. It cannot
 * establish that a posture receipt was freshly observed, that a verifier ran,
 * that a transcript was durably persisted, or that a production mutation is
 * authorized. Those powers remain in the production facade and the enclosing
 * signed authority chain.
 */
export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA =
  "dnai.phala-cvm-domain-launch-completion-evidence.v4";
export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS =
  "committed_private_production_posture_and_machine_verifier_evidence_bound";
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA =
  "dnai.phala-seven-cvm-launch-completion-receipt.v4";
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-launch-completion-receipt/v4\0";
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS =
  "all_seven_committed_private_production_posture_and_machine_verifier_evidence_bound";
export const PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH =
  "exact_seven_cvm_release_resource_posture_five_qvl_identity_and_two_workload_verdict_activation_evidence_leases_bound_with_private_identity_quote_transcript_persistence_no_external_quote_private_artifact_secret_or_live_authority";
export const PHALA_SEVEN_CVM_COMPLETION_ORDER = Object.freeze([
  ...PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER,
]);
export const REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA =
  "dnai.phala-six-cvm-launch-completion-receipt.v1";
export const REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_AUTHORITY =
  Object.freeze({
    schema: REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
    domain: "dnai-wikigen/phala-six-cvm-launch-completion-receipt/v1\0",
    status: "revoked_incomplete_topology_missing_compute_workload_qvl",
  });

export {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
};

export const PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH =
  "exact_commit_posture_resource_and_machine_verifier_projection_bound_with_identity_quote_bytes_only_in_private_historical_transcript_no_external_quote_or_secret_egress";
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const INSTANCE_TYPE = /^[a-z][a-z0-9.-]{1,63}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const DOMAIN_AUTHORITY_FIELDS = Object.freeze([
  "domain",
  "descriptor_file",
  "descriptor_sha256",
  "app_id",
  "cvm_id",
  "committed_compose_hash",
  "kms_id",
  "instance_type",
  "disk_size",
  "os_image_hash",
  "provision_attempted_at",
  "provision_observed_at",
  "commit_attempted_at",
  "commit_observed_at",
  "production_posture_verified_at",
  "machine_evidence_verified_at",
  "activation_evidence_lease_expires_at",
  "provision_observation_sha256",
  "commit_observation_sha256",
  "production_posture_verification_receipt_sha256",
  "machine_evidence_kind",
  "machine_evidence_sha256",
  "tdx_attestation_evidence_sha256",
  "tdx_attestation_verification_receipt_sha256",
  "tdx_measurements_sha256",
  "tdx_measurement_authority_sha256",
  "qvl_release_policy_sha256",
  "qvl_verification_receipt_sha256",
  "qvl_identity_sha256",
  "tee_identity",
  "bound_contract_name",
  "bound_contract_address",
  "private_historical_transcript_contains_quote_bytes",
  "raw_quote_external_egress",
  "raw_secret_egress",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`${label} is not canonical fixed-width lowercase data`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new TypeError(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function epochSecond(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    throw new TypeError(`${label} must be a bounded Unix second`);
  }
  return value;
}

function exactDomainMap(value, label) {
  return exactRecord(value, PHALA_SEVEN_CVM_COMPLETION_ORDER, label);
}

function normalizeDomainAuthority(value, expectedDomain) {
  const parsed = exactRecord(
    value,
    DOMAIN_AUTHORITY_FIELDS,
    `${expectedDomain} completion authority`,
  );
  const identityEvidence = parsed.machine_evidence_kind
    === "qvl_identity_local_dcap_verification";
  const workloadEvidence = parsed.machine_evidence_kind
    === "workload_independent_signed_qvl_verdict";
  const workloadDomain = [
    "main_runtime_cvm",
    "independent_metering_cvm",
  ].includes(expectedDomain);
  if (parsed.domain !== expectedDomain
    || parsed.descriptor_file !== CVM_LAUNCH_DESCRIPTOR_FILES[expectedDomain]
    || !APP_ID.test(parsed.app_id)
    || !IDENTIFIER.test(parsed.cvm_id)
    || !IDENTIFIER.test(parsed.kms_id)
    || !INSTANCE_TYPE.test(parsed.instance_type)
    || !Number.isSafeInteger(parsed.disk_size)
    || parsed.disk_size < 20 || parsed.disk_size > 16_384
    || parsed.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || (!identityEvidence && !workloadEvidence)
    || workloadEvidence !== workloadDomain
    || parsed.private_historical_transcript_contains_quote_bytes
      !== identityEvidence
    || parsed.raw_quote_external_egress !== false
    || parsed.raw_secret_egress !== false
    || !ADDRESS.test(parsed.tee_identity)) {
    throw new TypeError(`${expectedDomain} completion authority is invalid`);
  }
  const times = {
    provision_attempted_at: timestamp(
      parsed.provision_attempted_at,
      `${expectedDomain} provision attempted_at`,
    ),
    provision_observed_at: timestamp(
      parsed.provision_observed_at,
      `${expectedDomain} provision observed_at`,
    ),
    commit_attempted_at: timestamp(
      parsed.commit_attempted_at,
      `${expectedDomain} commit attempted_at`,
    ),
    commit_observed_at: timestamp(
      parsed.commit_observed_at,
      `${expectedDomain} commit observed_at`,
    ),
    production_posture_verified_at: timestamp(
      parsed.production_posture_verified_at,
      `${expectedDomain} posture verified_at`,
    ),
  };
  if (Date.parse(times.provision_observed_at)
      < Date.parse(times.provision_attempted_at)
    || Date.parse(times.commit_observed_at)
      < Date.parse(times.commit_attempted_at)
    || Date.parse(times.production_posture_verified_at)
      < Date.parse(times.commit_observed_at)) {
    throw new TypeError(`${expectedDomain} completion event times are not monotonic`);
  }
  const machineEvidenceVerifiedAt = epochSecond(
    parsed.machine_evidence_verified_at,
    `${expectedDomain} machine evidence verified_at`,
  );
  const activationEvidenceLeaseExpiresAt = epochSecond(
    parsed.activation_evidence_lease_expires_at,
    `${expectedDomain} activation-evidence lease expires_at`,
  );
  if (machineEvidenceVerifiedAt
      < Math.floor(Date.parse(times.production_posture_verified_at) / 1_000)) {
    throw new TypeError(
      `${expectedDomain} machine evidence predates production posture`,
    );
  }
  if (activationEvidenceLeaseExpiresAt <= machineEvidenceVerifiedAt) {
    throw new TypeError(
      `${expectedDomain} activation-evidence lease does not outlive verification`,
    );
  }
  for (const field of [
    "descriptor_sha256",
    "provision_observation_sha256",
    "commit_observation_sha256",
    "production_posture_verification_receipt_sha256",
    "machine_evidence_sha256",
    "tdx_attestation_evidence_sha256",
    "tdx_attestation_verification_receipt_sha256",
    "qvl_release_policy_sha256",
    "qvl_verification_receipt_sha256",
    "qvl_identity_sha256",
  ]) digest(parsed[field], `${expectedDomain} ${field}`);
  const tdxMeasurementsSha256 = identityEvidence
    ? digest(
      parsed.tdx_measurements_sha256,
      `${expectedDomain} observed TDX measurements`,
    )
    : parsed.tdx_measurements_sha256;
  if (!identityEvidence && tdxMeasurementsSha256 !== null) {
    throw new TypeError(
      `${expectedDomain} workload evidence cannot invent observed TDX measurements`,
    );
  }
  digest(
    parsed.tdx_measurement_authority_sha256,
    `${expectedDomain} TDX measurement authority`,
  );
  fixed(
    parsed.committed_compose_hash,
    BARE_SHA256,
    `${expectedDomain} compose hash`,
  );
  if (workloadEvidence) {
    const expectedName = expectedDomain === "main_runtime_cvm"
      ? "DiligenceRoom"
      : "ComputeCreditVault";
    if (parsed.bound_contract_name !== expectedName) {
      throw new TypeError(`${expectedDomain} workload contract name is invalid`);
    }
    fixed(
      parsed.bound_contract_address,
      ADDRESS,
      `${expectedDomain} workload contract`,
    );
  } else if (parsed.bound_contract_name !== null
    || parsed.bound_contract_address !== null) {
    throw new TypeError(
      `${expectedDomain} QVL identity cannot bind a workload contract`,
    );
  }
  return {
    domain: expectedDomain,
    descriptor_file: CVM_LAUNCH_DESCRIPTOR_FILES[expectedDomain],
    descriptor_sha256: parsed.descriptor_sha256,
    app_id: parsed.app_id,
    cvm_id: parsed.cvm_id,
    committed_compose_hash: parsed.committed_compose_hash,
    kms_id: parsed.kms_id,
    instance_type: parsed.instance_type,
    disk_size: parsed.disk_size,
    os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    ...times,
    machine_evidence_verified_at: machineEvidenceVerifiedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    provision_observation_sha256: parsed.provision_observation_sha256,
    commit_observation_sha256: parsed.commit_observation_sha256,
    production_posture_verification_receipt_sha256:
      parsed.production_posture_verification_receipt_sha256,
    machine_evidence_kind: parsed.machine_evidence_kind,
    machine_evidence_sha256: parsed.machine_evidence_sha256,
    tdx_attestation_evidence_sha256: parsed.tdx_attestation_evidence_sha256,
    tdx_attestation_verification_receipt_sha256:
      parsed.tdx_attestation_verification_receipt_sha256,
    tdx_measurements_sha256: tdxMeasurementsSha256,
    tdx_measurement_authority_sha256: parsed.tdx_measurement_authority_sha256,
    qvl_release_policy_sha256: parsed.qvl_release_policy_sha256,
    qvl_verification_receipt_sha256: parsed.qvl_verification_receipt_sha256,
    qvl_identity_sha256: parsed.qvl_identity_sha256,
    tee_identity: parsed.tee_identity,
    bound_contract_name: parsed.bound_contract_name,
    bound_contract_address: parsed.bound_contract_address,
    private_historical_transcript_contains_quote_bytes: identityEvidence,
    raw_quote_external_egress: false,
    raw_secret_egress: false,
  };
}

export function normalizePhalaSevenCvmLaunchCompletionExpectedAuthority(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "seven-CVM completion external authority",
  });
  const expected = exactRecord(value, [
    "release_sha",
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "diligence_room_address",
    "compute_credit_vault_address",
    "cvm_launch_intent_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "bootstrap_authorization_id",
    "batch_id",
    "bootstrap_authorization_issued_at",
    "bootstrap_authorization_expires_at",
    "production_target_authority_sha256",
    "image_release_manifest_sha256",
    "image_release_sigstore_verification_receipt_sha256",
    "image_release_sigstore_bundle_sha256",
    "topology_sha256",
    "descriptor_set_receipt_sha256",
    "executor_final_state_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "machine_verifier_evidence_set_sha256",
    "release_verification_authority",
    "release_verification_authority_sha256",
    "machine_verifier_evidence_mode",
    "machine_verifier_evidence_issued_at",
    "machine_verifier_verified_at",
    "activation_evidence_lease_expires_at",
    "historical_transcript_persistence_receipt_sha256",
    "historical_transcript_file_set_sha256",
    "transcript_file_set",
    "descriptor_sha256_by_domain",
    "domain_completion_authority_by_domain",
  ], "seven-CVM completion external authority");
  fixed(expected.release_sha, SHA40, "seven-CVM completion release SHA");
  for (const field of [
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "cvm_launch_intent_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "bootstrap_authorization_id",
    "batch_id",
    "production_target_authority_sha256",
    "image_release_manifest_sha256",
    "image_release_sigstore_verification_receipt_sha256",
    "image_release_sigstore_bundle_sha256",
    "topology_sha256",
    "descriptor_set_receipt_sha256",
    "executor_final_state_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "machine_verifier_evidence_set_sha256",
    "release_verification_authority_sha256",
    "historical_transcript_persistence_receipt_sha256",
    "historical_transcript_file_set_sha256",
  ]) digest(expected[field], `seven-CVM completion authority ${field}`);
  const diligenceRoomAddress = fixed(
    expected.diligence_room_address,
    ADDRESS,
    "DiligenceRoom authority",
  );
  const computeCreditVaultAddress = fixed(
    expected.compute_credit_vault_address,
    ADDRESS,
    "ComputeCreditVault authority",
  );
  if (diligenceRoomAddress === computeCreditVaultAddress
    || expected.machine_verifier_evidence_mode
      !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new TypeError(
      "seven-CVM contract or production verifier authority is invalid",
    );
  }
  const issuedAt = timestamp(
    expected.bootstrap_authorization_issued_at,
    "seven-CVM completion A issued_at",
  );
  const expiresAt = timestamp(
    expected.bootstrap_authorization_expires_at,
    "seven-CVM completion A expires_at",
  );
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new TypeError("seven-CVM completion A window is invalid");
  }
  const verifierTime = epochSecond(
    expected.machine_verifier_verified_at,
    "seven-CVM verifier completion time",
  );
  const activationEvidenceLeaseExpiresAt = epochSecond(
    expected.activation_evidence_lease_expires_at,
    "seven-CVM activation-evidence lease expiry",
  );
  const verifierIssuedAt = epochSecond(
    expected.machine_verifier_evidence_issued_at,
    "seven-CVM evidence-set issued_at",
  );
  if (activationEvidenceLeaseExpiresAt <= verifierTime
    || verifierIssuedAt < verifierTime
    || verifierIssuedAt >= activationEvidenceLeaseExpiresAt) {
    throw new TypeError("seven-CVM activation-evidence lease is invalid");
  }
  const transcriptFileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    expected.transcript_file_set,
  );
  if (phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet)
      !== expected.historical_transcript_file_set_sha256) {
    throw new TypeError(
      "seven-CVM completion historical transcript file-set digest drifted",
    );
  }
  const descriptors = exactDomainMap(
    expected.descriptor_sha256_by_domain,
    "seven-CVM descriptor authority",
  );
  const rawDomains = exactDomainMap(
    expected.domain_completion_authority_by_domain,
    "seven-CVM domain completion authority",
  );
  const normalizedDomains = Object.fromEntries(
    PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => {
      const normalized = normalizeDomainAuthority(rawDomains[domain], domain);
      if (normalized.descriptor_sha256 !== descriptors[domain]
        || normalized.machine_evidence_verified_at > verifierTime) {
        throw new TypeError(
          `${domain} completion authority drifts from descriptor or proof set`,
        );
      }
      digest(descriptors[domain], `${domain} descriptor authority`);
      return [domain, normalized];
    }),
  );
  const minimumDomainLeaseExpiry = Math.min(
    ...Object.values(normalizedDomains)
      .map((entry) => entry.activation_evidence_lease_expires_at),
  );
  if (activationEvidenceLeaseExpiresAt !== minimumDomainLeaseExpiry) {
    throw new TypeError(
      "seven-CVM activation-evidence lease is not the exact domain minimum",
    );
  }
  if (new Set(Object.values(descriptors)).size !== 7) {
    throw new TypeError("seven-CVM descriptor hashes must be pairwise distinct");
  }
  if (normalizedDomains.main_runtime_cvm.bound_contract_name !== "DiligenceRoom"
    || normalizedDomains.main_runtime_cvm.bound_contract_address
      !== diligenceRoomAddress
    || normalizedDomains.independent_metering_cvm.bound_contract_name
      !== "ComputeCreditVault"
    || normalizedDomains.independent_metering_cvm.bound_contract_address
      !== computeCreditVaultAddress) {
    throw new TypeError(
      "seven-CVM workload contracts drift from top-level contract authority",
    );
  }

  const releaseAuthority = normalizePhalaSevenCvmReleaseVerificationAuthority(
    expected.release_verification_authority,
  );
  const releaseAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const runtimeAuthority = releaseAuthority.cvm_descriptor_runtime_authority;
  if (releaseAuthoritySha256 !== expected.release_verification_authority_sha256
    || releaseAuthority.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE
    || releaseAuthority.release_sha !== expected.release_sha
    || releaseAuthority.deployment_intent_sha256
      !== expected.deployment_intent_sha256
    || releaseAuthority.bootstrap_authorization_receipt_sha256
      !== expected.nonlive_bootstrap_authorization_receipt_sha256
    || releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256
      !== expected.fresh_contract_deployment_receipt_sha256
    || releaseAuthority.contracts.diligence_room !== diligenceRoomAddress
    || releaseAuthority.contracts.compute_credit_vault
      !== computeCreditVaultAddress
    || runtimeAuthority.descriptor_set_receipt_sha256
      !== expected.descriptor_set_receipt_sha256
    || runtimeAuthority.image_manifest_sha256
      !== expected.image_release_manifest_sha256
    || runtimeAuthority.topology_sha256 !== expected.topology_sha256) {
    throw new TypeError(
      "seven-CVM release verification authority or transitive lineage drifted",
    );
  }
  const releaseDescriptors = new Map(
    releaseAuthority.descriptors.map((descriptor) => [descriptor.domain, descriptor]),
  );
  for (const domain of PHALA_SEVEN_CVM_COMPLETION_ORDER) {
    const releaseDescriptor = releaseDescriptors.get(domain);
    const completion = normalizedDomains[domain];
    if (!releaseDescriptor
      || releaseDescriptor.descriptor_sha256 !== completion.descriptor_sha256
      || releaseDescriptor.app_id !== completion.app_id
      || releaseDescriptor.cvm_id !== completion.cvm_id
      || releaseDescriptor.compose_hash !== completion.committed_compose_hash
      || releaseDescriptor.os_image_hash !== completion.os_image_hash
      || releaseDescriptor.posture_receipt_sha256
        !== completion.production_posture_verification_receipt_sha256
      || releaseDescriptor.posture_observed_at
        !== completion.production_posture_verified_at
      || releaseDescriptor.kms_id !== completion.kms_id
      || releaseDescriptor.instance_type !== completion.instance_type
      || releaseDescriptor.disk_size !== completion.disk_size) {
      throw new TypeError(
        `${domain} completion differs from embedded release resource authority`,
      );
    }
  }

  return deepFreezeCanonicalPlainDataGraph({
    ...expected,
    diligence_room_address: diligenceRoomAddress,
    compute_credit_vault_address: computeCreditVaultAddress,
    bootstrap_authorization_issued_at: issuedAt,
    bootstrap_authorization_expires_at: expiresAt,
    machine_verifier_verified_at: verifierTime,
    machine_verifier_evidence_issued_at: verifierIssuedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256: releaseAuthoritySha256,
    transcript_file_set: transcriptFileSet,
    descriptor_sha256_by_domain: Object.fromEntries(
      PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => [
        domain,
        descriptors[domain],
      ]),
    ),
    domain_completion_authority_by_domain: normalizedDomains,
  }, { label: "seven-CVM completion expected authority" });
}

export function normalizePhalaCvmDomainLaunchCompletionEvidence(
  value,
  optionsValue = {},
) {
  assertCanonicalPlainDataGraph(optionsValue, {
    label: "domain completion normalization options",
  });
  const {
    expectedDomain,
    expectedAuthority,
  } = exactRecord(optionsValue, [
    "expectedDomain",
    "expectedAuthority",
  ], "domain completion normalization options");
  assertCanonicalPlainDataGraph(value, {
    label: `${expectedDomain || "unknown"} domain completion evidence`,
  });
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    ...DOMAIN_AUTHORITY_FIELDS,
  ], `${expectedDomain || "unknown"} domain completion evidence`);
  if (parsed.schema !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA
    || parsed.status !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS
    || parsed.truth_status
      !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH) {
    throw new TypeError(
      `${expectedDomain} domain completion schema or status is invalid`,
    );
  }
  const normalized = normalizeDomainAuthority(
    Object.fromEntries(DOMAIN_AUTHORITY_FIELDS.map((field) => [
      field,
      parsed[field],
    ])),
    expectedDomain,
  );
  const expected = normalizeDomainAuthority(expectedAuthority, expectedDomain);
  if (!same(normalized, expected)) {
    throw new TypeError(
      `${expectedDomain} domain completion differs from external authority`,
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
    status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS,
    truth_status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH,
    ...normalized,
  }, { label: `${expectedDomain} domain completion evidence` });
}

export function normalizePhalaSevenCvmLaunchCompletionReceipt(
  value,
  optionsValue = {},
) {
  assertCanonicalPlainDataGraph(optionsValue, {
    label: "seven-CVM launch completion normalization options",
  });
  const { expectedAuthority } = exactRecord(optionsValue, [
    "expectedAuthority",
  ], "seven-CVM launch completion normalization options");
  assertCanonicalPlainDataGraph(value, {
    label: "seven-CVM launch completion receipt",
  });
  if (value?.schema === REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA) {
    throw new TypeError(
      "the retired six-CVM launch completion schema is explicitly revoked",
    );
  }
  const expected = normalizePhalaSevenCvmLaunchCompletionExpectedAuthority(
    expectedAuthority,
  );
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "chain_id",
    "release_sha",
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "cvm_launch_intent_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "bootstrap_authorization_id",
    "batch_id",
    "production_target_authority_sha256",
    "image_release_manifest_sha256",
    "image_release_sigstore_verification_receipt_sha256",
    "image_release_sigstore_bundle_sha256",
    "topology_sha256",
    "descriptor_set_receipt_sha256",
    "executor_final_state_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "machine_verifier_evidence_set_sha256",
    "machine_verifier_evidence_mode",
    "machine_verifier_evidence_issued_at",
    "activation_evidence_lease_expires_at",
    "release_verification_authority_sha256",
    "historical_transcript_persistence_receipt_sha256",
    "historical_transcript_file_set_sha256",
    "transcript_file_set",
    "completion_order",
    "mutation_order",
    "domains",
    "completed_at",
    "commit_count",
    "all_seven_committed",
    "all_seven_production_posture_validated",
    "five_qvl_identities_machine_verified",
    "two_workload_verdicts_machine_verified",
    "all_seven_machine_verified",
    "live_traffic_authorized",
    "late_secret_activation_authorized",
    "compute_workload_recipient_activation_authorized",
    "private_historical_identity_response_quote_bytes_persisted",
    "raw_quote_external_egress",
    "raw_private_artifact_egress",
    "raw_secret_egress",
  ], "seven-CVM launch completion receipt");
  const exactTop = {
    release_sha: expected.release_sha,
    deployment_intent_sha256: expected.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      expected.reviewer_authority_genesis_acceptance_sha256,
    fresh_contract_deployment_receipt_sha256:
      expected.fresh_contract_deployment_receipt_sha256,
    cvm_launch_intent_sha256: expected.cvm_launch_intent_sha256,
    nonlive_bootstrap_authorization_receipt_sha256:
      expected.nonlive_bootstrap_authorization_receipt_sha256,
    bootstrap_authorization_id: expected.bootstrap_authorization_id,
    batch_id: expected.batch_id,
    production_target_authority_sha256:
      expected.production_target_authority_sha256,
    image_release_manifest_sha256: expected.image_release_manifest_sha256,
    image_release_sigstore_verification_receipt_sha256:
      expected.image_release_sigstore_verification_receipt_sha256,
    image_release_sigstore_bundle_sha256:
      expected.image_release_sigstore_bundle_sha256,
    topology_sha256: expected.topology_sha256,
    descriptor_set_receipt_sha256: expected.descriptor_set_receipt_sha256,
    executor_final_state_sha256: expected.executor_final_state_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      expected.phala_recovery_directory_identity_anchor_sha256,
    machine_verifier_evidence_set_sha256:
      expected.machine_verifier_evidence_set_sha256,
    machine_verifier_evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    machine_verifier_evidence_issued_at:
      expected.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      expected.activation_evidence_lease_expires_at,
    release_verification_authority_sha256:
      expected.release_verification_authority_sha256,
    historical_transcript_persistence_receipt_sha256:
      expected.historical_transcript_persistence_receipt_sha256,
    historical_transcript_file_set_sha256:
      expected.historical_transcript_file_set_sha256,
  };
  const transcriptFileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    parsed.transcript_file_set,
  );
  if (parsed.schema !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA
    || parsed.status !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS
    || parsed.truth_status !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || Object.entries(exactTop).some(([field, expectedValue]) => (
      parsed[field] !== expectedValue
    ))
    || !same(transcriptFileSet, expected.transcript_file_set)
    || !same(parsed.completion_order, PHALA_SEVEN_CVM_COMPLETION_ORDER)
    || !same(parsed.mutation_order, PHALA_EXECUTION_ORDER)
    || parsed.commit_count !== 7
    || parsed.all_seven_committed !== true
    || parsed.all_seven_production_posture_validated !== true
    || parsed.five_qvl_identities_machine_verified !== true
    || parsed.two_workload_verdicts_machine_verified !== true
    || parsed.all_seven_machine_verified !== true
    || parsed.live_traffic_authorized !== false
    || parsed.late_secret_activation_authorized !== false
    || parsed.compute_workload_recipient_activation_authorized !== false
    || parsed.private_historical_identity_response_quote_bytes_persisted
      !== true
    || parsed.raw_quote_external_egress !== false
    || parsed.raw_private_artifact_egress !== false
    || parsed.raw_secret_egress !== false
    || !Array.isArray(parsed.domains) || parsed.domains.length !== 7) {
    throw new TypeError(
      "seven-CVM launch completion receipt authority or posture is invalid",
    );
  }
  const domains = parsed.domains.map((entry, index) => {
    const domain = PHALA_SEVEN_CVM_COMPLETION_ORDER[index];
    return normalizePhalaCvmDomainLaunchCompletionEvidence(entry, {
      expectedDomain: domain,
      expectedAuthority: expected.domain_completion_authority_by_domain[domain],
    });
  });
  for (const field of ["app_id", "cvm_id", "committed_compose_hash", "tee_identity"]) {
    if (new Set(domains.map((entry) => entry[field])).size !== 7) {
      throw new TypeError(`seven-CVM ${field} values must be pairwise distinct`);
    }
  }
  const byDomain = new Map(domains.map((entry) => [entry.domain, entry]));
  const issuedMs = Date.parse(expected.bootstrap_authorization_issued_at);
  const expiresMs = Date.parse(expected.bootstrap_authorization_expires_at);
  for (const domain of PHALA_EXECUTION_ORDER) {
    const entry = byDomain.get(domain);
    for (const field of [
      "provision_attempted_at",
      "provision_observed_at",
      "commit_attempted_at",
      "commit_observed_at",
    ]) {
      const time = Date.parse(entry[field]);
      if (time < issuedMs || time >= expiresMs) {
        throw new TypeError(
          `${domain} ${field} is outside signed A's mutation window`,
        );
      }
    }
  }
  for (let index = 1; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const previous = byDomain.get(PHALA_EXECUTION_ORDER[index - 1]);
    const current = byDomain.get(PHALA_EXECUTION_ORDER[index]);
    if (Date.parse(current.provision_attempted_at)
        < Date.parse(previous.provision_observed_at)
      || Date.parse(current.commit_attempted_at)
        < Date.parse(previous.commit_observed_at)) {
      throw new TypeError(
        "seven-CVM mutations do not follow supporting-six-then-main order",
      );
    }
  }
  if (Date.parse(byDomain.get(PHALA_EXECUTION_ORDER[0]).commit_attempted_at)
      < Math.max(...domains.map((entry) => Date.parse(entry.provision_observed_at)))) {
    throw new TypeError(
      "seven-CVM commits began before all seven preparations completed",
    );
  }
  const completedAt = epochSecond(parsed.completed_at, "seven-CVM completed_at");
  if (completedAt !== expected.machine_verifier_verified_at
    || completedAt !== Math.max(...domains.map((entry) => (
      entry.machine_evidence_verified_at
    )))) {
    throw new TypeError(
      "seven-CVM completed_at is not the exact maximum machine-proof time",
    );
  }
  if (completedAt >= parsed.activation_evidence_lease_expires_at) {
    throw new TypeError(
      "seven-CVM completion is outside the activation-evidence lease",
    );
  }
  if (domains.filter((entry) => (
    entry.machine_evidence_kind === "qvl_identity_local_dcap_verification"
  )).length !== 5
    || domains.filter((entry) => (
      entry.machine_evidence_kind === "workload_independent_signed_qvl_verdict"
    )).length !== 2) {
    throw new TypeError(
      "seven-CVM completion does not bind exactly five QVL and two workload proofs",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
    status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS,
    truth_status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    ...exactTop,
    transcript_file_set: transcriptFileSet,
    completion_order: [...PHALA_SEVEN_CVM_COMPLETION_ORDER],
    mutation_order: [...PHALA_EXECUTION_ORDER],
    domains,
    completed_at: completedAt,
    commit_count: 7,
    all_seven_committed: true,
    all_seven_production_posture_validated: true,
    five_qvl_identities_machine_verified: true,
    two_workload_verdicts_machine_verified: true,
    all_seven_machine_verified: true,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    compute_workload_recipient_activation_authorized: false,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  }, { label: "normalized seven-CVM launch completion receipt" });
}

export function canonicalPhalaSevenCvmLaunchCompletionReceiptText(
  value,
  options = {},
) {
  return `${JSON.stringify(
    sorted(normalizePhalaSevenCvmLaunchCompletionReceipt(value, options)),
    null,
    2,
  )}\n`;
}

export function phalaSevenCvmLaunchCompletionReceiptSha256(value, options = {}) {
  return `sha256:${createHash("sha256")
    .update(PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN, "utf8")
    .update(canonicalPhalaSevenCvmLaunchCompletionReceiptText(value, options), "utf8")
    .digest("hex")}`;
}

export function createPhalaSevenCvmLaunchCompletionReceiptCandidate(
  expectedAuthority,
) {
  const expected = normalizePhalaSevenCvmLaunchCompletionExpectedAuthority(
    expectedAuthority,
  );
  return normalizePhalaSevenCvmLaunchCompletionReceipt({
    schema: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
    status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS,
    truth_status: PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    release_sha: expected.release_sha,
    deployment_intent_sha256: expected.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      expected.reviewer_authority_genesis_acceptance_sha256,
    fresh_contract_deployment_receipt_sha256:
      expected.fresh_contract_deployment_receipt_sha256,
    cvm_launch_intent_sha256: expected.cvm_launch_intent_sha256,
    nonlive_bootstrap_authorization_receipt_sha256:
      expected.nonlive_bootstrap_authorization_receipt_sha256,
    bootstrap_authorization_id: expected.bootstrap_authorization_id,
    batch_id: expected.batch_id,
    production_target_authority_sha256:
      expected.production_target_authority_sha256,
    image_release_manifest_sha256: expected.image_release_manifest_sha256,
    image_release_sigstore_verification_receipt_sha256:
      expected.image_release_sigstore_verification_receipt_sha256,
    image_release_sigstore_bundle_sha256:
      expected.image_release_sigstore_bundle_sha256,
    topology_sha256: expected.topology_sha256,
    descriptor_set_receipt_sha256: expected.descriptor_set_receipt_sha256,
    executor_final_state_sha256: expected.executor_final_state_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      expected.phala_recovery_directory_identity_anchor_sha256,
    machine_verifier_evidence_set_sha256:
      expected.machine_verifier_evidence_set_sha256,
    machine_verifier_evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    machine_verifier_evidence_issued_at:
      expected.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      expected.activation_evidence_lease_expires_at,
    release_verification_authority_sha256:
      expected.release_verification_authority_sha256,
    historical_transcript_persistence_receipt_sha256:
      expected.historical_transcript_persistence_receipt_sha256,
    historical_transcript_file_set_sha256:
      expected.historical_transcript_file_set_sha256,
    transcript_file_set: expected.transcript_file_set,
    completion_order: [...PHALA_SEVEN_CVM_COMPLETION_ORDER],
    mutation_order: [...PHALA_EXECUTION_ORDER],
    domains: PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => ({
      schema: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
      status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS,
      truth_status: PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH,
      ...expected.domain_completion_authority_by_domain[domain],
    })),
    completed_at: expected.machine_verifier_verified_at,
    commit_count: 7,
    all_seven_committed: true,
    all_seven_production_posture_validated: true,
    five_qvl_identities_machine_verified: true,
    two_workload_verdicts_machine_verified: true,
    all_seven_machine_verified: true,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    compute_workload_recipient_activation_authorized: false,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  }, { expectedAuthority: expected });
}

function normalizeHistoricalBootstrapAuthorizationBinding(value) {
  const parsed = exactRecord(value, [
    "authorization_id",
    "batch_id",
    "receipt_sha256",
    "issued_at",
    "expires_at",
  ], "historical signed-A launch binding");
  const issuedAt = timestamp(parsed.issued_at, "historical signed-A issued_at");
  const expiresAt = timestamp(parsed.expires_at, "historical signed-A expires_at");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new TypeError("historical signed-A launch window is invalid");
  }
  return {
    authorization_id: digest(
      parsed.authorization_id,
      "historical signed-A authorization id",
    ),
    batch_id: digest(parsed.batch_id, "historical signed-A batch"),
    receipt_sha256: digest(parsed.receipt_sha256, "historical signed-A receipt"),
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
}

function domainAuthorityFromPersistedEvidence(value, expectedDomain) {
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    ...DOMAIN_AUTHORITY_FIELDS,
  ], `${expectedDomain} persisted completion evidence`);
  if (parsed.schema !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA
    || parsed.status !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_STATUS
    || parsed.truth_status
      !== PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_TRUTH) {
    throw new TypeError(
      `${expectedDomain} persisted completion evidence is invalid`,
    );
  }
  return normalizeDomainAuthority(
    Object.fromEntries(DOMAIN_AUTHORITY_FIELDS.map((field) => [
      field,
      parsed[field],
    ])),
    expectedDomain,
  );
}

/**
 * Reconstruct persisted L as historical, unbranded data.
 *
 * The caller must authenticate R and signed A in the enclosing signed chain.
 * This function deliberately performs no I/O, current-clock check, freshness
 * renewal, production brand creation, verifier execution, or mutation.
 */
export function reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency(
  input = {},
) {
  assertCanonicalPlainDataGraph(input, {
    label: "historical seven-CVM completion reconstruction input",
  });
  const {
    persistedReceipt,
    persistedExecutorFinalState,
    historicalPreCeremonyRuntimeBinding,
    historicalBootstrapAuthorizationBinding,
  } = exactRecord(input, [
    "persistedReceipt",
    "persistedExecutorFinalState",
    "historicalPreCeremonyRuntimeBinding",
    "historicalBootstrapAuthorizationBinding",
  ], "historical seven-CVM completion reconstruction input");
  const runtimeBinding = normalizePhalaSevenCvmHistoricalRuntimeBinding(
    historicalPreCeremonyRuntimeBinding,
  );
  const executor = normalizeCompletedPhalaExecutorState(
    persistedExecutorFinalState,
  );
  const bootstrap = normalizeHistoricalBootstrapAuthorizationBinding(
    historicalBootstrapAuthorizationBinding,
  );
  if (!isRecord(persistedReceipt)
    || !Array.isArray(persistedReceipt.domains)
    || persistedReceipt.domains.length !== PHALA_SEVEN_CVM_COMPLETION_ORDER.length) {
    throw new TypeError(
      "persisted seven-CVM completion omits the exact seven domains",
    );
  }
  const domains = Object.fromEntries(
    PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain, index) => [
      domain,
      domainAuthorityFromPersistedEvidence(
        persistedReceipt.domains[index],
        domain,
      ),
    ]),
  );
  const main = domains.main_runtime_cvm;
  const independentMetering = domains.independent_metering_cvm;
  const releaseAuthority = runtimeBinding.release_verification_authority;
  const expectedAuthority = normalizePhalaSevenCvmLaunchCompletionExpectedAuthority({
    release_sha: persistedReceipt.release_sha,
    deployment_intent_sha256: persistedReceipt.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      persistedReceipt.reviewer_authority_genesis_acceptance_sha256,
    fresh_contract_deployment_receipt_sha256:
      persistedReceipt.fresh_contract_deployment_receipt_sha256,
    diligence_room_address: main.bound_contract_address,
    compute_credit_vault_address: independentMetering.bound_contract_address,
    cvm_launch_intent_sha256: persistedReceipt.cvm_launch_intent_sha256,
    nonlive_bootstrap_authorization_receipt_sha256: bootstrap.receipt_sha256,
    bootstrap_authorization_id: bootstrap.authorization_id,
    batch_id: bootstrap.batch_id,
    bootstrap_authorization_issued_at: bootstrap.issued_at,
    bootstrap_authorization_expires_at: bootstrap.expires_at,
    production_target_authority_sha256:
      persistedReceipt.production_target_authority_sha256,
    image_release_manifest_sha256:
      persistedReceipt.image_release_manifest_sha256,
    image_release_sigstore_verification_receipt_sha256:
      persistedReceipt.image_release_sigstore_verification_receipt_sha256,
    image_release_sigstore_bundle_sha256:
      persistedReceipt.image_release_sigstore_bundle_sha256,
    topology_sha256: persistedReceipt.topology_sha256,
    descriptor_set_receipt_sha256: persistedReceipt.descriptor_set_receipt_sha256,
    executor_final_state_sha256: phalaExecutorStateDigest(executor),
    phala_recovery_directory_identity_anchor_sha256:
      executor.phala_recovery_directory_identity_anchor_sha256,
    machine_verifier_evidence_set_sha256:
      runtimeBinding.seven_cvm_verified_evidence_set_sha256,
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256:
      runtimeBinding.release_verification_authority_sha256,
    machine_verifier_evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    machine_verifier_evidence_issued_at:
      runtimeBinding.machine_verifier_evidence_issued_at,
    machine_verifier_verified_at: persistedReceipt.completed_at,
    activation_evidence_lease_expires_at:
      runtimeBinding.activation_evidence_lease_expires_at,
    historical_transcript_persistence_receipt_sha256:
      persistedReceipt.historical_transcript_persistence_receipt_sha256,
    historical_transcript_file_set_sha256:
      persistedReceipt.historical_transcript_file_set_sha256,
    transcript_file_set: persistedReceipt.transcript_file_set,
    descriptor_sha256_by_domain: Object.fromEntries(
      PHALA_SEVEN_CVM_COMPLETION_ORDER.map((domain) => [
        domain,
        domains[domain].descriptor_sha256,
      ]),
    ),
    domain_completion_authority_by_domain: domains,
  });
  const receipt = normalizePhalaSevenCvmLaunchCompletionReceipt(
    persistedReceipt,
    { expectedAuthority },
  );
  const receiptSha256 = phalaSevenCvmLaunchCompletionReceiptSha256(receipt, {
    expectedAuthority,
  });
  const planCreatedAt = Math.floor(
    Date.parse(runtimeBinding.activation_plan_created_at) / 1_000,
  );
  const mainTarget = runtimeBinding.main_runtime_target;
  if (receiptSha256
      !== runtimeBinding.seven_cvm_launch_completion_receipt_sha256
    || receipt.release_sha !== runtimeBinding.release_sha
    || receipt.release_sha !== executor.release_sha
    || receipt.deployment_intent_sha256
      !== runtimeBinding.deployment_intent_sha256
    || receipt.cvm_launch_intent_sha256
      !== runtimeBinding.cvm_launch_intent_sha256
    || receipt.cvm_launch_intent_sha256 !== executor.launch_intent_sha256
    || receipt.batch_id !== runtimeBinding.batch_id
    || receipt.batch_id !== executor.batch_id
    || receipt.batch_id !== bootstrap.batch_id
    || receipt.nonlive_bootstrap_authorization_receipt_sha256
      !== bootstrap.receipt_sha256
    || receipt.nonlive_bootstrap_authorization_receipt_sha256
      !== executor.bootstrap_authorization_receipt_sha256
    || receipt.bootstrap_authorization_id !== bootstrap.authorization_id
    || receipt.bootstrap_authorization_id !== executor.bootstrap_authorization_id
    || receipt.production_target_authority_sha256
      !== executor.target_authority_sha256
    || receipt.phala_recovery_directory_identity_anchor_sha256
      !== executor.phala_recovery_directory_identity_anchor_sha256
    || receipt.phala_recovery_directory_identity_anchor_sha256
      !== runtimeBinding.phala_recovery_directory_identity_anchor_sha256
    || receipt.machine_verifier_evidence_set_sha256
      !== runtimeBinding.seven_cvm_verified_evidence_set_sha256
    || receipt.release_verification_authority_sha256
      !== runtimeBinding.release_verification_authority_sha256
    || receipt.completed_at > planCreatedAt
    || receipt.activation_evidence_lease_expires_at
      !== runtimeBinding.activation_evidence_lease_expires_at
    || receipt.completed_at
      >= runtimeBinding.activation_evidence_lease_expires_at
    || mainTarget.descriptor_sha256 !== main.descriptor_sha256
    || mainTarget.app_id !== main.app_id
    || mainTarget.cvm_id !== main.cvm_id
    || mainTarget.compose_hash !== main.committed_compose_hash
    || mainTarget.os_image_hash !== main.os_image_hash) {
    throw new TypeError(
      "persisted L, executor, R, plan, release authority, or historical signed-A binding drifted",
    );
  }
  const executorReservations = new Map(
    executor.reservations.map((entry) => [entry.domain, entry]),
  );
  const executorPreparations = new Map(
    executor.preparations.map((entry) => [entry.domain, entry]),
  );
  const executorCommits = new Map(
    executor.committed_prefix.map((entry) => [entry.domain, entry]),
  );
  const executorPostures = new Map(
    executor.posture_receipts.map((entry) => [entry.domain, entry]),
  );
  for (const domain of PHALA_EXECUTION_ORDER) {
    const completion = domains[domain];
    const reservation = executorReservations.get(domain);
    const preparation = executorPreparations.get(domain);
    const commit = executorCommits.get(domain);
    const posture = executorPostures.get(domain);
    if (!reservation || !preparation || !commit || !posture
      || reservation.app_id !== completion.app_id
      || preparation.attempted_at !== completion.provision_attempted_at
      || preparation.observed_at !== completion.provision_observed_at
      || preparation.observation_sha256
        !== completion.provision_observation_sha256
      || commit.cvm_id !== completion.cvm_id
      || commit.attempted_at !== completion.commit_attempted_at
      || commit.observed_at !== completion.commit_observed_at
      || commit.observation_sha256 !== completion.commit_observation_sha256
      || posture.receipt_sha256
        !== completion.production_posture_verification_receipt_sha256) {
      throw new TypeError(
        `${domain} persisted executor differs from historical L completion`,
      );
    }
  }
  return deepFreezeCanonicalPlainDataGraph({
    receipt,
    receipt_sha256: receiptSha256,
    executor_final_state: executor,
    executor_final_state_sha256: phalaExecutorStateDigest(executor),
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256:
      runtimeBinding.release_verification_authority_sha256,
    truth_status:
      "historical_signed_dependency_reconstructed_with_exact_release_resources_without_refreshing_machine_or_posture_freshness",
    freshness_renewed: false,
    production_brand_minted: false,
    live_traffic_authorized: false,
  }, { label: "historical seven-CVM completion reconstruction" });
}
