import { createHash } from "node:crypto";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  PHALA_QVL_IDENTITY_DOMAIN_PROFILE,
  PHALA_SEVEN_CVM_EXECUTION_ORDER,
  PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
  PhalaWorkloadVerdictChallengeLedger,
  createPhalaQvlIdentityChallenge,
  createPhalaSevenCvmVerifiedEvidenceSet,
  independentTdxVerdictSigningDigest,
  phalaComputeWorkloadRecipientReportData,
  phalaQvlIdentityReportData,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  phalaWorkloadTdxVerdictVerificationSha256,
  qvlChallengeSigningDigest,
  verifyPhalaComputeWorkloadRecipientActivation,
  verifyPhalaQvlIdentityLaunchEvidence,
  verifyPhalaWorkloadIndependentTdxVerdict,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  PHALA_QVL_MEASUREMENT_POLICY_SCHEMA,
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";

export const SYNTHETIC_PHALA_SEVEN_CVM_VERIFIER_EVIDENCE_TRUTH =
  "synthetic_node_test_fixture_never_live_release_authority";

const NOW = 2_000_000_000;
const CHAIN_ID = 84_532;
const MEASUREMENT_DOMAIN = "dnai-wikigen/tdx-measurements/v1\0";
const COMPUTE_REPORT_DATA_DOMAIN =
  "dnai-wikigen/compute-metering-signer-attestation/v1\0";
const COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-release/v2\0";
const QVL_CHALLENGE_DOMAIN = "dnai-wikigen/attestation-qvl/challenge/v2\0";

const hex = (index) => index.toString(16).padStart(2, "0");
const bare = (index) => hex(index).repeat(32);
const word = (index) => `0x${bare(index)}`;
const sha = (index) => `sha256:${bare(index)}`;
const address = (index) => `0x${index.toString(16).padStart(40, "0")}`;
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
  );
};
const compact = (value) => JSON.stringify(canonical(value));
const canonicalText = (value) => `${JSON.stringify(canonical(value), null, 2)}\n`;

function measurements(seed) {
  const fields = {
    tee_tcb_svn: hex(seed).repeat(16),
    mr_seam: hex(seed + 1).repeat(48),
    mr_signer_seam: hex(seed + 2).repeat(48),
    seam_attributes: hex(seed + 3).repeat(8),
    td_attributes: hex(seed + 4).repeat(8),
    xfam: hex(seed + 5).repeat(8),
    mr_td: hex(seed + 6).repeat(48),
    mr_config_id: hex(seed + 7).repeat(48),
    mr_owner: hex(seed + 8).repeat(48),
    mr_owner_config: hex(seed + 9).repeat(48),
    rt_mr0: hex(seed + 10).repeat(48),
    rt_mr1: hex(seed + 11).repeat(48),
    rt_mr2: hex(seed + 12).repeat(48),
    rt_mr3: hex(seed + 13).repeat(48),
  };
  return {
    fields,
    sha256: `sha256:${createHash("sha256")
      .update(MEASUREMENT_DOMAIN, "utf8")
      .update(compact(fields), "ascii")
      .digest("hex")}`,
  };
}

function measurementPolicy(domain, index, deploymentIntent, measure) {
  return {
    schema: PHALA_QVL_MEASUREMENT_POLICY_SCHEMA,
    domain,
    profile: PHALA_QVL_IDENTITY_DOMAIN_PROFILE[domain],
    deployment_intent_sha256: deploymentIntent,
    reference_id: `${domain.replaceAll("_", "-")}-reference-v1`,
    mr_td: measure.fields.mr_td,
    mr_config_id: measure.fields.mr_config_id,
    mr_owner: measure.fields.mr_owner,
    mr_owner_config: measure.fields.mr_owner_config,
    rt_mr0: measure.fields.rt_mr0,
    rt_mr1: measure.fields.rt_mr1,
    rt_mr2: measure.fields.rt_mr2,
    rt_mr3: measure.fields.rt_mr3,
    td_attributes: measure.fields.td_attributes,
    td_attributes_required_mask: "00".repeat(8),
    td_attributes_forbidden_mask: "01" + "00".repeat(7),
    xfam: measure.fields.xfam,
    xfam_required_mask: "00".repeat(8),
    xfam_forbidden_mask: "00".repeat(8),
  };
}

function descriptor(domain, index) {
  if (domain === "main_runtime_cvm") {
    return {
      domain,
      descriptor_sha256: sha(10),
      app_id: hex(60).repeat(20),
      cvm_id: "cvm-workload-01",
      compose_hash: bare(80),
      os_image_hash: bare(100),
      posture_receipt_sha256: sha(110),
      posture_observed_at: new Date((NOW - 10) * 1_000).toISOString().replace(".000", ""),
      kms_id: "kms-synthetic-01",
      instance_type: "tdx.large",
      disk_size: 40,
    };
  }
  if (domain === "independent_metering_cvm") {
    return {
      domain,
      descriptor_sha256: sha(16),
      app_id: hex(61).repeat(20),
      cvm_id: "cvm-workload-02",
      compose_hash: bare(81),
      os_image_hash: bare(101),
      posture_receipt_sha256: sha(116),
      posture_observed_at: new Date((NOW - 10) * 1_000).toISOString().replace(".000", ""),
      kms_id: "kms-synthetic-01",
      instance_type: "tdx.small",
      disk_size: 20,
    };
  }
  const qvlIndex = Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).indexOf(domain);
  return {
    domain,
    descriptor_sha256: sha(11 + qvlIndex),
    app_id: hex(50 + qvlIndex).repeat(20),
    cvm_id: `cvm-verifier-${String(qvlIndex + 1).padStart(2, "0")}`,
    compose_hash: bare(70 + qvlIndex),
    os_image_hash: bare(90 + qvlIndex),
    posture_receipt_sha256: sha(111 + qvlIndex),
    posture_observed_at: new Date((NOW - 10) * 1_000).toISOString().replace(".000", ""),
    kms_id: "kms-synthetic-01",
    instance_type: "tdx.small",
    disk_size: 20,
  };
}

function syntheticReleaseAuthority(measureByDomain) {
  const deploymentIntent = sha(200);
  const policies = Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).map((domain, index) =>
    measurementPolicy(domain, index, deploymentIntent, measureByDomain.get(domain)));
  return syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
    releaseSha: "ab".repeat(20),
    deploymentIntentSha256: deploymentIntent,
    bootstrapAuthorizationReceiptSha256: sha(201),
    ceremonyNonce: word(202),
    freshContractDeploymentReceiptSha256: sha(241),
    diligenceRoom: address(500),
    computeCreditVault: address(501),
    computeCreditVaultRuntimeCodeHash: word(240),
    qvlMeasurementPolicies: policies,
    releaseDescriptors: PHALA_SEVEN_CVM_EXECUTION_ORDER.map(descriptor),
  });
}

function qvlIdentityFixture(domain, index, verifierAddress, releaseAuthority, measure) {
  const request = createPhalaQvlIdentityChallenge({
    domain,
    releaseAuthority,
    ttlSeconds: 90,
    testOnlyNow: NOW,
    testOnlyChallengeIdBytes: Buffer.from(hex(110 + index).repeat(32), "hex"),
  });
  const releasePolicyHash = word(30 + index);
  const reportData = phalaQvlIdentityReportData({
    request,
    verifierAddress,
    releasePolicyHash,
  });
  const quoteReportData = `${reportData}${request.challenge_digest.slice(2)}`;
  const quote = Buffer.alloc(1_024, 130 + index);
  const response = {
    schema: "dnai.qvl-identity-attestation-response.v3",
    chain_id: CHAIN_ID,
    domain,
    profile: request.profile,
    cvm_id: request.cvm_id,
    deployment_intent_sha256: request.deployment_intent_sha256,
    release_authority_sha256: request.release_authority_sha256,
    ceremony_nonce: request.ceremony_nonce,
    measurement_policy_sha256: request.measurement_policy_sha256,
    verifier_address: verifierAddress,
    release_policy_hash: releasePolicyHash,
    report_data: reportData,
    quote_report_data: quoteReportData,
    challenge_id: request.challenge_id,
    challenge_digest: request.challenge_digest,
    challenge_issued_at: request.issued_at,
    challenge_expires_at: request.expires_at,
    quote: `0x${quote.toString("hex")}`,
    quote_hash: `0x${createHash("sha256").update(quote).digest("hex")}`,
    quote_size: quote.length,
    app_id: request.app_id,
    compose_hash: request.compose_hash,
    os_image_hash: request.os_image_hash,
    raw_secret_egress: false,
  };
  return {
    domain,
    releaseAuthority,
    request,
    response,
    rawRequestText: canonicalText(request),
    rawResponseText: canonicalText(response),
    testOnlyNow: NOW,
    testOnlyVerifyQuote: async (_quote, policy) => {
      if (phalaQvlMeasurementPolicySha256(policy) !== request.measurement_policy_sha256) {
        throw new Error("fixture received the wrong measurement policy");
      }
      return {
        verified: true,
        quote_type: "TDX",
        status: "OK",
        debug: false,
        report_data: quoteReportData,
        measurements: measure.fields,
        measurements_sha256: measure.sha256,
        measurement_policy_sha256: request.measurement_policy_sha256,
        measurement_policy_reference_id: policy.reference_id,
        measurement_policy_matched: true,
        collateral_source: "https://pccs.phala.network",
        runtime_environment_sha256:
          PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
      };
    },
  };
}

function diligenceReportData(teeIdentity, contractAddress) {
  return `0x${createHash("sha256").update(compact({
    service: "dnai-wikigen",
    context: "diligence-room-submit-result",
    signer_address: teeIdentity,
    chain_id: CHAIN_ID,
    contract_address: contractAddress,
  }), "utf8").digest("hex")}`;
}

function computeReportData(teeIdentity, contractAddress, policySetHash) {
  return `0x${createHash("sha256")
    .update(COMPUTE_REPORT_DATA_DOMAIN, "utf8")
    .update(compact({
      schema: "dnai.compute-metering-signer-attestation.v1",
      chain_id: CHAIN_ID,
      vault_address: contractAddress,
      metering_verifier: teeIdentity,
      policy_set_hash: policySetHash,
      signer_custody: "dstack_derived_independent_cvm",
    }), "ascii")
    .digest("hex")}`;
}

async function signedWorkloadVerdict({
  domain,
  index,
  qvlAccount,
  qvlIdentity,
  workloadAccount,
  releaseAuthority,
  reportDataBinding,
}) {
  const target = releaseAuthority.descriptors.find((entry) => entry.domain === domain);
  const contractAddress = domain === "main_runtime_cvm"
    ? releaseAuthority.contracts.diligence_room
    : releaseAuthority.contracts.compute_credit_vault;
  const reportData = domain === "main_runtime_cvm"
    ? diligenceReportData(workloadAccount.address.toLowerCase(), contractAddress)
    : computeReportData(
      workloadAccount.address.toLowerCase(),
      contractAddress,
      reportDataBinding.policy_set_hash,
    );
  const lineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: domain === "main_runtime_cvm" ? "diligence" : "compute_metering",
    cvm_id: target.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: qvlIdentity.measurement_policy_sha256,
  };
  const challenge = {
    schema: "dnai.attestation-qvl-challenge.v2",
    ...lineage,
    release_policy_hash: `0x${qvlIdentity.release_policy_sha256.slice(7)}`,
    challenge_id: word(180 + index),
    issued_at: NOW - 2,
    expires_at: NOW + 60,
    verifier_address: qvlAccount.address.toLowerCase(),
    challenge_digest: word(182 + index),
    verifier_signature: `0x${"00".repeat(64)}1b`,
  };
  challenge.challenge_digest = qvlChallengeSigningDigest(challenge);
  challenge.verifier_signature = (await qvlAccount.signMessage({
    message: { raw: challenge.challenge_digest },
  })).toLowerCase();
  const verdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    ...lineage,
    release_policy_hash: challenge.release_policy_hash,
    challenge_id: challenge.challenge_id,
    challenge_digest: challenge.challenge_digest,
    challenge_issued_at: challenge.issued_at,
    challenge_expires_at: challenge.expires_at,
    quote_hash: word(184 + index),
    report_data: reportData,
    compose_hash: `0x${target.compose_hash}`,
    app_id: target.app_id,
    os_image_hash: target.os_image_hash,
    signer_address: workloadAccount.address.toLowerCase(),
    contract_address: contractAddress,
    issued_at: NOW - 1,
    activation_evidence_lease_expires_at: NOW + 899,
    expires_at: NOW + 899,
    verifier_address: qvlAccount.address.toLowerCase(),
    verifier_signature: `0x${"00".repeat(64)}1b`,
  };
  const digest = independentTdxVerdictSigningDigest(verdict);
  verdict.verifier_signature = (await qvlAccount.signMessage({
    message: { raw: digest },
  })).toLowerCase();
  return {
    challenge,
    verdict,
    rawChallengeText: canonicalText(challenge),
    rawVerdictText: canonicalText(verdict),
    expected: { reportDataBinding },
  };
}

function activationChallengeDigest(verdict) {
  const payload = {
    schema: "dnai.attestation-qvl-challenge.v2",
    chain_id: CHAIN_ID,
    domain: verdict.domain,
    profile: verdict.profile,
    cvm_id: verdict.cvm_id,
    deployment_intent_sha256: verdict.deployment_intent_sha256,
    release_authority_sha256: verdict.release_authority_sha256,
    ceremony_nonce: verdict.ceremony_nonce,
    measurement_policy_sha256: verdict.measurement_policy_sha256,
    release_policy_hash: verdict.release_policy_hash,
    challenge_id: verdict.challenge_id,
    issued_at: verdict.challenge_issued_at,
    expires_at: verdict.challenge_expires_at,
    verifier_address: verdict.verifier_address,
  };
  return `0x${createHash("sha256")
    .update(QVL_CHALLENGE_DOMAIN, "utf8")
    .update(compact(payload), "ascii")
    .digest("hex")}`;
}

export async function syntheticPhalaSevenCvmVerifierEvidenceFixture() {
  const qvlDomains = Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE);
  const measureByDomain = new Map(qvlDomains.map((domain, index) => [
    domain,
    measurements(10 + index * 20),
  ]));
  const releaseAuthority = syntheticReleaseAuthority(measureByDomain);
  const qvlPrivateKeys = [0x11, 0x22, 0x33, 0x44, 0x45].map((byte) =>
    `0x${byte.toString(16).padStart(2, "0").repeat(32)}`);
  const qvlAccounts = qvlPrivateKeys.map((key) => privateKeyToAccount(key));
  const qvlAccountByDomain = new Map(
    qvlDomains.map((domain, index) => [domain, qvlAccounts[index]]),
  );
  const workloadAccounts = [0x55, 0x66].map((byte) =>
    privateKeyToAccount(`0x${byte.toString(16).repeat(32)}`));
  const qvlRawInputs = qvlDomains.map((domain, index) => qvlIdentityFixture(
    domain,
    index,
    qvlAccounts[index].address.toLowerCase(),
    releaseAuthority,
    measureByDomain.get(domain),
  ));
  const qvlIdentityEvidence = [];
  for (const input of qvlRawInputs) {
    qvlIdentityEvidence.push(await verifyPhalaQvlIdentityLaunchEvidence({
      ...input,
      ledger: new PhalaWorkloadVerdictChallengeLedger(8),
    }));
  }
  const diligenceIdentity = qvlIdentityEvidence.find((entry) =>
    entry.domain === "diligence_qvl_cvm");
  const computeMeteringIdentity = qvlIdentityEvidence.find((entry) =>
    entry.domain === "compute_metering_qvl_cvm");
  const mainRaw = await signedWorkloadVerdict({
    domain: "main_runtime_cvm",
    index: 0,
    qvlAccount: qvlAccountByDomain.get("diligence_qvl_cvm"),
    qvlIdentity: diligenceIdentity,
    workloadAccount: workloadAccounts[0],
    releaseAuthority,
    reportDataBinding: { kind: "diligence_result_signer_v1" },
  });
  const meterRaw = await signedWorkloadVerdict({
    domain: "independent_metering_cvm",
    index: 1,
    qvlAccount: qvlAccountByDomain.get("compute_metering_qvl_cvm"),
    qvlIdentity: computeMeteringIdentity,
    workloadAccount: workloadAccounts[1],
    releaseAuthority,
    reportDataBinding: {
      kind: "compute_metering_signer_v1",
      policy_set_hash: word(210),
      signer_custody: "dstack_derived_independent_cvm",
    },
  });
  const workloadVerdictEvidence = [
    verifyPhalaWorkloadIndependentTdxVerdict({
      domain: "main_runtime_cvm",
      releaseAuthority,
      ...mainRaw,
      qvlIdentityEvidence: diligenceIdentity,
      challengeLedger: new PhalaWorkloadVerdictChallengeLedger(4),
      testOnlyNow: NOW,
    }),
    verifyPhalaWorkloadIndependentTdxVerdict({
      domain: "independent_metering_cvm",
      releaseAuthority,
      ...meterRaw,
      qvlIdentityEvidence: computeMeteringIdentity,
      challengeLedger: new PhalaWorkloadVerdictChallengeLedger(4),
      testOnlyNow: NOW,
    }),
  ];
  const evidenceSet = createPhalaSevenCvmVerifiedEvidenceSet({
    releaseAuthority,
    qvlIdentityEvidence,
    workloadVerdictEvidence,
    testOnlyNow: NOW,
  });
  const mainProof = workloadVerdictEvidence[0];
  const computeWorkloadIdentity = qvlIdentityEvidence.find((entry) =>
    entry.domain === "compute_workload_qvl_cvm");
  const activationAccount = privateKeyToAccount(`0x${"77".repeat(32)}`);
  const encryptionPublicKey = bare(230);
  const recipientKeyId = `sha256:${createHash("sha256")
    .update(Buffer.from(encryptionPublicKey, "hex"))
    .digest("hex")}`;
  const recipientAttestation = {
    schema: "dnai.compute-workload-recipient-attestation.v1",
    context: "compute_workload",
    audience: "dnai-wikigen:compute-workload-recipient",
    service: "dnai-wikigen",
    protocol: "compute_workload_ingress_v1",
    encryption_public_key: encryptionPublicKey,
    key_id: recipientKeyId,
    activation_signer_address: activationAccount.address.toLowerCase(),
    activation_signer_key_path: "tinker/compute_workload_activation_signer",
    activation_signer_custody: "dstack_derived_compute_workload_activation_signer",
    chain_id: CHAIN_ID,
    compute_vault_address: releaseAuthority.contracts.compute_credit_vault,
    compute_vault_runtime_code_hash:
      releaseAuthority.contracts.compute_credit_vault_runtime_code_hash,
    fresh_contract_deployment_receipt_sha256:
      `0x${releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256.slice(7)}`,
  };
  const recipientReportData = phalaComputeWorkloadRecipientReportData(recipientAttestation);
  const mainDescriptor = releaseAuthority.descriptors[0];
  const lineage = {
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: mainDescriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: computeWorkloadIdentity.measurement_policy_sha256,
  };
  const activationVerdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    ...lineage,
    release_policy_hash: `0x${computeWorkloadIdentity.release_policy_sha256.slice(7)}`,
    challenge_id: word(232),
    challenge_digest: word(234),
    challenge_issued_at: NOW - 2,
    challenge_expires_at: NOW + 60,
    quote_hash: word(233),
    report_data: recipientReportData,
    compose_hash: `0x${mainDescriptor.compose_hash}`,
    app_id: mainDescriptor.app_id,
    os_image_hash: mainDescriptor.os_image_hash,
    signer_address: activationAccount.address.toLowerCase(),
    contract_address: recipientAttestation.compute_vault_address,
    issued_at: NOW - 1,
    activation_evidence_lease_expires_at: NOW + 299,
    expires_at: NOW + 299,
    verifier_address: qvlAccountByDomain.get("compute_workload_qvl_cvm").address.toLowerCase(),
    verifier_signature: `0x${"00".repeat(64)}1b`,
  };
  activationVerdict.challenge_digest = activationChallengeDigest(activationVerdict);
  const activationVerdictDigest = independentTdxVerdictSigningDigest(activationVerdict);
  activationVerdict.verifier_signature = (await qvlAccountByDomain
    .get("compute_workload_qvl_cvm").signMessage({
      message: { raw: activationVerdictDigest },
    })).toLowerCase();
  const activationBase = {
    schema: "dnai.compute.workload-recipient-activation.v3",
    ...lineage,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    main_runtime_evidence_sha256: phalaWorkloadTdxVerdictVerificationSha256(mainProof),
    recipient_key_id: recipientKeyId,
    report_data: recipientReportData,
    compose_hash: activationVerdict.compose_hash,
    app_id: activationVerdict.app_id,
    os_image_hash: activationVerdict.os_image_hash,
    release_policy_hash: activationVerdict.release_policy_hash,
    quote_hash: activationVerdict.quote_hash,
    verifier_address: activationVerdict.verifier_address,
    verdict_digest: activationVerdictDigest,
    issued_at: activationVerdict.issued_at,
    recipient_evidence_lease_expires_at: activationVerdict.expires_at,
    expires_at: activationVerdict.expires_at,
    authenticated_at: NOW,
    recipient_attestation: recipientAttestation,
    authenticated_verdict: activationVerdict,
  };
  const releasePayload = {
    schema: "dnai.compute.workload-recipient-release.v2",
    chain_id: CHAIN_ID,
    domain: activationBase.domain,
    profile: "compute_workload",
    cvm_id: activationBase.cvm_id,
    deployment_intent_sha256: activationBase.deployment_intent_sha256,
    release_authority_sha256: activationBase.release_authority_sha256,
    ceremony_nonce: activationBase.ceremony_nonce,
    measurement_policy_set_sha256: activationBase.measurement_policy_set_sha256,
    measurement_policy_sha256: activationBase.measurement_policy_sha256,
    main_runtime_evidence_sha256: activationBase.main_runtime_evidence_sha256,
    recipient_key_id: recipientKeyId,
    report_data: recipientReportData,
    compose_hash: activationVerdict.compose_hash,
    app_id: activationVerdict.app_id,
    os_image_hash: activationVerdict.os_image_hash,
    release_policy_hash: activationVerdict.release_policy_hash,
    verifier_address: activationVerdict.verifier_address,
    verification_method: activationVerdict.verification_method,
    signer_address: activationVerdict.signer_address,
    contract_address: activationVerdict.contract_address,
    recipient_attestation: recipientAttestation,
  };
  const activation = {
    ...activationBase,
    recipient_release_commitment: `sha256:${createHash("sha256")
      .update(COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN, "utf8")
      .update(compact(releasePayload), "ascii")
      .digest("hex")}`,
  };
  const computeWorkloadActivationEvidence = verifyPhalaComputeWorkloadRecipientActivation({
    activation,
    releaseAuthority,
    qvlIdentityEvidence: computeWorkloadIdentity,
    mainRuntimeEvidence: mainProof,
    challengeLedger: new PhalaWorkloadVerdictChallengeLedger(4),
    testOnlyNow: NOW,
  });
  if (evidenceSet.schema !== PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA
    || evidenceSet.evidence_mode !== PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    throw new Error("synthetic seven-CVM verifier fixture crossed the production truth boundary");
  }
  return {
    truth_status: SYNTHETIC_PHALA_SEVEN_CVM_VERIFIER_EVIDENCE_TRUTH,
    now: NOW,
    releaseAuthority,
    qvlRawInputs,
    qvlIdentityEvidence,
    workloadRawInputs: [mainRaw, meterRaw],
    workloadVerdictEvidence,
    evidenceSet,
    computeWorkloadActivationRaw: activation,
    computeWorkloadActivationEvidence,
  };
}
