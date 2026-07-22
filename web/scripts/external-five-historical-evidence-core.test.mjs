import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { privateKeyToAccount } from "viem/accounts";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

import {
  EXTERNAL_FIVE_EVIDENCE_FLAGS,
  EXTERNAL_FIVE_HISTORICAL_EVIDENCE_STATUS,
  projectExternalFiveEvidenceFilesFromExact37ByKey,
  projectExternalFiveHistoricalQvlAuthority,
  validateExternalFiveHistoricalEvidenceBoundary,
} from "./external-five-historical-evidence-core.mjs";

const NOW = 2_000_000;
const MAX_PROTOCOL_SECOND = 4_102_444_800;
const RELEASE = "ab".repeat(20);
const pin = (byte) => `sha256:${byte.repeat(32)}`;
const word = (byte) => `0x${byte.repeat(32)}`;
const address = (byte) => `0x${byte.repeat(20)}`;
const B = pin("11");
const R = pin("12");
const O = pin("13");
const C = pin("14");
const D = pin("15");
const D_INPUTS = pin("16");
const RELEASE_AUTHORITY = pin("17");
const CEREMONY_NONCE = word("18");
const DEPLOYMENT_INTENT = pin("19");
const REVIEWER_ACCEPTANCE = pin("1a");
const APP_ID = "1b".repeat(20);
const CVM_ID = "cvm_external_five_release";
const COMPOSE = "1c".repeat(32);
const LOCAL_COMPOSE = "1d".repeat(32);
const RENDERED_COMPOSE = "1e".repeat(32);
const OS_IMAGE = "1f".repeat(32);
const OPERATOR = address("20");
const TEE = address("21");
const DILIGENCE = address("22");
const CHALLENGE = address("23");
const ROYALTY = address("24");
const TINKER = address("25");
const COMPUTE = address("26");
const EMAIL = address("27");
const RESULT_VERIFIER = address("28");
const COMPUTE_DEVELOPER = address("29");
const METERING_VERIFIER = address("2a");
const ANCHOR = address("2b");
const WRITER = address("2c");
const KMS = address("2d");
const KMS_IMPLEMENTATION = address("2e");
const BOOT_INSTANCE = address("2f");
const DEVICE_ID = word("30");
const KMS_REGISTRATION_TX = word("31");
const KMS_REGISTRATION_BLOCK_HASH = word("32");
const KMS_REGISTRATION_BLOCK = 1_900_000;
const RESTART_PROOF = word("33");
const RESTART_COMMITMENT = word("34");
const WRITER_COMMITMENT = word("35");
const IMAGE = {
  service: "delegate",
  image: `ghcr.io/therealwiki/dnai-wikigen/tinker-delegate@sha256:${"36".repeat(32)}`,
  repo: "therealwiki/dnai-wikigen",
  signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
  source_digest: RELEASE,
  source_ref: "refs/heads/main",
  provenance_attestation: "verified",
  sbom_attestation: "verified",
};
const VERDICT_DOMAIN = Buffer.from(
  "dnai-wikigen/independent-tdx-verdict/v4\0",
  "utf8",
);
const V3_VERDICT_DOMAIN = Buffer.from(
  "dnai-wikigen/independent-tdx-verdict/v3\0",
  "utf8",
);
const ANCHOR_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0",
  "utf8",
);
const ANCHOR_KEY_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-key-path/v1\0",
  "utf8",
);
const EMAIL_DOMAIN = Buffer.from(
  "dnai-wikigen/email-oracle-kms-restart-attestation/v1\0",
  "utf8",
);

function canonicalJson(value) {
  const normalize = (entry) => {
    if (Array.isArray(entry)) return entry.map(normalize);
    if (entry && typeof entry === "object") {
      return Object.fromEntries(
        Object.keys(entry).sort().map((key) => [key, normalize(entry[key])]),
      );
    }
    return entry;
  };
  return JSON.stringify(normalize(value));
}

function prettyBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function domainHash(domain, payload) {
  return `0x${createHash("sha256")
    .update(domain)
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function verdictDigest(
  verdict,
  signingDomain = VERDICT_DOMAIN,
  { includeActivationEvidenceLease = true } = {},
) {
  const fields = [
    "activation_evidence_lease_expires_at",
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at",
    "compose_hash", "contract_address", "cvm_id",
    "deployment_intent_sha256", "domain", "expires_at", "issued_at",
    "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "release_policy_hash", "report_data", "release_authority_sha256",
    "schema", "signer_address", "verification_method", "verified",
    "verifier_address",
  ].filter((key) => includeActivationEvidenceLease
    || key !== "activation_evidence_lease_expires_at");
  const payload = Object.fromEntries(fields
    .map((key) => [key, verdict[key]])
    .sort(([left], [right]) => left.localeCompare(right)));
  return `0x${createHash("sha256")
    .update(signingDomain)
    .update(Buffer.from(JSON.stringify(payload), "utf8"))
    .digest("hex")}`;
}

function recoverIndependentEip191PersonalSigner({ digest, signature }) {
  const message = Buffer.from(digest.slice(2), "hex");
  const personalHash = keccak_256(Buffer.concat([
    Buffer.from("\x19Ethereum Signed Message:\n32", "binary"),
    message,
  ]));
  const rawSignature = Buffer.from(signature.slice(2), "hex");
  const recovered = secp256k1.Signature
    .fromCompact(rawSignature.subarray(0, 64))
    .addRecoveryBit(rawSignature[64] - 27)
    .recoverPublicKey(personalHash)
    .toRawBytes(false);
  return `0x${Buffer.from(keccak_256(recovered.subarray(1))).subarray(12).toString("hex")}`;
}

async function signedVerdict({
  account,
  context,
  profile,
  contract,
  signer,
  qvlPolicy,
  measurementPolicy,
  reportData,
  quoteByte,
  schema = "dnai.independent-tdx-verdict.v4",
  signingDomain = VERDICT_DOMAIN,
  challengeIssuedAt = NOW - 100,
  challengeExpiresAt = NOW - 5,
  issuedAt = NOW - 10,
  activationEvidenceLeaseExpiresAt = NOW + 890,
  expiresAt = activationEvidenceLeaseExpiresAt,
}) {
  const verdict = {
    schema,
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    chain_id: 84_532,
    domain: "main_runtime_cvm",
    profile,
    cvm_id: CVM_ID,
    deployment_intent_sha256: DEPLOYMENT_INTENT,
    release_authority_sha256: RELEASE_AUTHORITY,
    ceremony_nonce: CEREMONY_NONCE,
    measurement_policy_sha256: measurementPolicy,
    release_policy_hash: qvlPolicy,
    challenge_id: word(quoteByte),
    challenge_digest: word(String(Number.parseInt(quoteByte, 16) + 1).padStart(2, "0")),
    challenge_issued_at: challengeIssuedAt,
    challenge_expires_at: challengeExpiresAt,
    quote_hash: word(String(Number.parseInt(quoteByte, 16) + 2).padStart(2, "0")),
    report_data: reportData,
    compose_hash: `0x${COMPOSE}`,
    app_id: APP_ID,
    os_image_hash: OS_IMAGE,
    signer_address: signer,
    contract_address: contract,
    issued_at: issuedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    expires_at: expiresAt,
    verifier_address: account.address.toLowerCase(),
    verifier_signature: "",
  };
  verdict.verifier_signature = await account.signMessage({
    message: { raw: verdictDigest(verdict, signingDomain) },
  });
  return {
    context,
    quote_sha256: `sha256:${verdict.quote_hash.slice(2)}`,
    verdict,
  };
}

function file(flag, value) {
  const bytes = prettyBytes(value);
  return { flag, byteLength: bytes.length, rawSha256: sha256(bytes), value };
}

async function fixture() {
  const accounts = [1, 2, 3, 4, 5].map((value) => privateKeyToAccount(
    `0x${value.toString(16).padStart(64, "0")}`,
  ));
  const qvlPolicies = ["40", "41", "42", "43", "44"].map(word);
  const qvlMeasurements = ["80", "81", "82", "83", "84"].map(pin);
  const emailBinding = {
    kind: "email_oracle_kms_restart_v1",
    email_oracle_auth_runtime_code_hash: word("45"),
    kms_eip1967_implementation_slot_word:
      `0x${"0".repeat(24)}${KMS_IMPLEMENTATION.slice(2)}`,
    kms_implementation_address: KMS_IMPLEMENTATION,
    kms_implementation_runtime_code_hash: word("46"),
    kms_proxy_address: KMS,
    kms_proxy_runtime_code_hash: word("47"),
    registration_block_hash: KMS_REGISTRATION_BLOCK_HASH,
    registration_block_number: KMS_REGISTRATION_BLOCK,
    registration_tx_hash: KMS_REGISTRATION_TX,
    restart_proof_hash: RESTART_PROOF,
    target_boot_tuple_hash: word("48"),
  };
  const anchorReportData = domainHash(ANCHOR_DOMAIN, {
    schema: "dnai.execution-policy-anchor-writer-qvl-evidence.v1",
    chain_id: 84_532,
    anchor_address: ANCHOR,
    writer_address: WRITER,
    writer_release_commitment: WRITER_COMMITMENT,
    writer_key_path: "tinker/execution_policy_anchor_writer",
    writer_custody: "dstack_derived_execution_policy_anchor_writer",
  });
  const emailReportData = domainHash(EMAIL_DOMAIN, {
    schema: "dnai.email-oracle-kms-restart-attestation.v1",
    chain_id: 84_532,
    main_cvm_signer: TEE,
    ...Object.fromEntries(Object.entries(emailBinding).filter(([key]) => key !== "kind")),
  });
  const artifactVerdict = await signedVerdict({
    account: accounts[0], context: "artifact", profile: "diligence",
    contract: DILIGENCE, signer: TEE, qvlPolicy: qvlPolicies[0],
    measurementPolicy: qvlMeasurements[0], reportData: word("50"),
    quoteByte: "51",
  });
  const arenaVerdict = await signedVerdict({
    account: accounts[1], context: "arena", profile: "arena",
    contract: CHALLENGE, signer: TEE, qvlPolicy: qvlPolicies[1],
    measurementPolicy: qvlMeasurements[1], reportData: word("52"),
    quoteByte: "53",
  });
  const anchorVerdict = await signedVerdict({
    account: accounts[2], context: "anchor_writer",
    profile: "execution_policy_anchor_writer", contract: ANCHOR,
    signer: WRITER, qvlPolicy: qvlPolicies[2],
    measurementPolicy: qvlMeasurements[2], reportData: anchorReportData,
    quoteByte: "54",
  });
  const emailVerdict = await signedVerdict({
    account: accounts[0], context: "email_oracle_kms_restart",
    profile: "email_oracle_kms_restart", contract: DILIGENCE,
    signer: TEE, qvlPolicy: qvlPolicies[0],
    measurementPolicy: qvlMeasurements[0], reportData: emailReportData,
    quoteByte: "55",
  });
  const runtimeHashes = Object.fromEntries([
    "diligence_room", "challenge_registry", "royalty_distributor",
    "tinker_account_encumbrance", "compute_credit_vault", "email_oracle_auth",
  ].map((key, index) => [key, word((60 + index).toString(16))]));
  const candidate = {
    release_sha: RELEASE,
    deployment_intent_sha256: DEPLOYMENT_INTENT,
    operator_address: OPERATOR,
    operator_policy: {
      ceremony_authorization_sha256: B,
      runtime_authority_dependency_sha256: R,
      live_activation_authority_sha256: C,
    },
    contracts: {
      diligence_room: {
        address: DILIGENCE,
        runtime_code_hash: runtimeHashes.diligence_room,
        result_verifier: RESULT_VERIFIER,
      },
      challenge_registry: {
        address: CHALLENGE,
        runtime_code_hash: runtimeHashes.challenge_registry,
      },
      royalty_distributor: {
        address: ROYALTY,
        runtime_code_hash: runtimeHashes.royalty_distributor,
      },
      tinker_account_encumbrance: {
        address: TINKER,
        runtime_code_hash: runtimeHashes.tinker_account_encumbrance,
      },
      compute_credit_vault: {
        address: COMPUTE,
        runtime_code_hash: runtimeHashes.compute_credit_vault,
        developer: COMPUTE_DEVELOPER,
      },
      email_oracle_auth: {
        address: EMAIL,
        runtime_code_hash: runtimeHashes.email_oracle_auth,
        consumer_address: TEE,
        release: {
          device_id: DEVICE_ID,
          kms_contract_address: KMS,
          kms_runtime_code_hash: emailBinding.kms_proxy_runtime_code_hash,
          kms_implementation_address: KMS_IMPLEMENTATION,
          kms_implementation_runtime_code_hash:
            emailBinding.kms_implementation_runtime_code_hash,
          kms_registration_tx_hash: KMS_REGISTRATION_TX,
          kms_registration_block: KMS_REGISTRATION_BLOCK,
          kms_registration_block_hash: KMS_REGISTRATION_BLOCK_HASH,
          target_boot: {
            instance_id: BOOT_INSTANCE,
            mr_aggregated: word("70"),
            mr_system: word("71"),
            os_image_hash: `0x${OS_IMAGE}`,
          },
          restart_key_derivation_proof_hash: RESTART_PROOF,
          external_evidence_sha256: word("72"),
        },
      },
    },
    cvm: {
      app_id: APP_ID,
      cvm_id: CVM_ID,
      compose_hash: COMPOSE,
      local_compose_hash: LOCAL_COMPOSE,
      rendered_compose_sha256: RENDERED_COMPOSE,
      os_image_hash: OS_IMAGE,
      tee_identity: TEE,
      delegate_url: "https://delegate.release.wikigen.me",
      images: [IMAGE],
    },
    trust_domains: {
      diligence_qvl: {
        identity: {
          verifier_address: accounts[0].address.toLowerCase(),
          release_policy_hash: qvlPolicies[0],
        },
        policy_binding: { email_oracle_kms_restart_binding: emailBinding },
      },
      arena_qvl: { identity: {
        verifier_address: accounts[1].address.toLowerCase(),
        release_policy_hash: qvlPolicies[1],
      } },
      anchor_writer_qvl: { identity: {
        verifier_address: accounts[2].address.toLowerCase(),
        release_policy_hash: qvlPolicies[2],
      } },
      compute_metering_qvl: { identity: {
        verifier_address: accounts[3].address.toLowerCase(),
        release_policy_hash: qvlPolicies[3],
      } },
      compute_workload_qvl: { identity: {
        verifier_address: accounts[4].address.toLowerCase(),
        release_policy_hash: qvlPolicies[4],
      } },
      compute_metering: { identity: { metering_verifier: METERING_VERIFIER } },
    },
    execution_policy: { rollback_anchor: {
      contract_address: ANCHOR,
      runtime_code_hash: word("73"),
      writer_address: WRITER,
      writer_release_commitment: WRITER_COMMITMENT,
      evidence_sha256: pin("74"),
    } },
    attestations: { artifact: artifactVerdict, arena: arenaVerdict },
  };
  const ledgerContract = (candidateKey, status) => ({
    status,
    address: candidate.contracts[candidateKey].address,
    sourceCommit: RELEASE,
    runtimeCodeHash: candidate.contracts[candidateKey].runtime_code_hash,
  });
  const ledger = {
    schemaVersion: 1,
    network: { name: "Base Sepolia", chainId: 84_532 },
    currentOperatorDeployer: {
      address: OPERATOR,
      keystoreAccount: "dev",
      fundingStatus: "verified_during_deployment_preflight",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: { contractSuite: {
      status: "broadcast_complete_pending_cvm_binding",
      keystoreAccount: "dev",
      sourceCommit: RELEASE,
      deploymentIntentSha256: DEPLOYMENT_INTENT,
      reviewerAuthorityGenesisAcceptanceSha256: REVIEWER_ACCEPTANCE,
      includesReviewedComputeCreditVault: true,
      excludesChallengePrizeAndCandidateCustodyContracts: true,
    } },
    contracts: {
      diligenceRoom: ledgerContract("diligence_room", "deployed_fail_closed_pending_tee_binding"),
      challengeRegistry: ledgerContract("challenge_registry", "deployed_empty_active_registry"),
      royaltyDistributor: ledgerContract("royalty_distributor", "deployed_ownerless_pull_payment_rail"),
      tinkerAccountEncumbrance: ledgerContract("tinker_account_encumbrance", "deployed_exact_release_policy_frozen_active"),
      computeCreditVault: ledgerContract("compute_credit_vault", "deployed_paused_fee_frozen_unbound_pending_release_binding"),
      emailOracleAuth: ledgerContract("email_oracle_auth", "deployed_deny_all_pending_cvm_binding"),
      executionPolicyAnchor: {
        status: "verified_active_frozen_release_writer",
        address: ANCHOR,
        sourceCommit: RELEASE,
        runtimeCodeHash: candidate.execution_policy.rollback_anchor.runtime_code_hash,
        writer: WRITER,
        writerReleaseCommitment: WRITER_COMMITMENT,
        writerRotationsFrozen: true,
        paused: false,
        globalSequence: 7,
        globalHead: word("75"),
        releaseSnapshotBlockNumber: 123_456,
        deploymentIntentSha256Bytes32: `0x${DEPLOYMENT_INTENT.slice(7)}`,
      },
    },
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: RELEASE,
      deploymentIntentSha256: DEPLOYMENT_INTENT,
      reviewerAuthorityGenesisAcceptanceSha256: REVIEWER_ACCEPTANCE,
    }],
    tinkerReleaseHistory: [],
    phala: {
      cvmId: CVM_ID,
      appId: APP_ID,
      composeHash: COMPOSE,
      localRawComposeImagePolicyHash: LOCAL_COMPOSE,
      renderedComposeSha256: RENDERED_COMPOSE,
      osImageHash: OS_IMAGE,
      osIsDev: false,
      publicLogs: false,
      publicSysinfo: false,
      publicTcbinfo: false,
      sourceDigest: RELEASE,
      endpoints: { delegate: candidate.cvm.delegate_url },
      imageDigests: [{
        service: IMAGE.service,
        image: IMAGE.image,
        githubProvenanceAttestation: "verified",
        githubSbomAttestation: "verified",
      }],
    },
  };
  const deploymentEvidence = (context, verdict, key) => ({
    schema: "dnai.deployment.evidence.v2",
    api_url: candidate.cvm.delegate_url,
    context,
    status: "evidence_checked_tdx_unverified",
    images: [{
      image: IMAGE.image,
      repo: IMAGE.repo,
      signer_workflow: IMAGE.signer_workflow,
      source_digest: IMAGE.source_digest,
      source_ref: IMAGE.source_ref,
      provenance_attestation: IMAGE.provenance_attestation,
      sbom_attestation: IMAGE.sbom_attestation,
    }],
    cvm: {
      api_url: candidate.cvm.delegate_url,
      context,
      mode: "tdx",
      compose_hash: LOCAL_COMPOSE,
      attested_compose_hash: COMPOSE,
      rendered_compose_sha256: RENDERED_COMPOSE,
      images: [{ service: IMAGE.service, image: IMAGE.image }],
      app_id: APP_ID,
      os_image_hash: OS_IMAGE,
      report_data: verdict.verdict.report_data.slice(2),
      encryption_public_key: key.repeat(32),
      quote_size: 2_048,
      fetched_at: NOW,
      quote_verification: "public-envelope-only; Intel TDX quote internals not parsed",
    },
    checks: {
      github_provenance_attestations: "verified_by_github_cli",
      github_sbom_attestations: "verified_by_github_cli",
      digest_pinned_compose: "matched_expected_inputs",
      cvm_attestation_envelope: "matched_claimed_identity_not_cryptographically_verified",
      intel_tdx_quote: "not_verified_no_independent_qvl_verdict",
      raw_secret_egress: false,
    },
    claims: {
      intel_tdx_quote_verified: false,
      independent_attestation_verdict_present: false,
      production_authorization_allowed: false,
    },
  });
  const anchorEvidence = {
    schema: "dnai.execution-policy-anchor-writer-qvl-evidence.v2",
    status: "independent_qvl_verified",
    chain_id: 84_532,
    anchor_address: ANCHOR,
    writer_address: WRITER,
    writer_release_commitment: WRITER_COMMITMENT,
    writer_key_path: "tinker/execution_policy_anchor_writer",
    writer_key_path_sha256: createHash("sha256")
      .update(ANCHOR_KEY_DOMAIN)
      .update(Buffer.from("tinker/execution_policy_anchor_writer", "ascii"))
      .digest("hex"),
    writer_custody: "dstack_derived_execution_policy_anchor_writer",
    app_id: APP_ID,
    compose_hash: `0x${COMPOSE}`,
    os_image_hash: OS_IMAGE,
    report_data: anchorReportData,
    quote_report_data:
      `${anchorReportData}${anchorVerdict.verdict.challenge_digest.slice(2)}`,
    quote_sha256: anchorVerdict.quote_sha256,
    quote_size: 2_048,
    qvl_release_policy_hash: qvlPolicies[2],
    qvl_verifier_address: accounts[2].address.toLowerCase(),
    qvl_verdict: anchorVerdict.verdict,
    verification_method: "intel_tdx_dcap_qvl",
    tdx_measurement_policy: "exact_release_pinned_measurements",
    raw_quote_egress: "authenticated_https_qvl_only",
    raw_quote_in_artifact: false,
    raw_private_key_egress: false,
  };
  const anchorFile = file("--anchor-writer-evidence", anchorEvidence);
  candidate.execution_policy.rollback_anchor.evidence_sha256 = anchorFile.rawSha256;
  const emailEvidence = {
    schema: "dnai.email-oracle-external-release-evidence.v1",
    status: "external_evidence_verified",
    chain_id: 84_532,
    release_sha: RELEASE,
    email_oracle_auth: EMAIL,
    main_cvm: {
      compose_hash: `0x${COMPOSE}`,
      consumer_app_id: TEE,
      cvm_id: CVM_ID,
      device_id: DEVICE_ID,
    },
    kms: {
      contract_address: KMS,
      implementation_address: KMS_IMPLEMENTATION,
      implementation_runtime_code_hash:
        emailBinding.kms_implementation_runtime_code_hash,
      kms_eip1967_implementation_slot_word:
        emailBinding.kms_eip1967_implementation_slot_word,
      runtime_code_hash: emailBinding.kms_proxy_runtime_code_hash,
      source_commit: "76".repeat(20),
      source_repository: "https://github.com/Dstack-TEE/dstack",
      verification_status: "verified_source_and_runtime",
      verification_url: `https://sepolia.basescan.org/address/${KMS_IMPLEMENTATION}`,
    },
    registration: {
      block_hash: KMS_REGISTRATION_BLOCK_HASH,
      block_number: KMS_REGISTRATION_BLOCK,
      registered_apps_readback: true,
      transaction_hash: KMS_REGISTRATION_TX,
    },
    target_boot: {
      advisory_ids: [],
      instance_id: BOOT_INSTANCE,
      kms_is_app_allowed: true,
      mr_aggregated: word("70"),
      mr_system: word("71"),
      os_image_hash: `0x${OS_IMAGE}`,
      tcb_status: "UpToDate",
    },
    restart_key_derivation: {
      derive_key_succeeded_after: true,
      derive_key_succeeded_before: true,
      key_path: "email/creds",
      post_restart_commitment: RESTART_COMMITMENT,
      pre_restart_commitment: RESTART_COMMITMENT,
      raw_key_egress: false,
      raw_secret_egress: false,
      restart_proof_hash: RESTART_PROOF,
      restart_observed: true,
      status: "verified_after_real_cvm_restart",
    },
    qvl_verification: {
      qvl_release_policy_hash: qvlPolicies[0],
      qvl_verdict: emailVerdict.verdict,
      qvl_verifier_address: accounts[0].address.toLowerCase(),
      quote_sha256: emailVerdict.quote_sha256,
      status: "independent_qvl_verified",
      verification_method: "intel_tdx_dcap_qvl",
    },
  };
  const emailFile = file("--email-oracle-evidence", emailEvidence);
  candidate.contracts.email_oracle_auth.release.external_evidence_sha256 =
    `0x${emailFile.rawSha256.slice(7)}`;
  const files = [
    file("--ledger", ledger),
    file("--artifact-evidence", deploymentEvidence("artifact", artifactVerdict, "77")),
    file("--arena-evidence", deploymentEvidence("arena", arenaVerdict, "78")),
    anchorFile,
    emailFile,
  ];
  const manifest = {
    release_sha: RELEASE,
    semantic_lineage: {
      deployment_intent_sha256: DEPLOYMENT_INTENT,
      ceremony_authorization_sha256: B,
      runtime_authority_dependency_sha256: R,
      compute_workload_activation_observation_sha256: O,
    },
    pre_D_private_inputs: files.map(({ flag, rawSha256 }) => ({
      flag,
      projection: "raw_canonical_file_bytes",
      sha256: rawSha256,
    })),
    qvl_verifier_roots: accounts.map((account) => account.address.toLowerCase()),
  };
  const historicalQvlAuthority = projectExternalFiveHistoricalQvlAuthority({
    qvlIdentityEvidence: [
      ["diligence_qvl_cvm", 0],
      ["arena_qvl_cvm", 1],
      ["anchor_writer_qvl_cvm", 2],
      ["compute_workload_qvl_cvm", 4],
      ["compute_metering_qvl_cvm", 3],
    ].map(([domain, index]) => ({
      domain,
      deployment_intent_sha256: DEPLOYMENT_INTENT,
      release_authority_sha256: RELEASE_AUTHORITY,
      ceremony_nonce: CEREMONY_NONCE,
      measurement_policy_sha256: qvlMeasurements[index],
      release_policy_sha256: `sha256:${qvlPolicies[index].slice(2)}`,
      tee_identity: accounts[index].address.toLowerCase(),
      activation_evidence_lease_expires_at: NOW + 900,
    })),
    activationEvidenceLeaseSeconds: 900,
  });
  return {
    files,
    releaseCandidate: candidate,
    ceremonyAuthorization: {
      release_sha: RELEASE,
      pre_ceremony_runtime_authority_sha256: R,
    },
    computeWorkloadActivationObservation: {
      release_sha: RELEASE,
      lineage: {
        deployment_intent_sha256: DEPLOYMENT_INTENT,
        release_verification_authority_sha256: RELEASE_AUTHORITY,
        ceremony_nonce: CEREMONY_NONCE,
        ceremony_authorization_sha256: B,
        pre_ceremony_runtime_authority_sha256: R,
      },
    },
    frontendBuildInputManifest: manifest,
    frontendBuildCandidateReceipt: {
      release_sha: RELEASE,
      deployment_intent_sha256: DEPLOYMENT_INTENT,
      release_inputs_sha256: D_INPUTS,
      ceremony_authorization_sha256: B,
      runtime_authority_dependency_sha256: R,
      compute_workload_activation_observation_sha256: O,
    },
    liveActivationAuthority: {
      release_sha: RELEASE,
      ceremony_authorization_sha256: B,
      post_ceremony_evidence: {
        compute_workload_activation_observation_sha256: O,
        frontend_build_candidate_receipt_sha256: D,
      },
      review: { signed_at: new Date(NOW * 1_000).toISOString() },
    },
    historicalQvlAuthority,
    authorityDigests: {
      ceremonyAuthorizationSha256: B,
      ceremonyNonce: CEREMONY_NONCE,
      computeWorkloadActivationObservationSha256: O,
      frontendBuildCandidateReceiptSha256: D,
      frontendBuildInputManifestSha256: D_INPUTS,
      liveActivationAuthoritySha256: C,
      releaseVerificationAuthoritySha256: RELEASE_AUTHORITY,
      runtimeAuthorityDependencySha256: R,
    },
    recoverIndependentEip191PersonalSigner,
    testOnly: { accounts, qvlMeasurements, qvlPolicies },
  };
}

async function resignVerdict(
  wrapper,
  account,
  signingDomain = VERDICT_DOMAIN,
  options,
) {
  wrapper.verdict.verifier_signature = await account.signMessage({
    message: { raw: verdictDigest(wrapper.verdict, signingDomain, options) },
  });
}

function recommitExternalFile(input, index) {
  input.files[index] = file(input.files[index].flag, input.files[index].value);
  const commitment = input.frontendBuildInputManifest.pre_D_private_inputs
    .find(({ flag }) => flag === input.files[index].flag);
  commitment.sha256 = input.files[index].rawSha256;
}

test("external five authenticates historical bytes, lineage, schemas and QVL signatures without elevating chain claims", async () => {
  const input = await fixture();
  const result = validateExternalFiveHistoricalEvidenceBoundary(input);
  assert.equal(result.status, EXTERNAL_FIVE_HISTORICAL_EVIDENCE_STATUS);
  assert.equal(result.frontend_D_raw_byte_commitments_authenticated, true);
  assert.equal(result.release_B_R_O_C_D_lineage_authenticated, true);
  assert.equal(result.historical_qvl_identity_evidence_authenticated, true);
  assert.equal(result.historical_v4_qvl_verdict_signatures_authenticated, true);
  assert.equal(
    result.recorded_challenge_and_activation_lease_relations_checked,
    true,
  );
  assert.equal(result.qvl_challenge_signatures_authenticated, false);
  assert.equal(result.raw_quotes_authenticated, false);
  assert.equal(result.qvl_challenge_consumption_authenticated, false);
  assert.equal(result.freshness_renewed, false);
  assert.equal(result.current_qvl_operation_performed, false);
  assert.equal(result.current_clock_consulted, false);
  assert.equal(result.live_traffic_authorized, false);
  assert.equal(result.ledger_chain_observations_authenticated, false);
  assert.equal(result.email_restart_observation_authenticated, false);
  assert.equal(result.canonicalDependencyChainVerified, false);
  assert.deepEqual(result.required_downstream_proofs.slice(0, 4), [
    "fresh_QVL_challenge_signatures_for_external_verdicts",
    "fresh_raw_TDX_quotes_and_current_DCAP_QVL_appraisals",
    "single_use_QVL_challenge_consumption_receipts",
    "current_clock_activation_evidence_lease_validation",
  ]);
  assert.equal(result.required_downstream_proofs.length, 9);
  assert.ok(Object.isFrozen(result));
});

test("external five rejects legacy v3 verdicts, the v3 signing domain, and non-exact v4 fields", async () => {
  const legacy = await fixture();
  const legacyVerdict = legacy.releaseCandidate.attestations.artifact;
  legacyVerdict.verdict.schema = "dnai.independent-tdx-verdict.v3";
  delete legacyVerdict.verdict.activation_evidence_lease_expires_at;
  await resignVerdict(
    legacyVerdict,
    legacy.testOnly.accounts[0],
    V3_VERDICT_DOMAIN,
    { includeActivationEvidenceLease: false },
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(legacy),
    /must contain exactly the canonical fields/i,
  );

  const legacyDomain = await fixture();
  await resignVerdict(
    legacyDomain.releaseCandidate.attestations.artifact,
    legacyDomain.testOnly.accounts[0],
    V3_VERDICT_DOMAIN,
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(legacyDomain),
    /signature is not authenticated/i,
  );

  const extra = await fixture();
  extra.releaseCandidate.attestations.artifact.verdict.challenge_consumed_at = NOW - 9;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(extra),
    /must contain exactly the canonical fields/i,
  );
});

test("external five rejects every invalid v4 challenge-to-lease relation", async () => {
  const aliasDrift = await fixture();
  aliasDrift.releaseCandidate.attestations.artifact.verdict
    .activation_evidence_lease_expires_at = NOW + 889;
  await resignVerdict(
    aliasDrift.releaseCandidate.attestations.artifact,
    aliasDrift.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(aliasDrift),
    /challenge or activation evidence lease relation is invalid/i,
  );

  const oversizedLease = await fixture();
  oversizedLease.releaseCandidate.attestations.artifact.verdict.expires_at = NOW + 891;
  oversizedLease.releaseCandidate.attestations.artifact.verdict
    .activation_evidence_lease_expires_at = NOW + 891;
  await resignVerdict(
    oversizedLease.releaseCandidate.attestations.artifact,
    oversizedLease.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(oversizedLease),
    /challenge or activation evidence lease relation is invalid/i,
  );

  const issuedAtChallengeExpiry = await fixture();
  issuedAtChallengeExpiry.releaseCandidate.attestations.artifact.verdict.issued_at =
    issuedAtChallengeExpiry.releaseCandidate.attestations.artifact.verdict
      .challenge_expires_at;
  await resignVerdict(
    issuedAtChallengeExpiry.releaseCandidate.attestations.artifact,
    issuedAtChallengeExpiry.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(issuedAtChallengeExpiry),
    /challenge or activation evidence lease relation is invalid/i,
  );

  const oversizedChallenge = await fixture();
  oversizedChallenge.releaseCandidate.attestations.artifact.verdict
    .challenge_issued_at = NOW - 126;
  await resignVerdict(
    oversizedChallenge.releaseCandidate.attestations.artifact,
    oversizedChallenge.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(oversizedChallenge),
    /challenge or activation evidence lease relation is invalid/i,
  );

  const beyondFutureTolerance = await fixture();
  Object.assign(beyondFutureTolerance.releaseCandidate.attestations.artifact.verdict, {
    challenge_issued_at: NOW + 6,
    challenge_expires_at: NOW + 100,
    issued_at: NOW + 6,
  });
  await resignVerdict(
    beyondFutureTolerance.releaseCandidate.attestations.artifact,
    beyondFutureTolerance.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(beyondFutureTolerance),
    /challenge or activation evidence lease relation is invalid/i,
  );

  const expiredAtSignedC = await fixture();
  const leaseExpiry = expiredAtSignedC.releaseCandidate.attestations.artifact
    .verdict.expires_at;
  expiredAtSignedC.liveActivationAuthority.review.signed_at =
    new Date(leaseExpiry * 1_000).toISOString();
  expiredAtSignedC.files[1].value.cvm.fetched_at = leaseExpiry;
  expiredAtSignedC.files[2].value.cvm.fetched_at = leaseExpiry;
  recommitExternalFile(expiredAtSignedC, 1);
  recommitExternalFile(expiredAtSignedC, 2);
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(expiredAtSignedC),
    /challenge or activation evidence lease relation is invalid/i,
  );

  for (const field of [
    "challenge_issued_at",
    "challenge_expires_at",
    "issued_at",
    "activation_evidence_lease_expires_at",
    "expires_at",
  ]) {
    const outOfProtocolRange = await fixture();
    outOfProtocolRange.releaseCandidate.attestations.artifact.verdict[field] =
      MAX_PROTOCOL_SECOND + 1;
    await resignVerdict(
      outOfProtocolRange.releaseCandidate.attestations.artifact,
      outOfProtocolRange.testOnly.accounts[0],
    );
    assert.throws(
      () => validateExternalFiveHistoricalEvidenceBoundary(outOfProtocolRange),
      /must be a bounded integer/i,
      field,
    );
  }
});

test("external five authenticates v4 lease fields as signed data", async () => {
  const tampered = await fixture();
  tampered.releaseCandidate.attestations.artifact.verdict.expires_at = NOW + 889;
  tampered.releaseCandidate.attestations.artifact.verdict
    .activation_evidence_lease_expires_at = NOW + 889;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(tampered),
    /signature is not authenticated/i,
  );
});

test("external five binds verifier identity, release policy, measurement policy, and identity lease", async () => {
  const verifierDrift = await fixture();
  verifierDrift.historicalQvlAuthority = structuredClone(
    verifierDrift.historicalQvlAuthority,
  );
  verifierDrift.historicalQvlAuthority.identities[0].verifier_address = address("fe");
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(verifierDrift),
    /historical QVL authority drifted from release\/L\/R\/C/i,
  );

  const releasePolicyDrift = await fixture();
  releasePolicyDrift.historicalQvlAuthority = structuredClone(
    releasePolicyDrift.historicalQvlAuthority,
  );
  releasePolicyDrift.historicalQvlAuthority.identities[0]
    .release_policy_sha256 = pin("ef");
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(releasePolicyDrift),
    /historical QVL authority drifted from release\/L\/R\/C/i,
  );

  const measurementDrift = await fixture();
  measurementDrift.releaseCandidate.attestations.artifact.verdict
    .measurement_policy_sha256 = pin("ee");
  await resignVerdict(
    measurementDrift.releaseCandidate.attestations.artifact,
    measurementDrift.testOnly.accounts[0],
  );
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(measurementDrift),
    /drifted from its authenticated historical QVL identity/i,
  );

  const identityLeaseDrift = await fixture();
  identityLeaseDrift.historicalQvlAuthority = structuredClone(
    identityLeaseDrift.historicalQvlAuthority,
  );
  identityLeaseDrift.historicalQvlAuthority.identities[0]
    .activation_evidence_lease_expires_at = NOW + 100;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(identityLeaseDrift),
    /challenge or activation evidence lease relation is invalid/i,
  );

  for (const field of ["current_clock_consulted", "live_traffic_authorized"]) {
    const elevated = await fixture();
    elevated.historicalQvlAuthority = structuredClone(
      elevated.historicalQvlAuthority,
    );
    elevated.historicalQvlAuthority[field] = true;
    assert.throws(
      () => validateExternalFiveHistoricalEvidenceBoundary(elevated),
      /historical QVL authority shape or truth boundary is invalid/i,
      field,
    );
  }
});

test("external five binds each signed verdict to its release domain, profile, CVM, and contract", async () => {
  const cases = [
    ["domain", "unexpected_runtime_domain"],
    ["profile", "unexpected_profile"],
    ["cvm_id", "cvm_other_release"],
    ["contract_address", address("fd")],
  ];
  for (const [field, value] of cases) {
    const input = await fixture();
    input.releaseCandidate.attestations.artifact.verdict[field] = value;
    await resignVerdict(
      input.releaseCandidate.attestations.artifact,
      input.testOnly.accounts[0],
    );
    assert.throws(
      () => validateExternalFiveHistoricalEvidenceBoundary(input),
      /verdict drifted from release\/C\/B\/R\/O\/D authority/i,
      field,
    );
  }
});

test("external five rejects D byte drift, promoted unverified claims, stale evidence and forged QVL signatures", async () => {
  const byteDrift = await fixture();
  byteDrift.frontendBuildInputManifest.pre_D_private_inputs[0].sha256 = pin("aa");
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(byteDrift),
    /raw-byte commitment.*ledger/i,
  );

  const promoted = await fixture();
  promoted.files[1].value.claims.production_authorization_allowed = true;
  promoted.files[1] = file("--artifact-evidence", promoted.files[1].value);
  promoted.frontendBuildInputManifest.pre_D_private_inputs[1].sha256 =
    promoted.files[1].rawSha256;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(promoted),
    /elevated.*unverified trust label/i,
  );

  const stale = await fixture();
  stale.files[2].value.cvm.fetched_at = NOW - 301;
  stale.files[2] = file("--arena-evidence", stale.files[2].value);
  stale.frontendBuildInputManifest.pre_D_private_inputs[2].sha256 = stale.files[2].rawSha256;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(stale),
    /not fresh at signed C/i,
  );

  const forged = await fixture();
  forged.releaseCandidate.attestations.artifact.verdict.verifier_signature =
    forged.releaseCandidate.attestations.arena.verdict.verifier_signature;
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(forged),
    /signature is not authenticated|signature cannot be recovered/i,
  );

  const fractionalReviewTime = await fixture();
  fractionalReviewTime.liveActivationAuthority.review.signed_at =
    "1970-01-24T03:33:20.001Z";
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(fractionalReviewTime),
    /canonical UTC whole-second precision/i,
  );

  const secondOnlyReviewTime = await fixture();
  secondOnlyReviewTime.liveActivationAuthority.review.signed_at =
    "1970-01-24T03:33:20Z";
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(secondOnlyReviewTime),
    /canonical UTC whole-second precision/i,
  );
});

test("external five rejects accessor and custom-prototype authority graphs before semantic reads", async () => {
  const accessor = await fixture();
  Object.defineProperty(accessor.releaseCandidate, "release_sha", {
    enumerable: true,
    get: () => RELEASE,
  });
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(accessor),
    /accessors.*forbidden/i,
  );

  const custom = await fixture();
  Object.setPrototypeOf(custom.files[0].value, { polluted: true });
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(custom),
    /custom prototypes.*forbidden/i,
  );
});

test("external five core closure has no ambient clock, I/O, dynamic import, WeakMap, or network primitive", async () => {
  const core = await readFile(new URL(
    "./external-five-historical-evidence-core.mjs",
    import.meta.url,
  ), "utf8");
  const graph = await readFile(new URL(
    "../../scripts/canonical-authority-graph.mjs",
    import.meta.url,
  ), "utf8");
  for (const source of [core, graph]) {
    assert.doesNotMatch(source, /Date\.now\s*\(/);
    assert.doesNotMatch(source, /\bWeakMap\b/);
    assert.doesNotMatch(source, /\bfetch\s*\(/);
    assert.doesNotMatch(source, /\bimport\s*\(/);
    assert.doesNotMatch(source, /node:(?:fs|path|child_process|net|http|https)/);
  }
});

test("external five flag order is the exact D-committed external subset", () => {
  assert.deepEqual(EXTERNAL_FIVE_EVIDENCE_FLAGS, [
    "--ledger",
    "--artifact-evidence",
    "--arena-evidence",
    "--anchor-writer-evidence",
    "--email-oracle-evidence",
  ]);
});

test("external five projects the pure byte identity directly from normalized exact-37 byKey entries", async () => {
  const input = await fixture();
  const byKey = Object.fromEntries(input.files.map((entry) => [({
    "--ledger": "ledger",
    "--artifact-evidence": "artifactEvidence",
    "--arena-evidence": "arenaEvidence",
    "--anchor-writer-evidence": "anchorWriterEvidence",
    "--email-oracle-evidence": "emailOracleEvidence",
  })[entry.flag], {
    ...entry,
    key: "ignored_by_projection",
    filePath: "/private/normalized/exact37.json",
  }]));
  assert.deepEqual(
    projectExternalFiveEvidenceFilesFromExact37ByKey(byKey),
    input.files,
  );
});

test("external five uses an explicit synchronous raw-bytes32 EIP-191 recovery seam", async () => {
  const input = await fixture();
  const recover = input.recoverIndependentEip191PersonalSigner;
  const observed = [];
  input.recoverIndependentEip191PersonalSigner = (request) => {
    assert.deepEqual(Object.keys(request).sort(), ["digest", "signature"]);
    assert.match(request.digest, /^0x[0-9a-f]{64}$/);
    assert.match(request.signature, /^0x[0-9a-f]{130}$/);
    observed.push(request.digest);
    return recover(request);
  };
  validateExternalFiveHistoricalEvidenceBoundary(input);
  assert.equal(observed.length, 4);

  const asynchronous = await fixture();
  asynchronous.recoverIndependentEip191PersonalSigner = async (request) =>
    recover(request);
  assert.throws(
    () => validateExternalFiveHistoricalEvidenceBoundary(asynchronous),
    /synchronous static implementation/i,
  );
});
