import { afterEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import {
  authenticateComputeWorkloadEncryptionContract,
  canonicalAsciiJson,
  computeIndependentQvlVerdictDigest,
  computeWorkloadActivationCommitment,
  computeWorkloadRecipientBindings,
  computeWorkloadRecipientKeyId,
  computeWorkloadRecipientReleaseCommitment,
  deriveComputeWorkloadWireBinding,
  parseComputeWorkloadEncryptionContract,
  prepareComputeWorkloadUpload,
  uploadPreparedComputeWorkload,
  type ComputeWorkloadEncryptionContract,
  type ComputeWorkloadManifest,
  type ComputeWorkloadRecipientActivation,
  type ComputeWorkloadRecipientAttestation,
  type ComputeWorkloadTrustPolicy,
  type IndependentQvlVerdict,
} from "./computeWorkload";
import wireVector from "./computeWorkloadWireVectors.json";

const NOW = 1_800_000_000;
const RELEASE_POLICY_HASH = `0x${"33".repeat(32)}` as Hex;
const COMPOSE_HASH = `0x${"31".repeat(32)}` as Hex;
const OS_IMAGE_HASH = "32".repeat(32);
const QUOTE_HASH = `0x${"34".repeat(32)}` as Hex;
const CHALLENGE_ID = `0x${"73".repeat(32)}` as Hex;
const CHALLENGE_DIGEST = `0x${"74".repeat(32)}` as Hex;
const TEE_SIGNER = `0x${"71".repeat(20)}` as Address;
const COMPUTE_VAULT = `0x${"72".repeat(20)}` as Address;
const COMPUTE_VAULT_RUNTIME_CODE_HASH = `0x${"76".repeat(32)}` as Hex;
const FRESH_DEPLOYMENT_RECEIPT_SHA256 = `0x${"77".repeat(32)}` as Hex;
const CVM_ID = "main-runtime-cvm-0001";
const DEPLOYMENT_INTENT_SHA256 = `sha256:${"78".repeat(32)}`;
const RELEASE_AUTHORITY_SHA256 = `sha256:${"79".repeat(32)}`;
const CEREMONY_NONCE = `0x${"7a".repeat(32)}` as Hex;
const MEASUREMENT_POLICY_SET_SHA256 = `sha256:${"7b".repeat(32)}`;
const MEASUREMENT_POLICY_SHA256 = `sha256:${"7c".repeat(32)}`;
const MAIN_RUNTIME_EVIDENCE_SHA256 = `sha256:${"7d".repeat(32)}`;
const PROJECT_ID = "prj_alpha";
const WALLET = `0x${"11".repeat(20)}`;

function bytesHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeBase64url(value: string): Uint8Array {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

async function fixture(): Promise<{
  raw: ComputeWorkloadEncryptionContract;
  trust: ComputeWorkloadTrustPolicy;
}> {
  const recipientKeys = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const recipientPublic = bytesHex(new Uint8Array(await crypto.subtle.exportKey("raw", recipientKeys.publicKey)));
  const recipientAttestation: ComputeWorkloadRecipientAttestation = {
    schema: "dnai.compute-workload-recipient-attestation.v1",
    context: "compute_workload",
    audience: "dnai-wikigen:compute-workload-recipient",
    service: "dnai-wikigen",
    protocol: "compute_workload_ingress_v1",
    encryption_public_key: recipientPublic,
    key_id: await computeWorkloadRecipientKeyId(recipientPublic),
    activation_signer_address: TEE_SIGNER,
    activation_signer_key_path: "tinker/compute_workload_activation_signer",
    activation_signer_custody: "dstack_derived_compute_workload_activation_signer",
    chain_id: 84_532,
    compute_vault_address: COMPUTE_VAULT,
    compute_vault_runtime_code_hash: COMPUTE_VAULT_RUNTIME_CODE_HASH,
    fresh_contract_deployment_receipt_sha256: FRESH_DEPLOYMENT_RECEIPT_SHA256,
  };
  const recipient = await computeWorkloadRecipientBindings(recipientPublic, recipientAttestation);
  const qvl = privateKeyToAccount(`0x${"75".repeat(32)}`);
  const verifierAddress = qvl.address.toLowerCase() as Address;
  const unsigned: IndependentQvlVerdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    chain_id: 84_532,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: CVM_ID,
    deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
    release_authority_sha256: RELEASE_AUTHORITY_SHA256,
    ceremony_nonce: CEREMONY_NONCE,
    measurement_policy_sha256: MEASUREMENT_POLICY_SHA256,
    release_policy_hash: RELEASE_POLICY_HASH,
    challenge_id: CHALLENGE_ID,
    challenge_digest: CHALLENGE_DIGEST,
    challenge_issued_at: NOW - 20,
    challenge_expires_at: NOW - 5,
    quote_hash: QUOTE_HASH,
    report_data: recipient.reportDataBytes32,
    compose_hash: COMPOSE_HASH,
    app_id: "a1".repeat(20),
    os_image_hash: OS_IMAGE_HASH,
    signer_address: TEE_SIGNER,
    contract_address: COMPUTE_VAULT,
    issued_at: NOW - 10,
    activation_evidence_lease_expires_at: NOW + 90,
    expires_at: NOW + 90,
    verifier_address: verifierAddress,
    verifier_signature: `0x${"00".repeat(65)}`,
  };
  const verdictDigest = await computeIndependentQvlVerdictDigest(unsigned);
  const verdict: IndependentQvlVerdict = {
    ...unsigned,
    verifier_signature: (await qvl.signMessage({ message: { raw: verdictDigest } })).toLowerCase() as Hex,
  };
  const activationProjection = {
    chain_id: 84_532 as const,
    domain: "main_runtime_cvm" as const,
    profile: "compute_workload" as const,
    cvm_id: CVM_ID,
    deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
    release_authority_sha256: RELEASE_AUTHORITY_SHA256,
    ceremony_nonce: CEREMONY_NONCE,
    measurement_policy_set_sha256: MEASUREMENT_POLICY_SET_SHA256,
    measurement_policy_sha256: MEASUREMENT_POLICY_SHA256,
    main_runtime_evidence_sha256: MAIN_RUNTIME_EVIDENCE_SHA256,
    recipient_key_id: recipient.keyId,
    report_data: recipient.reportDataBytes32,
    compose_hash: COMPOSE_HASH,
    app_id: verdict.app_id,
    os_image_hash: OS_IMAGE_HASH,
    release_policy_hash: RELEASE_POLICY_HASH,
    verifier_address: verifierAddress,
    recipient_attestation: recipientAttestation,
    authenticated_verdict: verdict,
  };
  const recipientReleaseCommitment = await computeWorkloadRecipientReleaseCommitment(
    activationProjection,
  );
  const activation: ComputeWorkloadRecipientActivation = {
    schema: "dnai.compute.workload-recipient-activation.v3",
    ...activationProjection,
    quote_hash: QUOTE_HASH,
    verdict_digest: verdictDigest,
    issued_at: verdict.issued_at,
    recipient_evidence_lease_expires_at: verdict.activation_evidence_lease_expires_at,
    expires_at: verdict.expires_at,
    authenticated_at: NOW,
    recipient_release_commitment: recipientReleaseCommitment,
  };
  const activationCommitment = await computeWorkloadActivationCommitment(activation);
  const raw: ComputeWorkloadEncryptionContract = {
    surface: "compute_workload_encryption_contract",
    schema_version: 1,
    status: "live",
    upload_enabled: true,
    reason: "verified_recipient_activation_current",
    protocol: {
      algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
      encoding: "base64url-nopad",
      hkdf_hash: "SHA-256",
      hkdf_salt: "SHA-256(canonical_aad_bytes)",
      hkdf_info_utf8: "dnai-wikigen/compute-workload-ingress/v1",
      aes_gcm_nonce_bytes: 12,
      aes_gcm_tag_bytes: 16,
      additional_authenticated_data: "canonical_aad_bytes",
      sealed_plaintext_frame: {
        magic_hex: "444e4149574c3100",
        payload_length_bytes: 4,
        blinding_bytes: 32,
        blinding_source: "client_csprng",
        padding_source: "client_csprng",
        exact_payload_length_private: true,
        exact_example_count_private: true,
      },
      workload_commitment: "SHA-256(domain || canonical_manifest || 0x00 || secret_blinding || 0x00 || private_payload)",
    },
    recipient: {
      encryption_public_key: recipientPublic,
      key_id: recipient.keyId,
      report_context: "compute_workload",
      report_data: recipient.reportData,
      report_data_sha256: recipient.reportDataSha256,
      activation_commitment: activationCommitment,
      recipient_release_commitment: recipientReleaseCommitment,
      activation_expires_at: activation.expires_at,
      independent_tdx_verdict_authenticated: true,
    },
    activation,
    workload_schemas: {
      inference: {
        schema: "dnai.compute.workload.inference.v1",
        payload_schema: "dnai.compute.inference-prompt.v1",
        recipe: "qwen3_8b_bounded",
        max_content_bytes: 262_144,
        max_prefill_tokens: 32_768,
        max_sample_tokens: 4_096,
      },
      training: {
        schema: "dnai.compute.workload.sft-jsonl.v1",
        line_fields: ["completion", "prompt"],
        recipe: "qwen3_8b_lora_r32",
        max_content_bytes: 1_048_516,
        max_examples: 256,
        max_field_bytes: 32_768,
        max_train_tokens: 10_000_000,
      },
    },
    privacy_classes: {
      payload_size_bytes: { "4k": 4_096, "16k": 16_384, "64k": 65_536, "256k": 262_144, "1m": 1_048_560 },
      example_count_ranges: { none: [0, 0], "1_8": [1, 8], "9_32": [9, 32], "33_128": [33, 128], "129_256": [129, 256] },
      ciphertext_length_reveals_only_payload_size_class: true,
      commitment_is_secret_blinded: true,
    },
    limits: { max_aad_bytes: 8_192, max_ciphertext_bytes: 1_048_576, max_envelopes: 10_000, idempotency_key_max_bytes: 128 },
    gates: {
      real_dstack_required: true,
      simulator_rejected: true,
      fresh_independent_qvl_verdict_required: true,
      release_and_measurement_binding_required: true,
      matching_recipient_key_and_report_data_required: true,
      wallet_or_workloads_create_device_scope_required: true,
      provider_dispatch_enabled: false,
    },
    plaintext_fields_accepted: false,
    ciphertext_egress: false,
    raw_prompt_egress: false,
    raw_examples_egress: false,
    raw_dataset_egress: false,
    raw_output_egress: false,
  };
  return {
    raw,
    trust: {
      trustedVerifierAddresses: [verifierAddress],
      cvmId: CVM_ID,
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      releaseAuthoritySha256: RELEASE_AUTHORITY_SHA256,
      ceremonyNonce: CEREMONY_NONCE,
      measurementPolicySetSha256: MEASUREMENT_POLICY_SET_SHA256,
      measurementPolicySha256: MEASUREMENT_POLICY_SHA256,
      mainRuntimeEvidenceSha256: MAIN_RUNTIME_EVIDENCE_SHA256,
      releasePolicyHash: RELEASE_POLICY_HASH,
      composeHash: COMPOSE_HASH,
      appId: verdict.app_id,
      osImageHash: OS_IMAGE_HASH,
      activationSignerAddress: TEE_SIGNER,
      chainId: 84_532,
      contractAddress: COMPUTE_VAULT,
      vaultRuntimeCodeHash: COMPUTE_VAULT_RUNTIME_CODE_HASH,
      freshDeploymentReceiptSha256: FRESH_DEPLOYMENT_RECEIPT_SHA256,
      maxVerdictAgeSeconds: 300,
    },
  };
}

const inferenceManifest: ComputeWorkloadManifest = {
  schema: "dnai.compute.workload.inference.v1",
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  payload_size_class: "4k",
  example_count_class: "none",
  max_prefill_tokens: 1_024,
  max_sample_tokens: 128,
  max_train_tokens: 0,
};

afterEach(() => vi.restoreAllMocks());

describe("Compute sealed workload browser wire", () => {
  it("matches Python ASCII canonical JSON, including non-ASCII strings", () => {
    expect(canonicalAsciiJson({ z: "β🧬", a: { n: 2, ok: true } })).toBe(
      '{"a":{"n":2,"ok":true},"z":"\\u03b2\\ud83e\\uddec"}',
    );
  });

  it("matches the canonical verifier's frozen verdict-v4 signing KAT", async () => {
    const verdict: IndependentQvlVerdict = {
      schema: "dnai.independent-tdx-verdict.v4",
      verification_method: "intel_tdx_dcap_qvl",
      verified: true,
      chain_id: 84_532,
      domain: "main_runtime_cvm",
      profile: "compute_workload",
      cvm_id: "main-runtime-cvm-0001",
      deployment_intent_sha256: `sha256:${"11".repeat(32)}`,
      release_authority_sha256: `sha256:${"12".repeat(32)}`,
      ceremony_nonce: `0x${"13".repeat(32)}`,
      measurement_policy_sha256: `sha256:${"14".repeat(32)}`,
      release_policy_hash: `0x${"15".repeat(32)}`,
      challenge_id: `0x${"16".repeat(32)}`,
      challenge_digest: `0x${"17".repeat(32)}`,
      challenge_issued_at: 1_800_000_000,
      challenge_expires_at: 1_800_000_120,
      quote_hash: `0x${"18".repeat(32)}`,
      report_data: `0x${"19".repeat(32)}`,
      compose_hash: `0x${"1a".repeat(32)}`,
      app_id: "1b".repeat(20),
      os_image_hash: "1c".repeat(32),
      signer_address: `0x${"1d".repeat(20)}`,
      contract_address: `0x${"1e".repeat(20)}`,
      issued_at: 1_800_000_001,
      activation_evidence_lease_expires_at: 1_800_000_119,
      expires_at: 1_800_000_119,
      verifier_address: `0x${"1f".repeat(20)}`,
      verifier_signature: `0x${"20".repeat(64)}1b`,
    };
    expect(await computeIndependentQvlVerdictDigest(verdict)).toBe(
      "0xe5030817bc86cb01586826ce35631bf1382d9c5deece6a46e21484d9b48512b6",
    );
  });

  it("matches the shared Python commitment and AAD vector exactly", async () => {
    expect(wireVector.fixture_only_nonsecret).toBe(true);
    const recipient = await computeWorkloadRecipientBindings(
      wireVector.recipient_public_key_hex,
      wireVector.recipient_attestation as ComputeWorkloadRecipientAttestation,
    );
    expect(recipient).toEqual({
      keyId: wireVector.recipient_key_id,
      reportData: wireVector.recipient_report_data,
      reportDataBytes32: `0x${wireVector.recipient_report_data}`,
      reportDataSha256: wireVector.report_data_sha256,
    });
    const payload = new TextEncoder().encode(canonicalAsciiJson({
      schema: "dnai.compute.inference-prompt.v1",
      prompt: wireVector.payload_utf8,
    }));
    expect(bytesHex(payload)).toBe(wireVector.canonical_payload_hex);
    const binding = await deriveComputeWorkloadWireBinding({
      principal: {
        kind: "wallet",
        projectId: wireVector.principal.project_id,
        actorId: wireVector.principal.actor_id,
      },
      idempotencyKey: wireVector.idempotency_key,
      manifest: wireVector.manifest as ComputeWorkloadManifest,
      privatePayload: payload,
      blinding: Uint8Array.from(wireVector.blinding_hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16)),
      recipient: {
        keyId: wireVector.recipient_key_id,
        reportDataSha256: wireVector.report_data_sha256,
        activationCommitment: wireVector.activation_commitment,
        recipientReleaseCommitment: wireVector.recipient_release_commitment,
      },
    });
    expect(binding).toMatchObject({
      projectCommitment: wireVector.project_commitment,
      actorCommitment: wireVector.actor_commitment,
      idempotencyHash: wireVector.idempotency_hash,
      manifestCommitment: wireVector.manifest_commitment,
      workloadCommitment: wireVector.workload_commitment,
      aadBase64url: wireVector.aad_base64url,
      aadSha256: wireVector.aad_sha256,
    });
    expect(wireVector.sealed_plaintext_bytes).toBe(4_096);
    payload.fill(0);
    binding.aad.fill(0);
  });

  it("authenticates the full signed QVL descriptor and rejects a forged signature", async () => {
    const { raw, trust } = await fixture();
    expect(raw.activation.authenticated_verdict.challenge_expires_at).toBeLessThan(NOW);
    expect(raw.activation.recipient_evidence_lease_expires_at).toBeGreaterThan(NOW);
    const authenticated = await authenticateComputeWorkloadEncryptionContract(raw, trust, NOW);
    expect(authenticated.recipient.independent_tdx_verdict_authenticated).toBe(true);
    expect(authenticated.gates.provider_dispatch_enabled).toBe(false);

    const forged = structuredClone(raw);
    forged.activation.authenticated_verdict.verifier_signature = `0x${"00".repeat(65)}`;
    forged.recipient.activation_commitment = await computeWorkloadActivationCommitment(forged.activation);
    await expect(authenticateComputeWorkloadEncryptionContract(forged, trust, NOW)).rejects.toThrow(/signature/i);
  });

  it("accepts only verdict v4 and activation v3 with every exact lineage and lease field", async () => {
    const { raw } = await fixture();
    expect(parseComputeWorkloadEncryptionContract(raw).activation).toMatchObject({
      schema: "dnai.compute.workload-recipient-activation.v3",
      chain_id: 84_532,
      domain: "main_runtime_cvm",
      profile: "compute_workload",
      cvm_id: CVM_ID,
      deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
      release_authority_sha256: RELEASE_AUTHORITY_SHA256,
      ceremony_nonce: CEREMONY_NONCE,
      measurement_policy_set_sha256: MEASUREMENT_POLICY_SET_SHA256,
      measurement_policy_sha256: MEASUREMENT_POLICY_SHA256,
      main_runtime_evidence_sha256: MAIN_RUNTIME_EVIDENCE_SHA256,
      recipient_evidence_lease_expires_at: NOW + 90,
      authenticated_verdict: {
        schema: "dnai.independent-tdx-verdict.v4",
        domain: "main_runtime_cvm",
        cvm_id: CVM_ID,
        activation_evidence_lease_expires_at: NOW + 90,
      },
    });

    for (const schema of [
      "dnai.compute.workload-recipient-activation.v1",
      "dnai.compute.workload-recipient-activation.v2",
    ]) {
      const downgraded = structuredClone(raw) as unknown as {
        activation: { schema: string };
      };
      downgraded.activation.schema = schema;
      expect(() => parseComputeWorkloadEncryptionContract(downgraded)).toThrow(/activation schema/i);
    }
    for (const schema of [
      "dnai.independent-tdx-verdict.v1",
      "dnai.independent-tdx-verdict.v2",
      "dnai.independent-tdx-verdict.v3",
    ]) {
      const downgraded = structuredClone(raw) as unknown as {
        activation: { authenticated_verdict: { schema: string } };
      };
      downgraded.activation.authenticated_verdict.schema = schema;
      expect(() => parseComputeWorkloadEncryptionContract(downgraded)).toThrow(/verdict schema/i);
    }
  });

  it("rejects omitted, extra, noncanonical, and cross-layer lineage", async () => {
    const { raw, trust } = await fixture();
    const requiredOuter = [
      "chain_id",
      "domain",
      "profile",
      "cvm_id",
      "deployment_intent_sha256",
      "release_authority_sha256",
      "ceremony_nonce",
      "measurement_policy_set_sha256",
      "measurement_policy_sha256",
      "main_runtime_evidence_sha256",
      "recipient_evidence_lease_expires_at",
    ] as const;
    const requiredInner = [
      "chain_id",
      "domain",
      "profile",
      "cvm_id",
      "deployment_intent_sha256",
      "release_authority_sha256",
      "ceremony_nonce",
      "measurement_policy_sha256",
      "activation_evidence_lease_expires_at",
    ] as const;
    for (const field of requiredOuter) {
      const missing = structuredClone(raw) as unknown as {
        activation: Record<string, unknown>;
      };
      delete missing.activation[field];
      expect(() => parseComputeWorkloadEncryptionContract(missing)).toThrow(/missing or unexpected fields/i);
    }
    for (const field of requiredInner) {
      const missing = structuredClone(raw) as unknown as {
        activation: { authenticated_verdict: Record<string, unknown> };
      };
      delete missing.activation.authenticated_verdict[field];
      expect(() => parseComputeWorkloadEncryptionContract(missing)).toThrow(/missing or unexpected fields/i);
    }

    const extra = structuredClone(raw) as unknown as {
      activation: Record<string, unknown>;
    };
    extra.activation.legacy_release_authority = RELEASE_AUTHORITY_SHA256;
    expect(() => parseComputeWorkloadEncryptionContract(extra)).toThrow(/missing or unexpected fields/i);

    const noncanonical = structuredClone(raw) as unknown as {
      activation: { cvm_id: string };
    };
    noncanonical.activation.cvm_id = "Main-Runtime-CVM-0001";
    expect(() => parseComputeWorkloadEncryptionContract(noncanonical)).toThrow(/CVM id is invalid/i);

    const drifted = structuredClone(raw);
    drifted.activation.release_authority_sha256 = `sha256:${"8a".repeat(32)}`;
    drifted.activation.recipient_release_commitment = await computeWorkloadRecipientReleaseCommitment(
      drifted.activation,
    );
    drifted.recipient.recipient_release_commitment = drifted.activation.recipient_release_commitment;
    drifted.recipient.activation_commitment = await computeWorkloadActivationCommitment(
      drifted.activation,
    );
    await expect(
      authenticateComputeWorkloadEncryptionContract(drifted, trust, NOW),
    ).rejects.toThrow(/release policy/i);
  });

  it("cryptographically covers the v4 release-lineage and lease fields in the QVL signature", async () => {
    const { raw, trust } = await fixture();
    for (const mutate of [
      (candidate: ComputeWorkloadEncryptionContract) => {
        candidate.activation.authenticated_verdict.challenge_digest =
          `0x${"8b".repeat(32)}`;
      },
      (candidate: ComputeWorkloadEncryptionContract) => {
        candidate.activation.authenticated_verdict.activation_evidence_lease_expires_at += 1;
        candidate.activation.authenticated_verdict.expires_at += 1;
        candidate.activation.recipient_evidence_lease_expires_at += 1;
        candidate.activation.expires_at += 1;
        candidate.recipient.activation_expires_at += 1;
      },
    ]) {
      const mutated = structuredClone(raw);
      mutate(mutated);
      mutated.activation.verdict_digest = await computeIndependentQvlVerdictDigest(
        mutated.activation.authenticated_verdict,
      );
      mutated.recipient.activation_commitment = await computeWorkloadActivationCommitment(
        mutated.activation,
      );
      await expect(
        authenticateComputeWorkloadEncryptionContract(mutated, trust, NOW),
      ).rejects.toThrow(/signer is not authenticated|signature/i);
    }
  });

  it("requires every ceremony-lineage field from independent browser trust policy", async () => {
    const { raw, trust } = await fixture();
    const substitutions: Partial<Record<keyof ComputeWorkloadTrustPolicy, string>> = {
      cvmId: "main-runtime-cvm-substitution",
      deploymentIntentSha256: `sha256:${"91".repeat(32)}`,
      releaseAuthoritySha256: `sha256:${"92".repeat(32)}`,
      ceremonyNonce: `0x${"93".repeat(32)}`,
      measurementPolicySetSha256: `sha256:${"94".repeat(32)}`,
      measurementPolicySha256: `sha256:${"95".repeat(32)}`,
      mainRuntimeEvidenceSha256: `sha256:${"96".repeat(32)}`,
    };
    for (const [field, value] of Object.entries(substitutions)) {
      const drifted = { ...trust, [field]: value } as ComputeWorkloadTrustPolicy;
      await expect(
        authenticateComputeWorkloadEncryptionContract(raw, drifted, NOW),
        field,
      ).rejects.toThrow(/release policy/i);
    }
  });

  it("rejects lease aliases that diverge and a verdict issued at challenge expiry", async () => {
    const { raw, trust } = await fixture();

    const driftedVerdictLease = structuredClone(raw);
    driftedVerdictLease.activation.authenticated_verdict.activation_evidence_lease_expires_at -= 1;
    await expect(
      authenticateComputeWorkloadEncryptionContract(driftedVerdictLease, trust, NOW),
    ).rejects.toThrow(/release policy/i);

    const driftedRecipientLease = structuredClone(raw);
    driftedRecipientLease.activation.recipient_evidence_lease_expires_at -= 1;
    await expect(
      authenticateComputeWorkloadEncryptionContract(driftedRecipientLease, trust, NOW),
    ).rejects.toThrow(/release policy/i);

    const completedAtExpiry = structuredClone(raw);
    completedAtExpiry.activation.authenticated_verdict.challenge_expires_at =
      completedAtExpiry.activation.authenticated_verdict.issued_at;
    await expect(
      authenticateComputeWorkloadEncryptionContract(completedAtExpiry, trust, NOW),
    ).rejects.toThrow(/stale|invalid/i);
  });

  it("rejects stale replay and a substituted stable release commitment", async () => {
    const { raw, trust } = await fixture();
    await expect(
      authenticateComputeWorkloadEncryptionContract(raw, trust, NOW + 91),
    ).rejects.toThrow(/stale|invalid/i);

    const substituted = structuredClone(raw);
    substituted.activation.recipient_release_commitment = `sha256:${"bb".repeat(32)}`;
    substituted.recipient.recipient_release_commitment = substituted.activation.recipient_release_commitment;
    substituted.recipient.activation_commitment = await computeWorkloadActivationCommitment(substituted.activation);
    await expect(
      authenticateComputeWorkloadEncryptionContract(substituted, trust, NOW),
    ).rejects.toThrow(/release policy/i);
  });

  it("rejects a self-asserted boolean when the signed activation is absent", async () => {
    const { raw } = await fixture();
    const liar = structuredClone(raw) as unknown as Record<string, unknown>;
    liar.activation = null;
    expect(() => parseComputeWorkloadEncryptionContract(liar)).toThrow(/activation/i);
  });

  it("secret-blinds and pads equal-class workloads without placing plaintext in the request", async () => {
    const { raw, trust } = await fixture();
    const contract = await authenticateComputeWorkloadEncryptionContract(raw, trust, NOW);
    const first = await prepareComputeWorkloadUpload({
      contract,
      principal: { kind: "wallet", projectId: PROJECT_ID, actorId: WALLET },
      idempotencyKey: "workload.browser.0001",
      manifest: inferenceManifest,
      workload: { kind: "inference", prompt: "PRIVATE DNA PROMPT A" },
    });
    const second = await prepareComputeWorkloadUpload({
      contract,
      principal: { kind: "wallet", projectId: PROJECT_ID, actorId: WALLET },
      idempotencyKey: "workload.browser.0002",
      manifest: inferenceManifest,
      workload: { kind: "inference", prompt: "PRIVATE DNA PROMPT B with a longer private observation" },
    });
    expect(decodeBase64url(first.body.envelope.ciphertext)).toHaveLength(4_096 + 16);
    expect(decodeBase64url(second.body.envelope.ciphertext)).toHaveLength(4_096 + 16);
    expect(first.body.workload_commitment).not.toBe(second.body.workload_commitment);
    expect(JSON.stringify(first.body)).not.toContain("PRIVATE DNA PROMPT");
    expect(Object.keys(first.body)).toEqual(["workload_commitment", "manifest", "envelope"]);
  });

  it("keeps the ephemeral X25519 private key non-exportable", async () => {
    const { raw, trust } = await fixture();
    const contract = await authenticateComputeWorkloadEncryptionContract(raw, trust, NOW);
    const generateKey = vi.spyOn(crypto.subtle, "generateKey");
    const exportKey = vi.spyOn(crypto.subtle, "exportKey");
    await prepareComputeWorkloadUpload({
      contract,
      principal: { kind: "wallet", projectId: PROJECT_ID, actorId: WALLET },
      idempotencyKey: "workload.browser.nonexportable.0001",
      manifest: inferenceManifest,
      workload: { kind: "inference", prompt: "PRIVATE NONEXPORTABLE KEY CHECK" },
    });
    expect(generateKey).toHaveBeenCalledWith({ name: "X25519" }, false, ["deriveBits"]);
    const generated = await (generateKey.mock.results[0]?.value as Promise<CryptoKeyPair>);
    expect(generated.privateKey.extractable).toBe(false);
    expect(generated.publicKey.extractable).toBe(true);
    expect(exportKey.mock.calls.some(([, key]) => key.type === "private")).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", generated.privateKey)).rejects.toThrow();
  });

  it("retries the identical ciphertext request and returns the exact dispatch binding", async () => {
    const { raw, trust } = await fixture();
    const contract = await authenticateComputeWorkloadEncryptionContract(raw, trust, NOW);
    const prepared = await prepareComputeWorkloadUpload({
      contract,
      principal: { kind: "wallet", projectId: PROJECT_ID, actorId: WALLET },
      idempotencyKey: "workload.browser.retry.0001",
      manifest: inferenceManifest,
      workload: { kind: "inference", prompt: "PRIVATE RETRY PAYLOAD" },
    });
    const receipt = (created: boolean) => ({
      surface: "compute_workload_ingress_receipt",
      schema_version: 1,
      workload_id: `wrk_${"ab".repeat(16)}`,
      workload_schema: prepared.expected.workloadSchema,
      workload_commitment: prepared.expected.workloadCommitment,
      manifest_commitment: prepared.expected.manifestCommitment,
      ciphertext_sha256: prepared.expected.ciphertextSha256,
      blob_sha256: `sha256:${"cd".repeat(32)}`,
      key_id: prepared.expected.keyId,
      activation_commitment: prepared.expected.activationCommitment,
      recipient_release_commitment: prepared.expected.recipientReleaseCommitment,
      created,
      idempotent_replay: !created,
      ciphertext_egress: false,
      raw_prompt_egress: false,
      raw_examples_egress: false,
      raw_dataset_egress: false,
      raw_output_egress: false,
      provider_dispatch_enabled: false,
    });
    const request = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse(receipt(true)))
      .mockResolvedValueOnce(jsonResponse(receipt(false)));
    const first = await uploadPreparedComputeWorkload("https://delegate.example", "Bearer wallet-session-token-123456", prepared);
    const replay = await uploadPreparedComputeWorkload("https://delegate.example", "Bearer wallet-session-token-123456", prepared);
    expect(first.dispatchBinding).toEqual({
      workloadId: `wrk_${"ab".repeat(16)}`,
      workloadSchema: inferenceManifest.schema,
      manifestCommitment: `0x${prepared.expected.manifestCommitment.slice(7)}`,
      workloadCommitment: `0x${prepared.expected.workloadCommitment.slice(7)}`,
    });
    expect(replay.receipt.idempotent_replay).toBe(true);
    expect(request.mock.calls[0]?.[1]?.body).toBe(request.mock.calls[1]?.[1]?.body);
    expect(String(request.mock.calls[0]?.[1]?.body)).not.toContain("PRIVATE RETRY PAYLOAD");
  });
});
