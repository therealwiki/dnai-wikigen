import {
  recoverMessageAddress,
  type Address,
  type Hex,
} from "viem";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_AAD_BYTES = 8_192;
const MAX_INFERENCE_PROMPT_BYTES = 262_144;
const MAX_SFT_FIELD_BYTES = 32_768;
const MAX_SFT_EXAMPLES = 256;
const SEALED_MAGIC = hexBytes("444e4149574c3100");
const SEALED_HEADER_BYTES = 44;
const WORKLOAD_COMMITMENT_DOMAIN = encoder.encode("dnai-wikigen/compute-workload/v1\0");
const RECIPIENT_RELEASE_COMMITMENT_DOMAIN = encoder.encode("dnai-wikigen/compute-workload-recipient-release/v2\0");
const RECIPIENT_ATTESTATION_DOMAIN = encoder.encode("dnai-wikigen/compute-workload-recipient-attestation/v1\0");
const PROJECT_COMMITMENT_DOMAIN = encoder.encode("dnai-wikigen/compute-workload-project/v1\0");
const PRINCIPAL_COMMITMENT_DOMAIN = encoder.encode("dnai-wikigen/compute-workload-principal/v1\0");
const IDEMPOTENCY_COMMITMENT_DOMAIN = encoder.encode("dnai-wikigen/compute-workload-idempotency/v1\0");
const QVL_VERDICT_DOMAIN = encoder.encode("dnai-wikigen/independent-tdx-verdict/v4\0");
const HKDF_INFO = encoder.encode("dnai-wikigen/compute-workload-ingress/v1");

const ADDRESS = /^0x[0-9a-f]{40}$/;
const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const NONZERO_SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_130 = /^0x[0-9a-f]{130}$/;
const PHALA_APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const RESOURCE_ID = /^[a-z][a-z0-9_]{2,63}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const WORKLOAD_ID = /^wrk_[0-9a-f]{32}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;

export const COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES = Object.freeze({
  "4k": 4_096,
  "16k": 16_384,
  "64k": 65_536,
  "256k": 262_144,
  "1m": 1_048_560,
} as const);

export const COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES = Object.freeze({
  none: [0, 0],
  "1_8": [1, 8],
  "9_32": [9, 32],
  "33_128": [33, 128],
  "129_256": [129, 256],
} as const);

export type ComputeWorkloadPayloadSizeClass = keyof typeof COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES;
export type ComputeWorkloadExampleCountClass = keyof typeof COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES;

export interface ComputeWorkloadManifest {
  schema: "dnai.compute.workload.inference.v1" | "dnai.compute.workload.sft-jsonl.v1";
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  payload_size_class: ComputeWorkloadPayloadSizeClass;
  example_count_class: ComputeWorkloadExampleCountClass;
  max_prefill_tokens: number;
  max_sample_tokens: number;
  max_train_tokens: number;
}

export type ComputePrivateWorkload =
  | { kind: "inference"; prompt: string }
  | { kind: "training"; examples: readonly { prompt: string; completion: string }[] };

export interface ComputeWorkloadPrincipal {
  kind: "wallet" | "credential";
  projectId: string;
  actorId: string;
}

export interface IndependentQvlVerdict {
  schema: "dnai.independent-tdx-verdict.v4";
  verification_method: "intel_tdx_dcap_qvl";
  verified: true;
  chain_id: 84_532;
  domain: "main_runtime_cvm";
  profile: "compute_workload";
  cvm_id: string;
  deployment_intent_sha256: string;
  release_authority_sha256: string;
  ceremony_nonce: Hex;
  measurement_policy_sha256: string;
  release_policy_hash: Hex;
  challenge_id: Hex;
  challenge_digest: Hex;
  challenge_issued_at: number;
  challenge_expires_at: number;
  quote_hash: Hex;
  report_data: Hex;
  compose_hash: Hex;
  app_id: string;
  os_image_hash: string;
  signer_address: Address;
  contract_address: Address;
  issued_at: number;
  activation_evidence_lease_expires_at: number;
  expires_at: number;
  verifier_address: Address;
  verifier_signature: Hex;
}

export interface ComputeWorkloadRecipientAttestation {
  schema: "dnai.compute-workload-recipient-attestation.v1";
  context: "compute_workload";
  audience: "dnai-wikigen:compute-workload-recipient";
  service: "dnai-wikigen";
  protocol: "compute_workload_ingress_v1";
  encryption_public_key: string;
  key_id: string;
  activation_signer_address: Address;
  activation_signer_key_path: "tinker/compute_workload_activation_signer";
  activation_signer_custody: "dstack_derived_compute_workload_activation_signer";
  chain_id: 84_532;
  compute_vault_address: Address;
  compute_vault_runtime_code_hash: Hex;
  fresh_contract_deployment_receipt_sha256: Hex;
}

export interface ComputeWorkloadRecipientActivation {
  schema: "dnai.compute.workload-recipient-activation.v3";
  chain_id: 84_532;
  domain: "main_runtime_cvm";
  profile: "compute_workload";
  cvm_id: string;
  deployment_intent_sha256: string;
  release_authority_sha256: string;
  ceremony_nonce: Hex;
  measurement_policy_set_sha256: string;
  measurement_policy_sha256: string;
  main_runtime_evidence_sha256: string;
  recipient_key_id: string;
  report_data: Hex;
  compose_hash: Hex;
  app_id: string;
  os_image_hash: string;
  release_policy_hash: Hex;
  quote_hash: Hex;
  verifier_address: Address;
  verdict_digest: Hex;
  issued_at: number;
  recipient_evidence_lease_expires_at: number;
  expires_at: number;
  authenticated_at: number;
  recipient_release_commitment: string;
  recipient_attestation: ComputeWorkloadRecipientAttestation;
  authenticated_verdict: IndependentQvlVerdict;
}

export interface ComputeWorkloadEncryptionContract {
  surface: "compute_workload_encryption_contract";
  schema_version: 1;
  status: "live";
  upload_enabled: true;
  reason: "verified_recipient_activation_current";
  protocol: {
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
    encoding: "base64url-nopad";
    hkdf_hash: "SHA-256";
    hkdf_salt: "SHA-256(canonical_aad_bytes)";
    hkdf_info_utf8: "dnai-wikigen/compute-workload-ingress/v1";
    aes_gcm_nonce_bytes: 12;
    aes_gcm_tag_bytes: 16;
    additional_authenticated_data: "canonical_aad_bytes";
    sealed_plaintext_frame: {
      magic_hex: "444e4149574c3100";
      payload_length_bytes: 4;
      blinding_bytes: 32;
      blinding_source: "client_csprng";
      padding_source: "client_csprng";
      exact_payload_length_private: true;
      exact_example_count_private: true;
    };
    workload_commitment: string;
  };
  recipient: {
    encryption_public_key: string;
    key_id: string;
    report_context: "compute_workload";
    report_data: string;
    report_data_sha256: string;
    activation_commitment: string;
    recipient_release_commitment: string;
    activation_expires_at: number;
    independent_tdx_verdict_authenticated: true;
  };
  activation: ComputeWorkloadRecipientActivation;
  workload_schemas: Record<string, unknown>;
  privacy_classes: {
    payload_size_bytes: Record<ComputeWorkloadPayloadSizeClass, number>;
    example_count_ranges: Record<ComputeWorkloadExampleCountClass, [number, number]>;
    ciphertext_length_reveals_only_payload_size_class: true;
    commitment_is_secret_blinded: true;
  };
  limits: {
    max_aad_bytes: number;
    max_ciphertext_bytes: number;
    max_envelopes: number;
    idempotency_key_max_bytes: number;
  };
  gates: {
    real_dstack_required: true;
    simulator_rejected: true;
    fresh_independent_qvl_verdict_required: true;
    release_and_measurement_binding_required: true;
    matching_recipient_key_and_report_data_required: true;
    wallet_or_workloads_create_device_scope_required: true;
    provider_dispatch_enabled: false;
  };
  plaintext_fields_accepted: false;
  ciphertext_egress: false;
  raw_prompt_egress: false;
  raw_examples_egress: false;
  raw_dataset_egress: false;
  raw_output_egress: false;
}

export interface ComputeWorkloadTrustPolicy {
  trustedVerifierAddresses: readonly string[];
  cvmId: string;
  deploymentIntentSha256: string;
  releaseAuthoritySha256: string;
  ceremonyNonce: string;
  measurementPolicySetSha256: string;
  measurementPolicySha256: string;
  mainRuntimeEvidenceSha256: string;
  releasePolicyHash: string;
  composeHash: string;
  appId: string;
  osImageHash: string;
  activationSignerAddress: string;
  chainId: number;
  contractAddress: string;
  vaultRuntimeCodeHash: string;
  freshDeploymentReceiptSha256: string;
  maxVerdictAgeSeconds?: number;
  revokedQuoteHashes?: readonly string[];
}

declare const authenticatedContractBrand: unique symbol;
export type AuthenticatedComputeWorkloadContract = ComputeWorkloadEncryptionContract & {
  readonly [authenticatedContractBrand]: true;
};

export interface ComputeWorkloadEnvelope {
  schema_version: 1;
  algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
  encoding: "base64url-nopad";
  key_id: string;
  attestation_report_data: string;
  activation_commitment: string;
  aad: string;
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
}

export interface PreparedComputeWorkloadUpload {
  readonly projectId: string;
  readonly idempotencyKey: string;
  readonly body: {
    workload_commitment: string;
    manifest: ComputeWorkloadManifest;
    envelope: ComputeWorkloadEnvelope;
  };
  readonly expected: {
    workloadSchema: ComputeWorkloadManifest["schema"];
    workloadCommitment: string;
    manifestCommitment: string;
    ciphertextSha256: string;
    keyId: string;
    activationCommitment: string;
    recipientReleaseCommitment: string;
  };
}

export interface ComputeWorkloadIngressReceipt {
  surface: "compute_workload_ingress_receipt";
  schema_version: 1;
  workload_id: string;
  workload_schema: ComputeWorkloadManifest["schema"];
  workload_commitment: string;
  manifest_commitment: string;
  ciphertext_sha256: string;
  blob_sha256: string;
  key_id: string;
  activation_commitment: string;
  recipient_release_commitment: string;
  created: boolean;
  idempotent_replay: boolean;
  ciphertext_egress: false;
  raw_prompt_egress: false;
  raw_examples_egress: false;
  raw_dataset_egress: false;
  raw_output_egress: false;
  provider_dispatch_enabled: false;
}

export interface ComputeWorkloadDispatchBinding {
  workloadId: string;
  workloadSchema: ComputeWorkloadManifest["schema"];
  manifestCommitment: Hex;
  workloadCommitment: Hex;
}

export interface ComputeWorkloadWireBinding {
  projectCommitment: string;
  actorCommitment: string;
  idempotencyHash: string;
  manifestCommitment: string;
  workloadCommitment: string;
  aad: Uint8Array;
  aadBase64url: string;
  aadSha256: string;
}

export class ComputeWorkloadWireError extends Error {
  constructor(message = "Compute workload encryption contract is invalid") {
    super(message);
    this.name = "ComputeWorkloadWireError";
  }
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function asciiJsonString(value: string): string {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22) output += '\\"';
    else if (code === 0x5c) output += "\\\\";
    else if (code === 0x08) output += "\\b";
    else if (code === 0x0c) output += "\\f";
    else if (code === 0x0a) output += "\\n";
    else if (code === 0x0d) output += "\\r";
    else if (code === 0x09) output += "\\t";
    else if (code < 0x20 || code > 0x7e) output += `\\u${code.toString(16).padStart(4, "0")}`;
    else output += value[index];
  }
  return `${output}"`;
}

function assertUnicodeScalarString(value: string, label: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new ComputeWorkloadWireError(`${label} contains an unpaired surrogate`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new ComputeWorkloadWireError(`${label} contains an unpaired surrogate`);
    }
  }
}

export function canonicalAsciiJson(value: Json): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return asciiJsonString(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new ComputeWorkloadWireError("Canonical JSON number must be a safe integer");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalAsciiJson).join(",")}]`;
  if (typeof value !== "object") throw new ComputeWorkloadWireError("Canonical JSON value is invalid");
  return `{${Object.keys(value).sort().map((key) => {
    const nested = value[key];
    if (nested === undefined) throw new ComputeWorkloadWireError("Canonical JSON cannot contain undefined");
    return `${asciiJsonString(key)}:${canonicalAsciiJson(nested)}`;
  }).join(",")}}`;
}

function canonicalBytes(value: Json): Uint8Array {
  return encoder.encode(canonicalAsciiJson(value));
}

function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
  let offset = 0;
  values.forEach((value) => {
    result.set(value, offset);
    offset += value.length;
  });
  return result;
}

function hexBytes(value: string): Uint8Array {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^(?:[0-9a-f]{2})*$/.test(normalized)) throw new ComputeWorkloadWireError("Hex value is invalid");
  return Uint8Array.from(normalized.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function bytesHex(value: Uint8Array, prefix = false): string {
  const encoded = Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return prefix ? `0x${encoded}` : encoded;
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

async function digestBytes(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ownedArrayBuffer(value)));
}

async function sha256Commitment(...values: readonly Uint8Array[]): Promise<string> {
  return `sha256:${bytesHex(await digestBytes(concatBytes(...values)))}`;
}

async function bytes32Digest(...values: readonly Uint8Array[]): Promise<Hex> {
  return bytesHex(await digestBytes(concatBytes(...values)), true) as Hex;
}

function base64url(value: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ComputeWorkloadWireError(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ComputeWorkloadWireError(`${label} has missing or unexpected fields`);
  }
  return record;
}

function stringValue(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new ComputeWorkloadWireError(`${label} is invalid`);
  return value;
}

function integerValue(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new ComputeWorkloadWireError(`${label} is invalid`);
  }
  return value as number;
}

function exactValue<T>(value: unknown, expected: T, label: string): T {
  if (value !== expected) throw new ComputeWorkloadWireError(`${label} is invalid`);
  return expected;
}

function nonzeroBytes32(value: unknown, label: string): Hex {
  return stringValue(value, NONZERO_BYTES32, label) as Hex;
}

function lowerAddress(value: unknown, label: string): Address {
  return stringValue(value, ADDRESS, label) as Address;
}

function nonzeroLowerAddress(value: unknown, label: string): Address {
  const address = lowerAddress(value, label);
  if (address === `0x${"0".repeat(40)}`) throw new ComputeWorkloadWireError(`${label} is invalid`);
  return address;
}

function parseVerdict(value: unknown): IndependentQvlVerdict {
  const verdict = exactObject(value, [
    "schema", "verification_method", "verified", "chain_id", "domain", "profile",
    "cvm_id", "deployment_intent_sha256", "release_authority_sha256",
    "ceremony_nonce", "measurement_policy_sha256", "release_policy_hash",
    "challenge_id", "challenge_digest", "challenge_issued_at", "challenge_expires_at",
    "quote_hash", "report_data", "compose_hash", "app_id", "os_image_hash",
    "signer_address", "contract_address", "issued_at",
    "activation_evidence_lease_expires_at", "expires_at",
    "verifier_address", "verifier_signature",
  ], "QVL verdict");
  const appId = verdict.app_id;
  if (typeof appId !== "string" || !PHALA_APP_ID.test(appId)) throw new ComputeWorkloadWireError("QVL app id is invalid");
  return {
    schema: exactValue(verdict.schema, "dnai.independent-tdx-verdict.v4", "QVL verdict schema"),
    verification_method: exactValue(verdict.verification_method, "intel_tdx_dcap_qvl", "QVL verification method"),
    verified: exactValue(verdict.verified, true, "QVL verified state"),
    chain_id: exactValue(verdict.chain_id, 84_532, "QVL chain id"),
    domain: exactValue(verdict.domain, "main_runtime_cvm", "QVL domain"),
    profile: exactValue(verdict.profile, "compute_workload", "QVL profile"),
    cvm_id: stringValue(verdict.cvm_id, CVM_ID, "QVL CVM id"),
    deployment_intent_sha256: stringValue(
      verdict.deployment_intent_sha256,
      NONZERO_SHA256,
      "QVL deployment intent",
    ),
    release_authority_sha256: stringValue(
      verdict.release_authority_sha256,
      NONZERO_SHA256,
      "QVL release authority",
    ),
    ceremony_nonce: nonzeroBytes32(verdict.ceremony_nonce, "QVL ceremony nonce"),
    measurement_policy_sha256: stringValue(
      verdict.measurement_policy_sha256,
      NONZERO_SHA256,
      "QVL measurement policy",
    ),
    release_policy_hash: nonzeroBytes32(verdict.release_policy_hash, "QVL release policy"),
    challenge_id: nonzeroBytes32(verdict.challenge_id, "QVL challenge id"),
    challenge_digest: nonzeroBytes32(verdict.challenge_digest, "QVL challenge digest"),
    challenge_issued_at: integerValue(verdict.challenge_issued_at, 1, 4_102_444_800, "QVL challenge issued time"),
    challenge_expires_at: integerValue(verdict.challenge_expires_at, 1, 4_102_444_800, "QVL challenge expiry"),
    quote_hash: nonzeroBytes32(verdict.quote_hash, "QVL quote hash"),
    report_data: nonzeroBytes32(verdict.report_data, "QVL report data"),
    compose_hash: nonzeroBytes32(verdict.compose_hash, "QVL compose hash"),
    app_id: appId,
    os_image_hash: stringValue(verdict.os_image_hash, /^(?!0{64}$)[0-9a-f]{64}$/, "QVL OS image hash"),
    signer_address: nonzeroLowerAddress(verdict.signer_address, "QVL signer"),
    contract_address: nonzeroLowerAddress(verdict.contract_address, "QVL contract"),
    issued_at: integerValue(verdict.issued_at, 1, 4_102_444_800, "QVL issued time"),
    activation_evidence_lease_expires_at: integerValue(
      verdict.activation_evidence_lease_expires_at,
      1,
      4_102_444_800,
      "QVL activation evidence lease expiry",
    ),
    expires_at: integerValue(verdict.expires_at, 1, 4_102_444_800, "QVL expiry"),
    verifier_address: nonzeroLowerAddress(verdict.verifier_address, "QVL verifier"),
    verifier_signature: stringValue(verdict.verifier_signature, HEX_130, "QVL verifier signature") as Hex,
  };
}

function parseRecipientAttestation(value: unknown): ComputeWorkloadRecipientAttestation {
  const attestation = exactObject(value, [
    "schema", "context", "audience", "service", "protocol",
    "encryption_public_key", "key_id", "activation_signer_address",
    "activation_signer_key_path", "activation_signer_custody", "chain_id",
    "compute_vault_address", "compute_vault_runtime_code_hash",
    "fresh_contract_deployment_receipt_sha256",
  ], "Compute workload recipient attestation");
  return {
    schema: exactValue(
      attestation.schema,
      "dnai.compute-workload-recipient-attestation.v1",
      "recipient attestation schema",
    ),
    context: exactValue(attestation.context, "compute_workload", "recipient attestation context"),
    audience: exactValue(
      attestation.audience,
      "dnai-wikigen:compute-workload-recipient",
      "recipient attestation audience",
    ),
    service: exactValue(attestation.service, "dnai-wikigen", "recipient attestation service"),
    protocol: exactValue(
      attestation.protocol,
      "compute_workload_ingress_v1",
      "recipient attestation protocol",
    ),
    encryption_public_key: stringValue(
      attestation.encryption_public_key,
      HEX_64,
      "recipient attestation public key",
    ),
    key_id: stringValue(attestation.key_id, NONZERO_SHA256, "recipient attestation key id"),
    activation_signer_address: nonzeroLowerAddress(
      attestation.activation_signer_address,
      "recipient activation signer",
    ),
    activation_signer_key_path: exactValue(
      attestation.activation_signer_key_path,
      "tinker/compute_workload_activation_signer",
      "recipient activation signer key path",
    ),
    activation_signer_custody: exactValue(
      attestation.activation_signer_custody,
      "dstack_derived_compute_workload_activation_signer",
      "recipient activation signer custody",
    ),
    chain_id: exactValue(attestation.chain_id, 84_532, "recipient attestation chain id"),
    compute_vault_address: nonzeroLowerAddress(
      attestation.compute_vault_address,
      "recipient attestation ComputeVault",
    ),
    compute_vault_runtime_code_hash: nonzeroBytes32(
      attestation.compute_vault_runtime_code_hash,
      "recipient attestation ComputeVault runtime hash",
    ),
    fresh_contract_deployment_receipt_sha256: nonzeroBytes32(
      attestation.fresh_contract_deployment_receipt_sha256,
      "recipient attestation fresh deployment receipt",
    ),
  };
}

function parseActivation(value: unknown): ComputeWorkloadRecipientActivation {
  const activation = exactObject(value, [
    "schema", "chain_id", "domain", "profile", "cvm_id",
    "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce",
    "measurement_policy_set_sha256", "measurement_policy_sha256",
    "main_runtime_evidence_sha256", "recipient_key_id", "report_data",
    "compose_hash", "app_id", "os_image_hash", "release_policy_hash",
    "quote_hash", "verifier_address", "verdict_digest", "issued_at",
    "recipient_evidence_lease_expires_at", "expires_at", "authenticated_at",
    "recipient_release_commitment", "recipient_attestation",
    "authenticated_verdict",
  ], "Compute workload recipient activation");
  return {
    schema: exactValue(activation.schema, "dnai.compute.workload-recipient-activation.v3", "activation schema"),
    chain_id: exactValue(activation.chain_id, 84_532, "activation chain id"),
    domain: exactValue(activation.domain, "main_runtime_cvm", "activation domain"),
    profile: exactValue(activation.profile, "compute_workload", "activation profile"),
    cvm_id: stringValue(activation.cvm_id, CVM_ID, "activation CVM id"),
    deployment_intent_sha256: stringValue(
      activation.deployment_intent_sha256,
      NONZERO_SHA256,
      "activation deployment intent",
    ),
    release_authority_sha256: stringValue(
      activation.release_authority_sha256,
      NONZERO_SHA256,
      "activation release authority",
    ),
    ceremony_nonce: nonzeroBytes32(activation.ceremony_nonce, "activation ceremony nonce"),
    measurement_policy_set_sha256: stringValue(
      activation.measurement_policy_set_sha256,
      NONZERO_SHA256,
      "activation measurement policy set",
    ),
    measurement_policy_sha256: stringValue(
      activation.measurement_policy_sha256,
      NONZERO_SHA256,
      "activation measurement policy",
    ),
    main_runtime_evidence_sha256: stringValue(
      activation.main_runtime_evidence_sha256,
      NONZERO_SHA256,
      "activation main runtime evidence",
    ),
    recipient_key_id: stringValue(activation.recipient_key_id, NONZERO_SHA256, "activation recipient key"),
    report_data: nonzeroBytes32(activation.report_data, "activation report data"),
    compose_hash: nonzeroBytes32(activation.compose_hash, "activation compose hash"),
    app_id: stringValue(activation.app_id, PHALA_APP_ID, "activation app id"),
    os_image_hash: stringValue(activation.os_image_hash, /^(?!0{64}$)[0-9a-f]{64}$/, "activation OS image hash"),
    release_policy_hash: nonzeroBytes32(activation.release_policy_hash, "activation release policy"),
    quote_hash: nonzeroBytes32(activation.quote_hash, "activation quote hash"),
    verifier_address: nonzeroLowerAddress(activation.verifier_address, "activation verifier"),
    verdict_digest: nonzeroBytes32(activation.verdict_digest, "activation verdict digest"),
    issued_at: integerValue(activation.issued_at, 1, 4_102_444_800, "activation issued time"),
    recipient_evidence_lease_expires_at: integerValue(
      activation.recipient_evidence_lease_expires_at,
      1,
      4_102_444_800,
      "activation recipient evidence lease expiry",
    ),
    expires_at: integerValue(activation.expires_at, 1, 4_102_444_800, "activation expiry"),
    authenticated_at: integerValue(activation.authenticated_at, 1, 4_102_444_800, "activation authenticated time"),
    recipient_release_commitment: stringValue(activation.recipient_release_commitment, NONZERO_SHA256, "activation recipient release commitment"),
    recipient_attestation: parseRecipientAttestation(activation.recipient_attestation),
    authenticated_verdict: parseVerdict(activation.authenticated_verdict),
  };
}

function parseProtocol(value: unknown): ComputeWorkloadEncryptionContract["protocol"] {
  const protocol = exactObject(value, [
    "algorithm", "encoding", "hkdf_hash", "hkdf_salt", "hkdf_info_utf8",
    "aes_gcm_nonce_bytes", "aes_gcm_tag_bytes", "additional_authenticated_data",
    "sealed_plaintext_frame", "workload_commitment",
  ], "Compute workload protocol");
  const frame = exactObject(protocol.sealed_plaintext_frame, [
    "magic_hex", "payload_length_bytes", "blinding_bytes", "blinding_source",
    "padding_source", "exact_payload_length_private", "exact_example_count_private",
  ], "Compute workload sealed frame");
  return {
    algorithm: exactValue(protocol.algorithm, "X25519-HKDF-SHA256-AES-256-GCM", "workload algorithm"),
    encoding: exactValue(protocol.encoding, "base64url-nopad", "workload encoding"),
    hkdf_hash: exactValue(protocol.hkdf_hash, "SHA-256", "workload HKDF hash"),
    hkdf_salt: exactValue(protocol.hkdf_salt, "SHA-256(canonical_aad_bytes)", "workload HKDF salt"),
    hkdf_info_utf8: exactValue(protocol.hkdf_info_utf8, "dnai-wikigen/compute-workload-ingress/v1", "workload HKDF info"),
    aes_gcm_nonce_bytes: exactValue(protocol.aes_gcm_nonce_bytes, 12, "workload nonce size"),
    aes_gcm_tag_bytes: exactValue(protocol.aes_gcm_tag_bytes, 16, "workload tag size"),
    additional_authenticated_data: exactValue(protocol.additional_authenticated_data, "canonical_aad_bytes", "workload AAD"),
    sealed_plaintext_frame: {
      magic_hex: exactValue(frame.magic_hex, "444e4149574c3100", "workload frame magic"),
      payload_length_bytes: exactValue(frame.payload_length_bytes, 4, "workload private length size"),
      blinding_bytes: exactValue(frame.blinding_bytes, 32, "workload blind size"),
      blinding_source: exactValue(frame.blinding_source, "client_csprng", "workload blind source"),
      padding_source: exactValue(frame.padding_source, "client_csprng", "workload padding source"),
      exact_payload_length_private: exactValue(frame.exact_payload_length_private, true, "workload private length boundary"),
      exact_example_count_private: exactValue(frame.exact_example_count_private, true, "workload private count boundary"),
    },
    workload_commitment: exactValue(
      protocol.workload_commitment,
      "SHA-256(domain || canonical_manifest || 0x00 || secret_blinding || 0x00 || private_payload)",
      "workload commitment scheme",
    ),
  };
}

function parseSchemaDescriptors(value: unknown): Record<string, unknown> {
  const schemas = exactObject(value, ["inference", "training"], "Compute workload schemas");
  const inference = exactObject(schemas.inference, ["schema", "payload_schema", "recipe", "max_content_bytes", "max_prefill_tokens", "max_sample_tokens"], "inference workload schema");
  exactValue(inference.schema, "dnai.compute.workload.inference.v1", "inference schema");
  exactValue(inference.payload_schema, "dnai.compute.inference-prompt.v1", "inference payload schema");
  exactValue(inference.recipe, "qwen3_8b_bounded", "inference recipe");
  exactValue(inference.max_content_bytes, 262_144, "inference maximum content bytes");
  exactValue(inference.max_prefill_tokens, 32_768, "inference prefill cap");
  exactValue(inference.max_sample_tokens, 4_096, "inference sample cap");
  const training = exactObject(schemas.training, ["schema", "line_fields", "recipe", "max_content_bytes", "max_examples", "max_field_bytes", "max_train_tokens"], "training workload schema");
  exactValue(training.schema, "dnai.compute.workload.sft-jsonl.v1", "training schema");
  exactValue(training.recipe, "qwen3_8b_lora_r32", "training recipe");
  exactValue(training.max_content_bytes, 1_048_516, "training maximum content bytes");
  exactValue(training.max_examples, 256, "training maximum examples");
  exactValue(training.max_field_bytes, 32_768, "training maximum field bytes");
  exactValue(training.max_train_tokens, 10_000_000, "training token cap");
  if (!Array.isArray(training.line_fields) || training.line_fields.length !== 2 || training.line_fields[0] !== "completion" || training.line_fields[1] !== "prompt") {
    throw new ComputeWorkloadWireError("training JSONL fields are invalid");
  }
  return { inference, training };
}

export function parseComputeWorkloadEncryptionContract(value: unknown): ComputeWorkloadEncryptionContract {
  const root = exactObject(value, [
    "surface", "schema_version", "status", "upload_enabled", "reason", "protocol",
    "recipient", "activation", "workload_schemas", "privacy_classes", "limits", "gates",
    "plaintext_fields_accepted", "ciphertext_egress", "raw_prompt_egress",
    "raw_examples_egress", "raw_dataset_egress", "raw_output_egress",
  ], "Compute workload encryption contract");
  exactValue(root.surface, "compute_workload_encryption_contract", "workload surface");
  exactValue(root.schema_version, 1, "workload contract schema");
  exactValue(root.status, "live", "workload contract status");
  exactValue(root.upload_enabled, true, "workload upload gate");
  exactValue(root.reason, "verified_recipient_activation_current", "workload activation reason");
  const protocol = parseProtocol(root.protocol);
  const activation = parseActivation(root.activation);
  const recipient = exactObject(root.recipient, [
    "encryption_public_key", "key_id", "report_context", "report_data",
    "report_data_sha256", "activation_commitment", "activation_expires_at",
    "recipient_release_commitment",
    "independent_tdx_verdict_authenticated",
  ], "Compute workload recipient");
  const privacy = exactObject(root.privacy_classes, [
    "payload_size_bytes", "example_count_ranges",
    "ciphertext_length_reveals_only_payload_size_class", "commitment_is_secret_blinded",
  ], "Compute workload privacy classes");
  const sizes = exactObject(privacy.payload_size_bytes, ["4k", "16k", "64k", "256k", "1m"], "Compute workload payload classes");
  Object.entries(COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES).forEach(([key, expected]) => exactValue(sizes[key], expected, `payload class ${key}`));
  const ranges = exactObject(privacy.example_count_ranges, ["none", "1_8", "9_32", "33_128", "129_256"], "Compute workload count classes");
  Object.entries(COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES).forEach(([key, expected]) => {
    const actual = ranges[key];
    if (!Array.isArray(actual) || actual.length !== 2 || actual[0] !== expected[0] || actual[1] !== expected[1]) throw new ComputeWorkloadWireError(`example count class ${key} is invalid`);
  });
  const limits = exactObject(root.limits, ["max_aad_bytes", "max_ciphertext_bytes", "max_envelopes", "idempotency_key_max_bytes"], "Compute workload limits");
  exactValue(limits.max_aad_bytes, 8_192, "workload AAD limit");
  exactValue(limits.max_ciphertext_bytes, 1_048_576, "workload ciphertext limit");
  exactValue(limits.idempotency_key_max_bytes, 128, "workload idempotency limit");
  integerValue(limits.max_envelopes, 1, 10_000, "workload envelope capacity");
  const gates = exactObject(root.gates, [
    "real_dstack_required", "simulator_rejected", "fresh_independent_qvl_verdict_required",
    "release_and_measurement_binding_required", "matching_recipient_key_and_report_data_required",
    "wallet_or_workloads_create_device_scope_required", "provider_dispatch_enabled",
  ], "Compute workload gates");
  ["real_dstack_required", "simulator_rejected", "fresh_independent_qvl_verdict_required", "release_and_measurement_binding_required", "matching_recipient_key_and_report_data_required", "wallet_or_workloads_create_device_scope_required"].forEach((key) => exactValue(gates[key], true, `workload gate ${key}`));
  exactValue(gates.provider_dispatch_enabled, false, "provider dispatch gate");
  ["plaintext_fields_accepted", "ciphertext_egress", "raw_prompt_egress", "raw_examples_egress", "raw_dataset_egress", "raw_output_egress"].forEach((key) => exactValue(root[key], false, `workload boundary ${key}`));
  exactValue(privacy.ciphertext_length_reveals_only_payload_size_class, true, "ciphertext length privacy");
  exactValue(privacy.commitment_is_secret_blinded, true, "commitment privacy");
  return {
    surface: "compute_workload_encryption_contract",
    schema_version: 1,
    status: "live",
    upload_enabled: true,
    reason: "verified_recipient_activation_current",
    protocol,
    recipient: {
      encryption_public_key: stringValue(recipient.encryption_public_key, HEX_64, "recipient public key"),
      key_id: stringValue(recipient.key_id, SHA256, "recipient key id"),
      report_context: exactValue(recipient.report_context, "compute_workload", "recipient report context"),
      report_data: stringValue(recipient.report_data, HEX_64, "recipient report data"),
      report_data_sha256: stringValue(recipient.report_data_sha256, SHA256, "recipient report data hash"),
      activation_commitment: stringValue(recipient.activation_commitment, SHA256, "recipient activation commitment"),
      recipient_release_commitment: stringValue(recipient.recipient_release_commitment, SHA256, "recipient release commitment"),
      activation_expires_at: integerValue(recipient.activation_expires_at, 1, 4_102_444_800, "recipient activation expiry"),
      independent_tdx_verdict_authenticated: exactValue(recipient.independent_tdx_verdict_authenticated, true, "recipient QVL authentication"),
    },
    activation,
    workload_schemas: parseSchemaDescriptors(root.workload_schemas),
    privacy_classes: {
      payload_size_bytes: { ...COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES },
      example_count_ranges: {
        none: [0, 0], "1_8": [1, 8], "9_32": [9, 32], "33_128": [33, 128], "129_256": [129, 256],
      },
      ciphertext_length_reveals_only_payload_size_class: true,
      commitment_is_secret_blinded: true,
    },
    limits: { max_aad_bytes: 8_192, max_ciphertext_bytes: 1_048_576, max_envelopes: limits.max_envelopes as number, idempotency_key_max_bytes: 128 },
    gates: {
      real_dstack_required: true, simulator_rejected: true, fresh_independent_qvl_verdict_required: true,
      release_and_measurement_binding_required: true, matching_recipient_key_and_report_data_required: true,
      wallet_or_workloads_create_device_scope_required: true, provider_dispatch_enabled: false,
    },
    plaintext_fields_accepted: false, ciphertext_egress: false, raw_prompt_egress: false,
    raw_examples_egress: false, raw_dataset_egress: false, raw_output_egress: false,
  };
}

function verdictDigestPayload(verdict: IndependentQvlVerdict): Json {
  const { verifier_signature: _signature, ...payload } = verdict;
  return payload as unknown as Json;
}

export async function computeIndependentQvlVerdictDigest(verdict: IndependentQvlVerdict): Promise<Hex> {
  return bytes32Digest(QVL_VERDICT_DOMAIN, canonicalBytes(verdictDigestPayload(verdict)));
}

export async function computeWorkloadActivationCommitment(
  activation: ComputeWorkloadRecipientActivation,
): Promise<string> {
  return sha256Commitment(canonicalBytes(activation as unknown as Json));
}

export async function computeWorkloadRecipientReleaseCommitment(
  activation: Pick<
    ComputeWorkloadRecipientActivation,
    | "chain_id"
    | "domain"
    | "profile"
    | "cvm_id"
    | "deployment_intent_sha256"
    | "release_authority_sha256"
    | "ceremony_nonce"
    | "measurement_policy_set_sha256"
    | "measurement_policy_sha256"
    | "main_runtime_evidence_sha256"
    | "recipient_key_id"
    | "report_data"
    | "compose_hash"
    | "app_id"
    | "os_image_hash"
    | "release_policy_hash"
    | "verifier_address"
    | "recipient_attestation"
    | "authenticated_verdict"
  >,
): Promise<string> {
  const verdict = activation.authenticated_verdict;
  return sha256Commitment(
    RECIPIENT_RELEASE_COMMITMENT_DOMAIN,
    canonicalBytes({
      schema: "dnai.compute.workload-recipient-release.v2",
      chain_id: activation.chain_id,
      domain: activation.domain,
      profile: activation.profile,
      cvm_id: activation.cvm_id,
      deployment_intent_sha256: activation.deployment_intent_sha256,
      release_authority_sha256: activation.release_authority_sha256,
      ceremony_nonce: activation.ceremony_nonce,
      measurement_policy_set_sha256: activation.measurement_policy_set_sha256,
      measurement_policy_sha256: activation.measurement_policy_sha256,
      main_runtime_evidence_sha256: activation.main_runtime_evidence_sha256,
      recipient_key_id: activation.recipient_key_id,
      report_data: activation.report_data,
      compose_hash: activation.compose_hash,
      app_id: activation.app_id,
      os_image_hash: activation.os_image_hash,
      release_policy_hash: activation.release_policy_hash,
      verifier_address: activation.verifier_address,
      verification_method: verdict.verification_method,
      signer_address: verdict.signer_address,
      contract_address: verdict.contract_address,
      recipient_attestation: activation.recipient_attestation as unknown as Json,
    }),
  );
}

export async function computeWorkloadRecipientKeyId(publicKeyHex: string): Promise<string> {
  const publicKey = hexBytes(stringValue(publicKeyHex, HEX_64, "recipient public key"));
  return sha256Commitment(publicKey);
}

export async function computeWorkloadRecipientBindings(
  publicKeyHex: string,
  attestation: ComputeWorkloadRecipientAttestation,
): Promise<{
  keyId: string;
  reportData: string;
  reportDataBytes32: Hex;
  reportDataSha256: string;
}> {
  const publicKey = hexBytes(stringValue(publicKeyHex, HEX_64, "recipient public key"));
  const keyId = await sha256Commitment(publicKey);
  const parsedAttestation = parseRecipientAttestation(attestation);
  if (
    parsedAttestation.encryption_public_key !== publicKeyHex
    || parsedAttestation.key_id !== keyId
  ) throw new ComputeWorkloadWireError("Compute workload recipient attestation does not match its encryption key");
  const reportDataRaw = await digestBytes(concatBytes(
    RECIPIENT_ATTESTATION_DOMAIN,
    canonicalBytes(parsedAttestation as unknown as Json),
  ));
  return {
    keyId,
    reportData: bytesHex(reportDataRaw),
    reportDataBytes32: bytesHex(reportDataRaw, true) as Hex,
    reportDataSha256: await sha256Commitment(reportDataRaw),
  };
}

function normalizedTrustPolicy(policy: ComputeWorkloadTrustPolicy): Required<ComputeWorkloadTrustPolicy> {
  const trustedVerifierAddresses = policy.trustedVerifierAddresses.map((value) => value.toLowerCase());
  if (trustedVerifierAddresses.length < 1 || trustedVerifierAddresses.some((value) => !ADDRESS.test(value))) throw new ComputeWorkloadWireError("trusted QVL verifier set is invalid");
  const maxVerdictAgeSeconds = policy.maxVerdictAgeSeconds ?? 300;
  if (!Number.isSafeInteger(maxVerdictAgeSeconds) || maxVerdictAgeSeconds < 1 || maxVerdictAgeSeconds > 300) throw new ComputeWorkloadWireError("QVL maximum verdict age is invalid");
  const revokedQuoteHashes = (policy.revokedQuoteHashes ?? []).map((value) => value.toLowerCase());
  if (revokedQuoteHashes.some((value) => !NONZERO_BYTES32.test(value))) throw new ComputeWorkloadWireError("revoked QVL quote set is invalid");
  return {
    trustedVerifierAddresses,
    cvmId: stringValue(policy.cvmId, CVM_ID, "trusted main-runtime CVM id"),
    deploymentIntentSha256: stringValue(
      policy.deploymentIntentSha256,
      NONZERO_SHA256,
      "trusted deployment intent",
    ),
    releaseAuthoritySha256: stringValue(
      policy.releaseAuthoritySha256,
      NONZERO_SHA256,
      "trusted release authority",
    ),
    ceremonyNonce: nonzeroBytes32(
      policy.ceremonyNonce.toLowerCase(),
      "trusted ceremony nonce",
    ),
    measurementPolicySetSha256: stringValue(
      policy.measurementPolicySetSha256,
      NONZERO_SHA256,
      "trusted measurement policy set",
    ),
    measurementPolicySha256: stringValue(
      policy.measurementPolicySha256,
      NONZERO_SHA256,
      "trusted compute-workload measurement policy",
    ),
    mainRuntimeEvidenceSha256: stringValue(
      policy.mainRuntimeEvidenceSha256,
      NONZERO_SHA256,
      "trusted main-runtime evidence",
    ),
    releasePolicyHash: nonzeroBytes32(policy.releasePolicyHash.toLowerCase(), "trusted release policy"),
    composeHash: nonzeroBytes32(policy.composeHash.toLowerCase(), "trusted compose hash"),
    appId: stringValue(policy.appId, PHALA_APP_ID, "trusted Phala app id"),
    osImageHash: stringValue(policy.osImageHash.toLowerCase(), /^(?!0{64}$)[0-9a-f]{64}$/, "trusted OS image hash"),
    activationSignerAddress: lowerAddress(
      policy.activationSignerAddress.toLowerCase(),
      "trusted workload activation signer",
    ),
    chainId: integerValue(policy.chainId, 1, Number.MAX_SAFE_INTEGER, "trusted chain id"),
    contractAddress: lowerAddress(policy.contractAddress.toLowerCase(), "trusted contract"),
    vaultRuntimeCodeHash: nonzeroBytes32(
      policy.vaultRuntimeCodeHash.toLowerCase(),
      "trusted ComputeVault runtime hash",
    ),
    freshDeploymentReceiptSha256: nonzeroBytes32(
      policy.freshDeploymentReceiptSha256.toLowerCase(),
      "trusted fresh deployment receipt",
    ),
    maxVerdictAgeSeconds,
    revokedQuoteHashes,
  };
}

export async function authenticateComputeWorkloadEncryptionContract(
  raw: unknown,
  trustPolicy: ComputeWorkloadTrustPolicy,
  now = Math.floor(Date.now() / 1_000),
): Promise<AuthenticatedComputeWorkloadContract> {
  const contract = parseComputeWorkloadEncryptionContract(raw);
  const trust = normalizedTrustPolicy(trustPolicy);
  const activation = contract.activation;
  const verdict = activation.authenticated_verdict;
  const attestation = activation.recipient_attestation;
  const recipient = await computeWorkloadRecipientBindings(
    contract.recipient.encryption_public_key,
    attestation,
  );
  const recipientReleaseCommitment = await computeWorkloadRecipientReleaseCommitment(activation);
  const mismatch = (
    recipient.keyId !== contract.recipient.key_id
    || recipient.reportData !== contract.recipient.report_data
    || recipient.reportDataSha256 !== contract.recipient.report_data_sha256
    || activation.recipient_key_id !== recipient.keyId
    || attestation.encryption_public_key !== contract.recipient.encryption_public_key
    || attestation.key_id !== recipient.keyId
    || attestation.activation_signer_address !== verdict.signer_address
    || attestation.activation_signer_address !== trust.activationSignerAddress
    || attestation.chain_id !== verdict.chain_id
    || attestation.chain_id !== trust.chainId
    || attestation.compute_vault_address !== verdict.contract_address
    || attestation.compute_vault_address !== trust.contractAddress
    || attestation.compute_vault_runtime_code_hash !== trust.vaultRuntimeCodeHash
    || attestation.fresh_contract_deployment_receipt_sha256 !== trust.freshDeploymentReceiptSha256
    || activation.chain_id !== verdict.chain_id
    || activation.domain !== verdict.domain
    || activation.profile !== verdict.profile
    || activation.cvm_id !== verdict.cvm_id
    || activation.deployment_intent_sha256 !== verdict.deployment_intent_sha256
    || activation.release_authority_sha256 !== verdict.release_authority_sha256
    || activation.ceremony_nonce !== verdict.ceremony_nonce
    || activation.measurement_policy_sha256 !== verdict.measurement_policy_sha256
    || activation.report_data !== recipient.reportDataBytes32
    || activation.report_data !== verdict.report_data
    || activation.compose_hash !== verdict.compose_hash
    || activation.app_id !== verdict.app_id
    || activation.os_image_hash !== verdict.os_image_hash
    || activation.release_policy_hash !== verdict.release_policy_hash
    || activation.quote_hash !== verdict.quote_hash
    || activation.verifier_address !== verdict.verifier_address
    || activation.issued_at !== verdict.issued_at
    || verdict.activation_evidence_lease_expires_at !== verdict.expires_at
    || activation.recipient_evidence_lease_expires_at !== verdict.activation_evidence_lease_expires_at
    || activation.recipient_evidence_lease_expires_at !== activation.expires_at
    || activation.expires_at !== verdict.expires_at
    || contract.recipient.activation_expires_at !== activation.expires_at
    || activation.recipient_release_commitment !== recipientReleaseCommitment
    || contract.recipient.recipient_release_commitment !== recipientReleaseCommitment
    || verdict.release_policy_hash !== trust.releasePolicyHash
    || verdict.cvm_id !== trust.cvmId
    || verdict.deployment_intent_sha256 !== trust.deploymentIntentSha256
    || verdict.release_authority_sha256 !== trust.releaseAuthoritySha256
    || verdict.ceremony_nonce !== trust.ceremonyNonce
    || activation.measurement_policy_set_sha256 !== trust.measurementPolicySetSha256
    || verdict.measurement_policy_sha256 !== trust.measurementPolicySha256
    || activation.main_runtime_evidence_sha256 !== trust.mainRuntimeEvidenceSha256
    || verdict.compose_hash !== trust.composeHash
    || verdict.app_id !== trust.appId
    || verdict.os_image_hash !== trust.osImageHash
    || verdict.signer_address !== trust.activationSignerAddress
    || verdict.chain_id !== trust.chainId
    || verdict.contract_address !== trust.contractAddress
    || !trust.trustedVerifierAddresses.includes(verdict.verifier_address)
    || verdict.verifier_address === verdict.signer_address
    || trust.revokedQuoteHashes.includes(verdict.quote_hash)
  );
  if (mismatch) throw new ComputeWorkloadWireError("Compute workload recipient does not match trusted release policy");
  if (
    verdict.issued_at > now + 30
    || verdict.expires_at <= now
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at > trust.maxVerdictAgeSeconds
    || now - verdict.issued_at > trust.maxVerdictAgeSeconds
    || verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || activation.authenticated_at > now + 30
    || activation.authenticated_at < activation.issued_at - 30
    || activation.authenticated_at >= activation.recipient_evidence_lease_expires_at
    || now - activation.authenticated_at > trust.maxVerdictAgeSeconds
  ) throw new ComputeWorkloadWireError("Compute workload QVL verdict is stale or invalid");
  const verdictDigest = await computeIndependentQvlVerdictDigest(verdict);
  if (verdictDigest !== activation.verdict_digest) throw new ComputeWorkloadWireError("Compute workload QVL verdict digest does not match");
  let recovered: Address;
  try {
    recovered = (await recoverMessageAddress({
      message: { raw: verdictDigest },
      signature: verdict.verifier_signature,
    })).toLowerCase() as Address;
  } catch {
    throw new ComputeWorkloadWireError("Compute workload QVL verdict signature is invalid");
  }
  if (recovered !== verdict.verifier_address) throw new ComputeWorkloadWireError("Compute workload QVL verdict signer is not authenticated");
  const activationCommitment = await computeWorkloadActivationCommitment(activation);
  if (activationCommitment !== contract.recipient.activation_commitment) throw new ComputeWorkloadWireError("Compute workload activation commitment does not match");
  return Object.freeze(contract) as AuthenticatedComputeWorkloadContract;
}

async function strictJsonResponse(response: Response, label: string): Promise<unknown> {
  if (response.redirected || !response.ok) throw new ComputeWorkloadWireError(`${label} was rejected`);
  const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json" && !contentType?.endsWith("+json")) throw new ComputeWorkloadWireError(`${label} did not return JSON`);
  const raw = new Uint8Array(await response.arrayBuffer());
  if (raw.length > MAX_RESPONSE_BYTES) throw new ComputeWorkloadWireError(`${label} response is oversized`);
  try {
    return JSON.parse(decoder.decode(raw));
  } catch {
    throw new ComputeWorkloadWireError(`${label} returned invalid JSON`);
  } finally {
    raw.fill(0);
  }
}

export async function fetchAuthenticatedComputeWorkloadContract(
  delegateUrl: string,
  trustPolicy: ComputeWorkloadTrustPolicy,
  now = Math.floor(Date.now() / 1_000),
): Promise<AuthenticatedComputeWorkloadContract> {
  const response = await fetch(`${delegateUrl.replace(/\/$/, "")}/compute/workload-encryption-contract`, {
    method: "GET",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    headers: { Accept: "application/json" },
  });
  return authenticateComputeWorkloadEncryptionContract(await strictJsonResponse(response, "Compute workload contract"), trustPolicy, now);
}

function validateManifest(manifest: ComputeWorkloadManifest): void {
  exactObject(manifest, ["schema", "operation", "model", "recipe", "payload_size_class", "example_count_class", "max_prefill_tokens", "max_sample_tokens", "max_train_tokens"], "Compute workload manifest");
  if (!(manifest.payload_size_class in COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES) || !(manifest.example_count_class in COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES)) throw new ComputeWorkloadWireError("Compute workload privacy class is invalid");
  [manifest.max_prefill_tokens, manifest.max_sample_tokens, manifest.max_train_tokens].forEach((value) => integerValue(value, 0, 100_000_000, "Compute workload resource cap"));
  if (manifest.model !== "qwen3_8b") throw new ComputeWorkloadWireError("Compute workload model is invalid");
  if (manifest.operation === "inference") {
    if (manifest.schema !== "dnai.compute.workload.inference.v1" || manifest.recipe !== "qwen3_8b_bounded" || manifest.example_count_class !== "none" || manifest.max_prefill_tokens < 1 || manifest.max_prefill_tokens > 32_768 || manifest.max_sample_tokens < 1 || manifest.max_sample_tokens > 4_096 || manifest.max_train_tokens !== 0) throw new ComputeWorkloadWireError("Inference manifest caps are invalid");
  } else if (manifest.operation === "training") {
    if (manifest.schema !== "dnai.compute.workload.sft-jsonl.v1" || manifest.recipe !== "qwen3_8b_lora_r32" || manifest.example_count_class === "none" || manifest.max_prefill_tokens !== 0 || manifest.max_sample_tokens !== 0 || manifest.max_train_tokens < 1 || manifest.max_train_tokens > 10_000_000) throw new ComputeWorkloadWireError("Training manifest caps are invalid");
  } else throw new ComputeWorkloadWireError("Compute workload operation is invalid");
}

function privatePayloadBytes(manifest: ComputeWorkloadManifest, workload: ComputePrivateWorkload): Uint8Array {
  if (manifest.operation === "inference") {
    if (workload.kind !== "inference") throw new ComputeWorkloadWireError("Inference workload kind does not match manifest");
    assertUnicodeScalarString(workload.prompt, "Inference prompt");
    const promptBytes = encoder.encode(workload.prompt).length;
    if (promptBytes < 1 || promptBytes > MAX_INFERENCE_PROMPT_BYTES) throw new ComputeWorkloadWireError("Inference prompt size is invalid");
    return canonicalBytes({ schema: "dnai.compute.inference-prompt.v1", prompt: workload.prompt });
  }
  if (workload.kind !== "training" || workload.examples.length < 1 || workload.examples.length > MAX_SFT_EXAMPLES) throw new ComputeWorkloadWireError("Training examples are invalid");
  const [minimum, maximum] = COMPUTE_WORKLOAD_EXAMPLE_COUNT_CLASSES[manifest.example_count_class];
  if (workload.examples.length < minimum || workload.examples.length > maximum) throw new ComputeWorkloadWireError("Training example count class does not match");
  const lines = workload.examples.map((example) => {
    assertUnicodeScalarString(example.prompt, "Training prompt");
    assertUnicodeScalarString(example.completion, "Training completion");
    if (encoder.encode(example.prompt).length < 1 || encoder.encode(example.prompt).length > MAX_SFT_FIELD_BYTES || encoder.encode(example.completion).length < 1 || encoder.encode(example.completion).length > MAX_SFT_FIELD_BYTES) throw new ComputeWorkloadWireError("Training example field size is invalid");
    return canonicalAsciiJson({ completion: example.completion, prompt: example.prompt });
  });
  return encoder.encode(`${lines.join("\n")}\n`);
}

function randomFill(value: Uint8Array): void {
  for (let offset = 0; offset < value.length; offset += 65_536) crypto.getRandomValues(value.subarray(offset, Math.min(offset + 65_536, value.length)));
}

function validatePrincipal(principal: ComputeWorkloadPrincipal): { kind: "wallet" | "credential"; projectId: string; actorId: string } {
  if (!RESOURCE_ID.test(principal.projectId)) throw new ComputeWorkloadWireError("Compute workload project id is invalid");
  if (principal.kind === "wallet") {
    const actorId = principal.actorId.toLowerCase();
    if (!ADDRESS.test(actorId)) throw new ComputeWorkloadWireError("Compute workload wallet is invalid");
    return { kind: "wallet", projectId: principal.projectId, actorId };
  }
  if (principal.kind !== "credential" || !RESOURCE_ID.test(principal.actorId)) throw new ComputeWorkloadWireError("Compute workload credential is invalid");
  return { kind: "credential", projectId: principal.projectId, actorId: principal.actorId };
}

/**
 * Derive only the public commitments and AAD for an in-memory private payload.
 * The payload and blind are never returned or persisted. Callers must provide a
 * fresh 32-byte CSPRNG blind and zero their own input buffers after use.
 */
export async function deriveComputeWorkloadWireBinding(input: {
  principal: ComputeWorkloadPrincipal;
  idempotencyKey: string;
  manifest: ComputeWorkloadManifest;
  privatePayload: Uint8Array;
  blinding: Uint8Array;
  recipient: {
    keyId: string;
    reportDataSha256: string;
    activationCommitment: string;
    recipientReleaseCommitment: string;
  };
}): Promise<ComputeWorkloadWireBinding> {
  validateManifest(input.manifest);
  const principal = validatePrincipal(input.principal);
  if (!IDEMPOTENCY_KEY.test(input.idempotencyKey) || encoder.encode(input.idempotencyKey).length > 128) throw new ComputeWorkloadWireError("Compute workload idempotency key is invalid");
  if (input.blinding.length !== 32 || input.blinding.every((byte) => byte === 0)) throw new ComputeWorkloadWireError("Compute workload blinding value is invalid");
  const classBytes = COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[input.manifest.payload_size_class];
  if (input.privatePayload.length < 1 || input.privatePayload.length > classBytes - SEALED_HEADER_BYTES) throw new ComputeWorkloadWireError("Private workload does not fit its padded size class");
  stringValue(input.recipient.keyId, SHA256, "recipient key id");
  stringValue(input.recipient.reportDataSha256, SHA256, "recipient report data hash");
  stringValue(input.recipient.activationCommitment, SHA256, "recipient activation commitment");
  stringValue(input.recipient.recipientReleaseCommitment, SHA256, "recipient release commitment");
  const manifestBytes = canonicalBytes(input.manifest as unknown as Json);
  const manifestCommitment = await sha256Commitment(manifestBytes);
  const workloadCommitment = await sha256Commitment(WORKLOAD_COMMITMENT_DOMAIN, manifestBytes, Uint8Array.of(0), input.blinding, Uint8Array.of(0), input.privatePayload);
  const projectCommitment = await sha256Commitment(PROJECT_COMMITMENT_DOMAIN, encoder.encode(principal.projectId));
  const actorCommitment = await sha256Commitment(PRINCIPAL_COMMITMENT_DOMAIN, canonicalBytes({ kind: principal.kind, project_id: principal.projectId, actor_id: principal.actorId }));
  const idempotencyHash = await sha256Commitment(IDEMPOTENCY_COMMITMENT_DOMAIN, canonicalBytes({ project_id: principal.projectId, actor_commitment: actorCommitment, idempotency_key: input.idempotencyKey }));
  const aad = canonicalBytes({
    service: "dnai-wikigen",
    context: "compute_workload_ingress",
    schema_version: 1,
    project_commitment: projectCommitment,
    actor_kind: principal.kind,
    actor_commitment: actorCommitment,
    manifest: input.manifest as unknown as Json,
    manifest_commitment: manifestCommitment,
    workload_commitment: workloadCommitment,
    idempotency_hash: idempotencyHash,
    recipient_key_id: input.recipient.keyId,
    report_data_sha256: input.recipient.reportDataSha256,
    activation_commitment: input.recipient.activationCommitment,
    recipient_release_commitment: input.recipient.recipientReleaseCommitment,
  });
  if (aad.length > MAX_AAD_BYTES) throw new ComputeWorkloadWireError("Compute workload AAD is oversized");
  return {
    projectCommitment,
    actorCommitment,
    idempotencyHash,
    manifestCommitment,
    workloadCommitment,
    aad,
    aadBase64url: base64url(aad),
    aadSha256: await sha256Commitment(aad),
  };
}

export async function prepareComputeWorkloadUpload(input: {
  contract: AuthenticatedComputeWorkloadContract;
  principal: ComputeWorkloadPrincipal;
  idempotencyKey: string;
  manifest: ComputeWorkloadManifest;
  workload: ComputePrivateWorkload;
}): Promise<PreparedComputeWorkloadUpload> {
  const { contract, manifest } = input;
  validateManifest(manifest);
  const principal = validatePrincipal(input.principal);
  if (!IDEMPOTENCY_KEY.test(input.idempotencyKey) || encoder.encode(input.idempotencyKey).length > 128) throw new ComputeWorkloadWireError("Compute workload idempotency key is invalid");
  const payload = privatePayloadBytes(manifest, input.workload);
  const classBytes = COMPUTE_WORKLOAD_PAYLOAD_CLASS_BYTES[manifest.payload_size_class];
  if (payload.length < 1 || payload.length > classBytes - SEALED_HEADER_BYTES) {
    payload.fill(0);
    throw new ComputeWorkloadWireError("Private workload does not fit its padded size class");
  }
  const blind = new Uint8Array(32);
  do randomFill(blind); while (blind.every((byte) => byte === 0));
  const sealed = new Uint8Array(classBytes);
  sealed.set(SEALED_MAGIC, 0);
  new DataView(sealed.buffer).setUint32(8, payload.length, false);
  sealed.set(blind, 12);
  sealed.set(payload, SEALED_HEADER_BYTES);
  randomFill(sealed.subarray(SEALED_HEADER_BYTES + payload.length));
  let shared = new Uint8Array();
  let ciphertext = new Uint8Array();
  let nonce = new Uint8Array();
  try {
    const binding = await deriveComputeWorkloadWireBinding({
      principal,
      idempotencyKey: input.idempotencyKey,
      manifest,
      privatePayload: payload,
      blinding: blind,
      recipient: {
        keyId: contract.recipient.key_id,
        reportDataSha256: contract.recipient.report_data_sha256,
        activationCommitment: contract.recipient.activation_commitment,
        recipientReleaseCommitment: contract.recipient.recipient_release_commitment,
      },
    });
    const aad = binding.aad;
    const recipientKey = await crypto.subtle.importKey("raw", ownedArrayBuffer(hexBytes(contract.recipient.encryption_public_key)), { name: "X25519" }, false, []);
    // WebCrypto keeps the private half non-exportable while the public half
    // remains exportable for the envelope. Never make the ephemeral private
    // key extractable merely to serialize its public peer.
    const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: recipientKey }, ephemeral.privateKey, 256));
    const material = await crypto.subtle.importKey("raw", ownedArrayBuffer(shared), "HKDF", false, ["deriveKey"]);
    const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: ownedArrayBuffer(await digestBytes(aad)), info: ownedArrayBuffer(HKDF_INFO) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    nonce = new Uint8Array(12);
    randomFill(nonce);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ownedArrayBuffer(nonce), additionalData: ownedArrayBuffer(aad), tagLength: 128 }, aes, ownedArrayBuffer(sealed)));
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
    const ciphertextSha256 = await sha256Commitment(ciphertext);
    const body = {
      workload_commitment: binding.workloadCommitment,
      manifest: { ...manifest },
      envelope: {
        schema_version: 1 as const,
        algorithm: "X25519-HKDF-SHA256-AES-256-GCM" as const,
        encoding: "base64url-nopad" as const,
        key_id: contract.recipient.key_id,
        attestation_report_data: contract.recipient.report_data,
        activation_commitment: contract.recipient.activation_commitment,
        aad: binding.aadBase64url,
        ephemeral_public_key: base64url(ephemeralPublic),
        nonce: base64url(nonce),
        ciphertext: base64url(ciphertext),
      },
    };
    return Object.freeze({
      projectId: principal.projectId,
      idempotencyKey: input.idempotencyKey,
      body: Object.freeze(body),
      expected: Object.freeze({
        workloadSchema: manifest.schema,
        workloadCommitment: binding.workloadCommitment,
        manifestCommitment: binding.manifestCommitment,
        ciphertextSha256,
        keyId: contract.recipient.key_id,
        activationCommitment: contract.recipient.activation_commitment,
        recipientReleaseCommitment: contract.recipient.recipient_release_commitment,
      }),
    });
  } catch (error) {
    if (error instanceof ComputeWorkloadWireError) throw error;
    throw new ComputeWorkloadWireError("Browser X25519 workload encryption is unavailable");
  } finally {
    payload.fill(0);
    blind.fill(0);
    sealed.fill(0);
    shared.fill(0);
    ciphertext.fill(0);
    nonce.fill(0);
  }
}

function parseReceipt(value: unknown, expected: PreparedComputeWorkloadUpload["expected"]): ComputeWorkloadIngressReceipt {
  const receipt = exactObject(value, [
    "surface", "schema_version", "workload_id", "workload_schema", "workload_commitment",
    "manifest_commitment", "ciphertext_sha256", "blob_sha256", "key_id",
    "activation_commitment", "created", "idempotent_replay", "ciphertext_egress",
    "recipient_release_commitment",
    "raw_prompt_egress", "raw_examples_egress", "raw_dataset_egress", "raw_output_egress",
    "provider_dispatch_enabled",
  ], "Compute workload ingress receipt");
  const created = typeof receipt.created === "boolean" ? receipt.created : (() => { throw new ComputeWorkloadWireError("workload receipt created state is invalid"); })();
  const replay = typeof receipt.idempotent_replay === "boolean" ? receipt.idempotent_replay : (() => { throw new ComputeWorkloadWireError("workload receipt replay state is invalid"); })();
  if (created === replay) throw new ComputeWorkloadWireError("workload receipt idempotency state is invalid");
  const parsed: ComputeWorkloadIngressReceipt = {
    surface: exactValue(receipt.surface, "compute_workload_ingress_receipt", "workload receipt surface"),
    schema_version: exactValue(receipt.schema_version, 1, "workload receipt schema"),
    workload_id: stringValue(receipt.workload_id, WORKLOAD_ID, "workload id"),
    workload_schema: exactValue(receipt.workload_schema, expected.workloadSchema, "workload receipt schema binding"),
    workload_commitment: exactValue(receipt.workload_commitment, expected.workloadCommitment, "workload receipt commitment"),
    manifest_commitment: exactValue(receipt.manifest_commitment, expected.manifestCommitment, "workload manifest commitment"),
    ciphertext_sha256: exactValue(receipt.ciphertext_sha256, expected.ciphertextSha256, "workload ciphertext commitment"),
    blob_sha256: stringValue(receipt.blob_sha256, SHA256, "workload blob commitment"),
    key_id: exactValue(receipt.key_id, expected.keyId, "workload recipient key"),
    activation_commitment: exactValue(receipt.activation_commitment, expected.activationCommitment, "workload activation commitment"),
    recipient_release_commitment: exactValue(receipt.recipient_release_commitment, expected.recipientReleaseCommitment, "workload recipient release commitment"),
    created,
    idempotent_replay: replay,
    ciphertext_egress: exactValue(receipt.ciphertext_egress, false, "workload ciphertext egress"),
    raw_prompt_egress: exactValue(receipt.raw_prompt_egress, false, "workload prompt egress"),
    raw_examples_egress: exactValue(receipt.raw_examples_egress, false, "workload examples egress"),
    raw_dataset_egress: exactValue(receipt.raw_dataset_egress, false, "workload dataset egress"),
    raw_output_egress: exactValue(receipt.raw_output_egress, false, "workload output egress"),
    provider_dispatch_enabled: exactValue(receipt.provider_dispatch_enabled, false, "workload provider dispatch"),
  };
  return parsed;
}

export async function uploadPreparedComputeWorkload(
  delegateUrl: string,
  authorization: string,
  prepared: PreparedComputeWorkloadUpload,
): Promise<{ receipt: ComputeWorkloadIngressReceipt; dispatchBinding: ComputeWorkloadDispatchBinding }> {
  if (typeof authorization !== "string" || !/^Bearer [^\s]{16,4096}$/.test(authorization)) throw new ComputeWorkloadWireError("Compute workload authorization is invalid");
  const response = await fetch(`${delegateUrl.replace(/\/$/, "")}/compute/projects/${encodeURIComponent(prepared.projectId)}/workloads`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: authorization,
      "Idempotency-Key": prepared.idempotencyKey,
    },
    body: JSON.stringify(prepared.body),
  });
  const receipt = parseReceipt(await strictJsonResponse(response, "Compute workload upload"), prepared.expected);
  return {
    receipt,
    dispatchBinding: {
      workloadId: receipt.workload_id,
      workloadSchema: receipt.workload_schema,
      manifestCommitment: `0x${receipt.manifest_commitment.slice(7)}` as Hex,
      workloadCommitment: `0x${receipt.workload_commitment.slice(7)}` as Hex,
    },
  };
}
