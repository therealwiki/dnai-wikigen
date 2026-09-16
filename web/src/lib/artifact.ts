import { keccak256, type Hex } from "viem";
import { deployment } from "../config";
import { publicErrorText } from "./errorText";

export const ARTIFACT_COMMITMENT_SCHEME = "dnai-wikigen/artifact-commitment/v2" as const;
export const ARTIFACT_ENVELOPE_SCHEME = "dnai-wikigen/artifact-envelope/v3" as const;
export const ARTIFACT_PADDING_PROFILE = "fixed_1m_v3" as const;
export const ARTIFACT_ENVELOPE_MAGIC = "DNAIARTIFACTV3\u0000\u0000" as const;
export const MAX_ARTIFACT_BYTES = 1_048_576;
export const ARTIFACT_FRAME_HEADER_BYTES = 16 + 4 + 32;
export const ARTIFACT_FRAME_BYTES = ARTIFACT_FRAME_HEADER_BYTES + MAX_ARTIFACT_BYTES;
export const ARTIFACT_CIPHERTEXT_BYTES = ARTIFACT_FRAME_BYTES + 16;
export const ARTIFACT_CHAIN_ID = 84532;

export interface ArtifactRecoveryReceipt {
  schema_version: 2;
  scheme: typeof ARTIFACT_COMMITMENT_SCHEME;
  artifact_commitment: Hex;
  commitment_secret: Hex;
}

interface AttestationEnvelope {
  mode: string;
  quote: string;
  encryption_public_key: string;
  report_context: string;
  report_data: string;
  quote_report_data: string;
  app_id: string;
  compose_hash: string;
  os_image_hash: string;
  verified: boolean;
}

export interface EncryptedArtifactPayload {
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
  artifact_hash: Hex;
  commitment_scheme: typeof ARTIFACT_COMMITMENT_SCHEME;
  envelope_scheme: typeof ARTIFACT_ENVELOPE_SCHEME;
  padding_profile: typeof ARTIFACT_PADDING_PROFILE;
}

const PUBLIC_FIELDS = new Set([
  "mode",
  "quote",
  "encryption_public_key",
  "report_context",
  "report_data",
  "quote_report_data",
  "app_id",
  "compose_hash",
  "os_image_hash",
  "verified",
]);

const encoder = new TextEncoder();
const COMMITMENT_PREFIX = encoder.encode(`${ARTIFACT_COMMITMENT_SCHEME}\u0000`);
const ENVELOPE_MAGIC = encoder.encode(ARTIFACT_ENVELOPE_MAGIC);
const RECEIPT_FIELDS = new Set(["schema_version", "scheme", "artifact_commitment", "commitment_secret"]);
const UPLOAD_RESULT_FIELDS = new Set([
  "deal_id",
  "received",
  "ciphertext_sha256",
  "commitment_scheme",
  "envelope_scheme",
  "padding_profile",
  "exact_plaintext_size_egress",
]);

export interface ArtifactUploadReceipt {
  deal_id: string;
  received: true;
  ciphertext_sha256: `sha256:${string}`;
  commitment_scheme: typeof ARTIFACT_COMMITMENT_SCHEME;
  envelope_scheme: typeof ARTIFACT_ENVELOPE_SCHEME;
  padding_profile: typeof ARTIFACT_PADDING_PROFILE;
  exact_plaintext_size_egress: false;
}

export type ArtifactUploadLifecycle = Readonly<{
  onPostStarted?: () => void;
}>;

function requireArtifactSize(bytes: { byteLength: number }): void {
  if (bytes.byteLength <= 0 || bytes.byteLength > MAX_ARTIFACT_BYTES) {
    throw new Error("Artifact must be between 1 byte and 1 MiB");
  }
}

function bytesFromHex(value: string, expectedLength?: number): Uint8Array {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-f]*$/i.test(raw) || raw.length % 2 !== 0) throw new Error("Attestation contains invalid hex");
  const result = new Uint8Array(raw.length / 2);
  for (let index = 0; index < result.length; index += 1) result[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  if (expectedLength !== undefined && result.length !== expectedLength) throw new Error(`Attestation field must be ${expectedLength} bytes`);
  return result;
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function constantEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function bytes32Hex(value: unknown, field: string): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${field} must be lowercase 0x-prefixed bytes32 hex`);
  }
  return value as Hex;
}

export function parseArtifactUploadReceipt(
  value: unknown,
  expectedDealId: string,
  expectedCiphertextSha256: `sha256:${string}`,
): ArtifactUploadReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Delegate returned an invalid bounded upload result");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== UPLOAD_RESULT_FIELDS.size || keys.some((key) => !UPLOAD_RESULT_FIELDS.has(key))) {
    throw new Error("Delegate upload result contains undeclared fields");
  }
  if (
    record.deal_id !== expectedDealId
    || record.received !== true
    || record.ciphertext_sha256 !== expectedCiphertextSha256
    || record.commitment_scheme !== ARTIFACT_COMMITMENT_SCHEME
    || record.envelope_scheme !== ARTIFACT_ENVELOPE_SCHEME
    || record.padding_profile !== ARTIFACT_PADDING_PROFILE
    || record.exact_plaintext_size_egress !== false
  ) {
    throw new Error("Delegate did not acknowledge the exact artifact commitment v2 upload");
  }
  return record as unknown as ArtifactUploadReceipt;
}

function normalizedDiligenceRoom(value: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    throw new Error("DiligenceRoom address must be a nonzero Ethereum address");
  }
  return value.toLowerCase();
}

function canonicalDealId(value: string): string {
  if (!/^(0|[1-9][0-9]{0,77})$/.test(value)) throw new Error("Deal id is not a canonical uint256 decimal string");
  return value;
}

function nonzeroPolicyCommitment(value: Hex): Hex {
  const normalized = bytes32Hex(value.toLowerCase(), "Evaluator policy commitment");
  if (/^0x0{64}$/.test(normalized)) throw new Error("Evaluator policy commitment must be nonzero");
  return normalized;
}

function artifactContext(
  prefix: string,
  diligenceRoomAddress: string,
  dealId: string,
  artifactHash: Hex,
  evaluatorPolicyCommitment: Hex,
): Uint8Array {
  return encoder.encode([
    prefix,
    String(ARTIFACT_CHAIN_ID),
    normalizedDiligenceRoom(diligenceRoomAddress),
    canonicalDealId(dealId),
    bytes32Hex(artifactHash.toLowerCase(), "Artifact commitment"),
    nonzeroPolicyCommitment(evaluatorPolicyCommitment),
    ARTIFACT_ENVELOPE_SCHEME,
  ].join("|"));
}

function fillRandomBounded(target: Uint8Array): void {
  // Web Crypto limits each getRandomValues call to 65,536 bytes.
  for (let offset = 0; offset < target.byteLength; offset += 65_536) {
    crypto.getRandomValues(target.subarray(offset, Math.min(offset + 65_536, target.byteLength)));
  }
}

/** Encode the only plaintext artifact transport accepted by envelope v3. */
export function encodeArtifactEnvelopeFrame(
  rawArtifact: Uint8Array,
  commitmentSecret: Uint8Array,
): Uint8Array {
  requireArtifactSize(rawArtifact);
  if (commitmentSecret.byteLength !== 32) throw new Error("Commitment secret must be exactly 32 bytes");
  if (ENVELOPE_MAGIC.byteLength !== 16) throw new Error("Artifact envelope magic must be exactly 16 bytes");
  const frame = new Uint8Array(ARTIFACT_FRAME_BYTES);
  frame.set(ENVELOPE_MAGIC, 0);
  new DataView(frame.buffer).setUint32(16, rawArtifact.byteLength, false);
  frame.set(commitmentSecret, 20);
  frame.set(rawArtifact, ARTIFACT_FRAME_HEADER_BYTES);
  fillRandomBounded(frame.subarray(ARTIFACT_FRAME_HEADER_BYTES + rawArtifact.byteLength));
  return frame;
}

export function artifactCommitment(rawArtifact: Uint8Array, commitmentSecret: Uint8Array): Hex {
  requireArtifactSize(rawArtifact);
  if (commitmentSecret.byteLength !== 32) throw new Error("Commitment secret must be exactly 32 bytes");
  const preimage = concatBytes(COMMITMENT_PREFIX, commitmentSecret, rawArtifact);
  try {
    return keccak256(preimage);
  } finally {
    preimage.fill(0);
  }
}

export function createArtifactRecoveryReceipt(rawArtifact: Uint8Array): ArtifactRecoveryReceipt {
  requireArtifactSize(rawArtifact);
  const secret = crypto.getRandomValues(new Uint8Array(32));
  try {
    return {
      schema_version: 2,
      scheme: ARTIFACT_COMMITMENT_SCHEME,
      artifact_commitment: artifactCommitment(rawArtifact, secret),
      commitment_secret: `0x${hexFromBytes(secret)}`,
    };
  } finally {
    secret.fill(0);
  }
}

export function parseArtifactRecoveryReceipt(value: unknown): ArtifactRecoveryReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Recovery receipt must be a JSON object");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== RECEIPT_FIELDS.size || keys.some((key) => !RECEIPT_FIELDS.has(key))) {
    throw new Error("Recovery receipt fields do not match the v2 schema");
  }
  if (record.schema_version !== 2 || record.scheme !== ARTIFACT_COMMITMENT_SCHEME) {
    throw new Error("Recovery receipt is not the required artifact commitment v2 format");
  }
  return {
    schema_version: 2,
    scheme: ARTIFACT_COMMITMENT_SCHEME,
    artifact_commitment: bytes32Hex(record.artifact_commitment, "Artifact commitment"),
    commitment_secret: bytes32Hex(record.commitment_secret, "Commitment secret"),
  };
}

async function expectedReportData(context: string, publicKey: string): Promise<Uint8Array> {
  const canonical = JSON.stringify({
    context,
    encryption_public_key: publicKey,
    service: "tinker-delegate",
  });
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical)));
}

async function independentQuoteDigest(quote: string): Promise<`sha256:${string}`> {
  const quoteBytes = bytesFromHex(quote);
  if (quoteBytes.length < 512 || quoteBytes.length > 16 * 1024) throw new Error("TDX quote length is outside the approved bound");
  try {
    return `sha256:${hexFromBytes(await crypto.subtle.digest("SHA-256", arrayBuffer(quoteBytes)))}`;
  } finally {
    quoteBytes.fill(0);
  }
}

function requireEnvelopeShape(value: unknown): AttestationEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Attestation envelope is not an object");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !PUBLIC_FIELDS.has(key))) throw new Error("Attestation envelope contains undeclared fields");
  const requiredStrings = ["mode", "quote", "encryption_public_key", "report_context", "report_data", "quote_report_data", "app_id", "compose_hash", "os_image_hash"];
  if (requiredStrings.some((key) => typeof record[key] !== "string") || typeof record.verified !== "boolean") {
    throw new Error("Attestation envelope is missing a declared field");
  }
  return record as unknown as AttestationEnvelope;
}

async function verifyArtifactEnvelope(value: unknown): Promise<AttestationEnvelope> {
  const envelope = requireEnvelopeShape(value);
  if (envelope.mode !== "tdx" || !envelope.quote) throw new Error("Artifact ingress requires a TDX quote");
  if (envelope.verified !== false) throw new Error("Artifact ingress refuses a service-local verification claim; an independent quote pin is required");
  if (!/^sha256:[0-9a-f]{64}$/.test(deployment.artifactVerifiedQuoteSha256)) throw new Error("No independently verified artifact quote is pinned in this build");
  if (await independentQuoteDigest(envelope.quote) !== deployment.artifactVerifiedQuoteSha256) throw new Error("Artifact quote does not match the independently verified quote pin");
  if (envelope.report_context !== "artifact") throw new Error("Attestation context is not artifact ingress");
  if (!deployment.composeHash || envelope.compose_hash !== deployment.composeHash) throw new Error("Compose hash does not match the approved frontend manifest");
  if (deployment.appId && envelope.app_id !== deployment.appId) throw new Error("Phala app identity does not match the approved frontend manifest");
  if (deployment.osImageHash && envelope.os_image_hash !== deployment.osImageHash) throw new Error("OS image hash does not match the approved frontend manifest");
  const publicKey = bytesFromHex(envelope.encryption_public_key, 32);
  const reportData = bytesFromHex(envelope.report_data, 32);
  const expected = await expectedReportData("artifact", envelope.encryption_public_key);
  const quoteReportData = bytesFromHex(envelope.quote_report_data);
  try {
    if (!constantEqual(reportData, expected)) throw new Error("Report data does not bind the artifact encryption key");
    const validLength = quoteReportData.length === 32 || quoteReportData.length === 64;
    if (!validLength || !constantEqual(quoteReportData.slice(0, 32), reportData) || (quoteReportData.length === 64 && quoteReportData.slice(32).some((byte) => byte !== 0))) {
      throw new Error("Quote report data does not match the declared report binding");
    }
    return envelope;
  } finally {
    publicKey.fill(0);
    expected.fill(0);
    reportData.fill(0);
    quoteReportData.fill(0);
  }
}

export async function encryptArtifact(
  rawArtifact: Uint8Array,
  commitmentSecret: Uint8Array,
  teePublicKeyHex: string,
  dealId: string,
  artifactHash: Hex,
  diligenceRoomAddress: string,
  evaluatorPolicyCommitment: Hex,
): Promise<EncryptedArtifactPayload> {
  requireArtifactSize(rawArtifact);
  if (commitmentSecret.byteLength !== 32) throw new Error("Commitment secret must be exactly 32 bytes");
  const normalizedHash = bytes32Hex(artifactHash.toLowerCase(), "Artifact commitment");
  const normalizedPolicy = nonzeroPolicyCommitment(evaluatorPolicyCommitment);
  const teeBytes = bytesFromHex(teePublicKeyHex, 32);
  const wrapper = encodeArtifactEnvelopeFrame(rawArtifact, commitmentSecret);
  const sharedSecret = new Uint8Array(32);
  const info = artifactContext(
    "tinker-delegate-artifact|v3",
    diligenceRoomAddress,
    dealId,
    normalizedHash,
    normalizedPolicy,
  );
  const associatedData = artifactContext(
    "dnai-wikigen/artifact-envelope-aad/v3",
    diligenceRoomAddress,
    dealId,
    normalizedHash,
    normalizedPolicy,
  );
  try {
    // The public half remains exportable for the wire envelope; the ephemeral
    // private half must not be exportable from Web Crypto.
    const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
    const teePublicKey = await crypto.subtle.importKey("raw", arrayBuffer(teeBytes), { name: "X25519" }, false, []);
    sharedSecret.set(new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: teePublicKey }, ephemeral.privateKey, 256)));
    const hkdfKey = await crypto.subtle.importKey("raw", arrayBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new ArrayBuffer(0), info: arrayBuffer(info) },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: arrayBuffer(associatedData), tagLength: 128 },
      aesKey,
      arrayBuffer(wrapper),
    );
    if (ciphertext.byteLength !== ARTIFACT_CIPHERTEXT_BYTES) throw new Error("Artifact ciphertext did not match the fixed v3 size");
    const ephemeralPublic = await crypto.subtle.exportKey("raw", ephemeral.publicKey);
    return {
      ephemeral_public_key: hexFromBytes(ephemeralPublic),
      nonce: hexFromBytes(nonce),
      ciphertext: hexFromBytes(ciphertext),
      artifact_hash: normalizedHash,
      commitment_scheme: ARTIFACT_COMMITMENT_SCHEME,
      envelope_scheme: ARTIFACT_ENVELOPE_SCHEME,
      padding_profile: ARTIFACT_PADDING_PROFILE,
    };
  } finally {
    teeBytes.fill(0);
    wrapper.fill(0);
    sharedSecret.fill(0);
    info.fill(0);
    associatedData.fill(0);
  }
}

async function boundedJson(response: Response, maxBytes = 64 * 1024): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error("Delegate response exceeds the public response limit");
  if (!response.body) throw new Error("Delegate returned an empty response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error("Delegate response exceeds the public response limit");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = concatBytes(...chunks);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    value = undefined;
  } finally {
    body.fill(0);
    chunks.forEach((chunk) => chunk.fill(0));
  }
  if (!response.ok) {
    const fallback = `Request failed with status ${response.status}`;
    const detail = value && typeof value === "object" && "detail" in value ? (value as { detail: unknown }).detail : fallback;
    throw new Error(publicErrorText(detail, fallback));
  }
  if (value === undefined) throw new Error("Delegate returned invalid JSON");
  return value;
}

export async function uploadEncryptedArtifact(
  file: File,
  recoveryReceiptValue: unknown,
  dealId: bigint | string,
  walletToken: string,
  expectedArtifactHash: Hex,
  evaluatorPolicyCommitment: Hex,
  lifecycle: ArtifactUploadLifecycle = {},
): Promise<{ ciphertextSha256: `sha256:${string}`; received: true; commitmentScheme: typeof ARTIFACT_COMMITMENT_SCHEME }> {
  if (!deployment.artifactUploadEnabled) throw new Error("Browser artifact ingress is disabled until independent quote verification is configured");
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  requireArtifactSize({ byteLength: file.size });
  if (!walletToken || walletToken.length > 8192) throw new Error("Artifact upload authorization is missing or invalid");
  const deal = String(dealId);
  if (!/^(0|[1-9][0-9]{0,77})$/.test(deal)) throw new Error("Deal id is not a canonical unsigned integer");
  const expected = bytes32Hex(expectedArtifactHash.toLowerCase(), "On-chain artifact commitment");
  const policyCommitment = nonzeroPolicyCommitment(evaluatorPolicyCommitment);
  if (!deployment.contractAddress) throw new Error("Fresh DiligenceRoom address is not configured");
  const receipt = parseArtifactRecoveryReceipt(recoveryReceiptValue);
  if (receipt.artifact_commitment !== expected) throw new Error("Recovery receipt does not match the on-chain artifact commitment");
  const secret = bytesFromHex(receipt.commitment_secret, 32);
  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    const actualHash = artifactCommitment(bytes, secret);
    if (actualHash !== expected) throw new Error("Selected file and recovery receipt do not match the on-chain artifact commitment");
    const baseUrl = deployment.delegateUrl.replace(/\/$/, "");
    const envelope = await verifyArtifactEnvelope(await boundedJson(await fetch(`${baseUrl}/attestation?context=artifact`, {
      cache: "no-store",
      credentials: "omit",
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(10000),
    })));
    const payload = await encryptArtifact(
      bytes,
      secret,
      envelope.encryption_public_key,
      deal,
      actualHash,
      deployment.contractAddress,
      policyCommitment,
    );
    const ciphertextBytes = bytesFromHex(payload.ciphertext);
    let ciphertextSha256: `sha256:${string}`;
    try {
      ciphertextSha256 = `sha256:${hexFromBytes(await crypto.subtle.digest("SHA-256", arrayBuffer(ciphertextBytes)))}`;
    } finally {
      ciphertextBytes.fill(0);
    }
    lifecycle.onPostStarted?.();
    const result = await boundedJson(await fetch(`${baseUrl}/deal/${encodeURIComponent(deal)}/artifact/encrypted`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${walletToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "omit",
      signal: AbortSignal.timeout(45000),
    }));
    parseArtifactUploadReceipt(result, deal, ciphertextSha256);
    return { ciphertextSha256, received: true, commitmentScheme: ARTIFACT_COMMITMENT_SCHEME };
  } finally {
    bytes.fill(0);
    secret.fill(0);
  }
}
