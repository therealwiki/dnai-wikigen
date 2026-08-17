import { describe, expect, it } from "vitest";
import { toHex, type Hex } from "viem";
import {
  ARTIFACT_CHAIN_ID,
  ARTIFACT_CIPHERTEXT_BYTES,
  ARTIFACT_COMMITMENT_SCHEME,
  ARTIFACT_ENVELOPE_MAGIC,
  ARTIFACT_ENVELOPE_SCHEME,
  ARTIFACT_FRAME_BYTES,
  ARTIFACT_FRAME_HEADER_BYTES,
  ARTIFACT_PADDING_PROFILE,
  MAX_ARTIFACT_BYTES,
  artifactCommitment,
  createArtifactRecoveryReceipt,
  encodeArtifactEnvelopeFrame,
  encryptArtifact,
  parseArtifactRecoveryReceipt,
  parseArtifactUploadReceipt,
} from "./artifact";

const encoder = new TextEncoder();
const COMMITMENT_SECRET = Uint8Array.from({ length: 32 }, (_, index) => index);
const EXPECTED_TEST_ARTIFACT_HASH = "0x0f5dd8f2c3fba9bcd4d19565c66257757094f11017d8f3fdd264c7b0b5156d80" as Hex;
const ROOM = "0x3333333333333333333333333333333333333333";
const POLICY = `0x${"44".repeat(32)}` as Hex;
const STATIC_FRAME_SHA256 = "e7f2c7d6368e30b50140efc2d3cf858d19ea901ec30951bc28ef94fd1248bd5c";
const STATIC_HKDF_INFO_SHA256 = "4281a0c2db422d32441993267cd08e2a642646140a4e3f7f345806a41202490f";
const STATIC_AAD_SHA256 = "234e48e68de98daf9ea4331505a3542a3f2d48abf597e2dc8f13cd447bc5ea8d";

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function bytes(value: string): Uint8Array {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const output = new Uint8Array(raw.length / 2);
  for (let index = 0; index < output.length; index += 1) output[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  return output;
}

function hex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (item) => item.toString(16).padStart(2, "0")).join("");
}

async function decrypt(
  encrypted: Awaited<ReturnType<typeof encryptArtifact>>,
  recipient: CryptoKeyPair,
): Promise<Uint8Array> {
  const ephemeral = await crypto.subtle.importKey("raw", buffer(bytes(encrypted.ephemeral_public_key)), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, recipient.privateKey, 256));
  const info = encoder.encode([
    "tinker-delegate-artifact|v3",
    String(ARTIFACT_CHAIN_ID),
    ROOM,
    "42",
    EXPECTED_TEST_ARTIFACT_HASH,
    POLICY,
    ARTIFACT_ENVELOPE_SCHEME,
  ].join("|"));
  const aad = encoder.encode([
    "dnai-wikigen/artifact-envelope-aad/v3",
    String(ARTIFACT_CHAIN_ID),
    ROOM,
    "42",
    EXPECTED_TEST_ARTIFACT_HASH,
    POLICY,
    ARTIFACT_ENVELOPE_SCHEME,
  ].join("|"));
  try {
    const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new ArrayBuffer(0), info: buffer(info) },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(bytes(encrypted.nonce)), additionalData: buffer(aad), tagLength: 128 },
      key,
      buffer(bytes(encrypted.ciphertext)),
    ));
  } finally {
    shared.fill(0);
    info.fill(0);
    aad.fill(0);
  }
}

describe("artifact commitment v2 and private transport v3", () => {
  it("keeps the cross-language salted commitment fixture", () => {
    const artifact = encoder.encode("test-artifact");
    expect(artifactCommitment(artifact, COMMITMENT_SECRET)).toBe(EXPECTED_TEST_ARTIFACT_HASH);
    expect(artifactCommitment(encoder.encode("other-artifact"), COMMITMENT_SECRET)).not.toBe(EXPECTED_TEST_ARTIFACT_HASH);
    expect(() => artifactCommitment(new Uint8Array(), COMMITMENT_SECRET)).toThrow(/between 1 byte and 1 MiB/i);
    expect(() => artifactCommitment(new Uint8Array(MAX_ARTIFACT_BYTES + 1), COMMITMENT_SECRET)).toThrow(/between 1 byte and 1 MiB/i);
  });

  it("creates an exact private recovery receipt and rejects downgrade or extra fields", () => {
    const receipt = createArtifactRecoveryReceipt(encoder.encode("private fixture"));
    expect(receipt).toEqual(parseArtifactRecoveryReceipt(JSON.parse(JSON.stringify(receipt))));
    expect(receipt.schema_version).toBe(2);
    expect(receipt.scheme).toBe(ARTIFACT_COMMITMENT_SCHEME);
    expect(receipt.artifact_commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(receipt.commitment_secret).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() => parseArtifactRecoveryReceipt({ ...receipt, scheme: "dnai-wikigen/artifact-commitment/v1" })).toThrow(/required artifact commitment v2/i);
    expect(() => parseArtifactRecoveryReceipt({ ...receipt, raw_artifact: "leak" })).toThrow(/fields do not match/i);
  });

  it("encodes the exact constant frame and chunks Web Crypto randomness", async () => {
    const artifact = Uint8Array.of(0x7a);
    const frame = encodeArtifactEnvelopeFrame(artifact, COMMITMENT_SECRET);
    expect(frame.byteLength).toBe(ARTIFACT_FRAME_BYTES);
    expect(frame.slice(0, 16)).toEqual(encoder.encode(ARTIFACT_ENVELOPE_MAGIC));
    expect(new DataView(frame.buffer).getUint32(16, false)).toBe(1);
    expect(frame.slice(20, ARTIFACT_FRAME_HEADER_BYTES)).toEqual(COMMITMENT_SECRET);
    expect(frame[ARTIFACT_FRAME_HEADER_BYTES]).toBe(0x7a);

    const fullArtifact = new Uint8Array(MAX_ARTIFACT_BYTES).fill(0x5a);
    const deterministic = encodeArtifactEnvelopeFrame(fullArtifact, COMMITMENT_SECRET);
    expect(hex(await crypto.subtle.digest("SHA-256", buffer(deterministic)))).toBe(STATIC_FRAME_SHA256);
    frame.fill(0);
    deterministic.fill(0);
    fullArtifact.fill(0);
  });

  it("encrypts one-byte and maximum artifacts to one exact public ciphertext size", async () => {
    const recipient = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
    const recipientPublic = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    for (const artifact of [Uint8Array.of(0x61), new Uint8Array(MAX_ARTIFACT_BYTES).fill(0x62)]) {
      const hash = artifactCommitment(artifact, COMMITMENT_SECRET);
      const encrypted = await encryptArtifact(artifact, COMMITMENT_SECRET, toHex(recipientPublic).slice(2), "42", hash, ROOM, POLICY);
      expect(bytes(encrypted.ciphertext).byteLength).toBe(ARTIFACT_CIPHERTEXT_BYTES);
      expect(encrypted).toMatchObject({
        artifact_hash: hash,
        commitment_scheme: ARTIFACT_COMMITMENT_SCHEME,
        envelope_scheme: ARTIFACT_ENVELOPE_SCHEME,
        padding_profile: ARTIFACT_PADDING_PROFILE,
      });
      artifact.fill(0);
    }
  }, 20_000);

  it("binds chain, room, deal, commitment, policy, and envelope scheme into HKDF/AAD", async () => {
    const recipient = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
    const recipientPublic = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const artifact = encoder.encode("test-artifact");
    const encrypted = await encryptArtifact(artifact, COMMITMENT_SECRET, toHex(recipientPublic).slice(2), "42", EXPECTED_TEST_ARTIFACT_HASH, ROOM, POLICY);
    const hkdfVector = encoder.encode(`tinker-delegate-artifact|v3|84532|${ROOM}|42|${EXPECTED_TEST_ARTIFACT_HASH}|${POLICY}|${ARTIFACT_ENVELOPE_SCHEME}`);
    const aadVector = encoder.encode(`dnai-wikigen/artifact-envelope-aad/v3|84532|${ROOM}|42|${EXPECTED_TEST_ARTIFACT_HASH}|${POLICY}|${ARTIFACT_ENVELOPE_SCHEME}`);
    expect(hex(await crypto.subtle.digest("SHA-256", buffer(hkdfVector)))).toBe(STATIC_HKDF_INFO_SHA256);
    expect(hex(await crypto.subtle.digest("SHA-256", buffer(aadVector)))).toBe(STATIC_AAD_SHA256);
    const frame = await decrypt(encrypted, recipient);
    expect(frame.byteLength).toBe(ARTIFACT_FRAME_BYTES);
    expect(new DataView(frame.buffer).getUint32(16, false)).toBe(artifact.byteLength);
    expect(frame.slice(ARTIFACT_FRAME_HEADER_BYTES, ARTIFACT_FRAME_HEADER_BYTES + artifact.byteLength)).toEqual(artifact);

    await expect(encryptArtifact(artifact, COMMITMENT_SECRET, toHex(recipientPublic).slice(2), "042", EXPECTED_TEST_ARTIFACT_HASH, ROOM, POLICY)).rejects.toThrow(/canonical uint256/i);
    await expect(encryptArtifact(artifact, COMMITMENT_SECRET, toHex(recipientPublic).slice(2), "42", EXPECTED_TEST_ARTIFACT_HASH, "0x0000000000000000000000000000000000000000", POLICY)).rejects.toThrow(/nonzero/i);
    await expect(encryptArtifact(artifact, COMMITMENT_SECRET, toHex(recipientPublic).slice(2), "42", EXPECTED_TEST_ARTIFACT_HASH, ROOM, `0x${"0".repeat(64)}` as Hex)).rejects.toThrow(/nonzero/i);
    frame.fill(0);
  });

  it("accepts only the class-only bounded upload receipt", () => {
    const ciphertextSha256 = `sha256:${"a".repeat(64)}` as const;
    const bounded = {
      deal_id: "42",
      received: true,
      ciphertext_sha256: ciphertextSha256,
      commitment_scheme: ARTIFACT_COMMITMENT_SCHEME,
      envelope_scheme: ARTIFACT_ENVELOPE_SCHEME,
      padding_profile: ARTIFACT_PADDING_PROFILE,
      exact_plaintext_size_egress: false,
    };
    expect(parseArtifactUploadReceipt(bounded, "42", ciphertextSha256)).toEqual(bounded);
    expect(() => parseArtifactUploadReceipt({ ...bounded, size: 13 }, "42", ciphertextSha256)).toThrow(/undeclared fields/);
    expect(() => parseArtifactUploadReceipt({ ...bounded, private_size_egress: false }, "42", ciphertextSha256)).toThrow(/undeclared fields/);
    expect(() => parseArtifactUploadReceipt({ ...bounded, padding_profile: "variable" }, "42", ciphertextSha256)).toThrow(/did not acknowledge/);
  });
});
