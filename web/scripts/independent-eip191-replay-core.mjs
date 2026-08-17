import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from "@noble/hashes/utils";

/**
 * Static, RPC-free EIP-191 recovery used only for independent historical
 * replay. This adapter does not authorize a current operation and does not
 * claim that the original ceremony verifier was re-executed.
 */
export const INDEPENDENT_EIP191_REPLAY_VERIFIER = Object.freeze({
  schema: "dnai.independent-eip191-replay-verifier.v1",
  tool:
    "@noble/curves secp256k1 recoverPublicKey plus @noble/hashes keccak_256",
  curves_package: "@noble/curves",
  curves_version: "1.9.1",
  curves_integrity:
    "sha512-k11yZxZg+t+gWvBbIswW0yoJlu8cHOC7dhunwOzoWH/mXGBiYyR4YY6hAEK/3EUs4UpB8la1RfdRpeGsFHkWsA==",
  hashes_package: "@noble/hashes",
  hashes_version: "1.8.0",
  hashes_integrity:
    "sha512-jCs9ldd7NwzpgXDIf6P3+NrHh9/sD6CQdxHyjQI+h/6rDNo88ypBxxz45UDuZHz9r3tNz7N/VInSVoVdtXEI4A==",
  message_modes: Object.freeze([
    "utf8_eip191_personal_sign",
    "raw_bytes32_eip191_personal_sign",
  ]),
  account_kind: "externally_owned_account",
  network_or_rpc_required: false,
});

const SIGNATURE = /^0x[0-9a-f]{130}$/;
const RAW_DIGEST = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const SECP256K1_N =
  BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N / 2n;
const MAX_MESSAGE_BYTES = 1024 * 1024;

function snapshotExactOwnDataRecord(value, fields, label) {
  // Browser JavaScript has no non-trapping Proxy predicate. Capture exactly one
  // own-descriptor view, then ensure every semantic read uses only this plain
  // snapshot; the caller's potentially divergent `get` view is never read.
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain-data object`);
  }
  let prototype;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new TypeError(`${label} could not be snapshotted as own data`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must not use a custom prototype`);
  }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")
    || JSON.stringify([...keys].sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} fields do not match the exact schema`);
  }
  const snapshot = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")
      || typeof descriptor.get === "function"
      || typeof descriptor.set === "function") {
      throw new TypeError(`${label} must contain enumerable own data fields only`);
    }
    Object.defineProperty(snapshot, field, {
      value: descriptor.value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(snapshot);
}

function canonicalSignatureBytes(value) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    throw new TypeError(
      "independent EIP-191 signature must be lowercase 65-byte hex",
    );
  }
  const compact = value.slice(2, 130);
  const r = BigInt(`0x${compact.slice(0, 64)}`);
  const s = BigInt(`0x${compact.slice(64)}`);
  const v = Number.parseInt(value.slice(130), 16);
  if (r <= 0n || r >= SECP256K1_N
    || s <= 0n || s > SECP256K1_HALF_N
    || (v !== 27 && v !== 28)) {
    throw new TypeError(
      "independent EIP-191 signature must use canonical low-s secp256k1 with v 27 or 28",
    );
  }
  return {
    compact: hexToBytes(compact),
    recovery: v - 27,
  };
}

function eip191PersonalSigningHash(messageBytes) {
  if (!(messageBytes instanceof Uint8Array)
    || messageBytes.length > MAX_MESSAGE_BYTES) {
    throw new TypeError("independent EIP-191 message bytes are invalid or too large");
  }
  const prefix = utf8ToBytes(
    `\x19Ethereum Signed Message:\n${messageBytes.length}`,
  );
  return keccak_256(concatBytes(prefix, messageBytes));
}

function recoverSigner(messageBytes, signature) {
  const canonical = canonicalSignatureBytes(signature);
  let publicKey;
  try {
    publicKey = secp256k1.Signature
      .fromCompact(canonical.compact)
      .addRecoveryBit(canonical.recovery)
      .recoverPublicKey(eip191PersonalSigningHash(messageBytes))
      .toRawBytes(false);
  } catch {
    throw new TypeError("independent EIP-191 signature recovery failed");
  }
  if (publicKey.length !== 65 || publicKey[0] !== 4) {
    throw new TypeError("independent EIP-191 recovery returned a noncanonical key");
  }
  const addressBytes = keccak_256(publicKey.subarray(1)).subarray(12);
  return `0x${bytesToHex(addressBytes)}`;
}

/** Recover an EOA from an EIP-191 personal-sign UTF-8 message. */
export function recoverIndependentEip191PersonalSigner(input = {}) {
  const { message, signature } = snapshotExactOwnDataRecord(
    input,
    ["message", "signature"],
    "independent EIP-191 UTF-8 recovery input",
  );
  if (typeof message !== "string") {
    throw new TypeError("independent EIP-191 UTF-8 message must be a string");
  }
  return recoverSigner(utf8ToBytes(message), signature);
}

/**
 * Recover an EOA when the EIP-191 message payload is exactly 32 raw bytes.
 * This is intentionally distinct from signing the digest's hexadecimal text.
 */
export function recoverIndependentEip191PersonalSignerFromRawDigest(input = {}) {
  const { digest, signature } = snapshotExactOwnDataRecord(
    input,
    ["digest", "signature"],
    "independent EIP-191 raw-digest recovery input",
  );
  if (typeof digest !== "string" || !RAW_DIGEST.test(digest)) {
    throw new TypeError(
      "independent EIP-191 raw digest must be one nonzero lowercase bytes32 value",
    );
  }
  return recoverSigner(hexToBytes(digest.slice(2)), signature);
}
