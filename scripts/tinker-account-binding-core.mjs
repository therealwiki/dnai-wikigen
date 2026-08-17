import {
  ethereumKeccak256Bytes,
  ethereumKeccak256Hex,
} from "./ethereum-keccak.mjs";
import { hkdfSync } from "node:crypto";

export const TINKER_ACCOUNT_BINDING_SCHEMA =
  "dnai.tinker-account-binding.v1";
export const TINKER_ACCOUNT_BINDING_TYPE =
  "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)";
export const TINKER_PROVIDER_NAMESPACE_LABEL =
  "thinking-machines/tinker";
export const TINKER_ACCOUNT_BINDING_CHAIN_ID = 84_532n;
export const TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT =
  "dnai-wikigen/tinker-account-binding/v1";

const WORD_BYTES = 32;
const ROOT = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;

export const TINKER_ACCOUNT_BINDING_TYPEHASH = ethereumKeccak256Hex(
  Buffer.from(TINKER_ACCOUNT_BINDING_TYPE, "utf8"),
);
export const TINKER_PROVIDER_NAMESPACE = ethereumKeccak256Hex(
  Buffer.from(TINKER_PROVIDER_NAMESPACE_LABEL, "utf8"),
);

function uint256Word(value, label) {
  const parsed = typeof value === "bigint"
    ? value
    : typeof value === "number" && Number.isSafeInteger(value)
      ? BigInt(value)
      : null;
  if (parsed === null) {
    throw new TypeError(`${label} must be an unsigned 256-bit integer`);
  }
  if (parsed < 1n || parsed > MAX_UINT256) {
    throw new TypeError(`${label} must be an unsigned nonzero 256-bit integer`);
  }
  return Buffer.from(parsed.toString(16).padStart(WORD_BYTES * 2, "0"), "hex");
}

function exactBindingRoot(value) {
  if (typeof value === "string") {
    if (!ROOT.test(value)) {
      throw new TypeError(
        "Tinker account binding root must be a nonzero lowercase 0x-prefixed bytes32",
      );
    }
    return Buffer.from(value.slice(2), "hex");
  }
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value)
    : null;
  if (!bytes || bytes.length !== WORD_BYTES || bytes.every((byte) => byte === 0)) {
    throw new TypeError(
      "Tinker account binding root must be exactly 32 nonzero private bytes",
    );
  }
  return bytes;
}

function exactShare(value, label) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value)
    : null;
  if (!bytes || bytes.length !== WORD_BYTES || bytes.every((byte) => byte === 0)) {
    throw new TypeError(`${label} must be exactly 32 nonzero private bytes`);
  }
  return bytes;
}

/**
 * Reconstruct the opaque binding root from two independently generated shares.
 * Lexicographic ordering makes the derivation independent of caller ordering;
 * controller identities and share digests are deliberately not committed or
 * exposed here. Signature/envelope authorization belongs to the ceremony.
 */
export function deriveTinkerAccountBindingRoot(
  shares,
  { chainId = TINKER_ACCOUNT_BINDING_CHAIN_ID } = {},
) {
  if (!Array.isArray(shares) || shares.length !== 2) {
    throw new TypeError("Tinker account binding requires exactly two private shares");
  }
  const ordered = shares
    .map((share, index) => exactShare(share, `Tinker account binding share[${index}]`))
    .sort(Buffer.compare);
  if (ordered[0].equals(ordered[1])) {
    throw new TypeError("Tinker account binding shares must be distinct");
  }
  const info = Buffer.concat([
    uint256Word(chainId, "Tinker account binding chain id"),
    ethereumKeccak256Bytes(Buffer.from(TINKER_PROVIDER_NAMESPACE_LABEL, "utf8")),
  ]);
  return Buffer.from(hkdfSync(
    "sha256",
    Buffer.concat(ordered),
    Buffer.from(TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT, "ascii"),
    info,
    WORD_BYTES,
  ));
}

/**
 * Derive the public on-chain commitment for one opaque private account-binding
 * root. The root is intentionally independent of an email address, provider
 * account identifier, API key, project id, contract address, and release SHA.
 * A measured provisioner must later bind the real provider account to the root
 * and emit bounded attested evidence; this derivation alone is not that claim.
 */
export function deriveTinkerAccountCommitment(
  bindingRoot,
  { chainId = TINKER_ACCOUNT_BINDING_CHAIN_ID } = {},
) {
  const encoded = Buffer.concat([
    ethereumKeccak256Bytes(Buffer.from(TINKER_ACCOUNT_BINDING_TYPE, "utf8")),
    uint256Word(chainId, "Tinker account binding chain id"),
    ethereumKeccak256Bytes(Buffer.from(TINKER_PROVIDER_NAMESPACE_LABEL, "utf8")),
    exactBindingRoot(bindingRoot),
  ]);
  return ethereumKeccak256Hex(encoded);
}
