import { createHash } from "node:crypto";

import { ethereumKeccak256Hex } from "./ethereum-keccak.mjs";

export const ROYALTY_RELEASE_AUTHORITY_SCHEMA =
  "dnai.royalty-release-authority.v1";
export const ROYALTY_RELEASE_STATE_SCHEMA =
  "dnai.royalty-release-state.v1";
export const ROYALTY_RELEASE_STATE_DOMAIN =
  "dnai-wikigen/royalty-release-state/v1\0";
export const ROYALTY_RELEASE_HISTORY_SCHEMA =
  "dnai.royalty-release-history.v1";
export const ROYALTY_RELEASE_HISTORY_DOMAIN =
  "dnai-wikigen/royalty-release-history/v1\0";
export const ROYALTY_RELEASE_HISTORY_V2_SCHEMA =
  "dnai.royalty-release-history.v2";
export const ROYALTY_RELEASE_HISTORY_V2_DOMAIN =
  "dnai-wikigen/royalty-release-history/v2\0";
export const ROYALTY_RELEASE_EXECUTION_MODES = Object.freeze([
  "activate_and_unpause",
  "recover_reverted_unpause",
]);
export const ROYALTY_AUTHORITY_TIMELOCK_SECONDS = 2 * 24 * 60 * 60;
export const ROYALTY_INITIAL_AUTHORITY_NONCE = 1;
export const ROYALTY_RELEASE_POLICY_TYPE =
  "RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)";
export const ROYALTY_RELEASE_POLICY_TYPEHASH = ethereumKeccak256Hex(
  Buffer.from(ROYALTY_RELEASE_POLICY_TYPE, "utf8"),
);

const CHAIN_ID = 84_532;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;

function fail(message) {
  throw new TypeError(message);
}

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function address(value, label, { allowZero = false } = {}) {
  if (!ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) {
    fail(`${label} must be a canonical${allowZero ? "" : " nonzero"} address`);
  }
  return value;
}

function bytes32(value, label, { allowZero = false } = {}) {
  if (!BYTES32.test(value) || (!allowZero && value === ZERO_BYTES32)) {
    fail(`${label} must be canonical${allowZero ? "" : " nonzero"} bytes32`);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function uintWord(value, label) {
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    fail(`${label} must be uint256`);
  }
  if (parsed < 0n || parsed >= (1n << 256n)) fail(`${label} must be uint256`);
  return Buffer.from(parsed.toString(16).padStart(64, "0"), "hex");
}

function addressWord(value, label) {
  const normalized = address(value, label);
  return Buffer.from(normalized.slice(2).padStart(64, "0"), "hex");
}

function bytes32Word(value, label) {
  return Buffer.from(bytes32(value, label).slice(2), "hex");
}

function hexWord(buffer) {
  return `0x${buffer.toString("hex")}`;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
  );
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(`${JSON.stringify(canonical(value), null, 2)}\n`, "utf8")
    .digest("hex")}`;
}

export function royaltyReleasePolicyCommitment({
  chainId = CHAIN_ID,
  distributorAddress,
  authorityNonce,
  settlementVerifier,
  qvlVerifier,
  executionPolicyAnchor,
  anchorWriterReleaseCommitment,
} = {}) {
  integer(chainId, "royalty release chain ID", CHAIN_ID, CHAIN_ID);
  const encoded = Buffer.concat([
    Buffer.from(ROYALTY_RELEASE_POLICY_TYPEHASH.slice(2), "hex"),
    uintWord(chainId, "royalty release chain ID"),
    addressWord(distributorAddress, "RoyaltyDistributor address"),
    uintWord(authorityNonce, "royalty authority nonce"),
    addressWord(settlementVerifier, "royalty settlement verifier"),
    addressWord(qvlVerifier, "royalty QVL verifier"),
    addressWord(executionPolicyAnchor, "royalty execution-policy anchor"),
    bytes32Word(
      anchorWriterReleaseCommitment,
      "royalty anchor-writer release commitment",
    ),
  ]);
  return ethereumKeccak256Hex(encoded);
}

export function royaltyReleaseMutationCalldataSha256(operation, authority) {
  const normalized = normalizeRoyaltyReleaseAuthority(authority);
  let signature;
  let args = Buffer.alloc(0);
  if (operation === "propose_authority_binding") {
    signature = "proposeAuthorityBinding(address,address,address,bytes32)";
    args = Buffer.concat([
      addressWord(normalized.settlement_verifier, "royalty settlement verifier"),
      addressWord(normalized.qvl_verifier, "royalty QVL verifier"),
      addressWord(normalized.execution_policy_anchor, "royalty execution-policy anchor"),
      bytes32Word(
        normalized.anchor_writer_release_commitment,
        "royalty anchor-writer release commitment",
      ),
    ]);
  } else if (operation === "activate_authority_proposal") {
    signature = "activateAuthorityProposal()";
  } else if (operation === "unpause") {
    signature = "setPaused(bool)";
    args = uintWord(0, "royalty unpause argument");
  } else {
    fail("royalty release mutation operation is unsupported");
  }
  const selector = Buffer.from(
    ethereumKeccak256Hex(Buffer.from(signature, "utf8")).slice(2, 10),
    "hex",
  );
  return `sha256:${createHash("sha256")
    .update(Buffer.concat([selector, args]))
    .digest("hex")}`;
}

export function royaltyReleaseMutationEvent(operation, authority, {
  pendingAuthorityActivatesAt = 0,
} = {}) {
  const normalized = normalizeRoyaltyReleaseAuthority(authority);
  let signature;
  let topics;
  let data;
  if (operation === "propose_authority_binding") {
    signature = "AuthorityBindingProposed(uint256,address,address,address,bytes32,bytes32,uint256)";
    topics = [
      ethereumKeccak256Hex(Buffer.from(signature, "utf8")),
      hexWord(uintWord(normalized.authority_nonce, "royalty authority nonce")),
      hexWord(addressWord(normalized.settlement_verifier, "royalty settlement verifier")),
      hexWord(addressWord(normalized.qvl_verifier, "royalty QVL verifier")),
    ];
    data = hexWord(Buffer.concat([
      addressWord(normalized.execution_policy_anchor, "royalty execution-policy anchor"),
      bytes32Word(normalized.anchor_writer_release_commitment, "royalty anchor-writer release commitment"),
      bytes32Word(normalized.release_policy_commitment, "royalty release-policy commitment"),
      uintWord(pendingAuthorityActivatesAt, "royalty pending activation timestamp"),
    ]));
  } else if (operation === "activate_authority_proposal") {
    signature = "AuthorityBindingActivated(uint256,address,address,address,bytes32,bytes32)";
    topics = [
      ethereumKeccak256Hex(Buffer.from(signature, "utf8")),
      hexWord(uintWord(normalized.authority_nonce, "royalty authority nonce")),
      hexWord(addressWord(normalized.settlement_verifier, "royalty settlement verifier")),
      hexWord(addressWord(normalized.qvl_verifier, "royalty QVL verifier")),
    ];
    data = hexWord(Buffer.concat([
      addressWord(normalized.execution_policy_anchor, "royalty execution-policy anchor"),
      bytes32Word(normalized.anchor_writer_release_commitment, "royalty anchor-writer release commitment"),
      bytes32Word(normalized.release_policy_commitment, "royalty release-policy commitment"),
    ]));
  } else if (operation === "unpause") {
    signature = "PauseSet(bool,address)";
    topics = [
      ethereumKeccak256Hex(Buffer.from(signature, "utf8")),
      hexWord(addressWord(normalized.owner, "RoyaltyDistributor owner")),
    ];
    data = hexWord(uintWord(0, "royalty unpause event value"));
  } else {
    fail("royalty release mutation operation is unsupported");
  }
  return Object.freeze({
    address: normalized.distributor_address,
    topics: Object.freeze(topics),
    data,
  });
}

export function normalizeRoyaltyReleaseAuthority(value) {
  const parsed = exact(value, [
    "anchor_writer", "anchor_writer_release_commitment", "authority_nonce",
    "authority_timelock_seconds", "chain_id", "distributor_address",
    "execution_policy_anchor", "owner", "qvl_verifier",
    "release_policy_commitment", "schema", "settlement_verifier",
  ], "royalty release authority");
  exactString(parsed.schema, ROYALTY_RELEASE_AUTHORITY_SCHEMA, "royalty release authority schema");
  const normalized = {
    schema: parsed.schema,
    chain_id: integer(parsed.chain_id, "royalty release chain ID", CHAIN_ID, CHAIN_ID),
    distributor_address: address(parsed.distributor_address, "RoyaltyDistributor address"),
    owner: address(parsed.owner, "RoyaltyDistributor owner"),
    settlement_verifier: address(parsed.settlement_verifier, "royalty settlement verifier"),
    qvl_verifier: address(parsed.qvl_verifier, "royalty QVL verifier"),
    execution_policy_anchor: address(parsed.execution_policy_anchor, "royalty execution-policy anchor"),
    anchor_writer: address(parsed.anchor_writer, "royalty anchor writer"),
    anchor_writer_release_commitment: bytes32(
      parsed.anchor_writer_release_commitment,
      "royalty anchor-writer release commitment",
    ),
    authority_nonce: integer(
      parsed.authority_nonce,
      "royalty authority nonce",
      ROYALTY_INITIAL_AUTHORITY_NONCE,
      ROYALTY_INITIAL_AUTHORITY_NONCE,
    ),
    authority_timelock_seconds: integer(
      parsed.authority_timelock_seconds,
      "royalty authority timelock",
      ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
      ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
    ),
    release_policy_commitment: bytes32(
      parsed.release_policy_commitment,
      "royalty release-policy commitment",
    ),
  };
  const roles = [
    normalized.distributor_address,
    normalized.owner,
    normalized.settlement_verifier,
    normalized.qvl_verifier,
    normalized.execution_policy_anchor,
    normalized.anchor_writer,
  ];
  if (new Set(roles).size !== roles.length) {
    fail("royalty owner, distributor, verifiers, anchor, and anchor writer must be distinct");
  }
  const expectedPolicy = royaltyReleasePolicyCommitment({
    chainId: normalized.chain_id,
    distributorAddress: normalized.distributor_address,
    authorityNonce: normalized.authority_nonce,
    settlementVerifier: normalized.settlement_verifier,
    qvlVerifier: normalized.qvl_verifier,
    executionPolicyAnchor: normalized.execution_policy_anchor,
    anchorWriterReleaseCommitment:
      normalized.anchor_writer_release_commitment,
  });
  if (normalized.release_policy_commitment !== expectedPolicy) {
    fail("royalty release-policy commitment does not match the Solidity typed commitment");
  }
  return normalized;
}

export function normalizeRoyaltyReleaseState(value, {
  authority: authorityValue,
  phase,
} = {}) {
  const authority = normalizeRoyaltyReleaseAuthority(authorityValue);
  if (!["fresh", "phase_one_pending", "phase_two_active"].includes(phase)) {
    fail("royalty release state phase is unsupported");
  }
  const parsed = exact(value, [
    "anchor_writer_ever_configured", "anchor_writer_release_commitment",
    "authority_nonce", "block_hash", "block_number", "block_timestamp",
    "chain_id", "computed_release_policy_commitment", "contract_address",
    "execution_policy_anchor", "owner", "paused", "pending_anchor_writer_release_commitment",
    "pending_authority_activates_at", "pending_authority_nonce",
    "pending_authority_revocation", "pending_execution_policy_anchor",
    "pending_owner", "pending_qvl_verifier", "pending_release_policy_commitment",
    "pending_settlement_verifier", "qvl_verifier", "qvl_verifier_ever_configured",
    "release_policy_commitment", "schema", "settlement_verifier",
    "settlement_verifier_ever_configured",
  ], `royalty ${phase} state`);
  exactString(parsed.schema, ROYALTY_RELEASE_STATE_SCHEMA, `royalty ${phase} state schema`);
  const normalized = {
    schema: parsed.schema,
    chain_id: integer(parsed.chain_id, "royalty state chain ID", CHAIN_ID, CHAIN_ID),
    contract_address: address(parsed.contract_address, "royalty state contract address"),
    block_number: integer(parsed.block_number, "royalty state block number", 1),
    block_hash: bytes32(parsed.block_hash, "royalty state block hash"),
    block_timestamp: integer(parsed.block_timestamp, "royalty state block timestamp", 1),
    owner: address(parsed.owner, "royalty state owner"),
    pending_owner: address(parsed.pending_owner, "royalty state pending owner", { allowZero: true }),
    paused: parsed.paused,
    settlement_verifier: address(parsed.settlement_verifier, "royalty state settlement verifier", { allowZero: true }),
    qvl_verifier: address(parsed.qvl_verifier, "royalty state QVL verifier", { allowZero: true }),
    execution_policy_anchor: address(parsed.execution_policy_anchor, "royalty state execution-policy anchor", { allowZero: true }),
    anchor_writer_release_commitment: bytes32(parsed.anchor_writer_release_commitment, "royalty state anchor-writer release", { allowZero: true }),
    release_policy_commitment: bytes32(parsed.release_policy_commitment, "royalty state release policy", { allowZero: true }),
    authority_nonce: integer(parsed.authority_nonce, "royalty state authority nonce"),
    pending_settlement_verifier: address(parsed.pending_settlement_verifier, "royalty state pending settlement verifier", { allowZero: true }),
    pending_qvl_verifier: address(parsed.pending_qvl_verifier, "royalty state pending QVL verifier", { allowZero: true }),
    pending_execution_policy_anchor: address(parsed.pending_execution_policy_anchor, "royalty state pending execution-policy anchor", { allowZero: true }),
    pending_anchor_writer_release_commitment: bytes32(parsed.pending_anchor_writer_release_commitment, "royalty state pending anchor-writer release", { allowZero: true }),
    pending_release_policy_commitment: bytes32(parsed.pending_release_policy_commitment, "royalty state pending release policy", { allowZero: true }),
    pending_authority_nonce: integer(parsed.pending_authority_nonce, "royalty state pending authority nonce"),
    pending_authority_activates_at: integer(parsed.pending_authority_activates_at, "royalty state activation timestamp"),
    pending_authority_revocation: parsed.pending_authority_revocation,
    settlement_verifier_ever_configured: parsed.settlement_verifier_ever_configured,
    qvl_verifier_ever_configured: parsed.qvl_verifier_ever_configured,
    anchor_writer_ever_configured: parsed.anchor_writer_ever_configured,
    computed_release_policy_commitment: bytes32(parsed.computed_release_policy_commitment, "royalty recomputed release policy"),
  };
  if (typeof normalized.paused !== "boolean"
    || typeof normalized.pending_authority_revocation !== "boolean"
    || typeof normalized.settlement_verifier_ever_configured !== "boolean"
    || typeof normalized.qvl_verifier_ever_configured !== "boolean"
    || typeof normalized.anchor_writer_ever_configured !== "boolean") {
    fail(`royalty ${phase} state boolean fields are invalid`);
  }
  if (normalized.contract_address !== authority.distributor_address
    || normalized.owner !== authority.owner
    || normalized.pending_owner !== ZERO_ADDRESS
    || normalized.computed_release_policy_commitment
      !== authority.release_policy_commitment) {
    fail(`royalty ${phase} state drifts from the exact release authority`);
  }
  const activeEmpty = normalized.settlement_verifier === ZERO_ADDRESS
    && normalized.qvl_verifier === ZERO_ADDRESS
    && normalized.execution_policy_anchor === ZERO_ADDRESS
    && normalized.anchor_writer_release_commitment === ZERO_BYTES32
    && normalized.release_policy_commitment === ZERO_BYTES32
    && normalized.authority_nonce === 0;
  const pendingEmpty = normalized.pending_settlement_verifier === ZERO_ADDRESS
    && normalized.pending_qvl_verifier === ZERO_ADDRESS
    && normalized.pending_execution_policy_anchor === ZERO_ADDRESS
    && normalized.pending_anchor_writer_release_commitment === ZERO_BYTES32
    && normalized.pending_release_policy_commitment === ZERO_BYTES32
    && normalized.pending_authority_nonce === 0
    && normalized.pending_authority_activates_at === 0
    && normalized.pending_authority_revocation === false;
  const historyEmpty = normalized.settlement_verifier_ever_configured === false
    && normalized.qvl_verifier_ever_configured === false
    && normalized.anchor_writer_ever_configured === false;
  const activeExact = normalized.settlement_verifier === authority.settlement_verifier
    && normalized.qvl_verifier === authority.qvl_verifier
    && normalized.execution_policy_anchor === authority.execution_policy_anchor
    && normalized.anchor_writer_release_commitment
      === authority.anchor_writer_release_commitment
    && normalized.release_policy_commitment === authority.release_policy_commitment
    && normalized.authority_nonce === authority.authority_nonce;
  const pendingExact = normalized.pending_settlement_verifier
      === authority.settlement_verifier
    && normalized.pending_qvl_verifier === authority.qvl_verifier
    && normalized.pending_execution_policy_anchor
      === authority.execution_policy_anchor
    && normalized.pending_anchor_writer_release_commitment
      === authority.anchor_writer_release_commitment
    && normalized.pending_release_policy_commitment
      === authority.release_policy_commitment
    && normalized.pending_authority_nonce === authority.authority_nonce
    && normalized.pending_authority_activates_at > normalized.block_timestamp
    && normalized.pending_authority_revocation === false;
  const historyExact = normalized.settlement_verifier_ever_configured === true
    && normalized.qvl_verifier_ever_configured === true
    && normalized.anchor_writer_ever_configured === true;
  if (phase === "fresh"
    && !(normalized.paused === true && activeEmpty && pendingEmpty && historyEmpty)) {
    fail("fresh RoyaltyDistributor state must be paused with empty active, pending, and history roles");
  }
  if (phase === "phase_one_pending"
    && !(normalized.paused === true && activeEmpty && pendingExact && historyEmpty)) {
    fail("phase-one RoyaltyDistributor state must contain only the exact pending authority");
  }
  if (phase === "phase_two_active"
    && !(normalized.paused === false && activeExact && pendingEmpty && historyExact)) {
    fail("phase-two RoyaltyDistributor state must be active, unpaused, and clear every pending role");
  }
  return normalized;
}

export function royaltyReleaseStateSha256(value, options) {
  return domainDigest(
    ROYALTY_RELEASE_STATE_DOMAIN,
    normalizeRoyaltyReleaseState(value, options),
  );
}

export function isRoyaltyReleaseAuthority(value) {
  try {
    normalizeRoyaltyReleaseAuthority(value);
    return true;
  } catch {
    return false;
  }
}

export const ROYALTY_ZERO_ADDRESS = ZERO_ADDRESS;
export const ROYALTY_ZERO_BYTES32 = ZERO_BYTES32;
export const ROYALTY_SHA256_PATTERN = SHA256;
