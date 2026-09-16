import {
  encodeAbiParameters,
  keccak256,
  stringToHex,
  type Address,
  type Hex,
} from "viem";

export const ROYALTY_RELEASE_AUTHORITY_SCHEMA =
  "dnai.royalty-release-authority.v1";
export const ROYALTY_RELEASE_STATE_SCHEMA =
  "dnai.royalty-release-state.v1";
export const ROYALTY_RELEASE_POLICY_TYPE =
  "RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)";
export const ROYALTY_RELEASE_POLICY_TYPEHASH = keccak256(
  stringToHex(ROYALTY_RELEASE_POLICY_TYPE),
);
export const ROYALTY_AUTHORITY_TIMELOCK_SECONDS = 172_800;
export const ROYALTY_INITIAL_AUTHORITY_NONCE = 1;

const CHAIN_ID = 84_532;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;

const AUTHORITY_KEYS = [
  "anchor_writer",
  "anchor_writer_release_commitment",
  "authority_nonce",
  "authority_timelock_seconds",
  "chain_id",
  "distributor_address",
  "execution_policy_anchor",
  "owner",
  "qvl_verifier",
  "release_policy_commitment",
  "schema",
  "settlement_verifier",
] as const;

const ACTIVE_STATE_KEYS = [
  "anchor_writer_ever_configured",
  "anchor_writer_release_commitment",
  "authority_nonce",
  "block_hash",
  "block_number",
  "block_timestamp",
  "chain_id",
  "computed_release_policy_commitment",
  "contract_address",
  "execution_policy_anchor",
  "owner",
  "paused",
  "pending_anchor_writer_release_commitment",
  "pending_authority_activates_at",
  "pending_authority_nonce",
  "pending_authority_revocation",
  "pending_execution_policy_anchor",
  "pending_owner",
  "pending_qvl_verifier",
  "pending_release_policy_commitment",
  "pending_settlement_verifier",
  "qvl_verifier",
  "qvl_verifier_ever_configured",
  "release_policy_commitment",
  "schema",
  "settlement_verifier",
  "settlement_verifier_ever_configured",
] as const;

export interface RoyaltyReleaseAuthority {
  readonly schema: typeof ROYALTY_RELEASE_AUTHORITY_SCHEMA;
  readonly chain_id: typeof CHAIN_ID;
  readonly distributor_address: Address;
  readonly owner: Address;
  readonly settlement_verifier: Address;
  readonly qvl_verifier: Address;
  readonly execution_policy_anchor: Address;
  readonly anchor_writer: Address;
  readonly anchor_writer_release_commitment: Hex;
  readonly authority_nonce: typeof ROYALTY_INITIAL_AUTHORITY_NONCE;
  readonly authority_timelock_seconds: typeof ROYALTY_AUTHORITY_TIMELOCK_SECONDS;
  readonly release_policy_commitment: Hex;
}

export interface RoyaltyReleaseActiveState {
  readonly schema: typeof ROYALTY_RELEASE_STATE_SCHEMA;
  readonly chain_id: typeof CHAIN_ID;
  readonly contract_address: Address;
  readonly block_number: number;
  readonly block_hash: Hex;
  readonly block_timestamp: number;
  readonly owner: Address;
  readonly pending_owner: Address;
  readonly paused: false;
  readonly settlement_verifier: Address;
  readonly qvl_verifier: Address;
  readonly execution_policy_anchor: Address;
  readonly anchor_writer_release_commitment: Hex;
  readonly release_policy_commitment: Hex;
  readonly authority_nonce: typeof ROYALTY_INITIAL_AUTHORITY_NONCE;
  readonly pending_settlement_verifier: Address;
  readonly pending_qvl_verifier: Address;
  readonly pending_execution_policy_anchor: Address;
  readonly pending_anchor_writer_release_commitment: Hex;
  readonly pending_release_policy_commitment: Hex;
  readonly pending_authority_nonce: 0;
  readonly pending_authority_activates_at: 0;
  readonly pending_authority_revocation: false;
  readonly settlement_verifier_ever_configured: true;
  readonly qvl_verifier_ever_configured: true;
  readonly anchor_writer_ever_configured: true;
  readonly computed_release_policy_commitment: Hex;
}

export interface RoyaltyReleaseConfiguration {
  readonly configured: boolean;
  readonly authority?: RoyaltyReleaseAuthority;
  readonly activeState?: RoyaltyReleaseActiveState;
  readonly historySha256?: `sha256:${string}`;
  readonly historyReceiptSha256?: `sha256:${string}`;
  /**
   * This label describes the release producer's evidence model. It never means
   * that a browser RPC read independently reproduced two-RPC or QVL evidence.
   */
  readonly releaseEvidenceModel: "dual_rpc_history_H";
  readonly issues: readonly string[];
}

type PublicEnv = Readonly<Record<string, string | boolean | undefined>>;

function clean(value: string | boolean | undefined): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized === "undefined" || normalized === "null" ? "" : normalized;
}

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields do not match the exact schema`);
  }
  return value as Record<string, unknown>;
}

function exactAddress(value: unknown, label: string, allowZero = false): Address {
  if (typeof value !== "string" || !ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) {
    throw new Error(`${label} must be a canonical${allowZero ? "" : " nonzero"} address`);
  }
  return value as Address;
}

function exactBytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !BYTES32.test(value) || (!allowZero && value === ZERO_BYTES32)) {
    throw new Error(`${label} must be canonical${allowZero ? "" : " nonzero"} bytes32`);
  }
  return value as Hex;
}

function safeInteger(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`${label} must be a bounded safe integer`);
  }
  return value as number;
}

function exactBoolean(value: unknown, expected: boolean, label: string): boolean {
  if (value !== expected) throw new Error(`${label} must be ${expected}`);
  return value;
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
}

export function royaltyReleasePolicyCommitment(input: {
  readonly chainId: number;
  readonly distributorAddress: Address;
  readonly authorityNonce: number;
  readonly settlementVerifier: Address;
  readonly qvlVerifier: Address;
  readonly executionPolicyAnchor: Address;
  readonly anchorWriterReleaseCommitment: Hex;
}): Hex {
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "uint256" },
      { type: "address" },
      { type: "uint256" },
      { type: "address" },
      { type: "address" },
      { type: "address" },
      { type: "bytes32" },
    ],
    [
      ROYALTY_RELEASE_POLICY_TYPEHASH,
      BigInt(input.chainId),
      input.distributorAddress,
      BigInt(input.authorityNonce),
      input.settlementVerifier,
      input.qvlVerifier,
      input.executionPolicyAnchor,
      input.anchorWriterReleaseCommitment,
    ],
  ));
}

export function normalizeRoyaltyReleaseAuthorityBrowser(
  value: unknown,
): RoyaltyReleaseAuthority {
  const parsed = exactObject(value, AUTHORITY_KEYS, "Royalty release authority");
  if (parsed.schema !== ROYALTY_RELEASE_AUTHORITY_SCHEMA) {
    throw new Error("Royalty release authority schema is not v1");
  }
  if (parsed.chain_id !== CHAIN_ID) {
    throw new Error("Royalty release authority is not Base Sepolia");
  }
  if (parsed.authority_nonce !== ROYALTY_INITIAL_AUTHORITY_NONCE) {
    throw new Error("Royalty release authority nonce is not the reviewed initial nonce");
  }
  if (parsed.authority_timelock_seconds !== ROYALTY_AUTHORITY_TIMELOCK_SECONDS) {
    throw new Error("Royalty release authority timelock is not two days");
  }
  const normalized: RoyaltyReleaseAuthority = {
    schema: ROYALTY_RELEASE_AUTHORITY_SCHEMA,
    chain_id: CHAIN_ID,
    distributor_address: exactAddress(parsed.distributor_address, "RoyaltyDistributor"),
    owner: exactAddress(parsed.owner, "Royalty owner"),
    settlement_verifier: exactAddress(parsed.settlement_verifier, "Royalty settlement verifier"),
    qvl_verifier: exactAddress(parsed.qvl_verifier, "Royalty QVL verifier"),
    execution_policy_anchor: exactAddress(parsed.execution_policy_anchor, "Royalty execution-policy anchor"),
    anchor_writer: exactAddress(parsed.anchor_writer, "Royalty anchor writer"),
    anchor_writer_release_commitment: exactBytes32(
      parsed.anchor_writer_release_commitment,
      "Royalty anchor-writer release commitment",
    ),
    authority_nonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
    authority_timelock_seconds: ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
    release_policy_commitment: exactBytes32(
      parsed.release_policy_commitment,
      "Royalty release-policy commitment",
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
    throw new Error("Royalty release roles must be pairwise distinct");
  }
  const expectedPolicy = royaltyReleasePolicyCommitment({
    chainId: normalized.chain_id,
    distributorAddress: normalized.distributor_address,
    authorityNonce: normalized.authority_nonce,
    settlementVerifier: normalized.settlement_verifier,
    qvlVerifier: normalized.qvl_verifier,
    executionPolicyAnchor: normalized.execution_policy_anchor,
    anchorWriterReleaseCommitment: normalized.anchor_writer_release_commitment,
  });
  if (normalized.release_policy_commitment !== expectedPolicy) {
    throw new Error("Royalty release-policy commitment does not recompute");
  }
  return Object.freeze(normalized);
}

export function normalizeRoyaltyReleaseActiveStateBrowser(
  value: unknown,
  authority: RoyaltyReleaseAuthority,
): RoyaltyReleaseActiveState {
  const parsed = exactObject(value, ACTIVE_STATE_KEYS, "Royalty active state");
  if (parsed.schema !== ROYALTY_RELEASE_STATE_SCHEMA || parsed.chain_id !== CHAIN_ID) {
    throw new Error("Royalty active state schema or chain is invalid");
  }
  const normalized: RoyaltyReleaseActiveState = {
    schema: ROYALTY_RELEASE_STATE_SCHEMA,
    chain_id: CHAIN_ID,
    contract_address: exactAddress(parsed.contract_address, "Royalty active contract"),
    block_number: safeInteger(parsed.block_number, "Royalty active block", 1),
    block_hash: exactBytes32(parsed.block_hash, "Royalty active block hash"),
    block_timestamp: safeInteger(parsed.block_timestamp, "Royalty active block timestamp", 1),
    owner: exactAddress(parsed.owner, "Royalty active owner"),
    pending_owner: exactAddress(parsed.pending_owner, "Royalty pending owner", true),
    paused: exactBoolean(parsed.paused, false, "Royalty paused") as false,
    settlement_verifier: exactAddress(parsed.settlement_verifier, "Royalty active settlement verifier"),
    qvl_verifier: exactAddress(parsed.qvl_verifier, "Royalty active QVL verifier"),
    execution_policy_anchor: exactAddress(parsed.execution_policy_anchor, "Royalty active anchor"),
    anchor_writer_release_commitment: exactBytes32(parsed.anchor_writer_release_commitment, "Royalty active writer release"),
    release_policy_commitment: exactBytes32(parsed.release_policy_commitment, "Royalty active release policy"),
    authority_nonce: safeInteger(parsed.authority_nonce, "Royalty active authority nonce", 1) as 1,
    pending_settlement_verifier: exactAddress(parsed.pending_settlement_verifier, "Royalty pending settlement verifier", true),
    pending_qvl_verifier: exactAddress(parsed.pending_qvl_verifier, "Royalty pending QVL verifier", true),
    pending_execution_policy_anchor: exactAddress(parsed.pending_execution_policy_anchor, "Royalty pending anchor", true),
    pending_anchor_writer_release_commitment: exactBytes32(parsed.pending_anchor_writer_release_commitment, "Royalty pending writer release", true),
    pending_release_policy_commitment: exactBytes32(parsed.pending_release_policy_commitment, "Royalty pending release policy", true),
    pending_authority_nonce: safeInteger(parsed.pending_authority_nonce, "Royalty pending nonce") as 0,
    pending_authority_activates_at: safeInteger(parsed.pending_authority_activates_at, "Royalty pending activation") as 0,
    pending_authority_revocation: exactBoolean(parsed.pending_authority_revocation, false, "Royalty pending revocation") as false,
    settlement_verifier_ever_configured: exactBoolean(parsed.settlement_verifier_ever_configured, true, "Royalty settlement history") as true,
    qvl_verifier_ever_configured: exactBoolean(parsed.qvl_verifier_ever_configured, true, "Royalty QVL history") as true,
    anchor_writer_ever_configured: exactBoolean(parsed.anchor_writer_ever_configured, true, "Royalty writer history") as true,
    computed_release_policy_commitment: exactBytes32(parsed.computed_release_policy_commitment, "Royalty computed release policy"),
  };
  if (
    normalized.authority_nonce !== ROYALTY_INITIAL_AUTHORITY_NONCE
    || normalized.pending_owner !== ZERO_ADDRESS
    || normalized.pending_settlement_verifier !== ZERO_ADDRESS
    || normalized.pending_qvl_verifier !== ZERO_ADDRESS
    || normalized.pending_execution_policy_anchor !== ZERO_ADDRESS
    || normalized.pending_anchor_writer_release_commitment !== ZERO_BYTES32
    || normalized.pending_release_policy_commitment !== ZERO_BYTES32
    || normalized.pending_authority_nonce !== 0
    || normalized.pending_authority_activates_at !== 0
    || normalized.contract_address !== authority.distributor_address
    || normalized.owner !== authority.owner
    || normalized.settlement_verifier !== authority.settlement_verifier
    || normalized.qvl_verifier !== authority.qvl_verifier
    || normalized.execution_policy_anchor !== authority.execution_policy_anchor
    || normalized.anchor_writer_release_commitment !== authority.anchor_writer_release_commitment
    || normalized.release_policy_commitment !== authority.release_policy_commitment
    || normalized.computed_release_policy_commitment !== authority.release_policy_commitment
  ) {
    throw new Error("Royalty active state drifts from the exact clear-pending release authority");
  }
  return Object.freeze(normalized);
}

export function parseRoyaltyReleaseConfiguration(env: PublicEnv): RoyaltyReleaseConfiguration {
  const authorityJson = clean(env.VITE_ROYALTY_RELEASE_AUTHORITY_JSON);
  const activeStateJson = clean(env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON);
  const historySha256 = clean(env.VITE_ROYALTY_RELEASE_HISTORY_SHA256);
  const historyReceiptSha256 = clean(
    env.VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256,
  );
  const present = [
    authorityJson,
    activeStateJson,
    historySha256,
    historyReceiptSha256,
  ].filter(Boolean).length;
  if (present === 0) {
    return Object.freeze({
      configured: false,
      releaseEvidenceModel: "dual_rpc_history_H",
      issues: Object.freeze(["Royalty dual-RPC release history is not configured"]),
    });
  }
  if (present !== 4) {
    return Object.freeze({
      configured: false,
      releaseEvidenceModel: "dual_rpc_history_H",
      issues: Object.freeze(["Royalty release authority, active state, history digest, and H receipt digest must be configured together"]),
    });
  }
  try {
    const authority = normalizeRoyaltyReleaseAuthorityBrowser(
      parseJson(authorityJson, "Royalty release authority"),
    );
    const activeState = normalizeRoyaltyReleaseActiveStateBrowser(
      parseJson(activeStateJson, "Royalty active state"),
      authority,
    );
    if (!SHA256.test(historySha256) || historySha256 === `sha256:${"0".repeat(64)}`) {
      throw new Error("Royalty release history digest must be nonzero sha256");
    }
    if (
      !SHA256.test(historyReceiptSha256)
      || historyReceiptSha256 === `sha256:${"0".repeat(64)}`
      || historyReceiptSha256 === historySha256
    ) {
      throw new Error("Royalty H receipt digest must be a distinct nonzero sha256");
    }
    return Object.freeze({
      configured: true,
      authority,
      activeState,
      historySha256: historySha256 as `sha256:${string}`,
      historyReceiptSha256: historyReceiptSha256 as `sha256:${string}`,
      releaseEvidenceModel: "dual_rpc_history_H",
      issues: Object.freeze([]),
    });
  } catch (error) {
    return Object.freeze({
      configured: false,
      releaseEvidenceModel: "dual_rpc_history_H",
      issues: Object.freeze([
        error instanceof Error ? error.message : "Royalty release authority is invalid",
      ]),
    });
  }
}

export const ROYALTY_RELEASE_ZERO_ADDRESS = ZERO_ADDRESS;
export const ROYALTY_RELEASE_ZERO_BYTES32 = ZERO_BYTES32;
