import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  numberToHex,
  padHex,
  stringToHex,
  type Address,
  type Hex,
} from "viem";

import { BASE_SEPOLIA, deployment } from "../config";
import { publicClient } from "./contract";
import { requestCollaborationAuthenticatedApi } from "./collaboration";
import { loadFinalizedRoyaltyRailState } from "./royalty";
import { wallet } from "./wallet";

const UINT256_MAX = (1n << 256n) - 1n;
const CANONICAL_UINT = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const HEX_BYTES = /^0x(?:[0-9a-f]{2})+$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const EXECUTION_ID = /^exec_[0-9a-f]{64}$/;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const FAILURE_CODE = /^[a-z][a-z0-9_]{2,95}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const BARE_HASH = /^(?!0{64}$)[0-9a-f]{64}$/;

const SETTLEMENT_STORAGE_PREFIX =
  "dnai.collaboration.royalty-settlement.pending.v1";
const SETTLEMENT_STORAGE_RECORD =
  "dnai_collaboration_royalty_settlement_pending";
const MAX_STORAGE_BYTES = 96 * 1024;

const settlementAuthorizationComponents = [
  { name: "settlementId", type: "bytes32" },
  { name: "settlementNonce", type: "uint256" },
  { name: "fundingReservationId", type: "bytes32" },
  { name: "releasePolicyCommitment", type: "bytes32" },
  { name: "roomCommitment", type: "bytes32" },
  { name: "roomStateCommitment", type: "bytes32" },
  { name: "queryCommitment", type: "bytes32" },
  { name: "grantSetCommitment", type: "bytes32" },
  { name: "allocationCommitment", type: "bytes32" },
  { name: "ownersAmountsHash", type: "bytes32" },
  { name: "asset", type: "address" },
  { name: "total", type: "uint256" },
  { name: "executionCommitment", type: "bytes32" },
  { name: "resultCommitment", type: "bytes32" },
  { name: "usageCommitment", type: "bytes32" },
  { name: "attestationEvidenceHash", type: "bytes32" },
  { name: "anchorResourceHash", type: "bytes32" },
  { name: "anchorDecisionHash", type: "bytes32" },
  { name: "anchorSequence", type: "uint256" },
  { name: "expiry", type: "uint256" },
] as const;

export const collaborationRoyaltySettlementAbi = [
  {
    type: "function",
    name: "settleReserved",
    stateMutability: "nonpayable",
    inputs: [
      { name: "reservationId", type: "bytes32" },
      {
        name: "authorization",
        type: "tuple",
        components: settlementAuthorizationComponents,
      },
      { name: "owners", type: "address[]" },
      { name: "amounts", type: "uint256[]" },
      { name: "settlementSignature", type: "bytes" },
      { name: "qvlSignature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "fundingReservationSettlementState",
    stateMutability: "view",
    inputs: [{ name: "reservationId", type: "bytes32" }],
    outputs: [{
      name: "viewState",
      type: "tuple",
      components: [
        { name: "consumed", type: "bool" },
        { name: "settlementProcessed", type: "bool" },
        { name: "nonceProcessed", type: "bool" },
        { name: "settlementId", type: "bytes32" },
        { name: "settlementNonce", type: "uint256" },
        { name: "asset", type: "address" },
        { name: "total", type: "uint256" },
        { name: "ownerAmountsHash", type: "bytes32" },
      ],
    }],
  },
  {
    type: "function",
    name: "fundingReservationState",
    stateMutability: "view",
    inputs: [{ name: "reservationId", type: "bytes32" }],
    outputs: [
      {
        name: "reservation",
        type: "tuple",
        components: [
          { name: "intentCommitment", type: "bytes32" },
          { name: "settlementId", type: "bytes32" },
          { name: "settlementNonce", type: "uint256" },
          { name: "releasePolicyCommitment", type: "bytes32" },
          { name: "ownersAmountsHash", type: "bytes32" },
          { name: "executionCommitment", type: "bytes32" },
          { name: "sponsor", type: "address" },
          { name: "asset", type: "address" },
          { name: "total", type: "uint256" },
          { name: "refundAfter", type: "uint64" },
          { name: "status", type: "uint8" },
        ],
      },
      { name: "active", type: "bool" },
    ],
  },
] as const;

export interface CollaborationRoyaltySettlementAuthorization {
  readonly settlement_id: Hex;
  readonly settlement_nonce: string;
  readonly funding_reservation_id: Hex;
  readonly release_policy_commitment: Hex;
  readonly room_commitment: Hex;
  readonly room_state_commitment: Hex;
  readonly query_commitment: Hex;
  readonly grant_set_commitment: Hex;
  readonly allocation_commitment: Hex;
  readonly owners_amounts_hash: Hex;
  readonly asset: Address;
  readonly total: string;
  readonly execution_commitment: Hex;
  readonly result_commitment: Hex;
  readonly usage_commitment: Hex;
  readonly attestation_evidence_hash: Hex;
  readonly anchor_resource_hash: Hex;
  readonly anchor_decision_hash: Hex;
  readonly anchor_sequence: string;
  readonly expiry: string;
}

export interface CollaborationRoyaltyAnchorFinality {
  readonly schema: "dnai-wikigen/execution-policy-anchor-status/v1";
  readonly status: "rpc_reported_finalized_release_match";
  readonly verification_model:
    "single_rpc_reported_finalized_with_confirmation_depth";
  readonly chain_id: 84_532;
  readonly block_number: string;
  readonly block_hash: Hex;
  readonly block_timestamp: string;
  readonly contract_address: Address;
  readonly runtime_code_hash: Hex;
  readonly writer: Address;
  readonly writer_release_commitment: Hex;
  readonly writer_rotations_frozen: true;
  readonly paused: false;
  readonly global_sequence: string;
  readonly global_head: Hex;
  readonly resource_id_hash: string;
  readonly resource_decision_head: Hex;
  readonly resource_sequence: string;
  readonly decision_hash: string;
  readonly decision_sequence: string;
  readonly latest_block_number: string;
  readonly rpc_finalized_block_number: string;
  readonly rpc_finalized_block_hash: Hex;
  readonly minimum_confirmation_depth: string;
  readonly observed_confirmation_depth: string;
  readonly independent_rpc_quorum_verified: false;
  readonly consensus_proof_verified: false;
  readonly opaque_commitments_only: true;
  readonly raw_resource_id_egress: false;
  readonly raw_policy_egress: false;
}

export interface CollaborationRoyaltySettlementWalletPlan {
  readonly schema: "dnai.collaboration.royalty-settlement-wallet-plan.v1";
  readonly chain_id: 84_532;
  readonly to: Address;
  readonly data: Hex;
  readonly value: "0x0";
  readonly function: "settleReserved";
  readonly plan_commitment: Hex;
  readonly authorization_expires_at: string;
  readonly refund_after: string;
  readonly funding_reservation_id: Hex;
  readonly settlement_id: Hex;
  readonly settlement_nonce: string;
  readonly authorization: CollaborationRoyaltySettlementAuthorization;
  readonly owners: readonly Address[];
  readonly amounts: readonly string[];
  readonly settlement_verifier_address: Address;
  readonly settlement_authorization_digest: Hex;
  readonly settlement_authorization_signature: Hex;
  readonly qvl_verifier_address: Address;
  readonly qvl_policy_commitment: Hex;
  readonly qvl_authorization_digest: Hex;
  readonly qvl_authorization_signature: Hex;
  readonly qvl_anchor_evidence_commitment: Hex;
  readonly qvl_verdict_verifier_address: Address;
  readonly qvl_verdict_digest: Hex;
  readonly qvl_release_policy_hash: Hex;
  readonly quote_hash: Hex;
  readonly report_data: Hex;
  readonly compose_hash: Hex;
  readonly app_id: string;
  readonly os_image_hash: string;
  readonly anchor_finality: CollaborationRoyaltyAnchorFinality;
  readonly sponsor_must_broadcast: true;
  readonly prefunded: true;
  readonly raw_quote_egress: false;
  readonly raw_artifact_egress: false;
  readonly provider_credential_egress: false;
  readonly raw_secret_egress: false;
}

export interface CollaborationRoyaltySettlementBroadcastHint {
  readonly transaction_hash: Hex;
  readonly reported_at: string;
}

export interface CollaborationRoyaltyFinalizedSettlement {
  readonly chain_id: 84_532;
  readonly block_number: string;
  readonly block_hash: Hex;
  readonly block_timestamp: string;
  readonly reservation_active: false;
  readonly reservation_consumed: true;
  readonly settlement_processed: true;
  readonly settlement_nonce_processed: true;
  readonly source_commitment: string;
}

export interface CollaborationRoyaltyTerminalEvidence {
  readonly outcome: "reservation_expired" | "reservation_refunded";
  readonly chain_id: 84_532;
  readonly block_number: string;
  readonly block_hash: Hex;
  readonly block_timestamp: string;
  readonly funding_reservation_id: Hex;
  readonly reservation_storage_status: "active" | "refunded";
  readonly reservation_active: false;
  readonly reservation_consumed: false;
  readonly reservation_deposited_amount: string;
  readonly settlement_processed: false;
  readonly settlement_nonce_processed: false;
  readonly source_commitment: string;
}

export type CollaborationRoyaltySettlementState =
  | "not_requested"
  | "prepare_requested"
  | "authorizing"
  | "plan_ready"
  | "broadcast_reported"
  | "settled"
  | "expired"
  | "reservation_expired"
  | "refunded"
  | "reconciliation_hold";

export interface CollaborationRoyaltySettlementStatus {
  readonly schema: "dnai.collaboration.royalty-settlement-status.v2";
  readonly execution_id: string;
  readonly sponsor_address: Address;
  readonly state: CollaborationRoyaltySettlementState;
  readonly generation: string;
  readonly funding_reservation_id: Hex;
  readonly settlement_id: Hex;
  readonly settlement_nonce: string;
  readonly refund_after: string;
  readonly prepare_requested_at: string | null;
  readonly plan_commitment: Hex | null;
  readonly authorization_expires_at: string | null;
  readonly wallet_plan: CollaborationRoyaltySettlementWalletPlan | null;
  readonly broadcast_hint: CollaborationRoyaltySettlementBroadcastHint | null;
  readonly finalized_settlement: CollaborationRoyaltyFinalizedSettlement | null;
  readonly terminal_evidence: CollaborationRoyaltyTerminalEvidence | null;
  readonly failure_code: string | null;
  readonly retryable: boolean;
  readonly modeled: false;
  readonly raw_secret_egress: false;
  readonly clientProjectionProvesSettlement: false;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be one object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) throw new Error(`${label} has an unexpected schema`);
}

function literal<T extends string | number | boolean | null>(
  value: unknown,
  expected: T,
  label: string,
): T {
  if (value !== expected) throw new Error(`${label} is invalid`);
  return expected;
}

function oneOf<T extends string>(
  value: unknown,
  choices: readonly T[],
  label: string,
): T {
  if (typeof value !== "string" || !choices.includes(value as T)) {
    throw new Error(`${label} is invalid`);
  }
  return value as T;
}

function uintString(
  value: unknown,
  label: string,
  options: { positive?: boolean; maximum?: bigint } = {},
): string {
  if (
    typeof value !== "string"
    || !CANONICAL_UINT.test(value)
    || value.length > 78
  ) throw new Error(`${label} must be a canonical decimal string`);
  const parsed = BigInt(value);
  if (
    (options.positive !== false && parsed === 0n)
    || parsed > (options.maximum ?? UINT256_MAX)
  ) throw new Error(`${label} is out of range`);
  return value;
}

function address(value: unknown, label: string, allowZero = false): Address {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-f]{40}$/.test(value)
    || (!allowZero && !ADDRESS.test(value))
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value as Address;
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value as Hex;
}

function signature(value: unknown, label: string): Hex {
  if (
    typeof value !== "string"
    || !HEX_BYTES.test(value)
    || value.length !== 132
  ) throw new Error(`${label} is invalid`);
  return value as Hex;
}

function sha256Commitment(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function parseAuthorization(
  value: unknown,
): CollaborationRoyaltySettlementAuthorization {
  const authorization = object(value, "Royalty settlement authorization");
  const keys = [
    "settlement_id", "settlement_nonce", "funding_reservation_id",
    "release_policy_commitment", "room_commitment", "room_state_commitment",
    "query_commitment", "grant_set_commitment", "allocation_commitment",
    "owners_amounts_hash", "asset", "total", "execution_commitment",
    "result_commitment", "usage_commitment", "attestation_evidence_hash",
    "anchor_resource_hash", "anchor_decision_hash", "anchor_sequence",
    "expiry",
  ] as const;
  exactKeys(authorization, keys, "Royalty settlement authorization");
  return Object.freeze({
    settlement_id: bytes32(authorization.settlement_id, "Settlement ID"),
    settlement_nonce: uintString(authorization.settlement_nonce, "Settlement nonce"),
    funding_reservation_id: bytes32(authorization.funding_reservation_id, "Funding reservation ID"),
    release_policy_commitment: bytes32(authorization.release_policy_commitment, "Release policy commitment"),
    room_commitment: bytes32(authorization.room_commitment, "Room commitment"),
    room_state_commitment: bytes32(authorization.room_state_commitment, "Room-state commitment"),
    query_commitment: bytes32(authorization.query_commitment, "Query commitment"),
    grant_set_commitment: bytes32(authorization.grant_set_commitment, "Grant-set commitment"),
    allocation_commitment: bytes32(authorization.allocation_commitment, "Allocation commitment"),
    owners_amounts_hash: bytes32(authorization.owners_amounts_hash, "Owner-amounts hash"),
    asset: address(authorization.asset, "Settlement asset", true),
    total: uintString(authorization.total, "Settlement total"),
    execution_commitment: bytes32(authorization.execution_commitment, "Execution commitment"),
    result_commitment: bytes32(authorization.result_commitment, "Result commitment"),
    usage_commitment: bytes32(authorization.usage_commitment, "Usage commitment"),
    attestation_evidence_hash: bytes32(authorization.attestation_evidence_hash, "Attestation evidence hash"),
    anchor_resource_hash: bytes32(authorization.anchor_resource_hash, "Anchor resource hash"),
    anchor_decision_hash: bytes32(authorization.anchor_decision_hash, "Anchor decision hash"),
    anchor_sequence: uintString(authorization.anchor_sequence, "Anchor sequence"),
    expiry: uintString(authorization.expiry, "Authorization expiry"),
  });
}

const ANCHOR_KEYS = [
  "schema", "status", "verification_model", "chain_id", "block_number",
  "block_hash", "block_timestamp", "contract_address", "runtime_code_hash",
  "writer", "writer_release_commitment", "writer_rotations_frozen", "paused",
  "global_sequence", "global_head", "resource_id_hash",
  "resource_decision_head", "resource_sequence", "decision_hash",
  "decision_sequence", "latest_block_number", "rpc_finalized_block_number",
  "rpc_finalized_block_hash", "minimum_confirmation_depth",
  "observed_confirmation_depth", "independent_rpc_quorum_verified",
  "consensus_proof_verified", "opaque_commitments_only",
  "raw_resource_id_egress", "raw_policy_egress",
] as const;

function parseAnchorFinality(
  value: unknown,
  authorization: CollaborationRoyaltySettlementAuthorization,
): CollaborationRoyaltyAnchorFinality {
  const anchor = object(value, "Royalty anchor finality");
  exactKeys(anchor, ANCHOR_KEYS, "Royalty anchor finality");
  const globalSequence = uintString(anchor.global_sequence, "Anchor global sequence");
  const resourceSequence = uintString(anchor.resource_sequence, "Anchor resource sequence");
  const decisionSequence = uintString(anchor.decision_sequence, "Anchor decision sequence");
  const latestBlock = uintString(anchor.latest_block_number, "Anchor latest block");
  const finalizedBlock = uintString(anchor.rpc_finalized_block_number, "Anchor RPC finalized block");
  const blockNumber = uintString(anchor.block_number, "Anchor block number");
  const minimumDepth = uintString(
    anchor.minimum_confirmation_depth,
    "Anchor minimum confirmation depth",
    { positive: false },
  );
  const observedDepth = uintString(
    anchor.observed_confirmation_depth,
    "Anchor observed confirmation depth",
    { positive: false },
  );
  const resourceIdHash = typeof anchor.resource_id_hash === "string"
    && BARE_HASH.test(anchor.resource_id_hash)
    ? anchor.resource_id_hash
    : undefined;
  const decisionHash = typeof anchor.decision_hash === "string"
    && BARE_HASH.test(anchor.decision_hash)
    ? anchor.decision_hash
    : undefined;
  const blockHash = bytes32(anchor.block_hash, "Anchor block hash");
  const finalizedBlockHash = bytes32(
    anchor.rpc_finalized_block_hash,
    "Anchor RPC finalized hash",
  );
  if (
    !resourceIdHash
    || !decisionHash
    || `0x${resourceIdHash}` !== authorization.anchor_resource_hash
    || `0x${decisionHash}` !== authorization.anchor_decision_hash
    || anchor.resource_decision_head !== authorization.anchor_decision_hash
    || resourceSequence !== authorization.anchor_sequence
    || decisionSequence !== authorization.anchor_sequence
    || BigInt(globalSequence) < BigInt(resourceSequence)
    || BigInt(observedDepth) < BigInt(minimumDepth)
    || BigInt(latestBlock) < BigInt(blockNumber)
    || BigInt(latestBlock) < BigInt(finalizedBlock)
    || BigInt(blockNumber) > BigInt(finalizedBlock)
    || BigInt(observedDepth)
      !== BigInt(latestBlock) - BigInt(blockNumber) + 1n
    || (blockNumber === finalizedBlock && blockHash !== finalizedBlockHash)
  ) throw new Error("Royalty anchor finality does not match the authorization");
  return Object.freeze({
    schema: literal(anchor.schema, "dnai-wikigen/execution-policy-anchor-status/v1", "Anchor schema"),
    status: literal(anchor.status, "rpc_reported_finalized_release_match", "Anchor status"),
    verification_model: literal(anchor.verification_model, "single_rpc_reported_finalized_with_confirmation_depth", "Anchor verification model"),
    chain_id: literal(anchor.chain_id, BASE_SEPOLIA.id, "Anchor chain"),
    block_number: blockNumber,
    block_hash: blockHash,
    block_timestamp: uintString(anchor.block_timestamp, "Anchor block timestamp"),
    contract_address: address(anchor.contract_address, "ExecutionPolicyAnchor address"),
    runtime_code_hash: bytes32(anchor.runtime_code_hash, "ExecutionPolicyAnchor runtime"),
    writer: address(anchor.writer, "ExecutionPolicyAnchor writer"),
    writer_release_commitment: bytes32(anchor.writer_release_commitment, "Anchor writer release"),
    writer_rotations_frozen: literal(anchor.writer_rotations_frozen, true, "Anchor writer rotations"),
    paused: literal(anchor.paused, false, "Anchor pause state"),
    global_sequence: globalSequence,
    global_head: bytes32(anchor.global_head, "Anchor global head"),
    resource_id_hash: resourceIdHash,
    resource_decision_head: bytes32(anchor.resource_decision_head, "Anchor resource head"),
    resource_sequence: resourceSequence,
    decision_hash: decisionHash,
    decision_sequence: decisionSequence,
    latest_block_number: latestBlock,
    rpc_finalized_block_number: finalizedBlock,
    rpc_finalized_block_hash: finalizedBlockHash,
    minimum_confirmation_depth: minimumDepth,
    observed_confirmation_depth: observedDepth,
    independent_rpc_quorum_verified: literal(anchor.independent_rpc_quorum_verified, false, "Anchor RPC quorum boundary"),
    consensus_proof_verified: literal(anchor.consensus_proof_verified, false, "Anchor consensus-proof boundary"),
    opaque_commitments_only: literal(anchor.opaque_commitments_only, true, "Anchor opaque boundary"),
    raw_resource_id_egress: literal(anchor.raw_resource_id_egress, false, "Anchor resource egress boundary"),
    raw_policy_egress: literal(anchor.raw_policy_egress, false, "Anchor policy egress boundary"),
  });
}

function ownerAmountsHash(owners: readonly Address[], amounts: readonly bigint[]): Hex {
  const typehash = keccak256(stringToHex(
    "RoyaltyOwnerAmounts(address[] owners,uint256[] amounts)",
  ));
  const ownerWords = concatHex(owners.map((owner) => padHex(owner, { size: 32 })));
  const amountWords = concatHex(amounts.map((amount) => numberToHex(amount, { size: 32 })));
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
    [typehash, keccak256(ownerWords), keccak256(amountWords)],
  ));
}

function authorizationArgs(
  authorization: CollaborationRoyaltySettlementAuthorization,
) {
  return {
    settlementId: authorization.settlement_id,
    settlementNonce: BigInt(authorization.settlement_nonce),
    fundingReservationId: authorization.funding_reservation_id,
    releasePolicyCommitment: authorization.release_policy_commitment,
    roomCommitment: authorization.room_commitment,
    roomStateCommitment: authorization.room_state_commitment,
    queryCommitment: authorization.query_commitment,
    grantSetCommitment: authorization.grant_set_commitment,
    allocationCommitment: authorization.allocation_commitment,
    ownersAmountsHash: authorization.owners_amounts_hash,
    asset: authorization.asset,
    total: BigInt(authorization.total),
    executionCommitment: authorization.execution_commitment,
    resultCommitment: authorization.result_commitment,
    usageCommitment: authorization.usage_commitment,
    attestationEvidenceHash: authorization.attestation_evidence_hash,
    anchorResourceHash: authorization.anchor_resource_hash,
    anchorDecisionHash: authorization.anchor_decision_hash,
    anchorSequence: BigInt(authorization.anchor_sequence),
    expiry: BigInt(authorization.expiry),
  } as const;
}

const WALLET_PLAN_KEYS = [
  "schema", "chain_id", "to", "data", "value", "function",
  "plan_commitment", "authorization_expires_at", "refund_after",
  "funding_reservation_id", "settlement_id", "settlement_nonce",
  "authorization", "owners", "amounts", "settlement_verifier_address",
  "settlement_authorization_digest", "settlement_authorization_signature",
  "qvl_verifier_address", "qvl_policy_commitment", "qvl_authorization_digest",
  "qvl_authorization_signature", "qvl_anchor_evidence_commitment",
  "qvl_verdict_verifier_address", "qvl_verdict_digest",
  "qvl_release_policy_hash", "quote_hash", "report_data", "compose_hash",
  "app_id", "os_image_hash", "anchor_finality", "sponsor_must_broadcast",
  "prefunded", "raw_quote_egress", "raw_artifact_egress",
  "provider_credential_egress", "raw_secret_egress",
] as const;

export function parseCollaborationRoyaltySettlementWalletPlan(
  value: unknown,
): CollaborationRoyaltySettlementWalletPlan {
  const plan = object(value, "Collaboration Royalty settlement wallet plan");
  exactKeys(plan, WALLET_PLAN_KEYS, "Collaboration Royalty settlement wallet plan");
  const authorization = parseAuthorization(plan.authorization);
  if (!Array.isArray(plan.owners) || !Array.isArray(plan.amounts)) {
    throw new Error("Royalty settlement owner amounts are invalid");
  }
  if (
    plan.owners.length < 1
    || plan.owners.length > 16
    || plan.owners.length !== plan.amounts.length
  ) throw new Error("Royalty settlement owner amounts are invalid");
  const owners = Object.freeze(plan.owners.map((owner) => address(owner, "Royalty owner")));
  const amounts = Object.freeze(plan.amounts.map((amount) => uintString(amount, "Royalty owner amount")));
  for (let index = 1; index < owners.length; index += 1) {
    if (BigInt(owners[index - 1]) >= BigInt(owners[index])) {
      throw new Error("Royalty settlement owners are not strictly sorted");
    }
  }
  const amountValues = amounts.map(BigInt);
  if (
    amountValues.reduce((total, amount) => total + amount, 0n)
      !== BigInt(authorization.total)
    || ownerAmountsHash(owners, amountValues) !== authorization.owners_amounts_hash
  ) throw new Error("Royalty settlement owner amounts do not recompute");
  const data = typeof plan.data === "string" && HEX_BYTES.test(plan.data)
    ? plan.data as Hex
    : undefined;
  const settlementSignature = signature(
    plan.settlement_authorization_signature,
    "Settlement authorization signature",
  );
  const qvlSignature = signature(
    plan.qvl_authorization_signature,
    "QVL authorization signature",
  );
  const expectedData = encodeFunctionData({
    abi: collaborationRoyaltySettlementAbi,
    functionName: "settleReserved",
    args: [
      authorization.funding_reservation_id,
      authorizationArgs(authorization),
      owners,
      amountValues,
      settlementSignature,
      qvlSignature,
    ],
  });
  if (!data || data !== expectedData) {
    throw new Error("Royalty settlement calldata does not recompute");
  }
  const authorizationExpiry = uintString(
    plan.authorization_expires_at,
    "Settlement authorization expiry",
  );
  const refundAfter = uintString(plan.refund_after, "Reservation refund time");
  const settlementNonce = uintString(plan.settlement_nonce, "Settlement nonce");
  const fundingReservationId = bytes32(plan.funding_reservation_id, "Funding reservation ID");
  const settlementId = bytes32(plan.settlement_id, "Settlement ID");
  if (
    authorizationExpiry !== authorization.expiry
    || BigInt(refundAfter) < BigInt(authorizationExpiry)
    || settlementNonce !== authorization.settlement_nonce
    || fundingReservationId !== authorization.funding_reservation_id
    || settlementId !== authorization.settlement_id
  ) throw new Error("Royalty settlement top-level authorization changed");
  const anchorFinality = parseAnchorFinality(plan.anchor_finality, authorization);
  const appId = typeof plan.app_id === "string" && APP_ID.test(plan.app_id)
    ? plan.app_id
    : undefined;
  const osImageHash = typeof plan.os_image_hash === "string"
    && BARE_HASH.test(plan.os_image_hash) ? plan.os_image_hash : undefined;
  if (!appId || !osImageHash) throw new Error("Royalty settlement release identity is invalid");
  const addresses = {
    to: address(plan.to, "Royalty settlement target"),
    settlement: address(plan.settlement_verifier_address, "Settlement verifier"),
    qvl: address(plan.qvl_verifier_address, "QVL verifier"),
    verdict: address(plan.qvl_verdict_verifier_address, "QVL verdict verifier"),
  };
  if (new Set(Object.values(addresses).map((item) => item.toLowerCase())).size !== 4) {
    throw new Error("Royalty settlement roles are not distinct");
  }
  return Object.freeze({
    schema: literal(plan.schema, "dnai.collaboration.royalty-settlement-wallet-plan.v1", "Settlement wallet-plan schema"),
    chain_id: literal(plan.chain_id, BASE_SEPOLIA.id, "Settlement chain"),
    to: addresses.to,
    data,
    value: literal(plan.value, "0x0", "Settlement transaction value"),
    function: literal(plan.function, "settleReserved", "Settlement function"),
    plan_commitment: bytes32(plan.plan_commitment, "Settlement plan commitment"),
    authorization_expires_at: authorizationExpiry,
    refund_after: refundAfter,
    funding_reservation_id: fundingReservationId,
    settlement_id: settlementId,
    settlement_nonce: settlementNonce,
    authorization,
    owners,
    amounts,
    settlement_verifier_address: addresses.settlement,
    settlement_authorization_digest: bytes32(plan.settlement_authorization_digest, "Settlement authorization digest"),
    settlement_authorization_signature: settlementSignature,
    qvl_verifier_address: addresses.qvl,
    qvl_policy_commitment: bytes32(plan.qvl_policy_commitment, "QVL policy commitment"),
    qvl_authorization_digest: bytes32(plan.qvl_authorization_digest, "QVL authorization digest"),
    qvl_authorization_signature: qvlSignature,
    qvl_anchor_evidence_commitment: bytes32(plan.qvl_anchor_evidence_commitment, "QVL anchor evidence commitment"),
    qvl_verdict_verifier_address: addresses.verdict,
    qvl_verdict_digest: bytes32(plan.qvl_verdict_digest, "QVL verdict digest"),
    qvl_release_policy_hash: bytes32(plan.qvl_release_policy_hash, "QVL release policy hash"),
    quote_hash: bytes32(plan.quote_hash, "TDX quote hash"),
    report_data: bytes32(plan.report_data, "TDX report data"),
    compose_hash: bytes32(plan.compose_hash, "Settlement compose hash"),
    app_id: appId,
    os_image_hash: osImageHash,
    anchor_finality: anchorFinality,
    sponsor_must_broadcast: literal(plan.sponsor_must_broadcast, true, "Sponsor broadcast boundary"),
    prefunded: literal(plan.prefunded, true, "Settlement prefunding boundary"),
    raw_quote_egress: literal(plan.raw_quote_egress, false, "Raw quote egress boundary"),
    raw_artifact_egress: literal(plan.raw_artifact_egress, false, "Raw artifact egress boundary"),
    provider_credential_egress: literal(plan.provider_credential_egress, false, "Provider credential egress boundary"),
    raw_secret_egress: literal(plan.raw_secret_egress, false, "Raw secret egress boundary"),
  });
}

const STATUS_KEYS = [
  "schema", "execution_id", "sponsor_address", "state", "generation",
  "funding_reservation_id", "settlement_id", "settlement_nonce",
  "refund_after", "prepare_requested_at", "plan_commitment",
  "authorization_expires_at", "wallet_plan", "broadcast_hint",
  "finalized_settlement", "terminal_evidence", "failure_code", "retryable", "modeled",
  "raw_secret_egress",
] as const;

function parseBroadcastHint(
  value: unknown,
): CollaborationRoyaltySettlementBroadcastHint | null {
  if (value === null) return null;
  const hint = object(value, "Royalty settlement broadcast hint");
  exactKeys(hint, ["transaction_hash", "reported_at"], "Royalty settlement broadcast hint");
  return Object.freeze({
    transaction_hash: bytes32(hint.transaction_hash, "Settlement transaction hash"),
    reported_at: uintString(hint.reported_at, "Settlement broadcast report time"),
  });
}

function parseFinalizedSettlement(
  value: unknown,
): CollaborationRoyaltyFinalizedSettlement | null {
  if (value === null) return null;
  const finalized = object(value, "Finalized Royalty settlement");
  exactKeys(finalized, [
    "chain_id", "block_number", "block_hash", "block_timestamp",
    "reservation_active", "reservation_consumed", "settlement_processed",
    "settlement_nonce_processed", "source_commitment",
  ], "Finalized Royalty settlement");
  return Object.freeze({
    chain_id: literal(finalized.chain_id, BASE_SEPOLIA.id, "Finalized settlement chain"),
    block_number: uintString(finalized.block_number, "Finalized settlement block"),
    block_hash: bytes32(finalized.block_hash, "Finalized settlement block hash"),
    block_timestamp: uintString(finalized.block_timestamp, "Finalized settlement block time"),
    reservation_active: literal(finalized.reservation_active, false, "Finalized active-reservation state"),
    reservation_consumed: literal(finalized.reservation_consumed, true, "Finalized consumed-reservation state"),
    settlement_processed: literal(finalized.settlement_processed, true, "Finalized settlement state"),
    settlement_nonce_processed: literal(finalized.settlement_nonce_processed, true, "Finalized settlement nonce state"),
    source_commitment: sha256Commitment(finalized.source_commitment, "Finalized settlement source"),
  });
}

function parseTerminalEvidence(
  value: unknown,
): CollaborationRoyaltyTerminalEvidence | null {
  if (value === null) return null;
  const evidence = object(value, "Royalty terminal evidence");
  exactKeys(evidence, [
    "outcome", "chain_id", "block_number", "block_hash", "block_timestamp",
    "funding_reservation_id", "reservation_storage_status",
    "reservation_active", "reservation_consumed",
    "reservation_deposited_amount", "settlement_processed",
    "settlement_nonce_processed", "source_commitment",
  ], "Royalty terminal evidence");
  return Object.freeze({
    outcome: oneOf(evidence.outcome, [
      "reservation_expired", "reservation_refunded",
    ] as const, "Royalty terminal outcome"),
    chain_id: literal(evidence.chain_id, BASE_SEPOLIA.id, "Royalty terminal chain"),
    block_number: uintString(evidence.block_number, "Royalty terminal block"),
    block_hash: bytes32(evidence.block_hash, "Royalty terminal block hash"),
    block_timestamp: uintString(evidence.block_timestamp, "Royalty terminal block time"),
    funding_reservation_id: bytes32(
      evidence.funding_reservation_id,
      "Royalty terminal reservation ID",
    ),
    reservation_storage_status: oneOf(evidence.reservation_storage_status, [
      "active", "refunded",
    ] as const, "Royalty terminal storage status"),
    reservation_active: literal(evidence.reservation_active, false, "Royalty terminal active state"),
    reservation_consumed: literal(evidence.reservation_consumed, false, "Royalty terminal consumed state"),
    reservation_deposited_amount: uintString(
      evidence.reservation_deposited_amount,
      "Royalty terminal deposited amount",
      { positive: false },
    ),
    settlement_processed: literal(evidence.settlement_processed, false, "Royalty terminal settlement state"),
    settlement_nonce_processed: literal(evidence.settlement_nonce_processed, false, "Royalty terminal nonce state"),
    source_commitment: sha256Commitment(
      evidence.source_commitment,
      "Royalty terminal source",
    ),
  });
}

export function parseCollaborationRoyaltySettlementStatus(
  value: unknown,
  expected?: { executionId?: string; sponsorAddress?: string },
): CollaborationRoyaltySettlementStatus {
  const status = object(value, "Collaboration Royalty settlement status");
  exactKeys(status, STATUS_KEYS, "Collaboration Royalty settlement status");
  const state = oneOf(status.state, [
    "not_requested", "prepare_requested", "authorizing", "plan_ready",
    "broadcast_reported", "settled", "expired", "reservation_expired", "refunded",
    "reconciliation_hold",
  ] as const, "Royalty settlement state");
  const executionId = typeof status.execution_id === "string"
    && EXECUTION_ID.test(status.execution_id) ? status.execution_id : undefined;
  if (!executionId) throw new Error("Royalty settlement execution ID is invalid");
  const sponsor = address(status.sponsor_address, "Royalty settlement sponsor");
  if (
    (expected?.executionId && expected.executionId !== executionId)
    || (expected?.sponsorAddress
      && expected.sponsorAddress.toLowerCase() !== sponsor.toLowerCase())
  ) throw new Error("Royalty settlement status belongs to another execution or sponsor");
  const generation = uintString(
    status.generation,
    "Royalty settlement generation",
    { positive: state !== "not_requested" },
  );
  const prepareRequestedAt = status.prepare_requested_at === null
    ? null
    : uintString(status.prepare_requested_at, "Settlement prepare time");
  const planCommitment = status.plan_commitment === null
    ? null
    : bytes32(status.plan_commitment, "Settlement plan commitment");
  const authorizationExpiresAt = status.authorization_expires_at === null
    ? null
    : uintString(status.authorization_expires_at, "Settlement authorization expiry");
  const walletPlan = status.wallet_plan === null
    ? null
    : parseCollaborationRoyaltySettlementWalletPlan(status.wallet_plan);
  const hint = parseBroadcastHint(status.broadcast_hint);
  const finalized = parseFinalizedSettlement(status.finalized_settlement);
  const terminal = parseTerminalEvidence(status.terminal_evidence);
  const fundingReservationId = bytes32(status.funding_reservation_id, "Funding reservation ID");
  const settlementId = bytes32(status.settlement_id, "Settlement ID");
  const settlementNonce = uintString(status.settlement_nonce, "Settlement nonce");
  const refundAfter = uintString(status.refund_after, "Reservation refund time");
  const failureCode = status.failure_code === null
    ? null
    : typeof status.failure_code === "string" && FAILURE_CODE.test(status.failure_code)
      ? status.failure_code
      : undefined;
  if (failureCode === undefined) throw new Error("Royalty settlement failure code is invalid");
  const retryable = typeof status.retryable === "boolean"
    ? status.retryable
    : (() => { throw new Error("Settlement retry state is invalid"); })();
  const planState = ["plan_ready", "broadcast_reported", "settled"].includes(state);
  if (
    (state === "not_requested") !== (generation === "0")
    || (state === "not_requested") !== (prepareRequestedAt === null)
    || (planCommitment === null) !== (authorizationExpiresAt === null)
    || (planState && planCommitment === null)
    || (walletPlan !== null && state !== "plan_ready")
    || (hint !== null && walletPlan !== null)
    || (state === "broadcast_reported" && hint === null)
    || (state === "settled") !== (finalized !== null)
    || (["reservation_expired", "refunded"].includes(state)) !== (terminal !== null)
  ) throw new Error("Royalty settlement status is contradictory");
  if (terminal && (
    terminal.funding_reservation_id !== fundingReservationId
    || BigInt(terminal.block_timestamp) < BigInt(refundAfter)
    || (state === "reservation_expired" && (
      terminal.outcome !== "reservation_expired"
      || terminal.reservation_storage_status !== "active"
      || terminal.reservation_deposited_amount === "0"
    ))
    || (state === "refunded" && (
      terminal.outcome !== "reservation_refunded"
      || terminal.reservation_storage_status !== "refunded"
      || terminal.reservation_deposited_amount !== "0"
    ))
  )) throw new Error("Royalty terminal evidence changed across status");
  if (
    (["not_requested", "prepare_requested", "authorizing"].includes(state)
      && (failureCode !== null || !retryable))
    || (["plan_ready", "broadcast_reported", "settled"].includes(state)
      && (failureCode !== null || retryable))
    || (state === "expired"
      && (failureCode !== "authorization_expired" || !retryable))
    || (state === "reservation_expired"
      && (failureCode !== "reservation_expired" || retryable))
    || (state === "refunded"
      && (failureCode !== "reservation_refunded" || retryable))
    || (state === "reconciliation_hold" && failureCode === null)
  ) throw new Error("Royalty settlement failure/retry state is contradictory");
  if (walletPlan && (
    walletPlan.plan_commitment !== planCommitment
    || walletPlan.authorization_expires_at !== authorizationExpiresAt
    || walletPlan.refund_after !== refundAfter
    || walletPlan.funding_reservation_id !== fundingReservationId
    || walletPlan.settlement_id !== settlementId
    || walletPlan.settlement_nonce !== settlementNonce
  )) throw new Error("Royalty settlement wallet plan changed across the status envelope");
  return Object.freeze({
    schema: literal(status.schema, "dnai.collaboration.royalty-settlement-status.v2", "Settlement status schema"),
    execution_id: executionId,
    sponsor_address: sponsor,
    state,
    generation,
    funding_reservation_id: fundingReservationId,
    settlement_id: settlementId,
    settlement_nonce: settlementNonce,
    refund_after: refundAfter,
    prepare_requested_at: prepareRequestedAt,
    plan_commitment: planCommitment,
    authorization_expires_at: authorizationExpiresAt,
    wallet_plan: walletPlan,
    broadcast_hint: hint,
    finalized_settlement: finalized,
    terminal_evidence: terminal,
    failure_code: failureCode,
    retryable,
    modeled: literal(status.modeled, false, "Settlement modeled boundary"),
    raw_secret_egress: literal(status.raw_secret_egress, false, "Settlement secret boundary"),
    clientProjectionProvesSettlement: false as const,
  });
}

function exactIdempotencyKey(value: string): string {
  if (typeof value !== "string" || !IDEMPOTENCY.test(value)) {
    throw new Error("Royalty settlement idempotency key is invalid");
  }
  return value;
}

export async function prepareCollaborationRoyaltySettlement(
  token: string,
  executionId: string,
  input: { readonly idempotency_key: string; readonly replace_expired: boolean },
  sponsorAddress?: string,
  signal?: AbortSignal,
): Promise<CollaborationRoyaltySettlementStatus> {
  if (!EXECUTION_ID.test(executionId)) throw new Error("Royalty settlement execution ID is invalid");
  exactKeys(object(input, "Royalty settlement prepare request"), [
    "idempotency_key", "replace_expired",
  ], "Royalty settlement prepare request");
  exactIdempotencyKey(input.idempotency_key);
  if (typeof input.replace_expired !== "boolean") {
    throw new Error("Royalty settlement replacement flag is invalid");
  }
  return parseCollaborationRoyaltySettlementStatus(
    await requestCollaborationAuthenticatedApi(
      `/collaboration/executions/${encodeURIComponent(executionId)}/royalty-settlement/prepare`,
      { method: "POST", token, body: { ...input }, signal },
    ),
    { executionId, sponsorAddress },
  );
}

export async function fetchCollaborationRoyaltySettlementStatus(
  token: string,
  executionId: string,
  sponsorAddress?: string,
  signal?: AbortSignal,
): Promise<CollaborationRoyaltySettlementStatus> {
  if (!EXECUTION_ID.test(executionId)) throw new Error("Royalty settlement execution ID is invalid");
  return parseCollaborationRoyaltySettlementStatus(
    await requestCollaborationAuthenticatedApi(
      `/collaboration/executions/${encodeURIComponent(executionId)}/royalty-settlement`,
      { token, signal },
    ),
    { executionId, sponsorAddress },
  );
}

export async function reportCollaborationRoyaltySettlementBroadcast(
  token: string,
  executionId: string,
  input: {
    readonly idempotency_key: string;
    readonly plan_commitment: string;
    readonly transaction_hash: string;
  },
  sponsorAddress?: string,
  signal?: AbortSignal,
): Promise<CollaborationRoyaltySettlementStatus> {
  if (!EXECUTION_ID.test(executionId)) throw new Error("Royalty settlement execution ID is invalid");
  exactKeys(object(input, "Royalty settlement broadcast report"), [
    "idempotency_key", "plan_commitment", "transaction_hash",
  ], "Royalty settlement broadcast report");
  exactIdempotencyKey(input.idempotency_key);
  bytes32(input.plan_commitment, "Settlement plan commitment");
  bytes32(input.transaction_hash, "Settlement transaction hash");
  return parseCollaborationRoyaltySettlementStatus(
    await requestCollaborationAuthenticatedApi(
      `/collaboration/executions/${encodeURIComponent(executionId)}/royalty-settlement/broadcast`,
      { method: "POST", token, body: { ...input }, signal },
    ),
    { executionId, sponsorAddress },
  );
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function settlementReleaseFingerprint(
  executionId: string,
  plan: CollaborationRoyaltySettlementWalletPlan,
): string {
  return JSON.stringify([
    "dnai.collaboration.royalty-settlement.release.v1",
    deployment.release,
    deployment.releaseSha ?? null,
    deployment.collaborationExecutionRelease.releaseVerificationSha256 ?? null,
    BASE_SEPOLIA.id,
    executionId,
    plan.plan_commitment,
    plan.to.toLowerCase(),
    deployment.royaltyDistributorCodeHash?.toLowerCase() ?? null,
    plan.authorization.release_policy_commitment,
    plan.anchor_finality.contract_address.toLowerCase(),
    plan.anchor_finality.runtime_code_hash,
  ]);
}

export function assertCollaborationSettlementPlanMatchesCurrentRelease(
  plan: CollaborationRoyaltySettlementWalletPlan,
): void {
  const release = deployment.collaborationExecutionRelease;
  const authority = deployment.royaltyRelease.authority;
  if (
    !release.configured
    || !release.executionEnabled
    || !deployment.royaltyDistributorAddress
    || !deployment.royaltyDistributorCodeHash
    || !deployment.composeHash
    || !deployment.appId
    || !deployment.osImageHash
    || !deployment.executionPolicyAnchorAddress
    || !deployment.executionPolicyAnchorCodeHash
    || !authority
    || !sameHex(plan.to, deployment.royaltyDistributorAddress)
    || !sameHex(plan.authorization.release_policy_commitment, authority.release_policy_commitment)
    || !sameHex(plan.settlement_verifier_address, authority.settlement_verifier)
    || !sameHex(plan.qvl_verifier_address, authority.qvl_verifier)
    || !sameHex(plan.anchor_finality.contract_address, authority.execution_policy_anchor)
    || !sameHex(plan.anchor_finality.contract_address, deployment.executionPolicyAnchorAddress)
    || !sameHex(plan.anchor_finality.runtime_code_hash, deployment.executionPolicyAnchorCodeHash)
    || !sameHex(plan.anchor_finality.writer, authority.anchor_writer)
    || !sameHex(plan.anchor_finality.writer_release_commitment, authority.anchor_writer_release_commitment)
    || !sameHex(plan.compose_hash, deployment.composeHash)
    || plan.app_id !== deployment.appId.toLowerCase()
    || plan.os_image_hash !== deployment.osImageHash.toLowerCase()
  ) throw new Error("Royalty settlement plan does not match the current reviewed release");
}

export type CollaborationRoyaltySettlementIntentStage =
  | "plan_persisted"
  | "transaction_submitted"
  | "broadcast_reported";

export interface CollaborationRoyaltySettlementIntent {
  readonly surface: "collaboration_royalty_settlement_intent";
  readonly schemaVersion: 1;
  readonly executionId: string;
  readonly account: Address;
  readonly authorizationVersion: number;
  readonly releaseFingerprint: string;
  readonly broadcastIdempotencyKey: string;
  readonly createdAt: number;
  readonly stage: CollaborationRoyaltySettlementIntentStage;
  readonly plan: CollaborationRoyaltySettlementWalletPlan;
  readonly transactionHash?: Hex;
}

export class CollaborationSettlementRetentionError extends Error {
  readonly intent: CollaborationRoyaltySettlementIntent;

  constructor(message: string, intent: CollaborationRoyaltySettlementIntent) {
    super(message);
    this.name = "CollaborationSettlementRetentionError";
    this.intent = intent;
  }
}

export interface CollaborationRoyaltySettlementStorage {
  readonly length?: number;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key?(index: number): string | null;
}

function settlementStorageKey(input: {
  account: string;
  executionId: string;
  planCommitment: string;
}): string {
  return [
    SETTLEMENT_STORAGE_PREFIX,
    BASE_SEPOLIA.id,
    address(input.account, "Settlement storage account").toLowerCase(),
    input.executionId,
    bytes32(input.planCommitment, "Settlement storage plan"),
  ].join(":");
}

function storedSettlementPayload(intent: CollaborationRoyaltySettlementIntent) {
  return {
    surface: intent.surface,
    schemaVersion: intent.schemaVersion,
    executionId: intent.executionId,
    account: intent.account.toLowerCase(),
    authorizationVersion: intent.authorizationVersion,
    releaseFingerprint: intent.releaseFingerprint,
    broadcastIdempotencyKey: intent.broadcastIdempotencyKey,
    createdAt: intent.createdAt,
    stage: intent.stage,
    plan: intent.plan,
    transactionHash: intent.transactionHash ?? null,
  };
}

export function serializeCollaborationRoyaltySettlementIntent(
  intent: CollaborationRoyaltySettlementIntent,
): string {
  const payload = storedSettlementPayload(intent);
  return JSON.stringify({
    recordType: SETTLEMENT_STORAGE_RECORD,
    schemaVersion: 1,
    payload,
    integrityHash: keccak256(stringToHex(JSON.stringify(payload))),
  });
}

export function parseStoredCollaborationRoyaltySettlementIntent(
  serialized: string,
  context: { account: string; authorizationVersion: number },
): CollaborationRoyaltySettlementIntent {
  if (
    typeof serialized !== "string"
    || serialized.length < 2
    || serialized.length > MAX_STORAGE_BYTES
  ) throw new Error("Retained Royalty settlement intent is invalid");
  let envelope: unknown;
  try { envelope = JSON.parse(serialized) as unknown; } catch {
    throw new Error("Retained Royalty settlement intent is not JSON");
  }
  const root = object(envelope, "Retained Royalty settlement envelope");
  exactKeys(root, ["recordType", "schemaVersion", "payload", "integrityHash"], "Retained Royalty settlement envelope");
  literal(root.recordType, SETTLEMENT_STORAGE_RECORD, "Retained settlement record type");
  literal(root.schemaVersion, 1, "Retained settlement schema");
  const payload = object(root.payload, "Retained Royalty settlement payload");
  exactKeys(payload, [
    "surface", "schemaVersion", "executionId", "account",
    "authorizationVersion", "releaseFingerprint", "broadcastIdempotencyKey",
    "createdAt", "stage", "plan", "transactionHash",
  ], "Retained Royalty settlement payload");
  if (root.integrityHash !== keccak256(stringToHex(JSON.stringify(payload)))) {
    throw new Error("Retained Royalty settlement integrity check failed");
  }
  const plan = parseCollaborationRoyaltySettlementWalletPlan(payload.plan);
  assertCollaborationSettlementPlanMatchesCurrentRelease(plan);
  const executionId = typeof payload.executionId === "string"
    && EXECUTION_ID.test(payload.executionId) ? payload.executionId : undefined;
  const account = address(context.account, "Settlement restore account");
  const releaseFingerprint = executionId
    ? settlementReleaseFingerprint(executionId, plan)
    : "";
  const stage = oneOf(payload.stage, [
    "plan_persisted", "transaction_submitted", "broadcast_reported",
  ] as const, "Retained settlement stage");
  const transactionHash = payload.transactionHash === null
    ? undefined
    : bytes32(payload.transactionHash, "Retained settlement transaction hash");
  if (
    !executionId
    || payload.surface !== "collaboration_royalty_settlement_intent"
    || payload.schemaVersion !== 1
    || typeof payload.account !== "string"
    || payload.account.toLowerCase() !== account.toLowerCase()
    || payload.releaseFingerprint !== releaseFingerprint
    || !Number.isSafeInteger(context.authorizationVersion)
    || context.authorizationVersion < 0
    || !Number.isSafeInteger(payload.createdAt)
    || Number(payload.createdAt) < 1
    || (stage === "plan_persisted" && transactionHash)
    || (stage !== "plan_persisted" && !transactionHash)
  ) throw new Error("Retained Royalty settlement context changed");
  return Object.freeze({
    surface: "collaboration_royalty_settlement_intent" as const,
    schemaVersion: 1 as const,
    executionId,
    account,
    authorizationVersion: context.authorizationVersion,
    releaseFingerprint,
    broadcastIdempotencyKey: exactIdempotencyKey(String(payload.broadcastIdempotencyKey)),
    createdAt: Number(payload.createdAt),
    stage,
    plan,
    transactionHash,
  });
}

function retainSettlementIntent(
  storage: CollaborationRoyaltySettlementStorage,
  intent: CollaborationRoyaltySettlementIntent,
): void {
  storage.setItem(
    settlementStorageKey({
      account: intent.account,
      executionId: intent.executionId,
      planCommitment: intent.plan.plan_commitment,
    }),
    serializeCollaborationRoyaltySettlementIntent(intent),
  );
}

export function restoreCollaborationRoyaltySettlementIntent(
  storage: CollaborationRoyaltySettlementStorage,
  context: {
    account: string;
    authorizationVersion: number;
    executionId: string;
  },
): CollaborationRoyaltySettlementIntent | undefined {
  if (
    typeof storage.length !== "number"
    || !Number.isSafeInteger(storage.length)
    || storage.length < 0
    || storage.length > 512
    || typeof storage.key !== "function"
  ) throw new Error("Settlement storage cannot be recovered safely");
  const prefix = [
    SETTLEMENT_STORAGE_PREFIX,
    BASE_SEPOLIA.id,
    address(context.account, "Settlement restore account").toLowerCase(),
    context.executionId,
    "",
  ].join(":");
  const matches: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key?.startsWith(prefix)) matches.push(key);
  }
  if (matches.length === 0) return undefined;
  if (matches.length !== 1) {
    throw new Error("Multiple retained Royalty settlement plans require reconciliation");
  }
  const serialized = storage.getItem(matches[0]);
  if (!serialized) throw new Error("Retained Royalty settlement disappeared");
  return parseStoredCollaborationRoyaltySettlementIntent(serialized, context);
}

export function listCollaborationRoyaltySettlementIntents(
  storage: CollaborationRoyaltySettlementStorage,
  context: { account: string; authorizationVersion: number },
): readonly CollaborationRoyaltySettlementIntent[] {
  if (
    typeof storage.length !== "number"
    || !Number.isSafeInteger(storage.length)
    || storage.length < 0
    || storage.length > 512
    || typeof storage.key !== "function"
  ) throw new Error("Settlement storage cannot be enumerated safely");
  const prefix = [
    SETTLEMENT_STORAGE_PREFIX,
    BASE_SEPOLIA.id,
    address(context.account, "Settlement restore account").toLowerCase(),
    "",
  ].join(":");
  const records: CollaborationRoyaltySettlementIntent[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (!key?.startsWith(prefix)) continue;
    const serialized = storage.getItem(key);
    if (!serialized) throw new Error("Retained Royalty settlement disappeared");
    records.push(parseStoredCollaborationRoyaltySettlementIntent(
      serialized,
      context,
    ));
  }
  records.sort((left, right) => (
    left.executionId.localeCompare(right.executionId)
    || left.plan.plan_commitment.localeCompare(right.plan.plan_commitment)
  ));
  return Object.freeze(records);
}

function currentWalletContext(): {
  account: Address;
  authorizationVersion: number;
  client: NonNullable<ReturnType<typeof wallet.client>>;
} {
  const account = wallet.account();
  const client = wallet.client();
  if (!account || !client || wallet.chainId() !== BASE_SEPOLIA.id) {
    throw new Error("Connect the settlement sponsor on Base Sepolia");
  }
  return { account, client, authorizationVersion: wallet.authorizationVersion() };
}

function assertStableSettlementWallet(
  intent: CollaborationRoyaltySettlementIntent,
  client: NonNullable<ReturnType<typeof wallet.client>>,
): void {
  if (
    wallet.client() !== client
    || wallet.account()?.toLowerCase() !== intent.account.toLowerCase()
    || wallet.chainId() !== BASE_SEPOLIA.id
    || wallet.authorizationVersion() !== intent.authorizationVersion
    || settlementReleaseFingerprint(intent.executionId, intent.plan)
      !== intent.releaseFingerprint
  ) throw new Error("Wallet, network, or reviewed release changed during settlement");
}

async function assertFreshRoyaltySettlementAuthority(
  intent: CollaborationRoyaltySettlementIntent,
): Promise<void> {
  const state = await loadFinalizedRoyaltyRailState(intent.account);
  const observation = state.settlementAuthority.observation;
  if (
    !state.runtimeVerified
    || state.observedChainId !== BASE_SEPOLIA.id
    || !state.address
    || !state.runtimeCodeHash
    || state.blockNumber === undefined
    || !state.blockHash
    || state.observationFinality !== "rpc_reported_finalized"
    || !sameHex(state.address, intent.plan.to)
    || !state.settlementAuthority.releaseEvidenceVerified
    || !state.settlementAuthority.browserObservationAvailable
    || !state.settlementAuthority.browserMatchesRelease
    || !state.settlementAuthority.newSettlementsEnabled
    || state.settlementAuthority.issues.length > 0
    || !observation
    || observation.blockNumber !== state.blockNumber
    || !sameHex(observation.releasePolicyCommitment, intent.plan.authorization.release_policy_commitment)
    || !sameHex(observation.settlementVerifier, intent.plan.settlement_verifier_address)
    || !sameHex(observation.qvlVerifier, intent.plan.qvl_verifier_address)
    || !sameHex(observation.executionPolicyAnchor, intent.plan.anchor_finality.contract_address)
    || !sameHex(observation.anchorWriterReleaseCommitment, intent.plan.anchor_finality.writer_release_commitment)
  ) throw new Error(
    state.settlementAuthority.issues[0]
      ?? state.issues[0]
      ?? "Fresh Royalty settlement authority is unavailable",
  );
}

export function persistCollaborationRoyaltySettlementPlan(
  status: CollaborationRoyaltySettlementStatus,
  broadcastIdempotencyKey: string,
  storage: CollaborationRoyaltySettlementStorage,
): CollaborationRoyaltySettlementIntent {
  const plan = status.wallet_plan;
  if (status.state !== "plan_ready" || !plan) {
    throw new Error("No current sponsor wallet settlement plan is available");
  }
  assertCollaborationSettlementPlanMatchesCurrentRelease(plan);
  const context = currentWalletContext();
  if (context.account.toLowerCase() !== status.sponsor_address.toLowerCase()) {
    throw new Error("Connected wallet is not the settlement sponsor");
  }
  const intent: CollaborationRoyaltySettlementIntent = Object.freeze({
    surface: "collaboration_royalty_settlement_intent" as const,
    schemaVersion: 1 as const,
    executionId: status.execution_id,
    account: context.account,
    authorizationVersion: context.authorizationVersion,
    releaseFingerprint: settlementReleaseFingerprint(status.execution_id, plan),
    broadcastIdempotencyKey: exactIdempotencyKey(broadcastIdempotencyKey),
    createdAt: Math.floor(Date.now() / 1_000),
    stage: "plan_persisted" as const,
    plan,
  });
  const key = settlementStorageKey({
    account: intent.account,
    executionId: intent.executionId,
    planCommitment: intent.plan.plan_commitment,
  });
  const existing = storage.getItem(key);
  if (existing !== null) {
    return parseStoredCollaborationRoyaltySettlementIntent(existing, {
      account: context.account,
      authorizationVersion: context.authorizationVersion,
    });
  }
  // Exact public plan and report idempotency are durable before any wallet prompt.
  retainSettlementIntent(storage, intent);
  return intent;
}

const activeSettlementMutations = new Set<string>();

async function withSettlementLock<T>(
  intent: CollaborationRoyaltySettlementIntent,
  action: () => Promise<T>,
): Promise<T> {
  const key = `${intent.account.toLowerCase()}:${intent.plan.plan_commitment}`;
  if (activeSettlementMutations.has(key)) {
    throw new Error("This exact Royalty settlement already has a wallet operation in progress");
  }
  activeSettlementMutations.add(key);
  try { return await action(); } finally { activeSettlementMutations.delete(key); }
}

export async function submitCollaborationRoyaltySettlement(
  intent: CollaborationRoyaltySettlementIntent,
  token: string,
  storage: CollaborationRoyaltySettlementStorage,
): Promise<CollaborationRoyaltySettlementIntent> {
  return withSettlementLock(intent, async () => {
    if (intent.transactionHash) {
      throw new Error("The retained settlement hash must be reconciled; do not rebroadcast");
    }
    const context = currentWalletContext();
    assertStableSettlementWallet(intent, context.client);
    const assertSponsorWindow = () => {
      if (
        BigInt(intent.plan.authorization_expires_at)
          < BigInt(Math.floor(Date.now() / 1_000) + 30)
      ) throw new Error(
        "The settlement plan no longer has the required 30-second sponsor window",
      );
    };
    assertSponsorWindow();
    const status = await fetchCollaborationRoyaltySettlementStatus(
      token,
      intent.executionId,
      intent.account,
    );
    if (
      status.state !== "plan_ready"
      || !status.wallet_plan
      || status.wallet_plan.plan_commitment !== intent.plan.plan_commitment
      || status.wallet_plan.data !== intent.plan.data
    ) throw new Error("The exact settlement plan is no longer current or broadcastable");
    assertCollaborationSettlementPlanMatchesCurrentRelease(status.wallet_plan);
    await assertFreshRoyaltySettlementAuthority(intent);
    assertStableSettlementWallet(intent, context.client);
    const simulation = await publicClient.simulateContract({
      account: intent.account,
      address: intent.plan.to,
      abi: collaborationRoyaltySettlementAbi,
      functionName: "settleReserved",
      args: [
        intent.plan.funding_reservation_id,
        authorizationArgs(intent.plan.authorization),
        intent.plan.owners,
        intent.plan.amounts.map(BigInt),
        intent.plan.settlement_authorization_signature,
        intent.plan.qvl_authorization_signature,
      ],
    });
    assertStableSettlementWallet(intent, context.client);
    assertSponsorWindow();
    const transactionHash = bytes32(
      await context.client.writeContract(simulation.request as never),
      "Settlement transaction hash",
    );
    const submitted = Object.freeze({
      ...intent,
      stage: "transaction_submitted" as const,
      transactionHash,
    });
    try {
      retainSettlementIntent(storage, submitted);
    } catch {
      throw new CollaborationSettlementRetentionError(
        `Wallet returned ${transactionHash}, but retention failed. Reconcile this hash; do not rebroadcast.`,
        submitted,
      );
    }
    return submitted;
  });
}

export async function reportRetainedCollaborationSettlementBroadcast(
  intent: CollaborationRoyaltySettlementIntent,
  token: string,
  storage: CollaborationRoyaltySettlementStorage,
): Promise<{
  readonly intent: CollaborationRoyaltySettlementIntent;
  readonly status: CollaborationRoyaltySettlementStatus;
}> {
  if (!intent.transactionHash) throw new Error("No retained settlement transaction hash exists");
  const status = await reportCollaborationRoyaltySettlementBroadcast(
    token,
    intent.executionId,
    {
      idempotency_key: intent.broadcastIdempotencyKey,
      plan_commitment: intent.plan.plan_commitment,
      transaction_hash: intent.transactionHash,
    },
    intent.account,
  );
  if (
    ![
      "broadcast_reported",
      "settled",
      "expired",
      "reservation_expired",
      "refunded",
      "reconciliation_hold",
    ].includes(status.state)
    || status.wallet_plan !== null
    || status.plan_commitment !== intent.plan.plan_commitment
    || status.broadcast_hint?.transaction_hash !== intent.transactionHash
  ) throw new Error(
    "Settlement broadcast acknowledgement changed the retained hash or plan",
  );
  const reported = Object.freeze({
    ...intent,
    stage: "broadcast_reported" as const,
  });
  retainSettlementIntent(storage, reported);
  return { intent: reported, status };
}

export type CollaborationSettlementReconciliationState =
  | "pending"
  | "included"
  | "browser_finalized_included"
  | "settled"
  | "refunded"
  | "reverted"
  | "ambiguous";

export interface CollaborationSettlementReconciliation {
  readonly state: CollaborationSettlementReconciliationState;
  readonly intent: CollaborationRoyaltySettlementIntent;
  readonly status: CollaborationRoyaltySettlementStatus;
  readonly transactionHash: Hex;
  readonly browserFinalizedInclusion: boolean;
  readonly serverFinalizedSettlement: boolean;
  readonly clearRetainedIntent: boolean;
  readonly detail: string;
}

export async function reconcileCollaborationRoyaltySettlement(
  intent: CollaborationRoyaltySettlementIntent,
  token: string,
): Promise<CollaborationSettlementReconciliation> {
  const transactionHash = intent.transactionHash;
  if (!transactionHash) throw new Error("No retained settlement transaction hash exists");
  const [status, chainId, finalized] = await Promise.all([
    fetchCollaborationRoyaltySettlementStatus(
      token,
      intent.executionId,
      intent.account,
    ),
    publicClient.getChainId(),
    publicClient.getBlock({ blockTag: "finalized" }),
  ]);
  if (chainId !== BASE_SEPOLIA.id || finalized.number === null || !finalized.hash) {
    throw new Error("Base Sepolia finalized-head evidence is unavailable");
  }
  let receipt: Awaited<ReturnType<typeof publicClient.getTransactionReceipt>> | undefined;
  try { receipt = await publicClient.getTransactionReceipt({ hash: transactionHash }); } catch {
    receipt = undefined;
  }
  let isFinalized = false;
  if (receipt) {
    const transaction = await publicClient.getTransaction({ hash: transactionHash });
    const receiptBlock = await publicClient.getBlock({ blockNumber: receipt.blockNumber });
    if (
      !sameHex(receipt.transactionHash, transactionHash)
      || receiptBlock.hash !== receipt.blockHash
      || transaction.blockNumber !== receipt.blockNumber
      || !sameHex(transaction.blockHash ?? undefined, receipt.blockHash)
      || !sameHex(receipt.from, intent.account)
      || !sameHex(receipt.to ?? undefined, intent.plan.to)
      || !sameHex(transaction.from, intent.account)
      || !sameHex(transaction.to ?? undefined, intent.plan.to)
      || !sameHex(transaction.input, intent.plan.data)
      || transaction.value !== 0n
    ) throw new Error("Settlement transaction evidence does not match the retained plan");
    isFinalized = receipt.blockNumber <= finalized.number;
  }
  if (
    status.state === "settled"
    && status.finalized_settlement
  ) {
    const serverFinalizedBlockNumber = BigInt(
      status.finalized_settlement.block_number,
    );
    const [serverFinalizedBlock, runtime, settlementState] = await Promise.all([
      publicClient.getBlock({ blockNumber: serverFinalizedBlockNumber }),
      publicClient.getBytecode({
        address: intent.plan.to,
        blockNumber: finalized.number,
      }),
      publicClient.readContract({
        address: intent.plan.to,
        abi: collaborationRoyaltySettlementAbi,
        functionName: "fundingReservationSettlementState",
        args: [intent.plan.funding_reservation_id],
        blockNumber: finalized.number,
      }),
    ]);
    const runtimeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
    const sameAuthorizedGeneration = status.plan_commitment === intent.plan.plan_commitment;
    const exactFinalizedState = Boolean(
      serverFinalizedBlockNumber <= finalized.number
      && serverFinalizedBlock.hash
      && sameHex(
        serverFinalizedBlock.hash,
        status.finalized_settlement.block_hash,
      )
      && runtimeHash
      && deployment.royaltyDistributorCodeHash
      && sameHex(runtimeHash, deployment.royaltyDistributorCodeHash)
      && settlementState.consumed
      && settlementState.settlementProcessed
      && settlementState.nonceProcessed
      && sameHex(settlementState.settlementId, intent.plan.settlement_id)
      && settlementState.settlementNonce === BigInt(intent.plan.settlement_nonce)
      && sameHex(settlementState.asset, intent.plan.authorization.asset)
      && settlementState.total === BigInt(intent.plan.authorization.total)
      && sameHex(
        settlementState.ownerAmountsHash,
        intent.plan.authorization.owners_amounts_hash,
      )
    );
    if (exactFinalizedState) {
      return {
        state: "settled",
        intent,
        status,
        transactionHash,
        browserFinalizedInclusion: isFinalized,
        serverFinalizedSettlement: sameAuthorizedGeneration,
        clearRetainedIntent: true,
        detail: !sameAuthorizedGeneration
          ? "Canonical finalized RoyaltyDistributor state proves the reservation consumed with both replay markers processed, but the authenticated journal belongs to a different authorized plan generation. This obsolete retained intent is safe to clear; it is not proof that this exact plan settled."
          : receipt?.status === "reverted"
            ? "The sponsor transaction reverted after another relay settled the same exact plan, but canonical finalized RoyaltyDistributor state proves the reservation consumed with both replay markers processed."
            : !receipt
              ? "The sponsor hash has no receipt, but authenticated finalized journal evidence and a fresh canonical RoyaltyDistributor read prove the exact reservation consumed with both replay markers processed."
              : "The retained transaction is canonical and finalized, and a fresh finalized RoyaltyDistributor read proves the exact reservation consumed with both replay markers processed.",
      };
    }
    return {
      state: "ambiguous",
      intent,
      status,
      transactionHash,
      browserFinalizedInclusion: isFinalized,
      serverFinalizedSettlement: false,
      clearRetainedIntent: false,
      detail: "The API reports settlement, but the browser could not independently bind that report to exact canonical finalized RoyaltyDistributor state. Keep the retained hash.",
    };
  }
  if (
    status.state === "refunded"
    && status.terminal_evidence
  ) {
    const terminalBlockNumber = BigInt(status.terminal_evidence.block_number);
    const [terminalBlock, runtime, reservationResult] = await Promise.all([
      publicClient.getBlock({ blockNumber: terminalBlockNumber }),
      publicClient.getBytecode({
        address: intent.plan.to,
        blockNumber: finalized.number,
      }),
      publicClient.readContract({
        address: intent.plan.to,
        abi: collaborationRoyaltySettlementAbi,
        functionName: "fundingReservationState",
        args: [intent.plan.funding_reservation_id],
        blockNumber: finalized.number,
      }),
    ]);
    const [reservation, active] = reservationResult;
    const runtimeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
    const exactRefundedState = Boolean(
      terminalBlockNumber <= finalized.number
      && terminalBlock.hash
      && sameHex(terminalBlock.hash, status.terminal_evidence.block_hash)
      && runtimeHash
      && deployment.royaltyDistributorCodeHash
      && sameHex(runtimeHash, deployment.royaltyDistributorCodeHash)
      && Number(reservation.status) === 3
      && !active
      && sameHex(reservation.intentCommitment, intent.plan.funding_reservation_id)
      && sameHex(reservation.settlementId, intent.plan.settlement_id)
      && reservation.settlementNonce === BigInt(intent.plan.settlement_nonce)
      && sameHex(
        reservation.releasePolicyCommitment,
        intent.plan.authorization.release_policy_commitment,
      )
      && sameHex(
        reservation.ownersAmountsHash,
        intent.plan.authorization.owners_amounts_hash,
      )
      && sameHex(
        reservation.executionCommitment,
        intent.plan.authorization.execution_commitment,
      )
      && sameHex(reservation.sponsor, intent.account)
      && sameHex(reservation.asset, intent.plan.authorization.asset)
      && reservation.total === BigInt(intent.plan.authorization.total)
      && reservation.refundAfter === BigInt(intent.plan.refund_after)
    );
    if (exactRefundedState) {
      return {
        state: "refunded",
        intent,
        status,
        transactionHash,
        browserFinalizedInclusion: isFinalized,
        serverFinalizedSettlement: false,
        clearRetainedIntent: true,
        detail: "The settlement transaction did not win, but authenticated terminal evidence and a fresh canonical finalized RoyaltyDistributor read prove the exact reservation permanently refunded.",
      };
    }
    return {
      state: "ambiguous",
      intent,
      status,
      transactionHash,
      browserFinalizedInclusion: isFinalized,
      serverFinalizedSettlement: false,
      clearRetainedIntent: false,
      detail: "The API reports a refund, but the browser could not bind it to exact canonical finalized reservation state. Keep the retained hash.",
    };
  }
  if (!receipt) {
    return {
      state: "ambiguous",
      intent,
      status,
      transactionHash,
      browserFinalizedInclusion: false,
      serverFinalizedSettlement: false,
      clearRetainedIntent: false,
      detail: "The transaction hash is retained but no conclusive receipt or permanent exact terminal state is available. Do not rebroadcast.",
    };
  }
  if (isFinalized && receipt.status === "reverted") {
    return {
      state: "reverted",
      intent,
      status,
      transactionHash,
      browserFinalizedInclusion: true,
      serverFinalizedSettlement: false,
      clearRetainedIntent: true,
      detail: "The exact settlement transaction reverted in a canonical finalized block and no permanent settled or refunded state is proven.",
    };
  }
  return {
    state: isFinalized ? "browser_finalized_included" : "included",
    intent,
    status,
    transactionHash,
    browserFinalizedInclusion: isFinalized,
    serverFinalizedSettlement: false,
    clearRetainedIntent: false,
    detail: isFinalized
      ? status.state === "refunded"
        ? "The API reports a refund, but this settlement record is retained until exact canonical finalized reservation state is independently reconciled."
        : "The browser sees finalized inclusion, but exact authenticated journal and finalized RoyaltyDistributor state have not both been proven."
      : "The transaction is included but not finalized. Keep the exact retained hash.",
  };
}

export function clearResolvedCollaborationRoyaltySettlement(
  storage: CollaborationRoyaltySettlementStorage,
  result: CollaborationSettlementReconciliation,
): boolean {
  if (
    !result.clearRetainedIntent
    || !["settled", "refunded", "reverted"].includes(result.state)
  ) return false;
  try {
    storage.removeItem(settlementStorageKey({
      account: result.intent.account,
      executionId: result.intent.executionId,
      planCommitment: result.intent.plan.plan_commitment,
    }));
    return true;
  } catch {
    return false;
  }
}
