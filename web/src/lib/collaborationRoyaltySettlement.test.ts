import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  numberToHex,
  padHex,
  sha256,
  stringToHex,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { describe, expect, it } from "vitest";

import {
  collaborationRoyaltySettlementAbi,
  parseCollaborationRoyaltySettlementStatus,
  parseCollaborationRoyaltySettlementWalletPlan,
} from "./collaborationRoyaltySettlement";

// Frozen from the independent Python manual ABI encoder and cross-checked
// byte-for-byte with Foundry cast. The canonical producer fixture remains at
// ⚙️/tinker-delegate/tests/fixtures/collaboration_settle_reserved_calldata_v1.json.
const INDEPENDENT_SETTLE_RESERVED_VECTOR = Object.freeze({
  calldataByteLength: 1_252,
  calldataSha256:
    "sha256:bc53b6726d0da89108a6df4dc7c5b6fbf3d0b5102c24cbd539f0ead3fd6d608b",
  ownersAmountsHash:
    "0x2dcddadc828719d85e5b23aebafab1b66899d4b1f8670f3d6adc3ba3b67eabe5",
  selector: "0xf4ae1db5",
});

const word = (character: string) => `0x${character.repeat(64)}` as Hex;
const address = (character: string) => `0x${character.repeat(40)}` as Address;

function ownerAmountsHash(owners: readonly Address[], amounts: readonly bigint[]): Hex {
  const typehash = keccak256(stringToHex(
    "RoyaltyOwnerAmounts(address[] owners,uint256[] amounts)",
  ));
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
    [
      typehash,
      keccak256(concatHex(owners.map((owner) => padHex(owner, { size: 32 })))),
      keccak256(concatHex(amounts.map((amount) => numberToHex(amount, { size: 32 })))),
    ],
  ));
}

function walletPlan() {
  const owners = [address("8"), address("9")] as const;
  const amounts = [9_007_199_254_740_993n, 29n] as const;
  const authorization = {
    settlement_id: word("1"),
    settlement_nonce: "9007199254741011",
    funding_reservation_id: word("2"),
    release_policy_commitment: word("3"),
    room_commitment: word("4"),
    room_state_commitment: word("5"),
    query_commitment: word("6"),
    grant_set_commitment: word("7"),
    allocation_commitment: word("8"),
    owners_amounts_hash: ownerAmountsHash(owners, amounts),
    asset: zeroAddress,
    total: (amounts[0] + amounts[1]).toString(),
    execution_commitment: word("9"),
    result_commitment: word("a"),
    usage_commitment: word("b"),
    attestation_evidence_hash: word("c"),
    anchor_resource_hash: word("d"),
    anchor_decision_hash: word("e"),
    anchor_sequence: "9007199254741023",
    expiry: "1900000300",
  } as const;
  const settlementSignature = `0x${"1".repeat(130)}` as Hex;
  const qvlSignature = `0x${"2".repeat(130)}` as Hex;
  const args = {
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
  return {
    schema: "dnai.collaboration.royalty-settlement-wallet-plan.v1",
    chain_id: 84_532,
    to: address("1"),
    data: encodeFunctionData({
      abi: collaborationRoyaltySettlementAbi,
      functionName: "settleReserved",
      args: [
        authorization.funding_reservation_id,
        args,
        owners,
        amounts,
        settlementSignature,
        qvlSignature,
      ],
    }),
    value: "0x0",
    function: "settleReserved",
    plan_commitment: word("f"),
    authorization_expires_at: authorization.expiry,
    refund_after: "1900000900",
    funding_reservation_id: authorization.funding_reservation_id,
    settlement_id: authorization.settlement_id,
    settlement_nonce: authorization.settlement_nonce,
    authorization,
    owners,
    amounts: amounts.map(String),
    settlement_verifier_address: address("2"),
    settlement_authorization_digest: word("1"),
    settlement_authorization_signature: settlementSignature,
    qvl_verifier_address: address("3"),
    qvl_policy_commitment: word("2"),
    qvl_authorization_digest: word("3"),
    qvl_authorization_signature: qvlSignature,
    qvl_anchor_evidence_commitment: word("4"),
    qvl_verdict_verifier_address: address("4"),
    qvl_verdict_digest: word("5"),
    qvl_release_policy_hash: word("6"),
    quote_hash: word("7"),
    report_data: word("8"),
    compose_hash: word("9"),
    app_id: "a".repeat(40),
    os_image_hash: "b".repeat(64),
    anchor_finality: {
      schema: "dnai-wikigen/execution-policy-anchor-status/v1",
      status: "rpc_reported_finalized_release_match",
      verification_model: "single_rpc_reported_finalized_with_confirmation_depth",
      chain_id: 84_532,
      block_number: "9007199254741001",
      block_hash: word("a"),
      block_timestamp: "1900000000",
      contract_address: address("5"),
      runtime_code_hash: word("b"),
      writer: address("6"),
      writer_release_commitment: word("c"),
      writer_rotations_frozen: true,
      paused: false,
      global_sequence: "9007199254741024",
      global_head: word("d"),
      resource_id_hash: authorization.anchor_resource_hash.slice(2),
      resource_decision_head: authorization.anchor_decision_hash,
      resource_sequence: authorization.anchor_sequence,
      decision_hash: authorization.anchor_decision_hash.slice(2),
      decision_sequence: authorization.anchor_sequence,
      latest_block_number: "9007199254741010",
      rpc_finalized_block_number: "9007199254741009",
      rpc_finalized_block_hash: word("e"),
      minimum_confirmation_depth: "4",
      observed_confirmation_depth: "10",
      independent_rpc_quorum_verified: false,
      consensus_proof_verified: false,
      opaque_commitments_only: true,
      raw_resource_id_egress: false,
      raw_policy_egress: false,
    },
    sponsor_must_broadcast: true,
    prefunded: true,
    raw_quote_egress: false,
    raw_artifact_egress: false,
    provider_credential_egress: false,
    raw_secret_egress: false,
  };
}

describe("Collaboration Royalty settlement sponsor wallet seam", () => {
  it("recomputes exact settleReserved calldata and preserves all uints above 2^53", () => {
    const parsed = parseCollaborationRoyaltySettlementWalletPlan(walletPlan());
    expect(parsed.authorization.owners_amounts_hash).toBe(
      INDEPENDENT_SETTLE_RESERVED_VECTOR.ownersAmountsHash,
    );
    expect(parsed.data.slice(0, 10)).toBe(
      INDEPENDENT_SETTLE_RESERVED_VECTOR.selector,
    );
    expect((parsed.data.length - 2) / 2).toBe(
      INDEPENDENT_SETTLE_RESERVED_VECTOR.calldataByteLength,
    );
    expect(`sha256:${sha256(parsed.data).slice(2)}`).toBe(
      INDEPENDENT_SETTLE_RESERVED_VECTOR.calldataSha256,
    );
    expect(parsed.settlement_nonce).toBe("9007199254741011");
    expect(parsed.amounts[0]).toBe("9007199254740993");
    expect(parsed.authorization.anchor_sequence).toBe("9007199254741023");
    expect(parsed.anchor_finality.global_sequence).toBe("9007199254741024");
    expect(parsed.raw_quote_egress).toBe(false);
    expect(() => parseCollaborationRoyaltySettlementWalletPlan({
      ...walletPlan(),
      data: "0x1234",
    })).toThrow("calldata does not recompute");
    expect(() => parseCollaborationRoyaltySettlementWalletPlan({
      ...walletPlan(),
      settlement_nonce: Number("9007199254741011"),
    })).toThrow("canonical decimal string");
    expect(() => parseCollaborationRoyaltySettlementWalletPlan({
      ...walletPlan(),
      anchor_finality: {
        ...walletPlan().anchor_finality,
        global_sequence: Number("9007199254741024"),
      },
    })).toThrow("canonical decimal string");
  });

  it("accepts only a cross-bound, non-modeled plan-ready status", () => {
    const plan = walletPlan();
    const status = {
      schema: "dnai.collaboration.royalty-settlement-status.v2",
      execution_id: `exec_${"1".repeat(64)}`,
      sponsor_address: address("7"),
      state: "plan_ready",
      generation: "1",
      funding_reservation_id: plan.funding_reservation_id,
      settlement_id: plan.settlement_id,
      settlement_nonce: plan.settlement_nonce,
      refund_after: plan.refund_after,
      prepare_requested_at: "1900000000",
      plan_commitment: plan.plan_commitment,
      authorization_expires_at: plan.authorization_expires_at,
      wallet_plan: plan,
      broadcast_hint: null,
      finalized_settlement: null,
      terminal_evidence: null,
      failure_code: null,
      retryable: false,
      modeled: false,
      raw_secret_egress: false,
    };
    const parsed = parseCollaborationRoyaltySettlementStatus(status);
    expect(parsed.state).toBe("plan_ready");
    expect(parsed.wallet_plan?.plan_commitment).toBe(plan.plan_commitment);
    expect(parsed.clientProjectionProvesSettlement).toBe(false);
    expect(() => parseCollaborationRoyaltySettlementStatus({
      ...status,
      modeled: true,
    })).toThrow("modeled boundary");
    expect(() => parseCollaborationRoyaltySettlementStatus({
      ...status,
      plan_commitment: word("1"),
    })).toThrow("changed across");
  });

  it("requires exact finalized consumed and processed settlement flags", () => {
    const status = {
      schema: "dnai.collaboration.royalty-settlement-status.v2",
      execution_id: `exec_${"1".repeat(64)}`,
      sponsor_address: address("7"),
      state: "settled",
      generation: "2",
      funding_reservation_id: word("1"),
      settlement_id: word("2"),
      settlement_nonce: "9",
      refund_after: "1900000900",
      prepare_requested_at: "1900000000",
      plan_commitment: word("3"),
      authorization_expires_at: "1900000300",
      wallet_plan: null,
      broadcast_hint: {
        transaction_hash: word("4"),
        reported_at: "1900000010",
      },
      finalized_settlement: {
        chain_id: 84_532,
        block_number: "9007199254740995",
        block_hash: word("5"),
        block_timestamp: "1900000020",
        reservation_active: false,
        reservation_consumed: true,
        settlement_processed: true,
        settlement_nonce_processed: true,
        source_commitment: `sha256:${"6".repeat(64)}`,
      },
      terminal_evidence: null,
      failure_code: null,
      retryable: false,
      modeled: false,
      raw_secret_egress: false,
    };
    expect(parseCollaborationRoyaltySettlementStatus(status).finalized_settlement)
      .toMatchObject({ reservation_consumed: true, settlement_processed: true });
    expect(() => parseCollaborationRoyaltySettlementStatus({
      ...status,
      finalized_settlement: {
        ...status.finalized_settlement,
        reservation_consumed: false,
      },
    })).toThrow("consumed-reservation");
  });

  it("accepts only exact post-expiry and refunded terminal evidence", () => {
    const terminalStatus = {
      schema: "dnai.collaboration.royalty-settlement-status.v2",
      execution_id: `exec_${"1".repeat(64)}`,
      sponsor_address: address("7"),
      state: "reservation_expired",
      generation: "3",
      funding_reservation_id: word("1"),
      settlement_id: word("2"),
      settlement_nonce: "9007199254741011",
      refund_after: "1900000900",
      prepare_requested_at: "1900000000",
      plan_commitment: word("3"),
      authorization_expires_at: "1900000300",
      wallet_plan: null,
      broadcast_hint: null,
      finalized_settlement: null,
      terminal_evidence: {
        outcome: "reservation_expired",
        chain_id: 84_532,
        block_number: "9007199254740995",
        block_hash: word("4"),
        block_timestamp: "1900000900",
        funding_reservation_id: word("1"),
        reservation_storage_status: "active",
        reservation_active: false,
        reservation_consumed: false,
        reservation_deposited_amount: "9007199254740993",
        settlement_processed: false,
        settlement_nonce_processed: false,
        source_commitment: `sha256:${"5".repeat(64)}`,
      },
      failure_code: "reservation_expired",
      retryable: false,
      modeled: false,
      raw_secret_egress: false,
    } as const;

    const expired = parseCollaborationRoyaltySettlementStatus(terminalStatus);
    expect(expired.terminal_evidence).toMatchObject({
      outcome: "reservation_expired",
      reservation_storage_status: "active",
      reservation_deposited_amount: "9007199254740993",
    });
    expect(() => parseCollaborationRoyaltySettlementStatus({
      ...terminalStatus,
      terminal_evidence: {
        ...terminalStatus.terminal_evidence,
        block_timestamp: "1900000899",
      },
    })).toThrow("changed across status");
    expect(() => parseCollaborationRoyaltySettlementStatus({
      ...terminalStatus,
      failure_code: "reservation_refunded",
    })).toThrow("failure/retry state is contradictory");

    const refunded = parseCollaborationRoyaltySettlementStatus({
      ...terminalStatus,
      state: "refunded",
      terminal_evidence: {
        ...terminalStatus.terminal_evidence,
        outcome: "reservation_refunded",
        reservation_storage_status: "refunded",
        reservation_deposited_amount: "0",
      },
      failure_code: "reservation_refunded",
    });
    expect(refunded.state).toBe("refunded");
  });
});
