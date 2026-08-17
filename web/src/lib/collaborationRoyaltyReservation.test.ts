import { describe, expect, it } from "vitest";
import { zeroAddress, type Address, type Hex } from "viem";

import { BASE_SEPOLIA } from "../config";
import {
  COLLABORATION_FUNDING_RESERVATION_TYPE,
  clearResolvedCollaborationReservation,
  collaborationFundingReservationCall,
  collaborationFundingReservationId,
  collaborationReservationReleaseFingerprint,
  collaborationReservationStorageKey,
  listCollaborationReservationIntents,
  parseStoredCollaborationReservationIntent,
  restoreLatestCollaborationReservationIntent,
  retainCollaborationReservationIntent,
  serializeCollaborationReservationIntent,
  verifyCollaborationFundingReservationProjection,
  type CollaborationFundingReservationIntent,
  type CollaborationFundingReservationRequest,
  type CollaborationReservationStorage,
} from "./collaborationRoyaltyReservation";

const DISTRIBUTOR = `0x${"1".repeat(40)}` as Address;
const SPONSOR = `0x${"2".repeat(40)}` as Address;
const TOKEN = `0x${"3".repeat(40)}` as Address;
const word = (character: string) => `0x${character.repeat(64)}` as Hex;

class MemoryStorage implements CollaborationReservationStorage {
  private readonly values = new Map<string, string>();

  get length() { return this.values.size; }
  key(index: number) { return [...this.values.keys()][index] ?? null; }
  getItem(key: string) { return this.values.get(key) ?? null; }
  setItem(key: string, value: string) { this.values.set(key, value); }
  removeItem(key: string) { this.values.delete(key); }
}

function request(asset: Address = zeroAddress): CollaborationFundingReservationRequest {
  return {
    settlementId: word("1"),
    settlementNonce: 7n,
    releasePolicyCommitment: word("2"),
    roomCommitment: word("3"),
    roomStateCommitment: word("4"),
    queryCommitment: word("5"),
    grantSetCommitment: word("6"),
    allocationCommitment: word("7"),
    ownersAmountsHash: word("8"),
    asset,
    total: 2_000n,
    executionCommitment: word("9"),
    refundAfter: 1_900_001_500n,
  };
}

describe("Collaboration Royalty reservation contract binding", () => {
  it("pins the exact Solidity type and deterministic sponsor-bound reservation ID", () => {
    expect(COLLABORATION_FUNDING_RESERVATION_TYPE).toContain(
      "address distributor,address sponsor,bytes32 settlementId",
    );
    const first = collaborationFundingReservationId({
      chainId: BASE_SEPOLIA.id,
      distributor: DISTRIBUTOR,
      sponsor: SPONSOR,
      request: request(),
    });
    expect(first).toMatch(/^0x[0-9a-f]{64}$/);
    expect(collaborationFundingReservationId({
      chainId: BASE_SEPOLIA.id,
      distributor: DISTRIBUTOR,
      sponsor: SPONSOR,
      request: request(),
    })).toBe(first);
    expect(collaborationFundingReservationId({
      chainId: BASE_SEPOLIA.id,
      distributor: DISTRIBUTOR,
      sponsor: `0x${"4".repeat(40)}`,
      request: request(),
    })).not.toBe(first);
  });

  it("matches the shared Solidity and Python V3 known-answer vector", () => {
    expect(collaborationFundingReservationId({
      chainId: 84_532,
      distributor: `0x${"55".repeat(20)}`,
      sponsor: `0x${"66".repeat(20)}`,
      request: {
        settlementId: `0x${"01".repeat(32)}`,
        settlementNonce: 7n,
        releasePolicyCommitment: `0x${"02".repeat(32)}`,
        roomCommitment: `0x${"03".repeat(32)}`,
        roomStateCommitment: `0x${"04".repeat(32)}`,
        queryCommitment: `0x${"05".repeat(32)}`,
        grantSetCommitment: `0x${"06".repeat(32)}`,
        allocationCommitment: `0x${"07".repeat(32)}`,
        ownersAmountsHash: `0x${"08".repeat(32)}`,
        asset: `0x${"77".repeat(20)}`,
        total: 123_456_789n,
        executionCommitment: `0x${"09".repeat(32)}`,
        refundAfter: 1_800_003_600n,
      },
    })).toBe(
      "0xd0d62c115a12faf9651d4218dd1afb623b46248be0200645058fbd422d50f53f",
    );
  });

  it("encodes exact native value and zero-value ERC20 calls", () => {
    const native = collaborationFundingReservationCall(request());
    const erc20 = collaborationFundingReservationCall(request(TOKEN));

    expect(native).toMatchObject({ functionName: "reserveNative", value: 2_000n });
    expect(erc20).toMatchObject({ functionName: "reserveERC20", value: 0n });
    expect(native.expectedCalldata).toMatch(/^0x[0-9a-f]+$/);
    expect(erc20.expectedCalldata).toMatch(/^0x[0-9a-f]+$/);
    expect(native.expectedCalldata).not.toBe(erc20.expectedCalldata);
  });

  it("rejects a wrong chain, zero commitments, zero totals, and uint64 overflow", () => {
    const derive = (
      next: CollaborationFundingReservationRequest,
      chainId: number = BASE_SEPOLIA.id,
    ) => (
      collaborationFundingReservationId({
        chainId,
        distributor: DISTRIBUTOR,
        sponsor: SPONSOR,
        request: next,
      })
    );
    expect(() => derive(request(), 1)).toThrow("Base Sepolia");
    expect(() => derive({ ...request(), settlementId: `0x${"0".repeat(64)}` })).toThrow("nonzero");
    expect(() => derive({ ...request(), total: 0n })).toThrow("positive");
    expect(() => derive({ ...request(), refundAfter: 1n << 64n })).toThrow("bounded");
  });

  it("recomputes every server-projected ID, calldata, value, and approval field", () => {
    const exact = request();
    const call = collaborationFundingReservationCall(exact);
    const reservationId = collaborationFundingReservationId({
      chainId: BASE_SEPOLIA.id,
      distributor: DISTRIBUTOR,
      sponsor: SPONSOR,
      request: exact,
    });
    const projection = {
      chain_id: BASE_SEPOLIA.id,
      distributor_address: DISTRIBUTOR,
      sponsor_address: SPONSOR,
      reservation_id: reservationId,
      request: {
        settlement_id: exact.settlementId,
        settlement_nonce: exact.settlementNonce.toString(),
        release_policy_commitment: exact.releasePolicyCommitment,
        room_commitment: exact.roomCommitment,
        room_state_commitment: exact.roomStateCommitment,
        query_commitment: exact.queryCommitment,
        grant_set_commitment: exact.grantSetCommitment,
        allocation_commitment: exact.allocationCommitment,
        owners_amounts_hash: exact.ownersAmountsHash,
        asset: exact.asset,
        total: exact.total.toString(),
        execution_commitment: exact.executionCommitment,
        refund_after: exact.refundAfter.toString(),
      },
      transaction: {
        to: DISTRIBUTOR,
        function_name: call.functionName,
        calldata: call.expectedCalldata,
        value: call.value.toString(),
        erc20_approval_required: false,
        erc20_approval: null,
      },
    } as const;
    expect(verifyCollaborationFundingReservationProjection(projection)).toMatchObject({
      reservationId,
      sponsor: SPONSOR,
      request: { settlementNonce: 7n, total: 2_000n },
      call: { functionName: "reserveNative", value: 2_000n },
    });
    expect(() => verifyCollaborationFundingReservationProjection({
      ...projection,
      reservation_id: word("f"),
    })).toThrow("does not recompute");
    expect(() => verifyCollaborationFundingReservationProjection({
      ...projection,
      transaction: { ...projection.transaction, calldata: "0x12345678" },
    })).toThrow("transaction does not recompute");
    expect(() => verifyCollaborationFundingReservationProjection({
      ...projection,
      request: { ...projection.request, settlement_nonce: "9.1" },
    })).toThrow("canonical decimal string");

    const huge = {
      ...exact,
      settlementNonce: 9_007_199_254_740_993n,
      total: 9_007_199_254_740_995n,
    };
    const hugeCall = collaborationFundingReservationCall(huge);
    const hugeProjection = {
      ...projection,
      reservation_id: collaborationFundingReservationId({
        chainId: BASE_SEPOLIA.id,
        distributor: DISTRIBUTOR,
        sponsor: SPONSOR,
        request: huge,
      }),
      request: {
        ...projection.request,
        settlement_nonce: huge.settlementNonce.toString(),
        total: huge.total.toString(),
      },
      transaction: {
        ...projection.transaction,
        calldata: hugeCall.expectedCalldata,
        value: hugeCall.value.toString(),
      },
    } as const;
    expect(verifyCollaborationFundingReservationProjection(hugeProjection))
      .toMatchObject({
        request: {
          settlementNonce: 9_007_199_254_740_993n,
          total: 9_007_199_254_740_995n,
        },
      });
    expect(() => verifyCollaborationFundingReservationProjection({
      ...hugeProjection,
      request: {
        ...hugeProjection.request,
        settlement_nonce: Number(hugeProjection.request.settlement_nonce),
      },
    } as never)).toThrow("canonical decimal string");

    const gated = verifyCollaborationFundingReservationProjection({
      ...projection,
      transaction: {
        schema: "dnai.collaboration.royalty-funding-action-gated.v1",
        status: "gated_worker_presence_required",
        reason: "fresh_authenticated_worker_and_qvl_capability_required",
        executable: false,
        wallet_transaction_included: false,
        erc20_approval_included: false,
      },
    });
    expect(gated).toMatchObject({
      reservationId,
      walletActionReady: false,
      call: { functionName: "reserveNative", value: 2_000n },
    });
    expect(() => verifyCollaborationFundingReservationProjection({
      ...projection,
      transaction: {
        schema: "dnai.collaboration.royalty-funding-action-gated.v1",
        status: "gated_worker_presence_required",
        reason: "fresh_authenticated_worker_and_qvl_capability_required",
        executable: true,
        wallet_transaction_included: false,
        erc20_approval_included: false,
      },
    } as never)).toThrow("wallet action gate");
  });

  it("round-trips and discovers one exact retained intent without blind rebroadcast", () => {
    const exact = request();
    const call = collaborationFundingReservationCall(exact);
    const reservationId = collaborationFundingReservationId({
      chainId: BASE_SEPOLIA.id,
      distributor: DISTRIBUTOR,
      sponsor: SPONSOR,
      request: exact,
    });
    const projection = {
      chain_id: BASE_SEPOLIA.id,
      distributor_address: DISTRIBUTOR,
      sponsor_address: SPONSOR,
      reservation_id: reservationId,
      request: {
        settlement_id: exact.settlementId,
        settlement_nonce: exact.settlementNonce.toString(),
        release_policy_commitment: exact.releasePolicyCommitment,
        room_commitment: exact.roomCommitment,
        room_state_commitment: exact.roomStateCommitment,
        query_commitment: exact.queryCommitment,
        grant_set_commitment: exact.grantSetCommitment,
        allocation_commitment: exact.allocationCommitment,
        owners_amounts_hash: exact.ownersAmountsHash,
        asset: exact.asset,
        total: exact.total.toString(),
        execution_commitment: exact.executionCommitment,
        refund_after: exact.refundAfter.toString(),
      },
      transaction: {
        to: DISTRIBUTOR,
        function_name: call.functionName,
        calldata: call.expectedCalldata,
        value: call.value.toString(),
        erc20_approval_required: false,
        erc20_approval: null,
      },
    } as const;
    const verified = verifyCollaborationFundingReservationProjection(projection);
    const intent: CollaborationFundingReservationIntent = Object.freeze({
      ...verified,
      surface: "collaboration_royalty_reservation_intent",
      schemaVersion: 1,
      executionId: `exec_${"a".repeat(64)}`,
      account: SPONSOR,
      authorizationVersion: 3,
      releaseFingerprint: collaborationReservationReleaseFingerprint(verified),
      distributorRuntimeCodeHash: word("a"),
      createdAt: 1_900_000_000,
      stage: "intent_persisted",
    });
    const serialized = serializeCollaborationReservationIntent(intent);
    expect(parseStoredCollaborationReservationIntent(serialized, {
      account: SPONSOR,
      authorizationVersion: 4,
      releaseFingerprint: intent.releaseFingerprint,
    })).toMatchObject({
      reservationId,
      authorizationVersion: 4,
      stage: "intent_persisted",
    });

    const storage = new MemoryStorage();
    retainCollaborationReservationIntent(storage, intent);
    expect(restoreLatestCollaborationReservationIntent(storage, {
      account: SPONSOR,
      authorizationVersion: 5,
    })).toMatchObject({
      reservationId,
      authorizationVersion: 5,
    });

    expect(listCollaborationReservationIntents(storage, {
      account: SPONSOR,
      authorizationVersion: 5,
    })).toHaveLength(1);

    const key = collaborationReservationStorageKey(intent);
    const tampered = JSON.parse(storage.getItem(key)!) as {
      payload: { stage: string };
    };
    tampered.payload.stage = "reservation_submitted";
    storage.setItem(key, JSON.stringify(tampered));
    expect(() => restoreLatestCollaborationReservationIntent(storage, {
      account: SPONSOR,
      authorizationVersion: 5,
    })).toThrow("integrity check failed");

    storage.setItem(key, serialized);
    expect(clearResolvedCollaborationReservation(storage, {
      status: "consumed",
      intent,
      finalizedBlockNumber: 10n,
      finalizedBlockHash: word("b"),
      browserObservedActive: false,
      workerObservedFinalizedActive: false,
      retrySafe: false,
      clearRetainedIntent: true,
      detail: "finalized",
    })).toBe(true);
    expect(storage.getItem(key)).toBeNull();
  });
});
