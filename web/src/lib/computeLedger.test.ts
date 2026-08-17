import { describe, expect, it } from "vitest";
import {
  computeLedgerAdjacency,
  parseComputeLedger,
  type ComputeLedgerTransaction,
} from "./compute";

const PROJECT_ID = "prj_0123456789abcdef01234567";
const OTHER_PROJECT_ID = "prj_89abcdef0123456701234567";
const JOB_ID = "job_0123456789abcdef01234567";
const HASH_ONE = "1".repeat(64);
const HASH_TWO = "2".repeat(64);
const HASH_THREE = "3".repeat(64);
const GENESIS_HASH = "0".repeat(64);

function validLedger() {
  return {
    surface: "compute_ledger",
    schema_version: 1,
    project_id: PROJECT_ID,
    balance: {
      surface: "compute_credit_balance",
      schema_version: 1,
      project_id: PROJECT_ID,
      available_credits: 100,
      reserved_credits: 0,
      total_service_credits: 100,
      unit: "service_credit",
      nominal_usd_cents_per_credit: 1,
      transferable: false,
      redeemable: false,
      onchain_token: false,
    },
    transactions: [
      {
        transaction_id: "txn_333333333333333333333333",
        sequence: 3,
        kind: "job_cancel",
        project_id: PROJECT_ID,
        job_id: JOB_ID,
        amount_credits: 20,
        postings: [
          { account: `project:${PROJECT_ID}:reserved`, delta: -20 },
          { account: `project:${PROJECT_ID}:available`, delta: 20 },
        ],
        authority: "project_wallet_developer",
        created_at: 1_700_000_020,
        settlement_status: "user_canceled_before_dispatch",
        transaction_hash: HASH_THREE,
        previous_hash: HASH_TWO,
      },
      {
        transaction_id: "txn_222222222222222222222222",
        sequence: 2,
        kind: "job_reserve",
        project_id: PROJECT_ID,
        job_id: JOB_ID,
        amount_credits: 20,
        postings: [
          { account: `project:${PROJECT_ID}:available`, delta: -20 },
          { account: `project:${PROJECT_ID}:reserved`, delta: 20 },
        ],
        authority: "wallet",
        created_at: 1_700_000_010,
        settlement_status: "reserved",
        transaction_hash: HASH_TWO,
        previous_hash: HASH_ONE,
      },
      {
        transaction_id: "txn_111111111111111111111111",
        sequence: 1,
        kind: "testnet_grant",
        project_id: PROJECT_ID,
        job_id: null,
        amount_credits: 100,
        postings: [
          { account: `project:${PROJECT_ID}:available`, delta: 100 },
          { account: "system:testnet_grant_pool", delta: -100 },
        ],
        authority: "operator_runtime",
        created_at: 1_700_000_000,
        settlement_status: "operator_testnet_only",
        transaction_hash: HASH_ONE,
        previous_hash: GENESIS_HASH,
      },
    ],
    append_only: true,
    double_entry: true,
    currency: "service_credit",
    transferable: false,
    redeemable: false,
  };
}

describe("Compute live ledger parser", () => {
  it("returns a freshly bounded ledger after exact field and semantic validation", () => {
    const source = validLedger();
    const parsed = parseComputeLedger(source, PROJECT_ID);

    expect(parsed).not.toBe(source);
    expect(parsed.balance).toBe(source.balance);
    expect(parsed.transactions).not.toBe(source.transactions);
    expect(parsed.transactions.map((transaction) => transaction.kind)).toEqual([
      "job_cancel",
      "job_reserve",
      "testnet_grant",
    ]);
    expect(parsed.transactions[0].project_id).toBe(PROJECT_ID);
  });

  it("rejects extra root, balance, transaction, and posting fields", () => {
    const root = validLedger();
    Object.assign(root, { unmodeled_claim: true });
    expect(() => parseComputeLedger(root, PROJECT_ID)).toThrow(/unsupported fields/);

    const balance = validLedger();
    Object.assign(balance.balance, { cash_value_usd: 1 });
    expect(() => parseComputeLedger(balance, PROJECT_ID)).toThrow(/unsupported fields/);

    const transaction = validLedger();
    Object.assign(transaction.transactions[0], { hash_verified: true });
    expect(() => parseComputeLedger(transaction, PROJECT_ID)).toThrow(/unsupported fields/);

    const posting = validLedger();
    Object.assign(posting.transactions[0].postings[0], { memo: "refund" });
    expect(() => parseComputeLedger(posting, PROJECT_ID)).toThrow(/unsupported fields/);
  });

  it("binds the root, balance, and every transaction to the requested project", () => {
    const root = validLedger();
    root.project_id = OTHER_PROJECT_ID;
    expect(() => parseComputeLedger(root, PROJECT_ID)).toThrow();

    const balance = validLedger();
    balance.balance.project_id = OTHER_PROJECT_ID;
    expect(() => parseComputeLedger(balance, PROJECT_ID)).toThrow();

    const transaction = validLedger();
    transaction.transactions[1].project_id = OTHER_PROJECT_ID;
    expect(() => parseComputeLedger(transaction, PROJECT_ID)).toThrow();

    expect(() => parseComputeLedger(validLedger(), "prj_alpha")).toThrow(/project binding/);
  });

  it("rejects legacy or unknown kinds and mismatched status or authority vocabularies", () => {
    const legacyKind = validLedger();
    legacyKind.transactions[2].kind = "operator_grant";
    expect(() => parseComputeLedger(legacyKind, PROJECT_ID)).toThrow();

    const wrongStatus = validLedger();
    wrongStatus.transactions[1].settlement_status = "operator_testnet_only";
    expect(() => parseComputeLedger(wrongStatus, PROJECT_ID)).toThrow(/reservation transaction/);

    const wrongAuthority = validLedger();
    wrongAuthority.transactions[0].authority = "operator_runtime";
    expect(() => parseComputeLedger(wrongAuthority, PROJECT_ID)).toThrow(/release transaction/);

    const unknownAuthority = validLedger();
    unknownAuthority.transactions[1].authority = "wallet_owner";
    expect(() => parseComputeLedger(unknownAuthority, PROJECT_ID)).toThrow();
  });

  it("rejects unsupported, cross-project, duplicate, or semantically false postings", () => {
    const crossProject = validLedger();
    crossProject.transactions[1].postings[0].account = `project:${OTHER_PROJECT_ID}:available`;
    expect(() => parseComputeLedger(crossProject, PROJECT_ID)).toThrow(/account/);

    const unsupported = validLedger();
    unsupported.transactions[2].postings[1].account = "system:treasury";
    expect(() => parseComputeLedger(unsupported, PROJECT_ID)).toThrow(/account/);

    const duplicate = validLedger();
    duplicate.transactions[1].postings[1].account = `project:${PROJECT_ID}:available`;
    expect(() => parseComputeLedger(duplicate, PROJECT_ID)).toThrow(/duplicated/);

    const falseReserve = validLedger();
    falseReserve.transactions[1].postings[0].delta = -19;
    falseReserve.transactions[1].postings[1].delta = 19;
    expect(() => parseComputeLedger(falseReserve, PROJECT_ID)).toThrow(/reservation transaction/);
  });

  it("enforces the exact settlement debit, revenue, and refund relation", () => {
    const settlement = validLedger();
    settlement.transactions = [{
      transaction_id: "txn_444444444444444444444444",
      sequence: 4,
      kind: "job_settle",
      project_id: PROJECT_ID,
      job_id: JOB_ID,
      amount_credits: 12,
      postings: [
        { account: `project:${PROJECT_ID}:reserved`, delta: -20 },
        { account: "system:service_revenue", delta: 12 },
        { account: `project:${PROJECT_ID}:available`, delta: 8 },
      ],
      authority: "operator_runtime",
      created_at: 1_700_000_030,
      settlement_status: "provisional_internal_metering",
      transaction_hash: "4".repeat(64),
      previous_hash: HASH_THREE,
    }];
    expect(parseComputeLedger(settlement, PROJECT_ID).transactions[0].amount_credits).toBe(12);

    settlement.transactions[0].postings[2].delta = 7;
    settlement.transactions[0].postings[1].delta = 13;
    expect(() => parseComputeLedger(settlement, PROJECT_ID)).toThrow(/settlement transaction/);
  });

  it("accepts only the operator release vocabulary and exact reservation reversal", () => {
    const release = validLedger();
    release.transactions = [{
      transaction_id: "txn_444444444444444444444444",
      sequence: 4,
      kind: "job_release",
      project_id: PROJECT_ID,
      job_id: JOB_ID,
      amount_credits: 20,
      postings: [
        { account: `project:${PROJECT_ID}:reserved`, delta: -20 },
        { account: `project:${PROJECT_ID}:available`, delta: 20 },
      ],
      authority: "operator_runtime",
      created_at: 1_700_000_030,
      settlement_status: "released_without_service_settlement",
      transaction_hash: "4".repeat(64),
      previous_hash: HASH_THREE,
    }];
    expect(parseComputeLedger(release, PROJECT_ID).transactions[0].kind).toBe("job_release");

    release.transactions[0].settlement_status = "user_canceled_before_dispatch";
    expect(() => parseComputeLedger(release, PROJECT_ID)).toThrow(/release transaction/);
  });

  it("requires newest-first unique sequences, transaction IDs, and transaction hashes", () => {
    const ascending = validLedger();
    ascending.transactions.reverse();
    expect(() => parseComputeLedger(ascending, PROJECT_ID)).toThrow(/ordering/);

    const duplicateSequence = validLedger();
    duplicateSequence.transactions[0].sequence = 2;
    expect(() => parseComputeLedger(duplicateSequence, PROJECT_ID)).toThrow(/ordering/);

    const duplicateId = validLedger();
    duplicateId.transactions[1].transaction_id = duplicateId.transactions[0].transaction_id;
    expect(() => parseComputeLedger(duplicateId, PROJECT_ID)).toThrow(/ordering/);

    const duplicateHash = validLedger();
    duplicateHash.transactions[1].transaction_hash = duplicateHash.transactions[0].transaction_hash;
    expect(() => parseComputeLedger(duplicateHash, PROJECT_ID)).toThrow(/ordering/);
  });

  it("fails closed on a mismatched hash between visible consecutive sequences", () => {
    const ledger = validLedger();
    ledger.transactions[0].previous_hash = "a".repeat(64);
    expect(() => parseComputeLedger(ledger, PROJECT_ID)).toThrow(/visible hash chain/);
  });

  it("accepts a project-filtered global sequence gap without calling it a chain failure", () => {
    const ledger = validLedger();
    ledger.transactions.splice(1, 1);
    const parsed = parseComputeLedger(ledger, PROJECT_ID);

    expect(computeLedgerAdjacency(parsed.transactions[0], parsed.transactions[1])).toBe("interleaved_global");
  });

  it("classifies genesis, visible links, and a predecessor outside the response", () => {
    const parsed = parseComputeLedger(validLedger(), PROJECT_ID);
    expect(computeLedgerAdjacency(parsed.transactions[0], parsed.transactions[1])).toBe("visible_link");
    expect(computeLedgerAdjacency(parsed.transactions[2])).toBe("genesis");
    expect(computeLedgerAdjacency(parsed.transactions[0])).toBe("outside_view");

    const invalidGenesis = {
      ...parsed.transactions[2],
      previous_hash: HASH_TWO,
    } satisfies ComputeLedgerTransaction;
    expect(computeLedgerAdjacency(invalidGenesis)).toBe("invalid");
  });

  it("requires generated lowercase IDs, hashes, bounded sequences, and timestamps", () => {
    const badId = validLedger();
    badId.transactions[0].transaction_id = "txn_ABCDEF333333333333333333";
    expect(() => parseComputeLedger(badId, PROJECT_ID)).toThrow();

    const badHash = validLedger();
    badHash.transactions[0].transaction_hash = "A".repeat(64);
    expect(() => parseComputeLedger(badHash, PROJECT_ID)).toThrow();

    const badSequence = validLedger();
    badSequence.transactions[0].sequence = 40_001;
    expect(() => parseComputeLedger(badSequence, PROJECT_ID)).toThrow(/sequence/);

    const badTimestamp = validLedger();
    badTimestamp.transactions[0].created_at = 4_102_444_801;
    expect(() => parseComputeLedger(badTimestamp, PROJECT_ID)).toThrow(/timestamp/);
  });
});
