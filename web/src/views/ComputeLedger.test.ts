import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import type { ComputeLedgerTransaction } from "../lib/compute";
import { LedgerEvidenceBoundary, LedgerRow } from "./Compute";

const PROJECT_ID = "prj_0123456789abcdef01234567";
const JOB_ID = "job_0123456789abcdef01234567";
const OLDER_HASH = "1".repeat(64);
const NEWER_HASH = "2".repeat(64);

const older: ComputeLedgerTransaction = {
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
  transaction_hash: OLDER_HASH,
  previous_hash: "0".repeat(64),
};

const newer: ComputeLedgerTransaction = {
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
  transaction_hash: NEWER_HASH,
  previous_hash: OLDER_HASH,
};

describe("Compute ledger evidence presentation", () => {
  it("shows sequence, both hash references, and only the visible adjacency claim", () => {
    const html = renderToString(() => createComponent(LedgerRow, {
      entry: newer,
      olderEntry: older,
    }));

    expect(html).toContain('data-chain-adjacency="visible_link"');
    expect(html).toContain("Ledger sequence 2");
    expect(html).toContain("222222222222…22222222");
    expect(html).toContain("111111111111…11111111");
    expect(html).toContain(`title="${NEWER_HASH}"`);
    expect(html).toContain(`title="${OLDER_HASH}"`);
    expect(html).toContain("Visible adjacent link");
    expect(html).not.toContain("Hash verified");
    expect(html).not.toContain("Chain verified");
  });

  it("labels an omitted predecessor without implying a broken chain", () => {
    const html = renderToString(() => createComponent(LedgerRow, {
      entry: newer,
    }));

    expect(html).toContain('data-chain-adjacency="outside_view"');
    expect(html).toContain("Predecessor outside view");
    expect(html).not.toContain("Invalid visible link");
  });

  it("labels a gap between visible project rows as an interleaved global sequence", () => {
    const html = renderToString(() => createComponent(LedgerRow, {
      entry: { ...newer, sequence: 3 },
      olderEntry: older,
    }));

    expect(html).toContain('data-chain-adjacency="interleaved_global"');
    expect(html).toContain("Interleaved global sequence");
    expect(html).not.toContain("Invalid visible link");
  });

  it("states why the browser cannot recompute the public transaction hash", () => {
    const html = renderToString(() => createComponent(LedgerEvidenceBoundary, {}));

    expect(html).toContain("internal request and idempotency commitments");
    expect(html).toContain("does not recompute transaction hashes");
    expect(html).toContain("Gaps can contain other projects and are not chain failures");
  });
});
