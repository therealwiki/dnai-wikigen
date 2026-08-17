import { describe, expect, it, vi } from "vitest";

const AUTHORITY_CONTEXT = "a".repeat(64);
const DECISION_HASH = "b".repeat(64);
const STATE_HASH = "c".repeat(64);
const DEPLOYMENT_INTENT = `sha256:${"1".repeat(64)}`;
const RELEASE_AUTHORITY = `sha256:${"2".repeat(64)}`;
const CEREMONY_NONCE = `0x${"3".repeat(64)}`;

vi.mock("../config", () => ({
  BASE_SEPOLIA: {
    id: 84532,
    rpcUrl: "https://sepolia.base.org",
    secondaryRpcUrl: "",
  },
  deployment: {
    delegateUrl: "https://delegate.release.example",
    releaseIdentityStatus: "release_bound",
    cvmId: "cvm-main-runtime-release",
    walletAuthDomain: "www.wikigen.me",
    walletAuthUri: "https://www.wikigen.me",
    executionPolicyAnchorRelease: {
      address: `0x${"1".repeat(40)}`,
      runtimeCodeHash: `0x${"2".repeat(64)}`,
      writer: `0x${"3".repeat(40)}`,
      writerReleaseCommitment: `0x${"4".repeat(64)}`,
      confirmations: 12,
      maxBlockAgeSeconds: 3_600,
      maxFutureBlockSkewSeconds: 30,
    },
  },
  computeWorkloadDeployment: {
    enabled: true,
    configured: true,
    issues: [],
    trustPolicy: {
      cvmId: "cvm-main-runtime-release",
      deploymentIntentSha256: `sha256:${"1".repeat(64)}`,
      releaseAuthoritySha256: `sha256:${"2".repeat(64)}`,
      ceremonyNonce: `0x${"3".repeat(64)}`,
    },
  },
}));

import {
  appendReviewQueuePage,
  fetchReviewQueue,
  issueReviewChallenge,
  parseReviewChallenge,
  parseReviewQueue,
  parseReviewQueueCursor,
  REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
  REVIEW_QUEUE_MAX_PAGE_SIZE,
  ReviewQueueRestartRequiredError,
  reviewReleaseConfigured,
  reviewQueueSnapshotKey,
  startReviewQueueWindow,
  submitReviewDecision,
} from "./review";

function rollbackStatus() {
  return {
    schema: "dnai-wikigen/execution-policy-anchor-status/v1",
    status: "rpc_reported_finalized_release_match",
    verification_model: "single_rpc_reported_finalized_with_confirmation_depth",
    chain_id: 84532,
    latest_block_number: 120,
    rpc_finalized_block_number: 110,
    rpc_finalized_block_hash: `0x${"5".repeat(64)}`,
    minimum_confirmation_depth: 12,
    observed_confirmation_depth: 12,
    block_number: 109,
    block_hash: `0x${"6".repeat(64)}`,
    block_timestamp: 2_000_000_000,
    contract_address: `0x${"1".repeat(40)}`,
    runtime_code_hash: `0x${"2".repeat(64)}`,
    writer: `0x${"3".repeat(40)}`,
    writer_release_commitment: `0x${"4".repeat(64)}`,
    writer_rotations_frozen: true,
    paused: false,
    global_sequence: 8,
    global_head: `0x${"7".repeat(64)}`,
    resource_id_hash: AUTHORITY_CONTEXT,
    resource_decision_head: `0x${DECISION_HASH}`,
    resource_sequence: 3,
    decision_hash: DECISION_HASH,
    decision_sequence: 3,
    opaque_commitments_only: true,
    independent_rpc_quorum_verified: false,
    consensus_proof_verified: false,
    raw_resource_id_egress: false,
    raw_policy_egress: false,
  };
}

function ticket(ticketRef = "8".repeat(64)) {
  return {
    ticket_ref_hash: ticketRef,
    turn_ref_hash: "9".repeat(64),
    corpus_ref_hash: "d".repeat(64),
    routed_role: "biosecurity-review",
    reason_hash: "e".repeat(64),
    opened_at: 1_900_000_000,
    expires_at: 2_100_000_000,
    status: "pending",
    reviewer_ref_hash: "",
    submitter_ref_hash: "f".repeat(64),
    required_approvals: 2,
    approvals_count: 0,
    approval_reviewer_hashes: [],
    approval_authorization_hashes: [],
    reviewer_authorization_hash: "",
    authority_context_hash: "",
    decision_hash: "",
    updated_at: 1_900_000_000,
    raw_secret_egress: false,
  };
}

function queue() {
  return {
    surface: "human_review_queue",
    schema_version: 2,
    ticket_count: 1,
    pending_count: 1,
    status_counts: { pending: 1, released: 0, denied: 0, expired: 0 },
    tickets: [ticket()],
    audit_hash: "0".repeat(64),
    audit_count: 1,
    raw_secret_egress: false,
    page: {
      limit: REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
      returned_count: 1,
      has_more: false,
      next_cursor: "",
    },
    authority: {
      enabled: true,
      chain_id: 84532,
      authority_context_hash: AUTHORITY_CONTEXT,
      release_context: {
        schema: "dnai.review-release-context.v1",
        chain_id: 84532,
        wallet_domain: "www.wikigen.me",
        wallet_uri: "https://www.wikigen.me",
        main_runtime_cvm_id: "cvm-main-runtime-release",
        deployment_intent_sha256: DEPLOYMENT_INTENT,
        release_authority_sha256: RELEASE_AUTHORITY,
        ceremony_nonce: CEREMONY_NONCE,
      },
      release_provenance: {
        reviewer_authority_genesis_acceptance_sha256: `sha256:${"4".repeat(64)}`,
        reviewer_authority_current_status_epoch: 7,
        reviewer_authority_current_status_sha256: `sha256:${"5".repeat(64)}`,
        reviewer_authority_active_reviewers_sha256: `sha256:${"6".repeat(64)}`,
      },
      active_reviewers: {
        active_reviewer_count: 3,
        active_reviewers_sha256: `sha256:${"6".repeat(64)}`,
        raw_reviewer_identity_egress: false,
      },
      rollback_protection: "base_sepolia_execution_policy_anchor",
      rollback_anchor: {
        schema: "dnai.review-queue-rollback-anchor.v1",
        state_hash: STATE_HASH,
        decision_hash: DECISION_HASH,
        sequence: 3,
        rollback_anchor: rollbackStatus(),
        opaque_commitments_only: true,
        raw_ticket_egress: false,
        raw_reviewer_identity_egress: false,
      },
      schema: "dnai.review-authority-policy.v1",
      policy_sha256: "7".repeat(64),
      roles: [{
        role: "biosecurity-review",
        threshold: 2,
        reviewer_count: 3,
        reviewer_set_hash: "8".repeat(64),
      }],
      raw_reviewer_identity_egress: false,
    },
  };
}

function pageQueue(
  tickets: ReturnType<typeof ticket>[],
  options: {
    total: number;
    limit?: number;
    hasMore?: boolean;
    nextCursor?: string;
    routedRole?: string;
  },
) {
  const value = structuredClone(queue());
  value.ticket_count = options.total;
  value.pending_count = options.total;
  value.status_counts = {
    pending: options.total,
    released: 0,
    denied: 0,
    expired: 0,
  };
  value.tickets = structuredClone(tickets);
  value.page = {
    limit: options.limit ?? REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
    returned_count: tickets.length,
    has_more: options.hasMore ?? false,
    next_cursor: options.hasMore
      ? options.nextCursor ?? tickets.at(-1)?.ticket_ref_hash ?? ""
      : "",
  };
  return options.routedRole
    ? {
      ...value,
      kind: "review_queue_pending",
      routed_role: options.routedRole,
    }
    : value;
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("review release client", () => {
  it("parses only the hash-only v2 queue and exact live authority schema", () => {
    const parsed = parseReviewQueue(queue());
    expect(parsed.tickets[0].ticket_ref_hash).toBe("8".repeat(64));
    expect(parsed.authority.release_context.deployment_intent_sha256).toBe(DEPLOYMENT_INTENT);

    const expanded = structuredClone(queue());
    (expanded.tickets[0] as Record<string, unknown>).ticket_id = "raw-secret-name";
    expect(() => parseReviewQueue(expanded)).toThrow(/unsupported fields/i);

    const localOnly = structuredClone(queue());
    localOnly.authority.rollback_protection = "local_test_only_hmac_no_rollback_claim";
    expect(() => parseReviewQueue(localOnly)).toThrow(/live Base Sepolia release authority/i);
  });

  it("fetches without credentials and verifies the exact finalized anchor binding", async () => {
    expect(reviewReleaseConfigured()).toBe(true);
    const fetcher = vi.fn(async (..._args: Parameters<typeof fetch>): Promise<Response> => response(queue()));
    const verifyAnchor = vi.fn(async () => undefined);
    const parsed = await fetchReviewQueue({ fetcher, verifyAnchor });

    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0][0]).toBe(
      `https://delegate.release.example/review/queue?limit=${REVIEW_QUEUE_DEFAULT_PAGE_SIZE}`,
    );
    expect(fetcher.mock.calls[0][1]).toMatchObject({ credentials: "omit", method: "GET" });
    expect(verifyAnchor).toHaveBeenCalledWith(
      parsed.authority.rollback_anchor.rollback_anchor,
      AUTHORITY_CONTEXT,
      DECISION_HASH,
      3,
    );
  });

  it("treats the continuation as a strict opaque token and normalizes exhaustion to null", () => {
    const cursor = "a".repeat(64);
    const first = parseReviewQueue(pageQueue(
      [ticket()],
      { total: 2, hasMore: true, nextCursor: cursor },
    ));
    expect(first.page.next_cursor).toBe(cursor);
    expect(parseReviewQueueCursor(cursor)).toBe(cursor);

    const exhausted = parseReviewQueue(pageQueue(
      [ticket()],
      { total: 1 },
    ));
    expect(exhausted.page.next_cursor).toBeNull();

    for (const malformed of [
      cursor.toUpperCase(),
      `${cursor} `,
      cursor.slice(1),
      "",
    ]) {
      expect(() => parseReviewQueueCursor(malformed)).toThrow(
        /cursor is invalid/i,
      );
    }

    const cursorAfterExhaustion = pageQueue([ticket()], { total: 1 });
    cursorAfterExhaustion.page.next_cursor = cursor;
    expect(() => parseReviewQueue(cursorAfterExhaustion)).toThrow(
      /pagination/i,
    );

    const missingContinuation = pageQueue(
      [ticket()],
      { total: 2, hasMore: true, nextCursor: cursor },
    );
    missingContinuation.page.next_cursor = "";
    expect(() => parseReviewQueue(missingContinuation)).toThrow(/cursor/i);
  });

  it("carries the role and cursor verbatim while bounding the requested page size", async () => {
    const cursor = parseReviewQueueCursor("b".repeat(64));
    const nextCursor = "c".repeat(64);
    const fetcher = vi.fn(async (..._args: Parameters<typeof fetch>): Promise<Response> => response(
      pageQueue(
        [ticket("d".repeat(64))],
        {
          total: 2,
          limit: 10,
          hasMore: true,
          nextCursor,
          routedRole: "biosecurity-review",
        },
      ),
    ));
    const parsed = await fetchReviewQueue({
      cursor,
      limit: 10,
      routedRole: "biosecurity-review",
      fetcher,
      verifyAnchor: vi.fn(async () => undefined),
    });

    expect(fetcher.mock.calls[0][0]).toBe(
      `https://delegate.release.example/review/queue?limit=10&routed_role=biosecurity-review&cursor=${cursor}`,
    );
    expect(parsed.routed_role).toBe("biosecurity-review");
    expect(parsed.page.next_cursor).toBe(nextCursor);

    const neverCalled = vi.fn();
    await expect(fetchReviewQueue({
      limit: REVIEW_QUEUE_MAX_PAGE_SIZE + 1,
      fetcher: neverCalled as typeof fetch,
    })).rejects.toThrow(/page size/i);
    expect(neverCalled).not.toHaveBeenCalled();

    await expect(fetchReviewQueue({
      limit: 10,
      fetcher: vi.fn(async () => response(pageQueue(
        [ticket()],
        { total: 1, limit: 11 },
      ))),
      verifyAnchor: vi.fn(async () => undefined),
    })).rejects.toThrow(/changed the requested page/i);
  });

  it("appends only pages from one filter and anchored release snapshot", () => {
    const firstPage = parseReviewQueue(pageQueue(
      [ticket("1".repeat(64))],
      {
        total: 2,
        limit: 1,
        hasMore: true,
        nextCursor: "1".repeat(64),
        routedRole: "biosecurity-review",
      },
    ));
    const secondPage = parseReviewQueue(pageQueue(
      [ticket("2".repeat(64))],
      {
        total: 2,
        limit: 1,
        routedRole: "biosecurity-review",
      },
    ));
    const firstWindow = startReviewQueueWindow(firstPage);
    const appended = appendReviewQueuePage(
      firstWindow,
      secondPage,
      firstPage.page.next_cursor!,
    );

    expect(appended.tickets.map((item) => item.ticket_ref_hash)).toEqual([
      "1".repeat(64),
      "2".repeat(64),
    ]);
    expect(appended.loaded_count).toBe(2);
    expect(appended.has_more).toBe(false);
    expect(appended.next_cursor).toBeNull();
    expect(appended.routed_role).toBe("biosecurity-review");

    const driftedRaw = pageQueue(
      [ticket("2".repeat(64))],
      {
        total: 2,
        limit: 1,
        routedRole: "biosecurity-review",
      },
    );
    driftedRaw.authority.policy_sha256 = "f".repeat(64);
    const drifted = parseReviewQueue(driftedRaw);
    expect(reviewQueueSnapshotKey(drifted)).not.toBe(
      reviewQueueSnapshotKey(firstPage),
    );
    expect(() => appendReviewQueuePage(
      firstWindow,
      drifted,
      firstPage.page.next_cursor!,
    )).toThrow(ReviewQueueRestartRequiredError);

    const duplicate = parseReviewQueue(pageQueue(
      [ticket("1".repeat(64))],
      {
        total: 2,
        limit: 1,
        routedRole: "biosecurity-review",
      },
    ));
    expect(() => appendReviewQueuePage(
      firstWindow,
      duplicate,
      firstPage.page.next_cursor!,
    )).toThrow(/repeated a displayed ticket/i);
  });

  it("rejects cursor cycles and requires a first-page restart after the chain changes", () => {
    const firstPage = parseReviewQueue(pageQueue(
      [ticket("1".repeat(64))],
      {
        total: 3,
        limit: 1,
        hasMore: true,
        nextCursor: "a".repeat(64),
      },
    ));
    const cyclePage = parseReviewQueue(pageQueue(
      [ticket("2".repeat(64))],
      {
        total: 3,
        limit: 1,
        hasMore: true,
        nextCursor: "a".repeat(64),
      },
    ));
    expect(() => appendReviewQueuePage(
      startReviewQueueWindow(firstPage),
      cyclePage,
      firstPage.page.next_cursor!,
    )).toThrow(/fresh opaque cursor/i);
  });

  it("binds a wallet challenge to the selected ticket, decision, and authority", async () => {
    const parsed = parseReviewQueue(queue());
    const challenge = {
      schema: "dnai.review-authority-challenge.v1",
      ticket_ref_hash: parsed.tickets[0].ticket_ref_hash,
      ticket_state_hash: "9".repeat(64),
      routed_role: "biosecurity-review",
      decision: "release",
      reviewer_ref_hash: "a".repeat(64),
      authority_context_hash: AUTHORITY_CONTEXT,
      policy_sha256: "7".repeat(64),
      nonce: "b".repeat(32),
      message: "Release-bound review decision for one current ticket state",
      issued_at: 2_000_000_000,
      expires_at: 2_000_000_300,
      chain_id: 84532,
      raw_reviewer_identity_egress: false,
    };
    expect(parseReviewChallenge(challenge).decision).toBe("release");
    const fetcher = vi.fn(async (..._args: Parameters<typeof fetch>): Promise<Response> => response(challenge));
    await issueReviewChallenge(
      parsed,
      parsed.tickets[0],
      `0x${"a".repeat(40)}`,
      "release",
      { fetcher, nowSeconds: 2_000_000_000 },
    );
    const request = fetcher.mock.calls[0];
    expect(request[0]).toBe("https://delegate.release.example/auth/review/challenge");
    expect(JSON.parse(String(request[1]?.body))).toEqual({
      address: `0x${"a".repeat(40)}`,
      ticket_ref_hash: "8".repeat(64),
      decision: "release",
    });

    const drift = { ...challenge, policy_sha256: "c".repeat(64) };
    await expect(issueReviewChallenge(
      parsed,
      parsed.tickets[0],
      `0x${"a".repeat(40)}`,
      "release",
      {
        fetcher: vi.fn(async (..._args: Parameters<typeof fetch>): Promise<Response> => response(drift)),
        nowSeconds: 2_000_000_000,
      },
    )).rejects.toThrow(/another ticket or release authority/i);
  });

  it("submits only a bounded signature and re-verifies the returned queue head", async () => {
    const fetcher = vi.fn(async (..._args: Parameters<typeof fetch>): Promise<Response> => response(queue()));
    const verifyAnchor = vi.fn(async () => undefined);
    await submitReviewDecision(
      "b".repeat(32),
      `0x${"c".repeat(130)}`,
      { fetcher, verifyAnchor },
    );
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toEqual({
      nonce: "b".repeat(32),
      signature: `0x${"c".repeat(130)}`,
    });
    expect(verifyAnchor).toHaveBeenCalledOnce();
    await expect(submitReviewDecision(
      "b".repeat(31),
      "0x12",
      { fetcher, verifyAnchor },
    )).rejects.toThrow(/malformed/i);
  });
});
