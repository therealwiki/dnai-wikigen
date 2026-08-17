import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import reviewQueueSource from "./ReviewQueue.tsx?raw";
import {
  ReviewQueue,
  reviewAuthorityReady,
  reviewQueueRequestScopeKey,
  type ReviewAuthorityReadiness,
} from "./ReviewQueue";

const READY: ReviewAuthorityReadiness = {
  safeBrowserAdapterConfigured: true,
  releasePolicyPinned: true,
  reviewerSetPinned: true,
  signatureDomainPinned: true,
  releaseIdentityVerified: true,
};

function renderReviewQueue(): string {
  return renderToString(() => createComponent(ReviewQueue, {}));
}

describe("review authority readiness", () => {
  it("requires every independent launch prerequisite", () => {
    expect(reviewAuthorityReady(READY)).toBe(true);
    for (const key of Object.keys(READY) as Array<keyof ReviewAuthorityReadiness>) {
      expect(reviewAuthorityReady({ ...READY, [key]: false }), key).toBe(false);
    }
  });
});

describe("ReviewQueue product boundary", () => {
  it("renders an explicit modeled fallback when no immutable release is configured", () => {
    const html = renderReviewQueue();
    expect(html).toContain("Modeled fallback · control plane release-gated");
    expect(html).toContain(
      "These source-modeled examples describe the bounded review shape only",
    );
    expect(html).toContain("customer control plane remains release-gated");
    expect(html).toContain("not a live queue");
    expect(html).toContain("MODELED SAMPLE");
    expect(html).toContain("RELEASE GATED");
    expect(html).toContain("Illustrative sequence · not an audit log");
    expect(html).toContain("MODELED · NOT RECORDED");
    expect(html).toContain("HELD · RELEASE AUTHORITY INCOMPLETE");
    expect(html).toContain("NO RELEASE AUTHORITY");
    expect(html).not.toContain("LIVE-CAPABLE");
    expect(html).not.toContain("finalized Base Sepolia anchor verified");
  });

  it("keeps every live mutation disabled in the modeled build and explains its gate", () => {
    const html = renderReviewQueue();
    for (const label of [
      "Control plane release-gated",
      "Refresh head",
      "Sign denial",
      "Sign approval",
      "Connect reviewer wallet in header",
    ]) expect(html).toContain(label);
    expect(html.match(/<button\b[^>]*\bdisabled(?:="")?[^>]*>/g)).toHaveLength(3);
    expect(reviewQueueSource).toContain(
      'class="primary-button large review-authority-button review-nonaction-status" role="status"',
    );
    expect(reviewQueueSource).toContain(
      'class="secondary-button review-signature-request review-nonaction-status" role="status"',
    );
    expect(reviewQueueSource).not.toContain(
      '<button class="secondary-button review-signature-request"',
    );
    expect(html).toContain("Release gated: the exact release authority and finalized queue witness must verify first.");
    expect(html).toContain("Wallet access proves neither reviewer authority nor TDX execution.");
    expect(html).toContain("no release-authorized safe adapter, policy, reviewer roster, signature domain, or exact release lineage");
    expect(html).toContain("no review mutation is available");
  });

  it("contains a real release-gated wallet decision path with ambiguous-commit recovery", () => {
    for (const call of [
      "fetchReviewQueue({",
      "issueReviewChallenge(",
      "requestWalletAuthSignature(",
      "submitReviewDecision(",
      "wallet.authorizationVersion()",
      "wallet.switchToBase()",
    ]) expect(reviewQueueSource).toContain(call);
    expect(reviewQueueSource).toContain("may have committed but its receipt was not verified");
    expect(reviewQueueSource).toContain("await refreshQueue({ quiet: true })");
    expect(reviewQueueSource).toContain("inspect the ticket before signing again");
    expect(reviewQueueSource).toContain("wallet.provider() !== provider");
    expect(reviewQueueSource).not.toContain("runtime_bearer");
    expect(reviewQueueSource).not.toContain("Authorization: Bearer");
  });

  it("loads opaque continuation pages with retry and first-page restart controls", () => {
    for (const contract of [
      "REVIEW_QUEUE_DEFAULT_PAGE_SIZE",
      "cursor,",
      "limit: current.page_size",
      "routedRole: current.routed_role ?? undefined",
      "appendReviewQueuePage(current, nextPage, cursor)",
      "Retry next page",
      "Restart from first page",
      "The verified rows already shown were preserved.",
    ]) expect(reviewQueueSource).toContain(contract);
    expect(reviewQueueSource).toContain(
      'aria-label="Review queue pagination"',
    );
    expect(reviewQueueSource).toContain(
      'aria-controls="review-public-queue-list"',
    );
    expect(reviewQueueSource).toContain(
      'id="review-queue-pagination-status"',
    );
    expect(reviewQueueSource).toContain('aria-live="polite"');
    expect(reviewQueueSource).toContain('aria-atomic="true"');
  });

  it("keeps the routed-role filter on every continuation and restart", () => {
    for (const contract of [
      'aria-label="Filter review queue by routed role"',
      "selectedRole() || undefined",
      "current.routed_role ?? undefined",
      "setSelectedRole(nextRole)",
      "void refreshQueue({ quiet: true })",
      "filter remains bound to every continuation request",
    ]) expect(reviewQueueSource).toContain(contract);
  });

  it("drops stale queue results after wallet, filter, or release scope changes", () => {
    const base = {
      walletAddress: `0x${"1".repeat(40)}`,
      walletAuthorizationVersion: 7,
      chainId: 84532,
      routedRole: "biosecurity-review",
      releaseScope: "release-a",
    };
    const fingerprint = reviewQueueRequestScopeKey(base);
    expect(reviewQueueRequestScopeKey({
      ...base,
      walletAddress: `0x${"2".repeat(40)}`,
    })).not.toBe(fingerprint);
    expect(reviewQueueRequestScopeKey({
      ...base,
      walletAuthorizationVersion: 8,
    })).not.toBe(fingerprint);
    expect(reviewQueueRequestScopeKey({
      ...base,
      chainId: 1,
    })).not.toBe(fingerprint);
    expect(reviewQueueRequestScopeKey({
      ...base,
      routedRole: "evidence-review",
    })).not.toBe(fingerprint);
    expect(reviewQueueRequestScopeKey({
      ...base,
      releaseScope: "release-b",
    })).not.toBe(fingerprint);

    for (const guard of [
      "queueRequestGeneration",
      "queueRequestIsCurrent(requestContext)",
      "context.scope === currentQueueRequestScope()",
      "reviewQueueSnapshotKey(latest.snapshot) === decisionSnapshot",
      "activeQueueController?.abort()",
    ]) expect(reviewQueueSource).toContain(guard);
  });

  it("states and enforces the bounded public egress model without TDX overclaiming", () => {
    const html = renderReviewQueue();
    expect(html).toContain("Five controls before a human can release less.");
    expect(html).toContain("SOURCE REQUIREMENT");
    expect(html).toContain("CLIENT ENFORCED");
    expect(html).toContain("HUMAN CHECK");
    expect(html).toContain("AUTHORITY CHECK");
    expect(html).toContain("RELEASE GATED");
    expect(html).toContain("Free text · raw source · attachment · undeclared field · identity roster · signature bytes");
    expect(html).toContain("Raw tickets, corpora, turns, reviewer identities, and signatures are excluded from public persistence.");
    expect(html).not.toContain("0x");
    expect(html).not.toContain("QVL verified");
    expect(html).not.toContain("Intel TDX evidence");
  });

  it("does not represent modeled reviewer roles as people or configured authority", () => {
    const html = renderReviewQueue();
    expect(html).toContain("No reviewer roster in this build");
    expect(html).toContain("not people, wallet addresses, public keys, signatures, approvals, or claims of configured authority");
    expect(html.match(/UNCONFIGURED/g)).toHaveLength(3);
    expect(html).toContain("Safe browser authority not configured");
    expect(html.match(/UNRESOLVED/g)).toHaveLength(4);
  });

  it("exposes modeled selection and action gates to assistive technology", () => {
    const html = renderReviewQueue();
    expect(html).toContain('role="list" aria-label="Source-modeled review examples"');
    expect(html.match(/role="listitem"/g)).toHaveLength(3);
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain('aria-controls="review-selected-workbench"');
    expect(html).toContain('id="review-selected-workbench" class="review-detail-panel"');
    expect(html).toContain('role="status" aria-live="polite"');
    expect(html).toContain('aria-describedby="review-actions-gate"');
    expect(html).toContain('id="review-authority-boundary"');
  });
});
