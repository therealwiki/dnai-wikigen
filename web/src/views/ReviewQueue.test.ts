import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import reviewQueueSource from "./ReviewQueue.tsx?raw";
import {
  ReviewQueue,
  reviewAuthorityReady,
  type ReviewAuthorityReadiness,
} from "./ReviewQueue";

const READY: ReviewAuthorityReadiness = {
  reviewerBackendConfigured: true,
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

describe("ReviewQueue source-modeled boundary", () => {
  it("labels the entire desk as roadmap and never presents examples as a live queue", () => {
    const html = renderReviewQueue();

    expect(html).toContain("Roadmap · source-modeled examples only");
    expect(html).toContain("not a live queue");
    expect(html).toContain("MODELED SAMPLE");
    expect(html).toContain("RELEASE GATED");
    expect(html).toContain("Illustrative sequence · not an audit log");
    expect(html).toContain("MODELED · NOT RECORDED");
    expect(html).toContain("HELD · 0 OF 5 AUTHORITY PREREQUISITES");
    expect(html).toContain("NO RELEASE AUTHORITY");
  });

  it("renders every authority-bearing action disabled with a visible gate explanation", () => {
    const html = renderReviewQueue();

    expect(reviewQueueSource.match(/type="button"\s+disabled\b/g)).toHaveLength(5);
    expect(reviewQueueSource.match(/\bonClick=/g)).toHaveLength(1);
    expect(reviewQueueSource).toContain("onClick={() => setSelectedId(item.id)}");

    for (const label of [
      "Release authority unavailable",
      "Record hold",
      "Request changes",
      "Sign and release",
      "Request reviewer signatures",
    ]) {
      expect(html).toContain(label);
    }

    expect(html.match(/<button\b[^>]*\bdisabled(?:="")?[^>]*>/g)).toHaveLength(5);
    expect(html).toContain("Roadmap / release gated: no mutation handler is connected.");
    expect(html).toContain("Disabled until reviewer identities and the signature domain are independently pinned.");
  });

  it("shows policy requirements without claiming that any control passed", () => {
    const html = renderReviewQueue();

    expect(html).toContain("Five controls before a human can release less.");
    expect(html.match(/UNVERIFIED/g)).toHaveLength(4);
    expect(html).toContain("SOURCE REQUIREMENT");
    expect(html).toContain("They are requirements, not browser-verified checks");
    expect(html).not.toContain("CONTROL PASSED");
    expect(html).not.toContain("POLICY PASSED");
  });

  it("contains no fake reviewer identity, signature material, hardware verdict, or backend path", () => {
    const html = renderReviewQueue();

    expect(html).toContain("No people, wallet addresses, public keys, signature bytes, or approvals");
    expect(html.match(/Unconfigured/g)).toHaveLength(3);
    expect(html.match(/Not requested/g)).toHaveLength(3);
    expect(html).not.toContain("0x");
    expect(html).not.toContain("QVL verified");
    expect(html).not.toContain("Intel TDX evidence");
    expect(reviewQueueSource).not.toContain("fetch(");
    expect(reviewQueueSource).not.toContain("wallet.");
    expect(reviewQueueSource).not.toContain("publicClient");
  });

  it("exposes the modeled selection and gate explanations to assistive technology", () => {
    const html = renderReviewQueue();

    expect(html).toContain('role="list" aria-label="Source-modeled review examples"');
    expect(html.match(/role="listitem"/g)).toHaveLength(3);
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain('aria-controls="review-selected-workbench"');
    expect(html).toContain('id="review-selected-workbench" class="review-detail-panel"');
    expect(html).toContain('role="status" aria-live="polite"');
    expect(html).toContain('aria-describedby="review-actions-gate"');
    expect(html).toContain('aria-describedby="review-signature-gate"');
  });
});
