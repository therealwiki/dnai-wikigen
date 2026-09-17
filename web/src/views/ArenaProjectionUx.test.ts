import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import arenaSource from "./Arena.tsx?raw";
import { Arena, arenaPublicQueuePresentation, canReusePreparedArenaSubmission } from "./Arena";
import type { PreparedArenaSubmission } from "../lib/arena";

const noNavigation = () => undefined;

describe("Arena public projection freshness", () => {
  it("polls only visible service-backed challenge projections and cleans up the timer", () => {
    expect(arenaSource).toContain('document.visibilityState === "visible"');
    expect(arenaSource).toContain("}, 30_000)");
    expect(arenaSource).toContain("window.clearInterval(poll)");
    expect(arenaSource).toContain("onCleanup(() => {");
    expect(arenaSource).toContain("untrack(() => void refreshSelectedChallenge(false))");
  });

  it("distinguishes refresh failure from a successfully empty ranking or queue", () => {
    expect(arenaSource).toContain("Rankings could not be refreshed.");
    expect(arenaSource).toContain("Queue status could not be refreshed.");
    expect(arenaSource).toContain("No ranking data is being shown as an empty result.");
    expect(arenaSource).toContain("No queue data is being presented as an empty queue.");
    expect(arenaSource).toContain('projectionState() !== "loading" && projectionState() !== "error"');
  });

  it("offers explicit refresh actions without upgrading row evidence", () => {
    expect(arenaSource.match(/onClick=\{\(\) => void refreshSelectedChallenge\(\)\}/g)?.length).toBeGreaterThanOrEqual(2);
    expect(arenaSource).toContain("Worker-reported QVL binding; not independently verified by this browser");
    expect(arenaSource).toContain(
      "Worker-reported provenance is not independent QVL or TDX verification.",
    );
    expect(arenaSource).toContain(
      "Worker-reported QVL binding · not independently verified",
    );
    expect(arenaSource).toContain("The last bounded projection remains visible and may be stale.");
  });

  it("separates observed service presence, ciphertext ingress, and row execution", () => {
    expect(arenaSource).toContain("service observed · execution per row");
    expect(arenaSource).toContain("service not observed · execution per row");
    expect(arenaSource).toContain("Prepare ciphertext ingress");
    expect(arenaSource).toContain("CIPHERTEXT INGRESS · RELEASE GATED");
    expect(arenaSource).toContain("Encrypt and create gated ingress record");
    expect(arenaSource).toContain("execution remains separately gated and unproven");
    expect(arenaSource).toContain("Ciphertext accepted is not code executed.");
    expect(arenaSource).toContain("This queue is an unexecuted product model.");
    expect(arenaSource).toContain("Ingress records can be live while execution remains absent");
    expect(arenaSource).not.toContain("Encrypt and create modeled record");
    expect(arenaSource).not.toContain("entered the modeled queue");
  });

  it("exposes queue rows as a labeled list with a mobile-visible status label", () => {
    expect(arenaSource).toContain('class="queue-list" role="list"');
    expect(arenaSource).toContain('class="queue-row" role="listitem"');
    expect(arenaSource).toContain('data-queue-phase={run.phase}');
    expect(arenaSource).toContain(
      'aria-label={`${run.phase === "terminal" ? "Terminal" : "Active"} status: ${run.status}`}',
    );
    expect(arenaSource).toContain('class="queue-state-label">{run.status}</span>');
  });

  it("presents active and terminal queue states explicitly instead of folding terminal rows into queued", () => {
    for (const state of [
      "submitted",
      "policy_screen",
      "queued",
      "provisioning",
      "public_tests",
      "sealed_eval",
      "review_hold",
    ] as const) {
      expect(arenaPublicQueuePresentation(state).phase).toBe("active");
    }

    for (const state of [
      "completed",
      "failed",
      "withheld",
      "cancelled",
      "expired",
      "dead_letter",
    ] as const) {
      const presentation = arenaPublicQueuePresentation(state);
      expect(presentation.phase, state).toBe("terminal");
      expect(presentation.label, state).not.toBe("queued");
      expect(presentation.tone, state).not.toBe("queued");
      expect(presentation.spinning, state).toBe(false);
    }

    expect(arenaPublicQueuePresentation("completed").label).toBe("completed");
    expect(arenaPublicQueuePresentation("failed").label).toBe("failed");
    expect(arenaPublicQueuePresentation("withheld").label).toBe("withheld");
    expect(arenaPublicQueuePresentation("cancelled").label).toBe("cancelled");
    expect(arenaPublicQueuePresentation("expired").label).toBe("expired");
    expect(arenaPublicQueuePresentation("dead_letter").label).toBe("dead letter");
  });

  it("paginates public rankings and queue rows without treating per-page counts as totals", () => {
    expect(arenaSource).toContain("appendArenaLeaderboardPageRows");
    expect(arenaSource).toContain("appendArenaQueuePageRows");
    expect(arenaSource).toContain("Load more rankings");
    expect(arenaSource).toContain("Load more queue records");
    expect(arenaSource).toContain("Next ranking page rejected.");
    expect(arenaSource).toContain("Next queue page rejected.");
    expect(arenaSource.match(/Restart from first page/g)).toHaveLength(2);
    expect(arenaSource).toContain('aria-controls="arena-public-rankings-table"');
    expect(arenaSource).toContain('aria-controls="arena-public-queue-list"');
    expect(arenaSource).toContain('role="status" aria-live="polite" aria-atomic="true"');
    expect(arenaSource).toContain("publicLeaderboardRows().length");
    expect(arenaSource).toContain("publicQueueRows().length");
    expect(arenaSource).toContain("PUBLIC API · LOADED QUEUE ROWS");
    expect(arenaSource).toContain("ROWS LOADED");
    expect(arenaSource).not.toContain("PUBLIC API · QUEUE COUNT");
    expect(arenaSource).not.toContain('"INGRESS RECORDS"');
    expect(arenaSource).toContain("No continuation cursor was returned.");
  });

  it("preserves explicitly extended pages until the user restarts from page one", () => {
    expect(arenaSource).toContain("const extendedProjection =");
    expect(arenaSource).toContain('document.visibilityState === "visible" && !extendedProjection');
    expect(arenaSource).toContain("The rows already shown were preserved.");
  });

  it("binds Arena preparation, wallet authorization, and submission to one wallet generation", () => {
    expect(arenaSource).toContain("const walletVersion = wallet.authorizationVersion()");
    expect(arenaSource).toContain("wallet.authorizationVersion() !== walletVersion");
    expect(arenaSource).toContain("prepared.walletAddress !== token.address.toLowerCase()");
    expect(arenaSource).toContain("Wallet session changed while preparing the Arena submission");
  });

  it("offers owner-state recovery after a submission error without replacing or resending the prepared request", () => {
    const errorRecovery = arenaSource.match(/<Show when=\{submissionError\(\)\}>([\s\S]*?)<\/Show>/)?.[1];
    expect(errorRecovery).toBeDefined();
    expect(errorRecovery).toContain('role="alert">{submissionError()}');
    expect(errorRecovery).toContain('data-arena-action="inspect-submission-error"');
    expect(errorRecovery).toContain('disabled={submitting()}');
    expect(errorRecovery).toContain('onClick={() => { closeSubmissionDialog(); chooseTab("submissions"); }}');
    expect(errorRecovery).toContain("View my submissions");
    expect(errorRecovery).toContain("Inspect your wallet-owned records before retrying.");
    expect(errorRecovery).toContain("Viewing records does not resend or replace your prepared request.");
    expect(errorRecovery).not.toMatch(/submitProgram|submitPreparedArenaSubmission|prepareArenaSubmission|newArenaIdempotencyKey|setPreparedSubmission|setSubmissionResult/);

    const closeDialog = arenaSource.match(/const closeSubmissionDialog = \(\): void => \{([\s\S]*?)\n  \};/)?.[1];
    const switchTab = arenaSource.match(/const chooseTab = \(next: ArenaTab\): void => \{([\s\S]*?)\n  \};/)?.[1];
    expect(closeDialog).toBeDefined();
    expect(switchTab).toBeDefined();
    expect(closeDialog).toContain("if (submitting()) return;");
    expect(switchTab).toContain("setTab(next)");
    for (const navigation of [closeDialog, switchTab]) {
      expect(navigation).not.toMatch(/setPreparedSubmission|setSubmissionFile|setSubmissionHash|prepareArenaSubmission|submitPreparedArenaSubmission|newArenaIdempotencyKey/);
    }
    expect(arenaSource).toContain('onClick={() => void refreshOwnerView()}');
    expect(arenaSource).toContain('onClick={() => void authorizeOwnerView()}');
    expect(arenaSource).toContain("if (!canReusePreparedArenaSubmission(prepared, {");
    expect(arenaSource).toContain(": canReusePreparedArenaSubmission(preparedSubmission(), {");
    expect(arenaSource).toContain('? "Retry same encrypted request"');
    expect(arenaSource).toContain('onClick={() => void submitProgram()}');
    expect(arenaSource).toContain('disabled={!submissionConfigured() || !challenge().apiBacked || !submissionFile() || !submissionHash() || !wallet.account() || hashing() || submitting()}');
  });

  it("promises same-request retry only for the exact retained wallet, challenge, manifest, and source context", () => {
    const context = {
      challengeId: "dnaseq-variant-qc-safe-ir",
      challengeVersion: "1.0.0",
      challengeManifestHash: "1".repeat(64),
      candidateCommitment: `sha256:${"2".repeat(64)}`,
      sourceBytes: 200,
      walletAddress: `0x${"ab".repeat(20)}`,
    };
    const prepared = {
      challengeId: context.challengeId,
      challengeVersion: context.challengeVersion,
      candidateCommitment: context.candidateCommitment,
      sourceBytes: context.sourceBytes,
      walletAddress: context.walletAddress,
      idempotencyKey: "original-uncertain-attempt",
      payload: { manifest: { challenge_manifest_hash: context.challengeManifestHash } },
    } as PreparedArenaSubmission;
    const retained = JSON.stringify(prepared);
    expect(canReusePreparedArenaSubmission(prepared, context)).toBe(true);
    expect(canReusePreparedArenaSubmission(undefined, context)).toBe(false);
    for (const changed of [
      { challengeId: "another-challenge" },
      { challengeVersion: "2.0.0" },
      { challengeManifestHash: "3".repeat(64) },
      { candidateCommitment: `sha256:${"4".repeat(64)}` },
      { sourceBytes: 201 },
      { walletAddress: `0x${"cd".repeat(20)}` },
      { walletAddress: undefined },
    ]) {
      expect(canReusePreparedArenaSubmission(prepared, { ...context, ...changed })).toBe(false);
    }
    expect(JSON.stringify(prepared)).toBe(retained);
    expect(prepared.idempotencyKey).toBe("original-uncertain-attempt");
  });

  it("offers owner-only pre-claim cancellation and retryable unlink with explicit evidence limits", () => {
    expect(arenaSource).toContain("challenge:submissions:manage");
    expect(arenaSource).toContain("Cancel before claim");
    expect(arenaSource).toContain("Confirm cancel");
    expect(arenaSource).toContain("Retry ciphertext unlink");
    expect(arenaSource).toContain("A successful cancel is terminal, prevents worker claim, and immediately attempts ciphertext unlink.");
    expect(arenaSource).toContain("one hour is the configured maximum-retention deadline");
    expect(arenaSource).toContain("not a promised wait");
    expect(arenaSource).toContain("becomes unavailable to service reads immediately");
    expect(arenaSource).toContain("physical-deletion guarantee");
    expect(arenaSource).toContain("no physical wipe claimed");
    expect(arenaSource).toContain("physical-media erasure is not claimed");
    expect(arenaSource).toContain('role="group" aria-label={`Confirm cancellation of ${item.submission_id}`}');
    expect(arenaSource).toContain("cannot drive worker transitions");
  });

  it("recovers ambiguous owner mutations from a fresh authenticated row without trusting stale wallet state", () => {
    expect(arenaSource).toContain("const recoverOwnerAction = async");
    expect(arenaSource).toContain("await loadOwnerPage(token)");
    expect(arenaSource).toContain("if (!ownerMutationStillCurrent(token, context)) return false");
    expect(arenaSource).toContain("Outcome not confirmed; refresh the authenticated owner state before retrying.");
    expect(arenaSource).toContain("Current unlink state is unconfirmed; refresh before retrying.");
    expect(arenaSource).toContain("arenaSession()?.access_token === token.access_token");
    expect(arenaSource).toContain("wallet.authorizationVersion() === context.walletVersion");
  });

  it("does not render a fallback challenge under an unresolved versioned deep link", () => {
    const html = renderToString(() => createComponent(Arena, {
      navigate: noNavigation,
      inspectEvidence: noNavigation,
      navigateArena: noNavigation,
      routeState: {
        challengeId: "unknown-challenge",
        version: "9.9.9",
        tab: "rankings",
      },
    }));

    expect(html).toContain("Resolving challenge link");
    expect(html).toContain("No fallback challenge data is shown");
    expect(html).not.toContain("Variant QC Safe-IR");
    expect(html).not.toContain("Versioned rankings");
    expect(arenaSource).toContain('queueMicrotask(() => props.navigate("not_found"))');
  });
});
