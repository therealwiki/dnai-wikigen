import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";

import { CollaborateExecution } from "./CollaborateExecution";
import componentSource from "./CollaborateExecution.tsx?raw";
import liveRailSource from "./CollaborateExecutionLiveRail.tsx?raw";
import { collaborationExecutionTransportAdapter } from "../lib/collaborationExecutionTransport";

function renderExecution(
  initialScenario:
    | "release_disabled"
    | "ambiguous_reconciliation"
    | "bounded_result"
    | "settlement_withdrawal",
): string {
  return renderToString(() => createComponent(CollaborateExecution, {
    initialScenario,
  }));
}

describe("CollaborateExecution", () => {
  it("renders implemented rails, a closed unsigned/dev release, and a separate modeled failure lab", () => {
    const html = renderExecution("release_disabled");

    expect(html).toContain('data-execution-state="disabled"');
    expect(html).toContain('data-execution-evidence="implemented-release-gated-rails-plus-modeled-lab"');
    expect(html).toContain("Production-capable execution rails · current release closed");
    expect(html).toContain("Current unsigned/dev release · mutations closed");
    expect(html).toContain("IMPLEMENTED · CURRENT RELEASE DISABLED");
    expect(html).toContain("the scenario controls remain a modeled failure lab");
    expect(html).toContain("Deterministic demo room input");
    expect(html).toContain("Compute source not authenticated here");
    expect(html).toContain("No TDX or QVL evidence");
    expect(html).toContain("No health-data intake");
    expect(html).toContain("Never reused as execution grants");
    expect(html).toContain("Release-gated wallet rail implemented · modeled failure lab isolated");
    expect(html).toContain('data-product-implementation="wallet-executable"');
    expect(html).toContain("IMPLEMENTED WALLET RAIL · RELEASE-GATED · BASE SEPOLIA");
  });

  it("shows the real Collaboration transport seam while mutations remain closed", () => {
    const html = renderToString(() => createComponent(CollaborateExecution, {
      initialScenario: "happy_path",
      session: {
        accessToken: `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`,
        address: `0x${"1".repeat(40)}`,
        issuedAt: 1_900_000_000,
        expiresAt: 1_900_000_600,
        walletAuthorizationVersion: 1,
      },
      transportAdapter: collaborationExecutionTransportAdapter,
    }));

    expect(html).toContain('data-execution-transport="closed"');
    expect(html).toContain("Typed adapter present");
    expect(html).toContain("Not current");
    expect(html).toContain("No standalone demo state can satisfy this gate");
    expect(html).toContain("MUTATIONS FAIL-CLOSED");
    expect(html.match(/data-live-execution-call=/g)).toHaveLength(5);
    expect(html.match(/ disabled/g)?.length).toBeGreaterThanOrEqual(5);
    expect(html).toContain("GET /execution-capability · no job claim");
    expect(html).toContain("Queue mutations, reservation");
    expect(html).toContain("STATUS LOOKUP · EXACT EXECUTION ID · READ-ONLY");
    expect(html).toContain("participant API projection—not independent TDX");
  });

  it("renders ambiguous dispatch as a reconciliation hold with no redispatch", () => {
    const html = renderExecution("ambiguous_reconciliation");

    expect(html).toContain('data-execution-state="modeled_reconciliation"');
    expect(html).toContain("RECONCILIATION HOLD");
    expect(html).toContain("Do not dispatch again.");
    expect(html).toContain("automatic redispatch is forbidden");
    expect(html).toContain("Typed projection ≠ journal proof.");
    expect(html).toContain("NOT AUTHENTICATED");
  });

  it("renders only a bounded modeled result with explicit attestation limits", () => {
    const html = renderExecution("bounded_result");

    expect(html).toContain('data-execution-state="modeled_bounded_result"');
    expect(html).toContain('data-result-evidence="modeled-not-qvl"');
    expect(html).toContain("BOUNDED RESULT · MODELED FIXTURE");
    expect(html).toContain("top 10 percent");
    expect(html).toContain("Raw provider output is absent.");
    expect(html).toContain("TDX / QVL");
    expect(html).toContain("not verified");
  });

  it("keeps every Royalty and owner-withdrawal proof stage distinct", () => {
    const html = renderExecution("settlement_withdrawal");

    expect(html).toContain('data-execution-state="modeled_withdrawal"');
    expect(html).toContain("Server-issued terms");
    expect(html).toContain("Onchain deposit");
    expect(html).toContain("Finalized reservation");
    expect(html).toContain("Settlement authority");
    expect(html).toContain("Independent QVL");
    expect(html).toContain("Broadcast");
    expect(html).toContain("Finalized receipt");
    expect(html).toContain("Owner withdrawal");
    expect(html).toContain("MODELED STAGE · NO LIVE RECEIPT");
    expect(html).toContain("Live credit");
    expect(html).toContain("Not observed");
    expect(html).toContain("Not broadcast");
    expect(html).toContain("Exact finalized reservation observed: no");
    expect(html).toContain("Broadcast / finality observed: no");
  });

  it("separates implemented wallet actions from modeled and per-job evidence", () => {
    expect(componentSource).toContain('data-collaboration-model-action="advance"');
    expect(componentSource).toContain("adapter.fetchStatus");
    expect(componentSource).toContain("adapter.fetchWorkerCapability");
    expect(componentSource).toContain(
      "authenticated-worker-presence-not-job-attestation",
    );
    expect(componentSource).toContain("nextSessionKey === liveStatusSessionKey");
    expect(componentSource).toContain("CLIENT DTO CANNOT UNLOCK EXECUTION");
    expect(componentSource).toContain("Read does not authorize a mutation");
    expect(componentSource).toContain("Authority remains split");
    expect(componentSource).toContain(
      "release: deployment.collaborationExecutionRelease",
    );
    expect(componentSource).not.toContain("release: props.executionRelease");
    expect(liveRailSource).toContain("adapter.createPlan");
    expect(liveRailSource).toContain("adapter.issueGrantChallenge");
    expect(liveRailSource).toContain("adapter.authorize");
    expect(liveRailSource).toContain("loadFinalizedRoyaltyRailState(account)");
    expect(liveRailSource).toContain(
      "assertFreshControlPlaneRoyaltyAuthority(currentPlan)",
    );
    expect(liveRailSource).toContain(
      "assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan)",
    );
    expect(liveRailSource).toContain(
      "assertCollaborationExecutionPlanMatchesJointRun(",
    );
    expect(liveRailSource).toContain("{ room, jointRun }");
    expect(liveRailSource).toContain("currentPlan,");
    expect(liveRailSource).toContain(
      "assertCollaborationExecutionGrantChallengeForSigning(challenge",
    );
    expect(liveRailSource).toContain("submitCollaborationFundingReservation");
    expect(liveRailSource).toContain("submitCollaborationRoyaltySettlement");
    expect(liveRailSource).toContain(
      "cause instanceof CollaborationReservationRetentionError",
    );
    expect(liveRailSource).toContain(
      "cause instanceof CollaborationSettlementRetentionError",
    );
    expect(liveRailSource).toContain("replaceReservationIntent(cause.intent)");
    expect(liveRailSource).toContain("replaceSettlementIntent(cause.intent)");
    expect(liveRailSource).toContain("Refund expired reservation");
    expect(liveRailSource).toContain('data-product-implementation="wallet-executable"');
    expect(liveRailSource).toContain("Requires per-job TDX + QVL + chain");
    expect(liveRailSource).not.toContain('data-live-product="wallet-executable"');
    expect(liveRailSource).not.toContain("LIVE PRODUCT RAIL");
    expect(componentSource).not.toContain("illustrative signature");
    expect(componentSource).not.toContain("TDX verified");
    expect(componentSource).not.toContain("QVL verified");
    expect(componentSource).not.toContain("funds reserved");
  });

});
