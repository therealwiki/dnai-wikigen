import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it, vi } from "vitest";
import { CollaborateComputePlanBuilder } from "./CollaborateComputePlanBuilder";
import builderSource from "./CollaborateComputePlanBuilder.tsx?raw";
import railSource from "./CollaborateExecutionLiveRail.tsx?raw";
import computeSource from "../views/Compute.tsx?raw";
import { computeTabForHash, routeForHash } from "../routes";

describe("guided Compute to Collaboration request UI", () => {
  it("renders a usable public import form while disconnected and release-gated preparation stays disabled", () => {
    const onPrepared = vi.fn();
    const html = renderToString(() => createComponent(CollaborateComputePlanBuilder, {
      enabled: false, workflowBusy: false, locked: false, onPrepared,
    }));
    expect(html).toContain("Compute → Workloads");
    const workloadLink = html.match(/href="([^"]+)"[^>]*>Compute → Workloads/)!;
    expect(workloadLink).not.toBeNull();
    expect(routeForHash(workloadLink[1])).toBe("compute");
    expect(computeTabForHash(workloadLink[1])).toBe("workloads");
    expect(html).toContain("PUBLIC WORKLOAD DRAFT · NO TOKENS OR PRIVATE INPUTS");
    expect(html).toContain("NEW JOB REFERENCE");
    expect(html).toContain("OWNER ROYALTY · BASE UNITS");
    expect(html).toContain("ALL-IN CAP · BASE UNITS");
    expect(html).toContain("Imported JSON is untrusted");
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Verify workload/);
    expect(html).not.toContain("Prepared:");
    expect(onPrepared).not.toHaveBeenCalled();
  });

  it("locks draft and funding controls once a plan exists or a workflow is pending", () => {
    for (const state of [{ locked: true, workflowBusy: false }, { locked: false, workflowBusy: true }]) {
      const html = renderToString(() => createComponent(CollaborateComputePlanBuilder, {
        enabled: true, ...state, onPrepared: () => {},
      }));
      expect(html).toContain("<fieldset disabled");
    }
  });

  it("wires validated funding before the console prompt and a second fresh read before plan creation", () => {
    expect(builderSource.indexOf("validateCollaborationExecutionFundingDraft(selectedFunding")).toBeLessThan(builderSource.indexOf("await wallet.authorizeComputeConsole()"));
    expect(builderSource).toContain("Authorize a short-lived Compute console session");
    expect(builderSource).not.toContain("Authorize a short-lived Compute read session");
    expect(builderSource).toContain("refreshCollaborationExecutionPlanRequest(");
    expect(railSource.indexOf("await prepared.verifyCurrent()")).toBeLessThan(railSource.indexOf("await adapter.createPlan("));
    expect(railSource).toContain("preparedComputePlan() !== prepared");
    expect(builderSource).toContain("if (!props.locked) props.onPrepared(undefined)");
  });

  it("keeps separate one-shot Compute authority, public recovery and Royalty funding in the actual rail", () => {
    expect(computeSource).toContain("Prepare public Collaboration draft");
    expect(computeSource).toContain("retainComputeCollaborationWorkloadDraft(");
    expect(railSource).toContain("assertCollaborationComputeAuthorizationMatchesPlanRequest(");
    expect(railSource).toContain("prepareCollaborationComputeAuthorization(");
    expect(railSource).toContain("submitCollaborationComputeAuthorization(");
    expect(railSource).toContain("reconcileCollaborationComputeAuthorization(");
    expect(railSource).toContain("submitCollaborationFundingReservation(");
    expect(railSource).not.toContain("authorizeVaultJob(");
    expect(railSource).not.toContain("planRequestJson");
  });
});
