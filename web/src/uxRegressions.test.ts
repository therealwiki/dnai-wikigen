import { describe, expect, it } from "vitest";
import webReadme from "../README.md?raw";
import appSource from "./App.tsx?raw";
import verificationContextSource from "./lib/verificationContext.ts?raw";
import arenaSource from "./views/Arena.tsx?raw";
import computeSource from "./views/Compute.tsx?raw";
import dealRoomSource from "./views/DealRoom.tsx?raw";
import verifySource from "./views/Verify.tsx?raw";

describe("cross-route evidence inspection regressions", () => {
  it("keeps exactly one bounded selection in App memory and out of durable/browser-addressable state", () => {
    expect(appSource).toContain("createSignal<VerificationContext>()");
    expect(appSource).toContain("setVerificationContext(context)");
    expect(appSource).toContain('goToRoute("verify")');
    expect(appSource).toContain("Global navigation always opens a generic route");
    expect(`${appSource}\n${verificationContextSource}`).not.toMatch(/localStorage|sessionStorage|history\.state|URLSearchParams/);
  });

  it("uses explicit Inspect actions instead of generic Verify navigation", () => {
    expect(arenaSource).toContain("createArenaRankingVerificationContext");
    expect(arenaSource).toContain("props.inspectEvidence");
    expect(arenaSource).not.toContain('props.navigate("verify")');
    expect(computeSource).toContain("createComputeJobVerificationContext(job)");
    expect(computeSource).toContain("Inspect receipt hash");
    expect(computeSource).not.toContain('navigate("verify")');
    expect(appSource).toContain("<DealRoom inspectEvidence={inspectEvidence} />");
    expect(dealRoomSource).toContain("createDealResultVerificationContext(props.deal");
    expect(dealRoomSource).toContain("Inspect in Trust Center");
  });

  it("keeps selected claims separate from independent browser checks", () => {
    expect(verifySource).toContain("Selecting this row never advances the six-level ladder or seeds the receipt editor");
    expect(verifySource).toContain("Hash only · receipt body absent");
    expect(verifySource).toContain("Worker-reported · not independently verified");
    expect(verifySource).toContain("Contract-reported · not independently verified");
    expect(verifySource).toContain("IN-MEMORY PUBLIC PROJECTION");
    expect(verifySource).not.toContain("QVL verified");
  });
});

describe("Compute safety regressions", () => {
  it("lets an authorized zero-project account dismiss the creation prompt without trapping focus", () => {
    expect(computeSource).toContain("() => setProjectOpen(false)");
    expect(computeSource).toContain('aria-label="Close project dialog"');
    expect(computeSource).toContain('class="dialog-backdrop" onClick={() => setProjectOpen(false)}');
    expect(computeSource).toContain("You can close this dialog without creating anything");
    expect(computeSource).toContain("Authorized · choose or create a project");
    expect(computeSource).not.toContain("projects().length > 0 && setProjectOpen(false)");
    expect(computeSource).not.toContain('disabled={projects().length === 0}');
  });

  it("starts every new credential at the read-only least-privilege scope", () => {
    expect(computeSource).toContain('createSignal<ComputeScope[]>(["jobs:read"])');
    expect(computeSource).toContain('setSelectedScopes(["jobs:read"])');
    expect(computeSource).toContain("Least privilege by default");
    expect(computeSource).toContain("must be opted into explicitly");
    expect(computeSource).toContain("onClick={openNewKeyDialog}");
  });

  it("keeps modeled Compute credentials inside the scopes this console can issue", () => {
    expect(computeSource).toContain('scopes: ["workloads:create", "jobs:read"]');
    expect(computeSource).not.toContain('scopes: ["challenge:submit", "receipts:read"]');
    expect(computeSource).toContain("Arena submission and receipt scopes remain in their purpose-separated authentication domains");
  });
});

describe("Arena modeled-state and documentation regressions", () => {
  it("labels every modeled metric category and modeled ranking row at the point of use", () => {
    expect(arenaSource).toContain("ILLUSTRATIVE BOUNTY");
    expect(arenaSource).toContain("ILLUSTRATIVE ENTRIES");
    expect(arenaSource).toContain("ILLUSTRATIVE WINDOW");
    expect(arenaSource).toContain("ILLUSTRATIVE METRIC");
    expect(arenaSource).toContain('evidenceLabel: "Modeled sample"');
    expect(arenaSource).toContain("Illustrative ranking only; no execution occurred");
    expect(arenaSource).toContain("BOUNTY STATUS · NO LIVE POOL");
  });

  it("documents all four Arena tabs and narrows Verify to checks this browser actually performs", () => {
    expect(webReadme).toContain("`rankings`, `queue`, `submissions`, or `spec`");
    expect(webReadme).toContain("bytecode presence and optional runtime-code-hash observations");
    expect(webReadme).toContain("it does not verify Intel collateral, QVL signatures, or release policy");
    expect(webReadme).not.toContain("CVM/verdict inspection");
  });
});
