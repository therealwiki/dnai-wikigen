import { describe, expect, it } from "vitest";
import {
  DealRoomOperationLock,
  dealRoomDraftMutationIsAllowed,
  runDealRoomOperation,
  type DealRoomOperationLease,
} from "../lib/dealRoomOperation";
import { projectDealLifecycle } from "./DealRoom";
import dealRoomSource from "./DealRoom.tsx?raw";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("Deal Room exclusive operations", () => {
  it("projects the full post-ciphertext lifecycle without inventing private worker telemetry", () => {
    const accepted = projectDealLifecycle({
      state: "Funded",
      ingress: { phase: "accepted", ciphertextReceipt: `sha256:${"a".repeat(64)}` },
    });
    expect(accepted.headline).toContain("Ciphertext acknowledged");
    expect(accepted.steps.map((step) => step.label)).toEqual([
      "Ciphertext",
      "Queued",
      "Awaiting policy",
      "Running",
      "Bounded result",
      "Expired / settled",
    ]);
    expect(accepted.steps.map((step) => step.tone)).toEqual([
      "complete",
      "unobserved",
      "unobserved",
      "unobserved",
      "pending",
      "pending",
    ]);
    expect(accepted.explanation).toContain("private worker states");

    const retry = projectDealLifecycle({ state: "Funded", ingress: { phase: "delivery_uncertain" } });
    expect(retry.headline).toContain("retry available");
    expect(retry.steps[0]).toMatchObject({ tone: "failed", detail: expect.stringContaining("retry retained pair") });

    const result = projectDealLifecycle({ state: "Evaluated", ingress: { phase: "idle" } });
    expect(result.steps.find((step) => step.key === "result")).toMatchObject({ tone: "complete" });
    expect(result.steps.find((step) => step.key === "resolution")).toMatchObject({ tone: "current" });

    const expired = projectDealLifecycle({ state: "Expired", ingress: { phase: "idle" } });
    expect(expired.steps.at(-1)).toMatchObject({ label: "Expired", tone: "expired" });
    expect(expired.explanation).toContain("does not infer");
  });

  it("admits only one deferred wallet workflow and rejects stale unlocks", async () => {
    const transitions: Array<DealRoomOperationLease | undefined> = [];
    const lock = new DealRoomOperationLock((active) => transitions.push(active));
    const walletPrompt = deferred();
    let workflowsLaunched = 0;
    let firstLease: DealRoomOperationLease | undefined;

    const first = runDealRoomOperation(
      lock,
      "wallet_transaction",
      "Fund room",
      async (lease) => {
        firstLease = lease;
        workflowsLaunched += 1;
        expect(Object.isFrozen(lease)).toBe(true);
        await walletPrompt.promise;
        return "confirmed";
      },
    );
    const duplicate = runDealRoomOperation(
      lock,
      "wallet_transaction",
      "Fund room again",
      async () => {
        workflowsLaunched += 1;
        return "duplicate";
      },
    );

    await expect(duplicate).resolves.toEqual({ started: false });
    expect(workflowsLaunched).toBe(1);
    expect(lock.busy).toBe(true);
    expect(lock.active).toMatchObject({ generation: 1, kind: "wallet_transaction", label: "Fund room" });

    walletPrompt.resolve();
    await expect(first).resolves.toEqual({ started: true, value: "confirmed" });
    expect(lock.busy).toBe(false);

    const nextLease = lock.acquire("wallet_transaction", "Withdraw ETH");
    expect(nextLease?.generation).toBe(2);
    expect(firstLease && lock.release(firstLease)).toBe(false);
    expect(lock.active).toBe(nextLease);
    expect(nextLease && lock.release(nextLease)).toBe(true);
    expect(transitions.map((lease) => lease?.label ?? "released")).toEqual([
      "Fund room",
      "released",
      "Withdraw ETH",
      "released",
    ]);
  });

  it("locks upload duplication and retains selectors through an uncertain result", async () => {
    const lock = new DealRoomOperationLock();
    const uploadResponse = deferred();
    let uploadRecoveryPending = false;
    let uploadsLaunched = 0;
    let selectedFile = "artifact-a.bin";
    let selectedReceipt = "artifact-a.recovery.json";

    const mutateSelection = (file: string, receipt: string): boolean => {
      if (!dealRoomDraftMutationIsAllowed({
        operationInFlight: lock.busy,
        uploadRecoveryPending,
      })) return false;
      selectedFile = file;
      selectedReceipt = receipt;
      return true;
    };

    const first = runDealRoomOperation(
      lock,
      "artifact_upload",
      "Authorize encrypted ingress",
      async () => {
        uploadsLaunched += 1;
        await uploadResponse.promise;
        // Model a POST whose response could not prove whether delivery landed.
        uploadRecoveryPending = true;
        return false;
      },
    );
    const duplicate = runDealRoomOperation(
      lock,
      "artifact_upload",
      "Authorize encrypted ingress again",
      async () => {
        uploadsLaunched += 1;
        return true;
      },
    );

    await expect(duplicate).resolves.toEqual({ started: false });
    expect(uploadsLaunched).toBe(1);
    expect(mutateSelection("artifact-b.bin", "artifact-b.recovery.json")).toBe(false);
    expect([selectedFile, selectedReceipt]).toEqual(["artifact-a.bin", "artifact-a.recovery.json"]);
    expect(dealRoomDraftMutationIsAllowed({
      operationInFlight: lock.busy,
      uploadRecoveryPending,
      explicitRecoveryDiscard: true,
    })).toBe(false);

    uploadResponse.resolve();
    await expect(first).resolves.toEqual({ started: true, value: false });
    expect(lock.busy).toBe(false);
    expect(uploadRecoveryPending).toBe(true);
    expect(mutateSelection("artifact-b.bin", "artifact-b.recovery.json")).toBe(false);
    expect([selectedFile, selectedReceipt]).toEqual(["artifact-a.bin", "artifact-a.recovery.json"]);

    expect(dealRoomDraftMutationIsAllowed({
      operationInFlight: lock.busy,
      uploadRecoveryPending,
      explicitRecoveryDiscard: true,
    })).toBe(true);
    uploadRecoveryPending = false;
    selectedFile = "";
    selectedReceipt = "";
    expect(mutateSelection("artifact-b.bin", "artifact-b.recovery.json")).toBe(true);
  });

  it("wires the shared lock into wallet, upload, selector, and reset paths", () => {
    expect(dealRoomSource).toContain("const operationLock = new DealRoomOperationLock");
    expect(dealRoomSource).toMatch(/runDealRoomOperation\(\s*operationLock,\s*"wallet_transaction"/);
    expect(dealRoomSource).toMatch(/runDealRoomOperation\(\s*props\.operationLock,\s*"artifact_upload"/);
    expect(dealRoomSource).toContain("if (!draftMutationIsAllowed()) return;");
    expect(dealRoomSource).toContain("if (!draftMutationIsAllowed(true)) return;");
    expect(dealRoomSource).toContain("disabled={uploadDraftLocked()}");
    expect(dealRoomSource.match(/type="file"[^>]*disabled=/g)).toHaveLength(3);
    expect(dealRoomSource).toContain("Unresolved artifact delivery retained");
    expect(dealRoomSource).toContain("Retry retained pair");
    expect(dealRoomSource).toContain("Discard retained pair");
    expect(dealRoomSource).toContain("const [artifactUploadRecovery, setArtifactUploadRecovery]");
    expect(dealRoomSource).toContain("if (deal.id.toString() === recoveryDealId) return true;");
    expect(dealRoomSource).toContain("onPostStarted: () => { uploadBoundaryEntered = true; }");
    expect(dealRoomSource).toContain('disabled={mutationLocked()} onClick={() => {\n            if (draftMutationIsAllowed()) setTx({ kind: "idle", label: "" });');
  });

  it("accepts no private artifact while release-authorized room creation is locked", () => {
    expect(dealRoomSource).toContain("const [chainBacked, setChainBacked] = createSignal(false)");
    expect(dealRoomSource).toContain("const writesReady = () => chainBacked() && deployment.contractWritesEnabled && Boolean(writePolicy())");
    expect(dealRoomSource).toContain("setChainBacked(true)");
    expect(dealRoomSource).toContain("Live chain read · writes locked");
    expect(dealRoomSource).toContain("Checking live chain read · writes locked");
    expect(dealRoomSource).toContain("Chain read unavailable · writes locked");
    expect(dealRoomSource).toContain('chainBacked={chainBacked()}');
    expect(dealRoomSource).toContain('writeReady={writesReady()}');
    expect(dealRoomSource).toMatch(/const creationDraftIsAllowed = \(\) =>[\s\S]*writesReady\(\)[\s\S]*draftMutationIsAllowed\(\)[\s\S]*dealCreationRecovery\(\) === undefined/);
    expect(dealRoomSource).toMatch(/const creationLocked = \(\) =>[\s\S]*!writesReady\(\)[\s\S]*mutationLocked\(\)[\s\S]*dealCreationRecovery\(\) !== undefined/);
    expect(dealRoomSource).toContain('disabled={creationLocked()} onClick={() => {\n          if (creationDraftIsAllowed()) setShowCreate(!showCreate());');
    expect(dealRoomSource).toContain('dealCreationStorageError() ? "Recovery storage blocked" : dealCreationRecovery() ? "Creation recovery required"');
    expect(dealRoomSource).toContain('type="file" disabled={creationLocked()}');
    expect(dealRoomSource).toContain("No fresh project-owned deployment");
    expect(dealRoomSource).toContain(
      "Any prior operator deployment is excluded rather than inherited",
    );
    expect(dealRoomSource).toContain(
      "no private artifact selector is enabled",
    );
    expect(dealRoomSource).not.toContain(
      "current repo deployment belongs to another operator",
    );
    expect(dealRoomSource).not.toContain("Contract configured · writes locked");
    for (const releasePin of [
      "deployment.contractInitialDeveloper",
      "deployment.contractReleaseGovernanceController",
    ]) expect(dealRoomSource).toContain(releasePin);
    for (const observation of [
      "initialDeveloper",
      "releaseGovernanceController",
      "pendingDeveloper",
      "pendingDeveloperActivatesAt",
    ]) expect(dealRoomSource).toContain(observation);
    expect(dealRoomSource).toContain(
      "DiligenceRoom governance controller has not accepted the delayed developer handoff",
    );
    expect(dealRoomSource).toContain(
      "DiligenceRoom has an unexpected pending developer handoff",
    );
  });

  it("hands result-bearing rooms to Trust Center without presenting commitments as verified attestation", () => {
    expect(dealRoomSource).toContain("createDealResultVerificationContext(props.deal");
    expect(dealRoomSource).toContain("props.inspectEvidence");
    expect(dealRoomSource).toContain("Inspect in Trust Center");
    expect(dealRoomSource).toContain("ATTESTATION COMMITMENT");
    expect(dealRoomSource).toContain("Contract/worker-reported binding · not independently verified by this browser");
    expect(dealRoomSource).toContain("Illustrative commitment · no execution, QVL, raw quote, or Intel evidence");
    expect(dealRoomSource).not.toContain("QVL EVIDENCE");
    expect(dealRoomSource).not.toContain("Intel TDX evidence verified");
  });

  it("exposes the selected Deal Room filter to assistive technology", () => {
    expect(dealRoomSource).toContain('aria-pressed={filter() === item.key}');
  });

  it("keeps deterministic pagination, retry, restart, exact lookup, and Mine completeness explicit", () => {
    expect(dealRoomSource).toContain("const page = await loadDeals({ cursor })");
    expect(dealRoomSource).toContain("dealContinuation() !== cursor");
    expect(dealRoomSource).toContain("mergeDealPages(current, page.deals)");
    expect(dealRoomSource).toContain('setLoadFailure("more")');
    expect(dealRoomSource).toContain("Retry same page");
    expect(dealRoomSource).toContain("Restart snapshot");
    expect(dealRoomSource).toContain("const lookup = await loadDealById(requestedId)");
    expect(dealRoomSource).toContain("shown once regardless of the active filter");
    expect(dealRoomSource).toContain("filteredDeals.some((deal) => deal.id === exact.id)");
    expect(dealRoomSource).toContain("Partial ownership scan: My rooms covers only loaded pages.");
    expect(dealRoomSource).toContain("Load every older page before treating this result as complete.");
    expect(dealRoomSource).toContain("Complete ownership scan for the snapshot at block");
  });

  it("persists one public exact create intent before prompting and retains a hash before receipt polling", () => {
    expect(dealRoomSource).toContain("const intent = createDealCreationIntent({");
    for (const field of [
      "account,",
      "chainId: baseSepolia.id",
      "releaseSha,",
      "contract,",
      "artifactHash: hash",
      "reservePrice,",
      "expiry,",
      "teeIdentity: tee",
      "paymentToken: token",
      "startBlock: await publicClient.getBlockNumber()",
    ]) expect(dealRoomSource).toContain(field);
    expect(dealRoomSource).toContain("persistDealCreationRecovery(recovery, true)");
    expect(dealRoomSource).toContain("window.localStorage.setItem(");
    expect(dealRoomSource).toContain("encodeDealCreationRecovery(normalized)");
    expect(dealRoomSource.indexOf("hooks?.onBroadcast?.(hash)")).toBeLessThan(
      dealRoomSource.indexOf("await publicClient.waitForTransactionReceipt({ hash })"),
    );
    expect(dealRoomSource).toContain("hash: broadcastHash");
  });

  it("reconciles ambiguous creation and permits retry only after a proven no-broadcast or revert outcome", () => {
    expect(dealRoomSource).toContain("reconcileDealCreation(recovery)");
    expect(dealRoomSource).toContain("result.transactionHash && !recovery.transactionHash");
    expect(dealRoomSource).toContain("createDealCreationRecovery(recovery.intent, result.transactionHash)");
    expect(dealRoomSource).toContain('return status === "reverted" || status === "not_broadcast"');
    expect(dealRoomSource).toContain("No retry is permitted until the browser reconciles");
    expect(dealRoomSource).toContain("Recovery clears only after {DEAL_CREATION_CONFIRMATION_DEPTH.toString()} canonical confirmations.");
    expect(dealRoomSource).toContain("same-RPC depth check, not consensus finality");
    expect(dealRoomSource).toContain("Retry same expiry + intent");
    expect(dealRoomSource).toContain("const exactRetry = createDealCreationRecovery(recovery.intent)");
    expect(dealRoomSource).toContain("recovery.intent.expiry <= BigInt");
    expect(dealRoomSource).toContain("Discard this resolved attempt explicitly before drafting a new expiry.");
    expect(dealRoomSource).toContain("assertDealCreationIntentContext(intent");
  });

  it("states the reload boundary and never persists private artifact recovery material", () => {
    expect(dealRoomSource).toContain("Reload restored only public intent metadata.");
    expect(dealRoomSource).toContain("It did not store the private file, salt, recovery receipt, ciphertext, wallet credentials, or a tab-local no-broadcast classification.");
    expect(dealRoomSource).toContain("A hashless reload stays blocked unless one exact log appears.");
    const persistedRegion = dealRoomSource.slice(
      dealRoomSource.indexOf("const persistDealCreationRecovery"),
      dealRoomSource.indexOf("const clearDealCreationRecovery"),
    );
    expect(persistedRegion).not.toMatch(/artifactReceipt|ArtifactRecoveryReceipt|uploadFile|ciphertext/i);
  });
});
