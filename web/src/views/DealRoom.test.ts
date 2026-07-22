import { describe, expect, it } from "vitest";
import {
  DealRoomOperationLock,
  dealRoomDraftMutationIsAllowed,
  runDealRoomOperation,
  type DealRoomOperationLease,
} from "../lib/dealRoomOperation";
import dealRoomSource from "./DealRoom.tsx?raw";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("Deal Room exclusive operations", () => {
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
    expect(dealRoomSource).toContain("const creationDraftIsAllowed = () => writesReady() && draftMutationIsAllowed()");
    expect(dealRoomSource).toContain("const creationLocked = () => !writesReady() || mutationLocked()");
    expect(dealRoomSource).toContain('disabled={creationLocked()} onClick={() => {\n          if (creationDraftIsAllowed()) setShowCreate(!showCreate());');
    expect(dealRoomSource).toContain('{writesReady() ? "Create room" : "Room creation locked"}');
    expect(dealRoomSource).toContain('type="file" disabled={creationLocked()}');
    expect(dealRoomSource).toContain("No private artifact selector is enabled in this state.");
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
});
