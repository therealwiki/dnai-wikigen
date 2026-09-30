import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { computeWorkloadDeployment, deployment } from "../config";
import type { CollaborationExecutionPlanRequest, CollaborationJointRun, CollaborationRoom } from "../lib/collaboration";
import {
  assertComputeCollaborationDraftContext,
  currentComputeCollaborationWorkloadDraft,
  parseComputeCollaborationWorkloadDraft,
  refreshCollaborationExecutionPlanRequest,
  validateCollaborationExecutionFundingDraft,
  type CollaborationExecutionFundingDraft,
  type ComputeCollaborationWorkloadDraft,
} from "../lib/computeCollaborationHandoff";
import { wallet } from "../lib/wallet";
import { canonicalHashForComputeTab } from "../routes";

export interface PreparedCollaborationComputePlan {
  readonly request: CollaborationExecutionPlanRequest;
  /** Rechecks current public facts; never signs or sends a mutation. */
  readonly verifyCurrent: () => Promise<void>;
}

export function CollaborateComputePlanBuilder(props: {
  room?: CollaborationRoom;
  jointRun?: CollaborationJointRun;
  enabled: boolean;
  workflowBusy: boolean;
  locked: boolean;
  onPrepared: (value: PreparedCollaborationComputePlan | undefined) => void;
}) {
  const existing = currentComputeCollaborationWorkloadDraft();
  const [json, setJson] = createSignal(existing ? JSON.stringify(existing, null, 2) : "");
  const [draft, setDraft] = createSignal<ComputeCollaborationWorkloadDraft>();
  const [funding, setFunding] = createSignal<CollaborationExecutionFundingDraft>({
    jobReference: "", assetKind: "native", computeCapBaseUnits: "", royaltyBaseUnits: "",
    allInCapBaseUnits: "", lifetimeSeconds: "1800",
  });
  const [busy, setBusy] = createSignal(false);
  const [message, setMessage] = createSignal("Import a public workload draft, then choose your exact-asset limits. No transaction is sent during preparation.");
  const [error, setError] = createSignal(false);
  const [ready, setReady] = createSignal(false);
  let revision = 0;
  let disposed = false;
  let readSession: { token: string; expiresAt: number; address: string; version: number } | undefined;
  onCleanup(() => { disposed = true; revision += 1; readSession = undefined; });
  createEffect(() => {
    wallet.account(); wallet.authorizationVersion(); wallet.chainId();
    readSession = undefined;
    revision += 1;
    setReady(false);
    if (!props.locked) props.onPrepared(undefined);
  });

  function changed(): void {
    revision += 1;
    setReady(false);
    setDraft(undefined);
    props.onPrepared(undefined);
  }

  function update(key: keyof CollaborationExecutionFundingDraft, value: string): void {
    if (props.locked || busy() || props.workflowBusy) return;
    changed();
    setFunding(current => ({ ...current, [key]: value }));
  }

  async function prepare(): Promise<void> {
    if (props.locked || busy() || props.workflowBusy || !props.enabled) return;
    const generation = ++revision;
    const account = wallet.account();
    const version = wallet.authorizationVersion();
    const room = props.room;
    const jointRun = props.jointRun;
    const source = json();
    const selectedFunding = { ...funding() };
    setBusy(true); setError(false); setReady(false); props.onPrepared(undefined);
    const assertCurrent = () => {
      if (disposed || revision !== generation || wallet.authorizationVersion() !== version
        || wallet.account() !== account || !wallet.isCorrectChain() || props.room !== room || props.jointRun !== jointRun
        || props.locked || !props.enabled) throw new Error("Wallet, project draft, room, chain or release context changed; prepare the request again");
    };
    try {
      if (!account || !room || !jointRun || !computeWorkloadDeployment.trustPolicy) throw new Error("A current sponsor wallet, joint-consent snapshot and configured workload recipient are required");
      if (source.length > 16384) throw new Error("Public workload draft exceeds its bounded size");
      const parsed = parseComputeCollaborationWorkloadDraft(JSON.parse(source));
      assertComputeCollaborationDraftContext(parsed, { walletAddress: account, delegateUrl: deployment.delegateUrl, releaseSha: deployment.releaseSha, chainId: wallet.chainId() });
      if (jointRun.requester_address !== parsed.wallet_address) throw new Error("The Compute funding wallet must be the current joint-consent requester");
      validateCollaborationExecutionFundingDraft(selectedFunding, room.owners.map(owner => owner.allocation_bps));
      assertCurrent();
      setMessage("Authorize a short-lived Compute console session. This step only rechecks project and workload records; it does not send a funding transaction.");
      if (!readSession || readSession.address !== account.toLowerCase() || readSession.version !== version || Date.now() >= readSession.expiresAt - 5000) {
        const response = await wallet.authorizeComputeConsole();
        assertCurrent();
        if (response.address.toLowerCase() !== account.toLowerCase()) throw new Error("Compute read session belongs to a different wallet");
        readSession = { token: response.access_token, expiresAt: response.expires_at * 1000, address: account.toLowerCase(), version };
      }
      const session = readSession;
      const verifyAndBuild = async () => {
        assertCurrent();
        if (readSession !== session || Date.now() >= session.expiresAt - 5000) throw new Error("Compute read session expired; prepare and verify the workload again");
        return refreshCollaborationExecutionPlanRequest({ draft: parsed, funding: selectedFunding,
          ownerAllocationBps: room.owners.map(owner => owner.allocation_bps), token: session.token,
          trustPolicy: computeWorkloadDeployment.trustPolicy!, walletAdoptionEnabled: deployment.collaborationExecutionRelease.walletAdoptionEnabled, assertCurrent });
      };
      const request = await verifyAndBuild();
      assertCurrent();
      props.onPrepared({ request, verifyCurrent: async () => {
        const fresh = await verifyAndBuild();
        if (JSON.stringify(fresh) !== JSON.stringify(request)) throw new Error("Vault nonce, asset or funding terms changed; prepare a fresh plan before asking owners to sign");
      } });
      setDraft(parsed); setReady(true);
      setMessage("Verified public workload and exact request ready. Create the plan next; fresh owner grants and a separate one-shot Compute vault authorization are still required.");
    } catch (cause) {
      if (disposed || revision !== generation) return;
      setError(true); setMessage(cause instanceof Error ? cause.message : "Public workload preparation failed closed");
    } finally {
      if (!disposed) setBusy(false);
    }
  }

  return <div class="collaboration-compute-builder">
    <p>Start in <a href={canonicalHashForComputeTab("workloads")}>Compute → Workloads</a> and prepare a public Collaboration draft. Imported JSON is untrusted until the authenticated project, workload recipient and pinned vault are rechecked.</p>
    <fieldset disabled={props.locked || busy() || props.workflowBusy}>
      <label for="collaboration-compute-packet"><span>PUBLIC WORKLOAD DRAFT · NO TOKENS OR PRIVATE INPUTS</span><textarea id="collaboration-compute-packet" value={json()} onInput={event => { changed(); setJson(event.currentTarget.value); }} rows={5} spellcheck={false} placeholder="Paste the public workload draft from Compute" /></label>
      <div class="collaboration-funding-fields">
        <label><span>NEW JOB REFERENCE</span><input value={funding().jobReference} maxLength={128} placeholder="joint-analysis-001" onInput={event => update("jobReference", event.currentTarget.value)} /></label>
        <label><span>EXACT ASSET</span><select value={funding().assetKind} onChange={event => update("assetKind", event.currentTarget.value)}><option value="native">ETH · wei</option><option value="erc20">Pinned ERC20 · base units</option></select></label>
        <label><span>COMPUTE CAP · BASE UNITS</span><input inputmode="numeric" value={funding().computeCapBaseUnits} placeholder="Maximum Compute debit" onInput={event => update("computeCapBaseUnits", event.currentTarget.value)} /></label>
        <label><span>OWNER ROYALTY · BASE UNITS</span><input inputmode="numeric" value={funding().royaltyBaseUnits} placeholder="Exact owner payout total" onInput={event => update("royaltyBaseUnits", event.currentTarget.value)} /></label>
        <label><span>ALL-IN CAP · BASE UNITS</span><input inputmode="numeric" value={funding().allInCapBaseUnits} placeholder="Compute cap + royalty or more" onInput={event => update("allInCapBaseUnits", event.currentTarget.value)} /></label>
        <label><span>PLAN LIFETIME · SECONDS</span><input inputmode="numeric" value={funding().lifetimeSeconds} onInput={event => update("lifetimeSeconds", event.currentTarget.value)} /></label>
      </div>
      <p>Amounts stay in the selected asset, not credits. ETH uses wei (10¹⁸ wei = 1 ETH). Exact request integers are limited to 9,007,199,254,740,991; values are never rounded. Lifetime is 60–3,600 seconds and includes owner signing and chain finality. Fund Compute capacity separately before preparing.</p>
      <button class="secondary-button" type="button" disabled={!props.enabled || !json().trim()} onClick={() => void prepare()}>{busy() ? "Verifying project, custody and vault…" : "Verify workload & prepare exact terms"}</button>
    </fieldset>
    <p class={error() ? "form-error" : "modeled-note"} role={error() ? "alert" : "status"}>{message()}</p>
    <Show when={ready() && draft()}><p><strong>Prepared:</strong> {draft()!.project_reference} · {draft()!.workload.operation} · {draft()!.workload.execution_binding.source_kind} source. No standalone authorization will be reused.</p></Show>
  </div>;
}
