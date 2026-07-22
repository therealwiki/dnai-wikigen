import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  FileSearch,
  Fingerprint,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldCheck,
  XCircle,
} from "lucide-solid";
import { zeroAddress, zeroHash } from "viem";
import { deployment, explorerAddress } from "../config";
import { shortAddress } from "../lib/contract";
import {
  loadTinkerEncumbranceObservation,
  normalizeTinkerOperationId,
  TINKER_OPERATION_KIND,
  type TinkerEncumbranceObservation,
  type TinkerPolicyPhase,
} from "../lib/tinkerEncumbrance";

type ReadState = "unconfigured" | "idle" | "loading" | "observed" | "blocked" | "error";

const PHASE_LABELS: Readonly<Record<TinkerPolicyPhase, string>> = {
  draft_halted: "Constructor draft · halted",
  pending_review: "Policy pending review",
  frozen_active: "Frozen policy · operations permitted",
  frozen_halted: "Frozen policy · emergency halted",
  unfrozen_unhalted: "Unsafe state · fail closed",
};

function exactPolicyUnits(value: bigint | undefined): string {
  return value === undefined ? "—" : value.toString();
}

function pendingActivation(value: bigint | undefined): string {
  if (!value) return "No proposal staged";
  const milliseconds = value * 1_000n;
  if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) return `Unix ${value.toString()}`;
  return `${new Date(Number(milliseconds)).toISOString()} · Unix ${value.toString()}`;
}

function pendingPolicyDetected(value: TinkerEncumbranceObservation): boolean {
  return Boolean(
    value.pendingReleasePolicyActivatesAt
    || value.pendingComposeCount
    || value.pendingManagerCount
    || (value.pendingReleasePolicyCommitment && value.pendingReleasePolicyCommitment.toLowerCase() !== zeroHash),
  );
}

function BooleanFact(props: {
  label: string;
  value: boolean;
  trueLabel: string;
  falseLabel: string;
  trueIsSafe?: boolean;
}) {
  const passes = () => props.value === (props.trueIsSafe ?? true);
  return (
    <div class={`tinker-policy-fact ${passes() ? "pass" : "fail"}`}>
      {passes() ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
      <span><small>{props.label}</small><strong>{props.value ? props.trueLabel : props.falseLabel}</strong></span>
    </div>
  );
}

export function TinkerPolicyStatus() {
  const configured = Boolean(
    deployment.encumbranceAddress
    && deployment.encumbranceAddress.toLowerCase() !== zeroAddress
    && deployment.encumbranceCodeHash
    && deployment.encumbranceCodeHash.toLowerCase() !== zeroHash,
  );
  const [readState, setReadState] = createSignal<ReadState>(configured ? "idle" : "unconfigured");
  const [message, setMessage] = createSignal(
    configured
      ? "No pinned Base Sepolia observation has been requested yet."
      : "Both the contract address and exact runtime code-hash pin are required before any policy field is queried.",
  );
  const [observation, setObservation] = createSignal<TinkerEncumbranceObservation>();
  const [operationInput, setOperationInput] = createSignal("");
  let requestGeneration = 0;

  const operationValidation = createMemo(() => {
    if (!operationInput().trim()) return "Enter one exact nonzero bytes32 operation ID";
    try {
      normalizeTinkerOperationId(operationInput());
      return undefined;
    } catch (error) {
      return error instanceof Error ? error.message : "Operation ID is invalid";
    }
  });

  async function observe(operationId?: string): Promise<void> {
    if (!configured) return;
    const generation = ++requestGeneration;
    setReadState("loading");
    setMessage("Verifying runtime bytecode, then reading policy fields at one pinned Base Sepolia block…");
    try {
      const next = await loadTinkerEncumbranceObservation(operationId);
      if (generation !== requestGeneration) return;
      setObservation(next);
      if (!next.runtimeVerified) {
        setReadState("blocked");
        setMessage(next.issues[0] ?? "Runtime identity could not be verified against the release pin.");
        return;
      }
      setReadState("observed");
      setMessage(
        next.issues.length
          ? `Runtime matched, but ${next.issues.length} on-chain policy condition${next.issues.length === 1 ? " requires" : "s require"} attention.`
          : "Runtime and frozen policy state were read successfully. This is a single-RPC contract observation, not proof of Tinker or CVM execution.",
      );
    } catch (error) {
      if (generation !== requestGeneration) return;
      setReadState("error");
      setMessage(error instanceof Error ? error.message : "Tinker policy observation failed");
    }
  }

  function lookupOperation(): void {
    if (operationValidation() || readState() === "loading") return;
    void observe(operationInput().trim());
  }

  onMount(() => {
    if (configured) void observe();
  });

  const statusTitle = (): string => {
    if (readState() === "loading") return "Reading one pinned block";
    if (readState() === "observed") return observation()?.phase ? PHASE_LABELS[observation()!.phase!] : "Policy observed";
    if (readState() === "blocked") return "Runtime verification blocked";
    if (readState() === "error") return "Observation rejected";
    if (readState() === "unconfigured") return "Release configuration absent";
    return "Live policy read pending";
  };

  return (
    <section class="tinker-chain-policy" aria-labelledby="tinker-chain-policy-title">
      <div class="tinker-chain-policy-head">
        <div>
          <p class="overline">Read-only chain inspector · TinkerAccountEncumbrance</p>
          <h2 id="tinker-chain-policy-title">See exactly what the contract can authorize.</h2>
          <p>
            The browser first checks the release-pinned runtime bytecode, then reads the active, frozen-baseline, and pending policy tuples from one Base Sepolia block. It never writes to the contract.
          </p>
        </div>
        <div class="tinker-chain-policy-actions">
          <span class={`tinker-chain-mode ${observation()?.runtimeVerified ? "observed" : "blocked"}`}>
            {observation()?.runtimeVerified ? "LIVE READ · SINGLE RPC" : readState() === "loading" || readState() === "idle" ? "LIVE READ · PENDING" : "LIVE READ PATH · BLOCKED"}
          </span>
          <span class="tinker-chain-mode modeled">PRODUCT FLOW · MODELED</span>
          <span class="read-only-chip"><LockKeyhole size={13} /> READ ONLY</span>
          <button
            class="icon-button"
            type="button"
            aria-label="Refresh Tinker contract policy"
            aria-controls="tinker-chain-policy-status"
            aria-busy={readState() === "loading"}
            disabled={!configured || readState() === "loading"}
            onClick={() => void observe()}
          >
            <RefreshCw class={readState() === "loading" ? "spin" : ""} size={16} />
          </button>
        </div>
      </div>

      <div id="tinker-chain-policy-status" class={`tinker-chain-status ${readState()}`} role="status" aria-live="polite" aria-atomic="true">
        {readState() === "observed"
          ? <ShieldCheck size={22} />
          : readState() === "loading" || readState() === "idle"
            ? <Fingerprint size={22} />
            : <AlertTriangle size={22} />}
        <div><strong>{statusTitle()}</strong><span>{message()}</span></div>
      </div>

      <div class="tinker-chain-release-id">
        <div>
          <small>CONTRACT</small>
          <Show when={deployment.encumbranceAddress} fallback={<strong>Not release configured</strong>}>
            {(address) => <a href={explorerAddress(address())} target="_blank" rel="noreferrer"><code>{address()}</code><ExternalLink size={12} /></a>}
          </Show>
        </div>
        <div><small>RELEASE RUNTIME PIN</small><code>{deployment.encumbranceCodeHash ?? "Not release pinned"}</code></div>
        <div><small>OBSERVED RUNTIME</small><code>{observation()?.observedCodeHash ?? "No verified observation"}</code></div>
      </div>

      <Show when={observation()?.runtimeVerified && observation()} keyed>
        {(value) => (
          <div class="tinker-chain-observation">
            <div class="tinker-chain-block-pin">
              <Fingerprint size={16} />
              <span><small>RPC-REPORTED FINALIZED BASE SEPOLIA OBSERVATION</small><strong>Block {value.blockNumber?.toString()}</strong><code title={value.blockHash}>{shortAddress(value.blockHash ?? "", 8)} · {value.phase ? PHASE_LABELS[value.phase] : "Unknown policy phase"}</code></span>
            </div>

            <div class="tinker-policy-facts">
              <BooleanFact label="RUNTIME PIN" value={value.runtimeVerified} trueLabel="Exact match" falseLabel="Mismatch" />
              <BooleanFact label="RELEASE POLICY" value={Boolean(value.releasePolicyFrozen)} trueLabel="Permanently frozen" falseLabel="Not frozen" />
              <BooleanFact label="EMERGENCY STATE" value={Boolean(value.emergencyHalted)} trueLabel="Halted" falseLabel="Not halted" trueIsSafe={false} />
              <BooleanFact label="PENDING POLICY" value={pendingPolicyDetected(value)} trueLabel="Review staged" falseLabel="None staged" trueIsSafe={false} />
            </div>

            <div class="tinker-policy-detail-grid">
              <article>
                <div class="tinker-policy-detail-head"><Fingerprint size={17} /><span><small>ACCOUNT + GOVERNANCE</small><strong>Public commitments, never credentials</strong></span></div>
                <dl>
                  <div><dt>Owner</dt><dd><code>{shortAddress(value.owner ?? "", 8)}</code></dd></div>
                  <div><dt>Pending owner</dt><dd><strong>{value.pendingOwner === "0x0000000000000000000000000000000000000000" ? "None" : shortAddress(value.pendingOwner ?? "", 8)}</strong></dd></div>
                  <div><dt>Account commitment</dt><dd><code title={value.accountCommitment}>{value.accountCommitment}</code></dd></div>
                  <div><dt>Release policy commitment</dt><dd><code title={value.releasePolicyCommitment}>{value.releasePolicyCommitment}</code></dd></div>
                </dl>
              </article>

              <article>
                <div class="tinker-policy-detail-head"><ShieldCheck size={17} /><span><small>CURRENT AUTHORITY</small><strong>Revocable subset after release freeze</strong></span></div>
                <dl>
                  <div><dt>Add-balance cap</dt><dd><code>{exactPolicyUnits(value.maxAddBalancePolicyUnits)}</code><span>unitless · per operation</span></dd></div>
                  <div><dt>Spend cap</dt><dd><code>{exactPolicyUnits(value.maxSpendPolicyUnits)}</code><span>unitless · per operation</span></dd></div>
                  <div><dt>Compose root / count</dt><dd><code title={value.approvedComposeRoot}>{shortAddress(value.approvedComposeRoot ?? "", 8)}</code><span>{value.approvedComposeCount?.toString()} active</span></dd></div>
                  <div><dt>Manager root / count</dt><dd><code title={value.managerRoot}>{shortAddress(value.managerRoot ?? "", 8)}</code><span>{value.managerCount?.toString()} active</span></dd></div>
                </dl>
              </article>

              <article>
                <div class="tinker-policy-detail-head"><LockKeyhole size={17} /><span><small>FROZEN BASELINE</small><strong>Original maximum authority envelope</strong></span></div>
                <dl>
                  <div><dt>Release add cap</dt><dd><code>{exactPolicyUnits(value.releaseMaxAddBalancePolicyUnits)}</code><span>unitless · not ETH</span></dd></div>
                  <div><dt>Release spend cap</dt><dd><code>{exactPolicyUnits(value.releaseMaxSpendPolicyUnits)}</code><span>not a cumulative budget</span></dd></div>
                  <div><dt>Release compose root / count</dt><dd><code title={value.releaseComposeRoot}>{shortAddress(value.releaseComposeRoot ?? "", 8)}</code><span>{value.releaseComposeCount?.toString()} frozen</span></dd></div>
                  <div><dt>Release manager root / count</dt><dd><code title={value.releaseManagerRoot}>{shortAddress(value.releaseManagerRoot ?? "", 8)}</code><span>{value.releaseManagerCount?.toString()} frozen</span></dd></div>
                </dl>
              </article>

              <article class={pendingPolicyDetected(value) ? "pending" : "clear"}>
                <div class="tinker-policy-detail-head"><AlertTriangle size={17} /><span><small>PENDING REVIEW</small><strong>{pendingPolicyDetected(value) ? "Staged policy detected" : "No staged release policy"}</strong></span></div>
                <dl>
                  <div><dt>Activation</dt><dd><strong>{pendingActivation(value.pendingReleasePolicyActivatesAt)}</strong></dd></div>
                  <div><dt>Pending account</dt><dd><code title={value.pendingAccountCommitment}>{shortAddress(value.pendingAccountCommitment ?? "", 8)}</code></dd></div>
                  <div><dt>Pending caps</dt><dd><code>{exactPolicyUnits(value.pendingMaxAddBalancePolicyUnits)} / {exactPolicyUnits(value.pendingMaxSpendPolicyUnits)}</code><span>add / spend policy units</span></dd></div>
                  <div><dt>Compose / manager</dt><dd><code title={`${value.pendingComposeRoot} · ${value.pendingManagerRoot}`}>{shortAddress(value.pendingComposeRoot ?? "", 6)} / {shortAddress(value.pendingManagerRoot ?? "", 6)}</code><span>{value.pendingComposeCount?.toString()} / {value.pendingManagerCount?.toString()} pending</span></dd></div>
                </dl>
              </article>
            </div>

            <Show when={value.issues.length > 0}>
              <div class="tinker-policy-issues">
                <div><AlertTriangle size={16} /><strong>Fail-closed policy notes</strong></div>
                <ul><For each={value.issues}>{(issue) => <li>{issue}</li>}</For></ul>
              </div>
            </Show>
          </div>
        )}
      </Show>

      <div class="tinker-operation-lookup">
        <div class="tinker-operation-lookup-copy">
          <FileSearch size={18} />
          <div><small>EXACT OPERATION LOOKUP</small><strong>Inspect one public audit record.</strong><span>Only one nonzero bytes32 ID is accepted. The lookup is pinned to the same block as the policy read and never authorizes or settles an operation.</span></div>
        </div>
        <div class="tinker-operation-form">
          <label for="tinker-operation-id">Operation ID</label>
          <div>
            <input
              id="tinker-operation-id"
              name="tinker-operation-id"
              type="text"
              inputmode="text"
              autocomplete="off"
              spellcheck={false}
              maxlength="66"
              placeholder="0x…64 hex characters"
              value={operationInput()}
              aria-describedby="tinker-operation-help"
              onInput={(event) => setOperationInput(event.currentTarget.value)}
              onKeyDown={(event) => { if (event.key === "Enter") lookupOperation(); }}
            />
            <button class="secondary-button" type="button" disabled={!configured || Boolean(operationValidation()) || readState() === "loading"} onClick={lookupOperation}>
              <Search size={14} /> {readState() === "loading" ? "Reading…" : "Inspect at pinned block"}
            </button>
          </div>
          <span id="tinker-operation-help">{operationValidation()}</span>
        </div>

        <Show when={observation()?.operation} keyed>
          {(operation) => (
            <div class={`tinker-operation-result ${operation.found ? "found" : "missing"}`}>
              {operation.found ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
              <div>
                <small>{operation.found ? "RECORD FOUND" : "NO RECORD AT PINNED BLOCK"}</small>
                <strong><code>{operation.operationId}</code></strong>
                <Show when={operation.found}>
                  <dl>
                    <div><dt>Kind</dt><dd>{TINKER_OPERATION_KIND[operation.kind ?? -1] ?? `Unsupported enum ${operation.kind}`}</dd></div>
                    <div><dt>Requester</dt><dd><code>{operation.requester}</code></dd></div>
                    <div><dt>Authorizer</dt><dd><code>{operation.authorizer}</code></dd></div>
                    <div><dt>Compose</dt><dd><code>{operation.composeHash}</code></dd></div>
                    <div><dt>Amount</dt><dd><code>{exactPolicyUnits(operation.amountPolicyUnits)}</code><span>unitless legacy policy units</span></dd></div>
                    <div><dt>Settlement</dt><dd>{operation.settled ? operation.success ? "Settled · success" : "Settled · failed" : "Not settled"}</dd></div>
                    <div><dt>Receipt commitment</dt><dd><code>{operation.receiptHash}</code></dd></div>
                  </dl>
                </Show>
                <Show when={!operation.found}><span>The contract reverted with <code>UnknownOperation</code> for this exact ID at block {observation()?.blockNumber?.toString()}.</span></Show>
              </div>
            </div>
          )}
        </Show>
      </div>

      <div class="tinker-chain-boundary">
        <AlertTriangle size={16} />
        <p><strong>Contract boundary</strong><code>TinkerAccountEncumbrance</code> does not custody funds, payment cards, provider balances, account credentials, or Tinker project IDs—and it does not execute a Tinker operation. It records bounded policy authorization and settlement commitments. A matching browser read is not a CVM health check, TDX quote, QVL verdict, provider receipt, or proof that Wikigen owns the configured deployment.</p>
      </div>
    </section>
  );
}
