import { createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  Clock3,
  FileJson,
  Fingerprint,
  FlaskConical,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Radio,
  RefreshCw,
  ScanSearch,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  UserRoundCheck,
  WalletCards,
} from "lucide-solid";
import { Simulator } from "../components/Simulator";
import type { RouteKey } from "../components/AppShell";
import { deployment } from "../config";
import {
  EXECUTION_POLICY_SURFACES,
  parsePolicyBundleText,
  readExecutionPolicyStatus,
  runExecutionPolicyWorkflow,
  type ExecutionPolicyStatus,
  type ExecutionPolicySurface,
  type ExecutionPolicyWorkflowResult,
} from "../lib/policy";
import { fetchComputeExecutionPolicyTarget } from "../lib/compute";
import { wallet } from "../lib/wallet";

const STAGES = [
  {
    n: "01",
    title: "Identity & authority",
    copy: "Bind the principal, role, assurance tier, and consent grant before a corpus is even addressable.",
    icon: UserRoundCheck,
  },
  {
    n: "02",
    title: "Purpose policy",
    copy: "Match the declared use and evidence against the owner's allowlist; ambiguity stops for review.",
    icon: ScanSearch,
  },
  {
    n: "03",
    title: "Safety screen",
    copy: "Deny restricted categories before inference and emit a bounded stop record without operational detail.",
    icon: ShieldAlert,
  },
  {
    n: "04",
    title: "Execution policy check",
    copy: "The browser model checks the pipeline allowlist. A deployed runtime must separately enforce resource caps, egress, and the declared output shape.",
    icon: LockKeyhole,
  },
];

const SURFACES = [
  {
    key: "deal_evaluation",
    index: "01",
    title: "Deal evaluation",
    description: "Approve one bounded evaluator run against a diligence-room resource.",
    placeholder: "deal reference",
    icon: ScanSearch,
  },
  {
    key: "arena_execution",
    index: "02",
    title: "Arena execution",
    description: "Bind a challenge candidate to its exact policy and execution window.",
    placeholder: "submission reference",
    icon: Activity,
  },
  {
    key: "compute_dispatch",
    index: "03",
    title: "Compute dispatch",
    description: "Gate a wallet-authenticated exact-asset intent; service-credit jobs are not supported here.",
    placeholder: "job reference",
    icon: ServerCog,
  },
] as const;

type OperatorPhase = "idle" | "preflight" | "approval" | "signing" | "persisting" | "complete";

export function executionPolicyOperatorReady(input: {
  delegateConfigured: boolean;
  approvalDomainPinned: boolean;
  approverSetPinned: boolean;
  monotonicAnchorPinned: boolean;
  walletConnected: boolean;
  walletOnBaseSepolia: boolean;
}): boolean {
  return input.delegateConfigured
    && input.approvalDomainPinned
    && input.approverSetPinned
    && input.monotonicAnchorPinned
    && input.walletConnected
    && input.walletOnBaseSepolia;
}

function compactHash(value: string): string {
  return value.length > 28 ? `${value.slice(0, 14)}…${value.slice(-10)}` : value;
}

function timestamp(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value * 1000));
}

function HashFact(props: { label: string; value: string | undefined }) {
  return (
    <Show when={props.value}>
      <div class="policy-hash-fact">
        <span>{props.label}</span>
        <code title={props.value}>{compactHash(props.value ?? "")}</code>
      </div>
    </Show>
  );
}

function BoundedStatus(props: { status: ExecutionPolicyStatus }) {
  return (
    <div class="policy-status-result" role="status" aria-live="polite">
      <div class="policy-status-head">
        <span class={`policy-decision ${props.status.current_pass ? "pass" : props.status.found ? props.status.record?.decision : "none"}`}>
          {props.status.current_pass ? <CheckCircle2 size={14} /> : <CircleAlert size={14} />}
          {props.status.current_pass ? "CURRENT PASS" : props.status.found ? `${props.status.record?.decision.toUpperCase()} RECORDED` : "NO RECORD"}
        </span>
        <span class="bounded-only"><LockKeyhole size={12} /> bounded readback</span>
      </div>
      <HashFact label="RESOURCE HASH" value={props.status.resource_id_hash} />
      <HashFact label="ANCHOR HEAD" value={props.status.rollback_anchor.global_head} />
      <div class="policy-status-meta">
        <span><small>ANCHOR BLOCK</small><strong>{props.status.rollback_anchor.block_number}</strong></span>
        <span><small>GLOBAL SEQUENCE</small><strong>{props.status.rollback_anchor.global_sequence}</strong></span>
        <span><small>OBSERVED DEPTH</small><strong>{props.status.rollback_anchor.observed_confirmation_depth} BLOCKS</strong></span>
        <span><small>RPC FINALIZED HEAD</small><strong>{props.status.rollback_anchor.rpc_finalized_block_number}</strong></span>
        <span><small>VERIFICATION MODEL</small><strong>SINGLE RPC · NO QUORUM</strong></span>
      </div>
      <Show when={props.status.record} keyed>
        {(record) => (
          <>
            <HashFact label="DECISION HASH" value={record.decision_hash} />
            <div class="policy-status-meta">
              <span><small>REASON</small><strong>{record.reason_code.replaceAll("_", " ")}</strong></span>
              <span><small>RECORDED</small><strong>{timestamp(record.recorded_at)}</strong></span>
              <span><small>EXPIRES</small><strong>{timestamp(record.expires_at)}</strong></span>
            </div>
          </>
        )}
      </Show>
    </div>
  );
}

export function SafeguardsLab(props: { navigate: (route: RouteKey) => void }) {
  const [surface, setSurface] = createSignal<ExecutionPolicySurface>(EXECUTION_POLICY_SURFACES[0]);
  const [resourceReference, setResourceReference] = createSignal("");
  const [statusReference, setStatusReference] = createSignal("");
  const [computeProjectReference, setComputeProjectReference] = createSignal("");
  const [computeStatusProjectReference, setComputeStatusProjectReference] = createSignal("");
  const [runtimeBearer, setRuntimeBearer] = createSignal("");
  const [ttlSeconds, setTtlSeconds] = createSignal(900);
  const [bundleReady, setBundleReady] = createSignal(false);
  const [busy, setBusy] = createSignal<"" | "evaluate" | "status">("");
  const [phase, setPhase] = createSignal<OperatorPhase>("idle");
  const [error, setError] = createSignal("");
  const [workflow, setWorkflow] = createSignal<ExecutionPolicyWorkflowResult>();
  const [statusResult, setStatusResult] = createSignal<ExecutionPolicyStatus>();

  let transientBundle: File | undefined;
  let bundleInput: HTMLInputElement | undefined;

  const selectedSurface = createMemo(() => SURFACES.find((item) => item.key === surface()) ?? SURFACES[0]);
  const delegateConfigured = createMemo(() => Boolean(deployment.delegateUrl));
  const approvalDomainPinned = createMemo(() => Boolean(deployment.executionPolicyApprovalDomainHash));
  const approverSetPinned = createMemo(() => Boolean(
    deployment.executionPolicyApproverRootHash
    && deployment.executionPolicyApprovedApproverHashes,
  ));
  const monotonicAnchorPinned = createMemo(() => Boolean(deployment.executionPolicyAnchorRelease));
  const walletConnected = createMemo(() => Boolean(wallet.account()));
  const walletOnBaseSepolia = createMemo(() => wallet.isCorrectChain());
  const liveReady = createMemo(() => executionPolicyOperatorReady({
    delegateConfigured: delegateConfigured(),
    approvalDomainPinned: approvalDomainPinned(),
    approverSetPinned: approverSetPinned(),
    monotonicAnchorPinned: monotonicAnchorPinned(),
    walletConnected: walletConnected(),
    walletOnBaseSepolia: walletOnBaseSepolia(),
  }));
  const phaseLabel = createMemo(() => ({
    idle: "Waiting for a transient policy bundle",
    preflight: "Validating strict request and policy fields locally",
    approval: "Requesting the delegate's canonical bounded decision",
    signing: "Wallet consent required for this PASS decision",
    persisting: "Persisting the signed execution binding and reading it back",
    complete: "Bounded decision persisted and independently read back",
  }[phase()]));

  function clearTransientBundle(): void {
    transientBundle = undefined;
    setBundleReady(false);
    if (bundleInput) bundleInput.value = "";
  }

  function selectBundle(file: File | undefined): void {
    transientBundle = file;
    setBundleReady(Boolean(file));
    setError("");
  }

  async function resolveExecutionTarget(
    privateReference: string,
    projectReference: string,
  ): Promise<{ resourceId: string; executionContextHash?: string }> {
    if (surface() !== "compute_dispatch") {
      return { resourceId: privateReference };
    }
    if (!projectReference) {
      throw new Error(
        "Enter the Compute project reference used by the exact-asset dispatch intent.",
      );
    }
    let transientComputeToken = "";
    try {
      const authorization = await wallet.authorizeComputeConsole();
      transientComputeToken = authorization.access_token;
      const target = await fetchComputeExecutionPolicyTarget(
        transientComputeToken,
        projectReference,
        privateReference,
        authorization.address,
      );
      const currentWallet = wallet.account()?.toLowerCase() ?? "";
      if (
        !wallet.isCorrectChain()
        || authorization.address.toLowerCase() !== currentWallet
        || target.authorizedUser.toLowerCase() !== currentWallet
      ) {
        throw new Error(
          "Authenticated Compute intent is not owned by the connected Base Sepolia wallet.",
        );
      }
      return {
        resourceId: target.resourceId,
        executionContextHash: target.executionContextHash,
      };
    } finally {
      // JavaScript strings cannot be zeroized, so never persist the token in
      // reactive state and drop the sole local reference immediately.
      transientComputeToken = "";
    }
  }

  async function evaluatePolicy(): Promise<void> {
    setError("");
    setWorkflow(undefined);
    setStatusResult(undefined);
    const connectedAccount = wallet.account();
    const anchorRelease = deployment.executionPolicyAnchorRelease;
    const file = transientBundle;
    if (!deployment.delegateUrl) {
      setError("A live delegate endpoint is not configured for this deployment.");
      return;
    }
    if (
      !deployment.executionPolicyApprovalDomainHash
      || !deployment.executionPolicyApproverRootHash
      || !deployment.executionPolicyApprovedApproverHashes
      || !anchorRelease
    ) {
      setError("This release does not pin the policy domain, immutable approver set, and active monotonic anchor.");
      return;
    }
    if (!connectedAccount) {
      setError("Connect an EIP-1193 wallet before running any execution-policy decision.");
      return;
    }
    if (!walletOnBaseSepolia()) {
      setError("Switch the connected wallet to Base Sepolia before sending a policy bundle to the delegate.");
      return;
    }
    if (!runtimeBearer()) {
      setError("Paste a runtime transport bearer for this session.");
      return;
    }
    if (!resourceReference()) {
      setError("Enter the private resource reference to bind.");
      return;
    }
    if (!file) {
      setError("Choose a strict request-and-policy JSON bundle.");
      return;
    }

    setBusy("evaluate");
    setPhase("preflight");
    let transientExecutionContextHash = "";
    try {
      const parsedBundle = parsePolicyBundleText(await file.text());
      const target = await resolveExecutionTarget(
        resourceReference(),
        computeProjectReference(),
      );
      transientExecutionContextHash = target.executionContextHash ?? "";
      setPhase("approval");
      const result = await runExecutionPolicyWorkflow({
        delegateUrl: deployment.delegateUrl,
        runtimeBearer: runtimeBearer(),
        approvalDomainHash: deployment.executionPolicyApprovalDomainHash,
        approverRootHash: deployment.executionPolicyApproverRootHash,
        approvedApproverHashes: deployment.executionPolicyApprovedApproverHashes,
        anchorRelease,
        surface: surface(),
        resourceId: target.resourceId,
        executionContextHash: transientExecutionContextHash || undefined,
        expiresAt: Math.floor(Date.now() / 1000) + ttlSeconds(),
        bundle: parsedBundle,
        approverAddress: connectedAccount,
        personalSign: async (message) => {
          setPhase("signing");
          const signature = await wallet.signPersonalMessage(message);
          setPhase("persisting");
          return signature;
        },
      });
      setWorkflow(result);
      setStatusResult(result.status);
      setPhase("complete");
    } catch (cause) {
      setPhase("idle");
      setError(cause instanceof Error ? cause.message : "Execution-policy workflow failed closed.");
    } finally {
      transientExecutionContextHash = "";
      setBusy("");
      setResourceReference("");
      setComputeProjectReference("");
      clearTransientBundle();
    }
  }

  async function readStatus(): Promise<void> {
    setError("");
    setStatusResult(undefined);
    const anchorRelease = deployment.executionPolicyAnchorRelease;
    if (!deployment.delegateUrl) {
      setError("A live delegate endpoint is not configured for this deployment.");
      return;
    }
    if (
      !deployment.executionPolicyApprovalDomainHash
      || !deployment.executionPolicyApproverRootHash
      || !deployment.executionPolicyApprovedApproverHashes
      || !anchorRelease
    ) {
      setError("This release does not pin the policy domain, immutable approver set, and active monotonic anchor.");
      return;
    }
    if (!wallet.account()) {
      setError("Connect an EIP-1193 wallet before reading execution-policy status.");
      return;
    }
    if (!walletOnBaseSepolia()) {
      setError("Switch the connected wallet to Base Sepolia before reading execution-policy status.");
      return;
    }
    if (!runtimeBearer()) {
      setError("Paste a runtime transport bearer for this session.");
      return;
    }
    if (!statusReference()) {
      setError("Enter the private resource reference to look up.");
      return;
    }
    setBusy("status");
    let transientExecutionContextHash = "";
    try {
      const target = await resolveExecutionTarget(
        statusReference(),
        computeStatusProjectReference(),
      );
      transientExecutionContextHash = target.executionContextHash ?? "";
      setStatusResult(await readExecutionPolicyStatus({
        delegateUrl: deployment.delegateUrl,
        runtimeBearer: runtimeBearer(),
        approvalDomainHash: deployment.executionPolicyApprovalDomainHash,
        approverRootHash: deployment.executionPolicyApproverRootHash,
        approvedApproverHashes: deployment.executionPolicyApprovedApproverHashes,
        anchorRelease,
        surface: surface(),
        resourceId: target.resourceId,
        executionContextHash: transientExecutionContextHash || undefined,
      }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Execution-policy status lookup failed closed.");
    } finally {
      transientExecutionContextHash = "";
      setBusy("");
      setStatusReference("");
      setComputeStatusProjectReference("");
    }
  }

  onCleanup(() => {
    clearTransientBundle();
    setRuntimeBearer("");
    setResourceReference("");
    setStatusReference("");
    setComputeProjectReference("");
    setComputeStatusProjectReference("");
  });

  return (
    <div class="page-wrap product-page lab-page">
      <header class="product-page-head lab-head">
        <div>
          <p class="overline">Release-candidate execution policy · modeled safeguards</p>
          <h1>Control the line before inference.</h1>
          <p>
            Evaluate strict policy bundles in the protected delegate, require explicit wallet
            consent for every PASS, and accept a bounded record only after its monotonic Base
            Sepolia anchor satisfies the release depth and the observer RPC's reported-finalized
            head, then is independently re-read by this browser. This is not RPC quorum or a
            consensus proof.
          </p>
        </div>
        <button class="secondary-button large" type="button" onClick={() => props.navigate("verify")}>
          <Fingerprint size={17} /> Inspect deployment evidence <ArrowRight size={15} />
        </button>
      </header>

      <section class="policy-operator" aria-labelledby="policy-operator-title">
        <div class="policy-operator-head">
          <div>
            <div class="operator-kicker"><span class={`feature-state ${delegateConfigured() ? "live" : "roadmap"}`}><Radio size={11} /> {delegateConfigured() ? "ENDPOINT CONFIGURED" : "RELEASE LOCKED"}</span> protected delegate control plane</div>
            <h2 id="policy-operator-title">Execution-policy approvals</h2>
            <p>
              A runtime bearer authenticates transport only; it can never approve a PASS. The
              browser recomputes the policy commitments and immutable approver root before a
              release-authorized EOA signs the bounded <code>personal_sign</code> message. Success
              remains blocked until the release-frozen writer anchors the decision and the
              browser verifies the configured finalized-head and confirmation-depth policy.
            </p>
          </div>
          <div class={`operator-readiness ${liveReady() ? "ready" : "blocked"}`} role="status" aria-live="polite">
            {liveReady() ? <ShieldCheck size={20} /> : <ShieldAlert size={20} />}
            <span>
              <small>OPERATOR READINESS</small>
              <strong>{liveReady()
                ? "Release binding + delegate + wallet ready"
                : !delegateConfigured()
                  ? "Live delegate unavailable"
                  : !approvalDomainPinned()
                    ? "Approval domain absent from release"
                    : !approverSetPinned()
                      ? "Immutable approver set absent from release"
                      : !monotonicAnchorPinned()
                        ? "Active monotonic anchor absent from release"
                        : !walletConnected()
                          ? "Connect wallet to unlock"
                          : "Switch wallet to Base Sepolia"}</strong>
            </span>
          </div>
        </div>

        <div class="policy-flow" role="list" aria-label="Release-gated execution policy sequence">
          <span role="listitem"><i>01</i><FileJson size={17} /><strong>Transient bundle</strong><small>strict JSON only</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>02</i><ShieldCheck size={17} /><strong>Delegate gate</strong><small>pass · hold · deny</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>03</i><WalletCards size={17} /><strong>Wallet consent</strong><small>PASS only</small></span>
          <ArrowRight size={15} aria-hidden="true" />
          <span role="listitem"><i>04</i><Fingerprint size={17} /><strong>Confirmed anchor</strong><small>RPC-finalized · depth · re-read</small></span>
        </div>

        <div class="policy-surface-picker" role="group" aria-label="Protected execution surface">
          <For each={SURFACES}>
            {(item) => {
              const Icon = item.icon;
              return (
                <button
                  type="button"
                  class={surface() === item.key ? "active" : ""}
                  aria-pressed={surface() === item.key}
                  onClick={() => {
                    setSurface(item.key);
                    setWorkflow(undefined);
                    setStatusResult(undefined);
                    setError("");
                    setResourceReference("");
                    setStatusReference("");
                    setComputeProjectReference("");
                    setComputeStatusProjectReference("");
                  }}
                >
                  <span>{item.index}</span>
                  <Icon size={18} />
                  <strong>{item.title}</strong>
                  <small>{item.description}</small>
                </button>
              );
            }}
          </For>
        </div>

        <div class="policy-console-grid">
          <form class="policy-control-card" onSubmit={(event) => { event.preventDefault(); void evaluatePolicy(); }}>
            <div class="policy-card-head">
              <span><KeyRound size={18} /></span>
              <div><p class="overline">{delegateConfigured() ? "Live operator input" : "Release-gated operator input"}</p><h3>Evaluate and bind</h3></div>
              <span class="policy-surface-code">{surface()}</span>
            </div>

            <div class="policy-secret-grid">
              <Show when={surface() === "compute_dispatch"}>
                <label>
                  <span>Exact-asset project reference <em>authenticated lookup</em></span>
                  <input
                    type="password"
                    autocomplete="off"
                    spellcheck={false}
                    maxlength="64"
                    placeholder="prj_..."
                    value={computeProjectReference()}
                    onInput={(event) => setComputeProjectReference(event.currentTarget.value)}
                  />
                </label>
              </Show>
              <label>
                <span>Runtime bearer <em>transport only</em></span>
                <input
                  type="password"
                  autocomplete="off"
                  spellcheck={false}
                  maxlength="4096"
                  placeholder="session-only credential"
                  value={runtimeBearer()}
                  onInput={(event) => setRuntimeBearer(event.currentTarget.value)}
                />
              </label>
              <label>
                <span>{surface() === "compute_dispatch" ? "Exact-asset job reference" : "Private resource reference"} <em>{surface() === "compute_dispatch" ? "resolved by wallet-authenticated API" : "hashed by delegate"}</em></span>
                <input
                  type="password"
                  autocomplete="off"
                  spellcheck={false}
                  maxlength="160"
                  placeholder={selectedSurface().placeholder}
                  value={resourceReference()}
                  onInput={(event) => setResourceReference(event.currentTarget.value)}
                />
              </label>
            </div>

            <div class="policy-upload-row">
              <label class={`policy-file-drop ${bundleReady() ? "ready" : ""}`}>
                <input
                  ref={bundleInput}
                  type="file"
                  accept=".json,application/json"
                  onChange={(event) => selectBundle(event.currentTarget.files?.[0])}
                />
                {bundleReady() ? <CheckCircle2 size={22} /> : <UploadCloud size={22} />}
                <span>
                  <strong>{bundleReady() ? "Transient bundle staged" : "Choose request + policy JSON"}</strong>
                  <small>{bundleReady() ? "Filename hidden · cleared after this attempt" : "64 KiB maximum · raw fields never rendered"}</small>
                </span>
              </label>
              <label class="policy-ttl">
                <span>Binding lifetime</span>
                <select value={ttlSeconds()} onChange={(event) => setTtlSeconds(Number(event.currentTarget.value))}>
                  <option value="300">5 minutes</option>
                  <option value="900">15 minutes</option>
                  <option value="3600">1 hour</option>
                </select>
                <small><Clock3 size={12} /> browser options capped at 1 hour</small>
              </label>
            </div>

            <button
              class="primary-button large full policy-run-button"
              type="submit"
              disabled={!liveReady() || !runtimeBearer() || !resourceReference() || !bundleReady() || (surface() === "compute_dispatch" && !computeProjectReference()) || Boolean(busy())}
            >
              {busy() === "evaluate" ? <LoaderCircle class="spin" size={17} /> : <WalletCards size={17} />}
              {busy() === "evaluate" ? phaseLabel() : liveReady() ? "Evaluate policy and request consent" : "Release binding + delegate + wallet required"}
            </button>

            <div class={`policy-phase ${phase()}`} aria-live="polite">
              <span><i /><i /><i /><i /></span>
              <small>{phaseLabel()}</small>
            </div>
          </form>

          <aside class="policy-receipt-card" aria-live="polite">
            <div class="policy-card-head">
              <span><Fingerprint size={18} /></span>
              <div><p class="overline">Bounded return surface</p><h3>Execution binding</h3></div>
              <span class="bounded-only"><LockKeyhole size={12} /> hashes only</span>
            </div>

            <Show when={workflow()} keyed fallback={
              <div class="policy-empty-state">
                <div><Fingerprint size={26} /></div>
                <h4>No live decision loaded</h4>
                <p>Raw requests, policies, resource IDs, bearer tokens, approval messages, and signatures are never placed in this result surface.</p>
                <span><ShieldCheck size={13} /> strict response schema</span>
                <span><WalletCards size={13} /> PASS requires personal_sign</span>
                <span><LockKeyhole size={13} /> fail closed on drift</span>
              </div>
            }>
              {(result) => (
                <div class="policy-receipt-body">
                  <div class="policy-verdict-line">
                    <span class={`policy-decision ${result.evaluation.decision}`}>
                      {result.evaluation.decision === "pass" ? <CheckCircle2 size={15} /> : <CircleAlert size={15} />}
                      {result.evaluation.decision.toUpperCase()}
                    </span>
                    <span>{result.evaluation.reason_code.replaceAll("_", " ")}</span>
                  </div>
                  <div class="policy-consent-note">
                    {result.approval.wallet_signature_required ? <WalletCards size={16} /> : <ShieldAlert size={16} />}
                    <span>
                      <strong>{result.approval.wallet_signature_required ? "Wallet approval bound" : "No approval evidence attached"}</strong>
                      <small>{result.approval.wallet_signature_required ? "PASS was signed through the connected EIP-1193 wallet and returned only after its anchor met the release confirmation policy." : "HOLD and DENY omit approval evidence but still require the same monotonic anchor policy."}</small>
                    </span>
                  </div>
                  <div class="policy-hash-grid">
                    <HashFact label="RESOURCE HASH" value={result.approval.resource_id_hash} />
                    <HashFact label="REQUEST HASH" value={result.approval.request_hash} />
                    <HashFact label="POLICY HASH" value={result.approval.policy_hash} />
                    <HashFact label="EXECUTION CONTEXT" value={result.approval.execution_context_hash} />
                    <HashFact label="APPROVAL MESSAGE HASH" value={result.approval.approval_message_hash} />
                    <HashFact label="DEPLOYMENT DOMAIN HASH" value={result.approval.approval_domain_hash} />
                    <HashFact label="DECISION HASH" value={result.evaluation.execution_binding.decision_hash} />
                    <HashFact label="ANCHOR GLOBAL HEAD" value={result.status.rollback_anchor.global_head} />
                    <HashFact label="ANCHOR RUNTIME HASH" value={result.status.rollback_anchor.runtime_code_hash} />
                  </div>
                  <div class="policy-stage-trace">
                    <p class="overline">Bounded stage trace</p>
                    <For each={result.evaluation.outcomes}>
                      {(outcome) => (
                        <div>
                          <span>{String(outcome.stage).padStart(2, "0")}</span>
                          <strong>{outcome.reason_code.replaceAll("_", " ")}</strong>
                          <em class={outcome.decision}>{outcome.decision}</em>
                          <small>{outcome.matched_category_count} hashed categor{outcome.matched_category_count === 1 ? "y" : "ies"}</small>
                        </div>
                      )}
                    </For>
                  </div>
                  <div class="policy-egress-seal">
                    <ShieldCheck size={16} />
                    <span><strong>Raw policy egress: false</strong><small>Raw resource egress: false · raw secret egress: false</small></span>
                  </div>
                </div>
              )}
            </Show>
          </aside>
        </div>

        <Show when={error()}>
          <div class="policy-operator-error" role="alert"><ShieldAlert size={17} /><span>{error()}</span></div>
        </Show>

        <section class="policy-status-console" aria-labelledby="policy-status-title">
          <div>
            <p class="overline">{delegateConfigured() ? "Live bounded lookup" : "Release-gated bounded lookup"}</p>
            <h3 id="policy-status-title">Read the latest execution binding.</h3>
            <p>The private reference is sent once and cleared; the delegate returns only its hash and the latest bounded record.</p>
          </div>
          <form onSubmit={(event) => { event.preventDefault(); void readStatus(); }}>
            <Show when={surface() === "compute_dispatch"}>
              <label>
                <span>Exact-asset Compute project reference</span>
                <input
                  type="password"
                  autocomplete="off"
                  spellcheck={false}
                  maxlength="64"
                  placeholder="prj_..."
                  value={computeStatusProjectReference()}
                  onInput={(event) => setComputeStatusProjectReference(event.currentTarget.value)}
                />
              </label>
            </Show>
            <label>
              <span>{selectedSurface().title} resource reference</span>
              <input
                type="password"
                autocomplete="off"
                spellcheck={false}
                maxlength="160"
                placeholder={selectedSurface().placeholder}
                value={statusReference()}
                onInput={(event) => setStatusReference(event.currentTarget.value)}
              />
            </label>
            <button class="secondary-button" type="submit" disabled={!liveReady() || !runtimeBearer() || !statusReference() || (surface() === "compute_dispatch" && !computeStatusProjectReference()) || Boolean(busy())}>
              {busy() === "status" ? <LoaderCircle class="spin" size={15} /> : <RefreshCw size={15} />}
              {busy() === "status" ? "Reading bounded status" : "Read status"}
            </button>
          </form>
          <Show when={statusResult()} keyed fallback={<div class="policy-status-placeholder" role="status"><Radio size={15} /> No bounded status loaded</div>}>
            {(status) => <BoundedStatus status={status} />}
          </Show>
        </section>
      </section>

      <div class="environment-banner modeled">
        <FlaskConical size={18} />
        <div>
          <strong>Modeled policy receipt—not Intel TDX evidence</strong>
          <span>
            The simulator below creates illustrative hashes and receipt-shaped JSON in your browser.
            It never represents a hardware quote, signed application envelope, or verified CVM run.
          </span>
        </div>
      </div>

      <section class="gate-architecture" aria-label="Four-stage modeled safeguards gate">
        <For each={STAGES}>
          {(stage, index) => {
            const Icon = stage.icon;
            return (
              <article class="gate-stage-card">
                <div class="gate-stage-top">
                  <span>{stage.n}</span>
                  <Icon size={20} />
                </div>
                <h2>{stage.title}</h2>
                <p>{stage.copy}</p>
                <div class="stage-contract"><CheckCircle2 size={13} /> pass · hold · deny</div>
                {index() < STAGES.length - 1 && <i class="stage-arrow" aria-hidden="true" />}
              </article>
            );
          }}
        </For>
      </section>

      <section class="lab-simulator-panel">
        <div class="section-heading split-heading compact-heading">
          <div>
            <p class="overline">Modeled · browser only</p>
            <h2>Explore the deterministic gate.</h2>
          </div>
          <p>
            Inspect a synthetic access request, every stage verdict, the modeled corpus policy, and
            an illustrative receipt. This section never calls the live delegate.
          </p>
        </div>
        <Simulator />
      </section>

      <section class="lab-boundary-grid">
        <article>
          <span class="feature-state modeled">MODELED</span>
          <ShieldCheck size={21} />
          <h3>What the browser model demonstrates</h3>
          <p>Policy ordering, deterministic branching, bounded reasons, and fail-closed control flow can be reviewed directly in the browser.</p>
        </article>
        <article>
          <span class="feature-state modeled">MODELED BOUNDARY</span>
          <ShieldAlert size={21} />
          <h3>What the model does not prove</h3>
          <p>No quote verification, measurement match, key derivation, sandbox isolation, evaluator signature, or chain settlement occurs here.</p>
        </article>
        <article>
          <span class="feature-state roadmap">ROADMAP</span>
          <Fingerprint size={21} />
          <h3>Independent receipt graduation</h3>
          <p>Graduate each run by independently verifying its image digest, compose hash, TDX quote, contract binding, and bounded evaluator result.</p>
        </article>
      </section>
    </div>
  );
}
