import { For, Show, createEffect, createMemo, createSignal } from "solid-js";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Banknote,
  Blocks,
  Check,
  ChevronRight,
  CircleDashed,
  Cpu,
  DatabaseZap,
  Fingerprint,
  Gauge,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Split,
  WalletCards,
} from "lucide-solid";
import type {
  CollaborationExecutionStatusProjection,
  CollaborationExecutionWorkerCapability,
  CollaborationJointRun,
  CollaborationRoom,
  CollaborationSession,
} from "../lib/collaboration";
import { collaborationSessionIsCurrent } from "../lib/collaboration";
import { deployment } from "../config";
import { wallet } from "../lib/wallet";
import {
  buildCollaborationExecutionModel,
  nextCollaborationHappyPathStep,
  type CollaborationExecutionLaneStatus,
  type CollaborationExecutionScenario,
} from "../lib/collaborationExecution";
import {
  collaborationExecutionTransportGate,
  type CollaborationExecutionTransportAdapter,
} from "../lib/collaborationExecutionTransport";
import { CollaborateExecutionLiveRail } from "./CollaborateExecutionLiveRail";

const SCENARIOS: readonly {
  readonly id: CollaborationExecutionScenario;
  readonly label: string;
  readonly shortLabel: string;
  readonly description: string;
}[] = [
  {
    id: "release_disabled",
    label: "Release disabled",
    shortLabel: "Closed",
    description: "Implementation truth: execution and wallet adapters are wired; this unsigned/dev release authorizes no mutations.",
  },
  {
    id: "happy_path",
    label: "Happy-path model",
    shortLabel: "Happy path",
    description: "Walk the local model from fresh grants through bounded settlement stages.",
  },
  {
    id: "grant_drift",
    label: "Owner grant drift",
    shortLabel: "Grant drift",
    description: "One changed owner grant invalidates the exact basis before any claim.",
  },
  {
    id: "stale_finalized_evidence",
    label: "Stale finalized evidence",
    shortLabel: "Stale vault",
    description: "A reported-finalized read outside the freshness window blocks the claim.",
  },
  {
    id: "ambiguous_reconciliation",
    label: "Ambiguous provider boundary",
    shortLabel: "Reconcile",
    description: "Dispatch may have occurred, so recovery polls the trusted journal and never redispatches.",
  },
  {
    id: "bounded_result",
    label: "Bounded result",
    shortLabel: "Result",
    description: "Only score-band and usage commitments enter the Collaboration projection.",
  },
  {
    id: "settlement_withdrawal",
    label: "Settlement + withdrawals",
    shortLabel: "Royalties",
    description: "Preview the distinct authority, QVL, funding, broadcast, finality, and withdrawal stages.",
  },
];

const ROYALTY_STAGE_ORDER = [
  "not_started",
  "reservation_terms_issued",
  "settlement_prepared",
  "settlement_finalized",
  "withdrawal_ready",
] as const;

const ROYALTY_EVIDENCE_STAGES = [
  ["Server-issued terms", "Exact reservation ID, asset, amount, payer, and owner split"],
  ["Onchain deposit", "Only after every fresh owner grant and authorization"],
  ["Finalized reservation", "Exact, active, funded, and unconsumed worker observation"],
  ["Settlement authority", "Release-pinned signer and policy"],
  ["Independent QVL", "Purpose-separated authorization"],
  ["Broadcast", "Transaction hash and inclusion"],
  ["Finalized receipt", "Pinned block and confirmation model"],
  ["Owner withdrawal", "Per-owner pull payment"],
] as const;

function short(value: string, left = 12, right = 8): string {
  if (value.length <= left + right + 1) return value;
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function laneIcon(status: CollaborationExecutionLaneStatus) {
  if (status === "complete") return <Check size={14} />;
  if (status === "blocked") return <ShieldAlert size={14} />;
  if (status === "reconciliation") return <RefreshCw size={14} />;
  if (status === "active") return <ChevronRight size={14} />;
  return <CircleDashed size={14} />;
}

function scenarioDefaults(scenario: CollaborationExecutionScenario): {
  readonly source: "wallet" | "credential";
  readonly adoptionEnabled: boolean;
} {
  if (scenario === "adoption_disabled") {
    return { source: "credential", adoptionEnabled: false };
  }
  if (scenario === "adoption_enabled") {
    return { source: "credential", adoptionEnabled: true };
  }
  return { source: "wallet", adoptionEnabled: false };
}

export interface CollaborateExecutionProps {
  readonly room?: CollaborationRoom;
  readonly jointRun?: CollaborationJointRun;
  readonly session?: CollaborationSession;
  readonly connectedAddress?: string;
  readonly coordinationReleaseEnabled?: boolean;
  readonly transportAdapter?: CollaborationExecutionTransportAdapter;
  readonly initialScenario?: CollaborationExecutionScenario;
  readonly initialHappyPathStep?: number;
  readonly initialWorkloadSource?: "wallet" | "credential";
  readonly initialAdoptionEnabled?: boolean;
}

export function CollaborateExecution(props: CollaborateExecutionProps) {
  const initialScenario = props.initialScenario ?? "release_disabled";
  const defaults = scenarioDefaults(initialScenario);
  const [scenario, setScenario] = createSignal<CollaborationExecutionScenario>(
    initialScenario,
  );
  const [happyPathStep, setHappyPathStep] = createSignal(
    props.initialHappyPathStep ?? 1,
  );
  const [workloadSource, setWorkloadSource] = createSignal<
    "wallet" | "credential"
  >(props.initialWorkloadSource ?? defaults.source);
  const [adoptionEnabled, setAdoptionEnabled] = createSignal(
    props.initialAdoptionEnabled ?? defaults.adoptionEnabled,
  );
  const [liveExecutionId, setLiveExecutionId] = createSignal("");
  const [liveStatus, setLiveStatus] =
    createSignal<CollaborationExecutionStatusProjection>();
  const [liveStatusState, setLiveStatusState] = createSignal<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [liveStatusMessage, setLiveStatusMessage] = createSignal("");
  const [workerCapability, setWorkerCapability] =
    createSignal<CollaborationExecutionWorkerCapability>();
  const [workerCapabilityState, setWorkerCapabilityState] = createSignal<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [workerCapabilityMessage, setWorkerCapabilityMessage] = createSignal("");
  const sessionIsCurrent = createMemo(() => collaborationSessionIsCurrent(
    props.session,
    {
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
    },
  ));
  let liveStatusSessionKey = sessionIsCurrent()
    ? props.session?.accessToken ?? ""
    : "";

  createEffect(() => {
    const nextSessionKey = sessionIsCurrent()
      ? props.session?.accessToken ?? ""
      : "";
    if (nextSessionKey === liveStatusSessionKey) return;
    liveStatusSessionKey = nextSessionKey;
    setLiveStatus(undefined);
    setLiveStatusState("idle");
    setLiveStatusMessage("");
    setWorkerCapability(undefined);
    setWorkerCapabilityState("idle");
    setWorkerCapabilityMessage("");
  });

  const model = createMemo(() => buildCollaborationExecutionModel({
    scenario: scenario(),
    happyPathStep: happyPathStep(),
    room: props.room,
    jointRun: props.jointRun,
    connectedAddress: props.connectedAddress,
    coordinationReleaseEnabled: props.coordinationReleaseEnabled,
    workloadSource: workloadSource(),
    walletAdoptionEnabled: adoptionEnabled(),
  }));
  const transportGate = createMemo(() => collaborationExecutionTransportGate({
    adapter: props.transportAdapter,
    session: props.session,
    walletContext: {
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
    },
    room: props.room,
    jointRun: props.jointRun,
    release: deployment.collaborationExecutionRelease,
    workerCapability: workerCapability(),
  }));

  const chooseScenario = (next: CollaborationExecutionScenario) => {
    setScenario(next);
    const nextDefaults = scenarioDefaults(next);
    setWorkloadSource(nextDefaults.source);
    setAdoptionEnabled(nextDefaults.adoptionEnabled);
    if (next === "happy_path") setHappyPathStep(1);
  };

  const modelCredentialAdoption = (enabled: boolean) => {
    setWorkloadSource("credential");
    setAdoptionEnabled(enabled);
    setScenario(enabled ? "adoption_enabled" : "adoption_disabled");
  };

  const royaltyStageReached = (minimum: typeof ROYALTY_STAGE_ORDER[number]) => (
    ROYALTY_STAGE_ORDER.indexOf(model().royalty.modeledStage)
      >= ROYALTY_STAGE_ORDER.indexOf(minimum)
  );
  const liveStatusReadReady = createMemo(() => Boolean(
    props.transportAdapter
    && props.session
    && sessionIsCurrent()
    && transportGate().controlPlaneStatusReadsEnabled
    && /^exec_[0-9a-f]{64}$/.test(liveExecutionId().trim()),
  ));
  const workerCapabilityReadReady = createMemo(() => Boolean(
    props.transportAdapter
    && props.session
    && sessionIsCurrent()
    && transportGate().controlPlaneStatusReadsEnabled,
  ));

  const readWorkerCapability = async () => {
    const adapter = props.transportAdapter;
    const session = props.session;
    if (!adapter || !session || !sessionIsCurrent()) {
      setWorkerCapability(undefined);
      setWorkerCapabilityState("error");
      setWorkerCapabilityMessage(
        "A current Collaboration wallet session and release-enabled control plane are required.",
      );
      return;
    }
    setWorkerCapability(undefined);
    setWorkerCapabilityState("loading");
    setWorkerCapabilityMessage(
      "Reading fresh authenticated worker presence…",
    );
    try {
      const capability = await adapter.fetchWorkerCapability(
        session.accessToken,
      );
      if (
        props.session?.accessToken !== session.accessToken
        || !sessionIsCurrent()
      ) return;
      setWorkerCapability(capability);
      setWorkerCapabilityState("ready");
      setWorkerCapabilityMessage(
        capability.status === "live"
          ? "Fresh HMAC-authenticated worker presence loaded. This is process presence, never a job attestation."
          : capability.warning,
      );
    } catch (cause) {
      if (
        props.session?.accessToken !== session.accessToken
        || !sessionIsCurrent()
      ) return;
      setWorkerCapability(undefined);
      setWorkerCapabilityState("error");
      setWorkerCapabilityMessage(
        cause instanceof Error
          ? cause.message
          : "The worker-capability read failed closed.",
      );
    }
  };

  const readLiveExecutionStatus = async () => {
    const adapter = props.transportAdapter;
    const session = props.session;
    const executionId = liveExecutionId().trim();
    if (
      !adapter
      || !session
      || !sessionIsCurrent()
      || !/^exec_[0-9a-f]{64}$/.test(executionId)
    ) {
      setLiveStatus(undefined);
      setLiveStatusState("error");
      setLiveStatusMessage(
        "Enter an exact execution ID while the Collaboration wallet session is current.",
      );
      return;
    }
    setLiveStatus(undefined);
    setLiveStatusState("loading");
    setLiveStatusMessage("Reading the participant-visible status projection…");
    try {
      const status = await adapter.fetchStatus(
        session.accessToken,
        executionId,
      );
      if (
        props.session?.accessToken !== session.accessToken
        || !sessionIsCurrent()
        || liveExecutionId().trim() !== executionId
      ) return;
      setLiveStatus(status);
      setLiveStatusState("ready");
      setLiveStatusMessage(
        "Participant-visible API projection loaded. Evidence boundaries remain explicit below.",
      );
    } catch (cause) {
      if (
        props.session?.accessToken !== session.accessToken
        || !sessionIsCurrent()
        || liveExecutionId().trim() !== executionId
      ) return;
      setLiveStatus(undefined);
      setLiveStatusState("error");
      setLiveStatusMessage(
        cause instanceof Error
          ? cause.message
          : "The Collaboration execution status read failed closed.",
      );
    }
  };

  return (
    <section
      class="collaboration-execution-workbench"
      aria-labelledby="collaboration-execution-title"
      data-execution-state={model().executionState}
      data-execution-evidence="implemented-release-gated-rails-plus-modeled-lab"
    >
      <header class="collaboration-execution-head">
        <div>
          <p class="overline">
            {transportGate().controlPlaneMutationCallsEnabled
              ? "Release-enabled queue and wallet rails · modeled failure lab"
              : "Production-capable execution rails · current release closed"}
          </p>
          <h2 id="collaboration-execution-title">
            Turn joint consent into one bounded, recoverable run.
          </h2>
          <p>
            The production-capable control plane and wallet rail implement fresh
            owner execution grants, a derived Compute intent, capped authorization,
            exact Royalty reservation and refund, journal-owned handoff, bounded
            output, and settlement. This unsigned/dev release keeps mutations
            closed; the scenario controls remain a modeled failure lab.
          </p>
        </div>
        <div class="collaboration-execution-state" aria-live="polite">
          <small>PRODUCT STATE</small>
          <strong>{model().stateLabel}</strong>
          <span>Release-gated wallet rail implemented · modeled failure lab isolated</span>
        </div>
      </header>

      <div class="collaboration-execution-truth" aria-label="Execution evidence boundaries">
        <span classList={{ blocked: !transportGate().controlPlaneMutationCallsEnabled, live: transportGate().controlPlaneMutationCallsEnabled }}>
          <LockKeyhole size={13} />
          {transportGate().controlPlaneMutationCallsEnabled
            ? "Queue controls release-enabled"
            : "Current unsigned/dev release · mutations closed"}
        </span>
        <span classList={{ live: model().coordination.roomBound }}>
          <Fingerprint size={13} />
          {model().coordination.roomBound
            ? "Selected participant room input"
            : "Deterministic demo room input"}
        </span>
        <span class="warning"><DatabaseZap size={13} /> Compute source not authenticated here</span>
        <span class="warning"><ShieldAlert size={13} /> No TDX or QVL evidence</span>
        <span class="neutral"><LockKeyhole size={13} /> No health-data intake</span>
      </div>

      <div class="collaboration-execution-binding">
        <div>
          <small>COORDINATION INPUT</small>
          <strong>{model().coordination.roomBound ? "Selected room" : "Demo fixture"}</strong>
          <code title={model().coordination.roomId}>
            {short(model().coordination.roomId, 16, 7)}
          </code>
        </div>
        <div>
          <small>EXACT QUERY GRANTS</small>
          <strong>{model().coordination.queryGrantsCurrent ? "Current input" : "Incomplete"}</strong>
          <span>Never reused as execution grants</span>
        </div>
        <div>
          <small>JOINT SNAPSHOT</small>
          <strong>{model().coordination.jointSnapshotCurrent ? "Current input" : "Missing / stale"}</strong>
          <span>Coordination evidence · no spend authority</span>
        </div>
        <div>
          <small>EXECUTION RELEASE</small>
          <strong>{transportGate().executionReleaseEnabled ? "Current v4 enabled" : "Disabled / unavailable"}</strong>
          <span>{transportGate().executionReleaseEnabled ? "Control plane only; independent write gates remain" : "Current release closed; failure lab can advance"}</span>
        </div>
      </div>

      <section
        class="collaboration-execution-transport"
        aria-labelledby="collaboration-execution-transport-title"
        data-execution-transport={transportGate().controlPlaneMutationCallsEnabled ? "queue-ready" : "closed"}
      >
        <div class="collaboration-execution-transport-head">
          <div>
            <small>IMPLEMENTED TRANSPORT SEAM · RELEASE-GATED</small>
            <strong id="collaboration-execution-transport-title">
              Typed endpoints are wired; release authority gates every mutation.
            </strong>
            <p>
              The real API path reuses the current wallet-scoped Collaboration
              session and selected room. Local scenario state is never consulted
              when deciding whether a live execution call may run.
            </p>
          </div>
          <span classList={{ ready: transportGate().controlPlaneMutationCallsEnabled }}>
            <LockKeyhole size={13} />
            {transportGate().controlPlaneMutationCallsEnabled ? "QUEUE CONTROLS RELEASE-ENABLED" : "MUTATIONS FAIL-CLOSED"}
          </span>
        </div>
        <div class="collaboration-execution-transport-facts">
          <div classList={{ ready: transportGate().apiContractWired }}>
            <small>API CONTRACT</small>
            <strong>{transportGate().apiContractWired ? "Typed adapter present" : "Adapter absent"}</strong>
            <span>Plan · owner challenge · authorize · status; Royalty reservation ID and release binding are server-derived</span>
          </div>
          <div classList={{ ready: transportGate().currentCollaborationSessionBound }}>
            <small>WALLET SESSION</small>
            <strong>{transportGate().currentCollaborationSessionBound ? "Current bearer bound" : "Not current"}</strong>
            <span>Same participant authority as the room console</span>
          </div>
          <div classList={{ ready: transportGate().currentJointSnapshotBound }}>
            <small>ROOM + SNAPSHOT</small>
            <strong>{transportGate().currentJointSnapshotBound ? "Current exact input" : "Missing or stale"}</strong>
            <span>No standalone demo state can satisfy this gate</span>
          </div>
          <div classList={{ ready: transportGate().canonicalReleaseConfigured && transportGate().executionReleaseEnabled }}>
            <small>EXECUTION RELEASE</small>
            <strong>{transportGate().canonicalReleaseConfigured ? transportGate().executionReleaseEnabled ? "Release-configured · queue controls" : "Valid projection · execution disabled" : "Not projected"}</strong>
            <span>{transportGate().canonicalReleaseConfigured ? "Canonical v4 profile · not worker or job evidence" : "API wiring alone is not deployment evidence"}</span>
          </div>
          <div classList={{ ready: transportGate().workerPresenceProven }}>
            <small>WORKER PRESENCE</small>
            <strong>{transportGate().workerPresenceProven ? "Fresh + release-matching" : "Not proven"}</strong>
            <span>Authenticated process presence · never TDX/QVL job evidence</span>
          </div>
        </div>
        <form
          class="collaboration-execution-status-lookup"
          aria-label="Read a participant-visible Collaboration execution status"
          onSubmit={(event) => {
            event.preventDefault();
            void readLiveExecutionStatus();
          }}
        >
          <label for="collaboration-execution-id">
            <span>STATUS LOOKUP · EXACT EXECUTION ID · READ-ONLY</span>
            <input
              id="collaboration-execution-id"
              value={liveExecutionId()}
              onInput={(event) => {
                setLiveExecutionId(event.currentTarget.value.trim());
                setLiveStatus(undefined);
                setLiveStatusState("idle");
                setLiveStatusMessage("");
              }}
              spellcheck={false}
              autocomplete="off"
              placeholder={`exec_${"0".repeat(64)}`}
              aria-describedby="collaboration-execution-status-help"
            />
          </label>
          <p id="collaboration-execution-status-help">
            Uses the current Collaboration bearer. A response is an authenticated
            participant API projection—not independent TDX, QVL, chain, or worker-presence proof.
          </p>
        </form>
        <div class="collaboration-execution-live-calls" aria-label="Implemented release-gated Collaboration calls">
          <button
            type="button"
            disabled={!workerCapabilityReadReady() || workerCapabilityState() === "loading"}
            data-live-execution-call="worker-capability"
            onClick={() => void readWorkerCapability()}
          >
            <span>00</span><div><strong>Refresh worker presence</strong><small>GET /execution-capability · no job claim</small></div>
          </button>
          <button type="button" disabled data-live-execution-call="plan">
            <span>01</span><div><strong>Create exact plan</strong><small>POST /runs/:run/execution-plans</small></div>
          </button>
          <button type="button" disabled data-live-execution-call="grant-challenge">
            <span>02</span><div><strong>Issue owner challenge</strong><small>Fresh one-shot grant · owner bearer</small></div>
          </button>
          <button type="button" disabled data-live-execution-call="authorize">
            <span>03</span><div><strong>Authorize grant set</strong><small>Returns exact deposit terms · queue stays inert</small></div>
          </button>
          <button
            type="button"
            disabled={!liveStatusReadReady() || liveStatusState() === "loading"}
            data-live-execution-call="status"
            onClick={() => void readLiveExecutionStatus()}
          >
            <span>04</span><div><strong>Read execution status</strong><small>Participant projection · not source proof</small></div>
          </button>
        </div>
        <Show when={workerCapabilityState() !== "idle"}>
          <div
            class={`collaboration-execution-status-feedback ${workerCapabilityState()}`}
            role="status"
            aria-live="polite"
          >
            {workerCapabilityState() === "loading"
              ? <RefreshCw size={15} />
              : workerCapabilityState() === "ready"
                ? <BadgeCheck size={15} />
                : <ShieldAlert size={15} />}
            <span>{workerCapabilityMessage()}</span>
          </div>
        </Show>
        <Show when={workerCapability()}>
          {(capability) => (
            <article
              class="collaboration-execution-live-status"
              data-live-status-evidence="authenticated-worker-presence-not-job-attestation"
            >
              <div class="collaboration-execution-live-status-head">
                <div>
                  <small>AUTHENTICATED WORKER PRESENCE · NOT JOB ATTESTATION</small>
                  <strong>{capability().status}</strong>
                  <code title={capability().presence_binding_sha256 ?? "No presence binding"}>
                    {capability().presence_binding_sha256
                      ? short(capability().presence_binding_sha256!, 18, 10)
                      : capability().gate_reason}
                  </code>
                </div>
                <span classList={{ warning: !transportGate().workerPresenceProven }}>
                  {transportGate().workerPresenceProven
                    ? "CURRENT RELEASE MATCH"
                    : "FAIL-CLOSED"}
                </span>
              </div>
              <dl>
                <div><dt>Heartbeat</dt><dd>{capability().freshness}</dd><small>{capability().heartbeat_observed_at ? new Date(capability().heartbeat_observed_at! * 1_000).toLocaleString() : "Not observed"}</small></div>
                <div><dt>Authenticity</dt><dd>{capability().evidence_authenticity.replaceAll("_", " ")}</dd><small>Server-verified heartbeat MAC</small></div>
                <div><dt>Release binding</dt><dd>{transportGate().workerPresenceProven ? "Current v4 match" : "Missing / drifted"}</dd><small>Release, main runtime, Royalty, and Compute vault</small></div>
                <div><dt>Reservation capability</dt><dd>{transportGate().reservationCapabilityReady ? "Worker ready" : "Blocked"}</dd><small>Fresh Royalty read + exact terms still required</small></div>
                <div><dt>Real dstack</dt><dd>{capability().real_dstack ? "Reported present" : "Unavailable"}</dd><small>Presence classification only</small></div>
                <div><dt>QVL reachability</dt><dd>{capability().qvl_capability.reachability.replaceAll("_", " ")}</dd><small>Authenticated capability only · never a per-job verdict</small></div>
                <div><dt>Per-job TDX</dt><dd>Not proven</dd><small>Settlement plan must carry fresh evidence</small></div>
                <div><dt>Per-job QVL</dt><dd>Not verified</dd><small>Independent verdict required</small></div>
              </dl>
            </article>
          )}
        </Show>
        <Show when={liveStatusState() !== "idle"}>
          <div
            class={`collaboration-execution-status-feedback ${liveStatusState()}`}
            role="status"
            aria-live="polite"
          >
            {liveStatusState() === "loading"
              ? <RefreshCw size={15} />
              : liveStatusState() === "ready"
                ? <BadgeCheck size={15} />
                : <ShieldAlert size={15} />}
            <span>{liveStatusMessage()}</span>
          </div>
        </Show>
        <Show when={liveStatus()}>
          {(status) => (
            <article class="collaboration-execution-live-status" data-live-status-evidence="participant-api-projection">
              <div class="collaboration-execution-live-status-head">
                <div>
                  <small>PARTICIPANT API PROJECTION · CLIENT DTO CANNOT UNLOCK EXECUTION</small>
                  <strong>{status().state.replaceAll("_", " ")}</strong>
                  <code title={status().execution_id}>{short(status().execution_id, 16, 10)}</code>
                </div>
                <span classList={{ warning: status().reconciliation_hold }}>
                  {status().reconciliation_hold ? "RECONCILIATION HOLD" : "STATUS LOADED"}
                </span>
              </div>
              <dl>
                <div><dt>API route</dt><dd>{status().apiWorkerWiringAvailable ? "Available" : "Not proven"}</dd><small>Routing only</small></div>
                <div><dt>Worker presence</dt><dd>Not proven</dd><small>No fresh heartbeat</small></div>
                <div><dt>Local Compute journal</dt><dd>{status().apiReportsAuthenticatedLocalJournal ? "API-authenticated receipt" : "No projection"}</dd><small>Independent browser proof: no</small></div>
                <div><dt>Provider boundary</dt><dd>{status().provider_dispatch_may_have_occurred === null ? "Unknown / not projected" : status().provider_dispatch_may_have_occurred ? "May have occurred" : "Reported pre-boundary"}</dd><small>Automatic redispatch: never</small></div>
                <div><dt>Bounded result</dt><dd>{status().bounded_result_present ? "Present in projection" : "Absent"}</dd><small>Raw result not exposed</small></div>
                <div><dt>TDX / QVL</dt><dd>Not verified here</dd><small>Separate production receipts required</small></div>
                <div><dt>Royalty reservation</dt><dd>Not proven here</dd><small>Exact active finalized unconsumed state required</small></div>
                <div><dt>Control authority</dt><dd>None from this DTO</dd><small>Read does not authorize a mutation</small></div>
              </dl>
            </article>
          )}
        </Show>
        <CollaborateExecutionLiveRail
          room={props.room}
          jointRun={props.jointRun}
          session={props.session}
          adapter={props.transportAdapter}
          queueMutationsEnabled={transportGate().controlPlaneMutationCallsEnabled}
          onWorkerCapability={setWorkerCapability}
          onExecutionStatus={(status) => {
            setLiveStatus(status);
            setLiveStatusState("ready");
            setLiveStatusMessage(
              "Participant-visible API projection loaded. Evidence boundaries remain explicit below.",
            );
          }}
          onExecutionId={setLiveExecutionId}
        />
        <div class="collaboration-execution-transport-note">
          <ShieldAlert size={14} />
          <span>
            <strong>Authority remains split.</strong>{" "}
            {transportGate().blockers.join(" ")} Queue mutations, reservation
            capability, sponsor wallet writes, and per-job settlement evidence are
            independent gates. A returned client DTO can render status and exact
            terms, but it never unlocks the worker.
          </span>
        </div>
      </section>

      <div class="collaboration-execution-labbar">
        <div>
          <small>LOCAL FAILURE LAB</small>
          <strong>Explore exact transitions and stop conditions</strong>
        </div>
        <div class="collaboration-execution-scenarios" role="group" aria-label="Modeled execution scenarios">
          <For each={SCENARIOS}>{(item) => (
            <button
              type="button"
              aria-pressed={scenario() === item.id}
              classList={{ selected: scenario() === item.id }}
              title={item.description}
              onClick={() => chooseScenario(item.id)}
            >
              {item.shortLabel}
            </button>
          )}</For>
        </div>
        <Show when={scenario() === "happy_path"}>
          <button
            type="button"
            class="primary-button collaboration-model-advance"
            data-collaboration-model-action="advance"
            onClick={() => setHappyPathStep(
              nextCollaborationHappyPathStep(happyPathStep()),
            )}
          >
            Advance modeled stage <ArrowRight size={14} />
          </button>
        </Show>
      </div>

      <div class="collaboration-execution-lanes" aria-label="Modeled execution sequence">
        <For each={model().lanes}>{(lane) => (
          <article
            class={`collaboration-execution-lane ${lane.status}`}
            data-lane={lane.id}
            data-lane-status={lane.status}
          >
            <div>
              <span>{lane.number}</span>
              <i>{laneIcon(lane.status)}</i>
            </div>
            <strong>{lane.label}</strong>
            <p>{lane.detail}</p>
            <small>
              {lane.evidence === "coordination_input"
                ? "ROOM INPUT"
                : lane.evidence === "modeled"
                  ? "MODELED"
                  : "NOT OBSERVED"}
            </small>
          </article>
        )}</For>
      </div>

      <Show when={model().blockers.length > 0}>
        <div class="collaboration-execution-blockers" role="status">
          <AlertTriangle size={17} />
          <div>
            <strong>Fail-closed conditions</strong>
            <ul>
              <For each={model().blockers}>{(blocker) => <li>{blocker}</li>}</For>
            </ul>
          </div>
        </div>
      </Show>

      <div class="collaboration-execution-grid">
        <article class="collaboration-execution-panel grant-panel">
          <div class="collaboration-execution-panel-head">
            <div><KeyRound size={17} /><span><small>AUTHORITY</small><strong>Fresh execution grants</strong></span></div>
            <em>{model().owners.length} owner{model().owners.length === 1 ? "" : "s"}</em>
          </div>
          <p class="collaboration-execution-panel-copy">
            Every owner signs the same non-circular execution basis after the
            exact query snapshot exists. A prior room-role or query signature is
            displayed for context but never promoted into execution authority.
          </p>
          <div class="collaboration-execution-owner-list">
            <For each={model().owners}>{(owner, index) => (
              <div>
                <span class="owner-order">{String(index() + 1).padStart(2, "0")}</span>
                <div>
                  <code>{short(owner.ownerAddress, 10, 7)}</code>
                  <small>{owner.allocationBps.toLocaleString()} bps royalty allocation</small>
                </div>
                <span class={`execution-proof-state query-${owner.queryGrantStatus}`}>
                  Query: {owner.queryGrantStatus}
                </span>
                <span class={`execution-proof-state grant-${owner.executionGrantStatus}`}>
                  Exec: {owner.executionGrantStatus}
                </span>
              </div>
            )}</For>
          </div>
          <div class="collaboration-execution-boundary-note">
            <Split size={14} />
            <span><strong>Two signatures, two purposes.</strong> Query grants answer “may this exact question be considered?” Execution grants answer “may this exact funded run be claimed once?”</span>
          </div>
        </article>

        <article class="collaboration-execution-panel workload-panel">
          <div class="collaboration-execution-panel-head">
            <div><Cpu size={17} /><span><small>COMPUTE V3</small><strong>Workload + derived intent</strong></span></div>
            <em>{model().workload.sourceKind}</em>
          </div>
          <p class="collaboration-execution-panel-copy">
            The full owner-grant set derives one canonical Compute authorization
            context and dispatch intent. The upload source stays immutable.
          </p>
          <div class="collaboration-source-toggle" role="group" aria-label="Modeled workload source">
            <button
              type="button"
              aria-pressed={workloadSource() === "wallet"}
              classList={{ selected: workloadSource() === "wallet" }}
              onClick={() => {
                setWorkloadSource("wallet");
                setAdoptionEnabled(false);
                setScenario("happy_path");
              }}
            >
              <WalletCards size={14} /> Wallet-native
            </button>
            <button
              type="button"
              aria-pressed={workloadSource() === "credential"}
              classList={{ selected: workloadSource() === "credential" }}
              onClick={() => modelCredentialAdoption(false)}
            >
              <DatabaseZap size={14} /> Credential upload
            </button>
          </div>
          <Show when={model().workload.sourceKind === "credential"}>
            <div class="collaboration-adoption-card">
              <div>
                <small>IMMUTABLE WALLET ADOPTION · MODELED</small>
                <strong>{model().workload.walletAdoptionEnabled ? "Release-enabled scenario" : "Release-disabled scenario"}</strong>
                <p>The credential/device remains the uploader. It never gains wallet or spending authority.</p>
              </div>
              <button
                type="button"
                class={model().workload.walletAdoptionEnabled ? "secondary-button" : "primary-button"}
                aria-pressed={model().workload.walletAdoptionEnabled}
                onClick={() => modelCredentialAdoption(!model().workload.walletAdoptionEnabled)}
              >
                {model().workload.walletAdoptionEnabled
                  ? "Model adoption disabled"
                  : "Model adoption enabled"}
              </button>
            </div>
          </Show>
          <dl class="collaboration-execution-mini-ledger">
            <div><dt>Basis</dt><dd title={model().commitments.executionBasis}>{short(model().commitments.executionBasis)}</dd></div>
            <div><dt>Grant set</dt><dd title={model().commitments.executionGrantSet}>{short(model().commitments.executionGrantSet)}</dd></div>
            <div><dt>Compute context</dt><dd title={model().commitments.computeAuthorizationContext}>{short(model().commitments.computeAuthorizationContext)}</dd></div>
            <div><dt>Dispatch intent</dt><dd title={model().commitments.computeDispatchIntent}>{short(model().commitments.computeDispatchIntent)}</dd></div>
          </dl>
          <div class="collaboration-execution-boundary-note">
            <LockKeyhole size={14} />
            <span><strong>Failure-lab device spend authority: none.</strong> In this modeled adoption scenario only the wallet could fund the retained exact intent; no live adoption claim is made.</span>
          </div>
        </article>

        <article class="collaboration-execution-panel funding-panel">
          <div class="collaboration-execution-panel-head">
            <div><Banknote size={17} /><span><small>ALL-IN CAP</small><strong>Compute cap + exact reservation</strong></span></div>
            <em>10,000 max</em>
          </div>
          <p class="collaboration-execution-panel-copy">
            Compute uses a capped nonce authorization. Royalty funding uses a
            server-issued reservation ID and exact deposit terms only after every
            fresh owner grant has been authorized.
          </p>
          <div class="collaboration-funding-legs">
            <div>
              <span><Cpu size={15} /></span>
              <div><small>COMPUTE CREDIT VAULT</small><strong>7,000 unit cap</strong><p>Usage-only authorization nonce bound to the derived Compute intent.</p></div>
              <em>{model().funding.computeAuthorizationStatus === "modeled_authorized" ? "MODELED AUTH" : "NOT AUTHORIZED"}</em>
            </div>
            <div>
              <span><Split size={15} /></span>
              <div><small>ROYALTY RESERVATION</small><strong>2,000 exact units</strong><p>Server-issued ID; payer, asset, owner amounts, refund floor, and release binding are exact.</p></div>
              <em>{model().funding.royaltyReservationStatus === "modeled_finalized_active" ? "MODELED FINALIZED" : model().funding.royaltyReservationStatus === "modeled_terms_issued" ? "MODELED TERMS" : "NOT ISSUED"}</em>
            </div>
          </div>
          <div class="collaboration-cap-meter" aria-label="Modeled authorization cap allocation">
            <span style={{ width: "70%" }}>Compute 70%</span>
            <span style={{ width: "20%" }}>Royalty 20%</span>
            <span style={{ width: "10%" }}>Unused 10%</span>
          </div>
          <div class="collaboration-execution-boundary-note warning">
            <ShieldAlert size={14} />
            <span><strong>Failure-lab boundary.</strong> This modeled panel never reads RPC state or moves funds. The implemented rail above may do so only after release, worker, finalized-chain, and exact-intent gates pass.</span>
          </div>
        </article>

        <article class="collaboration-execution-panel evidence-panel">
          <div class="collaboration-execution-panel-head">
            <div><Gauge size={17} /><span><small>TRUTH LEDGER</small><strong>Claim + provider evidence</strong></span></div>
            <em>fail closed</em>
          </div>
          <div class="collaboration-evidence-ledger">
            <div>
              <span classList={{ danger: model().vaultEvidence.status === "stale_fixture" }}><DatabaseZap size={14} /></span>
              <div><strong>Compute vault finality</strong><small>{model().vaultEvidence.status.replaceAll("_", " ")}</small></div>
              <em>{model().vaultEvidence.freshnessProven ? "PROVEN" : "NOT PROVEN"}</em>
            </div>
            <div>
              <span class="warning"><Blocks size={14} /></span>
              <div><strong>Compute journal source</strong><small>{model().computeJournal.projectionStatus.replaceAll("_", " ")}</small></div>
              <em>NOT AUTHENTICATED</em>
            </div>
            <div>
              <span classList={{ ready: Boolean(model().boundedResult) }}><BadgeCheck size={14} /></span>
              <div><strong>Bounded result</strong><small>{model().boundedResult?.resultClass.replaceAll("_", " ") ?? "not observed"}</small></div>
              <em>{model().boundedResult ? "MODELED" : "ABSENT"}</em>
            </div>
            <div>
              <span><ShieldCheck size={14} /></span>
              <div><strong>TDX + independent QVL</strong><small>Purpose-separated production receipts</small></div>
              <em>NOT VERIFIED</em>
            </div>
          </div>
          <Show when={model().computeJournal.reconciliationRequired}>
            <div class="collaboration-reconciliation-card">
              <RefreshCw size={18} />
              <div><small>RECONCILIATION HOLD</small><strong>Do not dispatch again.</strong><p>A provider attempt may exist. Only a later conclusive projection from the trusted local Compute-journal reader can resolve this hold.</p></div>
            </div>
          </Show>
          <div class="collaboration-execution-boundary-note">
            <Fingerprint size={14} />
            <span><strong>Typed projection ≠ journal proof.</strong> Source authentication is false; production requires <code>{model().computeJournal.sourceAuthenticationBoundary}</code>.</span>
          </div>
        </article>
      </div>

      <Show when={model().boundedResult}>
        {(result) => (
          <article class="collaboration-bounded-result" data-result-evidence="modeled-not-qvl">
            <div class="collaboration-result-mark"><BadgeCheck size={25} /></div>
            <div>
              <small>BOUNDED RESULT · MODELED FIXTURE</small>
              <h3>{result().scoreBand.replaceAll("_", " ")}</h3>
              <p>Only a score band, usage commitment, debit, and result commitment are present. Raw provider output is absent.</p>
            </div>
            <dl>
              <div><dt>Compute debit</dt><dd>{result().actualComputeDebit.toLocaleString()} / 7,000</dd></div>
              <div><dt>Result</dt><dd title={result().resultCommitment}>{short(result().resultCommitment)}</dd></div>
              <div><dt>Usage</dt><dd title={result().usageCommitment}>{short(result().usageCommitment)}</dd></div>
              <div><dt>TDX / QVL</dt><dd>not verified</dd></div>
            </dl>
          </article>
        )}
      </Show>

      <section class="collaboration-royalty-workflow" aria-labelledby="collaboration-royalty-model-title">
        <div class="collaboration-royalty-head">
          <div>
            <p class="overline">Royalty settlement · purpose-separated evidence</p>
            <h3 id="collaboration-royalty-model-title">Authorization is not a payout.</h3>
            <p>Each stage needs its own production receipt. Reaching a local model stage never implies an active contract authority, QVL decision, funded distributor, broadcast, finality, credit, or withdrawal.</p>
          </div>
          <span><Split size={16} /> {model().royalty.modeledStage.replaceAll("_", " ")}</span>
        </div>
        <div class="collaboration-royalty-stages">
          <For each={ROYALTY_EVIDENCE_STAGES}>{(stage, index) => {
            const modeledReached = () => {
              if (index() === 0) return royaltyStageReached("reservation_terms_issued");
              if (index() <= 5) return royaltyStageReached("settlement_prepared");
              if (index() === 6) return royaltyStageReached("settlement_finalized");
              return royaltyStageReached("withdrawal_ready");
            };
            return (
              <article classList={{ modeled: modeledReached() }}>
                <div><span>{String(index() + 1).padStart(2, "0")}</span><i>{modeledReached() ? <Check size={12} /> : <CircleDashed size={12} />}</i></div>
                <strong>{stage[0]}</strong>
                <p>{stage[1]}</p>
                <small>{modeledReached() ? "MODELED STAGE · NO LIVE RECEIPT" : "NOT OBSERVED"}</small>
              </article>
            );
          }}</For>
        </div>
        <div class="collaboration-withdrawal-table" role="region" aria-label="Modeled owner withdrawal plan" tabindex="0">
          <div class="collaboration-withdrawal-row header"><span>Owner</span><span>Modeled allocation</span><span>Live credit</span><span>Withdrawal</span></div>
          <For each={model().owners}>{(owner) => (
            <div class="collaboration-withdrawal-row">
              <code>{short(owner.ownerAddress, 12, 8)}</code>
              <span>{owner.modeledWithdrawalAmount.toLocaleString()} units</span>
              <span class="not-observed">Not observed</span>
              <span class="not-observed">Not broadcast</span>
            </div>
          )}</For>
        </div>
        <div class="collaboration-royalty-boundaries">
          <span><ShieldAlert size={13} /> Exact payout validation proven: no</span>
          <span><ShieldAlert size={13} /> Release authority verified: no</span>
          <span><ShieldAlert size={13} /> QVL authorization verified: no</span>
          <span><ShieldAlert size={13} /> Exact finalized reservation observed: no</span>
          <span><ShieldAlert size={13} /> Broadcast / finality observed: no</span>
        </div>
      </section>

      <details class="collaboration-execution-receipt">
        <summary><Fingerprint size={14} /> Inspect the modeled commitment chain</summary>
        <dl>
          <div><dt>Execution basis</dt><dd>{model().commitments.executionBasis}</dd></div>
          <div><dt>Fresh grant set</dt><dd>{model().commitments.executionGrantSet}</dd></div>
          <div><dt>Compute authorization context</dt><dd>{model().commitments.computeAuthorizationContext}</dd></div>
          <div><dt>Compute dispatch intent</dt><dd>{model().commitments.computeDispatchIntent}</dd></div>
          <div><dt>Durable handoff</dt><dd>{model().commitments.computeHandoff}</dd></div>
          <div><dt>Royalty owner amounts</dt><dd>{model().commitments.royaltyOwnerAmounts}</dd></div>
          <div><dt>Royalty reservation ID · modeled</dt><dd>{model().commitments.royaltyReservationId}</dd></div>
          <div><dt>Royalty release binding</dt><dd>{model().commitments.royaltyReleaseBinding}</dd></div>
        </dl>
      </details>

      <footer class="collaboration-execution-footer">
        <div><ShieldCheck size={17} /><span><strong>What the modeled lab proves</strong>Deterministic UI state, exact separation of authorities, and fail-closed recovery semantics.</span></div>
        <div><ShieldAlert size={17} /><span><strong>What the modeled lab does not prove</strong>Live execution, fresh RPC finality, Intel TDX, QVL, funding, settlement, health-data handling, or withdrawals.</span></div>
      </footer>
    </section>
  );
}
