import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show, untrack } from "solid-js";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Award,
  BookOpen,
  Braces,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Code2,
  Cpu,
  FileCode2,
  Fingerprint,
  Gauge,
  Hash,
  Layers3,
  ListChecks,
  LoaderCircle,
  LockKeyhole,
  Medal,
  Microscope,
  Play,
  Plus,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  TimerReset,
  TriangleAlert,
  Trophy,
} from "lucide-solid";
import { shortAddress } from "../lib/contract";
import {
  ARENA_SAFE_IR_STARTER_FILENAME,
  arenaWorkerPresenceMatchesRegistryPreflight,
  arenaSafeIrStarterCandidateBytes,
  candidateCommitment,
  fetchArenaCatalog,
  fetchArenaLeaderboard,
  fetchArenaOwnerSubmissions,
  fetchArenaQueue,
  fetchArenaWorkerCapability,
  prepareArenaSubmission,
  submitPreparedArenaSubmission,
  validateArenaSafeIrCandidateBytes,
  runArenaChallengeRegistryBrowserPreflight,
  type ArenaCatalog,
  type ArenaChallengeRegistryBrowserPreflight,
  type ArenaChallengeManifest,
  type ArenaLeaderboard,
  type ArenaOwnerSubmission,
  type ArenaSubmissionResult,
  type ArenaQueue,
  type ArenaExecutionProvenance,
  type ArenaWorkerCapability,
  type PreparedArenaSubmission,
} from "../lib/arena";
import { wallet, type ArenaWalletTokenResponse } from "../lib/wallet";
import { nextRovingTab } from "../lib/tabs";
import { useModalFocus, type RouteKey } from "../components/AppShell";
import { deployment } from "../config";
import {
  createArenaRankingVerificationContext,
  type VerificationContext,
} from "../lib/verificationContext";
import type { ArenaRouteState, ArenaRouteTab } from "../routes";

type ArenaTab = ArenaRouteTab;
type ChallengeStatus = "MODELED" | "ROADMAP";
type RegistryPreflightState = "not_applicable" | "checking" | "passed" | "blocked";

interface Challenge {
  id: string;
  short: string;
  title: string;
  domain: string;
  status: ChallengeStatus;
  prize: string;
  entries: number;
  time: string;
  metric: string;
  verifier: string;
  description: string;
  accent: string;
  version?: string;
  manifestHash?: string;
  maxSourceBytes?: number;
  apiBacked?: boolean;
  environment?: string;
  candidateKind?: string;
  runtime?: string;
  entrypoint?: string;
  manifest?: ArenaChallengeManifest;
}

interface Ranking {
  rank: number;
  handle: string;
  wallet: string;
  band: string;
  runtime: string;
  receipts: number;
  delta: number;
  updated: string;
  evidence: "illustrative" | "none" | "worker_reported";
  evidenceLabel: string;
  submissionId?: string;
  candidateCommitment?: string;
  provenance?: ArenaExecutionProvenance;
  ladder?: {
    stepIndex: number;
    denominator: number;
    improvementSteps: number;
  };
}

const CHALLENGES: Challenge[] = [
  {
    id: "dnaseq-variant-qc-safe-ir",
    short: "DNA-01",
    title: "Variant QC Safe-IR",
    domain: "DNA sequencing · synthetic variant QC",
    status: "MODELED",
    prize: "No live pool",
    entries: 0,
    time: "Source ready",
    metric: "Quality Ladder band",
    verifier: "sealed://variant-qc-v1",
    description: "Design a deterministic Safe-IR selector for two sealed synthetic quality lanes: truth-supported calls and simulated sequencing artifacts. Bases, reads, alleles, loci, sample IDs, exact scores, and exact timing never leave the confidential evaluator.",
    accent: "mint",
    version: "1.0.0",
    maxSourceBytes: 4_096,
    environment: "synthetic_dnaseq_variant_qc",
    candidateKind: "canonical Safe-IR JSON",
    runtime: "dnai-safe-ir-v1",
    entrypoint: "evaluate",
  },
  {
    id: "atlas-denoise-01",
    short: "AD-01",
    title: "Atlas signal recovery",
    domain: "single-cell RNA-seq",
    status: "MODELED",
    prize: "2.40 ETH",
    entries: 184,
    time: "4d 18h",
    metric: "Ladder reward band",
    verifier: "sealed://atlas-v3",
    description: "Write a program that restores biological signal in a noisy single-cell matrix. The private holdout, labels, and exact reward function remain sealed inside the CVM.",
    accent: "mint",
    maxSourceBytes: 4_096,
    environment: "synthetic_single_cell_assay_qc",
  },
  {
    id: "assay-qc-02",
    short: "AQ-02",
    title: "Assay QC generalization",
    domain: "antigen / antibody QC",
    status: "MODELED",
    prize: "1.20 ETH",
    entries: 92,
    time: "11d 03h",
    metric: "Robustness band",
    verifier: "sealed://assay-qc-v2",
    description: "Produce a bounded quality-control classifier that generalizes across hidden assay batches without exposing private sample attributes or exact failure cases.",
    accent: "violet",
    maxSourceBytes: 4_096,
    environment: "synthetic_antigen_antibody_qc",
  },
  {
    id: "cohort-harmony-01",
    short: "CH-01",
    title: "Cross-cohort harmonization",
    domain: "multi-owner atlas",
    status: "ROADMAP",
    prize: "3.00 ETH",
    entries: 0,
    time: "Opens soon",
    metric: "Joint score band",
    verifier: "sealed://federated-v1",
    description: "Optimize a shared transform across independently governed cohorts. Every owner gate must pass before a joint bounded receipt is released.",
    accent: "gold",
  },
];

const RANKINGS: Ranking[] = [
  { rank: 1, handle: "helix_works", wallet: "0x845A…8C42", band: "EXCEPTIONAL", runtime: "FAST", receipts: 47, delta: 2, updated: "7 min", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 2, handle: "agent/meridian-7", wallet: "0x17C9…A910", band: "EXCEPTIONAL", runtime: "FAST", receipts: 126, delta: -1, updated: "19 min", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 3, handle: "latent_orchid", wallet: "0x51F2…2B0E", band: "HIGH", runtime: "VERY FAST", receipts: 31, delta: 4, updated: "43 min", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 4, handle: "ttt-discover/bio", wallet: "0x22A4…61D8", band: "HIGH", runtime: "FAST", receipts: 284, delta: -1, updated: "1 hr", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 5, handle: "cell_smith", wallet: "0xB824…9E01", band: "HIGH", runtime: "MEDIUM", receipts: 72, delta: 0, updated: "2 hr", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 6, handle: "openproblem_33", wallet: "0xD9A0…14CA", band: "MEDIUM", runtime: "VERY FAST", receipts: 18, delta: 3, updated: "3 hr", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 7, handle: "bayes-bio", wallet: "0x0402…EA76", band: "MEDIUM", runtime: "FAST", receipts: 89, delta: -2, updated: "5 hr", evidence: "illustrative", evidenceLabel: "Modeled sample" },
  { rank: 8, handle: "agent/solace", wallet: "0x92B0…7781", band: "MEDIUM", runtime: "MEDIUM", receipts: 14, delta: 1, updated: "8 hr", evidence: "illustrative", evidenceLabel: "Modeled sample" },
];

const QUEUE = [
  { id: "run_9a30", who: "agent/meridian-7", stage: "Modeled execution", status: "running", eta: "sample only", spend: "sample", evidence: "Illustrative only" },
  { id: "run_f273", who: "latent_orchid", stage: "Modeled policy gate", status: "checking", eta: "sample only", spend: "sample", evidence: "Illustrative only" },
  { id: "run_2d8c", who: "ttt-discover/bio", stage: "Modeled queue", status: "queued", eta: "sample only", spend: "sample", evidence: "Illustrative only" },
  { id: "run_71ab", who: "helix_works", stage: "Modeled queue", status: "queued", eta: "sample only", spend: "sample", evidence: "Illustrative only" },
];

const ARENA_TABS: readonly { key: ArenaTab; label: string; icon: typeof Trophy }[] = [
  { key: "rankings", label: "Rankings", icon: Trophy },
  { key: "spec", label: "Challenge spec", icon: BookOpen },
  { key: "queue", label: "Evaluation queue", icon: ListChecks },
  { key: "submissions", label: "My submissions", icon: FileCode2 },
];

const ARENA_TAB_KEYS = ARENA_TABS.map((item) => item.key);

function catalogChallenge(item: ArenaCatalog["challenges"][number]): Challenge {
  const dnaseq = item.challenge_id === "dnaseq-variant-qc-safe-ir";
  return {
    id: item.challenge_id,
    short: dnaseq ? "DNA-01" : "BIO-01",
    title: item.title,
    domain: dnaseq ? "DNA sequencing · variant QC" : item.data_policy.synthetic_only ? "synthetic bio assay" : "sealed bio assay",
    status: "MODELED",
    prize: "No live pool",
    entries: 0,
    time: dnaseq ? "Source ready" : "Versioned preview",
    metric: `${item.evaluation.metric.replaceAll("_", " ")} · Ladder`,
    verifier: `manifest://${item.manifest_hash.slice(0, 12)}`,
    description: item.summary,
    accent: "mint",
    version: item.version,
    manifestHash: item.manifest_hash,
    maxSourceBytes: item.candidate.max_source_bytes,
    apiBacked: true,
    environment: item.environment,
    candidateKind: item.candidate.kind,
    runtime: item.candidate.runtime,
    entrypoint: item.candidate.entrypoint,
    manifest: item,
  };
}

function RankMedal(props: { rank: number }) {
  if (props.rank <= 3) return <span class={`rank-medal rank-${props.rank}`}><Medal size={15} />{props.rank}</span>;
  return <span class="rank-number">{props.rank}</span>;
}

function Trend(props: { value: number }) {
  if (props.value > 0) return <span class="trend up"><ArrowUp size={12} />{props.value}</span>;
  if (props.value < 0) return <span class="trend down"><ArrowDown size={12} />{Math.abs(props.value)}</span>;
  return <span class="trend flat">—</span>;
}

export function Arena(props: {
  navigate: (route: RouteKey) => void;
  inspectEvidence: (context: VerificationContext) => void;
  routeState?: ArenaRouteState;
  navigateArena: (route: ArenaRouteState) => void;
}) {
  const [challengeId, setChallengeId] = createSignal(props.routeState?.challengeId ?? CHALLENGES[0].id);
  const [challengeVersion, setChallengeVersion] = createSignal<string | undefined>(props.routeState?.version);
  const [tab, setTab] = createSignal<ArenaTab>(props.routeState?.tab ?? "rankings");
  const [search, setSearch] = createSignal("");
  const [submitOpen, setSubmitOpen] = createSignal(false);
  const [submissionFile, setSubmissionFile] = createSignal<File>();
  const [submissionHash, setSubmissionHash] = createSignal<`sha256:${string}`>();
  const [submissionError, setSubmissionError] = createSignal("");
  const [hashing, setHashing] = createSignal(false);
  const [submitting, setSubmitting] = createSignal(false);
  const [preparedSubmission, setPreparedSubmission] = createSignal<PreparedArenaSubmission>();
  const [submissionResult, setSubmissionResult] = createSignal<ArenaSubmissionResult>();
  const [catalog, setCatalog] = createSignal<ArenaCatalog>();
  const [publicQueue, setPublicQueue] = createSignal<ArenaQueue>();
  const [publicLeaderboard, setPublicLeaderboard] = createSignal<ArenaLeaderboard>();
  const [workerCapability, setWorkerCapability] = createSignal<ArenaWorkerCapability>();
  const [workerCapabilityError, setWorkerCapabilityError] = createSignal("");
  const [arenaSession, setArenaSession] = createSignal<ArenaWalletTokenResponse>();
  const [arenaSessionWalletVersion, setArenaSessionWalletVersion] = createSignal<number>();
  const [ownerSubmissions, setOwnerSubmissions] = createSignal<ArenaOwnerSubmission[]>([]);
  const [ownerNextCursor, setOwnerNextCursor] = createSignal<string | null>(null);
  const [ownerState, setOwnerState] = createSignal<"signed_out" | "authorizing" | "loading" | "ready" | "error">("signed_out");
  const [ownerError, setOwnerError] = createSignal("");
  const [apiState, setApiState] = createSignal<"preview" | "loading" | "connected" | "error">("preview");
  const [apiError, setApiError] = createSignal("");
  const [projectionState, setProjectionState] = createSignal<"idle" | "loading" | "ready" | "error">("idle");
  const [projectionError, setProjectionError] = createSignal("");
  const [projectionRefreshing, setProjectionRefreshing] = createSignal(false);
  const [registryPreflightState, setRegistryPreflightState] = createSignal<RegistryPreflightState>("not_applicable");
  const [registryBrowserPreflight, setRegistryBrowserPreflight] = createSignal<ArenaChallengeRegistryBrowserPreflight>();
  const [registryPreflightError, setRegistryPreflightError] = createSignal("");
  let submissionDialogRef: HTMLElement | undefined;

  const challenges = createMemo(() => {
    const liveCatalog = catalog();
    if (!liveCatalog) return CHALLENGES;
    const live = liveCatalog.challenges.map(catalogChallenge);
    const liveKeys = new Set(live.map((item) => `${item.id}@${item.version ?? ""}`));
    return [...live, ...CHALLENGES.filter((item) => !liveKeys.has(`${item.id}@${item.version ?? ""}`))];
  });

  const challenge = createMemo(() => challenges().find((item) => (
    item.id === challengeId()
    && (!challengeVersion() || item.version === challengeVersion())
  )) ?? challenges()[0]);
  const rankings = createMemo(() => {
    const needle = search().trim().toLowerCase();
    const boundedRows = publicLeaderboard()?.rows.map((row) => {
      return {
        rank: row.rank,
        handle: `entrant-${row.identity.project_id_hash.slice(0, 8)}`,
        wallet: `wallet:${row.identity.wallet_address_hash.slice(0, 10)}…`,
        band: `STEP ${row.leaderboard_step_index}/${row.step_denominator}`,
        runtime: row.execution_provenance.status === "worker_reported" ? "EXECUTED" : "NO ROW EVIDENCE",
        receipts: row.improvement_steps_so_far,
        delta: 0,
        updated: "released in bounded batch",
        evidence: row.execution_provenance.status === "worker_reported" ? "worker_reported" : "none",
        evidenceLabel: row.execution_provenance.status === "worker_reported" ? "QVL-bound claim" : "No row evidence",
        submissionId: row.submission_id,
        candidateCommitment: row.candidate_commitment,
        provenance: row.execution_provenance,
        ladder: {
          stepIndex: row.leaderboard_step_index,
          denominator: row.step_denominator,
          improvementSteps: row.improvement_steps_so_far,
        },
      } satisfies Ranking;
    });
    const source = challenge().apiBacked ? boundedRows ?? [] : RANKINGS;
    return needle ? source.filter((row) => `${row.handle} ${row.wallet}`.toLowerCase().includes(needle)) : source;
  });

  const queueRows = createMemo(() => {
    if (!challenge().apiBacked) return QUEUE;
    return (publicQueue()?.submissions ?? []).map((run) => ({
      id: run.submission_id,
      who: `entrant-${run.identity.project_id_hash.slice(0, 8)}`,
      stage: run.state.replaceAll("_", " "),
      status: run.state === "sealed_eval" || run.state === "public_tests" ? "running" : run.state === "policy_screen" ? "checking" : "queued",
      eta: "timing sealed",
      spend: "no charge",
      evidence: run.execution_provenance.status === "worker_reported" ? "QVL-bound claim" : "No execution evidence",
    }));
  });

  const safeIrWorkerPresenceMatchesPreflight = createMemo(() => Boolean(
    challenge().runtime === "dnai-safe-ir-v1"
      && arenaWorkerPresenceMatchesRegistryPreflight(
        workerCapability(),
        registryBrowserPreflight(),
      ),
  ));

  const submissionConfigured = createMemo(() => Boolean(
    challenge().apiBacked
      && registryPreflightState() === "passed"
      && deployment.arenaSubmissionEnabled
      && deployment.delegateUrl
      && deployment.composeHash
      && /^sha256:[0-9a-f]{64}$/.test(deployment.arenaVerifiedQuoteSha256),
  ));

  const briefExample = createMemo(() => {
    const entrypoint = challenge().entrypoint ?? "solve";
    if (challenge().runtime === "dnai-safe-ir-v1") {
      return `{"negative_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],"positive_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}`;
    }
    if (entrypoint === "process") {
      return `def process(positive_wells, negative_wells):\n    # Return bounded control selections only.\n    return positive_wells, negative_wells`;
    }
    return `def ${entrypoint}(public_inputs, sealed_inputs):\n    # Return only the challenge-declared output.\n    return result`;
  });

  const downloadSafeIrStarter = () => {
    const bytes = arenaSafeIrStarterCandidateBytes();
    const objectUrl = URL.createObjectURL(new Blob(
      [new TextDecoder("utf-8", { fatal: true }).decode(bytes)],
      { type: "application/json" },
    ));
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = ARENA_SAFE_IR_STARTER_FILENAME;
    anchor.click();
    queueMicrotask(() => URL.revokeObjectURL(objectUrl));
  };

  let projectionRequest = 0;
  const refreshSelectedChallenge = async (announce = true): Promise<void> => {
    const selected = challenge();
    if (!selected.apiBacked || !selected.version || projectionRefreshing()) return;
    const request = ++projectionRequest;
    const selectedId = selected.id;
    const selectedVersion = selected.version;
    setProjectionRefreshing(true);
    if (announce || (!publicQueue() && !publicLeaderboard())) setProjectionState("loading");
    setProjectionError("");
    try {
      const [queue, board] = await Promise.all([
        fetchArenaQueue(selectedId, selectedVersion),
        fetchArenaLeaderboard(selectedId, selectedVersion),
      ]);
      if (
        request !== projectionRequest
        || challengeId() !== selectedId
        || challenge().version !== selectedVersion
      ) return;
      setPublicQueue(queue);
      setPublicLeaderboard(board);
      setProjectionState("ready");
    } catch (cause) {
      if (
        request !== projectionRequest
        || challengeId() !== selectedId
        || challenge().version !== selectedVersion
      ) return;
      setProjectionState("error");
      setProjectionError(cause instanceof Error ? cause.message : "Arena projections are unavailable");
    } finally {
      if (request === projectionRequest) setProjectionRefreshing(false);
    }
  };

  onMount(() => {
    setApiState("loading");
    void fetchArenaCatalog()
      .then((nextCatalog) => {
        setCatalog(nextCatalog);
        const requested = props.routeState;
        const selected = requested
          ? nextCatalog.challenges.find((item) => item.challenge_id === requested.challengeId && item.version === requested.version)
          : nextCatalog.challenges[0];
        const fallback = selected ?? nextCatalog.challenges[0];
        setChallengeId(fallback?.challenge_id ?? CHALLENGES[0].id);
        setChallengeVersion(fallback?.version);
        if (requested && !selected) {
          setApiError(`Challenge ${requested.challengeId} ${requested.version} is not in the bounded catalog.`);
        } else if (!requested && fallback) {
          props.navigateArena({ challengeId: fallback.challenge_id, version: fallback.version, tab: "rankings" });
        }
        setApiState("connected");
        if (!requested || selected) setApiError("");
      })
      .catch((cause) => {
        setApiState("error");
        setApiError(cause instanceof Error ? cause.message : "Arena API is unavailable");
      });
  });

  createEffect(() => {
    const requested = props.routeState;
    if (!requested) return;
    // Tab routing is independent of API availability. A shareable queue/spec link
    // must still select the requested surface while the bounded catalog is offline.
    setTab(requested.tab);
    const liveCatalog = catalog();
    if (!liveCatalog) {
      const local = CHALLENGES.find((item) => (
        item.id === requested.challengeId && item.version === requested.version
      ));
      if (local) {
        setChallengeId(local.id);
        setChallengeVersion(local.version);
      }
      return;
    }
    const selected = liveCatalog.challenges.find((item) => (
      item.challenge_id === requested.challengeId && item.version === requested.version
    ));
    if (!selected) {
      setApiError(`Challenge ${requested.challengeId} ${requested.version} is not in the bounded catalog.`);
      return;
    }
    setChallengeId(selected.challenge_id);
    setChallengeVersion(selected.version);
  });

  createEffect(() => {
    const selected = challenge();
    ++projectionRequest;
    setPublicQueue(undefined);
    setPublicLeaderboard(undefined);
    setProjectionError("");
    if (!selected.apiBacked || !selected.version) {
      setProjectionState("idle");
      setProjectionRefreshing(false);
      return;
    }
    setProjectionState("loading");
    setProjectionRefreshing(false);
    untrack(() => void refreshSelectedChallenge(false));
    const poll = window.setInterval(() => {
      if (document.visibilityState === "visible") void refreshSelectedChallenge(false);
    }, 30_000);
    onCleanup(() => {
      window.clearInterval(poll);
      ++projectionRequest;
      setProjectionRefreshing(false);
    });
  });

  createEffect(() => {
    const selected = challenge();
    setWorkerCapability(undefined);
    setWorkerCapabilityError("");
    if (!selected.apiBacked || !selected.version) return;
    const selectedId = selected.id;
    const selectedVersion = selected.version;
    void fetchArenaWorkerCapability(selectedId, selectedVersion)
      .then((capability) => {
        if (challenge().id !== selectedId || challenge().version !== selectedVersion) return;
        setWorkerCapability(capability);
      })
      .catch((cause) => {
        if (challenge().id !== selectedId || challenge().version !== selectedVersion) return;
        setWorkerCapability(undefined);
        setWorkerCapabilityError(cause instanceof Error ? cause.message : "Worker presence is unavailable");
      });
  });

  createEffect(() => {
    const selected = challenge();
    const currentAccount = wallet.account()?.toLowerCase();
    const currentWalletVersion = wallet.authorizationVersion();
    const session = arenaSession();
    if (
      !session
      || !currentAccount
      || !wallet.isCorrectChain()
      || arenaSessionWalletVersion() !== currentWalletVersion
      || session.address.toLowerCase() !== currentAccount
      || session.challenge_id !== selected.id
      || session.challenge_version !== selected.version
      || session.expires_at <= Math.floor(Date.now() / 1000) + 5
    ) {
      if (session) {
        setArenaSession(undefined);
        setArenaSessionWalletVersion(undefined);
      }
      setOwnerSubmissions([]);
      setOwnerNextCursor(null);
      setOwnerError("");
      setOwnerState("signed_out");
    }
  });

  createEffect(() => {
    const selected = challenge();
    const manifest = selected.manifest;
    setRegistryBrowserPreflight(undefined);
    setRegistryPreflightError("");
    if (!selected.apiBacked || !selected.version || !manifest) {
      setRegistryPreflightState("not_applicable");
      return;
    }
    const selectedId = selected.id;
    const selectedVersion = selected.version;
    const selectedManifestHash = manifest.manifest_hash;
    setRegistryPreflightState("checking");
    void runArenaChallengeRegistryBrowserPreflight(manifest)
      .then((preflight) => {
        if (
          challenge().id !== selectedId
          || challenge().version !== selectedVersion
          || challenge().manifest?.manifest_hash !== selectedManifestHash
        ) return;
        setRegistryBrowserPreflight(preflight);
        setRegistryPreflightState("passed");
      })
      .catch((cause) => {
        if (
          challenge().id !== selectedId
          || challenge().version !== selectedVersion
          || challenge().manifest?.manifest_hash !== selectedManifestHash
        ) return;
        setRegistryBrowserPreflight(undefined);
        setRegistryPreflightState("blocked");
        setRegistryPreflightError(cause instanceof Error ? cause.message : "ChallengeRegistry browser preflight failed closed");
      });
  });

  const selectFile = async (file: File | undefined) => {
    if (!file) return;
    setSubmissionError("");
    setSubmissionHash(undefined);
    setSubmissionResult(undefined);
    setPreparedSubmission(undefined);
    const maximum = challenge().maxSourceBytes ?? 8 * 1024;
    if (file.size <= 0 || file.size > maximum) {
      setSubmissionFile(undefined);
      setSubmissionError(`Program must be between 1 byte and ${maximum.toLocaleString()} bytes for this challenge version.`);
      return;
    }
    setHashing(true);
    setSubmissionFile(file);
    let bytes: Uint8Array | undefined;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (challenge().runtime === "dnai-safe-ir-v1") validateArenaSafeIrCandidateBytes(bytes);
      setSubmissionHash(await candidateCommitment(bytes));
    } catch (cause) {
      setSubmissionFile(undefined);
      setSubmissionError(cause instanceof Error ? cause.message : "Could not hash this program");
    } finally {
      bytes?.fill(0);
      setHashing(false);
    }
  };

  const chooseChallenge = (next: Challenge) => {
    if (next.id === challengeId() && next.version === challengeVersion()) return;
    setChallengeId(next.id);
    setChallengeVersion(next.version);
    setSubmissionFile(undefined);
    setSubmissionHash(undefined);
    setPreparedSubmission(undefined);
    setSubmissionResult(undefined);
    setSubmissionError("");
    if (next.version) {
      props.navigateArena({
        challengeId: next.id,
        version: next.version,
        tab: tab(),
      });
    } else {
      props.navigate("arena");
    }
  };

  const chooseTab = (next: ArenaTab): void => {
    setTab(next);
    const selected = challenge();
    if (selected.version) {
      props.navigateArena({ challengeId: selected.id, version: selected.version, tab: next });
    }
  };

  const selectTabFromKeyboard = (event: KeyboardEvent, current: ArenaTab): void => {
    const next = nextRovingTab(ARENA_TAB_KEYS, current, event.key);
    if (!next) return;
    event.preventDefault();
    chooseTab(next);
    queueMicrotask(() => document.getElementById(`arena-tab-${next}`)?.focus());
  };

  const loadOwnerPage = async (
    token: ArenaWalletTokenResponse,
    cursor: string | null = null,
    append = false,
  ): Promise<void> => {
    const selected = challenge();
    if (!selected.apiBacked || !selected.version) throw new Error("Choose an API-backed challenge first");
    if (
      token.challenge_id !== selected.id
      || token.challenge_version !== selected.version
      || token.address.toLowerCase() !== wallet.account()?.toLowerCase()
      || !wallet.isCorrectChain()
      || arenaSessionWalletVersion() !== wallet.authorizationVersion()
    ) throw new Error("Arena wallet session no longer matches this challenge");
    setOwnerState("loading");
    setOwnerError("");
    const page = await fetchArenaOwnerSubmissions(
      selected.id,
      selected.version,
      token.access_token,
      { limit: 25, cursor },
    );
    if (
      challenge().id !== selected.id
      || challenge().version !== selected.version
      || wallet.account()?.toLowerCase() !== token.address.toLowerCase()
      || !wallet.isCorrectChain()
      || arenaSessionWalletVersion() !== wallet.authorizationVersion()
    ) return;
    setOwnerSubmissions((current) => append ? [...current, ...page.submissions] : page.submissions);
    setOwnerNextCursor(page.next_cursor);
    setOwnerState("ready");
  };

  const authorizeOwnerView = async (): Promise<void> => {
    const selected = challenge();
    if (!selected.apiBacked || !selected.version || !wallet.account()) {
      setOwnerError("Choose an API-backed challenge and connect a wallet first.");
      setOwnerState("error");
      return;
    }
    setOwnerState("authorizing");
    setOwnerError("");
    try {
      const token = await wallet.authorizeArenaSession(selected.id, selected.version);
      setArenaSessionWalletVersion(wallet.authorizationVersion());
      setArenaSession(token);
      await loadOwnerPage(token);
    } catch (cause) {
      setOwnerError(cause instanceof Error ? cause.message : "Arena wallet authorization failed");
      setOwnerState("error");
    }
  };

  const loadMoreOwnerSubmissions = async (): Promise<void> => {
    const token = arenaSession();
    const cursor = ownerNextCursor();
    if (!token || !cursor) return;
    try {
      await loadOwnerPage(token, cursor, true);
    } catch (cause) {
      setOwnerError(cause instanceof Error ? cause.message : "Could not load the next owner page");
      setOwnerState("error");
    }
  };

  const refreshOwnerView = async (): Promise<void> => {
    const token = arenaSession();
    if (!token) {
      await authorizeOwnerView();
      return;
    }
    try {
      await loadOwnerPage(token);
    } catch (cause) {
      setOwnerError(cause instanceof Error ? cause.message : "Could not refresh your submissions");
      setOwnerState("error");
    }
  };

  const submitProgram = async (): Promise<void> => {
    const file = submissionFile();
    const selected = challenge();
    const manifest = selected.manifest;
    if (!file || !submissionHash() || !manifest || !selected.apiBacked || !selected.version || !wallet.account()) {
      setSubmissionError("Select the API-backed challenge, connect a wallet, and choose a valid program first.");
      return;
    }
    if (!submissionConfigured()) {
      setSubmissionError(registryPreflightError() || "Encrypted submission remains locked until this browser passes the exact ChallengeRegistry preflight and the independently verified CVM pins are present.");
      return;
    }
    setSubmitting(true);
    setSubmissionError("");
    let source: Uint8Array | undefined;
    try {
      if (!wallet.isCorrectChain()) await wallet.switchToBase();
      const account = wallet.account()?.toLowerCase();
      const walletVersion = wallet.authorizationVersion();
      if (!account || !wallet.isCorrectChain()) {
        throw new Error("Connect a Base Sepolia wallet before preparing an Arena submission");
      }
      let prepared = preparedSubmission();
      if (
        !prepared
        || prepared.challengeId !== selected.id
        || prepared.challengeVersion !== selected.version
        || prepared.payload.manifest.challenge_manifest_hash !== manifest.manifest_hash
        || prepared.candidateCommitment !== submissionHash()
        || prepared.sourceBytes !== file.size
        || prepared.walletAddress !== account
      ) {
        source = new Uint8Array(await file.arrayBuffer());
        const localCommitment = await candidateCommitment(source);
        if (localCommitment !== submissionHash()) throw new Error("The selected program changed after it was committed. Choose it again.");
        prepared = await prepareArenaSubmission({ source, challenge: manifest, walletAddress: account });
        setPreparedSubmission(prepared);
      }
      if (
        wallet.authorizationVersion() !== walletVersion
        || !wallet.isCorrectChain()
        || wallet.account()?.toLowerCase() !== account
      ) throw new Error("Wallet session changed while preparing the Arena submission; prepare it again");
      const token = await wallet.authorizeArenaSession(selected.id, selected.version);
      if (
        wallet.authorizationVersion() !== walletVersion
        || !wallet.isCorrectChain()
        || wallet.account()?.toLowerCase() !== token.address.toLowerCase()
        || prepared.walletAddress !== token.address.toLowerCase()
      ) {
        throw new Error("Wallet session changed before the Arena submission; authorize it again");
      }
      const result = await submitPreparedArenaSubmission(prepared, token.access_token, manifest);
      if (
        wallet.authorizationVersion() !== walletVersion
        || !wallet.isCorrectChain()
        || wallet.account()?.toLowerCase() !== token.address.toLowerCase()
      ) throw new Error("Wallet session changed while the Arena submission was in flight; refresh your owner view before continuing");
      setArenaSessionWalletVersion(walletVersion);
      setArenaSession(token);
      setSubmissionResult(result);
      setSubmissionFile(undefined);
      setSubmissionHash(undefined);
      setPreparedSubmission(undefined);
      await refreshSelectedChallenge();
      await loadOwnerPage(token);
    } catch (cause) {
      setSubmissionError(cause instanceof Error ? cause.message : "Encrypted Arena submission failed");
    } finally {
      source?.fill(0);
      setSubmitting(false);
    }
  };

  const closeSubmissionDialog = (): void => {
    if (submitting()) return;
    setSubmitOpen(false);
    setSubmissionResult(undefined);
    setSubmissionError("");
  };

  useModalFocus(submitOpen, () => submissionDialogRef, closeSubmissionDialog);

  return (
    <div class="page-wrap product-page arena-page">
      <header class="product-page-head arena-head">
        <div>
          <p class="overline">Sealed evaluation network</p>
          <h1>DNA + bio challenge arena</h1>
          <p>Humans and agents can prepare submissions for synthetic public tasks. Private DNA, assay, or cohort holdouts may enter only after the exact release and per-job verification gates pass.</p>
        </div>
        <button class="primary-button large" type="button" disabled={!challenge().apiBacked} title={challenge().apiBacked ? undefined : challenge().version ? "Submission requires the fresh API, frozen contract gate, and release-bound CVM" : "Modeled challenge previews cannot accept submissions"} onClick={() => setSubmitOpen(true)}><Plus size={17} /> Submit program</button>
      </header>

      <div class={`environment-banner ${safeIrWorkerPresenceMatchesPreflight() ? "live" : "modeled"}`} role="status" aria-live="polite"><Sparkles size={17} /><div>
        <strong>{apiState() === "connected"
          ? safeIrWorkerPresenceMatchesPreflight() ? "Release-bound Safe-IR worker present" : "Modeled Arena API connected"
          : apiState() === "loading" ? "Checking the modeled Arena API" : "Modeled competition preview"}</strong>
        <span>{apiState() === "connected"
          ? safeIrWorkerPresenceMatchesPreflight()
            ? "A fresh authenticated heartbeat matches the deployed source SHA, image, release policy, catalog, and Safe-IR runtime. This presence record is not TDX evidence: the worker registry check is startup-scoped, and every job still requires fresh independent quote/QVL and execution-policy gates. General Python remains preview-only."
            : `The versioned challenge, durable queue, owner projection, and bounded Ladder ranking come from the service. Execution remains modeled until the deployed descriptor and a fresh matching Safe-IR heartbeat are present.${workerCapabilityError() ? ` Presence note: ${workerCapabilityError()}` : ""}${apiError() ? ` Catalog note: ${apiError()}` : ""}`
          : `Competitors, rewards, queue activity, and rankings are illustrative until the fresh evaluator is deployed.${apiState() === "error" && apiError() ? ` API note: ${apiError()}` : ""}`}</span>
      </div></div>

      <Show when={challenge().apiBacked}>
        <div class={`environment-banner ${registryPreflightState() === "blocked" ? "warning" : "modeled"}`} role="status" aria-live="polite">
          {registryPreflightState() === "checking" ? <LoaderCircle class="spin" size={17} /> : <ShieldCheck size={17} />}
          <div>
            <strong>{registryPreflightState() === "passed" ? "Browser registry preflight passed" : registryPreflightState() === "checking" ? "Running browser registry preflight" : "Browser registry preflight blocked"}</strong>
            <span>{registryPreflightState() === "passed"
              ? `This browser read a finalized Base Sepolia block and matched release-approved set ${registryBrowserPreflight()?.approvedChallengeSetSha256.slice(0, 19)}… to ChallengeRegistry #${registryBrowserPreflight()?.registryChallengeId} version ${registryBrowserPreflight()?.registryVersion}: Open, unpaused, frozen, code-hash pinned, and commitment-matched. This browser observation is not authority. Its exact block/hash snapshot is bound into the ciphertext request, and the proxy must independently re-read every field before persistence; any worker must still enforce separate per-job release and runtime gates.${safeIrWorkerPresenceMatchesPreflight() ? " Its authenticated presence tuple matches this browser preflight, but presence is not job authorization." : " Execution remains modeled and disconnected."}`
              : registryPreflightState() === "checking"
                ? "This browser is reading exact runtime bytecode, lifecycle, current version, freeze state, and immutable challenge commitments from Base Sepolia. The API and worker have not been authorized by this read."
                : registryPreflightError() || "This browser could not match the catalog version to the pinned ChallengeRegistry release tuple."}</span>
          </div>
        </div>
      </Show>

      <div class="arena-layout">
        <aside class="challenge-sidebar" aria-label="Challenge selector" tabIndex={0}>
          <div class="sidebar-label"><Trophy size={15} /> Challenges</div>
          <For each={challenges()}>
            {(item) => (
              <button
                class={`challenge-nav ${challengeId() === item.id && challengeVersion() === item.version ? "active" : ""}`}
                type="button"
                aria-pressed={challengeId() === item.id && challengeVersion() === item.version}
                onClick={() => chooseChallenge(item)}
              >
                <span class={`challenge-icon ${item.accent}`}><Microscope size={18} /></span>
                <span><small>{item.short} · {item.status}</small><strong>{item.title}</strong><em>{item.domain}</em></span>
                <ChevronRight size={15} />
              </button>
            )}
          </For>
          <div class="sidebar-callout">
            <LockKeyhole size={18} />
            <strong>Why sealed?</strong>
            <p>Exact hidden rewards would let adaptive agents reconstruct the private holdout. Wikigen releases quantized Ladder bands and, after deployment, a verifiable bounded receipt.</p>
          </div>
        </aside>

        <div class="challenge-main">
          <section class={`challenge-hero ${challenge().accent}`}>
            <div class="challenge-hero-copy">
              <div class="challenge-kicker"><span class="status-dot" />{challenge().status} · {challenge().short}</div>
              <h2>{challenge().title}</h2>
              <p>{challenge().description}</p>
              <div class="challenge-meta-row">
                <span><Award size={15} /><small>{challenge().apiBacked ? "BOUNTY STATUS · NO LIVE POOL" : `${challenge().status} · ILLUSTRATIVE BOUNTY`}</small><strong>{challenge().prize}</strong></span>
                <span><Code2 size={15} /><small>{challenge().apiBacked ? "PUBLIC API · QUEUE COUNT" : `${challenge().status} · ILLUSTRATIVE ENTRIES`}</small><strong>{challenge().apiBacked ? publicQueue()?.submission_count ?? "—" : challenge().entries}</strong></span>
                <span><Clock3 size={15} /><small>{challenge().apiBacked ? `${challenge().status} · DECLARED WINDOW` : `${challenge().status} · ILLUSTRATIVE WINDOW`}</small><strong>{challenge().time}</strong></span>
                <span><Gauge size={15} /><small>{challenge().apiBacked ? "PUBLIC MANIFEST · BOUNDED METRIC" : `${challenge().status} · ILLUSTRATIVE METRIC`}</small><strong>{challenge().metric}</strong></span>
              </div>
            </div>
            <div class="challenge-vault" aria-hidden="true">
              <div class="vault-grid" />
              <div class="vault-core"><Fingerprint size={30} /></div>
              <span class="vault-label">PRIVATE HOLDOUT</span>
              <code>{challenge().verifier}</code>
            </div>
          </section>

          <nav class="subtabs" aria-label="Challenge sections" role="tablist">
            <For each={ARENA_TABS}>
              {(item) => {
                const Icon = item.icon;
                return <button id={`arena-tab-${item.key}`} type="button" class={tab() === item.key ? "active" : ""} role="tab" aria-selected={tab() === item.key} aria-controls={`arena-panel-${item.key}`} tabindex={tab() === item.key ? 0 : -1} onClick={() => chooseTab(item.key)} onKeyDown={(event) => selectTabFromKeyboard(event, item.key)}><Icon size={15} />{item.label}</button>;
              }}
            </For>
          </nav>

          <Show when={tab() === "rankings"}>
            <section id="arena-panel-rankings" class="leaderboard-panel" role="tabpanel" aria-labelledby="arena-tab-rankings" tabindex="0">
              <div class="leaderboard-toolbar">
              <div><p class="overline">Public Ladder release + row provenance</p><h3>{challenge().apiBacked ? "Versioned rankings" : "Modeled rankings"}</h3></div>
                <div class="leaderboard-controls">
                  <label class="search-field"><Search size={15} /><span class="sr-only">Search ranking handle or wallet hash</span><input type="search" value={search()} onInput={(event) => setSearch(event.currentTarget.value)} placeholder="Search handle or wallet" /></label>
                  <div class="worker-presence-indicator" role="status" aria-live="polite" title="Worker presence is not proof for any result row">
                    <Activity size={14} /><span>{safeIrWorkerPresenceMatchesPreflight() ? "Worker present · inspect each row" : "Worker absent · rows remain explicit"}</span>
                  </div>
                  <Show when={challenge().apiBacked}><button class="secondary-button projection-refresh" type="button" aria-busy={projectionRefreshing()} disabled={projectionRefreshing()} onClick={() => void refreshSelectedChallenge()}><RefreshCw class={projectionRefreshing() ? "spin" : ""} size={14} /> {projectionRefreshing() ? "Refreshing" : "Refresh"}</button></Show>
                </div>
              </div>
              <div class="leaderboard-notice"><ShieldCheck size={15} /><span>Exact reward, hidden-label errors, outputs, and private examples never appear here. The public rank uses the Ladder step; ties resolve by earlier release time and then submission ID.</span></div>
              <Show when={challenge().apiBacked && projectionState() === "error"}><div class="projection-error" role="alert"><TriangleAlert size={15} /><span><strong>Rankings could not be refreshed.</strong> {projectionError()} {publicLeaderboard() ? "The last bounded projection remains visible and may be stale." : "No ranking data is being shown as an empty result."}</span><button class="secondary-button" type="button" disabled={projectionRefreshing()} onClick={() => void refreshSelectedChallenge()}>Retry</button></div></Show>
              <Show when={challenge().apiBacked && projectionState() === "loading" && !publicLeaderboard()}><div class="projection-loading" role="status" aria-live="polite"><LoaderCircle class="spin" size={16} /> Loading the bounded public ranking…</div></Show>
              <div class="leaderboard-scroll" role="region" aria-label={`${challenge().title} rankings table`} tabindex="0">
                <table class="leaderboard-table">
                  <caption class="sr-only">Public bounded rankings and row-level evidence state for {challenge().title}</caption>
                  <thead><tr><th>Rank</th><th>Competitor</th><th>Ladder release</th><th>Execution</th><th>Improvements</th><th>Movement</th><th>Released</th><th>Evidence</th></tr></thead>
                  <tbody>
                    <For each={rankings()}>
                      {(row) => (
                        <tr>
                          <td><RankMedal rank={row.rank} /></td>
                          <td><div class="competitor"><span>{row.handle.slice(0, 1).toUpperCase()}</span><div><strong>{row.handle}</strong><small class="mono">{row.wallet}</small></div></div></td>
                          <td><span class={`band-pill ${row.band.toLowerCase()}`}>{row.band}</span></td>
                          <td><span class="runtime-pill"><Activity size={12} />{row.runtime}</span></td>
                          <td>{row.receipts}</td>
                          <td><Trend value={row.delta} /></td>
                          <td>{row.updated}</td>
                          <td><button
                            class="proof-button"
                            type="button"
                            title={row.evidence === "worker_reported" ? "Worker-reported QVL binding; not independently verified by this browser" : row.evidence === "illustrative" ? "Illustrative ranking only; no execution occurred" : "No per-row execution evidence is attached"}
                            onClick={() => props.inspectEvidence(createArenaRankingVerificationContext({
                              challengeId: challenge().id,
                              challengeVersion: challenge().version,
                              rank: row.rank,
                              evidence: row.evidence,
                              submissionId: row.submissionId,
                              candidateCommitment: row.candidateCommitment,
                              ladder: row.ladder,
                              provenance: row.provenance,
                            }))}
                          ><Fingerprint size={14} /> Inspect {row.evidenceLabel}</button></td>
                        </tr>
                      )}
                    </For>
                    <Show when={rankings().length === 0 && projectionState() !== "loading" && projectionState() !== "error"}>
                      <tr><td colspan="8"><div class="table-empty"><Trophy size={19} /><span>No bounded ranking rows have been released for this challenge version.</span></div></td></tr>
                    </Show>
                  </tbody>
                </table>
              </div>
              <div class="leaderboard-foot" aria-live="polite"><span>Showing {rankings().length} {challenge().apiBacked ? "bounded public competitors" : "illustrative competitors"}</span><span>{rankings().filter((row) => row.evidence === "worker_reported").length} worker-reported · 0 browser-verified · exact rewards withheld</span></div>
            </section>
          </Show>

          <Show when={tab() === "spec"}>
            <section id="arena-panel-spec" class="brief-grid" role="tabpanel" aria-labelledby="arena-tab-spec" tabindex="0">
              <article class="brief-copy">
                <p class="overline">Objective</p>
                <h3>{challenge().title}</h3>
                <p>{challenge().runtime === "dnai-safe-ir-v1"
                  ? safeIrWorkerPresenceMatchesPreflight()
                    ? <>Write a canonical Safe-IR selector for two sealed, synthetic per-variant quality lanes: truth-supported calls and simulated sequencing artifacts. Fresh authenticated worker presence matches this release, but it is not row-level TDX evidence. Registry checking is startup-scoped; each candidate still needs fresh independent quote/QVL and execution-policy gates. Bases, reads, alleles, loci, sample IDs, exact scores, and exact timing never leave the boundary.</>
                    : <>Write a canonical Safe-IR selector for two sealed, synthetic per-variant quality lanes. The interpreter and fail-closed worker source are ready, but execution remains modeled until a deployed release descriptor and fresh matching authenticated heartbeat are available. No bases, reads, alleles, loci, sample IDs, exact scores, or timing are disclosed.</>
                  : challenge().apiBacked
                    ? <>Submit a bounded <code>{challenge().candidateKind}</code> source file exposing <code>{challenge().entrypoint}</code> under <code>{challenge().runtime}</code>. This release validates encrypted queue ingress only; it does not execute hostile code or charge Compute Credits.</>
                    : <>This is an illustrative challenge brief. A future versioned manifest will define the exact candidate contract, runtime, resource policy, and bounded release.</>}</p>
                <h4>Public interface</h4>
                <pre class="code-panel" role="region" tabindex="0" aria-label={`${challenge().title} public interface example`}><code>{briefExample()}</code></pre>
                <h4>Hard gates</h4>
                <ul class="check-list">
                  <li><CheckCircle2 size={15} /> Exact challenge version and manifest commitment</li>
                  <li><CheckCircle2 size={15} /> Quote-pinned recipient key and report-data binding</li>
                  <li><CheckCircle2 size={15} /> Ciphertext-only durable ingress with no source egress</li>
                  <li><CheckCircle2 size={15} /> {safeIrWorkerPresenceMatchesPreflight() ? "Release-bound presence and startup registry match; per-job quote/QVL and policy gates remain" : "Worker execution stays modeled without fresh matching release evidence"}</li>
                </ul>
              </article>
              <aside class="brief-aside">
                <div class="spec-card"><Braces size={19} /><div><small>CANDIDATE</small><strong>{challenge().candidateKind ?? "Versioned program"}</strong></div></div>
                <div class="spec-card"><Cpu size={19} /><div><small>DECLARED RUNTIME</small><strong>{challenge().runtime ?? "Roadmap"} · {safeIrWorkerPresenceMatchesPreflight() ? "live Safe-IR only" : "not running"}</strong></div></div>
                <div class="spec-card"><Layers3 size={19} /><div><small>ENVIRONMENT</small><strong>{challenge().environment?.replaceAll("_", " ") ?? "Not published"}</strong></div></div>
                <div class="spec-card"><LockKeyhole size={19} /><div><small>SEALED DATA</small><strong>Private holdout + reward</strong></div></div>
                <Show
                  when={challenge().runtime === "dnai-safe-ir-v1"}
                  fallback={<div class="non-action-state roadmap"><Code2 size={16} /> Starter kit · roadmap</div>}
                >
                  <button class="starter-kit-button" type="button" onClick={downloadSafeIrStarter}>
                    <Code2 size={16} /> Download byte-exact Safe-IR starter
                  </button>
                </Show>
              </aside>
            </section>
          </Show>

          <Show when={tab() === "queue"}>
            <section id="arena-panel-queue" class="queue-panel" role="tabpanel" aria-labelledby="arena-tab-queue" tabindex="0">
              <div class="queue-head"><div><p class="overline">{challenge().apiBacked ? "Bounded public projection" : "Modeled scheduler"}</p><h3>{challenge().apiBacked ? "Versioned evaluation queue" : "Evaluation queue preview"}</h3></div><div class="projection-actions"><div class="queue-stat"><TimerReset size={17} /><span><small>{challenge().apiBacked ? "DISCLOSED" : "SAMPLE MEDIAN"}</small><strong>{challenge().apiBacked ? publicQueue()?.submission_count ?? "—" : "6m 18s"}</strong></span></div><Show when={challenge().apiBacked}><button class="secondary-button projection-refresh" type="button" aria-busy={projectionRefreshing()} disabled={projectionRefreshing()} onClick={() => void refreshSelectedChallenge()}><RefreshCw class={projectionRefreshing() ? "spin" : ""} size={14} /> {projectionRefreshing() ? "Refreshing" : "Refresh"}</button></Show></div></div>
              <Show when={challenge().apiBacked && projectionState() === "error"}><div class="projection-error" role="alert"><TriangleAlert size={15} /><span><strong>Queue status could not be refreshed.</strong> {projectionError()} {publicQueue() ? "The last bounded projection remains visible and may be stale." : "No queue data is being presented as an empty queue."}</span><button class="secondary-button" type="button" disabled={projectionRefreshing()} onClick={() => void refreshSelectedChallenge()}>Retry</button></div></Show>
              <Show when={challenge().apiBacked && projectionState() === "loading" && !publicQueue()}><div class="projection-loading" role="status" aria-live="polite"><LoaderCircle class="spin" size={16} /> Loading the bounded public queue…</div></Show>
              <For each={queueRows()}>
                {(run, index) => (
                  <div class="queue-row">
                    <span class="queue-position">{index() + 1}</span>
                    <div class={`queue-state ${run.status}`}>{run.status === "running" || run.status === "checking" ? <LoaderCircle class="spin" size={15} /> : <CircleDot size={15} />}</div>
                    <div><strong>{run.id}</strong><small>{run.who}</small></div>
                    <div><small>STAGE</small><strong>{run.stage}</strong></div>
                    <div><small>UPDATED</small><strong>{run.eta}</strong></div>
                    <div><small>CREDITS</small><strong>{run.spend}</strong></div>
                    <span class="queue-detail-state"><LockKeyhole size={13} /> {run.evidence}</span>
                  </div>
                )}
              </For>
              <Show when={queueRows().length === 0 && projectionState() !== "loading" && projectionState() !== "error"}>
                <div class="empty-state compact-empty"><ListChecks size={24} /><h3>{challenge().apiBacked ? "The public queue is empty" : "The modeled queue is empty"}</h3><p>No encrypted candidate commitments have entered this challenge version.</p></div>
              </Show>
            </section>
          </Show>

          <Show when={tab() === "submissions"}>
            <section id="arena-panel-submissions" class="owner-submissions-panel" role="tabpanel" aria-labelledby="arena-tab-submissions" tabindex="0">
              <div class="owner-submissions-head">
                <div><p class="overline">Wallet-private · bounded</p><h3>My submissions</h3></div>
                <Show when={arenaSession()}>
                  <span class="owner-session-badge"><ShieldCheck size={13} /> challenge-version scoped</span>
                </Show>
              </div>
              <div class="leaderboard-notice"><LockKeyhole size={15} /><span>This view is filtered only by the address recovered from your signed Arena session. It omits encrypted object references, source, exact scores or rewards, timing, and internal errors.</span></div>

              <Show when={!challenge().apiBacked}>
                <div class="empty-state compact-empty"><FileCode2 size={24} /><h3>{challenge().version ? "Submission service is not connected" : "Choose a versioned service challenge"}</h3><p>{challenge().version ? "This source-ready challenge version has no wallet-authenticated API in the current release. Owner records stay unavailable until its frozen contract gate and release-bound CVM are activated." : "Illustrative challenge cards have no owner records or wallet-authenticated API."}</p></div>
              </Show>

              <Show when={challenge().apiBacked && !wallet.account()}>
                <div class="owner-auth-card"><Fingerprint size={25} /><div><h4>Connect your Base Sepolia wallet</h4><p>Use the wallet control in the header, then return here to sign the exact submit + owner-read session request. No transaction or fund transfer is requested.</p></div></div>
              </Show>

              <Show when={challenge().apiBacked && wallet.account() && !arenaSession()}>
                <div class="owner-auth-card">
                  {ownerState() === "authorizing" ? <LoaderCircle class="spin" size={25} /> : <Fingerprint size={25} />}
                  <div><h4>Authorize this challenge version</h4><p>Sign once to create a short-lived token carrying only <code>challenge:submit</code> and <code>challenge:submissions:read</code> for {challenge().id} {challenge().version}.</p></div>
                  <button class="primary-button" type="button" onClick={() => void authorizeOwnerView()} disabled={ownerState() === "authorizing"}>
                    {ownerState() === "authorizing" ? <LoaderCircle class="spin" size={15} /> : <ShieldCheck size={15} />}
                    {ownerState() === "authorizing" ? "Waiting for signature…" : "Sign and load mine"}
                  </button>
                </div>
                <Show when={ownerError()}><p class="form-error owner-error" role="alert">{ownerError()}</p></Show>
              </Show>

              <Show when={challenge().apiBacked && arenaSession()}>
                <div class="owner-session-strip"><span><Fingerprint size={14} /><code>{shortAddress(arenaSession()?.address ?? "", 8)}</code></span><span>Exact version · {challenge().version}</span><span>Timing withheld from records</span></div>
                <Show when={ownerError()}><p class="form-error owner-error" role="alert">{ownerError()}</p></Show>
                <Show when={ownerState() === "loading" && ownerSubmissions().length === 0}>
                  <div class="owner-loading" role="status" aria-live="polite"><LoaderCircle class="spin" size={20} /><span>Loading the authenticated bounded projection…</span></div>
                </Show>
                <div class="owner-submission-list">
                  <For each={ownerSubmissions()}>
                    {(item) => (
                      <article class="owner-submission-row">
                        <div class="owner-submission-icon"><FileCode2 size={17} /></div>
                        <div class="owner-submission-primary"><strong>{item.submission_id}</strong><small><code>{shortAddress(item.candidate_commitment, 13)}</code> · {item.manifest.runtime}</small></div>
                        <div><small>STATE</small><strong>{item.state.replaceAll("_", " ")}</strong></div>
                        <div><small>BOUNDED RESULT</small><strong>{item.bounded_result ? item.bounded_result.accepted ? `step ${item.bounded_result.leaderboard_step_index}/${item.bounded_result.step_denominator}` : "not accepted" : "not released"}</strong></div>
                        <span class="owner-private-pill"><LockKeyhole size={12} /> {item.execution_provenance.status === "worker_reported" ? "worker claim · not browser-verified" : "no execution evidence"}</span>
                      </article>
                    )}
                  </For>
                </div>
                <Show when={ownerState() === "ready" && ownerSubmissions().length === 0}>
                  <div class="empty-state compact-empty"><FileCode2 size={24} /><h3>No submissions for this wallet</h3><p>This exact challenge version has no records owned by the authenticated address.</p><button class="primary-button" type="button" onClick={() => setSubmitOpen(true)}><Send size={16} /> Prepare encrypted submission</button></div>
                </Show>
                <div class="owner-submissions-actions">
                  <button class="secondary-button" type="button" onClick={() => void refreshOwnerView()} disabled={ownerState() === "loading"}><Activity size={14} /> Refresh bounded status</button>
                  <Show when={ownerNextCursor()}>
                    <button class="primary-button" type="button" onClick={() => void loadMoreOwnerSubmissions()} disabled={ownerState() === "loading"}>{ownerState() === "loading" ? <LoaderCircle class="spin" size={14} /> : <ArrowDown size={14} />} Load next 25</button>
                  </Show>
                </div>
              </Show>
            </section>
          </Show>
        </div>
      </div>

      <Show when={submitOpen()}>
        <div class="dialog-backdrop" role="presentation" onClick={closeSubmissionDialog}>
          <section ref={(element) => { submissionDialogRef = element; }} class="submission-dialog" role="dialog" aria-modal="true" aria-labelledby="submit-title" tabindex="-1" onClick={(event) => event.stopPropagation()}>
            <button class="dialog-x" type="button" aria-label="Close submission dialog" data-autofocus onClick={closeSubmissionDialog} disabled={submitting()}>×</button>
            <div class="dialog-mark"><FileCode2 size={22} /></div>
            <Show when={submissionResult()} fallback={<>
              <p class="overline">{challenge().short} · ciphertext-only ingress</p>
              <h2 id="submit-title">Prepare an encrypted queue record</h2>
              <p>Your source is hashed locally, browser-preflighted against the exact frozen Base Sepolia challenge version, encrypted to the independently quote-pinned Arena recipient, authorized by your wallet, and sent as ciphertext only. The proposed finalized block/hash snapshot is cryptographically bound to the ciphertext; the proxy independently verifies it before either durable write.</p>
              <div class="submission-steps"><span class="done">1 <em>Commit</em></span><i /><span>2 <em>Verify + encrypt</em></span><i /><span>3 <em>Authorize</em></span><i /><span>4 <em>Queue</em></span></div>
              <label class="file-drop compact-drop"><input type="file" accept={challenge().runtime === "dnai-safe-ir-v1" ? ".json,application/json" : ".py,.zip,.tar.gz"} disabled={submitting()} onChange={(event) => void selectFile(event.currentTarget.files?.[0])} /><FileCode2 size={23} /><span><strong>{submissionFile()?.name || (challenge().runtime === "dnai-safe-ir-v1" ? "Choose a canonical Safe-IR JSON program" : "Choose a Python file or package")}</strong><small>{hashing() ? "Hashing locally…" : `Maximum ${(challenge().maxSourceBytes ?? 8 * 1024).toLocaleString()} bytes · plaintext never enters the request body`}</small></span></label>
              <Show when={submissionError()}><p class="form-error" role="alert">{submissionError()}</p></Show>
              <Show when={submissionHash()}><div class="hash-preview"><Hash size={15} /><code>{shortAddress(submissionHash() ?? "", 14)}</code></div></Show>
              <div class="submission-policy"><ShieldCheck size={16} /><span>{safeIrWorkerPresenceMatchesPreflight()
                ? "This creates a ciphertext-only queue record. The release-bound Safe-IR worker may claim it only after independent per-job gates pass. It does not charge Compute Credits, expose the sealed object reference, or promise a reward."
                : "This creates a durable modeled queue projection only. It does not reserve or charge Compute Credits, execute the program, expose a sealed object reference, or promise a reward."}</span></div>
              <button
                class="primary-button large full"
                type="button"
                onClick={() => void submitProgram()}
                disabled={!submissionConfigured() || !challenge().apiBacked || !submissionFile() || !submissionHash() || !wallet.account() || hashing() || submitting()}
              >
                {submitting() ? <LoaderCircle class="spin" size={17} /> : <Play size={17} />}
                {submitting()
                  ? "Verifying, encrypting, and authorizing…"
                  : !challenge().apiBacked
                    ? "Choose the API-backed challenge"
                    : registryPreflightState() === "checking"
                      ? "Running browser registry preflight"
                      : registryPreflightState() === "blocked"
                        ? "Browser registry preflight blocked"
                        : !submissionConfigured()
                          ? "Fresh independently verified CVM required"
                      : !wallet.account()
                        ? "Connect a wallet to continue"
                        : "Encrypt and create modeled record"}
                <ArrowRight size={16} />
              </button>
              <p class="modeled-note"><Sparkles size={13} /> This client requires the exact release-approved challenge-set digest, selected id/version commitments, the independently approved TDX quote/compose identity, and a finalized browser-side Base Sepolia snapshot. The snapshot is only a proposal: proxy authorization exists only after the service independently matches its pinned block/hash and contract state. Queue acceptance never grants worker execution authorization.</p>
            </>}>{(result) => <>
              <p class="overline">Ciphertext accepted · bounded queue</p>
              <h2 id="submit-title">Submission receipt created</h2>
              <div class="credential-callout"><CheckCircle2 size={18} /><div><strong>{result().submission.submission_id}</strong><span>{result().created ? "A new ciphertext-only record entered the modeled queue." : "The service returned the original record for this idempotent replay."}</span></div></div>
              <div class="envelope-facts"><div><span>Candidate commitment</span><code>{shortAddress(result().submission.candidate_commitment, 14)}</code></div><div><span>Ciphertext commitment</span><code>{shortAddress(result().candidate_ingress.ciphertext_sha256, 14)}</code></div><div><span>Recipient key</span><code>{shortAddress(result().candidate_ingress.key_id, 14)}</code></div><div><span>Ingress registry check</span><strong>Proxy verified pinned finalized block</strong></div><div><span>Execution</span><strong>{safeIrWorkerPresenceMatchesPreflight() ? "Per-job gates required" : "Not connected"}</strong></div><div><span>Credits charged</span><strong>0</strong></div><div><span>Raw source egress</span><strong>False</strong></div></div>
              <button class="primary-button large full" type="button" onClick={() => { closeSubmissionDialog(); chooseTab("submissions"); }}><FileCode2 size={17} /> View my submissions</button>
              <p class="modeled-note"><ShieldCheck size={13} /> This receipt proves only that the proxy independently matched the exact AEAD-bound snapshot at one RPC-reported finalized block before persistence. The browser preflight was not accepted as authority, RPC quorum and consensus proof were not established, and worker execution remains unauthorized until its separate per-job registry, release, TDX/QVL, and policy gates pass.</p>
            </>}</Show>
          </section>
        </div>
      </Show>
    </div>
  );
}
