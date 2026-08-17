import {
  createMemo,
  createSignal,
  For,
  onCleanup,
  onMount,
  Show,
} from "solid-js";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Clock3,
  ArrowDown,
  EyeOff,
  Fingerprint,
  History,
  KeyRound,
  ListChecks,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Signature,
  UserRoundCheck,
  WalletCards,
  XCircle,
} from "lucide-solid";
import { deployment } from "../config";
import { publicErrorText } from "../lib/errorText";
import {
  appendReviewQueuePage,
  fetchReviewQueue,
  issueReviewChallenge,
  REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
  reviewQueueSnapshotKey,
  reviewReleaseConfigured,
  reviewReleaseScopeKey,
  ReviewQueueRestartRequiredError,
  startReviewQueueWindow,
  submitReviewDecision,
  type ReviewDecision,
  type ReviewQueueWindow,
  type ReviewTicket,
} from "../lib/review";
import { requestWalletAuthSignature, wallet } from "../lib/wallet";

export interface ReviewAuthorityReadiness {
  safeBrowserAdapterConfigured: boolean;
  releasePolicyPinned: boolean;
  reviewerSetPinned: boolean;
  signatureDomainPinned: boolean;
  releaseIdentityVerified: boolean;
}

export function reviewAuthorityReady(input: ReviewAuthorityReadiness): boolean {
  return input.safeBrowserAdapterConfigured
    && input.releasePolicyPinned
    && input.reviewerSetPinned
    && input.signatureDomainPinned
    && input.releaseIdentityVerified;
}

export interface ReviewQueueRequestScope {
  walletAddress: string;
  walletAuthorizationVersion: number;
  chainId: number | string | null | undefined;
  routedRole: string;
  releaseScope: string;
}

export function reviewQueueRequestScopeKey(
  scope: ReviewQueueRequestScope,
): string {
  return JSON.stringify([
    scope.walletAddress.toLowerCase(),
    scope.walletAuthorizationVersion,
    scope.chainId ?? "",
    scope.routedRole,
    scope.releaseScope,
  ]);
}

type ReviewSurfaceState = "modeled" | "loading" | "live" | "held";

interface ModeledReview {
  kind: "modeled";
  id: string;
  lane: string;
  title: string;
  purpose: string;
  requestedOutput: string;
  outputClass: string;
  policy: string;
  hold: string;
  sequence: string;
}

interface LiveReview {
  kind: "live";
  id: string;
  ticket: ReviewTicket;
  lane: string;
  title: string;
  purpose: string;
  requestedOutput: string;
  outputClass: string;
  policy: string;
  hold: string;
  sequence: string;
}

type EmptyReview = Omit<ModeledReview, "kind"> & { kind: "empty" };
type ReviewItem = ModeledReview | EmptyReview | LiveReview;

const MODELED_REVIEWS: readonly ModeledReview[] = Object.freeze([
  Object.freeze({
    kind: "modeled",
    id: "RQ-MODEL-041",
    lane: "Arena result",
    title: "Publish a challenge score band",
    purpose: "Update a public ranking after a confidential evaluation",
    requestedOutput: "Score band + candidate commitment",
    outputClass: "Band · commitment",
    policy: "bounded-ranking.v1",
    hold: "Release authority bundle absent",
    sequence: "Illustrative order 01",
  }),
  Object.freeze({
    kind: "modeled",
    id: "RQ-MODEL-042",
    lane: "Compute output",
    title: "Return a workload completion receipt",
    purpose: "Report a bounded job outcome to the requesting principal",
    requestedOutput: "Outcome code + usage-receipt reference",
    outputClass: "Code · hash reference",
    policy: "bounded-compute-result.v1",
    hold: "Runtime evidence adapter absent",
    sequence: "Illustrative order 02",
  }),
  Object.freeze({
    kind: "modeled",
    id: "RQ-MODEL-043",
    lane: "Diligence finding",
    title: "Release an evaluator finding band",
    purpose: "Return a narrowly declared diligence conclusion",
    requestedOutput: "Finding band + reason code",
    outputClass: "Band · enum",
    policy: "bounded-diligence.v1",
    hold: "Reviewer identity set absent",
    sequence: "Illustrative order 03",
  }),
]);

const EMPTY_LIVE_REVIEW: EmptyReview = Object.freeze({
  kind: "empty",
  id: "RQ-LIVE-EMPTY",
  lane: "Current release",
  title: "No review tickets are queued",
  purpose: "The verified hash-only queue is empty under the current release authority.",
  requestedOutput: "No decision available",
  outputClass: "No public payload",
  policy: "Current release policy",
  hold: "Nothing requires reviewer action",
  sequence: "Anchored empty queue",
});

const OUTPUT_CONTROLS = Object.freeze([
  Object.freeze({
    title: "Declared output class",
    detail: "Only the named band, enum, count range, or commitment may be considered for release.",
    state: "SOURCE REQUIREMENT",
  }),
  Object.freeze({
    title: "Exact schema and field allowlist",
    detail: "Unexpected fields, free-form text, attachments, and nested payloads fail the browser parser closed.",
    state: "CLIENT ENFORCED",
  }),
  Object.freeze({
    title: "Anti-reconstruction review",
    detail: "Repeated queries, joins, and auxiliary context must not turn bounded outputs into source recovery.",
    state: "HUMAN CHECK",
  }),
  Object.freeze({
    title: "Purpose and recipient binding",
    detail: "The request, intended use, recipient, expiry, and release policy must share one signed domain.",
    state: "AUTHORITY CHECK",
  }),
  Object.freeze({
    title: "Independent rollback witness",
    detail: "Live decisions are accepted only after the browser rechecks the release-pinned finalized Base Sepolia anchor.",
    state: "RELEASE GATED",
  }),
]);

const MODELED_HOLDS = Object.freeze([
  Object.freeze({
    title: "Safe browser authority not configured",
    detail: "No release-bound delegate, current reviewer policy, or finalized rollback witness is configured in this build.",
  }),
  Object.freeze({
    title: "Policy authority not pinned",
    detail: "No live policy digest, reviewer threshold, active roster projection, or revocation head can be established.",
  }),
  Object.freeze({
    title: "Release identity not verified",
    detail: "The browser has no exact contract, CVM, signed ceremony, and workload lineage to compare with the service.",
  }),
  Object.freeze({
    title: "Freshness cannot be established",
    detail: "No authoritative challenge expiry, monotonic sequence, or current anchored queue head is available.",
  }),
]);

const MODELED_REVIEWERS = Object.freeze([
  Object.freeze({ role: "Policy reviewer", duty: "Output schema, purpose, and reconstruction risk" }),
  Object.freeze({ role: "Evidence reviewer", duty: "Release identity and execution-evidence chain" }),
  Object.freeze({ role: "Release custodian", duty: "Threshold, expiry, revocation, and final publication" }),
]);

function shortHash(value: string, size = 7): string {
  return value ? `${value.slice(0, size)}…${value.slice(-size)}` : "—";
}

function timestamp(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value * 1_000));
}

function liveReview(ticket: ReviewTicket, index: number, policy: string): LiveReview {
  const remaining = Math.max(0, ticket.required_approvals - ticket.approvals_count);
  return Object.freeze({
    kind: "live",
    id: ticket.ticket_ref_hash,
    ticket,
    lane: ticket.routed_role.replaceAll("-", " "),
    title: `Held result ${shortHash(ticket.ticket_ref_hash)}`,
    purpose: "Resolve one hash-only bounded-egress ticket under the current release reviewer authority.",
    requestedOutput: ticket.status === "pending" ? "Release or deny" : ticket.status,
    outputClass: "Opaque commitments only",
    policy: shortHash(policy),
    hold: ticket.status === "pending"
      ? `${remaining} more approval${remaining === 1 ? "" : "s"} required`
      : `Terminal state · ${ticket.status}`,
    sequence: `Anchored row ${String(index + 1).padStart(2, "0")}`,
  });
}

function GatePill(props: { children: string }) {
  return <span class="review-gate-pill"><LockKeyhole size={12} />{props.children}</span>;
}

export function ReviewQueue() {
  const releaseConfigured = reviewReleaseConfigured();
  const [surfaceState, setSurfaceState] = createSignal<ReviewSurfaceState>(
    releaseConfigured ? "loading" : "modeled",
  );
  const [listing, setListing] = createSignal<ReviewQueueWindow>();
  const [selectedId, setSelectedId] = createSignal(MODELED_REVIEWS[0].id);
  const [selectedRole, setSelectedRole] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");
  const [paginationError, setPaginationError] = createSignal("");
  const [paginationAnnouncement, setPaginationAnnouncement] = createSignal("");
  const [paginationNeedsRestart, setPaginationNeedsRestart] = createSignal(false);
  const [busy, setBusy] = createSignal<
    "" | "refresh" | "load-more" | ReviewDecision
  >("");
  let queueRequestGeneration = 0;
  let activeQueueController: AbortController | undefined;

  const queue = createMemo(() => listing()?.snapshot);
  const verifiedListingVisible = createMemo(() => Boolean(
    listing()
    && surfaceState() !== "modeled"
    && surfaceState() !== "loading",
  ));

  const items = createMemo<readonly ReviewItem[]>(() => {
    const current = listing();
    if (
      !current
      || surfaceState() === "modeled"
      || surfaceState() === "loading"
    ) return MODELED_REVIEWS;
    if (current.tickets.length === 0) return Object.freeze([EMPTY_LIVE_REVIEW]);
    return current.tickets.map((ticket, index) => (
      liveReview(ticket, index, current.snapshot.authority.policy_sha256)
    ));
  });
  const selected = createMemo<ReviewItem>(() => (
    items().find((item) => item.id === selectedId()) ?? items()[0] ?? (surfaceState() === "live" ? EMPTY_LIVE_REVIEW : MODELED_REVIEWS[0])
  ));
  const readiness = createMemo<ReviewAuthorityReadiness>(() => {
    const current = queue();
    const live = surfaceState() === "live" && Boolean(current);
    return {
      safeBrowserAdapterConfigured: live,
      releasePolicyPinned: live && Boolean(current?.authority.policy_sha256),
      reviewerSetPinned: live && Boolean(current?.authority.active_reviewers.active_reviewers_sha256),
      signatureDomainPinned: live
        && current?.authority.release_context.wallet_domain === deployment.walletAuthDomain
        && current?.authority.release_context.wallet_uri === deployment.walletAuthUri,
      releaseIdentityVerified: live && current?.authority.rollback_protection === "base_sepolia_execution_policy_anchor",
    };
  });
  const authorityReady = createMemo(() => reviewAuthorityReady(readiness()));
  const selectedLive = createMemo(() => {
    const item = selected();
    return item.kind === "live" ? item : undefined;
  });
  const selectedPending = createMemo(() => selectedLive()?.ticket.status === "pending");
  const decisionReady = createMemo(() => Boolean(
    authorityReady()
    && selectedPending()
    && wallet.account()
    && wallet.provider()
    && wallet.isCorrectChain()
    && !busy(),
  ));
  const approvalCount = createMemo(() => (
    listing()?.tickets.reduce(
      (sum, ticket) => sum + ticket.approvals_count,
      0,
    ) ?? 0
  ));
  const roleOptions = createMemo(() => queue()?.authority.roles ?? []);

  function currentQueueRequestScope(): string {
    return reviewQueueRequestScopeKey({
      walletAddress: wallet.account() ?? "",
      walletAuthorizationVersion: wallet.authorizationVersion(),
      chainId: wallet.chainId(),
      routedRole: selectedRole(),
      releaseScope: reviewReleaseScopeKey(),
    });
  }

  function beginQueueRequest(): {
    controller: AbortController;
    generation: number;
    scope: string;
  } {
    activeQueueController?.abort();
    const controller = new AbortController();
    activeQueueController = controller;
    return {
      controller,
      generation: ++queueRequestGeneration,
      scope: currentQueueRequestScope(),
    };
  }

  function queueRequestIsCurrent(context: {
    controller: AbortController;
    generation: number;
    scope: string;
  }): boolean {
    return !context.controller.signal.aborted
      && context.generation === queueRequestGeneration
      && context.scope === currentQueueRequestScope();
  }

  function selectFirstAvailable(current: ReviewQueueWindow): void {
    if (
      !current.tickets.some(
        (ticket) => ticket.ticket_ref_hash === selectedId(),
      )
    ) {
      setSelectedId(
        current.tickets[0]?.ticket_ref_hash ?? EMPTY_LIVE_REVIEW.id,
      );
    }
  }

  async function refreshQueue(
    options: { quiet?: boolean } = {},
  ): Promise<ReviewQueueWindow | undefined> {
    if (!releaseConfigured) return undefined;
    const requestContext = beginQueueRequest();
    setBusy("refresh");
    if (!options.quiet) setNotice("");
    setError("");
    setPaginationError("");
    setPaginationAnnouncement("");
    setPaginationNeedsRestart(false);
    if (!listing()) setSurfaceState("loading");
    try {
      const next = await fetchReviewQueue({
        limit: REVIEW_QUEUE_DEFAULT_PAGE_SIZE,
        routedRole: selectedRole() || undefined,
        signal: requestContext.controller.signal,
      });
      if (!queueRequestIsCurrent(requestContext)) return undefined;
      const nextListing = startReviewQueueWindow(next);
      setListing(nextListing);
      setSurfaceState("live");
      selectFirstAvailable(nextListing);
      setPaginationAnnouncement(
        `${nextListing.loaded_count} review ticket${
          nextListing.loaded_count === 1 ? "" : "s"
        } loaded from the first page.`,
      );
      if (!options.quiet) {
        setNotice(`Verified queue head ${shortHash(next.authority.rollback_anchor.state_hash)} at Base Sepolia sequence ${next.authority.rollback_anchor.sequence}.`);
      }
      return nextListing;
    } catch (cause) {
      if (!queueRequestIsCurrent(requestContext)) return undefined;
      setSurfaceState("held");
      setError(publicErrorText(
        cause instanceof Error ? cause.message : cause,
        "Review authority verification failed",
      ));
      return undefined;
    } finally {
      if (requestContext.generation === queueRequestGeneration) {
        setBusy("");
      }
    }
  }

  async function loadMoreQueue(): Promise<void> {
    const current = listing();
    const cursor = current?.next_cursor;
    if (
      !current
      || !current.has_more
      || !cursor
      || busy()
      || paginationNeedsRestart()
      || surfaceState() !== "live"
    ) return;
    const requestContext = beginQueueRequest();
    setBusy("load-more");
    setPaginationError("");
    setPaginationAnnouncement("");
    try {
      const nextPage = await fetchReviewQueue({
        cursor,
        limit: current.page_size,
        routedRole: current.routed_role ?? undefined,
        signal: requestContext.controller.signal,
      });
      if (
        !queueRequestIsCurrent(requestContext)
        || listing() !== current
      ) return;
      const appended = appendReviewQueuePage(current, nextPage, cursor);
      setListing(appended);
      setSurfaceState("live");
      setPaginationNeedsRestart(false);
      setPaginationAnnouncement(
        `Loaded ${appended.loaded_count - current.loaded_count} additional review ticket${
          appended.loaded_count - current.loaded_count === 1 ? "" : "s"
        }. ${appended.loaded_count} displayed.`,
      );
    } catch (cause) {
      if (!queueRequestIsCurrent(requestContext)) return;
      const detail = publicErrorText(
        cause instanceof Error ? cause.message : cause,
        "The next review queue page was rejected",
      );
      setPaginationError(detail);
      if (cause instanceof ReviewQueueRestartRequiredError) {
        setPaginationNeedsRestart(true);
        setSurfaceState("held");
        setError(
          "The queue changed while pages were loading. Restart from the first page before reviewing or signing.",
        );
      }
    } finally {
      if (requestContext.generation === queueRequestGeneration) {
        setBusy("");
      }
    }
  }

  function changeRoleFilter(nextRole: string): void {
    if (busy() || nextRole === selectedRole()) return;
    ++queueRequestGeneration;
    activeQueueController?.abort();
    setSelectedRole(nextRole);
    setSelectedId(EMPTY_LIVE_REVIEW.id);
    void refreshQueue({ quiet: true });
  }

  async function decide(decision: ReviewDecision): Promise<void> {
    const currentListing = listing();
    const currentQueue = currentListing?.snapshot;
    const item = selected();
    if (
      !currentListing
      || !currentQueue
      || item.kind !== "live"
      || item.ticket.status !== "pending"
    ) return;
    setBusy(decision);
    setError("");
    setNotice("");
    let submitted = false;
    let decisionScope = "";
    let decisionSnapshot = "";
    try {
      if (!wallet.account() || !wallet.provider()) {
        throw new Error("Connect an allowlisted reviewer wallet before signing a decision");
      }
      if (!wallet.isCorrectChain()) await wallet.switchToBase();
      const address = wallet.account();
      const provider = wallet.provider();
      const walletVersion = wallet.authorizationVersion();
      if (!address || !provider || !wallet.isCorrectChain()) {
        throw new Error("Reviewer wallet is not connected to Base Sepolia");
      }
      decisionScope = currentQueueRequestScope();
      decisionSnapshot = reviewQueueSnapshotKey(currentQueue);
      const decisionContextIsCurrent = () => {
        const latest = listing();
        return Boolean(
          latest
          && currentQueueRequestScope() === decisionScope
          && reviewQueueSnapshotKey(latest.snapshot) === decisionSnapshot,
        );
      };
      const challenge = await issueReviewChallenge(
        {
          authority: currentQueue.authority,
          tickets: currentListing.tickets,
        },
        item.ticket,
        address,
        decision,
      );
      if (
        !decisionContextIsCurrent()
        ||
        wallet.account()?.toLowerCase() !== address.toLowerCase()
        || wallet.provider() !== provider
        || wallet.authorizationVersion() !== walletVersion
        || !wallet.isCorrectChain()
      ) throw new Error("Wallet account or network changed before review signing");

      const signature = await requestWalletAuthSignature(provider, address, challenge.message);
      if (
        !decisionContextIsCurrent()
        ||
        wallet.account()?.toLowerCase() !== address.toLowerCase()
        || wallet.provider() !== provider
        || wallet.authorizationVersion() !== walletVersion
        || !wallet.isCorrectChain()
      ) throw new Error("Wallet account or network changed during review signing");

      submitted = true;
      const next = await submitReviewDecision(challenge.nonce, signature);
      if (
        !decisionContextIsCurrent()
        || next.authority.authority_context_hash
          !== currentQueue.authority.authority_context_hash
        || next.authority.policy_sha256
          !== currentQueue.authority.policy_sha256
      ) {
        throw new Error(
          "Review release or wallet context changed while recording the decision",
        );
      }
      const reconciled = await refreshQueue({ quiet: true });
      if (!reconciled) {
        setError(
          "The decision receipt verified, but the selected role page could not be refreshed. Restart from the first page before signing again.",
        );
        return;
      }
      setNotice(
        decision === "release"
          ? "Signed approval recorded. Release occurs only when the current M-of-N threshold is satisfied."
          : "Signed denial recorded. The bounded ticket is now denied under the current authority.",
      );
    } catch (cause) {
      const detail = publicErrorText(
        cause instanceof Error ? cause.message : cause,
        "Review decision failed",
      );
      if (submitted) {
        const ambiguous = `The signed decision may have committed but its receipt was not verified: ${detail}.`;
        const reconciled = decisionScope
          && currentQueueRequestScope() === decisionScope
          ? await refreshQueue({ quiet: true })
          : undefined;
        if (reconciled) {
          setError(`${ambiguous} The current anchored head is now displayed; inspect the ticket before signing again.`);
        } else {
          setError(`${ambiguous} The wallet or release scope changed; restart from the first page before signing again.`);
        }
      } else {
        setError(detail);
      }
    } finally {
      setBusy("");
    }
  }

  onMount(() => {
    if (releaseConfigured) void refreshQueue({ quiet: true });
  });
  onCleanup(() => {
    ++queueRequestGeneration;
    activeQueueController?.abort();
  });

  return (
    <div class="page-wrap product-page review-queue-page">
      <header class="product-page-head review-page-head">
        <div>
          <p class="overline">Human release review · bounded egress control</p>
          <h1>Review what may leave—not what stayed private.</h1>
          <p>
            One release desk joins a declared output, a current reviewer policy,
            a wallet signature, and a finalized rollback witness. Raw artifacts,
            reviewer identities, and signature bytes never appear in this interface.
          </p>
        </div>
        <Show
          when={releaseConfigured}
          fallback={(
            <span class="primary-button large review-authority-button review-nonaction-status" role="status">
              <LockKeyhole size={17} /> Control plane release-gated
            </span>
          )}
        >
          <button
            class="primary-button large review-authority-button"
            type="button"
            onClick={() => void refreshQueue()}
            disabled={busy() === "refresh"}
            aria-describedby="review-authority-boundary"
          >
            <Show when={busy() === "refresh"} fallback={<RefreshCw size={17} />}>
              <LoaderCircle class="spin" size={17} />
            </Show>
            {busy() === "refresh" ? "Verifying authority…" : "Refresh anchored queue"}
          </button>
        </Show>
      </header>

      <div
        id="review-authority-boundary"
        class={`environment-banner review-roadmap-banner ${surfaceState() === "live" ? "live" : surfaceState() === "modeled" ? "modeled" : "warning"}`}
        role="status"
        aria-live="polite"
      >
        <Show when={surfaceState() === "live"} fallback={<ShieldAlert size={18} />}>
          <ShieldCheck size={18} />
        </Show>
        <div>
          <strong>
            {surfaceState() === "live"
              ? "Live-capable authority · finalized Base Sepolia anchor verified"
              : surfaceState() === "loading"
                ? "Release configured · verifying the public queue and rollback witness"
                : surfaceState() === "held"
                  ? "Release held · browser verification did not complete"
                  : "Modeled fallback · control plane release-gated"}
          </strong>
          <span>
            {surfaceState() === "live"
              ? "The browser matched the delegate release context to this build, parsed an exact hash-only schema, and re-read the release-pinned rollback anchor. Decisions still require an allowlisted wallet and the current M-of-N threshold."
              : surfaceState() === "held"
                ? error() || "The configured authority failed closed. No signature request or decision mutation is available."
                : surfaceState() === "loading"
                  ? "No wallet prompt will appear until the public authority response and onchain witness both pass."
                  : "These source-modeled examples describe the bounded review shape only. The customer control plane remains release-gated: this browser has no release-authorized safe adapter, policy, reviewer roster, signature domain, or exact release lineage, so no review mutation is available."}
          </span>
        </div>
      </div>

      <Show when={notice()}>
        <div class="notice success" role="status">{notice()}</div>
      </Show>
      <Show when={error() && surfaceState() === "live"}>
        <div class="form-error" role="alert">{error()}</div>
      </Show>

      <dl class="review-summary-strip" aria-label="Review desk status">
        <div><dt>{verifiedListingVisible() ? "queue tickets" : "modeled examples"}<small>{verifiedListingVisible() ? `${listing()?.loaded_count ?? 0} loaded · hash only` : "not a live queue"}</small></dt><dd>{String(verifiedListingVisible() ? queue()?.ticket_count ?? 0 : 3).padStart(2, "0")}</dd></div>
        <div><dt>pending<small>{verifiedListingVisible() ? "current authority" : "release holds"}</small></dt><dd>{String(verifiedListingVisible() ? queue()?.pending_count ?? 0 : 4).padStart(2, "0")}</dd></div>
        <div><dt>anchor sequence<small>{verifiedListingVisible() ? "finalized witness" : "unavailable"}</small></dt><dd>{String(queue()?.authority.rollback_anchor.sequence ?? 0).padStart(2, "0")}</dd></div>
        <div><dt>signed approvals<small>{verifiedListingVisible() ? "loaded hash receipts" : "none requested"}</small></dt><dd>{String(approvalCount()).padStart(2, "0")}</dd></div>
      </dl>

      <section class="review-workspace" aria-labelledby="review-workspace-title">
        <div class="review-queue-column">
          <div class="section-heading compact-heading review-column-heading">
            <div>
              <p class="overline">{verifiedListingVisible() ? "Release queue" : "Modeled intake"}</p>
              <h2 id="review-workspace-title">Reviewer queue</h2>
            </div>
            <Show when={verifiedListingVisible()} fallback={(
              <span class="review-source-badge">
                <EyeOff size={13} /> SOURCE ONLY
              </span>
            )}>
              <label class="project-select">
                <span class="sr-only">Filter review queue by routed role</span>
                <select
                  aria-label="Filter review queue by routed role"
                  value={selectedRole()}
                  disabled={Boolean(busy())}
                  onChange={(event) => changeRoleFilter(event.currentTarget.value)}
                >
                  <option value="">All review roles</option>
                  <For each={roleOptions()}>
                    {(role) => (
                      <option value={role.role}>
                        {role.role.replaceAll("-", " ")}
                      </option>
                    )}
                  </For>
                </select>
              </label>
              <span class="review-source-badge">
                <ShieldCheck size={13} /> HASH ONLY
              </span>
            </Show>
          </div>
          <p class="review-column-note">
            {verifiedListingVisible()
              ? `Only domain-separated ticket, turn, corpus, reason, policy, and authorization commitments leave the CVM. ${
                selectedRole()
                  ? `The ${selectedRole().replaceAll("-", " ")} filter remains bound to every continuation request.`
                  : "All current release roles are included."
              }`
              : "Selecting an example changes only this in-memory presentation. It is not an acknowledgement, assignment, or review action."}
          </p>

          <div
            id="review-public-queue-list"
            class="review-queue-list"
            role="list"
            aria-label={verifiedListingVisible() ? "Release-bound review tickets" : "Source-modeled review examples"}
            aria-busy={busy() === "load-more"}
          >
            <For each={items()} fallback={(
              <div class="empty-state"><ClipboardCheck size={22} /><strong>No review tickets</strong><span>The verified queue is currently empty.</span></div>
            )}>
              {(item) => (
                <div role="listitem">
                  <button
                    class={`review-queue-card ${selectedId() === item.id ? "active" : ""}`}
                    type="button"
                    aria-pressed={selectedId() === item.id}
                    aria-controls="review-selected-workbench"
                    onClick={() => setSelectedId(item.id)}
                  >
                    <span class="review-queue-card-top">
                      <span>{item.sequence}</span>
                      <em>{item.kind === "live" ? item.ticket.status.toUpperCase() : item.kind === "empty" ? "EMPTY" : "MODELED"}</em>
                    </span>
                    <strong>{item.title}</strong>
                    <span>{item.lane}</span>
                    <small><AlertTriangle size={12} /> {item.hold}</small>
                    <ArrowRight class="review-card-arrow" size={15} aria-hidden="true" />
                  </button>
                </div>
              )}
            </For>
          </div>
          <Show when={verifiedListingVisible() && listing()}>
            <div
              class="public-projection-pagination"
              aria-label="Review queue pagination"
            >
              <p
                id="review-queue-pagination-status"
                class="public-pagination-status"
                role="status"
                aria-live="polite"
                aria-atomic="true"
              >
                {paginationAnnouncement()
                  || `${listing()?.loaded_count ?? 0} of ${queue()?.ticket_count ?? 0} review ticket${
                    queue()?.ticket_count === 1 ? "" : "s"
                  } loaded.${
                    listing()?.has_more
                      ? " More are available through an opaque queue cursor."
                      : " No continuation cursor was returned."
                  }`}
              </p>
              <Show when={paginationError()} fallback={(
                <button
                  class="secondary-button public-load-more"
                  type="button"
                  aria-controls="review-public-queue-list"
                  aria-describedby="review-queue-pagination-status"
                  aria-busy={busy() === "load-more"}
                  disabled={
                    !listing()?.has_more
                    || Boolean(busy())
                    || paginationNeedsRestart()
                    || surfaceState() !== "live"
                  }
                  onClick={() => void loadMoreQueue()}
                >
                  {busy() === "load-more"
                    ? <LoaderCircle class="spin" size={14} />
                    : <ArrowDown size={14} />}
                  {busy() === "load-more"
                    ? "Loading next review page…"
                    : listing()?.has_more
                      ? "Load more review tickets"
                      : "All returned review tickets loaded"}
                </button>
              )}>
                <div class="public-pagination-error" role="alert">
                  <AlertTriangle size={15} />
                  <span>
                    <strong>Next review page rejected.</strong>
                    {paginationError()} The verified rows already shown were preserved.
                  </span>
                  <div>
                    <button
                      class="secondary-button"
                      type="button"
                      disabled={Boolean(busy()) || paginationNeedsRestart()}
                      onClick={() => void loadMoreQueue()}
                    >
                      Retry next page
                    </button>
                    <button
                      class="ghost-button"
                      type="button"
                      disabled={Boolean(busy())}
                      onClick={() => void refreshQueue()}
                    >
                      Restart from first page
                    </button>
                  </div>
                </div>
              </Show>
            </div>
          </Show>
        </div>

        <article id="review-selected-workbench" class="review-detail-panel">
          <span class="sr-only" role="status" aria-live="polite">
            Selected {selected().kind === "live" ? "release-bound ticket" : selected().kind === "empty" ? "verified empty queue" : "modeled review example"}: {selected().title}.
          </span>
          <div class="review-detail-head">
            <div>
              <span class="review-source-badge">
                <ScanSearch size={13} /> {selected().kind === "live" ? "VERIFIED QUEUE ROW" : selected().kind === "empty" ? "VERIFIED EMPTY QUEUE" : "MODELED SAMPLE"}
              </span>
              <h2>{selected().title}</h2>
              <p>{selected().purpose}</p>
            </div>
            <GatePill>{selectedLive()?.ticket.status.toUpperCase() ?? "RELEASE GATED"}</GatePill>
          </div>

          <dl class="review-fact-grid">
            <div><dt>Lane</dt><dd>{selected().lane}</dd></div>
            <div><dt>Requested action</dt><dd>{selected().requestedOutput}</dd></div>
            <div><dt>Output boundary</dt><dd>{selected().outputClass}</dd></div>
            <div><dt>Policy</dt><dd>{selected().policy}</dd></div>
            <Show when={selected().kind === "live"}>
              <div><dt>Threshold</dt><dd>{(selected() as LiveReview).ticket.approvals_count} / {(selected() as LiveReview).ticket.required_approvals}</dd></div>
              <div><dt>Expires</dt><dd>{timestamp((selected() as LiveReview).ticket.expires_at)}</dd></div>
            </Show>
          </dl>

          <div class="review-scope-boundary">
            <EyeOff size={18} />
            <div>
              <strong>{selected().kind === "live" ? "Opaque review subject" : selected().kind === "empty" ? "No review subject" : "Illustrative content boundary"}</strong>
              <span>
                {selected().kind === "live"
                  ? `Ticket ${shortHash((selected() as LiveReview).ticket.ticket_ref_hash)} · corpus ${shortHash((selected() as LiveReview).ticket.corpus_ref_hash)} · reason ${shortHash((selected() as LiveReview).ticket.reason_hash)}. No raw subject or free-form output is returned.`
                  : selected().kind === "empty"
                    ? "The current anchored queue contains no ticket commitments. No modeled row is substituted for a live result."
                    : "This interface contains no source artifact, evaluator transcript, hidden candidate, private corpus, or real result. The sample describes the shape of a future bounded release decision."}
              </span>
            </div>
          </div>

          <div class="review-action-bar" aria-label="Release-gated review actions">
            <button
              class="secondary-button"
              type="button"
              onClick={() => void refreshQueue()}
              disabled={!releaseConfigured || Boolean(busy())}
              aria-describedby="review-actions-gate"
            >
              <RefreshCw size={15} /> Refresh head
            </button>
            <button
              class="secondary-button"
              type="button"
              onClick={() => void decide("deny")}
              disabled={!decisionReady()}
              aria-describedby="review-actions-gate"
            >
              {busy() === "deny" ? <LoaderCircle class="spin" size={15} /> : <XCircle size={15} />} Sign denial
            </button>
            <button
              class="primary-button"
              type="button"
              onClick={() => void decide("release")}
              disabled={!decisionReady()}
              aria-describedby="review-actions-gate"
            >
              {busy() === "release" ? <LoaderCircle class="spin" size={15} /> : <Signature size={15} />} Sign approval
            </button>
          </div>
          <p id="review-actions-gate" class="review-action-gate-copy">
            <LockKeyhole size={13} />
            {surfaceState() !== "live"
              ? "Release gated: the exact release authority and finalized queue witness must verify first."
              : !wallet.account()
                ? "Connect an allowlisted reviewer wallet from the header. The backend gives unauthorized, unknown-ticket, self-review, and duplicate-approval attempts the same bounded denial."
                : !wallet.isCorrectChain()
                  ? "Switch the connected wallet to Base Sepolia before requesting a one-time decision challenge."
                  : !selectedPending()
                    ? "The selected ticket is terminal; no further decision can be signed."
                    : "The wallet signs one exact ticket-state challenge. A signature never transfers funds, and raw signature bytes are not persisted in the review queue."}
          </p>
        </article>
      </section>

      <section class="review-controls-section" aria-labelledby="review-controls-title">
        <div class="section-heading split-heading compact-heading">
          <div>
            <p class="overline">Bounded-output policy</p>
            <h2 id="review-controls-title">Five controls before a human can release less.</h2>
          </div>
          <GatePill>{surfaceState() === "live" ? "PER-TICKET REVIEW" : "REQUIREMENTS ONLY"}</GatePill>
        </div>
        <div class="review-policy-grid">
          <For each={OUTPUT_CONTROLS}>
            {(control, index) => (
              <article class="review-policy-card">
                <div><span>0{index() + 1}</span><ListChecks size={15} /></div>
                <h3>{control.title}</h3>
                <p>{control.detail}</p>
                <small><LockKeyhole size={11} /> {control.state}</small>
              </article>
            )}
          </For>
        </div>
        <div class="review-egress-contract">
          <div><ShieldCheck size={17} /><span><small>ALLOWED SHAPE</small><strong>Band · enum · bounded count · opaque commitment · declared receipt</strong></span></div>
          <div><ShieldAlert size={17} /><span><small>FAIL-CLOSED SHAPE</small><strong>Free text · raw source · attachment · undeclared field · identity roster · signature bytes</strong></span></div>
        </div>
      </section>

      <section class="review-authority-grid" aria-label="Release checks and reviewer authority">
        <div class="review-holds-panel">
          <div class="section-heading compact-heading">
            <div><p class="overline">Fail-closed launch state</p><h2>{authorityReady() ? "Release checks" : "Release holds"}</h2></div>
          </div>
          <div class="review-hold-list">
            <Show when={authorityReady()} fallback={(
              <For each={MODELED_HOLDS}>
                {(hold) => (
                  <article>
                    <span><AlertTriangle size={15} /></span>
                    <div><strong>{hold.title}</strong><p>{hold.detail}</p></div>
                    <em>UNRESOLVED</em>
                  </article>
                )}
              </For>
            )}>
              <For each={[
                ["Exact release context", `${queue()?.authority.release_context.main_runtime_cvm_id} · ${shortHash(queue()?.authority.release_context.deployment_intent_sha256 ?? "")}`],
                ["Current reviewer authority", `Epoch ${queue()?.authority.release_provenance.reviewer_authority_current_status_epoch} · ${queue()?.authority.active_reviewers.active_reviewer_count} active reviewers`],
                ["Finalized rollback witness", `Sequence ${queue()?.authority.rollback_anchor.sequence} · state ${shortHash(queue()?.authority.rollback_anchor.state_hash ?? "")}`],
                ["Strict public egress", "Hash-only tickets · no raw reviewer identity · no persisted signature bytes"],
              ] as const}>
                {(check) => (
                  <article>
                    <span><CheckCircle2 size={15} /></span>
                    <div><strong>{check[0]}</strong><p>{check[1]}</p></div>
                    <em>VERIFIED</em>
                  </article>
                )}
              </For>
            </Show>
          </div>
        </div>

        <div class="review-signature-panel">
          <div class="section-heading compact-heading">
            <div><p class="overline">Threshold authority</p><h2>Reviewer wallets</h2></div>
          </div>
          <div class="review-signature-boundary">
            <Fingerprint size={18} />
            <p>
              <strong>{surfaceState() === "live" ? "Current M-of-N policy · identities remain private" : "No reviewer roster in this build"}</strong>
              {surfaceState() === "live"
                ? "The public queue reveals role thresholds and set commitments only. The CVM resolves an allowlisted wallet privately, rejects self-review, and accepts EOA or EIP-1271 signatures through trusted Base Sepolia RPCs."
                : "Modeled role slots below are responsibilities, not people, wallet addresses, public keys, signatures, approvals, or claims of configured authority."}
            </p>
          </div>
          <div class="reviewer-slot-list">
            <Show when={surfaceState() === "live" && queue()} fallback={(
              <For each={MODELED_REVIEWERS}>
                {(slot) => (
                  <article>
                    <span><UserRoundCheck size={15} /></span>
                    <div><strong>{slot.role}</strong><p>{slot.duty}</p></div>
                    <GatePill>UNCONFIGURED</GatePill>
                  </article>
                )}
              </For>
            )}>
              <For each={queue()?.authority.roles ?? []}>
                {(role) => (
                  <article>
                    <span><UserRoundCheck size={15} /></span>
                    <div><strong>{role.role.replaceAll("-", " ")}</strong><p>{role.threshold}-of-{role.reviewer_count} · set {shortHash(role.reviewer_set_hash)}</p></div>
                    <GatePill>ACTIVE</GatePill>
                  </article>
                )}
              </For>
            </Show>
          </div>
          <span class="secondary-button review-signature-request review-nonaction-status" role="status">
            <WalletCards size={15} /> {wallet.account() ? `Connected ${wallet.account()?.slice(0, 6)}…${wallet.account()?.slice(-4)}` : "Connect reviewer wallet in header"}
          </span>
          <p class="review-action-gate-copy">
            <KeyRound size={13} /> Wallet access proves neither reviewer authority nor TDX execution. Authority is resolved server-side for each current ticket-state challenge.
          </p>
        </div>
      </section>

      <section class="review-audit-section" aria-labelledby="review-audit-title">
        <div class="section-heading split-heading compact-heading">
          <div>
            <p class="overline">{surfaceState() === "live" ? "Opaque anchored audit head" : "Illustrative sequence · not an audit log"}</p>
            <h2 id="review-audit-title">What this browser can prove</h2>
          </div>
          <span class="review-source-badge"><History size={13} /> {surfaceState() === "live" ? "LIVE COMMITMENTS" : "MODELED · NOT RECORDED"}</span>
        </div>
        <div class="review-audit-timeline">
          <For each={surfaceState() === "live" ? [
            { n: "01", title: "Release context matched", detail: `CVM ${queue()?.authority.release_context.main_runtime_cvm_id} matched the immutable browser release.`, state: "RELEASE MATCH" },
            { n: "02", title: "Queue head re-read", detail: `Base Sepolia sequence ${queue()?.authority.rollback_anchor.sequence}; state ${shortHash(queue()?.authority.rollback_anchor.state_hash ?? "")}.`, state: "FINALIZED RPC" },
            { n: "03", title: "Audit digest bounded", detail: `${queue()?.audit_count ?? 0} events commit to ${shortHash(queue()?.audit_hash ?? "")}; event contents do not leave the CVM.`, state: "OPAQUE ONLY" },
          ] : [
            { n: "01", title: "Example composed", detail: "A source-only example was selected. Nothing was fetched or persisted.", state: "MODELED" },
            { n: "02", title: "Control screen shown", detail: "Required control categories are visible; no check is reported as passed.", state: "MODELED" },
            { n: "03", title: "Authority suppressed", detail: "Signature and decision mutations remain disabled while release authority is unavailable.", state: "FAIL CLOSED" },
          ]}>
            {(event) => (
              <article>
                <span>{event.n}</span>
                <div><Clock3 size={15} /><strong>{event.title}</strong><p>{event.detail}</p><em>{event.state}</em></div>
              </article>
            )}
          </For>
        </div>
        <div class={`review-launch-verdict ${authorityReady() ? "ready" : "held"}`} role="status">
          {authorityReady() ? <ShieldCheck size={20} /> : <ShieldAlert size={20} />}
          <div>
            <small>{authorityReady() ? "AUTHORITY READY · PER-TICKET WALLET CHECK REQUIRED" : "HELD · RELEASE AUTHORITY INCOMPLETE"}</small>
            <strong>{authorityReady() ? "The queue is verified; each decision remains individually authorized." : "This build cannot authorize a real release decision."}</strong>
            <span>{authorityReady() ? "A public queue read is not a release. The selected current ticket, reviewer membership, self-review rule, fresh nonce, signature, threshold, and anchored commit must all pass." : "Modeled workflow remains available for product review, but no action is recorded and no confidential-compute claim is made."}</span>
          </div>
          <GatePill>{authorityReady() ? "LIVE-CAPABLE" : "NO RELEASE AUTHORITY"}</GatePill>
        </div>
      </section>

      <footer class="review-page-footnote">
        <EyeOff size={16} />
        <p>
          <strong>Privacy boundary:</strong> the public adapter accepts only a wallet address,
          ticket commitment, decision enum, one-time nonce, and bounded signature. Raw tickets,
          corpora, turns, reviewer identities, and signatures are excluded from public persistence.
        </p>
        <ScanSearch size={15} />
        <ShieldCheck size={15} />
      </footer>
    </div>
  );
}
