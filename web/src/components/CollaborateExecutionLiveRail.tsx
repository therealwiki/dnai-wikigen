import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
} from "solid-js";
import {
  BadgeCheck,
  CircleDashed,
  Coins,
  FileJson,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  Send,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  WalletCards,
} from "lucide-solid";

import {
  assertCollaborationExecutionPlanRequest,
  assertCollaborationExecutionAuthorizationMatchesPlan,
  assertCollaborationExecutionPlanMatchesJointRun,
  assertCollaborationExecutionPlanMatchesCurrentRelease,
  assertCollaborationExecutionGrantChallengeForSigning,
  assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease,
  assertCollaborationComputeAuthorizationMatchesPlanRequest,
  collaborationSessionIsCurrent,
  type CollaborationExecutionAuthorizationResult,
  type CollaborationExecutionPlanProjection,
  type CollaborationExecutionPlanRequest,
  type CollaborationExecutionStatusProjection,
  type CollaborationExecutionWorkerCapability,
  type CollaborationJointRun,
  type CollaborationRoom,
  type CollaborationSession,
} from "../lib/collaboration";
import type { CollaborationExecutionTransportAdapter } from "../lib/collaborationExecutionTransport";
import { CollaborateComputePlanBuilder, type PreparedCollaborationComputePlan } from "./CollaborateComputePlanBuilder";
import { computeVaultDeployment, computeWorkloadDeployment, deployment } from "../config";
import { fetchAuthenticatedComputeWorkloadContract } from "../lib/computeWorkload";
import {
  listCollaborationComputeAuthorizationIntents,
  prepareCollaborationComputeAuthorization,
  reconcileCollaborationComputeAuthorization,
  submitCollaborationComputeAuthorization,
  verifyCollaborationComputeAuthorizationTerms,
  CollaborationComputeAuthorizationRetentionError,
  type CollaborationComputeAuthorizationIntent,
  type CollaborationComputeAuthorizationOutcome,
  type CollaborationComputeAuthorizationTerms,
} from "../lib/collaborationComputeAuthorization";
import {
  clearResolvedCollaborationReservation,
  inspectCollaborationFundingReservationState,
  listCollaborationReservationIntents,
  prepareCollaborationReservationIntent,
  reconcileCollaborationFundingReservation,
  reconcileCollaborationReservationApproval,
  submitCollaborationFundingReservation,
  submitCollaborationFundingReservationRefund,
  submitCollaborationReservationApproval,
  reconcileCollaborationFundingReservationRefund,
  verifyCollaborationFundingReservationProjection,
  verifyCollaborationFundingReservationForCurrentRelease,
  CollaborationReservationRetentionError,
  type CollaborationFundingReservationIntent,
  type CollaborationFundingReservationReleaseExpectation,
  type CollaborationReservationOutcome,
} from "../lib/collaborationRoyaltyReservation";
import {
  clearResolvedCollaborationRoyaltySettlement,
  fetchCollaborationRoyaltySettlementStatus,
  listCollaborationRoyaltySettlementIntents,
  persistCollaborationRoyaltySettlementPlan,
  prepareCollaborationRoyaltySettlement,
  reconcileCollaborationRoyaltySettlement,
  reportRetainedCollaborationSettlementBroadcast,
  submitCollaborationRoyaltySettlement,
  CollaborationSettlementRetentionError,
  type CollaborationRoyaltySettlementIntent,
  type CollaborationRoyaltySettlementStatus,
  type CollaborationSettlementReconciliation,
} from "../lib/collaborationRoyaltySettlement";
import { loadFinalizedRoyaltyRailState } from "../lib/royalty";
import { wallet } from "../lib/wallet";
import {
  createCollaborationExecutionGrantClock,
  collaborationExecutionResponseIsCurrent,
  inspectCollaborationExecutionGrants,
  replaceCollaborationOwnerGrant,
  type SignedExecutionGrant,
  type CollaborationExecutionResponseContext,
} from "./collaborationExecutionGrantState";

function short(value: string, left = 14, right = 8): string {
  if (value.length <= left + right + 1) return value;
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function exactIdempotencyKey(prefix: string): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  if (!uuid) throw new Error("Secure browser randomness is unavailable");
  return `${prefix}-${uuid}`;
}

function errorMessage(cause: unknown, fallback: string): string {
  return cause instanceof Error ? cause.message : fallback;
}

export interface CollaborateExecutionLiveRailProps {
  readonly room?: CollaborationRoom;
  readonly jointRun?: CollaborationJointRun;
  readonly session?: CollaborationSession;
  readonly adapter?: CollaborationExecutionTransportAdapter;
  readonly queueMutationsEnabled: boolean;
  readonly onWorkerCapability: (
    capability: CollaborationExecutionWorkerCapability,
  ) => void;
  readonly onExecutionStatus: (
    status: CollaborationExecutionStatusProjection,
  ) => void;
  readonly onExecutionId: (executionId: string) => void;
}

export function CollaborateExecutionLiveRail(
  props: CollaborateExecutionLiveRailProps,
) {
  const [preparedComputePlan, setPreparedComputePlan] = createSignal<PreparedCollaborationComputePlan>();
  const [plannedRequest, setPlannedRequest] = createSignal<CollaborationExecutionPlanRequest>();
  const [computeAuthorizationIntent, setComputeAuthorizationIntent] = createSignal<CollaborationComputeAuthorizationIntent>();
  const [computeAuthorizationOutcome, setComputeAuthorizationOutcome] = createSignal<CollaborationComputeAuthorizationOutcome>();
  const [retainedComputeIntents, setRetainedComputeIntents] = createSignal<readonly CollaborationComputeAuthorizationIntent[]>([]);
  const [plan, setPlan] = createSignal<CollaborationExecutionPlanProjection>();
  const [signedGrants, setSignedGrants] = createSignal<
    readonly SignedExecutionGrant[]
  >([]);
  const [authorization, setAuthorization] =
    createSignal<CollaborationExecutionAuthorizationResult>();
  const [authorizationIdempotencyKey, setAuthorizationIdempotencyKey] =
    createSignal("");
  const [retainedAuthorizationResponse, setRetainedAuthorizationResponse] = createSignal<{
    readonly plan: CollaborationExecutionPlanProjection;
    readonly request: CollaborationExecutionPlanRequest;
    readonly key: string;
    readonly result: CollaborationExecutionAuthorizationResult;
  }>();
  const [reservationIntents, setReservationIntents] = createSignal<
    readonly CollaborationFundingReservationIntent[]
  >([]);
  const [selectedReservationId, setSelectedReservationId] = createSignal("");
  const [reservationOutcome, setReservationOutcome] =
    createSignal<CollaborationReservationOutcome>();
  const [settlementStatus, setSettlementStatus] =
    createSignal<CollaborationRoyaltySettlementStatus>();
  const [settlementIntent, setSettlementIntent] =
    createSignal<CollaborationRoyaltySettlementIntent>();
  const [retainedSettlementIntents, setRetainedSettlementIntents] =
    createSignal<readonly CollaborationRoyaltySettlementIntent[]>([]);
  const [settlementReconciliation, setSettlementReconciliation] =
    createSignal<CollaborationSettlementReconciliation>();
  const [settlementPrepareIdempotencyKey, setSettlementPrepareIdempotencyKey]
    = createSignal("");
  const [workflowState, setWorkflowState] = createSignal<
    "idle" | "working" | "ready" | "error"
  >("idle");
  const [workflowMessage, setWorkflowMessage] = createSignal(
    "Prepare a verified public Compute workload and choose exact funding terms to begin.",
  );
  const [grantNowMs, setGrantNowMs] = createSignal(Date.now());
  const grantClock = createCollaborationExecutionGrantClock(setGrantNowMs);
  let disposed = false;
  createEffect(() => grantClock.replace([
    (plan()?.authorization_expiry ?? 0) * 1_000,
    (props.session?.expiresAt ?? 0) * 1_000 - 5_000,
    ...signedGrants().map((grant) => grant.expiresAt * 1_000),
  ]));
  onCleanup(() => grantClock.dispose());
  onCleanup(() => { disposed = true; });

  const sessionCurrent = createMemo(() => collaborationSessionIsCurrent(
    props.session,
    {
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
      nowMs: grantNowMs(),
    },
  ));
  const connectedAddress = createMemo(() => wallet.account()?.toLowerCase());
  const selectedReservation = createMemo(() => (
    reservationIntents().find(
      (intent) => intent.reservationId === selectedReservationId(),
    )
  ));
  const activeExecutionId = createMemo(() => (
    authorization()?.execution.execution_id
      ?? settlementIntent()?.executionId
      ?? selectedReservation()?.executionId
  ));
  const planContextMatches = createMemo(() => {
    const currentPlan = plan();
    if (!currentPlan || !props.room || !props.jointRun) return false;
    try {
      assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan);
      assertCollaborationExecutionPlanMatchesJointRun(currentPlan, props.jointRun, props.room);
      return true;
    } catch {
      return false;
    }
  });
  const grantReadiness = createMemo(() => inspectCollaborationExecutionGrants({
    plan: plan(),
    grants: signedGrants(),
    connectedAddress: connectedAddress(),
    nowMs: grantNowMs(),
    planContextMatches: planContextMatches(),
    participantContextCurrent: Boolean(props.adapter && props.queueMutationsEnabled && sessionCurrent()),
    authorizationState: authorization() ? "authorized"
      : authorizationIdempotencyKey() ? "attempted" : "not_started",
  }));
  const allOwnersSigned = () => grantReadiness().allOwnersSigned;
  const connectedOwnerNeedsGrant = () => grantReadiness().connectedOwnerNeedsGrant;
  const authorizationUnresolved = () => Boolean(authorizationIdempotencyKey() && !authorization());
  const selectedReservationRefundReady = createMemo(() => Boolean(
    selectedReservation()
    && (
      reservationOutcome()?.status === "reservation_expired"
      || (
        settlementStatus()?.state === "reservation_expired"
        && settlementStatus()?.funding_reservation_id
          === selectedReservation()?.reservationId
      )
    ),
  ));

  function requireContext(): {
    adapter: CollaborationExecutionTransportAdapter;
    session: CollaborationSession;
    account: string;
  } {
    const adapter = props.adapter;
    const session = props.session;
    const account = wallet.account();
    if (!adapter || !session || !account || !collaborationSessionIsCurrent(session, {
      address: account,
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
      nowMs: Date.now(),
    })) {
      throw new Error(
        "Connect this participant wallet on Base Sepolia and refresh its Collaboration session",
      );
    }
    return { adapter, session, account: account.toLowerCase() };
  }

  function authorizationResponseContext(): CollaborationExecutionResponseContext {
    return { plan: plan(), request: plannedRequest(), session: props.session, room: props.room,
      jointRun: props.jointRun, key: authorizationIdempotencyKey(), account: connectedAddress(),
      walletVersion: wallet.authorizationVersion() };
  }

  function assertGrantPlanContext(
    currentPlan: CollaborationExecutionPlanProjection,
    session: CollaborationSession,
    account: string,
  ): void {
    const current = requireContext();
    if (current.session !== session || current.account !== account || plan() !== currentPlan) {
      throw new Error("Wallet, Collaboration session, or selected plan changed");
    }
    if (!props.queueMutationsEnabled) {
      throw new Error("The release-enabled queue is no longer current");
    }
    if (Date.now() >= currentPlan.authorization_expiry * 1_000) {
      throw new Error("The execution plan expired; create a new plan before collecting owner grants");
    }
    assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan);
    if (!props.room || !props.jointRun) {
      throw new Error("The selected room or joint snapshot is no longer available");
    }
    assertCollaborationExecutionPlanMatchesJointRun(currentPlan, props.jointRun, props.room);
  }

  function assertOwnerGrantMayChange(): void {
    if (authorizationIdempotencyKey() || authorization()) {
      throw new Error("The attempted authorization grant set must remain unchanged; reconcile its outcome before starting new work");
    }
  }

  async function assertFreshControlPlaneRoyaltyAuthority(
    currentPlan?: CollaborationExecutionPlanProjection,
  ): Promise<void> {
    const account = wallet.account();
    if (!account) throw new Error("Connect a participant wallet on Base Sepolia");
    const state = await loadFinalizedRoyaltyRailState(account);
    const authority = state.settlementAuthority;
    const observation = authority.observation;
    if (
      !state.runtimeVerified
      || state.observedChainId !== 84_532
      || state.blockNumber === undefined
      || !state.blockHash
      || state.observationFinality !== "rpc_reported_finalized"
      || !state.address
      || !authority.releaseEvidenceVerified
      || !authority.browserObservationAvailable
      || !authority.browserMatchesRelease
      || !authority.newSettlementsEnabled
      || authority.issues.length > 0
      || !observation
      || observation.blockNumber !== state.blockNumber
    ) throw new Error(
      authority.issues[0]
        ?? state.issues[0]
        ?? "Fresh canonical Royalty authority is unavailable",
    );
    if (currentPlan && (
      state.address.toLowerCase()
        !== currentPlan.royalty_distributor_address.toLowerCase()
      || observation.releasePolicyCommitment.toLowerCase()
        !== currentPlan.royalty_release_policy_commitment.toLowerCase()
    )) throw new Error(
      "The plan no longer matches fresh canonical Royalty authority",
    );
  }

  async function runWorkflow(
    pendingMessage: string,
    operation: () => Promise<string>,
  ): Promise<void> {
    if (workflowState() === "working") return;
    setWorkflowState("working");
    setWorkflowMessage(pendingMessage);
    try {
      setWorkflowMessage(await operation());
      setWorkflowState("ready");
    } catch (cause) {
      if (cause instanceof CollaborationComputeAuthorizationRetentionError
        && cause.intent.terms.user === connectedAddress()
        && cause.intent.authorizationVersion === wallet.authorizationVersion()) {
        installComputeIntent(cause.intent, !authorization() || authorization()?.execution.execution_id === cause.intent.terms.executionId);
      }
      if (
        cause instanceof CollaborationReservationRetentionError
        && (
          cause.intent.approvalTransactionHash
          || cause.intent.reservationTransactionHash
          || cause.intent.refundTransactionHash
        )
      ) replaceReservationIntent(cause.intent);
      if (cause instanceof CollaborationSettlementRetentionError) {
        replaceSettlementIntent(cause.intent);
      }
      setWorkflowState("error");
      setWorkflowMessage(errorMessage(cause, "The live workflow failed closed"));
    }
  }

  function parsePlanRequest(): CollaborationExecutionPlanRequest {
    const account = wallet.account();
    if (!account) throw new Error("Connect the execution sponsor wallet");
    const value = preparedComputePlan()?.request;
    if (!value) throw new Error("Verify the public workload and prepare complete funding terms first");
    assertCollaborationExecutionPlanRequest(value, account);
    return value;
  }

  function reservationExpectation(): CollaborationFundingReservationReleaseExpectation {
    const currentPlan = plan();
    const currentAuthorization = authorization();
    if (!currentPlan || !currentAuthorization) {
      throw new Error("Create the plan and authorize every owner grant first");
    }
    return {
      executionId: currentAuthorization.execution.execution_id,
      sponsor: currentPlan.sponsor_address,
      settlementId: currentPlan.royalty_settlement_id,
      settlementNonce: currentPlan.royalty_settlement_nonce,
      royaltyReleasePolicyCommitment:
        currentPlan.royalty_release_policy_commitment,
      royaltyReleaseBindingCommitment:
        currentPlan.royalty_release_binding_commitment,
      distributor: currentPlan.royalty_distributor_address,
      roomCommitment: currentPlan.room_commitment,
      roomStateCommitment: currentPlan.room_state_commitment,
      queryProposalCommitment: currentPlan.query_proposal_commitment,
      allocationCommitment: currentPlan.allocation_commitment,
      ownersAmountsHash: currentPlan.royalty_owner_amounts_hash,
      asset: currentPlan.asset,
      total: currentPlan.royalty_total,
      authorizationExpiry: currentPlan.authorization_expiry,
      reservationSafetySeconds: currentPlan.royalty_reservation_safety_seconds,
      grantSetCommitment:
        currentAuthorization.execution.execution_grant_set_commitment,
      executionCommitment: currentAuthorization.execution.intent_commitment,
    };
  }

  async function freshReservationAuthority(): Promise<{
    readonly projection:
      CollaborationExecutionStatusProjection["royalty_reservation"];
    readonly status: CollaborationExecutionStatusProjection;
  }> {
    const { adapter, session } = requireContext();
    const currentPlan = plan();
    const currentAuthorization = authorization();
    if (!currentPlan || !currentAuthorization) {
      throw new Error("No current authorized execution is selected");
    }
    const envelope = await adapter.fetchStatusEnvelope(
      session.accessToken,
      currentAuthorization.execution.execution_id,
    );
    assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease(
      envelope.worker_capability,
      currentPlan,
      Date.now(),
    );
    if (
      !envelope.queue_control.onchain_reservation_ready
      || !envelope.payload.royalty_reservation.walletActionReady
      || envelope.payload.intent_commitment
        !== currentAuthorization.execution.intent_commitment
      || envelope.payload.authorization_commitment
        !== currentAuthorization.authorization_commitment
    ) throw new Error(
      "The authenticated execution status no longer authorizes this reservation",
    );
    verifyCollaborationFundingReservationForCurrentRelease(
      envelope.payload.royalty_reservation,
      reservationExpectation(),
    );
    props.onWorkerCapability(envelope.worker_capability);
    props.onExecutionStatus(envelope.payload);
    return {
      projection: envelope.payload.royalty_reservation,
      status: envelope.payload,
    };
  }

  async function refreshAndAssertReservationIntent(
    intent: CollaborationFundingReservationIntent,
  ): Promise<void> {
    let verified;
    if (plan() && authorization()) {
      const fresh = await freshReservationAuthority();
      verified = verifyCollaborationFundingReservationForCurrentRelease(
        fresh.projection,
        reservationExpectation(),
      );
    } else {
      const { adapter, session } = requireContext();
      const envelope = await adapter.fetchStatusEnvelope(
        session.accessToken,
        intent.executionId,
      );
      assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease(
        envelope.worker_capability,
        undefined,
        Date.now(),
      );
      if (
        !envelope.queue_control.onchain_reservation_ready
        || !envelope.payload.royalty_reservation.walletActionReady
      ) throw new Error(
        "Fresh authenticated worker/QVL reservation capability is unavailable",
      );
      verified = verifyCollaborationFundingReservationProjection(
        envelope.payload.royalty_reservation,
      );
      props.onWorkerCapability(envelope.worker_capability);
      props.onExecutionStatus(envelope.payload);
      props.onExecutionId(intent.executionId);
    }
    if (
      verified.reservationId !== intent.reservationId
      || verified.sponsor.toLowerCase() !== intent.sponsor.toLowerCase()
      || verified.call.expectedCalldata !== intent.call.expectedCalldata
      || verified.call.value !== intent.call.value
    ) throw new Error(
      "The retained browser intent does not match the authenticated server reservation",
    );
  }

  function replaceReservationIntent(
    next: CollaborationFundingReservationIntent,
  ): void {
    setReservationIntents((current) => {
      const retained = current.filter(
        (item) => item.reservationId !== next.reservationId,
      );
      return Object.freeze([...retained, next]);
    });
    setSelectedReservationId(next.reservationId);
  }

  function removeReservationIntent(reservationId: string): void {
    setReservationIntents((current) => Object.freeze(
      current.filter((item) => item.reservationId !== reservationId),
    ));
    if (selectedReservationId() === reservationId) {
      setSelectedReservationId("");
    }
  }

  function replaceSettlementIntent(
    next: CollaborationRoyaltySettlementIntent,
  ): void {
    setRetainedSettlementIntents((current) => Object.freeze([
      ...current.filter((item) => (
        item.plan.plan_commitment !== next.plan.plan_commitment
      )),
      next,
    ]));
    setSettlementIntent(next);
  }

  function removeSettlementIntent(
    intent: CollaborationRoyaltySettlementIntent,
  ): void {
    setRetainedSettlementIntents((current) => Object.freeze(
      current.filter((item) => (
        item.plan.plan_commitment !== intent.plan.plan_commitment
      )),
    ));
    if (
      settlementIntent()?.plan.plan_commitment
        === intent.plan.plan_commitment
    ) setSettlementIntent(undefined);
  }

  function recoverReservationIntents(): void {
    const account = wallet.account();
    if (!account) {
      setReservationIntents([]);
      setSelectedReservationId("");
      return;
    }
    try {
      const intents = listCollaborationReservationIntents(
        window.localStorage,
        {
          account,
          authorizationVersion: wallet.authorizationVersion(),
        },
      );
      setReservationIntents(intents);
      setSelectedReservationId((current) => (
        intents.some((intent) => intent.reservationId === current)
          ? current
          : intents[0]?.reservationId ?? ""
      ));
    } catch (cause) {
      setWorkflowState("error");
      setWorkflowMessage(errorMessage(
        cause,
        "Retained reservation recovery failed closed",
      ));
    }
  }

  function recoverSettlementIntents(): void {
    const account = wallet.account();
    if (!account) {
      setRetainedSettlementIntents([]);
      setSettlementIntent(undefined);
      return;
    }
    try {
      const intents = listCollaborationRoyaltySettlementIntents(
        window.localStorage,
        {
          account,
          authorizationVersion: wallet.authorizationVersion(),
        },
      );
      setRetainedSettlementIntents(intents);
      setSettlementIntent((current) => {
        if (current) {
          const match = intents.find((intent) => (
            intent.plan.plan_commitment === current.plan.plan_commitment
          ));
          if (match) return match;
        }
        return intents.length === 1 ? intents[0] : undefined;
      });
    } catch (cause) {
      setWorkflowState("error");
      setWorkflowMessage(errorMessage(
        cause,
        "Retained settlement recovery failed closed",
      ));
    }
  }

  createEffect(() => {
    wallet.account();
    wallet.authorizationVersion();
    recoverReservationIntents();
    recoverSettlementIntents();
  });

  const createPlan = () => runWorkflow(
    "Validating the exact Compute packet against the selected joint snapshot…",
    async () => {
      if (authorizationUnresolved()) {
        throw new Error("The previous authorization outcome is unresolved; retain its exact plan and grants for reconciliation");
      }
      const { adapter, session, account } = requireContext();
      const jointRun = props.jointRun;
      const room = props.room;
      if (!props.queueMutationsEnabled || !jointRun || !room) {
        throw new Error("The release-enabled queue and current joint snapshot are required");
      }
      await assertFreshControlPlaneRoyaltyAuthority();
      const prepared = preparedComputePlan();
      if (!prepared) throw new Error("Prepare a complete verified Compute request first");
      await prepared.verifyCurrent();
      const request = parsePlanRequest();
      const walletVersion = wallet.authorizationVersion();
      const next = await adapter.createPlan(
        session.accessToken,
        jointRun.run_id,
        request,
        account,
        undefined,
        { room, jointRun },
      );
      if (wallet.authorizationVersion() !== walletVersion || connectedAddress() !== account
        || props.session !== session || props.room !== room || props.jointRun !== jointRun || preparedComputePlan() !== prepared) {
        throw new Error("Plan response arrived after its wallet or joint snapshot changed; no local plan was installed");
      }
      setPlan(next);
      setPlannedRequest(request);
      setSignedGrants([]);
      setAuthorization(undefined);
      setAuthorizationIdempotencyKey("");
      setReservationOutcome(undefined);
      setSettlementStatus(undefined);
      setSettlementIntent(undefined);
      props.onExecutionId("");
      return `Exact plan ${short(next.basis_commitment)} created. Each listed owner must now connect and sign a fresh one-shot grant.`;
    },
  );

  const signOwnerGrant = () => runWorkflow(
    "Requesting a fresh server challenge before opening the wallet signature…",
    async () => {
      const { adapter, session, account } = requireContext();
      const currentPlan = plan();
      if (!currentPlan) throw new Error("Create the execution plan first");
      assertOwnerGrantMayChange();
      assertGrantPlanContext(currentPlan, session, account);
      if (!currentPlan.owner_addresses.includes(account)) {
        throw new Error("The connected wallet is not an owner in this exact plan");
      }
      if (signedGrants().some((grant) => grant.ownerAddress.toLowerCase() === account
        && Date.now() < grant.expiresAt * 1_000)) {
        throw new Error("The connected owner already has a fresh grant for this plan");
      }
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      assertOwnerGrantMayChange();
      assertGrantPlanContext(currentPlan, session, account);
      const challenge = await adapter.issueGrantChallenge(
        session.accessToken,
        currentPlan.plan_token,
      );
      assertCollaborationExecutionGrantChallengeForSigning(challenge, {
        plan: currentPlan,
        ownerAddress: account,
      });
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      assertOwnerGrantMayChange();
      assertGrantPlanContext(currentPlan, session, account);
      assertCollaborationExecutionGrantChallengeForSigning(challenge, {
        plan: currentPlan,
        ownerAddress: account,
      });
      const signature = await wallet.signPersonalMessage(challenge.message);
      assertOwnerGrantMayChange();
      assertGrantPlanContext(currentPlan, session, account);
      assertCollaborationExecutionGrantChallengeForSigning(challenge, {
        plan: currentPlan,
        ownerAddress: account,
      });
      const grant: SignedExecutionGrant = Object.freeze({
        ownerAddress: account,
        expiresAt: challenge.expires_at,
        challenge_token: challenge.challenge_token,
        signature,
      });
      setSignedGrants((current) => replaceCollaborationOwnerGrant(current, grant));
      return `Fresh one-shot execution grant signed for ${short(account)}. The signature remains in browser memory only until authorization.`;
    },
  );

  const authorize = () => runWorkflow(
    "Submitting the complete fresh owner grant set; no provider dispatch is allowed here…",
    async () => {
      const { adapter, session, account } = requireContext();
      const currentPlan = plan();
      if (!props.queueMutationsEnabled) {
        throw new Error("The release-enabled queue is no longer current");
      }
      if (!currentPlan || account !== currentPlan.sponsor_address) {
        throw new Error("Reconnect the exact plan sponsor before authorization");
      }
      if (authorization()) {
        throw new Error("This grant set already authorized an execution; use its retained execution status");
      }
      if (retainedAuthorizationResponse()) throw new Error("A completed response is retained for the original sponsor; recover it with a fresh read instead of submitting authorization again");
      assertGrantPlanContext(currentPlan, session, account);
      const grants = signedGrants();
      const assertFreshGrants = () => {
        if (!currentPlan.owner_addresses.every((owner) => grants.some(
          (grant) => grant.ownerAddress.toLowerCase() === owner && Date.now() < grant.expiresAt * 1_000,
        ))) {
          throw new Error(authorizationIdempotencyKey()
            ? "An attempted owner grant expired; its outcome is unresolved and the exact grant set must be retained for reconciliation"
            : "Every plan owner must sign a fresh execution grant; reconnect any expired owner to renew it");
        }
      };
      assertFreshGrants();
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      assertGrantPlanContext(currentPlan, session, account);
      assertFreshGrants();
      let key = authorizationIdempotencyKey();
      if (!key) {
        key = exactIdempotencyKey("collab-authorize");
        setAuthorizationIdempotencyKey(key);
      }
      const request = plannedRequest();
      if (!request) throw new Error("The original exact Compute request must remain in memory");
      const responseContext = authorizationResponseContext();
      const result = await adapter.authorize(
        session.accessToken,
        {
          plan_token: currentPlan.plan_token,
          idempotency_key: key,
          grants: grants.map((grant) => ({
            challenge_token: grant.challenge_token,
            signature: grant.signature,
          })),
        },
        undefined,
        currentPlan,
      );
      // Keep the successful response attached to its original request even if
      // the sponsor changed wallets while the server committed authorization.
      setRetainedAuthorizationResponse({ plan: currentPlan, request, key, result });
      if (!collaborationExecutionResponseIsCurrent(responseContext, authorizationResponseContext(), !disposed && sessionCurrent())) {
        throw new Error("Authorization response retained for its original sponsor and plan. Reconnect that context and recover the response; no new authorization will be sent");
      }
      assertCollaborationExecutionAuthorizationMatchesPlan(result, currentPlan);
      setAuthorization(result);
      setRetainedAuthorizationResponse(undefined);
      props.onExecutionId(result.execution.execution_id);
      props.onExecutionStatus(result.execution);
      setSettlementPrepareIdempotencyKey("");
      return `Execution ${short(result.execution.execution_id)} is ${result.execution.state}. Provider dispatch remains gated until the exact finalized funding reservation is independently observed.`;
    },
  );

  const recoverAuthorizationResponse = () => runWorkflow(
    "Reading the retained execution under its original sponsor; no authorization mutation will be sent…",
    async () => {
      const { adapter, session, account } = requireContext();
      const retained = retainedAuthorizationResponse();
      const room = props.room;
      const jointRun = props.jointRun;
      if (!retained || !room || !jointRun || retained.plan !== plan() || retained.request !== plannedRequest()
        || retained.key !== authorizationIdempotencyKey() || retained.plan.sponsor_address !== account) {
        throw new Error("Reconnect the original sponsor and selected plan to recover the completed response");
      }
      assertCollaborationExecutionPlanMatchesCurrentRelease(retained.plan);
      assertCollaborationExecutionPlanMatchesJointRun(retained.plan, jointRun, room);
      assertCollaborationExecutionAuthorizationMatchesPlan(retained.result, retained.plan);
      const responseContext = authorizationResponseContext();
      const status = await adapter.fetchStatus(session.accessToken, retained.result.execution.execution_id);
      if (retainedAuthorizationResponse() !== retained
        || !collaborationExecutionResponseIsCurrent(responseContext, authorizationResponseContext(), !disposed && sessionCurrent())) {
        throw new Error("Recovery context changed; the original response remains retained and was not installed");
      }
      const recovered = { ...retained.result, execution: status, royalty_reservation: status.royalty_reservation };
      assertCollaborationExecutionAuthorizationMatchesPlan(recovered, retained.plan);
      assertCollaborationComputeAuthorizationMatchesPlanRequest(status, retained.plan, retained.request);
      if (status.execution_id !== retained.result.execution.execution_id
        || status.intent_commitment !== retained.result.execution.intent_commitment
        || status.authorization_commitment !== retained.result.authorization_commitment) {
        throw new Error("The participant status does not match the retained authorization response");
      }
      setAuthorization(recovered);
      setRetainedAuthorizationResponse(undefined);
      props.onExecutionId(status.execution_id);
      props.onExecutionStatus(status);
      setSettlementPrepareIdempotencyKey("");
      return `Recovered exact authorization ${short(status.execution_id)} by authenticated read. Its current state is ${status.state}; no authorization was replayed.`;
    },
  );

  function computeReleaseFingerprint(): string {
    return JSON.stringify({
      release: deployment.collaborationExecutionRelease,
      delegate: deployment.delegateUrl,
      vault: computeVaultDeployment.address,
      runtime: computeVaultDeployment.codeHash,
      compose: computeVaultDeployment.composeHash,
    });
  }

  function computeTerms(status: CollaborationExecutionStatusProjection): CollaborationComputeAuthorizationTerms {
    const currentPlan = plan();
    const request = plannedRequest();
    if (!currentPlan || !request) throw new Error("Retain the original complete plan request before preparing Compute funding");
    assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan);
    assertCollaborationComputeAuthorizationMatchesPlanRequest(status, currentPlan, request);
    const { releaseSha: _release, releaseVerificationSha256: _verification, cvmId: _cvm, ...terms } = status.computeAuthorization;
    return verifyCollaborationComputeAuthorizationTerms({ ...terms, basisCommitment: currentPlan.basis_commitment as `sha256:${string}`, releaseFingerprint: computeReleaseFingerprint() });
  }

  async function freshComputeTerms(): Promise<CollaborationComputeAuthorizationTerms> {
    const account = connectedAddress();
    const version = wallet.authorizationVersion();
    const currentPlan = plan();
    const request = plannedRequest();
    if (!currentPlan || account !== currentPlan.sponsor_address || !request) throw new Error("Reconnect the exact plan sponsor and retain its original funding request");
    if (!computeWorkloadDeployment.trustPolicy) throw new Error("Current workload recipient authority is not configured");
    const [fresh, recipient] = await Promise.all([
      freshReservationAuthority(),
      fetchAuthenticatedComputeWorkloadContract(deployment.delegateUrl, computeWorkloadDeployment.trustPolicy),
    ]);
    if (connectedAddress() !== account || wallet.authorizationVersion() !== version || currentPlan !== plan() || request !== plannedRequest()) throw new Error("Compute authority returned after its wallet or plan changed");
    if (!["authorized", "queued"].includes(fresh.status.state)) throw new Error("This execution is no longer awaiting a new Compute vault authorization; reconcile the retained job instead");
    const terms = computeTerms(fresh.status);
    if (terms.workload.recipientReleaseCommitment !== recipient.recipient.recipient_release_commitment) throw new Error("The authenticated workload recipient changed; the old one-shot terms cannot be funded");
    return terms;
  }

  function recoverComputeIntents(): void {
    const account = connectedAddress();
    setComputeAuthorizationOutcome(undefined);
    setComputeAuthorizationIntent(undefined);
    if (!account) { setRetainedComputeIntents([]); return; }
    try {
      const retained = listCollaborationComputeAuthorizationIntents(window.localStorage, { account, releaseFingerprint: computeReleaseFingerprint(), authorizationVersion: wallet.authorizationVersion() });
      setRetainedComputeIntents(retained);
      if (retained.length === 1) setComputeAuthorizationIntent(retained[0]);
    } catch (cause) {
      setRetainedComputeIntents([]);
      setWorkflowState("error");
      setWorkflowMessage(errorMessage(cause, "Public Compute transaction recovery could not be read safely"));
    }
  }

  createEffect(() => { wallet.account(); wallet.authorizationVersion(); recoverComputeIntents(); });

  function installComputeIntent(intent: CollaborationComputeAuthorizationIntent, select = true): void {
    setRetainedComputeIntents(current => Object.freeze([
      ...current.filter(item => item.terms.executionId !== intent.terms.executionId), intent,
    ]));
    if (select) setComputeAuthorizationIntent(intent);
  }

  const prepareComputeAuthorization = () => runWorkflow(
    "Rechecking the exact server-derived one-shot Compute authority…",
    async () => {
      const currentPlan = plan();
      const request = plannedRequest();
      const room = props.room;
      const terms = await freshComputeTerms();
      const version = wallet.authorizationVersion();
      const intent = await prepareCollaborationComputeAuthorization(terms, window.localStorage);
      if (connectedAddress() !== terms.user || wallet.authorizationVersion() !== version) throw new Error("Compute preparation belongs to the previous wallet context");
      installComputeIntent(intent, false);
      if (plan() !== currentPlan || plannedRequest() !== request || props.room !== room) throw new Error("Prepared public Compute intent was retained for the original plan; reselect that execution before funding");
      installComputeIntent(intent); setComputeAuthorizationOutcome(undefined);
      return `Exact one-shot Compute job ${short(terms.jobId)} retained before its wallet prompt. This is separate from the Royalty reservation.`;
    },
  );

  const submitComputeAuthorization = () => runWorkflow(
    "Checking fresh authority before signing the exact one-shot Compute job…",
    async () => {
      const intent = computeAuthorizationIntent();
      if (!intent) throw new Error("Prepare the exact Compute authorization first");
      const currentPlan = plan();
      const request = plannedRequest();
      const room = props.room;
      if (intent.terms.executionId !== authorization()?.execution.execution_id) throw new Error("This retained Compute job belongs to a different execution; reconcile it without submitting a replacement");
      const version = wallet.authorizationVersion();
      const updated = await submitCollaborationComputeAuthorization(intent, window.localStorage, {
        refreshAndAssertAuthority: async (retained) => {
          const fresh = await freshComputeTerms();
          const serialize = (value: unknown) => JSON.stringify(value, (_key, item) => typeof item === "bigint" ? item.toString() : item);
          if (serialize(fresh) !== serialize(retained.terms)) throw new Error("The refreshed one-shot Compute authority differs from the retained transaction intent");
        },
      });
      if (connectedAddress() !== updated.terms.user || wallet.authorizationVersion() !== version) throw new Error("Transaction outcome is retained for the original sponsor; reconnect that wallet to reconcile it");
      installComputeIntent(updated, false);
      if (plan() !== currentPlan || plannedRequest() !== request || props.room !== room) throw new Error("Transaction outcome is retained for the original plan; reselect that execution to reconcile it");
      installComputeIntent(updated);
      return "Compute authorization transaction hash retained. Reconcile its exact event and finalized vault job; submission alone is not finality.";
    },
  );

  const reconcileComputeAuthorization = () => runWorkflow(
    "Reading the exact transaction, event and finalized Compute job…",
    async () => {
      const intent = computeAuthorizationIntent();
      if (!intent) throw new Error("Select the retained Compute authorization");
      const version = wallet.authorizationVersion();
      const result = await reconcileCollaborationComputeAuthorization(intent, window.localStorage);
      if (connectedAddress() !== intent.terms.user || wallet.authorizationVersion() !== version) throw new Error("Reconciliation belongs to the original sponsor; reconnect it to inspect the result");
      installComputeIntent(result.intent); setComputeAuthorizationOutcome(result);
      return result.detail;
    },
  );

  const prepareReservation = () => runWorkflow(
    "Re-fetching worker capability and the authenticated exact server reservation…",
    async () => {
      const fresh = await freshReservationAuthority();
      const intent = await prepareCollaborationReservationIntent(
        fresh.projection,
        reservationExpectation(),
        window.localStorage,
      );
      replaceReservationIntent(intent);
      return `Exact ${intent.asset.symbol} reservation ${short(intent.reservationId)} was retained before any wallet transaction prompt.`;
    },
  );

  const approveReservationAsset = () => runWorkflow(
    "Rebinding the retained reservation to fresh server, worker, Royalty, and token authority…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select one retained ERC20 reservation");
      }
      const next = await submitCollaborationReservationApproval(
        intent,
        window.localStorage,
        { refreshAndAssertAuthority: refreshAndAssertReservationIntent },
      );
      replaceReservationIntent(next);
      return `Exact approval hash ${short(next.approvalTransactionHash ?? "")} retained. Reconcile it before any other prompt.`;
    },
  );

  const reconcileApproval = () => runWorkflow(
    "Checking the exact approval transaction and allowance at the canonical finalized head…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select a retained approval transaction");
      }
      const outcome = await reconcileCollaborationReservationApproval(
        intent,
        window.localStorage,
      );
      setReservationOutcome(outcome);
      replaceReservationIntent(outcome.intent);
      if (outcome.clearRetainedIntent) {
        clearResolvedCollaborationReservation(window.localStorage, outcome);
        removeReservationIntent(intent.reservationId);
      }
      return outcome.detail;
    },
  );

  const reserveFunding = () => runWorkflow(
    "Rebinding authority and simulating the exact reservation immediately before the wallet prompt…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select the exact retained reservation");
      }
      const next = await submitCollaborationFundingReservation(
        intent,
        window.localStorage,
        { refreshAndAssertAuthority: refreshAndAssertReservationIntent },
      );
      replaceReservationIntent(next);
      return `Reservation transaction ${short(next.reservationTransactionHash ?? "")} retained. Execution is still locked pending independent worker finality.`;
    },
  );

  const reconcileReservation = () => runWorkflow(
    "Reading the exact transaction and reservation state at a canonical finalized block…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select a retained reservation transaction");
      }
      const outcome = await reconcileCollaborationFundingReservation(intent);
      setReservationOutcome(outcome);
      if (outcome.clearRetainedIntent) {
        clearResolvedCollaborationReservation(window.localStorage, outcome);
        removeReservationIntent(intent.reservationId);
      }
      return outcome.detail;
    },
  );

  const inspectReservation = () => runWorkflow(
    "Inspecting deterministic reservation state at one canonical finalized head…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select one retained reservation intent");
      }
      const outcome = await inspectCollaborationFundingReservationState(intent);
      setReservationOutcome(outcome);
      if (outcome.clearRetainedIntent) {
        clearResolvedCollaborationReservation(window.localStorage, outcome);
        removeReservationIntent(intent.reservationId);
      }
      return outcome.detail;
    },
  );

  const refundReservation = () => runWorkflow(
    "Rechecking the exact expired reservation at a finalized head before the sponsor refund prompt…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select the exact expired reservation");
      }
      const next = await submitCollaborationFundingReservationRefund(
        intent,
        window.localStorage,
      );
      replaceReservationIntent(next);
      return `Refund transaction ${short(next.refundTransactionHash ?? "")} retained. Reconcile permanent finalized state before clearing it.`;
    },
  );

  const reconcileRefund = () => runWorkflow(
    "Reconciling the exact refund transaction and permanent reservation state…",
    async () => {
      const intent = selectedReservation();
      if (!intent) {
        throw new Error("Select a retained refund transaction");
      }
      const outcome = await reconcileCollaborationFundingReservationRefund(
        intent,
        window.localStorage,
      );
      setReservationOutcome(outcome);
      if (outcome.clearRetainedIntent) {
        clearResolvedCollaborationReservation(window.localStorage, outcome);
        removeReservationIntent(intent.reservationId);
      } else {
        replaceReservationIntent(outcome.intent);
      }
      return outcome.detail;
    },
  );

  function adoptSettlementStatus(
    status: CollaborationRoyaltySettlementStatus,
  ): void {
    setSettlementStatus(status);
    const account = wallet.account();
    if (
      status.state === "plan_ready"
      && status.wallet_plan
      && account
    ) {
      let broadcastKey = settlementIntent()?.broadcastIdempotencyKey;
      if (!broadcastKey) broadcastKey = exactIdempotencyKey("collab-settlement-broadcast");
      replaceSettlementIntent(persistCollaborationRoyaltySettlementPlan(
        status,
        broadcastKey,
        window.localStorage,
      ));
    }
  }

  const prepareSettlement = () => runWorkflow(
    "Requesting per-job TDX, independent QVL, and finalized anchor authorization from the CVM queue…",
    async () => {
      const { session, account } = requireContext();
      const executionId = activeExecutionId();
      if (!executionId) throw new Error("Authorize or restore an execution first");
      let key = settlementPrepareIdempotencyKey();
      if (!key) {
        key = exactIdempotencyKey("collab-settlement-prepare");
        setSettlementPrepareIdempotencyKey(key);
      }
      const status = await prepareCollaborationRoyaltySettlement(
        session.accessToken,
        executionId,
        { idempotency_key: key, replace_expired: false },
        account,
      );
      adoptSettlementStatus(status);
      return status.state === "plan_ready"
        ? "A current dual-authorized settlement plan was retained before the wallet prompt."
        : `Settlement preparation is ${status.state.replaceAll("_", " ")}. Poll the authenticated queue; do not invent evidence client-side.`;
    },
  );

  const refreshSettlement = () => runWorkflow(
    "Refreshing the authenticated settlement journal…",
    async () => {
      const { session, account } = requireContext();
      const executionId = activeExecutionId();
      if (!executionId) throw new Error("No execution is selected");
      const status = await fetchCollaborationRoyaltySettlementStatus(
        session.accessToken,
        executionId,
        account,
      );
      adoptSettlementStatus(status);
      return `Settlement journal: ${status.state.replaceAll("_", " ")}. Client projection proves settlement: no.`;
    },
  );

  const replaceExpiredSettlement = () => runWorkflow(
    "Requesting a new generation after authenticated authorization expiry…",
    async () => {
      const { session, account } = requireContext();
      const executionId = activeExecutionId();
      if (!executionId || settlementStatus()?.state !== "expired") {
        throw new Error("Only an authenticated authorization-expired status may be replaced");
      }
      const unresolvedHash = retainedSettlementIntents().some((intent) => (
        intent.executionId === executionId && Boolean(intent.transactionHash)
      ));
      if (unresolvedHash) {
        throw new Error("Reconcile the retained settlement transaction hash before replacement");
      }
      const key = exactIdempotencyKey("collab-settlement-replace");
      setSettlementPrepareIdempotencyKey(key);
      const status = await prepareCollaborationRoyaltySettlement(
        session.accessToken,
        executionId,
        { idempotency_key: key, replace_expired: true },
        account,
      );
      adoptSettlementStatus(status);
      return `Replacement generation ${status.generation} is ${status.state.replaceAll("_", " ")}.`;
    },
  );

  const broadcastSettlement = () => runWorkflow(
    "Re-fetching the exact plan, Royalty authority, and finalized anchor before wallet broadcast…",
    async () => {
      const { session } = requireContext();
      const intent = settlementIntent();
      if (!intent) {
        throw new Error("No exact retained settlement plan is ready");
      }
      const next = await submitCollaborationRoyaltySettlement(
        intent,
        session.accessToken,
        window.localStorage,
      );
      replaceSettlementIntent(next);
      return `Settlement transaction ${short(next.transactionHash ?? "")} retained. Report this exact hash; never rebroadcast after an ambiguous response.`;
    },
  );

  const reportSettlement = () => runWorkflow(
    "Reporting the retained transaction hash to the authenticated reconciliation queue…",
    async () => {
      const { session } = requireContext();
      const intent = settlementIntent();
      if (!intent) {
        throw new Error("No retained settlement transaction exists");
      }
      const reported = await reportRetainedCollaborationSettlementBroadcast(
        intent,
        session.accessToken,
        window.localStorage,
      );
      replaceSettlementIntent(reported.intent);
      setSettlementStatus(reported.status);
      return "The exact hash is reported. Finalized settlement still requires both canonical chain state and the authenticated journal.";
    },
  );

  const reconcileSettlement = () => runWorkflow(
    "Cross-checking the retained transaction, canonical finalized chain state, and authenticated settlement journal…",
    async () => {
      const { session } = requireContext();
      const intent = settlementIntent();
      if (!intent) {
        throw new Error("No retained settlement transaction exists");
      }
      const result = await reconcileCollaborationRoyaltySettlement(
        intent,
        session.accessToken,
      );
      setSettlementReconciliation(result);
      setSettlementStatus(result.status);
      if (result.clearRetainedIntent) {
        clearResolvedCollaborationRoyaltySettlement(
          window.localStorage,
          result,
        );
        removeSettlementIntent(intent);
      }
      return result.detail;
    },
  );

  return (
    <section
      id="collaboration-live-builder"
      class="collaboration-live-rail"
      aria-labelledby="collaboration-live-builder-title"
      data-product-implementation="wallet-executable"
    >
      <header class="collaboration-live-rail-head">
        <div>
          <p class="overline">IMPLEMENTED WALLET RAIL · RELEASE-GATED · BASE SEPOLIA</p>
          <h3 id="collaboration-live-builder-title">
            Plan, co-sign, reserve, execute, and settle—without crossing evidence boundaries.
          </h3>
          <p>
            This rail uses the current MetaMask, injected, or WalletConnect
            session. Every server packet is parsed exactly; public intents are
            retained before a transaction prompt and transaction hashes are
            retained immediately after the wallet returns them.
          </p>
        </div>
        <span classList={{ ready: props.queueMutationsEnabled }}>
          <TerminalSquare size={14} />
          {props.queueMutationsEnabled ? "QUEUE CONTROL READY" : "CONTROL PLANE CLOSED"}
        </span>
      </header>

      <div class="collaboration-live-progress" aria-label="Implemented release-gated execution stages">
        <div classList={{ complete: Boolean(plan()) }}><span>01</span><strong>Plan</strong><small>Verified workload + explicit limits</small></div>
        <div classList={{ complete: Boolean(authorization()) || allOwnersSigned() }}><span>02</span><strong>Co-sign</strong><small>{authorization() ? "Authorized grant set" : `${grantReadiness().freshOwnerCount}/${plan()?.owner_addresses.length ?? 0} fresh owners`}</small></div>
        <div classList={{ complete: Boolean(authorization()) }}><span>03</span><strong>Authorize</strong><small>Server-derived terms</small></div>
        <div classList={{ complete: reservationOutcome()?.status === "browser_finalized_active" && computeAuthorizationOutcome()?.browserObservedAuthorized }}><span>04</span><strong>Fund both</strong><small>Compute + Royalty finality</small></div>
        <div classList={{ complete: settlementReconciliation()?.state === "settled" }}><span>05</span><strong>Settle</strong><small>Requires per-job TDX + QVL + chain</small></div>
      </div>

      <div class="collaboration-live-grid">
        <article class="collaboration-live-card plan-card">
          <div class="collaboration-live-card-title">
            <FileJson size={17} />
            <div><small>STEP 01 · SPONSOR</small><strong>Verified workload, explicit funding limits</strong></div>
          </div>
          <CollaborateComputePlanBuilder room={props.room} jointRun={props.jointRun} enabled={props.queueMutationsEnabled} workflowBusy={workflowState() === "working"} locked={Boolean(plan()) || authorizationUnresolved()} onPrepared={setPreparedComputePlan} />
          <button
            type="button"
            class="primary-button"
            disabled={workflowState() === "working" || !props.queueMutationsEnabled || !preparedComputePlan() || Boolean(plan()) || authorizationUnresolved()}
            onClick={() => void createPlan()}
          >
            <Fingerprint size={14} /> Create release-bound plan
          </button>
          <Show when={plan() && !authorization() && !authorizationUnresolved()}><button class="ghost-button" type="button" disabled={workflowState() === "working"} onClick={() => { setPlan(undefined); setPlannedRequest(undefined); setSignedGrants([]); setPreparedComputePlan(undefined); }}>Discard unsubmitted plan and prepare new terms</button></Show>
          <Show when={plan()}>{(value) => (
            <dl class="collaboration-live-facts">
              <div><dt>Basis</dt><dd>{short(value().basis_commitment)}</dd></div>
              <div><dt>Owners</dt><dd>{value().owner_addresses.length}</dd></div>
              <div><dt>Royalty</dt><dd>{value().royalty_total} base units</dd></div>
              <div><dt>Expires</dt><dd>{new Date(value().authorization_expiry * 1_000).toLocaleTimeString()}</dd></div>
            </dl>
          )}</Show>
        </article>

        <article class="collaboration-live-card grants-card">
          <div class="collaboration-live-card-title">
            <KeyRound size={17} />
            <div><small>STEP 02 · EVERY OWNER</small><strong>Fresh one-shot grants</strong></div>
          </div>
          <p>
            Each owner connects their own wallet and refreshes their existing
            Collaboration session. Query grants are never reused here.
          </p>
          <div class="collaboration-owner-signers">
            <For each={plan()?.owner_addresses ?? []}>{(owner) => {
              const status = () => grantReadiness().owners.find((entry) => entry.owner === owner)!;
              return (
                <div classList={{ signed: Boolean(authorization()) || status().fresh, connected: connectedAddress() === owner }}>
                  {authorization() || status().fresh ? <BadgeCheck size={14} /> : <CircleDashed size={14} />}
                  <code title={owner}>{short(owner, 9, 6)}</code>
                  <small>{status().label}</small>
                </div>
              );
            }}</For>
            <Show when={!plan()}><span class="collaboration-empty-state">Create a plan to reveal the exact owner set.</span></Show>
          </div>
          <button
            type="button"
            class="primary-button"
            disabled={workflowState() === "working" || !props.queueMutationsEnabled || !sessionCurrent() || !connectedOwnerNeedsGrant()}
            onClick={() => void signOwnerGrant()}
          >
            <WalletCards size={14} /> Sign connected owner grant
          </button>
          <small class="collaboration-live-boundary">
            Wallet prompt: personal_sign · raw signature is not written to localStorage
          </small>
          <Show when={!authorization() && grantReadiness().planState === "expired"}>
            <small class="collaboration-live-boundary" role="status">
              This plan expired. Fresh owner grants cannot extend its authorization deadline.
            </small>
          </Show>
        </article>

        <article class="collaboration-live-card authorize-card">
          <div class="collaboration-live-card-title">
            <ShieldCheck size={17} />
            <div><small>STEP 03 · SPONSOR</small><strong>Authorize exact grant set</strong></div>
          </div>
          <p>
            Switch back to the sponsor. Authorization derives the reservation
            from current owner grants; it neither deposits funds nor dispatches the provider.
          </p>
          <button
            type="button"
            class="primary-button"
            disabled={workflowState() === "working" || !grantReadiness().canAuthorize || Boolean(retainedAuthorizationResponse())}
            onClick={() => void authorize()}
          >
            <LockKeyhole size={14} /> Authorize and queue inertly
          </button>
          <Show when={retainedAuthorizationResponse()}><button class="secondary-button" type="button" disabled={workflowState() === "working" || !sessionCurrent() || connectedAddress() !== plan()?.sponsor_address || !planContextMatches()} onClick={() => void recoverAuthorizationResponse()}><RefreshCw size={14} /> Recover retained authorization response</button></Show>
          <Show when={authorizationUnresolved()}>
            <small class="collaboration-live-boundary" role="status">
              Authorization outcome unresolved. The exact plan, grant set, and request key remain in memory.
              Expiry does not prove rejection. Do not replace them; use read-only execution status or operator reconciliation.
            </small>
          </Show>
          <Show when={authorization()}>{(value) => (
            <dl class="collaboration-live-facts">
              <div><dt>Execution</dt><dd>{short(value().execution.execution_id)}</dd></div>
              <div><dt>State</dt><dd>{value().execution.state.replaceAll("_", " ")}</dd></div>
              <div><dt>Reservation</dt><dd>{short(value().royalty_reservation.reservation_id)}</dd></div>
              <div><dt>Wallet action</dt><dd>{value().royalty_reservation.walletActionReady ? "fresh capability ready" : "withheld"}</dd></div>
            </dl>
          )}</Show>
        </article>
      </div>

      <div class="collaboration-live-money-grid">
        <article class="collaboration-live-card compute-authorization-card">
          <div class="collaboration-live-card-title"><WalletCards size={17} /><div><small>STEP 04A · SPONSOR WALLET</small><strong>Authorize the exact one-shot Compute job</strong></div></div>
          <p>The server derives this job from the complete owner grant set. It is never a standalone authorization. Compute capacity is reserved separately from the Royalty payment below; the worker requires both exact finalized records.</p>
          <div class="collaboration-live-actions">
            <button type="button" disabled={workflowState() === "working" || !authorization() || connectedAddress() !== plan()?.sponsor_address} onClick={() => void prepareComputeAuthorization()}><Fingerprint size={13} /> Prepare Compute authorization</button>
            <button type="button" class="primary-button" disabled={workflowState() === "working" || computeAuthorizationIntent()?.stage !== "prepared" || computeAuthorizationIntent()?.terms.executionId !== authorization()?.execution.execution_id || !authorization() || connectedAddress() !== plan()?.sponsor_address} onClick={() => void submitComputeAuthorization()}><WalletCards size={13} /> Sign & reserve Compute</button>
            <button type="button" disabled={workflowState() === "working" || !computeAuthorizationIntent()} onClick={() => void reconcileComputeAuthorization()}><RefreshCw size={13} /> Reconcile Compute finality</button>
          </div>
          <Show when={retainedComputeIntents().length > 0}><div class="collaboration-retained-intents"><strong>Retained public Compute attempts</strong><For each={retainedComputeIntents()}>{intent => <button type="button" disabled={workflowState() === "working"} onClick={() => { setComputeAuthorizationIntent(intent); setComputeAuthorizationOutcome(undefined); }}><code>{short(intent.terms.jobId)}</code><small>{intent.stage.replaceAll("_", " ")}</small></button>}</For></div></Show>
          <Show when={computeAuthorizationIntent()}>{intent => <dl class="collaboration-live-facts"><div><dt>Job</dt><dd>{short(intent().terms.jobId)}</dd></div><div><dt>Maximum debit</dt><dd>{intent().terms.maxAssetDebit.toString()} base units</dd></div><div><dt>Stage</dt><dd>{intent().stage.replaceAll("_", " ")}</dd></div><div><dt>Transaction</dt><dd>{intent().transactionHash ? short(intent().transactionHash!) : intent().stage === "submission_started" ? "Unknown · do not resubmit" : "Not sent"}</dd></div></dl>}</Show>
          <Show when={computeAuthorizationOutcome()}>{outcome => <p role="status"><strong>{outcome().status.replaceAll("_", " ")}</strong> · {outcome().detail}</p>}</Show>
          <small class="collaboration-live-boundary">Only public exact terms and transaction recovery state are retained in browser storage. An unknown submission cannot be replaced or automatically retried. Finalized browser reads are not worker claim, TDX or QVL evidence.</small>
        </article>
        <article class="collaboration-live-card reservation-card">
          <div class="collaboration-live-card-title">
            <Coins size={17} />
            <div><small>STEP 04B · SPONSOR WALLET</small><strong>Fund exact Royalty reservation</strong></div>
          </div>
          <p>
            Fresh authenticated worker/QVL capability opens this funding seam.
            It is process reachability—not per-job attestation—and can expire before any click.
          </p>
          <div class="collaboration-live-actions">
            <button type="button" disabled={workflowState() === "working" || !authorization() || connectedAddress() !== plan()?.sponsor_address} onClick={() => void prepareReservation()}>
              <Fingerprint size={13} /> Retain exact intent
            </button>
            <button type="button" disabled={workflowState() === "working" || selectedReservation()?.asset.kind !== "erc20" || selectedReservation()?.stage !== "intent_persisted"} onClick={() => void approveReservationAsset()}>
              <WalletCards size={13} /> Approve exact token amount
            </button>
            <button type="button" disabled={workflowState() === "working" || selectedReservation()?.stage !== "approval_submitted"} onClick={() => void reconcileApproval()}>
              <RefreshCw size={13} /> Reconcile approval
            </button>
            <button type="button" class="primary-button" disabled={workflowState() === "working" || !selectedReservation() || Boolean(selectedReservation()?.reservationTransactionHash) || (selectedReservation()?.asset.kind === "erc20" && selectedReservation()?.stage !== "approval_finalized")} onClick={() => void reserveFunding()}>
              <Send size={13} /> Reserve funding
            </button>
            <button type="button" disabled={workflowState() === "working" || !selectedReservation()?.reservationTransactionHash} onClick={() => void reconcileReservation()}>
              <RefreshCw size={13} /> Reconcile finality
            </button>
            <button type="button" disabled={workflowState() === "working" || !selectedReservation()} onClick={() => void inspectReservation()}>
              <Fingerprint size={13} /> Inspect deterministic state
            </button>
            <button type="button" disabled={workflowState() === "working" || !selectedReservationRefundReady() || Boolean(selectedReservation()?.refundTransactionHash)} onClick={() => void refundReservation()}>
              <Coins size={13} /> Refund expired reservation
            </button>
            <button type="button" disabled={workflowState() === "working" || !selectedReservation()?.refundTransactionHash} onClick={() => void reconcileRefund()}>
              <RefreshCw size={13} /> Reconcile refund
            </button>
          </div>
          <Show when={reservationIntents().length > 0}>
            <div class="collaboration-retained-intents">
              <strong>Retained public intents</strong>
              <For each={reservationIntents()}>{(intent) => (
                <button
                  type="button"
                  classList={{ selected: selectedReservationId() === intent.reservationId }}
                  onClick={() => setSelectedReservationId(intent.reservationId)}
                >
                  <span>{intent.asset.symbol}</span>
                  <code>{short(intent.reservationId, 10, 7)}</code>
                  <small>{intent.stage.replaceAll("_", " ")}</small>
                </button>
              )}</For>
            </div>
          </Show>
          <Show when={selectedReservation()}>{(intent) => (
            <dl class="collaboration-live-facts">
              <div><dt>Total</dt><dd>{intent().request.total.toString()} {intent().asset.symbol}</dd></div>
              <div><dt>Refund after</dt><dd>{new Date(Number(intent().request.refundAfter) * 1_000).toLocaleString()}</dd></div>
              <div><dt>Approval tx</dt><dd>{intent().approvalTransactionHash ? short(intent().approvalTransactionHash!) : "not required / not sent"}</dd></div>
              <div><dt>Reservation tx</dt><dd>{intent().reservationTransactionHash ? short(intent().reservationTransactionHash!) : "not sent"}</dd></div>
              <div><dt>Refund tx</dt><dd>{intent().refundTransactionHash ? short(intent().refundTransactionHash!) : "not sent"}</dd></div>
            </dl>
          )}</Show>
          <Show when={reservationOutcome()}>{(outcome) => (
            <div class="collaboration-live-proofline">
              <BadgeCheck size={14} />
              <span><strong>{outcome().status.replaceAll("_", " ")}</strong>{outcome().detail}</span>
            </div>
          )}</Show>
        </article>

        <article class="collaboration-live-card settlement-card">
          <div class="collaboration-live-card-title">
            <ShieldCheck size={17} />
            <div><small>STEP 05 · AFTER BOUNDED RESULT</small><strong>Dual-authorized settlement</strong></div>
          </div>
          <p>
            The CVM prepares one exact plan only after per-job TDX evidence,
            independent QVL authorization, result commitments, and a finalized current anchor.
          </p>
          <div class="collaboration-live-actions">
            <button type="button" disabled={workflowState() === "working" || !activeExecutionId()} onClick={() => void prepareSettlement()}>
              <ShieldCheck size={13} /> Prepare evidence plan
            </button>
            <button type="button" disabled={workflowState() === "working" || !activeExecutionId()} onClick={() => void refreshSettlement()}>
              <RefreshCw size={13} /> Refresh journal
            </button>
            <button type="button" disabled={workflowState() === "working" || settlementStatus()?.state !== "expired"} onClick={() => void replaceExpiredSettlement()}>
              <RefreshCw size={13} /> Replace expired authorization
            </button>
            <button type="button" class="primary-button" disabled={workflowState() === "working" || settlementIntent()?.stage !== "plan_persisted"} onClick={() => void broadcastSettlement()}>
              <WalletCards size={13} /> Settle reserved
            </button>
            <button type="button" disabled={workflowState() === "working" || settlementIntent()?.stage !== "transaction_submitted"} onClick={() => void reportSettlement()}>
              <Send size={13} /> Report exact hash
            </button>
            <button type="button" disabled={workflowState() === "working" || !settlementIntent()?.transactionHash} onClick={() => void reconcileSettlement()}>
              <RefreshCw size={13} /> Reconcile settlement
            </button>
          </div>
          <Show when={retainedSettlementIntents().length > 0}>
            <div class="collaboration-retained-intents">
              <strong>Retained settlement plans</strong>
              <For each={retainedSettlementIntents()}>{(intent) => (
                <button
                  type="button"
                  classList={{
                    selected: settlementIntent()?.plan.plan_commitment
                      === intent.plan.plan_commitment,
                  }}
                  onClick={() => setSettlementIntent(intent)}
                >
                  <span>PLAN</span>
                  <code>{short(intent.executionId, 10, 7)}</code>
                  <small>{intent.stage.replaceAll("_", " ")}</small>
                </button>
              )}</For>
            </div>
          </Show>
          <Show when={settlementStatus()}>{(status) => (
            <dl class="collaboration-live-facts">
              <div><dt>Journal</dt><dd>{status().state.replaceAll("_", " ")}</dd></div>
              <div><dt>Generation</dt><dd>{status().generation}</dd></div>
              <div><dt>Plan</dt><dd>{status().plan_commitment ? short(status().plan_commitment!) : "not issued"}</dd></div>
              <div><dt>Client proves settlement</dt><dd>no</dd></div>
            </dl>
          )}</Show>
          <Show when={settlementIntent()}>{(intent) => (
            <div class="collaboration-live-proofline">
              <Fingerprint size={14} />
              <span><strong>{intent().stage.replaceAll("_", " ")}</strong>{intent().transactionHash ? `Retained ${short(intent().transactionHash!)}` : "Exact wallet plan retained before prompt"}</span>
            </div>
          )}</Show>
          <Show when={settlementReconciliation()}>{(result) => (
            <div class="collaboration-live-proofline">
              {result().state === "settled" ? <BadgeCheck size={14} /> : <ShieldAlert size={14} />}
              <span><strong>{result().state.replaceAll("_", " ")}</strong>{result().detail}</span>
            </div>
          )}</Show>
        </article>
      </div>

      <Show when={workflowState() !== "idle" || workflowMessage()}>
        <div
          class={`collaboration-live-feedback ${workflowState()}`}
          role="status"
          aria-live="polite"
        >
          {workflowState() === "working"
            ? <RefreshCw size={15} />
            : workflowState() === "error"
              ? <ShieldAlert size={15} />
              : <BadgeCheck size={15} />}
          <span>{workflowMessage()}</span>
        </div>
      </Show>

      <footer class="collaboration-live-boundaries">
        <span><LockKeyhole size={13} /> Browser DTOs never unlock the worker</span>
        <span><ShieldCheck size={13} /> QVL capability ≠ per-job verdict</span>
        <span><Fingerprint size={13} /> No raw artifact, quote, prompt, or credential egress</span>
      </footer>
    </section>
  );
}
