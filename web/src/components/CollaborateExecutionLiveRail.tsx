import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
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
  assertCollaborationExecutionPlanMatchesJointRun,
  assertCollaborationExecutionPlanMatchesCurrentRelease,
  assertCollaborationExecutionGrantChallengeForSigning,
  assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease,
  collaborationSessionIsCurrent,
  type CollaborationExecutionAuthorizationResult,
  type CollaborationExecutionGrantSubmission,
  type CollaborationExecutionPlanProjection,
  type CollaborationExecutionPlanRequest,
  type CollaborationExecutionStatusProjection,
  type CollaborationExecutionWorkerCapability,
  type CollaborationJointRun,
  type CollaborationRoom,
  type CollaborationSession,
} from "../lib/collaboration";
import type { CollaborationExecutionTransportAdapter } from "../lib/collaborationExecutionTransport";
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

interface SignedExecutionGrant extends CollaborationExecutionGrantSubmission {
  readonly ownerAddress: string;
  readonly expiresAt: number;
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
  const [planRequestJson, setPlanRequestJson] = createSignal("");
  const [plan, setPlan] = createSignal<CollaborationExecutionPlanProjection>();
  const [signedGrants, setSignedGrants] = createSignal<
    readonly SignedExecutionGrant[]
  >([]);
  const [authorization, setAuthorization] =
    createSignal<CollaborationExecutionAuthorizationResult>();
  const [authorizationIdempotencyKey, setAuthorizationIdempotencyKey] =
    createSignal("");
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
    "Paste one exact Compute authorization packet to begin.",
  );

  const sessionCurrent = createMemo(() => collaborationSessionIsCurrent(
    props.session,
    {
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
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
  const allOwnersSigned = createMemo(() => {
    const currentPlan = plan();
    if (!currentPlan) return false;
    const signed = new Set(
      signedGrants().map((grant) => grant.ownerAddress.toLowerCase()),
    );
    return currentPlan.owner_addresses.every((owner) => signed.has(owner));
  });
  const connectedOwnerNeedsGrant = createMemo(() => {
    const currentPlan = plan();
    const account = connectedAddress();
    if (!currentPlan || !account || !currentPlan.owner_addresses.includes(account)) {
      return false;
    }
    return !signedGrants().some(
      (grant) => grant.ownerAddress.toLowerCase() === account,
    );
  });
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
    if (!adapter || !session || !account || !sessionCurrent()) {
      throw new Error(
        "Connect this participant wallet on Base Sepolia and refresh its Collaboration session",
      );
    }
    return { adapter, session, account: account.toLowerCase() };
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
    let value: unknown;
    try {
      value = JSON.parse(planRequestJson()) as unknown;
    } catch {
      throw new Error("The Compute authorization packet is not valid JSON");
    }
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
      const { adapter, session, account } = requireContext();
      const jointRun = props.jointRun;
      const room = props.room;
      if (!props.queueMutationsEnabled || !jointRun || !room) {
        throw new Error("The release-enabled queue and current joint snapshot are required");
      }
      await assertFreshControlPlaneRoyaltyAuthority();
      const next = await adapter.createPlan(
        session.accessToken,
        jointRun.run_id,
        parsePlanRequest(),
        account,
        undefined,
        { room, jointRun },
      );
      setPlan(next);
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
      if (!props.queueMutationsEnabled) {
        throw new Error("The release-enabled queue is no longer current");
      }
      if (!currentPlan) throw new Error("Create the execution plan first");
      assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan);
      if (!props.room || !props.jointRun) {
        throw new Error("The selected room or joint snapshot is no longer available");
      }
      assertCollaborationExecutionPlanMatchesJointRun(
        currentPlan,
        props.jointRun,
        props.room,
      );
      if (!currentPlan.owner_addresses.includes(account)) {
        throw new Error("The connected wallet is not an owner in this exact plan");
      }
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      const challenge = await adapter.issueGrantChallenge(
        session.accessToken,
        currentPlan.plan_token,
      );
      assertCollaborationExecutionGrantChallengeForSigning(challenge, {
        plan: currentPlan,
        ownerAddress: account,
      });
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      assertCollaborationExecutionGrantChallengeForSigning(challenge, {
        plan: currentPlan,
        ownerAddress: account,
      });
      const signature = await wallet.signPersonalMessage(challenge.message);
      if (!sessionCurrent() || wallet.account()?.toLowerCase() !== account) {
        throw new Error("Wallet or Collaboration session changed during signing");
      }
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
      setSignedGrants((current) => Object.freeze([
        ...current.filter((item) => item.ownerAddress !== account),
        grant,
      ]));
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
      assertCollaborationExecutionPlanMatchesCurrentRelease(currentPlan);
      if (!props.room || !props.jointRun) {
        throw new Error("The selected room or joint snapshot is no longer available");
      }
      assertCollaborationExecutionPlanMatchesJointRun(
        currentPlan,
        props.jointRun,
        props.room,
      );
      if (!allOwnersSigned()) {
        throw new Error("Every plan owner must sign a fresh execution grant");
      }
      const now = Math.floor(Date.now() / 1_000);
      if (signedGrants().some((grant) => now >= grant.expiresAt)) {
        throw new Error("At least one owner grant expired; reconnect that owner and sign a fresh challenge");
      }
      let key = authorizationIdempotencyKey();
      if (!key) {
        key = exactIdempotencyKey("collab-authorize");
        setAuthorizationIdempotencyKey(key);
      }
      await assertFreshControlPlaneRoyaltyAuthority(currentPlan);
      const result = await adapter.authorize(
        session.accessToken,
        {
          plan_token: currentPlan.plan_token,
          idempotency_key: key,
          grants: signedGrants().map((grant) => ({
            challenge_token: grant.challenge_token,
            signature: grant.signature,
          })),
        },
        undefined,
        currentPlan,
      );
      setAuthorization(result);
      props.onExecutionId(result.execution.execution_id);
      props.onExecutionStatus(result.execution);
      setSettlementPrepareIdempotencyKey("");
      return `Execution ${short(result.execution.execution_id)} is ${result.execution.state}. Provider dispatch remains gated until the exact finalized funding reservation is independently observed.`;
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
        <div classList={{ complete: Boolean(plan()) }}><span>01</span><strong>Plan</strong><small>Exact Compute packet</small></div>
        <div classList={{ complete: allOwnersSigned() }}><span>02</span><strong>Co-sign</strong><small>{signedGrants().length}/{plan()?.owner_addresses.length ?? 0} owners</small></div>
        <div classList={{ complete: Boolean(authorization()) }}><span>03</span><strong>Authorize</strong><small>Server-derived terms</small></div>
        <div classList={{ complete: reservationOutcome()?.status === "browser_finalized_active" }}><span>04</span><strong>Reserve</strong><small>Canonical finality</small></div>
        <div classList={{ complete: settlementReconciliation()?.state === "settled" }}><span>05</span><strong>Settle</strong><small>Requires per-job TDX + QVL + chain</small></div>
      </div>

      <div class="collaboration-live-grid">
        <article class="collaboration-live-card plan-card">
          <div class="collaboration-live-card-title">
            <FileJson size={17} />
            <div><small>STEP 01 · SPONSOR</small><strong>Import exact Compute authority</strong></div>
          </div>
          <p>
            Paste the bounded packet exported by Compute. IDs and commitments
            are accepted; raw prompts, training data, and provider credentials are not.
          </p>
          <label for="collaboration-compute-packet">
            <span>COMPUTE AUTHORIZATION PACKET · EXACT JSON</span>
            <textarea
              id="collaboration-compute-packet"
              value={planRequestJson()}
              onInput={(event) => setPlanRequestJson(event.currentTarget.value)}
              placeholder={'{"compute_project_id":"0x…","compute_job_id":"0x…","compute_workload_id":"wrk_…"}' }
              spellcheck={false}
              rows={7}
            />
          </label>
          <button
            type="button"
            class="primary-button"
            disabled={workflowState() === "working" || !props.queueMutationsEnabled || !planRequestJson().trim()}
            onClick={() => void createPlan()}
          >
            <Fingerprint size={14} /> Create release-bound plan
          </button>
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
              const signed = () => signedGrants().find(
                (grant) => grant.ownerAddress === owner,
              );
              return (
                <div classList={{ signed: Boolean(signed()), connected: connectedAddress() === owner }}>
                  {signed() ? <BadgeCheck size={14} /> : <CircleDashed size={14} />}
                  <code title={owner}>{short(owner, 9, 6)}</code>
                  <small>{signed() ? "fresh grant in memory" : connectedAddress() === owner ? "connected · signature needed" : "awaiting owner"}</small>
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
            disabled={workflowState() === "working" || !props.queueMutationsEnabled || !sessionCurrent() || !allOwnersSigned() || connectedAddress() !== plan()?.sponsor_address}
            onClick={() => void authorize()}
          >
            <LockKeyhole size={14} /> Authorize and queue inertly
          </button>
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
        <article class="collaboration-live-card reservation-card">
          <div class="collaboration-live-card-title">
            <Coins size={17} />
            <div><small>STEP 04 · SPONSOR WALLET</small><strong>Fund exact Royalty reservation</strong></div>
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
