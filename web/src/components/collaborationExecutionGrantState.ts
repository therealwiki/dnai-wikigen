import type {
  CollaborationExecutionGrantSubmission,
  CollaborationExecutionPlanProjection,
  CollaborationExecutionPlanRequest,
  CollaborationSession,
  CollaborationRoom,
  CollaborationJointRun,
} from "../lib/collaboration";

export interface SignedExecutionGrant extends CollaborationExecutionGrantSubmission {
  readonly ownerAddress: string;
  readonly expiresAt: number;
}

export type ExecutionGrantAuthorizationState = "not_started" | "attempted" | "authorized";

export interface CollaborationExecutionResponseContext {
  readonly plan?: CollaborationExecutionPlanProjection;
  readonly request?: CollaborationExecutionPlanRequest;
  readonly session?: CollaborationSession;
  readonly room?: CollaborationRoom;
  readonly jointRun?: CollaborationJointRun;
  readonly key: string;
  readonly account?: string;
  readonly walletVersion: number;
}

/** A delayed authorization result is retained, but must not be published into a new UI scope. */
export function collaborationExecutionResponseIsCurrent(
  original: CollaborationExecutionResponseContext,
  current: CollaborationExecutionResponseContext,
  participantSessionCurrent: boolean,
): boolean {
  return participantSessionCurrent && Boolean(original.plan && original.request && original.session
    && original.room && original.jointRun && original.key && original.account)
    && original.plan === current.plan && original.request === current.request && original.session === current.session
    && original.room === current.room && original.jointRun === current.jointRun && original.key === current.key
    && original.account?.toLowerCase() === current.account?.toLowerCase() && original.walletVersion === current.walletVersion;
}

export function inspectCollaborationExecutionGrants(input: {
  readonly plan?: Pick<CollaborationExecutionPlanProjection, "owner_addresses" | "sponsor_address" | "authorization_expiry">;
  readonly grants: readonly SignedExecutionGrant[];
  readonly connectedAddress?: string;
  readonly nowMs: number;
  readonly planContextMatches: boolean;
  readonly participantContextCurrent: boolean;
  readonly authorizationState: ExecutionGrantAuthorizationState;
}) {
  const account = input.connectedAddress?.toLowerCase();
  const plan = input.plan;
  const planState = !plan ? "missing"
    : !Number.isSafeInteger(plan.authorization_expiry)
      || !Number.isFinite(input.nowMs)
      || input.nowMs >= plan.authorization_expiry * 1_000 ? "expired"
      : !input.planContextMatches ? "changed" : "current";
  const owners = (plan?.owner_addresses ?? []).map((owner) => {
    const grant = input.grants.find((item) => item.ownerAddress.toLowerCase() === owner);
    const fresh = Boolean(grant
      && Number.isSafeInteger(grant.expiresAt)
      && input.nowMs < grant.expiresAt * 1_000);
    const state = !grant ? "missing" : fresh ? "fresh" : "expired";
    const connected = account === owner;
    const label = input.authorizationState === "authorized" ? "included in authorized grant set"
      : input.authorizationState === "attempted" ? fresh
        ? "authorization attempted · set retained" : "grant expired · attempted set retained"
        : planState === "expired" ? "plan expired · new plan needed"
          : planState === "changed" ? "plan context changed · new plan needed"
            : fresh ? "fresh grant in memory"
              : grant ? connected
                ? input.participantContextCurrent ? "expired · connected owner can re-sign" : "expired · refresh owner session"
                : "expired · reconnect owner"
                : connected ? "connected · signature needed" : "awaiting owner";
    return Object.freeze({ owner, state, fresh: planState === "current" && fresh, connected, label });
  });
  const freshOwnerCount = owners.filter((owner) => owner.fresh).length;
  const allOwnersSigned = planState === "current" && owners.length > 0
    && freshOwnerCount === owners.length;
  return Object.freeze({
    planState,
    owners: Object.freeze(owners),
    freshOwnerCount,
    allOwnersSigned,
    connectedOwnerNeedsGrant: planState === "current"
      && input.participantContextCurrent
      && input.authorizationState === "not_started"
      && owners.some((owner) => owner.connected && !owner.fresh),
    canAuthorize: allOwnersSigned && input.participantContextCurrent
      && account === plan?.sponsor_address
      && input.authorizationState !== "authorized",
  });
}

export function replaceCollaborationOwnerGrant(
  current: readonly SignedExecutionGrant[],
  next: SignedExecutionGrant,
): readonly SignedExecutionGrant[] {
  return Object.freeze([
    ...current.filter((item) => item.ownerAddress.toLowerCase() !== next.ownerAddress.toLowerCase()),
    Object.freeze(next),
  ]);
}

// A deadline clock, not a polling mutation: expiry only refreshes presentation.
// Click handlers must still check Date.now() in case a background tab was paused.
export function createCollaborationExecutionGrantClock(onTime: (nowMs: number) => void) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let deadlines: readonly number[] = [];
  let disposed = false;
  const cancel = () => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  };
  const publishAndSchedule = () => {
    const now = Date.now();
    onTime(now);
    // Select against the published instant. Rendering can itself cross a
    // deadline; in that case a zero-delay tick must publish the later time.
    const next = deadlines.filter((deadline) => deadline > now).sort((a, b) => a - b)[0];
    if (next === undefined || disposed) return;
    timer = setTimeout(() => {
      timer = undefined;
      if (disposed) return;
      publishAndSchedule();
    }, Math.max(0, Math.min(next - Date.now(), 2_147_483_647)));
  };
  return Object.freeze({
    replace(next: readonly number[]) {
      if (disposed) return;
      cancel();
      deadlines = next.filter(Number.isFinite);
      publishAndSchedule();
    },
    dispose() {
      disposed = true;
      cancel();
      deadlines = [];
    },
  });
}
