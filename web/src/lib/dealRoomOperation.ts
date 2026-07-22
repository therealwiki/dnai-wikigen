export type DealRoomOperationKind = "wallet_transaction" | "artifact_upload";

export type DealRoomOperationLease = Readonly<{
  generation: number;
  kind: DealRoomOperationKind;
  label: string;
}>;

type DealRoomOperationListener = (active: DealRoomOperationLease | undefined) => void;

/**
 * A synchronous, identity-checked mutex for Deal Room mutations.
 *
 * The frozen lease is deliberately not a mutable boolean: only the workflow
 * that acquired the exact lease can release it, so a stale completion cannot
 * unlock a newer wallet prompt or artifact upload.
 */
export class DealRoomOperationLock {
  readonly #listener: DealRoomOperationListener | undefined;
  #generation = 0;
  #active: DealRoomOperationLease | undefined;

  constructor(listener?: DealRoomOperationListener) {
    this.#listener = listener;
  }

  get active(): DealRoomOperationLease | undefined {
    return this.#active;
  }

  get busy(): boolean {
    return this.#active !== undefined;
  }

  acquire(kind: DealRoomOperationKind, label: string): DealRoomOperationLease | undefined {
    if (this.#active) return undefined;
    const lease = Object.freeze({
      generation: ++this.#generation,
      kind,
      label,
    });
    this.#active = lease;
    this.#listener?.(lease);
    return lease;
  }

  isCurrent(lease: DealRoomOperationLease): boolean {
    return this.#active === lease;
  }

  release(lease: DealRoomOperationLease): boolean {
    if (!this.isCurrent(lease)) return false;
    this.#active = undefined;
    this.#listener?.(undefined);
    return true;
  }
}

export type DealRoomOperationResult<T> =
  | Readonly<{ started: false }>
  | Readonly<{ started: true; value: T }>;

export async function runDealRoomOperation<T>(
  lock: DealRoomOperationLock,
  kind: DealRoomOperationKind,
  label: string,
  workflow: (lease: DealRoomOperationLease) => Promise<T>,
): Promise<DealRoomOperationResult<T>> {
  const lease = lock.acquire(kind, label);
  if (!lease) return Object.freeze({ started: false });
  try {
    const value = await workflow(lease);
    return Object.freeze({ started: true, value });
  } finally {
    lock.release(lease);
  }
}

export function dealRoomDraftMutationIsAllowed(input: {
  operationInFlight: boolean;
  uploadRecoveryPending?: boolean;
  explicitRecoveryDiscard?: boolean;
}): boolean {
  if (input.operationInFlight) return false;
  return !input.uploadRecoveryPending || input.explicitRecoveryDiscard === true;
}
