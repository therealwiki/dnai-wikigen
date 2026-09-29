import {
  COMPUTE_PUBLIC_CREDENTIAL_SCOPES, decryptCredentialCapsule, generateDeviceKey, issueCredential, listCredentials, listDevices,
  newIdempotencyKey, registerDevice, revokeCredential, revokeDevice, rotateCredential,
  type ComputeCredential, type ComputeCredentialDelivery, type ComputeDevice,
  type ComputeScope, type DeviceKeyMaterial, type DeviceKind,
} from "./compute";

export interface CredentialDraft {
  name: string;
  kind: DeviceKind;
  scopes: ComputeScope[];
  expiresInSeconds: number;
  dailyCreditCap: number;
}

export interface CredentialDeliveryContext {
  token: string;
  projectId: string;
  /** Must bind the wallet, network, session, project generation and release endpoint. */
  isCurrent: () => boolean;
}

export interface CredentialDeliveryRecovery {
  stage: "preparing" | "registration" | "issuance" | "rotation";
  pending: boolean;
  projectId: string;
  deviceId?: string;
  credentialId?: string;
  device?: ComputeDevice;
  credentials: ComputeCredential[];
}

interface HeldAttempt {
  context: CredentialDeliveryContext;
  recovery: CredentialDeliveryRecovery;
  key?: DeviceKeyMaterial;
  keyHash?: string;
  draft?: CredentialDraft;
  rotation?: ComputeCredential;
  requestKey: string;
  dispatched: boolean;
}

export interface ReceivedCredential {
  plaintext: string;
  key: DeviceKeyMaterial;
  credential: ComputeCredential;
}

const defaultApi = {
  generateDeviceKey, registerDevice, issueCredential, rotateCredential,
  decryptCredentialCapsule, listDevices, listCredentials, revokeDevice, revokeCredential,
};

function captureCredentialDraft(draft: CredentialDraft): CredentialDraft {
  if (!draft || typeof draft.name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(draft.name.trim())
    || !["developer_device", "ci_service", "autonomous_agent"].includes(draft.kind)
    || !Array.isArray(draft.scopes) || draft.scopes.length < 1 || draft.scopes.length > COMPUTE_PUBLIC_CREDENTIAL_SCOPES.length
    || new Set(draft.scopes).size !== draft.scopes.length
    || draft.scopes.some((scope) => !COMPUTE_PUBLIC_CREDENTIAL_SCOPES.some((allowed) => allowed === scope))
    || !Number.isSafeInteger(draft.expiresInSeconds) || draft.expiresInSeconds < 60 || draft.expiresInSeconds > 604_800
    || !Number.isSafeInteger(draft.dailyCreditCap) || draft.dailyCreditCap < 1 || draft.dailyCreditCap > 1_000_000) {
    throw new Error("Credential draft is invalid. Use a 1–64 character alphanumeric device name, supported device/scopes, a whole-number credit cap from 1 to 1,000,000, and a lifetime from 60 seconds to seven days. No device or credential was registered.");
  }
  return { ...draft, name: draft.name.trim(), scopes: [...draft.scopes] };
}

/** Explicit recovery reuses the exact request key and body; there is no automatic retry.
 * The CVM atomically retains only encrypted delivery for bounded authenticated replay.
 * Private device keys and plaintext exist only in this tab and are never persisted here.
 */
export function createComputeCredentialDelivery(
  publish: (recovery: CredentialDeliveryRecovery | undefined) => void,
  api = defaultApi,
) {
  let held: HeldAttempt | undefined;
  const current = (attempt: HeldAttempt) => held === attempt && attempt.context.isCurrent();
  function assertCurrent(attempt: HeldAttempt): void {
    if (!current(attempt)) throw new Error("Credential delivery context changed; inspect the original project's credential records before issuing again.");
  }
  function emit(attempt: HeldAttempt): void {
    if (current(attempt)) publish({ ...attempt.recovery, credentials: [...attempt.recovery.credentials] });
  }
  function clear(): void {
    held = undefined;
    publish(undefined);
  }
  function fail(attempt: HeldAttempt): void {
    if (!current(attempt)) return;
    if (!attempt.dispatched) clear();
    else {
      attempt.recovery.pending = false;
      emit(attempt);
    }
  }
  async function prepareKey(attempt: HeldAttempt): Promise<void> {
    attempt.key ??= await api.generateDeviceKey();
    assertCurrent(attempt);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`compute_device_key:${attempt.key.publicKeyHex}`));
    assertCurrent(attempt);
    attempt.keyHash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  function begin(context: CredentialDeliveryContext, stage: CredentialDeliveryRecovery["stage"], key?: DeviceKeyMaterial): HeldAttempt {
    if (held) throw new Error("Resolve the unreceived credential delivery before starting another issuance or rotation.");
    if (!context.isCurrent()) throw new Error("Authorize the original wallet and project before delivering a credential.");
    const attempt: HeldAttempt = {
      context, key, requestKey: newIdempotencyKey("credential"), dispatched: false,
      recovery: { stage, pending: true, projectId: context.projectId, credentials: [] },
    };
    held = attempt;
    emit(attempt);
    return attempt;
  }
  async function receive(attempt: HeldAttempt, delivery: ComputeCredentialDelivery): Promise<ReceivedCredential> {
    assertCurrent(attempt);
    const credential = delivery.credential;
    if (credential.project_id !== attempt.context.projectId || credential.device_id !== attempt.recovery.deviceId
      || (attempt.recovery.credentialId && credential.credential_id !== attempt.recovery.credentialId)) {
      throw new Error("Credential response does not match the original project and delivery device.");
    }
    // Only a response bound to this attempt can identify its exact credential for revocation.
    attempt.recovery.credentialId = credential.credential_id;
    const plaintext = await api.decryptCredentialCapsule(delivery, attempt.key!);
    assertCurrent(attempt);
    const result = { plaintext, key: attempt.key!, credential };
    clear();
    return result;
  }
  async function registerAndIssue(attempt: HeldAttempt): Promise<ReceivedCredential> {
    assertCurrent(attempt);
    const { context, draft, key } = attempt;
    attempt.recovery.stage = "registration";
    attempt.recovery.pending = true;
    attempt.dispatched = true;
    emit(attempt);
    const device = await api.registerDevice(context.token, context.projectId, draft!.name, draft!.kind, key!.publicKeyHex);
    assertCurrent(attempt);
    if (device.project_id !== context.projectId || device.public_key_hash !== attempt.keyHash || device.status !== "active") {
      throw new Error("Registered device does not match this delivery key and project.");
    }
    attempt.recovery.deviceId = device.device_id;
    attempt.recovery.device = device;
    return issueToDevice(attempt);
  }
  async function issueToDevice(attempt: HeldAttempt): Promise<ReceivedCredential> {
    assertCurrent(attempt);
    const { context, draft } = attempt;
    attempt.recovery.stage = "issuance";
    attempt.recovery.pending = true;
    attempt.dispatched = true;
    emit(attempt);
    const delivery = await api.issueCredential(context.token, context.projectId, {
      deviceId: attempt.recovery.deviceId!, name: draft!.name, scopes: draft!.scopes,
      expiresInSeconds: draft!.expiresInSeconds, dailyCreditCap: draft!.dailyCreditCap,
    }, attempt.requestKey);
    return receive(attempt, delivery);
  }
  async function rotateHeld(attempt: HeldAttempt): Promise<ReceivedCredential> {
    assertCurrent(attempt);
    const { context, rotation } = attempt;
    attempt.recovery.stage = "rotation";
    attempt.recovery.pending = true;
    attempt.dispatched = true;
    emit(attempt);
    const delivery = await api.rotateCredential(context.token, context.projectId, rotation!, 7 * 86_400, attempt.requestKey);
    return receive(attempt, delivery);
  }
  function available(): HeldAttempt {
    if (!held || held.recovery.pending) throw new Error("No unresolved credential delivery is available for recovery.");
    assertCurrent(held);
    return held;
  }
  return {
    invalidate: clear,
    async issue(context: CredentialDeliveryContext, draft: CredentialDraft): Promise<ReceivedCredential> {
      const captured = captureCredentialDraft(draft);
      const attempt = begin(context, "preparing");
      attempt.draft = captured;
      try {
        await prepareKey(attempt);
        return await registerAndIssue(attempt);
      } catch (cause) { fail(attempt); throw cause; }
    },
    async rotate(context: CredentialDeliveryContext, credential: ComputeCredential, key: DeviceKeyMaterial): Promise<ReceivedCredential> {
      const attempt = begin(context, "preparing", key);
      attempt.rotation = { ...credential, scopes: [...credential.scopes] };
      attempt.recovery.deviceId = credential.device_id;
      attempt.recovery.credentialId = credential.credential_id;
      try {
        await prepareKey(attempt);
        if (credential.project_id !== context.projectId) throw new Error("Credential belongs to another project.");
        return await rotateHeld(attempt);
      } catch (cause) { fail(attempt); throw cause; }
    },
    async retryDelivery(): Promise<ReceivedCredential> {
      const attempt = available();
      try {
        if (attempt.recovery.stage === "registration") return await registerAndIssue(attempt);
        if (attempt.recovery.stage === "issuance") return await issueToDevice(attempt);
        if (attempt.recovery.stage === "rotation") return await rotateHeld(attempt);
        throw new Error("Credential recovery has no dispatched request to replay.");
      }
      catch (cause) { fail(attempt); throw cause; }
    },
    async reconcile(): Promise<void> {
      const attempt = available();
      attempt.recovery.pending = true;
      emit(attempt);
      try {
        const { token, projectId } = attempt.context;
        const [devices, credentials] = await Promise.all([api.listDevices(token, projectId), api.listCredentials(token, projectId)]);
        assertCurrent(attempt);
        const matching = devices.filter((device) => device.project_id === projectId && device.public_key_hash === attempt.keyHash
          && (!attempt.recovery.deviceId || device.device_id === attempt.recovery.deviceId));
        if (matching.length > 1) throw new Error("Multiple devices match the delivery key; recovery requires operator inspection.");
        const device = matching[0];
        attempt.recovery.device = device;
        if (device) attempt.recovery.deviceId = device.device_id;
        attempt.recovery.credentials = credentials.filter((credential) => credential.project_id === projectId
          && credential.device_id === attempt.recovery.deviceId);
        const exact = attempt.recovery.credentials.find((credential) => credential.credential_id === attempt.recovery.credentialId);
        // Revocation fences late mutations; absence or expiry never proves that a POST failed.
        if (device?.status === "revoked" || exact?.status === "revoked") clear();
        else { attempt.recovery.pending = false; emit(attempt); }
      } catch (cause) { fail(attempt); throw cause; }
    },
    async revokeUnreceived(target: "device" | "credential"): Promise<void> {
      const attempt = available();
      const { projectId, token } = attempt.context;
      const { deviceId, credentialId } = attempt.recovery;
      if (!deviceId || (target === "credential" && !credentialId)) throw new Error("Read the original delivery metadata before selecting an exact revocation target.");
      attempt.recovery.pending = true;
      emit(attempt);
      try {
        if (target === "device") {
          const device = await api.revokeDevice(token, projectId, deviceId);
          assertCurrent(attempt);
          if (device.project_id !== projectId || device.device_id !== deviceId || device.public_key_hash !== attempt.keyHash || device.status !== "revoked") {
            throw new Error("Device revocation was not confirmed for this delivery key.");
          }
        } else {
          const credential = await api.revokeCredential(token, projectId, credentialId!);
          assertCurrent(attempt);
          if (credential.project_id !== projectId || credential.device_id !== deviceId || credential.credential_id !== credentialId || credential.status !== "revoked") {
            throw new Error("Credential revocation was not confirmed for this delivery attempt.");
          }
        }
        clear();
      } catch (cause) { fail(attempt); throw cause; }
    },
  };
}
