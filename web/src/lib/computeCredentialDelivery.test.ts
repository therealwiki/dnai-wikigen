import { describe, expect, it, vi } from "vitest";
import { createComputeCredentialDelivery, type CredentialDeliveryRecovery, type CredentialDraft } from "./computeCredentialDelivery";
import type { ComputeCredential, ComputeCredentialDelivery, ComputeDevice, DeviceKeyMaterial } from "./compute";

const projectId = "prj_0123456789abcdef01234567";
const key: DeviceKeyMaterial = { publicKeyHex: "11".repeat(32), privateKey: {} as CryptoKey };
const draft: CredentialDraft = { name: "developer", kind: "developer_device", scopes: ["jobs:read"], expiresInSeconds: 604_800, dailyCreditCap: 500 };
const credential: ComputeCredential = {
  credential_id: "cred_0123456789abcdef01234567", project_id: projectId,
  device_id: "dev_0123456789abcdef01234567", name: draft.name, prefix: "wk_dev_234567",
  scopes: ["jobs:read"], daily_credit_cap: 500, generation: 1, status: "active",
  issued_at: 1_800_000_000, expires_at: 1_800_604_800, last_used_at: null,
  rotated_at: null, revoked_at: null, plaintext_token_stored: false, upstream_tinker_key_exposed: false,
};
const delivery: ComputeCredentialDelivery = {
  credential,
  capsule: { delivery: "x25519_aes_256_gcm_envelope", encrypted_token: { ephemeral_public_key: "22".repeat(32), nonce: "11".repeat(12), ciphertext: "33".repeat(32) }, associated_data: "11", associated_data_hash: "44".repeat(32), recipient_public_key_hash: "55".repeat(32), plaintext_token_returned: false },
};

async function fixture() {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`compute_device_key:${key.publicKeyHex}`));
  const device: ComputeDevice = {
    device_id: credential.device_id, project_id: projectId, label: draft.name, kind: draft.kind,
    public_key_hash: Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join(""),
    status: "active", registered_at: credential.issued_at, revoked_at: null,
    binding: "encrypted_delivery_only_not_hardware_attestation", public_key_returned: false,
  };
  let current = true;
  let recovery: CredentialDeliveryRecovery | undefined;
  const publish = vi.fn((value: CredentialDeliveryRecovery | undefined) => { recovery = value; });
  const api = {
    generateDeviceKey: vi.fn(async () => key), registerDevice: vi.fn(async () => device),
    issueCredential: vi.fn(async () => delivery),
    rotateCredential: vi.fn(async () => ({ ...delivery, credential: { ...credential, generation: 2 } })),
    decryptCredentialCapsule: vi.fn(async () => "one-time-test-token"),
    listDevices: vi.fn(async () => [device]), listCredentials: vi.fn(async () => [credential]),
    revokeDevice: vi.fn(async (): Promise<ComputeDevice> => ({ ...device, status: "revoked" })),
    revokeCredential: vi.fn(async (): Promise<ComputeCredential> => ({ ...credential, status: "revoked" })),
  };
  const controller = createComputeCredentialDelivery(publish, api);
  const context = { token: "wallet-session", projectId, isCurrent: () => current };
  return { controller, context, api, device, publish, recovery: () => recovery, invalidateContext: () => { current = false; controller.invalidate(); } };
}

describe("Bounded credential delivery recovery", () => {
  it.each([
    { name: "" }, { name: "_invalid" }, { name: "x".repeat(65) }, { name: "device\nname" },
    { kind: "unknown" }, { scopes: [] }, { scopes: ["unknown:scope"] }, { scopes: ["jobs:read", "jobs:read"] },
    { expiresInSeconds: 59 }, { expiresInSeconds: 604_801 }, { expiresInSeconds: 60.5 }, { expiresInSeconds: Number.NaN },
    { dailyCreditCap: 0 }, { dailyCreditCap: 1.5 }, { dailyCreditCap: 1_000_001 }, { dailyCreditCap: Number.NaN },
  ])("rejects malformed immutable drafts before generating a key or registering any device: %j", async (update) => {
    const f = await fixture();
    await expect(f.controller.issue(f.context, { ...draft, ...update } as CredentialDraft)).rejects.toThrow("draft is invalid");
    expect(f.recovery()).toBeUndefined();
    expect(f.api.generateDeviceKey).not.toHaveBeenCalled();
    expect(f.api.registerDevice).not.toHaveBeenCalled();
    expect(f.api.issueCredential).not.toHaveBeenCalled();
  });

  it("does not call a mutation or create ambiguous state when key preparation fails", async () => {
    const f = await fixture();
    f.api.generateDeviceKey.mockRejectedValueOnce(new Error("X25519 unavailable"));
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("X25519 unavailable");
    expect(f.recovery()).toBeUndefined();
    expect(f.api.registerDevice).not.toHaveBeenCalled();
    expect(f.api.issueCredential).not.toHaveBeenCalled();
    await expect(f.controller.issue(f.context, draft)).resolves.toMatchObject({ plaintext: "one-time-test-token" });
  });

  it("retries a lost registration with the same in-memory key and captured draft only on explicit request", async () => {
    const f = await fixture();
    const editable = { ...draft, scopes: [...draft.scopes] };
    f.api.registerDevice.mockRejectedValueOnce(new Error("lost registration response"));
    await expect(f.controller.issue(f.context, editable)).rejects.toThrow("lost registration");
    expect(f.recovery()).toMatchObject({ stage: "registration", pending: false });
    expect(f.api.registerDevice).toHaveBeenCalledTimes(1);
    expect(f.api.issueCredential).not.toHaveBeenCalled();
    editable.name = "different";
    editable.scopes.push("jobs:create");
    await expect(f.controller.retryDelivery()).resolves.toMatchObject({ plaintext: "one-time-test-token" });
    expect(f.api.generateDeviceKey).toHaveBeenCalledTimes(1);
    expect(f.api.registerDevice.mock.calls[1]).toEqual(f.api.registerDevice.mock.calls[0]);
    expect(f.api.issueCredential).toHaveBeenCalledWith("wallet-session", projectId, expect.objectContaining({ name: "developer", scopes: ["jobs:read"] }), expect.any(String));
    expect(f.recovery()).toBeUndefined();
  });

  it("recovers a lost issuance with the identical request key/body without registering or generating another key", async () => {
    const f = await fixture();
    f.api.issueCredential.mockRejectedValueOnce(new Error("response lost after commit"));
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("response lost");
    expect(f.recovery()).toMatchObject({ stage: "issuance", pending: false, deviceId: credential.device_id });
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("Resolve the unreceived");
    expect(f.api.issueCredential).toHaveBeenCalledTimes(1);
    await expect(f.controller.retryDelivery()).resolves.toMatchObject({ credential, plaintext: "one-time-test-token" });
    expect(f.api.issueCredential.mock.calls[1]).toEqual(f.api.issueCredential.mock.calls[0]);
    expect(f.api.registerDevice).toHaveBeenCalledTimes(1);
    expect(f.api.generateDeviceKey).toHaveBeenCalledTimes(1);
    expect(f.publish.mock.calls.every(([state]) => !state || (!JSON.stringify(state).includes("one-time-test-token") && !JSON.stringify(state).includes("privateKey")))).toBe(true);
  });

  it("rotation recovery retains the original expected generation even after later metadata changes", async () => {
    const f = await fixture();
    const original = { ...credential, scopes: [...credential.scopes] };
    f.api.rotateCredential.mockRejectedValueOnce(new Error("rotation response lost"));
    await expect(f.controller.rotate(f.context, original, key)).rejects.toThrow("rotation response lost");
    original.generation = 2;
    original.scopes.push("jobs:create");
    expect(f.recovery()).toMatchObject({ stage: "rotation", credentialId: credential.credential_id, pending: false });
    await f.controller.retryDelivery();
    expect(f.api.rotateCredential.mock.calls[1]).toEqual(f.api.rotateCredential.mock.calls[0]);
    expect(f.api.rotateCredential).toHaveBeenCalledWith("wallet-session", projectId, expect.objectContaining({ generation: 1, scopes: ["jobs:read"] }), 604_800, expect.any(String));
    expect(f.api.generateDeviceKey).not.toHaveBeenCalled();
  });

  it("retains the exact credential identity when decryption fails and requires confirmed revocation", async () => {
    const f = await fixture();
    f.api.decryptCredentialCapsule.mockRejectedValueOnce(new Error("invalid capsule binding"));
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("invalid capsule binding");
    expect(f.recovery()).toMatchObject({ credentialId: credential.credential_id, pending: false });
    f.api.revokeCredential.mockResolvedValueOnce({ ...credential, status: "active" });
    await expect(f.controller.revokeUnreceived("credential")).rejects.toThrow("not confirmed");
    expect(f.recovery()).toBeDefined();
    await f.controller.revokeUnreceived("credential");
    expect(f.recovery()).toBeUndefined();
  });

  it("GET absence never clears an ambiguous delivery or causes an automatic retry", async () => {
    const f = await fixture();
    f.api.issueCredential.mockRejectedValueOnce(new Error("timeout"));
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("timeout");
    f.api.listDevices.mockResolvedValueOnce([]);
    f.api.listCredentials.mockResolvedValueOnce([]);
    await f.controller.reconcile();
    expect(f.recovery()).toMatchObject({ stage: "issuance", pending: false, credentials: [] });
    expect(f.api.issueCredential).toHaveBeenCalledTimes(1);
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("Resolve the unreceived");
  });

  it("reconciles only the original key/project and does not infer an exact request ID from unrelated credentials", async () => {
    const f = await fixture();
    f.api.registerDevice.mockRejectedValueOnce(new Error("timeout"));
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("timeout");
    f.api.listDevices.mockResolvedValueOnce([{ ...f.device, project_id: "prj_elsewhere", status: "revoked" }]);
    f.api.listCredentials.mockResolvedValueOnce([{ ...credential, status: "revoked" }]);
    await f.controller.reconcile();
    expect(f.recovery()).toMatchObject({ stage: "registration", pending: false });
    expect(f.recovery()?.deviceId).toBeUndefined();
    await f.controller.reconcile();
    expect(f.recovery()?.deviceId).toBe(credential.device_id);
    expect(f.recovery()?.credentialId).toBeUndefined();
    await expect(f.controller.revokeUnreceived("credential")).rejects.toThrow("exact revocation target");
    await f.controller.revokeUnreceived("device");
    expect(f.recovery()).toBeUndefined();
  });

  it("revoked metadata resolves a known rotation, while expired metadata does not fence a late rotation", async () => {
    const f = await fixture();
    f.api.rotateCredential.mockRejectedValueOnce(new Error("timeout"));
    await expect(f.controller.rotate(f.context, credential, key)).rejects.toThrow("timeout");
    f.api.listCredentials.mockResolvedValueOnce([{ ...credential, status: "expired" }]);
    await f.controller.reconcile();
    expect(f.recovery()).toBeDefined();
    f.api.listCredentials.mockResolvedValueOnce([{ ...credential, status: "revoked" }]);
    await f.controller.reconcile();
    expect(f.recovery()).toBeUndefined();
  });

  it.each(["wallet", "project", "network", "release", "unmount"])("a %s boundary cannot publish a late credential or permit a retry", async () => {
    const f = await fixture();
    let finish!: (value: ComputeDevice) => void;
    f.api.registerDevice.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    const pending = f.controller.issue(f.context, draft);
    await vi.waitFor(() => expect(f.api.registerDevice).toHaveBeenCalledTimes(1));
    f.invalidateContext();
    finish(f.device);
    await expect(pending).rejects.toThrow("context changed");
    expect(f.api.issueCredential).not.toHaveBeenCalled();
    expect(f.api.decryptCredentialCapsule).not.toHaveBeenCalled();
    expect(f.recovery()).toBeUndefined();
    await expect(f.controller.retryDelivery()).rejects.toThrow("No unresolved");
  });

  it("suppresses plaintext when scope changes during decryption", async () => {
    const f = await fixture();
    f.api.decryptCredentialCapsule.mockImplementationOnce(async () => { f.invalidateContext(); return "late-secret"; });
    await expect(f.controller.issue(f.context, draft)).rejects.toThrow("context changed");
    expect(f.recovery()).toBeUndefined();
    expect(JSON.stringify(f.publish.mock.calls)).not.toContain("late-secret");
  });
});
