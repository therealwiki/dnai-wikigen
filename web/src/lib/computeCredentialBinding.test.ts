import { afterEach, describe, expect, it, vi } from "vitest";
import { deployment } from "../config";
import { issueCredential, rotateCredential, type ComputeCredential } from "./compute";

const originalUrl = deployment.delegateUrl;
afterEach(() => { Object.assign(deployment, { delegateUrl: originalUrl }); vi.unstubAllGlobals(); });
const credential: ComputeCredential = {
  credential_id: "cred_0123456789abcdef01234567", project_id: "prj_0123456789abcdef01234567",
  device_id: "dev_0123456789abcdef01234567", name: "developer", prefix: "wk_dev_234567",
  scopes: ["jobs:read"], daily_credit_cap: 500, generation: 1, status: "active",
  issued_at: 1_800_000_000, expires_at: 1_800_000_600, last_used_at: null,
  rotated_at: null, revoked_at: null, plaintext_token_stored: false, upstream_tinker_key_exposed: false,
};
const input = { deviceId: credential.device_id, name: credential.name, scopes: credential.scopes, expiresInSeconds: 600, dailyCreditCap: 500 };
function respond(value: ComputeCredential, kind: "issuance" | "rotation" = "issuance") {
  Object.assign(deployment, { delegateUrl: "https://delegate.example" });
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
    surface: `compute_credential_${kind}`, credential: value, plaintext_token_returned: false,
    upstream_tinker_key_exposed: false, idempotent_replay: true, prior_generation_revoked: true,
    capsule: { delivery: "x25519_aes_256_gcm_envelope", plaintext_token_returned: false,
      encrypted_token: { ephemeral_public_key: "11".repeat(32), nonce: "22".repeat(12), ciphertext: "33".repeat(32) },
      associated_data: "11", associated_data_hash: "44".repeat(32), recipient_public_key_hash: "55".repeat(32) },
  }), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}

describe("Credential response binding to the original request", () => {
  it("opts issuance into bounded replay using the captured request key", async () => {
    const fetcher = respond(credential);
    await expect(issueCredential("wallet-session", credential.project_id, input, "credential-attempt-1234")).resolves.toMatchObject({ credential });
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [, options] = fetcher.mock.calls[0];
    expect(options.headers["Idempotency-Key"]).toBe("credential-attempt-1234");
    expect(JSON.parse(options.body)).toEqual({ delivery_mode: "idempotent_encrypted_capsule_v1", device_id: input.deviceId, name: input.name, scopes: input.scopes, expires_in_seconds: 600, daily_credit_cap: 500 });
  });

  it.each([
    ["project", { project_id: "prj_another_project" }],
    ["device", { device_id: "dev_another_device" }],
    ["name", { name: "different" }],
    ["scope", { scopes: ["jobs:create"] }],
    ["cap", { daily_credit_cap: 501 }],
    ["generation", { generation: 2 }],
    ["lifetime", { expires_at: credential.expires_at + 1 }],
    ["revocation", { status: "revoked", revoked_at: 1_800_000_010 }],
  ] as const)("rejects an otherwise valid capsule with mismatched %s metadata", async (_label, update) => {
    respond({ ...credential, ...update } as ComputeCredential);
    await expect(issueCredential("wallet-session", credential.project_id, input, "credential-attempt-1234")).rejects.toThrow("does not match");
  });

  it("opts rotation into replay and sends the original generation CAS", async () => {
    const rotated = { ...credential, generation: 2, rotated_at: credential.issued_at };
    const fetcher = respond(rotated, "rotation");
    await expect(rotateCredential("wallet-session", credential.project_id, credential, 600, "rotation-attempt-1234")).resolves.toMatchObject({ credential: rotated });
    const [, options] = fetcher.mock.calls[0];
    expect(options.headers["Idempotency-Key"]).toBe("rotation-attempt-1234");
    expect(JSON.parse(options.body)).toEqual({ delivery_mode: "idempotent_encrypted_capsule_v1", expires_in_seconds: 600, expected_generation: 1 });
  });

  it.each([
    { credential_id: "cred_another_credential" }, { device_id: "dev_another_device" },
    { generation: 3 }, { generation: 1 }, { scopes: ["jobs:create"] }, { daily_credit_cap: 501 },
  ])("rejects a rotation response that changes identity or exceeds the one requested generation: %j", async (update) => {
    respond({ ...credential, generation: 2, ...update } as ComputeCredential, "rotation");
    await expect(rotateCredential("wallet-session", credential.project_id, credential, 600, "rotation-attempt-1234")).rejects.toThrow("does not match");
  });

  it("does not dispatch a rotation for a credential from another project", async () => {
    const fetcher = respond(credential);
    await expect(rotateCredential("wallet-session", "prj_another_project", credential, 600, "rotation-attempt-1234")).rejects.toThrow("another project");
    expect(fetcher).not.toHaveBeenCalled();
  });
});
