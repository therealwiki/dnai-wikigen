import { afterEach, describe, expect, it, vi } from "vitest";
import { deployment } from "../config";
import componentSource from "../components/ArenaAgentAccess.tsx?raw";
import arenaViewSource from "../views/Arena.tsx?raw";
import librarySource from "./arenaAgent.ts?raw";
import {
  ARENA_AGENT_SCOPES,
  arenaAgentCurlQuickstart,
  arenaAgentPythonQuickstart,
  assertArenaAgentCredential,
  assertArenaAgentCredentialTokenReceipt,
  createArenaAgentMutationGuard,
  decryptArenaAgentCredentialCapsule,
  generateArenaAgentDeviceKey,
  issueArenaAgentCredential,
  listArenaAgentCredentials,
  revokeArenaAgentCredential,
  rotateArenaAgentCredential,
  type ArenaAgentCredential,
  type ArenaAgentCredentialDelivery,
} from "./arenaAgent";

const owner = "0x1111111111111111111111111111111111111111";
const now = Math.floor(Date.now() / 1_000);

const credential: ArenaAgentCredential = {
  credential_id: `acred_${"a".repeat(24)}`,
  device_id: `adev_${"b".repeat(24)}`,
  challenge_id: "dnaseq-variant-qc-safe-ir",
  challenge_version: "1.0.0",
  name: "dnaseq-agent",
  prefix: "wka_aaaaaa",
  scopes: [...ARENA_AGENT_SCOPES],
  daily_submission_cap: 8,
  submission_attempts_used_today: 0,
  generation: 1,
  status: "active",
  issued_at: now - 10,
  expires_at: now + 3_590,
  last_used_at: null,
  rotated_at: null,
  revoked_at: null,
  plaintext_token_stored: false,
  cross_domain_authority: false,
  product_status: "modeled",
  execution_authority: false,
  tdx_attestation: false,
};

function base64UrlJson(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Text(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function tokenPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "dnai-wikigen:arena-agent-credential",
    aud: "dnai-wikigen:arena-agent",
    sub: credential.credential_id,
    device_id: credential.device_id,
    owner_address: owner,
    challenge_id: credential.challenge_id,
    challenge_version: credential.challenge_version,
    generation: credential.generation,
    scope: credential.scopes.join(" "),
    daily_submission_cap: credential.daily_submission_cap,
    iat: credential.issued_at,
    nbf: credential.issued_at,
    exp: credential.expires_at,
    jti: "c".repeat(32),
    ...overrides,
  };
}

function token(payload: Record<string, unknown>): string {
  return [
    base64UrlJson({ alg: "HS256", kid: "dstack-arena-agent-v1", typ: "JWT" }),
    base64UrlJson(payload),
    base64UrlBytes(new Uint8Array(32)),
  ].join(".");
}

function base64UrlBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function hex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(view, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

async function encryptedDelivery(overrides: Record<string, unknown> = {}): Promise<{
  delivery: ArenaAgentCredentialDelivery;
  deviceKey: Awaited<ReturnType<typeof generateArenaAgentDeviceKey>>;
}> {
  const deviceKey = await generateArenaAgentDeviceKey();
  const payload = tokenPayload(overrides);
  const plaintextToken = token(payload);
  const binding = {
    surface: "arena_agent_credential",
    credential_id: credential.credential_id,
    device_id: credential.device_id,
    owner_address_hash: await sha256Text(`arena_agent_owner:${owner}`),
    challenge_id: credential.challenge_id,
    challenge_version: credential.challenge_version,
    generation: credential.generation,
    jwt_id_hash: await sha256Text(`arena_agent_credential_jti:${"c".repeat(32)}`),
    expires_at: credential.expires_at,
  };
  const associatedData = new TextEncoder().encode(JSON.stringify(binding));
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const recipient = await crypto.subtle.importKey("raw", buffer(fromHex(deviceKey.publicKeyHex)), { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, ephemeral.privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: new TextEncoder().encode("dnai-wikigen-arena-agent-credential-v1") },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: associatedData, tagLength: 128 },
    aes,
    new TextEncoder().encode(plaintextToken),
  );
  const ephemeralPublic = await crypto.subtle.exportKey("raw", ephemeral.publicKey);
  const aadHex = hex(associatedData);
  const delivery = {
    credential,
    capsule: {
      delivery: "x25519_aes_256_gcm_envelope",
      encrypted_token: {
        ephemeral_public_key: hex(ephemeralPublic),
        nonce: hex(nonce),
        ciphertext: hex(ciphertext),
      },
      associated_data: aadHex,
      associated_data_hash: await sha256Text(`arena_agent_credential_aad:${aadHex}`),
      recipient_public_key_hash: await sha256Text(`arena_agent_device_key:${deviceKey.publicKeyHex}`),
      plaintext_token_returned: false,
    },
  } as ArenaAgentCredentialDelivery;
  return { delivery, deviceKey };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Arena agent credential protocol", () => {
  it("accepts only the modeled, secret-free credential projection", () => {
    expect(() => assertArenaAgentCredential(
      credential,
      credential.challenge_id,
      credential.challenge_version,
    )).not.toThrow();
    expect(() => assertArenaAgentCredential(
      { ...credential, tdx_attestation: true },
      credential.challenge_id,
      credential.challenge_version,
    )).toThrow(/bounded schema/);
    expect(() => assertArenaAgentCredential(
      { ...credential, scopes: ["challenge:submit", "challenge:agents:manage"] },
      credential.challenge_id,
      credential.challenge_version,
    )).toThrow(/bounded schema/);
    expect(() => assertArenaAgentCredential(
      { ...credential, challenge_version: "2.0.0" },
      credential.challenge_id,
      credential.challenge_version,
    )).toThrow(/bounded schema/);
  });

  it("rejects inconsistent credential status, generation, and usage timestamps", () => {
    const mutations: ArenaAgentCredential[] = [
      { ...credential, status: "revoked", revoked_at: null },
      { ...credential, generation: 2, rotated_at: null },
      { ...credential, last_used_at: credential.issued_at - 1 },
      {
        ...credential,
        status: "revoked",
        last_used_at: credential.issued_at + 4,
        revoked_at: credential.issued_at + 3,
      },
      { ...credential, status: "expired", expires_at: now + 3_600 },
    ];
    for (const mutated of mutations) {
      expect(() => assertArenaAgentCredential(
        mutated,
        credential.challenge_id,
        credential.challenge_version,
      )).toThrow(/temporal state/);
    }
    expect(() => assertArenaAgentCredential(
      {
        ...credential,
        generation: 2,
        issued_at: now,
        expires_at: now + 3_600,
        rotated_at: now,
        submission_attempts_used_today: 1,
        last_used_at: null,
      },
      credential.challenge_id,
      credential.challenge_version,
    )).not.toThrow();
  });

  it("aborts and rejects a late mutation continuation after invalidation or disposal", async () => {
    const guard = createArenaAgentMutationGuard();
    const first = guard.begin();
    let release!: () => void;
    const delayed = new Promise<void>((resolve) => { release = resolve; });
    const wouldPublishSecret = delayed.then(() => guard.isCurrent(first));
    guard.invalidate();
    release();
    await expect(wouldPublishSecret).resolves.toBe(false);
    expect(first.signal.aborted).toBe(true);

    const second = guard.begin();
    guard.dispose();
    expect(second.signal.aborted).toBe(true);
    expect(guard.isCurrent(second)).toBe(false);
    expect(() => guard.begin()).toThrow(/no longer active/);
  });

  it("checks the exact JWT payload and strict integer claim types", async () => {
    const jtiHash = await sha256Text(`arena_agent_credential_jti:${"c".repeat(32)}`);
    await expect(assertArenaAgentCredentialTokenReceipt(
      token(tokenPayload()), credential, owner, jtiHash,
    )).resolves.toBeUndefined();
    await expect(assertArenaAgentCredentialTokenReceipt(
      token(tokenPayload({ future_authority: true })), credential, owner, jtiHash,
    )).rejects.toThrow(/fields do not match/);
    for (const invalid of [true, "1", 1.5]) {
      await expect(assertArenaAgentCredentialTokenReceipt(
        token(tokenPayload({ generation: invalid })), credential, owner, jtiHash,
      )).rejects.toThrow(/supported bound/);
    }
    const valid = token(tokenPayload());
    const parts = valid.split(".");
    await expect(assertArenaAgentCredentialTokenReceipt(
      `${parts[0]}.${parts[1]}.eA`, credential, owner, jtiHash,
    )).rejects.toThrow(/signature/);
    const noncanonical = `${valid.slice(0, -1)}B`;
    await expect(assertArenaAgentCredentialTokenReceipt(
      noncanonical, credential, owner, jtiHash,
    )).rejects.toThrow(/canonical base64url/);
  });

  it("decrypts only an AAD, recipient, owner, and jti-bound capsule", async () => {
    const { delivery, deviceKey } = await encryptedDelivery();
    await expect(decryptArenaAgentCredentialCapsule(delivery, deviceKey, owner)).resolves.toMatch(/^ey/);
    await expect(decryptArenaAgentCredentialCapsule(
      delivery,
      deviceKey,
      "0x2222222222222222222222222222222222222222",
    )).rejects.toThrow(/binding/);
    await expect(decryptArenaAgentCredentialCapsule({
      ...delivery,
      capsule: { ...delivery.capsule, associated_data_hash: "0".repeat(64) },
    }, deviceKey, owner)).rejects.toThrow(/associated-data commitment/);
    await expect(decryptArenaAgentCredentialCapsule({
      ...delivery,
      capsule: { ...delivery.capsule, recipient_public_key_hash: "0".repeat(64) },
    }, deviceKey, owner)).rejects.toThrow(/recipient commitment/);

    const mismatchedJti = await encryptedDelivery({ jti: "d".repeat(32) });
    await expect(decryptArenaAgentCredentialCapsule(
      mismatchedJti.delivery,
      mismatchedJti.deviceKey,
      owner,
    )).rejects.toThrow(/token id/);
  });

  it("uses exact wallet-authenticated list, issue, rotate, and revoke requests", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const generatedPublicKey = "7".repeat(64);
    const recipientHash = await sha256Text(`arena_agent_device_key:${generatedPublicKey}`);
    const device = {
      device_id: credential.device_id,
      challenge_id: credential.challenge_id,
      challenge_version: credential.challenge_version,
      label: "arena-ci",
      kind: "ci_service",
      public_key_hash: recipientHash,
      status: "active",
      registered_at: credential.issued_at,
      revoked_at: null,
      binding: "encrypted_delivery_only_not_hardware_attestation",
      public_key_returned: false,
    };
    const capsule = {
      delivery: "x25519_aes_256_gcm_envelope",
      encrypted_token: { ephemeral_public_key: "2".repeat(64), nonce: "3".repeat(24), ciphertext: "4".repeat(64) },
      associated_data: "7b7d",
      associated_data_hash: "5".repeat(64),
      recipient_public_key_hash: recipientHash,
      plaintext_token_returned: false,
    };
    const list = {
      surface: "arena_agent_credentials", schema_version: 1,
      challenge_id: credential.challenge_id, challenge_version: credential.challenge_version,
      credentials: [credential], product_status: "modeled", execution_authority: false,
      tdx_attestation: false, plaintext_token_egress: false, cross_domain_authority: false,
    };
    const issuance = {
      surface: "arena_agent_credential_issuance", schema_version: 1, device, credential, capsule,
      plaintext_token_returned: false, cross_domain_authority: false, product_status: "modeled",
      execution_authority: false, tdx_attestation: false,
    };
    const rotation = {
      surface: "arena_agent_credential_rotation", schema_version: 1,
      credential: { ...credential, generation: 2, rotated_at: credential.issued_at }, capsule,
      prior_generation_revoked: true, plaintext_token_returned: false,
      cross_domain_authority: false, product_status: "modeled", execution_authority: false,
      tdx_attestation: false,
    };
    const revocation = {
      surface: "arena_agent_credential", schema_version: 1,
      credential: { ...credential, status: "revoked", revoked_at: credential.issued_at + 20 },
      product_status: "modeled", execution_authority: false, tdx_attestation: false,
      plaintext_token_returned: false, cross_domain_authority: false,
    };
    const responses = [list, issuance, rotation, revocation];
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const walletToken = `${"a".repeat(30)}.${"b".repeat(30)}.${"c".repeat(30)}`;
    try {
      await listArenaAgentCredentials(walletToken, credential.challenge_id, credential.challenge_version);
      await issueArenaAgentCredential(walletToken, credential.challenge_id, credential.challenge_version, {
        deviceLabel: "arena-ci", deviceKind: "ci_service", publicKey: generatedPublicKey,
        name: credential.name, expiresInSeconds: 3_600, dailySubmissionCap: 8,
      });
      await rotateArenaAgentCredential(walletToken, credential, 3_600);
      await revokeArenaAgentCredential(walletToken, credential);
      expect(fetchMock).toHaveBeenCalledTimes(4);
      const calls = fetchMock.mock.calls as unknown as Array<[string, RequestInit]>;
      expect(calls.map(([url]) => url)).toEqual([
        `https://delegate.example/arena/challenges/${credential.challenge_id}/versions/${credential.challenge_version}/agent-credentials`,
        `https://delegate.example/arena/challenges/${credential.challenge_id}/versions/${credential.challenge_version}/agent-credentials`,
        `https://delegate.example/arena/challenges/${credential.challenge_id}/versions/${credential.challenge_version}/agent-credentials/${credential.credential_id}/rotate`,
        `https://delegate.example/arena/challenges/${credential.challenge_id}/versions/${credential.challenge_version}/agent-credentials/${credential.credential_id}/revoke`,
      ]);
      for (const [, options] of calls) {
        expect(options.credentials).toBe("omit");
        expect(options.cache).toBe("no-store");
        expect(options.headers).toMatchObject({ Authorization: `Bearer ${walletToken}` });
      }
      expect(calls.map(([, options]) => options.method)).toEqual(["GET", "POST", "POST", "POST"]);
      expect(JSON.parse(String(calls[2][1].body))).toEqual({
        expires_in_seconds: 3_600,
        expected_generation: 1,
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("rejects extra response and capsule fields", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const walletToken = `${"a".repeat(30)}.${"b".repeat(30)}.${"c".repeat(30)}`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      surface: "arena_agent_credentials", schema_version: 1,
      challenge_id: credential.challenge_id, challenge_version: credential.challenge_version,
      credentials: [], product_status: "modeled", execution_authority: false,
      tdx_attestation: false, plaintext_token_egress: false, cross_domain_authority: false,
      future_authority: true,
    }), { status: 200, headers: { "Content-Type": "application/json" } })));
    try {
      await expect(listArenaAgentCredentials(
        walletToken, credential.challenge_id, credential.challenge_version,
      )).rejects.toThrow(/fields do not match/);

      const publicKey = "7".repeat(64);
      const recipientHash = await sha256Text(`arena_agent_device_key:${publicKey}`);
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
        surface: "arena_agent_credential_issuance",
        schema_version: 1,
        device: {
          device_id: credential.device_id,
          challenge_id: credential.challenge_id,
          challenge_version: credential.challenge_version,
          label: "different-label",
          kind: "ci_service",
          public_key_hash: recipientHash,
          status: "active",
          registered_at: credential.issued_at,
          revoked_at: null,
          binding: "encrypted_delivery_only_not_hardware_attestation",
          public_key_returned: false,
        },
        credential,
        capsule: {
          delivery: "x25519_aes_256_gcm_envelope",
          encrypted_token: { ephemeral_public_key: "2".repeat(64), nonce: "3".repeat(24), ciphertext: "4".repeat(64) },
          associated_data: "7b7d",
          associated_data_hash: "5".repeat(64),
          recipient_public_key_hash: recipientHash,
          plaintext_token_returned: false,
        },
        plaintext_token_returned: false,
        cross_domain_authority: false,
        product_status: "modeled",
        execution_authority: false,
        tdx_attestation: false,
      }), { status: 200, headers: { "Content-Type": "application/json" } })));
      await expect(issueArenaAgentCredential(
        walletToken,
        credential.challenge_id,
        credential.challenge_version,
        {
          deviceLabel: "arena-ci",
          deviceKind: "ci_service",
          publicKey,
          name: credential.name,
          expiresInSeconds: 3_600,
          dailySubmissionCap: credential.daily_submission_cap,
        },
      )).rejects.toThrow(/issuance receipt/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("rejects a device whose active status conflicts with its revocation time", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const walletToken = `${"a".repeat(30)}.${"b".repeat(30)}.${"c".repeat(30)}`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      surface: "arena_agent_credential_issuance",
      schema_version: 1,
      device: {
        device_id: credential.device_id,
        challenge_id: credential.challenge_id,
        challenge_version: credential.challenge_version,
        label: "arena-ci",
        kind: "ci_service",
        public_key_hash: "1".repeat(64),
        status: "active",
        registered_at: credential.issued_at,
        revoked_at: credential.issued_at + 1,
        binding: "encrypted_delivery_only_not_hardware_attestation",
        public_key_returned: false,
      },
      credential,
      capsule: {
        delivery: "x25519_aes_256_gcm_envelope",
        encrypted_token: { ephemeral_public_key: "2".repeat(64), nonce: "3".repeat(24), ciphertext: "4".repeat(64) },
        associated_data: "7b7d",
        associated_data_hash: "5".repeat(64),
        recipient_public_key_hash: "6".repeat(64),
        plaintext_token_returned: false,
      },
      plaintext_token_returned: false,
      cross_domain_authority: false,
      product_status: "modeled",
      execution_authority: false,
      tdx_attestation: false,
    }), { status: 200, headers: { "Content-Type": "application/json" } })));
    try {
      await expect(issueArenaAgentCredential(
        walletToken,
        credential.challenge_id,
        credential.challenge_version,
        {
          deviceLabel: "arena-ci",
          deviceKind: "ci_service",
          publicKey: "7".repeat(64),
          name: credential.name,
          expiresInSeconds: 3_600,
          dailySubmissionCap: 8,
        },
      )).rejects.toThrow(/device temporal state/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("binds rotation and revocation receipts to the requested credential", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const walletToken = `${"a".repeat(30)}.${"b".repeat(30)}.${"c".repeat(30)}`;
    const capsule = {
      delivery: "x25519_aes_256_gcm_envelope",
      encrypted_token: { ephemeral_public_key: "2".repeat(64), nonce: "3".repeat(24), ciphertext: "4".repeat(64) },
      associated_data: "7b7d",
      associated_data_hash: "5".repeat(64),
      recipient_public_key_hash: "6".repeat(64),
      plaintext_token_returned: false,
    };
    const differentId = `acred_${"d".repeat(24)}`;
    const responses = [
      {
        surface: "arena_agent_credential_rotation",
        schema_version: 1,
        credential: {
          ...credential,
          credential_id: differentId,
          prefix: "wka_dddddd",
          generation: 2,
          rotated_at: credential.issued_at,
        },
        capsule,
        prior_generation_revoked: true,
        plaintext_token_returned: false,
        cross_domain_authority: false,
        product_status: "modeled",
        execution_authority: false,
        tdx_attestation: false,
      },
      {
        surface: "arena_agent_credential",
        schema_version: 1,
        credential,
        product_status: "modeled",
        execution_authority: false,
        tdx_attestation: false,
        plaintext_token_returned: false,
        cross_domain_authority: false,
      },
    ];
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    try {
      await expect(rotateArenaAgentCredential(walletToken, credential, 3_600)).rejects.toThrow(/rotation receipt/);
      await expect(revokeArenaAgentCredential(walletToken, credential)).rejects.toThrow(/revocation receipt/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("generates env-var quickstarts without embedding a bearer", () => {
    const curl = arenaAgentCurlQuickstart(
      credential.challenge_id,
      credential.challenge_version,
      "https://delegate.example",
    );
    const python = arenaAgentPythonQuickstart(
      credential.challenge_id,
      credential.challenge_version,
      "https://delegate.example",
    );
    expect(curl).toContain("${WIKIGEN_ARENA_TOKEN}");
    expect(curl).toContain("Idempotency-Key");
    expect(curl).toContain(`${credential.challenge_id}/versions/${credential.challenge_version}`);
    expect(python).toContain('os.environ["WIKIGEN_ARENA_TOKEN"]');
    expect(`${curl}\n${python}`).not.toMatch(/Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./);
  });

  it("keeps private keys in memory and domains purpose-separated", () => {
    expect(`${librarySource}\n${componentSource}`).not.toMatch(/localStorage|sessionStorage|indexedDB/);
    expect(ARENA_AGENT_SCOPES.join(" ")).not.toContain("challenge:agents:manage");
    expect(componentSource).toContain("LIVE-CAPABLE AUTH · RELEASE GATED");
    expect(componentSource).toContain("LIVE-CAPABLE AGENT AUTH · RELEASE GATED · NO TDX CLAIM");
    expect(componentSource).not.toContain("MODELED AUTH");
    expect(componentSource).not.toContain("MODELED AGENT ACCESS");
    expect(componentSource).toContain("not rollback protection");
    expect(componentSource).toContain("it cannot use Compute, Deal, Tinker, contract, or payment routes");
    expect(componentSource).toContain("protects this one delivery only");
    expect(componentSource).toContain("not per-request proof-of-possession or device attestation");
    expect(componentSource).toContain("refresh the list and revoke any unexpected active credential");
    expect(componentSource).toContain("mutationGuard.dispose()");
    expect(componentSource).toContain('setOneTimeToken("")');
    expect(componentSource).toContain("Arena wallet session changed");
    expect(componentSource).not.toContain("walletSessionToken");
    expect(componentSource).toContain("Sign to manage agent keys");
    expect(componentSource).toContain("managementSession()?.access_token");
    expect(componentSource).not.toContain("deviceKeys.clear()");
    expect(arenaViewSource).toContain("const arenaAgentDeviceKeys = new Map");
    expect(arenaViewSource).toContain("onCleanup(() => arenaAgentDeviceKeys.clear())");
    expect(arenaViewSource).toContain("deviceKeys={arenaAgentDeviceKeys}");
    expect(arenaViewSource).not.toContain("walletSessionToken={arenaSession()?.access_token}");
    expect(arenaViewSource).toContain("session.expires_at * 1_000 - Date.now() - 5_000");
  });

  it("makes one-time examples and rotation blockers accessible without changing authority", () => {
    expect(componentSource).toContain('class="agent-example-tabs" role="tablist"');
    expect(componentSource).toContain('role="tab" aria-selected={example() === "curl"}');
    expect(componentSource).toContain('role="tab" aria-selected={example() === "python"}');
    expect(componentSource).toContain('aria-controls="arena-agent-example-panel"');
    expect(componentSource).toContain('class="agent-quickstart" role="tabpanel"');
    expect(componentSource).toContain('aria-labelledby={`arena-agent-example-tab-${example()}`} tabindex="0"');
    expect(componentSource).toContain("selectExampleFromKeyboard");
    expect(componentSource).toContain('class="agent-copy-error" role="alert"');
    expect(componentSource).toContain("Clipboard access was blocked.");
    expect(componentSource).toContain('aria-describedby={rotationReason() ? rotationReasonId : undefined}');
    expect(componentSource).toContain("Rotation is unavailable in this tab");
    expect(componentSource).not.toContain("challenge:agents:manage bearer");
  });

});
