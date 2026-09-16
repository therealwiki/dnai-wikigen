import { deployment } from "../config";
import { publicErrorText } from "./errorText";
import { readBoundedArenaResponseText } from "./arena";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const RESOURCE_ID = /^[a-z][a-z0-9_]{2,63}$/;
const CHALLENGE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const CHALLENGE_VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ARENA_AGENT_HKDF_INFO = "dnai-wikigen-arena-agent-credential-v1";
const ARENA_AGENT_ISSUER = "dnai-wikigen:arena-agent-credential";
const ARENA_AGENT_AUDIENCE = "dnai-wikigen:arena-agent";
const ARENA_AGENT_TOKEN_FIELDS = [
  "iss", "aud", "sub", "device_id", "owner_address", "challenge_id",
  "challenge_version", "generation", "scope", "daily_submission_cap",
  "iat", "nbf", "exp", "jti",
] as const;

export const ARENA_AGENT_SCOPES = [
  "challenge:submissions:read",
  "challenge:submit",
] as const;

export type ArenaAgentScope = typeof ARENA_AGENT_SCOPES[number];
export type ArenaAgentDeviceKind = "developer_device" | "ci_service" | "autonomous_agent";

export class ArenaAgentRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ArenaAgentRequestError";
    this.status = status;
  }
}

export interface ArenaAgentDeviceKey {
  publicKeyHex: string;
  privateKey: CryptoKey;
}

export interface ArenaAgentMutationLease {
  generation: number;
  signal: AbortSignal;
}

/**
 * Invalidates stale credential mutations and aborts their fetches. The UI
 * still binds each lease to the wallet/challenge props that began it; this
 * guard makes a late network/decrypt continuation unable to repopulate a
 * cleared one-time-secret view after session change or component disposal.
 */
export function createArenaAgentMutationGuard(): {
  begin: () => ArenaAgentMutationLease;
  invalidate: () => void;
  dispose: () => void;
  isCurrent: (lease: ArenaAgentMutationLease) => boolean;
  finish: (lease: ArenaAgentMutationLease) => boolean;
} {
  let disposed = false;
  let generation = 0;
  let controller: AbortController | undefined;

  const invalidate = (): void => {
    generation += 1;
    controller?.abort();
    controller = undefined;
  };

  return {
    begin: () => {
      if (disposed) throw new Error("Arena agent credential view is no longer active");
      invalidate();
      controller = new AbortController();
      return { generation, signal: controller.signal };
    },
    invalidate,
    dispose: () => {
      disposed = true;
      invalidate();
    },
    isCurrent: (lease) => (
      !disposed
      && lease.generation === generation
      && controller?.signal === lease.signal
      && !lease.signal.aborted
    ),
    finish: (lease) => {
      if (
        disposed
        || lease.generation !== generation
        || controller?.signal !== lease.signal
        || lease.signal.aborted
      ) return false;
      controller = undefined;
      return true;
    },
  };
}

export interface ArenaAgentDevice {
  device_id: string;
  challenge_id: string;
  challenge_version: string;
  label: string;
  kind: ArenaAgentDeviceKind;
  public_key_hash: string;
  status: "active" | "revoked";
  registered_at: number;
  revoked_at: number | null;
  binding: "encrypted_delivery_only_not_hardware_attestation";
  public_key_returned: false;
}

export interface ArenaAgentCredential {
  credential_id: string;
  device_id: string;
  challenge_id: string;
  challenge_version: string;
  name: string;
  prefix: string;
  scopes: ArenaAgentScope[];
  daily_submission_cap: number;
  submission_attempts_used_today: number;
  generation: number;
  status: "active" | "expired" | "revoked";
  issued_at: number;
  expires_at: number;
  last_used_at: number | null;
  rotated_at: number | null;
  revoked_at: number | null;
  plaintext_token_stored: false;
  cross_domain_authority: false;
  product_status: "modeled";
  execution_authority: false;
  tdx_attestation: false;
}

interface ArenaAgentCredentialCapsule {
  delivery: "x25519_aes_256_gcm_envelope";
  encrypted_token: {
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
  associated_data: string;
  associated_data_hash: string;
  recipient_public_key_hash: string;
  plaintext_token_returned: false;
}

export interface ArenaAgentCredentialDelivery {
  device?: ArenaAgentDevice;
  credential: ArenaAgentCredential;
  capsule: ArenaAgentCredentialCapsule;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactRecord(value: unknown, fields: readonly string[], label: string): Record<string, unknown> {
  const parsed = record(value, label);
  const actual = Object.keys(parsed).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} fields do not match the versioned protocol`);
  }
  return parsed;
}

function safeInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its supported bound`);
  }
  return value;
}

function boundedText(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || encoder.encode(value).byteLength > maximum || /[^\x20-\x7e]/.test(value)) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

function nullableTimestamp(value: unknown, label: string): number | null {
  return value === null ? null : safeInteger(value, label, 0, 4_102_444_800);
}

function assertChallenge(challengeId: string, challengeVersion: string): void {
  if (!CHALLENGE_ID.test(challengeId) || !CHALLENGE_VERSION.test(challengeVersion)) {
    throw new Error("Arena agent challenge version is malformed");
  }
}

function assertDevice(value: unknown, challengeId: string, challengeVersion: string): asserts value is ArenaAgentDevice {
  const device = exactRecord(value, [
    "device_id", "challenge_id", "challenge_version", "label", "kind",
    "public_key_hash", "status", "registered_at", "revoked_at", "binding",
    "public_key_returned",
  ], "Arena agent device");
  if (
    typeof device.device_id !== "string"
    || !RESOURCE_ID.test(device.device_id)
    || device.challenge_id !== challengeId
    || device.challenge_version !== challengeVersion
    || !["developer_device", "ci_service", "autonomous_agent"].includes(String(device.kind))
    || !["active", "revoked"].includes(String(device.status))
    || typeof device.public_key_hash !== "string"
    || !HEX_64.test(device.public_key_hash)
    || device.binding !== "encrypted_delivery_only_not_hardware_attestation"
    || device.public_key_returned !== false
  ) throw new Error("Arena agent device failed its bounded schema checks");
  boundedText(device.label, "Arena agent device label", 64);
  const registeredAt = safeInteger(device.registered_at, "Arena agent registered_at", 0, 4_102_444_800);
  const revokedAt = nullableTimestamp(device.revoked_at, "Arena agent revoked_at");
  if (
    (device.status === "revoked") !== (revokedAt !== null)
    || (revokedAt !== null && revokedAt < registeredAt)
  ) throw new Error("Arena agent device temporal state is inconsistent");
}

export function assertArenaAgentCredential(
  value: unknown,
  challengeId: string,
  challengeVersion: string,
): asserts value is ArenaAgentCredential {
  const credential = exactRecord(value, [
    "credential_id", "device_id", "challenge_id", "challenge_version", "name",
    "prefix", "scopes", "daily_submission_cap", "submission_attempts_used_today",
    "generation", "status", "issued_at", "expires_at", "last_used_at", "rotated_at",
    "revoked_at", "plaintext_token_stored", "cross_domain_authority", "product_status",
    "execution_authority", "tdx_attestation",
  ], "Arena agent credential");
  if (
    typeof credential.credential_id !== "string"
    || !RESOURCE_ID.test(credential.credential_id)
    || typeof credential.device_id !== "string"
    || !RESOURCE_ID.test(credential.device_id)
    || credential.challenge_id !== challengeId
    || credential.challenge_version !== challengeVersion
    || typeof credential.prefix !== "string"
    || !/^wka_[0-9a-f]{6}$/.test(credential.prefix)
    || credential.prefix !== `wka_${credential.credential_id.slice(-6)}`
    || !Array.isArray(credential.scopes)
    || credential.scopes.length !== ARENA_AGENT_SCOPES.length
    || credential.scopes.some((scope, index) => scope !== ARENA_AGENT_SCOPES[index])
    || !["active", "expired", "revoked"].includes(String(credential.status))
    || credential.plaintext_token_stored !== false
    || credential.cross_domain_authority !== false
    || credential.product_status !== "modeled"
    || credential.execution_authority !== false
    || credential.tdx_attestation !== false
  ) throw new Error("Arena agent credential failed its bounded schema checks");
  boundedText(credential.name, "Arena agent credential name", 64);
  const cap = safeInteger(credential.daily_submission_cap, "Arena agent daily cap", 1, 32);
  safeInteger(credential.submission_attempts_used_today, "Arena agent attempts used", 0, cap);
  safeInteger(credential.generation, "Arena agent generation", 1, 1_000_000);
  const issuedAt = safeInteger(credential.issued_at, "Arena agent issued_at", 0, 4_102_444_800);
  const expiresAt = safeInteger(credential.expires_at, "Arena agent expires_at", 1, 4_102_444_800);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 86_400) {
    throw new Error("Arena agent credential lifetime is invalid");
  }
  const lastUsedAt = nullableTimestamp(credential.last_used_at, "Arena agent last_used_at");
  const rotatedAt = nullableTimestamp(credential.rotated_at, "Arena agent rotated_at");
  const revokedAt = nullableTimestamp(credential.revoked_at, "Arena agent revoked_at");
  const now = Math.floor(Date.now() / 1_000);
  if (
    (lastUsedAt !== null && (lastUsedAt < issuedAt || lastUsedAt >= expiresAt))
    || ((credential.generation === 1) !== (rotatedAt === null))
    || (rotatedAt !== null && rotatedAt !== issuedAt)
    || ((credential.status === "revoked") !== (revokedAt !== null))
    || (revokedAt !== null && revokedAt < Math.max(issuedAt, lastUsedAt ?? 0, rotatedAt ?? 0))
    || (credential.status === "expired" && expiresAt > now + 30)
  ) throw new Error("Arena agent credential temporal state is inconsistent");
}

async function request(path: string, options: {
  method?: "GET" | "POST";
  token: string;
  body?: Record<string, unknown>;
  signal?: AbortSignal;
}): Promise<unknown> {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  if (typeof options.token !== "string" || options.token.length < 80 || options.token.length > 4_096 || !JWT.test(options.token)) {
    throw new Error("Arena wallet session is malformed");
  }
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${options.token}`,
  };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(`${deployment.delegateUrl.replace(/\/$/, "")}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: options.signal
      ? AbortSignal.any([options.signal, AbortSignal.timeout(10_000)])
      : AbortSignal.timeout(10_000),
    cache: "no-store",
  });
  const text = await readBoundedArenaResponseText(response, 256 * 1024);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Arena agent service returned malformed JSON");
  }
  if (!response.ok) {
    const fallback = `Arena agent request failed with status ${response.status}`;
    const detail = parsed && typeof parsed === "object" && "detail" in parsed
      ? (parsed as { detail: unknown }).detail
      : fallback;
    throw new ArenaAgentRequestError(publicErrorText(detail, fallback), response.status);
  }
  return parsed;
}

const CREDENTIAL_FIELDS = [
  "credential_id", "device_id", "challenge_id", "challenge_version", "name",
  "prefix", "scopes", "daily_submission_cap", "submission_attempts_used_today",
  "generation", "status", "issued_at", "expires_at", "last_used_at", "rotated_at",
  "revoked_at", "plaintext_token_stored", "cross_domain_authority", "product_status",
  "execution_authority", "tdx_attestation",
] as const;

function parseDelivery(
  value: unknown,
  expectedSurface: "arena_agent_credential_issuance" | "arena_agent_credential_rotation",
  challengeId: string,
  challengeVersion: string,
): ArenaAgentCredentialDelivery {
  const outerFields = expectedSurface === "arena_agent_credential_issuance"
    ? ["surface", "schema_version", "device", "credential", "capsule", "plaintext_token_returned", "cross_domain_authority", "product_status", "execution_authority", "tdx_attestation"]
    : ["surface", "schema_version", "credential", "capsule", "prior_generation_revoked", "plaintext_token_returned", "cross_domain_authority", "product_status", "execution_authority", "tdx_attestation"];
  const result = exactRecord(value, outerFields, "Arena agent credential delivery");
  if (
    result.surface !== expectedSurface
    || result.schema_version !== 1
    || result.plaintext_token_returned !== false
    || result.cross_domain_authority !== false
    || result.product_status !== "modeled"
    || result.execution_authority !== false
    || result.tdx_attestation !== false
    || (expectedSurface === "arena_agent_credential_rotation" && result.prior_generation_revoked !== true)
  ) throw new Error("Arena agent credential delivery made an unsupported authority claim");
  assertArenaAgentCredential(result.credential, challengeId, challengeVersion);
  if (expectedSurface === "arena_agent_credential_issuance") {
    assertDevice(result.device, challengeId, challengeVersion);
    if ((result.device as ArenaAgentDevice).device_id !== (result.credential as ArenaAgentCredential).device_id) {
      throw new Error("Arena agent device does not match its credential");
    }
  }
  const capsule = exactRecord(result.capsule, [
    "delivery", "encrypted_token", "associated_data", "associated_data_hash",
    "recipient_public_key_hash", "plaintext_token_returned",
  ], "Arena agent credential capsule");
  const encrypted = exactRecord(capsule.encrypted_token, [
    "ephemeral_public_key", "nonce", "ciphertext",
  ], "Arena agent encrypted token");
  if (
    capsule.delivery !== "x25519_aes_256_gcm_envelope"
    || capsule.plaintext_token_returned !== false
    || typeof encrypted.ephemeral_public_key !== "string"
    || !HEX_64.test(encrypted.ephemeral_public_key)
    || typeof encrypted.nonce !== "string"
    || !/^[0-9a-f]{24}$/.test(encrypted.nonce)
    || typeof encrypted.ciphertext !== "string"
    || !/^[0-9a-f]{32,16384}$/.test(encrypted.ciphertext)
    || typeof capsule.associated_data !== "string"
    || !/^[0-9a-f]{2,8192}$/.test(capsule.associated_data)
    || typeof capsule.associated_data_hash !== "string"
    || !HEX_64.test(capsule.associated_data_hash)
    || typeof capsule.recipient_public_key_hash !== "string"
    || !HEX_64.test(capsule.recipient_public_key_hash)
  ) throw new Error("Arena agent credential capsule failed its bounded schema checks");
  return {
    device: expectedSurface === "arena_agent_credential_issuance" ? result.device as ArenaAgentDevice : undefined,
    credential: result.credential as ArenaAgentCredential,
    capsule: capsule as unknown as ArenaAgentCredentialCapsule,
  };
}

export async function listArenaAgentCredentials(
  walletSessionToken: string,
  challengeId: string,
  challengeVersion: string,
): Promise<ArenaAgentCredential[]> {
  assertChallenge(challengeId, challengeVersion);
  const result = exactRecord(await request(
    `/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(challengeVersion)}/agent-credentials`,
    { token: walletSessionToken },
  ), [
    "surface", "schema_version", "challenge_id", "challenge_version", "credentials",
    "product_status", "execution_authority", "tdx_attestation", "plaintext_token_egress",
    "cross_domain_authority",
  ], "Arena agent credential list");
  if (
    result.surface !== "arena_agent_credentials"
    || result.schema_version !== 1
    || result.challenge_id !== challengeId
    || result.challenge_version !== challengeVersion
    || !Array.isArray(result.credentials)
    || result.credentials.length > 128
    || result.product_status !== "modeled"
    || result.execution_authority !== false
    || result.tdx_attestation !== false
    || result.plaintext_token_egress !== false
    || result.cross_domain_authority !== false
  ) throw new Error("Arena agent credential list failed its bounded schema checks");
  result.credentials.forEach((credential) => assertArenaAgentCredential(credential, challengeId, challengeVersion));
  return result.credentials as ArenaAgentCredential[];
}

export async function issueArenaAgentCredential(
  walletSessionToken: string,
  challengeId: string,
  challengeVersion: string,
  input: {
    deviceLabel: string;
    deviceKind: ArenaAgentDeviceKind;
    publicKey: string;
    name: string;
    expiresInSeconds: number;
    dailySubmissionCap: number;
  },
  signal?: AbortSignal,
): Promise<ArenaAgentCredentialDelivery> {
  assertChallenge(challengeId, challengeVersion);
  if (!HEX_64.test(input.publicKey)) throw new Error("Arena agent device public key is malformed");
  const delivery = parseDelivery(await request(
    `/arena/challenges/${encodeURIComponent(challengeId)}/versions/${encodeURIComponent(challengeVersion)}/agent-credentials`,
    {
      method: "POST",
      token: walletSessionToken,
      body: {
        device_label: input.deviceLabel,
        device_kind: input.deviceKind,
        public_key: input.publicKey,
        name: input.name,
        scopes: [...ARENA_AGENT_SCOPES],
        expires_in_seconds: input.expiresInSeconds,
        daily_submission_cap: input.dailySubmissionCap,
      },
      signal,
    },
  ), "arena_agent_credential_issuance", challengeId, challengeVersion);
  const expectedRecipientHash = await sha256Text(`arena_agent_device_key:${input.publicKey}`);
  if (
    !delivery.device
    || delivery.device.public_key_hash !== expectedRecipientHash
    || delivery.capsule.recipient_public_key_hash !== expectedRecipientHash
    || delivery.device.label !== input.deviceLabel
    || delivery.device.kind !== input.deviceKind
    || delivery.device.registered_at !== delivery.credential.issued_at
    || delivery.credential.name !== input.name
    || delivery.credential.daily_submission_cap !== input.dailySubmissionCap
    || delivery.credential.generation !== 1
    || delivery.credential.status !== "active"
    || delivery.credential.submission_attempts_used_today !== 0
    || delivery.credential.last_used_at !== null
    || delivery.credential.rotated_at !== null
    || delivery.credential.revoked_at !== null
    || delivery.credential.expires_at - delivery.credential.issued_at !== input.expiresInSeconds
  ) throw new Error("Arena agent issuance receipt does not match the generated device key");
  return delivery;
}

export async function rotateArenaAgentCredential(
  walletSessionToken: string,
  credential: ArenaAgentCredential,
  expiresInSeconds: number,
  signal?: AbortSignal,
): Promise<ArenaAgentCredentialDelivery> {
  assertArenaAgentCredential(credential, credential.challenge_id, credential.challenge_version);
  const delivery = parseDelivery(await request(
    `/arena/challenges/${encodeURIComponent(credential.challenge_id)}/versions/${encodeURIComponent(credential.challenge_version)}/agent-credentials/${encodeURIComponent(credential.credential_id)}/rotate`,
    {
      method: "POST",
      token: walletSessionToken,
      body: {
        expires_in_seconds: expiresInSeconds,
        expected_generation: credential.generation,
      },
      signal,
    },
  ), "arena_agent_credential_rotation", credential.challenge_id, credential.challenge_version);
  if (
    delivery.credential.credential_id !== credential.credential_id
    || delivery.credential.device_id !== credential.device_id
    || delivery.credential.name !== credential.name
    || delivery.credential.generation !== credential.generation + 1
    || delivery.credential.daily_submission_cap !== credential.daily_submission_cap
    || delivery.credential.scopes.some((scope, index) => scope !== credential.scopes[index])
    || delivery.credential.status !== "active"
    || delivery.credential.expires_at - delivery.credential.issued_at !== expiresInSeconds
  ) throw new Error("Arena agent rotation receipt does not match the requested credential");
  return delivery;
}

export async function revokeArenaAgentCredential(
  walletSessionToken: string,
  credential: ArenaAgentCredential,
  signal?: AbortSignal,
): Promise<ArenaAgentCredential> {
  assertArenaAgentCredential(credential, credential.challenge_id, credential.challenge_version);
  const result = exactRecord(await request(
    `/arena/challenges/${encodeURIComponent(credential.challenge_id)}/versions/${encodeURIComponent(credential.challenge_version)}/agent-credentials/${encodeURIComponent(credential.credential_id)}/revoke`,
    { method: "POST", token: walletSessionToken, signal },
  ), [
    "surface", "schema_version", "credential", "product_status", "execution_authority",
    "tdx_attestation", "plaintext_token_returned", "cross_domain_authority",
  ], "Arena agent credential revocation");
  if (
    result.surface !== "arena_agent_credential"
    || result.schema_version !== 1
    || result.product_status !== "modeled"
    || result.execution_authority !== false
    || result.tdx_attestation !== false
    || result.plaintext_token_returned !== false
    || result.cross_domain_authority !== false
  ) throw new Error("Arena agent credential revocation made an unsupported authority claim");
  assertArenaAgentCredential(result.credential, credential.challenge_id, credential.challenge_version);
  const revoked = result.credential as ArenaAgentCredential;
  if (
    revoked.credential_id !== credential.credential_id
    || revoked.device_id !== credential.device_id
    || revoked.name !== credential.name
    || revoked.generation !== credential.generation
    || revoked.daily_submission_cap !== credential.daily_submission_cap
    || revoked.scopes.some((scope, index) => scope !== credential.scopes[index])
    || revoked.status !== "revoked"
    || revoked.revoked_at === null
  ) throw new Error("Arena agent revocation receipt does not match the requested credential");
  return revoked;
}

function bytesFromHex(value: string, exactBytes?: number): Uint8Array {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error("Arena agent credential capsule contains invalid hex");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  if (exactBytes !== undefined && bytes.length !== exactBytes) {
    throw new Error("Arena agent credential capsule field has an invalid length");
  }
  return bytes;
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

async function sha256Text(value: string): Promise<string> {
  return hexFromBytes(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function generateArenaAgentDeviceKey(): Promise<ArenaAgentDeviceKey> {
  if (!crypto?.subtle) throw new Error("This browser cannot create an Arena agent device key");
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { publicKeyHex: hexFromBytes(publicKey), privateKey: pair.privateKey };
}

function decodeBase64UrlBytes(value: string, label: string, maximum: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Arena agent token encoding is invalid");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (bytes.length > maximum) throw new Error(`${label} exceeds its bound`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const canonical = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  if (canonical !== value) throw new Error(`${label} is not canonical base64url`);
  return bytes;
}

function decodeBase64UrlJson(value: string): Record<string, unknown> {
  const bytes = decodeBase64UrlBytes(value, "Arena agent token segment", 8_192);
  return record(JSON.parse(decoder.decode(bytes)), "Arena agent token segment");
}

export async function assertArenaAgentCredentialTokenReceipt(
  token: string,
  credential: ArenaAgentCredential,
  expectedOwnerAddress: string,
  expectedJwtIdHash: string,
): Promise<void> {
  if (token.length < 80 || token.length > 4_096 || !JWT.test(token)) {
    throw new Error("Arena agent token format is invalid");
  }
  const parts = token.split(".");
  if (decodeBase64UrlBytes(parts[2], "Arena agent token signature", 32).length !== 32) {
    throw new Error("Arena agent token signature must be canonical 32-byte HS256 output");
  }
  const header = exactRecord(
    decodeBase64UrlJson(parts[0]),
    ["alg", "kid", "typ"],
    "Arena agent token header",
  );
  const payload = exactRecord(
    decodeBase64UrlJson(parts[1]),
    ARENA_AGENT_TOKEN_FIELDS,
    "Arena agent token payload",
  );
  const now = Math.floor(Date.now() / 1_000);
  const issuedAt = safeInteger(payload.iat, "Arena agent token iat", 0, 4_102_444_800);
  const notBefore = safeInteger(payload.nbf, "Arena agent token nbf", 0, 4_102_444_800);
  const expiresAt = safeInteger(payload.exp, "Arena agent token exp", 1, 4_102_444_800);
  const generation = safeInteger(payload.generation, "Arena agent token generation", 1, 1_000_000);
  const dailyCap = safeInteger(payload.daily_submission_cap, "Arena agent token daily cap", 1, 32);
  const jwtId = payload.jti;
  if (
    header.alg !== "HS256"
    || header.kid !== "dstack-arena-agent-v1"
    || header.typ !== "JWT"
    || payload.iss !== ARENA_AGENT_ISSUER
    || payload.aud !== ARENA_AGENT_AUDIENCE
    || payload.sub !== credential.credential_id
    || payload.device_id !== credential.device_id
    || typeof payload.owner_address !== "string"
    || !/^0x[0-9a-f]{40}$/.test(payload.owner_address)
    || payload.owner_address !== expectedOwnerAddress.toLowerCase()
    || payload.challenge_id !== credential.challenge_id
    || payload.challenge_version !== credential.challenge_version
    || generation !== credential.generation
    || dailyCap !== credential.daily_submission_cap
    || issuedAt !== credential.issued_at
    || notBefore !== issuedAt
    || expiresAt !== credential.expires_at
    || issuedAt > now + 30
    || expiresAt <= now
    || expiresAt <= issuedAt
    || expiresAt - issuedAt > 86_400
    || typeof jwtId !== "string"
    || !/^[0-9a-f]{32}$/.test(jwtId)
    || typeof payload.scope !== "string"
    || payload.scope !== credential.scopes.join(" ")
  ) throw new Error("Arena agent token claims do not match the issuance receipt");
  if (await sha256Text(`arena_agent_credential_jti:${jwtId}`) !== expectedJwtIdHash) {
    throw new Error("Arena agent token id does not match its encrypted binding");
  }
}

export async function decryptArenaAgentCredentialCapsule(
  delivery: ArenaAgentCredentialDelivery,
  deviceKey: ArenaAgentDeviceKey,
  expectedOwnerAddress: string,
): Promise<string> {
  const { capsule, credential } = delivery;
  const ephemeralBytes = bytesFromHex(capsule.encrypted_token.ephemeral_public_key, 32);
  const nonce = bytesFromHex(capsule.encrypted_token.nonce, 12);
  const ciphertext = bytesFromHex(capsule.encrypted_token.ciphertext);
  const associatedData = bytesFromHex(capsule.associated_data);
  let shared = new Uint8Array();
  let plaintext = new Uint8Array();
  try {
    if (await sha256Text(`arena_agent_credential_aad:${capsule.associated_data}`) !== capsule.associated_data_hash) {
      throw new Error("Arena agent token associated-data commitment is invalid");
    }
    if (await sha256Text(`arena_agent_device_key:${deviceKey.publicKeyHex}`) !== capsule.recipient_public_key_hash) {
      throw new Error("Arena agent token recipient commitment is invalid");
    }
    const binding = exactRecord(JSON.parse(decoder.decode(associatedData)), [
      "surface", "credential_id", "device_id", "owner_address_hash", "challenge_id",
      "challenge_version", "generation", "jwt_id_hash", "expires_at",
    ], "Arena agent token binding");
    if (
      binding.surface !== "arena_agent_credential"
      || binding.credential_id !== credential.credential_id
      || binding.device_id !== credential.device_id
      || binding.challenge_id !== credential.challenge_id
      || binding.challenge_version !== credential.challenge_version
      || binding.generation !== credential.generation
      || binding.expires_at !== credential.expires_at
      || typeof binding.jwt_id_hash !== "string"
      || !HEX_64.test(binding.jwt_id_hash)
      || binding.owner_address_hash !== await sha256Text(`arena_agent_owner:${expectedOwnerAddress.toLowerCase()}`)
    ) throw new Error("Arena agent token binding does not match the issuance receipt");
    const ephemeral = await crypto.subtle.importKey("raw", buffer(ephemeralBytes), { name: "X25519" }, false, []);
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, deviceKey.privateKey, 256));
    const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode(ARENA_AGENT_HKDF_INFO) },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(associatedData), tagLength: 128 },
      key,
      buffer(ciphertext),
    ));
    const token = decoder.decode(plaintext);
    await assertArenaAgentCredentialTokenReceipt(token, credential, expectedOwnerAddress, String(binding.jwt_id_hash));
    return token;
  } catch (cause) {
    if (cause instanceof Error && cause.message.startsWith("Arena agent")) throw cause;
    throw new Error("Arena agent credential capsule could not be authenticated for this device");
  } finally {
    ephemeralBytes.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    associatedData.fill(0);
    shared.fill(0);
    plaintext.fill(0);
  }
}

function quickstartBaseUrl(baseUrl?: string): string {
  const configured = (baseUrl ?? deployment.delegateUrl).replace(/\/$/, "");
  return configured || "https://YOUR_DELEGATE";
}

export function arenaAgentCurlQuickstart(
  challengeId: string,
  challengeVersion: string,
  baseUrl?: string,
): string {
  assertChallenge(challengeId, challengeVersion);
  const root = quickstartBaseUrl(baseUrl);
  return [
    `# Set WIKIGEN_ARENA_TOKEN in your shell; never commit it.`,
    `curl --fail-with-body ${"\\"}`,
    `  -H "Authorization: Bearer \${WIKIGEN_ARENA_TOKEN}" ${"\\"}`,
    `  "${root}/arena/challenges/${challengeId}/versions/${challengeVersion}/submissions/mine?limit=25"`,
    "",
    `# encrypted-submission.json must contain the exact ciphertext-only v1 schema.`,
    `curl --fail-with-body -X POST ${"\\"}`,
    `  -H "Authorization: Bearer \${WIKIGEN_ARENA_TOKEN}" ${"\\"}`,
    `  -H "Idempotency-Key: agent-run-$(uuidgen)" ${"\\"}`,
    `  -H "Content-Type: application/json" ${"\\"}`,
    `  --data-binary @encrypted-submission.json ${"\\"}`,
    `  "${root}/arena/challenges/${challengeId}/versions/${challengeVersion}/submissions"`,
  ].join("\n");
}

export function arenaAgentPythonQuickstart(
  challengeId: string,
  challengeVersion: string,
  baseUrl?: string,
): string {
  assertChallenge(challengeId, challengeVersion);
  const root = quickstartBaseUrl(baseUrl);
  return `import os\nimport httpx\n\ntoken = os.environ["WIKIGEN_ARENA_TOKEN"]\nurl = "${root}/arena/challenges/${challengeId}/versions/${challengeVersion}/submissions/mine"\nresponse = httpx.get(url, params={"limit": 25}, headers={"Authorization": f"Bearer {token}"}, timeout=10.0)\nresponse.raise_for_status()\nprint(response.json())`;
}

// This constant is exported only for protocol-field tests. It prevents a
// future API response parser from silently widening the persisted secret set.
export const ARENA_AGENT_CREDENTIAL_PUBLIC_FIELDS = CREDENTIAL_FIELDS;
