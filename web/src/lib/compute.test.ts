import { afterEach, describe, expect, it, vi } from "vitest";
import { deployment } from "../config";
import {
  cancelComputeJob,
  canCancelComputeJob,
  canCreateComputeDispatchIntent,
  computeDispatchIntentCommitment,
  computeExecutionPolicyContextHash,
  createComputeDispatchIntent,
  decryptCredentialCapsule,
  fetchComputeExecutionPolicyTarget,
  fetchComputeDispatchIntent,
  generateDeviceKey,
  parseComputeDispatchIntent,
  parseComputeFundingCapabilities,
  parseDispatchUint256,
  parseComputeJobCancellation,
  UnresolvedIdempotencyAttempt,
  type ComputeDispatchCapability,
  type ComputeDispatchIntentStatus,
  type ComputeCredential,
  type ComputeCredentialDelivery,
  type ComputeJob,
  type ComputeJobCancellationReceipt,
  type ComputeProject,
  type DeviceKeyMaterial,
} from "./compute";
import { computeVaultJobId, computeVaultProjectId } from "./computeVault";
import contextVectors from "./computeExecutionPolicyContextVectors.json";

const encoder = new TextEncoder();

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function hex(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function b64url(value: string): string {
  const bytes = encoder.encode(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function digest(value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

describe("Compute project idempotency attempts", () => {
  it("reuses one key only while the same create request is unresolved", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const first = attempt.keyFor("project", "0xowner:atlas-research");

    expect(attempt.keyFor("project", "0xowner:atlas-research")).toBe(first);
    expect(attempt.keyFor("project", "0xowner:another-project")).not.toBe(first);
  });

  it("clears on authoritative create success before a downstream refresh failure", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const committed = attempt.keyFor("project", "0xowner:atlas-research");
    attempt.resolve(committed);

    expect(() => {
      throw new Error("project list refresh failed");
    }).toThrow("project list refresh failed");
    expect(attempt.keyFor("project", "0xowner:atlas-research")).not.toBe(committed);
  });

  it("does not let a stale completion clear the current unresolved request", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const stale = attempt.keyFor("project", "0xowner:first-project");
    const current = attempt.keyFor("project", "0xowner:second-project");

    attempt.resolve(stale);
    expect(attempt.keyFor("project", "0xowner:second-project")).toBe(current);
  });
});

const issuedAt = Math.floor(Date.now() / 1000) - 5;

const credential: ComputeCredential = {
  credential_id: "cred_0123456789abcdef01234567",
  project_id: "proj_0123456789abcdef01234567",
  device_id: "dev_0123456789abcdef01234567",
  name: "test-device",
  prefix: "wk_dev_234567",
  scopes: ["jobs:create", "jobs:read"],
  daily_credit_cap: 500,
  generation: 1,
  status: "active",
  issued_at: issuedAt,
  expires_at: issuedAt + 3_600,
  last_used_at: null,
  rotated_at: null,
  revoked_at: null,
  plaintext_token_stored: false,
  upstream_tinker_key_exposed: false,
};

const queuedJob: ComputeJob = {
  job_id: "job_0123456789abcdef01234567",
  project_id: credential.project_id,
  name: "bounded-sample",
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  max_credits: 125,
  actual_credits: null,
  released_credits: null,
  result_policy: "bounded_summary_receipt",
  environment_version: "env_v1",
  status: "queued",
  dispatch_status: "not_dispatched",
  backend_capability: "future_inference_proxy",
  credential_id: null,
  created_at: issuedAt,
  updated_at: issuedAt,
  started_at: null,
  completed_at: null,
  metering_source: null,
  usage_receipt_hash: null,
  settlement_authority: null,
  provider_authoritative_settlement: false,
  raw_input_persisted: false,
  raw_output_persisted: false,
};

const dispatchProject: ComputeProject = {
  project_id: "prj_0123456789abcdef01234567",
  name: "exact-asset-lab",
  role: "owner",
  policy: {
    per_job_max_credits: 500,
    daily_project_max_credits: 2_500,
    credential_max_ttl_seconds: 604_800,
    allowed_operations: ["inference", "training"],
  },
  members: [{ address: `0x${"1".repeat(40)}`, role: "owner" }],
  created_at: issuedAt,
  updated_at: issuedAt,
  credit_instrument: "closed_loop_nontransferable_service_credit",
  provider_dispatch_enabled: false,
};

function dispatchCapability(overrides: Partial<ComputeDispatchCapability> = {}): ComputeDispatchCapability {
  return {
    metadata_intent_creation: false,
    provider_dispatch: false,
    independent_metering: false,
    settlement: false,
    exact_asset_only: true,
    mutation_route: null,
    status_route_template: "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
    reason: "idempotent_tinker_provider_adapter_unavailable",
    ...overrides,
  } as ComputeDispatchCapability;
}

function fundingCapabilities(dispatch = dispatchCapability()): Record<string, unknown> {
  return {
    surface: "compute_funding_capabilities",
    schema_version: 1,
    card: {
      enabled: false,
      mutation_route: null,
      reason: "signed_webhook_and_hosted_checkout_not_configured",
      card_data_accepted: false,
      distinct_from_exact_asset_capacity: true,
    },
    usdc: {
      enabled: false,
      mutation_route: null,
      reason: "release_generated_base_sepolia_vault_evidence_required",
      capacity_model: "same_asset_nontransferable_vault_claim",
    },
    eth: {
      enabled: false,
      mutation_route: null,
      reason: "release_generated_base_sepolia_vault_evidence_required",
      capacity_model: "same_asset_nontransferable_vault_claim",
    },
    exact_asset_vault: {
      contract: "ComputeCreditVault",
      release_bound: true,
      review_status: "reviewed_and_extensively_tested_not_formally_audited",
      provider_dispatch_authoritative: false,
    },
    dispatch_intents: dispatch,
    operator_testnet_grants: {
      enabled: true,
      auth: "configured_runtime_bearer",
      cash_value: false,
    },
    credits: {
      kind: "closed_loop_service_credit",
      transferable: false,
      redeemable: false,
      onchain_token: false,
      nominal_usd_cents_per_credit: 1,
      legacy_modeled_ledger: true,
      distinct_from_exact_asset_vault: true,
    },
  };
}

function dispatchStatus(updates: Partial<ComputeDispatchIntentStatus> = {}): Record<string, unknown> {
  const projectReference = dispatchProject.project_id;
  const jobReference = "wallet-job-0001";
  const record: Record<string, unknown> = {
    surface: "compute_dispatch_intent",
    schema_version: 2,
    project_reference: projectReference,
    job_reference: jobReference,
    project_id: computeVaultProjectId(projectReference),
    job_id: computeVaultJobId(jobReference),
    user: `0x${"1".repeat(40)}`,
    asset: `0x${"0".repeat(40)}`,
    authorization_nonce: "9007199254740993",
    max_asset_debit: "1000000000000000000",
    authorization_expiry: Math.floor(Date.now() / 1_000) + 600,
    rate_policy_commitment: `0x${"3".repeat(64)}`,
    compose_hash: `0x${"4".repeat(64)}`,
    operation: "inference",
    model: "qwen3_8b",
    recipe: "qwen3_8b_bounded",
    result_policy: "bounded_summary_receipt",
    resource_limits: {
      max_prefill_tokens: 1_000,
      max_sample_tokens: 100,
      max_train_tokens: 0,
    },
    workload_id: `wrk_${"ab".repeat(16)}`,
    workload_schema: "dnai.compute.workload.inference.v1",
    manifest_commitment: `0x${"91".repeat(32)}`,
    workload_commitment: `0x${"92".repeat(32)}`,
    intent_commitment: `0x${"5".repeat(64)}`,
    execution_policy_context_hash: "5".repeat(64),
    stage: "intent_created",
    provider_authoritative: false,
    legacy_credit_ledger_mutated: false,
    provider_dispatch_status: "not_started",
    provider_dispatch_may_have_occurred: false,
    provider_usage_finalized: false,
    raw_prompt_accepted: false,
    raw_examples_accepted: false,
    arbitrary_program_accepted: false,
    exact_timing_egress: false,
    ...updates,
  };
  if (!Object.prototype.hasOwnProperty.call(updates, "intent_commitment")) {
    const limits = record.resource_limits as ComputeDispatchIntentStatus["resource_limits"];
    record.intent_commitment = computeDispatchIntentCommitment({
      projectReference: String(record.project_reference),
      jobReference: String(record.job_reference),
      projectId: record.project_id as `0x${string}`,
      jobId: record.job_id as `0x${string}`,
      user: record.user as `0x${string}`,
      asset: record.asset as `0x${string}`,
      authorizationNonce: BigInt(record.authorization_nonce as string | number | bigint),
      maxAssetDebit: BigInt(record.max_asset_debit as string | number | bigint),
      authorizationExpiry: Number(record.authorization_expiry),
      ratePolicyCommitment: record.rate_policy_commitment as `0x${string}`,
      composeHash: record.compose_hash as `0x${string}`,
      operation: String(record.operation),
      model: String(record.model),
      recipe: String(record.recipe),
      resultPolicy: String(record.result_policy),
      maxPrefillTokens: Number(limits.max_prefill_tokens),
      maxSampleTokens: Number(limits.max_sample_tokens),
      maxTrainTokens: Number(limits.max_train_tokens),
      workloadId: String(record.workload_id),
      workloadSchema: String(record.workload_schema),
      manifestCommitment: record.manifest_commitment as `0x${string}`,
      workloadCommitment: record.workload_commitment as `0x${string}`,
    });
  }
  if (!Object.prototype.hasOwnProperty.call(updates, "execution_policy_context_hash")) {
    record.execution_policy_context_hash = computeExecutionPolicyContextHash({
      jobId: record.job_id as `0x${string}`,
      intentCommitment: record.intent_commitment as `0x${string}`,
      operation: String(record.operation),
      model: String(record.model),
      recipe: String(record.recipe),
    });
  }
  return record;
}

function cancellationReceipt(): ComputeJobCancellationReceipt {
  return {
    surface: "compute_job_cancellation",
    schema_version: 1,
    project_id: queuedJob.project_id,
    job_id: queuedJob.job_id,
    status: "canceled",
    changed: true,
    idempotent_replay: false,
    released_credits: queuedJob.max_credits,
    credit_reversal: "reserved_to_available",
    ledger: {
      transaction_id: "txn_0123456789abcdef01234567",
      sequence: 3,
      kind: "job_cancel",
      transaction_hash: "1".repeat(64),
      previous_hash: "2".repeat(64),
      settlement_status: "user_canceled_before_dispatch",
    },
    provider_dispatch_performed: false,
    service_settlement_performed: false,
  };
}

async function deliveryFor(
  device: DeviceKeyMaterial,
  tokenJti = "0123456789abcdef0123456789abcdef",
  bindingJti = tokenJti,
): Promise<{ delivery: ComputeCredentialDelivery; token: string }> {
  const jwtIdHash = await digest(`compute_credential_jti:${bindingJti}`);
  const associatedObject = {
    credential_id: credential.credential_id,
    device_id: credential.device_id,
    expires_at: credential.expires_at,
    generation: credential.generation,
    jwt_id_hash: jwtIdHash,
    project_id: credential.project_id,
    surface: "compute_credential",
  };
  const associatedBytes = encoder.encode(JSON.stringify(associatedObject));
  const associatedHex = hex(associatedBytes);
  const header = { alg: "HS256", kid: "dstack-compute-credential-v1", typ: "JWT" };
  const payload = {
    sub: credential.credential_id,
    project_id: credential.project_id,
    device_id: credential.device_id,
    generation: credential.generation,
    scope: credential.scopes.join(" "),
    daily_credit_cap: credential.daily_credit_cap,
    iat: credential.issued_at,
    nbf: credential.issued_at,
    exp: credential.expires_at,
    jti: tokenJti,
  };
  const token = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${b64url("test-signature")}`;
  const recipient = await crypto.subtle.importKey("raw", buffer(Uint8Array.from(device.publicKeyHex.match(/../g)!.map((byte) => Number.parseInt(byte, 16)))), { name: "X25519" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, ephemeral.privateKey, 256));
  const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode("dnai-wikigen-compute-credential-v1") },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = new Uint8Array(12).fill(7);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: associatedBytes, tagLength: 128 }, key, encoder.encode(token));
  const ephemeralPublic = await crypto.subtle.exportKey("raw", ephemeral.publicKey);
  shared.fill(0);
  return {
    token,
    delivery: {
      credential,
      capsule: {
        delivery: "x25519_aes_256_gcm_envelope",
        encrypted_token: {
          ephemeral_public_key: hex(ephemeralPublic),
          nonce: hex(nonce),
          ciphertext: hex(ciphertext),
        },
        associated_data: associatedHex,
        associated_data_hash: await digest(`compute_credential_aad:${associatedHex}`),
        recipient_public_key_hash: await digest(`compute_device_key:${device.publicKeyHex}`),
        plaintext_token_returned: false,
      },
    },
  };
}

describe("Compute device credential delivery", () => {
  it("keeps the registered browser device private key non-exportable", async () => {
    const device = await generateDeviceKey();
    expect(device.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(device.privateKey.type).toBe("private");
    expect(device.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", device.privateKey)).rejects.toThrow();
  });

  it("decrypts a capsule only for its registered X25519 device and validates every binding", async () => {
    const device = await generateDeviceKey();
    const { delivery, token } = await deliveryFor(device);
    await expect(decryptCredentialCapsule(delivery, device)).resolves.toBe(token);

    const otherDevice = await generateDeviceKey();
    await expect(decryptCredentialCapsule(delivery, otherDevice)).rejects.toThrow(/recipient commitment/);
  });

  it("rejects a capsule whose associated-data commitment was altered", async () => {
    const device = await generateDeviceKey();
    const { delivery } = await deliveryFor(device);
    const tampered = structuredClone(delivery);
    tampered.capsule.associated_data_hash = "0".repeat(64);
    await expect(decryptCredentialCapsule(tampered, device)).rejects.toThrow(/associated-data commitment/);
  });

  it("rejects a decrypted JWT whose jti is not the capsule-bound credential generation", async () => {
    const device = await generateDeviceKey();
    const { delivery } = await deliveryFor(
      device,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    await expect(decryptCredentialCapsule(delivery, device)).rejects.toThrow(/token id does not match/);
  });
});

describe("Compute queued-job cancellation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("accepts only the exact bounded cancellation and immutable ledger receipt", () => {
    const value = cancellationReceipt();
    expect(
      parseComputeJobCancellation(value, queuedJob.project_id, queuedJob.job_id),
    ).toEqual(value);

    const replay = cancellationReceipt();
    replay.changed = false;
    replay.idempotent_replay = true;
    expect(
      parseComputeJobCancellation(replay, queuedJob.project_id, queuedJob.job_id),
    ).toEqual(replay);
  });

  it("rejects extra fields, identity drift, contradictory replay claims, and malformed ledger evidence", () => {
    const extra = { ...cancellationReceipt(), wallet_address: "0x" + "1".repeat(40) };
    expect(() => parseComputeJobCancellation(extra, queuedJob.project_id, queuedJob.job_id)).toThrow(/unsupported fields/);

    const nestedExtra = cancellationReceipt() as ComputeJobCancellationReceipt & { ledger: ComputeJobCancellationReceipt["ledger"] & { authority?: string } };
    nestedExtra.ledger.authority = "project_wallet_owner";
    expect(() => parseComputeJobCancellation(nestedExtra, queuedJob.project_id, queuedJob.job_id)).toThrow(/unsupported fields/);

    const contradictory = cancellationReceipt();
    contradictory.idempotent_replay = true;
    expect(() => parseComputeJobCancellation(contradictory, queuedJob.project_id, queuedJob.job_id)).toThrow(/bounded schema/);

    const malformedHash = cancellationReceipt();
    malformedHash.ledger.transaction_hash = "A".repeat(64);
    expect(() => parseComputeJobCancellation(malformedHash, queuedJob.project_id, queuedJob.job_id)).toThrow(/bounded schema/);

    const excessiveRelease = cancellationReceipt();
    excessiveRelease.released_credits = 501;
    expect(() => parseComputeJobCancellation(excessiveRelease, queuedJob.project_id, queuedJob.job_id)).toThrow(/released credits/);

    expect(() => parseComputeJobCancellation(
      cancellationReceipt(),
      "proj_ffffffffffffffffffffffff",
      queuedJob.job_id,
    )).toThrow(/bounded schema/);
  });

  it("permits only current mutating roles and pristine queued, never-dispatched records", () => {
    expect(canCancelComputeJob(queuedJob, "owner")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "admin")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "developer")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "viewer")).toBe(false);
    expect(canCancelComputeJob(queuedJob, undefined)).toBe(false);

    for (const mutation of [
      { status: "running" as const },
      { status: "succeeded" as const },
      { started_at: issuedAt },
      { completed_at: issuedAt },
      { actual_credits: 0 },
      { released_credits: 125 },
      { metering_source: "operator_bounded_receipt" },
      { usage_receipt_hash: `sha256:${"1".repeat(64)}` },
      { settlement_authority: "operator_runtime" },
    ]) {
      expect(canCancelComputeJob({ ...queuedJob, ...mutation }, "owner")).toBe(false);
    }
    const providerDispatched = {
      ...queuedJob,
      dispatch_status: "provider_dispatched",
    } as unknown as ComputeJob;
    expect(canCancelComputeJob(providerDispatched, "owner")).toBe(false);
  });

  it("posts the fixed cancellation intent with bearer and replay key, then parses the receipt", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(
      JSON.stringify(cancellationReceipt()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:12345678",
      )).resolves.toEqual(cancellationReceipt());
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${queuedJob.project_id}/jobs/${queuedJob.job_id}/cancel`);
      expect(options.method).toBe("POST");
      expect(options.credentials).toBe("omit");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "jobcancel:12345678",
      });
      expect(options.body).toBe(JSON.stringify({ reason: "user_requested_before_dispatch" }));

      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "short",
      )).rejects.toThrow(/idempotency key/);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("cancels an undeclared oversized response stream before JSON parsing", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    let canceled = false;
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(400 * 1024).fill(0x20));
        controller.enqueue(new Uint8Array(200 * 1024).fill(0x20));
      },
      cancel() {
        canceled = true;
      },
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(oversized, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:oversized-response",
      )).rejects.toThrow(/public size limit/);
      expect(canceled).toBe(true);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("rejects non-JSON Compute responses before parsing them", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    vi.stubGlobal("fetch", vi.fn(async () => new Response("not-json", {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    })));
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:wrong-content-type",
      )).rejects.toThrow(/application\/json/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });
});

describe("Compute exact-asset dispatch intents", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("parses the exact bounded journal schema and preserves uint256 precision", () => {
    const value = dispatchStatus();
    const parsed = parseComputeDispatchIntent(value, {
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-0001",
    });
    expect(parsed.authorization_nonce).toBe(9_007_199_254_740_993n);
    expect(parsed.max_asset_debit).toBe(1_000_000_000_000_000_000n);
    expect(parsed.project_id).toBe(computeVaultProjectId(dispatchProject.project_id));
    expect(parsed.job_id).toBe(computeVaultJobId("wallet-job-0001"));
    expect(() => parseComputeDispatchIntent(value, {
      projectReference: "prj_wrong",
      jobReference: "wallet-job-0001",
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(value, {
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-wrong",
    })).toThrow(/bounded schema/);
    expect(parseDispatchUint256((1n << 256n) - 1n)).toBe((1n << 256n) - 1n);
    expect(() => parseDispatchUint256(1n << 256n)).toThrow(/exceeds uint256/);
    expect(() => parseDispatchUint256("01")).toThrow(/canonical uint256/);
  });

  it("matches the Python runtime's canonical intent commitment vector", () => {
    expect(computeDispatchIntentCommitment({
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-0001",
      projectId: computeVaultProjectId(dispatchProject.project_id),
      jobId: computeVaultJobId("wallet-job-0001"),
      user: `0x${"1".repeat(40)}`,
      asset: `0x${"0".repeat(40)}`,
      authorizationNonce: 9_007_199_254_740_993n,
      maxAssetDebit: 1_000_000_000_000_000_000n,
      authorizationExpiry: 2_000_000_000,
      ratePolicyCommitment: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      operation: "inference",
      model: "qwen3_8b",
      recipe: "qwen3_8b_bounded",
      resultPolicy: "bounded_summary_receipt",
      maxPrefillTokens: 1_000,
      maxSampleTokens: 100,
      maxTrainTokens: 0,
      workloadId: `wrk_${"ab".repeat(16)}`,
      workloadSchema: "dnai.compute.workload.inference.v1",
      manifestCommitment: `0x${"91".repeat(32)}`,
      workloadCommitment: `0x${"92".repeat(32)}`,
    })).toBe("0x785edf5867fe64c8c566c010cfd5179a830e7c377e5ca86c46a0c43b2dd3a1ed");
  });

  it("matches Python's 0x-input to bare execution-context vector", () => {
    const vector = contextVectors.vectors[0];
    expect(vector.intent_commitment.startsWith("0x")).toBe(true);
    expect(vector.recipe_policy_commitment.startsWith("0x")).toBe(true);
    expect(vector.execution_context_hash.startsWith("0x")).toBe(false);
    expect(computeExecutionPolicyContextHash({
      jobId: vector.job_id as `0x${string}`,
      intentCommitment: vector.intent_commitment as `0x${string}`,
      operation: vector.intent.operation,
      model: vector.intent.model,
      recipe: vector.intent.recipe,
    })).toBe(vector.execution_context_hash);
  });

  it("derives the policy target only from wallet-authenticated exact-intent status", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const response = dispatchStatus();
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const target = await fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "wallet-job-0001",
        String(response.user),
      );
      expect(target).toEqual({
        resourceId: response.job_id,
        executionContextHash: response.execution_policy_context_hash,
        authorizedUser: response.user,
      });
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(
        `https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents/wallet-job-0001`,
      );
      expect(options.headers).toMatchObject({
        Authorization: "Bearer wallet-scoped-compute-token",
      });
      expect(options.credentials).toBe("omit");
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("rejects a Compute policy target owned by another wallet", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify(dispatchStatus()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));
    try {
      await expect(fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "wallet-job-0001",
        `0x${"2".repeat(40)}`,
      )).rejects.toThrow(/different wallet/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("keeps legacy service-credit job IDs outside the public policy target flow", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(
      JSON.stringify({ detail: "Exact-asset dispatch intent not found" }),
      { status: 404, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "job_legacy_service_credit",
        `0x${"1".repeat(40)}`,
      )).rejects.toThrow(/not found/);
      expect(String(fetchMock.mock.calls[0][0])).toContain(
        "/dispatch-intents/job_legacy_service_credit",
      );
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("rejects unknown egress, canonical-ID drift, recipe drift, and contradictory lifecycle flags", () => {
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), provider_id: "forbidden" })).toThrow(/unsupported fields/);
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), job_id: `0x${"9".repeat(64)}` })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      intent_commitment: `0x${"5".repeat(64)}`,
    }))).toThrow(/commitment does not match/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      execution_policy_context_hash: "5".repeat(64),
    }))).toThrow(/execution-policy context/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      resource_limits: { max_prefill_tokens: 32_769, max_sample_tokens: 100, max_train_tokens: 0 },
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      stage: "provider_dispatching",
      provider_dispatch_status: "not_started",
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      provider_dispatch_status: "usage_finalized",
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: false,
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), prompt: "private" })).toThrow(/forbidden field prompt/);
  });

  it("strictly parses the disabled capability and rejects unknown or contradictory upgrades", () => {
    expect(parseComputeFundingCapabilities(fundingCapabilities()).dispatch_intents).toEqual(dispatchCapability());

    const unknown = fundingCapabilities();
    (unknown.dispatch_intents as Record<string, unknown>).future_override = true;
    expect(() => parseComputeFundingCapabilities(unknown)).toThrow(/unsupported fields/);

    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      provider_dispatch: true,
    })))).toThrow(/contradictory/);
    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      metadata_intent_creation: true,
      mutation_route: null,
    })))).toThrow(/contradictory/);
    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      independent_metering: true,
    })))).toThrow(/contradictory/);
  });

  it("keeps creation disabled until both project and every independent release capability agree", () => {
    const allEnabled = dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      reason: "release_bound_dispatch_available",
    });
    expect(canCreateComputeDispatchIntent(dispatchProject, allEnabled)).toBe(false);
    const enabledProject = { ...dispatchProject, provider_dispatch_enabled: true };
    expect(canCreateComputeDispatchIntent(enabledProject, allEnabled)).toBe(true);
    expect(canCreateComputeDispatchIntent({ ...enabledProject, role: "viewer" }, allEnabled)).toBe(false);
    expect(canCreateComputeDispatchIntent(enabledProject, { ...allEnabled, settlement: false })).toBe(false);
  });

  it("reads the status route with bearer auth and losslessly parses bare oversized JSON integers", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const serialized = JSON.stringify(dispatchStatus())
      .replace('"authorization_nonce":"9007199254740993"', '"authorization_nonce":9007199254740993')
      .replace('"max_asset_debit":"1000000000000000000"', '"max_asset_debit":1000000000000000000');
    const fetchMock = vi.fn(async () => new Response(serialized, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const parsed = await fetchComputeDispatchIntent(
        "compute-wallet-token",
        dispatchProject.project_id,
        "wallet-job-0001",
      );
      expect(parsed.max_asset_debit).toBe(1_000_000_000_000_000_000n);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents/wallet-job-0001`);
      expect(options.credentials).toBe("omit");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("refuses disabled creation before fetch and posts only canonical metadata when fully enabled", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const allEnabled = dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      reason: "release_bound_dispatch_available",
    });
    const enabledProject = { ...dispatchProject, provider_dispatch_enabled: true };
    const input = {
      jobReference: "wallet-job-0001",
      workloadId: `wrk_${"ab".repeat(16)}`,
      asset: `0x${"0".repeat(40)}`,
      authorizationNonce: 9_007_199_254_740_993n,
      maxAssetDebit: 1_000_000_000_000_000_000n,
      authorizationExpiry: Math.floor(Date.now() / 1_000) + 600,
      ratePolicyCommitment: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      operation: "inference" as const,
      resultPolicy: "bounded_summary_receipt" as const,
      maxPrefillTokens: 1_000,
      maxSampleTokens: 100,
      maxTrainTokens: 0,
    };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      surface: "compute_dispatch_intent_result",
      schema_version: 2,
      created: true,
      idempotent_replay: false,
      intent: dispatchStatus({ authorization_expiry: input.authorizationExpiry }),
      legacy_credit_ledger_mutated: false,
      provider_dispatch_status: "not_started",
      provider_dispatch_may_have_occurred: false,
      provider_authoritative: false,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(createComputeDispatchIntent(
        "compute-wallet-token", dispatchProject, allEnabled, input, "dispatch:12345678",
      )).rejects.toThrow(/not enabled/);
      expect(fetchMock).not.toHaveBeenCalled();

      await expect(createComputeDispatchIntent(
        "compute-wallet-token", enabledProject, allEnabled, input, "dispatch:12345678",
      )).resolves.toMatchObject({ created: true, idempotentReplay: false });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents`);
      expect(options.method).toBe("POST");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "dispatch:12345678",
      });
      expect(JSON.parse(String(options.body))).toEqual({
        job_reference: "wallet-job-0001",
        workload_id: `wrk_${"ab".repeat(16)}`,
        asset: `0x${"0".repeat(40)}`,
        authorization_nonce: "9007199254740993",
        max_asset_debit: "1000000000000000000",
        authorization_expiry: input.authorizationExpiry,
        rate_policy_commitment: `0x${"3".repeat(64)}`,
        compose_hash: `0x${"4".repeat(64)}`,
        operation: "inference",
        model: "qwen3_8b",
        recipe: "qwen3_8b_bounded",
        result_policy: "bounded_summary_receipt",
        max_prefill_tokens: 1_000,
        max_sample_tokens: 100,
        max_train_tokens: 0,
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });
});
