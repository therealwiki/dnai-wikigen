import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { deployment } from "../config";
import {
  TinkerRequestError,
  TinkerTrainingReconciliationError,
  TinkerTrainingAttempt,
  TinkerIdempotencyAttempt,
  appendTinkerCredentialPage,
  assertTinkerCredentialListMatchesAccount,
  beginTinkerCredentialHistory,
  decryptTinkerCredentialCapsule,
  executeTinkerCustomerTraining,
  fetchCurrentTinkerAccount,
  generateTinkerDeviceKey,
  issueTinkerCredential,
  listTinkerCredentials,
  parseTinkerAccountRequestReceipt,
  parseTinkerAccountStatus,
  parseTinkerCredentialIssueReceipt,
  parseTinkerCredentialList,
  parseTinkerTrainingExecutionReceipt,
  parseTinkerTrainingReconciliationReceipt,
  parseTinkerTrainingDraft,
  recoverTinkerCustomerTraining,
  refreshTinkerCredentialHistory,
  revokeTinkerAccount,
  revokeTinkerCredential,
  rotateTinkerCredential,
  tinkerSessionIsCurrent,
  type TinkerCredentialIssueReceipt,
  type TinkerCustomerSession,
  type TinkerDeviceKey,
} from "./tinkerCustomer";
import tinkerCustomerSource from "./tinkerCustomer.ts?raw";

const encoder = new TextEncoder();
const ACCOUNT_ID = `tca_${"a".repeat(24)}`;
const CREDENTIAL_ID = `tcc_${"b".repeat(24)}`;
const RESERVATION_ID = `tcr_${"c".repeat(24)}`;
const ACCOUNT_COMMITMENT = `0x${"9".repeat(64)}`;
const ACCOUNT_BINDING_TRUTH =
  "independently_attested_opaque_binding_handle_not_cryptographic_proof_of_provider_internal_identity";
const ACCOUNT_BINDING_TYPE =
  "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)";
const ACCOUNT_BINDING_TYPEHASH =
  "0x7f67603ed57564d41a9f6c2ed90a06ffa1477e9f75cbd68a2cb624c63cd6a1f0";
const PROVIDER_NAMESPACE =
  "0xbebf29be35e78cf8b75112a67af061d2e2b608bc0a2b4df1273bfd992f0a06f6";
const NOW = 1_893_456_000;
const HUGE_CAP = "900719925474099312345678901234567890";
const WALLET_ADDRESS = `0x${"1".repeat(40)}`;

function digest(digit: string): string {
  return `sha256:${digit.repeat(64)}`;
}

function hex32(digit: string): string {
  return `0x${digit.repeat(64)}`;
}

function hex(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(
    bytes,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function base64Url(value: string): string {
  const bytes = encoder.encode(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function walletToken(): string {
  return [
    base64Url(JSON.stringify({ alg: "HS256", typ: "JWT" })),
    base64Url(JSON.stringify({
      sub: WALLET_ADDRESS,
      scope: "compute:console",
      exp: NOW + 900,
      padding: "wallet-scoped-tinker-session",
    })),
    base64Url("fixture-wallet-signature-material"),
  ].join(".");
}

function policy(): Record<string, unknown> {
  return {
    allowed_operations: ["training"],
    max_operation_policy_units: HUGE_CAP,
    max_outstanding_policy_units: "1801439850948198624691357802469135780",
    max_lifetime_policy_units: "3602879701896397249382715604938271560",
    credential_max_ttl_seconds: 3_600,
    max_active_credentials: 4,
    inference_enabled: false,
    hosted_card_funding: "roadmap",
    token_exchange: "roadmap",
    raw_secret_egress: false,
  };
}

function gate(): Record<string, unknown> {
  return {
    chain_id: 84532,
    finalized_block_number: 12_345_678,
    finalized_block_hash: hex32("1"),
    release_observation_digest: digest("2"),
    release_policy_tuple_digest: digest("3"),
    runtime_evidence_digest: digest("4"),
    tdx_verified: true,
    qvl_pass: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

function bindingAuthority(): Record<string, unknown> {
  return {
    truth_status: ACCOUNT_BINDING_TRUTH,
    account_binding_schema: "dnai.tinker-account-binding.v1",
    account_binding_version: 1,
    account_binding_chain_id: 84532,
    account_binding_type: ACCOUNT_BINDING_TYPE,
    account_binding_typehash: ACCOUNT_BINDING_TYPEHASH,
    provider_namespace_label: "thinking-machines/tinker",
    provider_namespace: PROVIDER_NAMESPACE,
    account_commitment: ACCOUNT_COMMITMENT,
    account_binding_receipt_digest: digest("5"),
    sealed_binding_record_hash: digest("6"),
    account_binding_ceremony_receipt_digest: digest("7"),
    deployment_intent_digest: digest("8"),
    account_binding_receipt_independently_attested: true,
    account_binding_handle_attested: true,
    provider_identity_checked: true,
    current_provider_session_rechecked: true,
    account_commitment_exact_match: true,
    provider_internal_identity_cryptographically_proven: false,
    raw_provider_account_id_egress: false,
    raw_binding_root_egress: false,
    raw_reviewer_share_egress: false,
    binding_root_or_share_digest_published: false,
    raw_provider_auth_egress: false,
    raw_provider_session_egress: false,
    raw_secret_egress: false,
  };
}

function accountStatus(
  lifecycle: "requested" | "active" = "requested",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const active = lifecycle === "active";
  return {
    surface: "tinker_customer_account_status",
    schema_version: 1,
    account_id: ACCOUNT_ID,
    status: lifecycle,
    mode: "create",
    owner_address_hash: digest("9"),
    request_commitment: digest("a"),
    account_commitment: ACCOUNT_COMMITMENT,
    release_lineage_digest: digest("b"),
    account_binding_authority_digest: active ? digest("c") : null,
    account_binding_authority: active ? bindingAuthority() : {},
    account_policy: policy(),
    credential_counts: active ? { active: 1 } : {},
    reservation_counts: {},
    settled_policy_units: "0",
    outstanding_policy_units: "0",
    upstream_account_exists: active,
    raw_account_identifier_returned: false,
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    hosted_card_funding: "roadmap",
    token_exchange: "roadmap",
    raw_secret_egress: false,
    ...overrides,
  };
}

function accountRequestReceipt(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    surface: "tinker_customer_account_request",
    schema_version: 1,
    account_id: ACCOUNT_ID,
    status: "requested",
    mode: "create",
    request_commitment: digest("a"),
    owner_address_hash: digest("9"),
    release_lineage_digest: digest("b"),
    account_binding_ceremony_receipt_digest: digest("7"),
    deployment_intent_digest: digest("8"),
    account_policy: policy(),
    upstream_account_exists: false,
    provisioning_performed: false,
    browser_supplied_account_commitment_accepted: false,
    hosted_card_funding: "roadmap",
    token_exchange: "roadmap",
    gate: gate(),
    idempotent_replay: false,
    raw_secret_egress: false,
    ...overrides,
  };
}

function credentialList(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    surface: "tinker_customer_credentials",
    schema_version: 2,
    account_id: ACCOUNT_ID,
    account_status: "active",
    release_lineage_digest: digest("b"),
    account_binding_authority_digest: digest("c"),
    total_credentials: 1,
    page_credential_count: 1,
    page_limit: 16,
    maximum_page_size: 64,
    has_more: false,
    next_cursor: null,
    snapshot_sequence: 9,
    ordering: "issued_at_desc_then_credential_id_desc",
    credentials: [{
      credential_id: CREDENTIAL_ID,
      status: "active",
      persisted_status: "active",
      operations: ["training"],
      scopes: ["tinker:train"],
      max_operation_policy_units: HUGE_CAP,
      recipient_public_key_hash: digest("d"),
      jwt_id_hash: digest("e"),
      issued_at: NOW - 5,
      expires_at: NOW + 300,
      revoked_at: 0,
      token_returned_in_plaintext: false,
    }],
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    credential_capsules_returned: false,
    plaintext_token_egress: false,
    raw_secret_egress: false,
    ...overrides,
  };
}

function trainingExecutionReceipt(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    surface: "tinker_customer_training_execution",
    schema_version: 1,
    status: "settled",
    reservation_id: RESERVATION_ID,
    reservation_commitment: digest("1"),
    workload_commitment: digest("2"),
    reserved_policy_units: "50000",
    actual_policy_units: "50000",
    released_policy_units: "0",
    policy_unit_definition: "one_policy_unit_per_requested_max_usd_micro",
    provider_authoritative_billing: false,
    authority_accounting_only: true,
    fixed_ceiling_accounting: true,
    at_most_once_claim_committed: true,
    automatic_provider_redispatch: false,
    reconciliation_required: false,
    training_result: {
      surface: "tinker_customer_training_result",
      schema_version: 1,
      success: true,
      outcome: "training_completed",
      furthest_stage: "cleanup_completed",
      deal_id_hash: "3".repeat(64),
      model_hash: "4".repeat(64),
      rank: 4,
      steps_requested: 2,
      steps_completed: 2,
      max_usd_band: "<1e6",
      metered_cost_band: "<1e6",
      checkpoint_saved: true,
      error_kind: "",
      bounded_message: "training_completed",
      issued_at: NOW,
      provider_dispatch_attempted: true,
      provider_dispatch_performed: true,
      provider_outcome_ambiguous: false,
      raw_secret_egress: false,
    },
    settlement: {
      status: "settled",
      usage_receipt_hash: digest("5"),
      dispatch_runtime_evidence_digest: digest("6"),
      provider_dispatch_performed: true,
    },
    idempotent_replay: false,
    raw_secret_egress: false,
    ...overrides,
  };
}

function trainingReconciliationReceipt(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    surface: "tinker_customer_training_reconciliation",
    schema_version: 1,
    status: "reconciliation_required",
    reservation_id: RESERVATION_ID,
    reservation_commitment: digest("1"),
    workload_commitment: digest("2"),
    at_most_once_claim_committed: true,
    automatic_provider_redispatch: false,
    provider_outcome_confirmed: false,
    provider_authoritative_billing: false,
    authority_accounting_only: true,
    raw_secret_egress: false,
    ...overrides,
  };
}

function jsonResponse(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function domainDigest(domain: string, value: string): Promise<string> {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`${domain}\u0000${value}`),
  );
  return `sha256:${hex(result)}`;
}

async function capsuleFixture(
  payloadOverrides: Record<string, unknown> = {},
): Promise<{
  device: TinkerDeviceKey;
  receipt: TinkerCredentialIssueReceipt;
  token: string;
}> {
  const device = await generateTinkerDeviceKey();
  const recipientBytes = Uint8Array.from(
    device.publicKeyHex.match(/../g) ?? [],
    (byte) => Number.parseInt(byte, 16),
  );
  const recipient = await crypto.subtle.importKey(
    "raw",
    buffer(recipientBytes),
    { name: "X25519" },
    false,
    [],
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"],
  ) as CryptoKeyPair;
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "X25519", public: recipient },
    ephemeral.privateKey,
    256,
  ));
  const hkdf = await crypto.subtle.importKey(
    "raw",
    buffer(shared),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: encoder.encode("dnai-wikigen-tinker-customer-credential-v1"),
    },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const recipientHash = await domainDigest(
    "tinker_customer_recipient",
    device.publicKeyHex,
  );
  const jwtId = "0123456789abcdef0123456789abcdef";
  const jwtIdHash = await domainDigest("tinker_customer_jti", jwtId);
  const associatedObject = {
    surface: "tinker_customer_credential",
    credential_id: CREDENTIAL_ID,
    account_id: ACCOUNT_ID,
    owner_address_hash: digest("9"),
    recipient_public_key_hash: recipientHash,
    operations: ["training"],
    max_operation_policy_units: HUGE_CAP,
    jwt_id_hash: jwtIdHash,
    release_policy_tuple_digest: digest("3"),
    release_lineage_digest: digest("b"),
    account_binding_authority_digest: digest("c"),
    account_binding_ceremony_receipt_digest: digest("7"),
    deployment_intent_digest: digest("8"),
    account_policy_digest: digest("f"),
    expires_at: NOW + 300,
  };
  const associatedBytes = encoder.encode(canonicalJson(associatedObject));
  const associatedHex = hex(associatedBytes);
  const header = {
    alg: "HS256",
    kid: "dstack-tinker-customer-v1",
    typ: "JWT",
  };
  const payload = {
    iss: "dnai-wikigen:tinker-customer",
    aud: "dnai-wikigen:tinker-proxy",
    sub: CREDENTIAL_ID,
    account_id: ACCOUNT_ID,
    owner_address_hash: digest("9"),
    scope: "tinker:train",
    operations: "training",
    max_operation_policy_units: HUGE_CAP,
    release_policy_tuple_digest: digest("3"),
    release_lineage_digest: digest("b"),
    account_binding_authority_digest: digest("c"),
    account_binding_ceremony_receipt_digest: digest("7"),
    deployment_intent_digest: digest("8"),
    account_policy_digest: digest("f"),
    iat: NOW - 5,
    nbf: NOW - 5,
    exp: NOW + 300,
    jti: jwtId,
    ...payloadOverrides,
  };
  const token = [
    base64Url(JSON.stringify(header)),
    base64Url(JSON.stringify(payload)),
    base64Url("fixture-service-signature-material"),
  ].join(".");
  const nonce = new Uint8Array(12).fill(7);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: buffer(nonce),
      additionalData: buffer(associatedBytes),
      tagLength: 128,
    },
    encryptionKey,
    encoder.encode(token),
  );
  const ephemeralPublic = await crypto.subtle.exportKey(
    "raw",
    ephemeral.publicKey,
  );
  shared.fill(0);
  recipientBytes.fill(0);

  const receipt = parseTinkerCredentialIssueReceipt({
    surface: "tinker_customer_credential_issue",
    schema_version: 1,
    credential_id: CREDENTIAL_ID,
    account_id: ACCOUNT_ID,
    status: "active",
    operations: ["training"],
    scopes: ["tinker:train"],
    max_operation_policy_units: HUGE_CAP,
    account_policy_digest: digest("f"),
    release_lineage_digest: digest("b"),
    account_binding_authority_digest: digest("c"),
    account_binding_ceremony_receipt_digest: digest("7"),
    deployment_intent_digest: digest("8"),
    issued_at: NOW - 5,
    expires_at: NOW + 300,
    jwt_id_hash: jwtIdHash,
    capsule: {
      delivery: "x25519_aes_256_gcm_envelope",
      encrypted_token: {
        ephemeral_public_key: hex(ephemeralPublic),
        nonce: hex(nonce),
        ciphertext: hex(ciphertext),
      },
      associated_data: associatedHex,
      associated_data_hash: await domainDigest(
        "tinker_customer_credential_aad",
        associatedHex,
      ),
      recipient_public_key_hash: recipientHash,
      token_returned_in_plaintext: false,
    },
    upstream_tinker_key_exposed: false,
    upstream_project_exposed: false,
    token_returned_in_plaintext: false,
    gate: gate(),
    idempotent_replay: false,
    raw_secret_egress: false,
  });
  return { device, receipt, token };
}

describe("Tinker customer lifecycle response contracts", () => {
  beforeEach(() => {
    vi.setSystemTime(new Date(NOW * 1_000));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("accepts exact pending and active account states", () => {
    const pending = parseTinkerAccountStatus(accountStatus("requested"));
    const active = parseTinkerAccountStatus(accountStatus("active"));

    expect(pending.status).toBe("requested");
    expect(pending.account_binding_authority_digest).toBeNull();
    expect(active.status).toBe("active");
    expect(active.account_binding_authority.account_commitment)
      .toBe(ACCOUNT_COMMITMENT);
  });

  it("rejects response extension, capability overclaim, and activation drift", () => {
    expect(() => parseTinkerAccountStatus(accountStatus("requested", {
      future_field: false,
    }))).toThrow("unsupported fields");
    expect(() => parseTinkerAccountStatus(accountStatus("requested", {
      upstream_tinker_key_exposed: true,
    }))).toThrow("upstream key egress");
    expect(() => parseTinkerAccountStatus(accountStatus("active", {
      account_binding_authority_digest: null,
    }))).toThrow("activation evidence");
    expect(() => parseTinkerAccountStatus(accountStatus("requested", {
      upstream_account_exists: "false",
    }))).toThrow("activation evidence");
  });

  it("requires the exact Base Sepolia live gate for account requests", () => {
    expect(parseTinkerAccountRequestReceipt(accountRequestReceipt()).gate.chain_id)
      .toBe(84532);
    expect(() => parseTinkerAccountRequestReceipt(accountRequestReceipt({
      gate: { ...gate(), chain_id: 1 },
    }))).toThrow("not Base Sepolia");
    expect(() => parseTinkerAccountRequestReceipt(accountRequestReceipt({
      gate: { ...gate(), tdx_verified: false },
    }))).toThrow("TDX gate");
  });

  it("accepts bounded credential metadata and rejects replayable capsules or secrets", () => {
    const parsed = parseTinkerCredentialList(
      credentialList(),
      ACCOUNT_ID,
    );
    expect(parsed.credentials).toHaveLength(1);
    expect(parsed.credentials[0].status).toBe("active");
    expect(parsed.credential_capsules_returned).toBe(false);

    const projectedExpired = parseTinkerCredentialList(
      credentialList({
        credentials: [{
          ...(credentialList().credentials as Record<string, unknown>[])[0],
          status: "expired",
        }],
      }),
      ACCOUNT_ID,
    );
    expect(projectedExpired.credentials[0].status).toBe("expired");

    expect(() => parseTinkerCredentialList(
      credentialList({ credential_capsules_returned: true }),
      ACCOUNT_ID,
    )).toThrow("credential list is invalid");
    expect(() => parseTinkerCredentialList(
      credentialList({
        total_credentials: 65,
        page_limit: 1,
        has_more: true,
        next_cursor: null,
      }),
      ACCOUNT_ID,
    )).toThrow("cursor state is inconsistent");
    expect(() => parseTinkerCredentialList(
      credentialList({
        credentials: [{
          ...(credentialList().credentials as Record<string, unknown>[])[0],
          max_operation_policy_units: "0",
        }],
      }),
      ACCOUNT_ID,
    )).toThrow("must be positive");
  });

  it("strictly appends one account/snapshot-bound credential history", () => {
    const newest = (
      credentialList().credentials as Record<string, unknown>[]
    )[0];
    const olderId = `tcc_${"a".repeat(24)}`;
    const first = parseTinkerCredentialList(credentialList({
      total_credentials: 2,
      page_credential_count: 1,
      page_limit: 1,
      has_more: true,
      next_cursor: "opaque.cursor.page-2",
    }), ACCOUNT_ID);
    const second = parseTinkerCredentialList(credentialList({
      total_credentials: 2,
      page_credential_count: 1,
      page_limit: 1,
      credentials: [{
        ...newest,
        credential_id: olderId,
        issued_at: NOW - 10,
      }],
    }), ACCOUNT_ID);
    const history = appendTinkerCredentialPage(
      beginTinkerCredentialHistory(first),
      second,
    );
    expect(history.credentials.map((credential) => credential.credential_id))
      .toEqual([CREDENTIAL_ID, olderId]);
    expect(history.has_more).toBe(false);
    expect(history.next_cursor).toBeNull();

    const refreshed = refreshTinkerCredentialHistory(
      history,
      parseTinkerCredentialList(credentialList({
        total_credentials: 2,
        page_credential_count: 1,
        page_limit: 1,
        has_more: true,
        next_cursor: "opaque.cursor.page-2",
        credentials: [{
          ...newest,
          status: "expired",
        }],
      }), ACCOUNT_ID),
    );
    expect(refreshed.credentials[0].status).toBe("expired");
    expect(refreshed.credentials[1].credential_id).toBe(olderId);

    expect(() => appendTinkerCredentialPage(
      beginTinkerCredentialHistory(first),
      parseTinkerCredentialList(credentialList({
        total_credentials: 2,
        page_credential_count: 1,
        page_limit: 1,
        snapshot_sequence: 10,
        credentials: [{
          ...newest,
          credential_id: olderId,
          issued_at: NOW - 10,
        }],
      }), ACCOUNT_ID),
    )).toThrow("does not continue");
    expect(() => parseTinkerCredentialList(credentialList({
      total_credentials: 2,
      page_credential_count: 2,
      page_limit: 2,
      credentials: [
        newest,
        {
          ...newest,
          credential_id: olderId,
          issued_at: NOW,
        },
      ],
    }), ACCOUNT_ID)).toThrow("ordering is invalid");
    expect(() => parseTinkerCredentialList(credentialList({
      total_credentials: 2,
      page_credential_count: 2,
      page_limit: 2,
      credentials: [newest, newest],
    }), ACCOUNT_ID)).toThrow("duplicate identities");
  });

  it("binds credential metadata back to the same account lineage and outer cap", () => {
    const account = parseTinkerAccountStatus(accountStatus("active"));
    const listing = parseTinkerCredentialList(credentialList(), ACCOUNT_ID);

    expect(() => assertTinkerCredentialListMatchesAccount(listing, account))
      .not.toThrow();

    const wrongLineage = parseTinkerCredentialList(credentialList({
      release_lineage_digest: digest("d"),
    }), ACCOUNT_ID);
    expect(() => assertTinkerCredentialListMatchesAccount(
      wrongLineage,
      account,
    )).toThrow("does not match");

    const widened = parseTinkerCredentialList(credentialList({
      credentials: [{
        ...(credentialList().credentials as Record<string, unknown>[])[0],
        max_operation_policy_units: (BigInt(HUGE_CAP) + 1n).toString(),
      }],
    }), ACCOUNT_ID);
    expect(() => assertTinkerCredentialListMatchesAccount(widened, account))
      .toThrow("exceeds its account policy");
  });

  it("rejects usage projections beyond immutable account caps", () => {
    expect(() => parseTinkerAccountStatus(accountStatus("active", {
      outstanding_policy_units: (
        BigInt(String(policy().max_outstanding_policy_units)) + 1n
      ).toString(),
    }))).toThrow("usage exceeds");
    expect(() => parseTinkerAccountStatus(accountStatus("active", {
      settled_policy_units: (
        BigInt(String(policy().max_lifetime_policy_units)) + 1n
      ).toString(),
    }))).toThrow("usage exceeds");
  });

  it("accepts only exact internally consistent customer-training settlements", () => {
    const parsed = parseTinkerTrainingExecutionReceipt(
      trainingExecutionReceipt(),
      { maxUsdMicros: 50_000, steps: 2 },
    );

    expect(parsed.status).toBe("settled");
    expect(parsed.training_result.outcome).toBe("training_completed");
    expect(parsed.settlement.provider_dispatch_performed).toBe(true);
    expect(parsed.provider_authoritative_billing).toBe(false);
    expect(parsed.authority_accounting_only).toBe(true);

    expect(() => parseTinkerTrainingExecutionReceipt(
      trainingExecutionReceipt({ released_policy_units: "1" }),
    )).toThrow("accounting");
    expect(() => parseTinkerTrainingExecutionReceipt(
      trainingExecutionReceipt({
        settlement: {
          status: "settled",
          usage_receipt_hash: digest("5"),
          dispatch_runtime_evidence_digest: digest("6"),
          provider_dispatch_performed: false,
        },
      }),
    )).toThrow("settlement evidence");
    expect(() => parseTinkerTrainingExecutionReceipt(
      trainingExecutionReceipt({
        training_result: {
          ...(trainingExecutionReceipt().training_result as Record<string, unknown>),
          provider_outcome_ambiguous: true,
        },
      }),
    )).toThrow("provider evidence");
  });

  it("accepts reconciliation only when the durable claim cannot redispatch", () => {
    const parsed = parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt(),
    );

    expect(parsed.status).toBe("reconciliation_required");
    expect(parsed.at_most_once_claim_committed).toBe(true);
    expect(parsed.automatic_provider_redispatch).toBe(false);
    expect(parsed.provider_outcome_confirmed).toBe(false);

    expect(() => parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt({
        automatic_provider_redispatch: true,
      }),
    )).toThrow("reconciliation receipt is invalid");
    expect(() => parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt({ raw_provider_response: "secret" }),
    )).toThrow("unsupported fields");
  });
});

describe("Tinker customer HTTP boundary", () => {
  const mutableDeployment = deployment as unknown as { delegateUrl: string };
  let originalDelegateUrl = "";

  beforeEach(() => {
    originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
  });

  afterEach(() => {
    mutableDeployment.delegateUrl = originalDelegateUrl;
    vi.unstubAllGlobals();
  });

  it("recovers a missing current account as an empty wallet-owned state", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse({
      detail: "customer account was not found",
    }, 404));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchCurrentTinkerAccount(walletToken())).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0])
      .toBe("https://delegate.example/tinker/customer/accounts/current");
  });

  it("treats credential cursors as opaque and exposes restart-required conflicts", async () => {
    const fetchMock = vi.fn(async (
      input: RequestInfo | URL,
      _init?: RequestInit,
    ) => (
      String(input).includes("cursor=")
        ? jsonResponse(credentialList({
          total_credentials: 2,
          page_credential_count: 1,
          page_limit: 1,
          credentials: [{
            ...(
              credentialList().credentials as Record<string, unknown>[]
            )[0],
            credential_id: `tcc_${"a".repeat(24)}`,
            issued_at: NOW - 10,
          }],
        }))
        : jsonResponse(credentialList({
          total_credentials: 2,
          page_credential_count: 1,
          page_limit: 1,
          has_more: true,
          next_cursor: "opaque.cursor.page-2",
        }))
    ));
    vi.stubGlobal("fetch", fetchMock);

    const first = await listTinkerCredentials(
      walletToken(),
      ACCOUNT_ID,
      { limit: 1 },
    );
    const second = await listTinkerCredentials(
      walletToken(),
      ACCOUNT_ID,
      { limit: 1, cursor: first.next_cursor ?? undefined },
    );
    expect(first.has_more).toBe(true);
    expect(second.has_more).toBe(false);
    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      (
        `https://delegate.example/tinker/customer/accounts/${ACCOUNT_ID}`
        + "/credentials?limit=1"
      ),
      (
        `https://delegate.example/tinker/customer/accounts/${ACCOUNT_ID}`
        + "/credentials?limit=1&cursor=opaque.cursor.page-2"
      ),
    ]);

    fetchMock.mockResolvedValueOnce(jsonResponse({
      detail: "Tinker customer request conflicts with current state",
    }, 409));
    const conflict = await listTinkerCredentials(
      walletToken(),
      ACCOUNT_ID,
      { limit: 1, cursor: "opaque.cursor.stale" },
    ).catch((cause: unknown) => cause);
    expect(conflict).toBeInstanceOf(TinkerRequestError);
    expect((conflict as TinkerRequestError).restartRequired).toBe(true);

    const callsBeforeInvalid = fetchMock.mock.calls.length;
    await expect(listTinkerCredentials(
      walletToken(),
      ACCOUNT_ID,
      { cursor: "invalid cursor\n" },
    )).rejects.toThrow("cursor is invalid");
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeInvalid);
  });

  it("serializes uint256 credential caps as exact raw JSON integers", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse({
      detail: "fixture stops after request inspection",
    }, 409));
    vi.stubGlobal("fetch", fetchMock);
    const recipient = "1".repeat(64);

    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      recipient,
      900,
      HUGE_CAP,
      "credential-issue-test-0001",
    )).rejects.toThrow("fixture stops");
    await expect(rotateTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      CREDENTIAL_ID,
      recipient,
      600,
      HUGE_CAP,
      "credential-rotate-test-0001",
    )).rejects.toThrow("fixture stops");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const issueInit = fetchMock.mock.calls[0][1] as RequestInit;
    const rotationInit = fetchMock.mock.calls[1][1] as RequestInit;
    expect(issueInit.body).toBe(
      `{"recipient_public_key":"${recipient}","operations":["training"],`
      + `"ttl_seconds":900,"max_operation_policy_units":${HUGE_CAP}}`,
    );
    expect(rotationInit.body).toBe(
      `{"recipient_public_key":"${recipient}","operations":["training"],`
      + `"ttl_seconds":600,"max_operation_policy_units":${HUGE_CAP}}`,
    );
    expect(String(issueInit.body)).not.toContain(`"${HUGE_CAP}"`);
    expect(issueInit.credentials).toBe("omit");
    expect(issueInit.cache).toBe("no-store");
    expect(issueInit.headers).toMatchObject({
      Authorization: `Bearer ${walletToken()}`,
      "Content-Type": "application/json",
      "Idempotency-Key": "credential-issue-test-0001",
    });
  });

  it("requires the issued lifetime to equal the requested TTL", async () => {
    const { device, receipt } = await capsuleFixture();
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse(receipt));
    vi.stubGlobal("fetch", fetchMock);

    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      device.publicKeyHex,
      305,
      HUGE_CAP,
      "credential-issue-test-ttl-0001",
    )).resolves.toMatchObject({ credential_id: CREDENTIAL_ID });

    fetchMock.mockResolvedValueOnce(jsonResponse({
      ...receipt,
      expires_at: receipt.expires_at + 1,
    }));
    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      device.publicKeyHex,
      305,
      HUGE_CAP,
      "credential-issue-test-ttl-0002",
    )).rejects.toThrow("changed its requested lifetime");
  });

  it("rejects noncanonical, zero, and out-of-range caps before network egress", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const recipient = "1".repeat(64);
    const overUint256 = (1n << 256n).toString();

    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      recipient,
      900,
      "01",
      "credential-issue-test-0002",
    )).rejects.toThrow("canonical uint256");
    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      recipient,
      900,
      "0",
      "credential-issue-test-0003",
    )).rejects.toThrow("must be positive");
    await expect(issueTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      recipient,
      900,
      overUint256,
      "credential-issue-test-0004",
    )).rejects.toThrow("exceeds uint256");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects non-hex resource identifiers before network egress", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(issueTinkerCredential(
      walletToken(),
      `tca_${"z".repeat(24)}`,
      "1".repeat(64),
      900,
      "1",
      "credential-issue-test-0005",
    )).rejects.toThrow("account ID is invalid");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends exact empty JSON objects for terminal credential and account revocation", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse({
      detail: "fixture stops after request inspection",
    }, 409));
    vi.stubGlobal("fetch", fetchMock);

    await expect(revokeTinkerCredential(
      walletToken(),
      ACCOUNT_ID,
      CREDENTIAL_ID,
      "credential-revoke-test-0001",
    )).rejects.toThrow("fixture stops");
    await expect(revokeTinkerAccount(
      walletToken(),
      ACCOUNT_ID,
      "account-revoke-test-0001",
    )).rejects.toThrow("fixture stops");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const call of fetchMock.mock.calls) {
      const init = call[1] as RequestInit;
      expect(init.method).toBe("POST");
      expect(init.body).toBe("{}");
      expect(init.headers).toMatchObject({
        "Content-Type": "application/json",
      });
    }
  });

  it("submits only three bounded training controls with the lower-authority bearer", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse(trainingExecutionReceipt()));
    vi.stubGlobal("fetch", fetchMock);
    const credential = walletToken();

    await expect(executeTinkerCustomerTraining(
      credential,
      { maxUsdMicros: 50_000, steps: 2, ttlSeconds: 600 },
      "customer-training-test-0001",
    )).resolves.toMatchObject({
      status: "settled",
      provider_authoritative_billing: false,
      automatic_provider_redispatch: false,
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0])
      .toBe("https://delegate.example/tinker/customer/train");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.body).toBe(
      '{"max_usd_micros":50000,"steps":2,"ttl_seconds":600}',
    );
    expect(init.credentials).toBe("omit");
    expect(init.cache).toBe("no-store");
    expect(init.headers).toMatchObject({
      Authorization: `Bearer ${credential}`,
      "Content-Type": "application/json",
      "Idempotency-Key": "customer-training-test-0001",
    });
    expect(String(init.body)).not.toMatch(/prompt|examples|dataset|api_key/);
  });

  it("projects a 409 claim hold as non-redispatching reconciliation", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({
      detail: trainingReconciliationReceipt(),
    }, 409)));

    const failure = await executeTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 2, ttlSeconds: 600 },
      "customer-training-test-0002",
    ).catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(TinkerTrainingReconciliationError);
    expect((failure as TinkerTrainingReconciliationError).receipt)
      .toMatchObject({
        status: "reconciliation_required",
        at_most_once_claim_committed: true,
        automatic_provider_redispatch: false,
      });
  });

  it("recovers only the exact retained claim with the original controls and idempotency key", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse(trainingExecutionReceipt()));
    vi.stubGlobal("fetch", fetchMock);
    const controls = Object.freeze({
      maxUsdMicros: 50_000,
      steps: 2,
      ttlSeconds: 600,
    });
    const hold = parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt(),
    );

    await expect(recoverTinkerCustomerTraining(
      walletToken(),
      controls,
      "customer-training-test-retained-0001",
      hold,
    )).resolves.toMatchObject({
      reservation_id: RESERVATION_ID,
      status: "settled",
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0])
      .toBe("https://delegate.example/tinker/customer/train");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.body).toBe(
      '{"max_usd_micros":50000,"steps":2,"ttl_seconds":600}',
    );
    expect(init.headers).toMatchObject({
      "Idempotency-Key": "customer-training-test-retained-0001",
    });
  });

  it("keeps the exact hold when signed recovery evidence is still absent", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      detail: trainingReconciliationReceipt(),
    }, 409));
    vi.stubGlobal("fetch", fetchMock);
    const hold = parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt(),
    );

    const failure = await recoverTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 2, ttlSeconds: 600 },
      "customer-training-test-retained-0002",
      hold,
    ).catch((cause: unknown) => cause);

    expect(failure).toBeInstanceOf(TinkerTrainingReconciliationError);
    expect((failure as TinkerTrainingReconciliationError).receipt).toEqual(hold);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects a recovered result or repeated hold bound to a different claim", async () => {
    const hold = parseTinkerTrainingReconciliationReceipt(
      trainingReconciliationReceipt(),
    );
    const otherReservation = `tcr_${"d".repeat(24)}`;
    const fetchMock = vi.fn(async () => jsonResponse(
      trainingExecutionReceipt({ reservation_id: otherReservation }),
    ));
    vi.stubGlobal("fetch", fetchMock);

    await expect(recoverTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 2, ttlSeconds: 600 },
      "customer-training-test-retained-0003",
      hold,
    )).rejects.toThrow("differs from the retained claim");

    fetchMock.mockResolvedValueOnce(jsonResponse({
      detail: trainingReconciliationReceipt({
        workload_commitment: digest("7"),
      }),
    }, 409));
    await expect(recoverTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 2, ttlSeconds: 600 },
      "customer-training-test-retained-0003",
      hold,
    )).rejects.toThrow("differs from the retained claim");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rejects non-integer or out-of-cap training controls before network egress", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(executeTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 0, steps: 1, ttlSeconds: 900 },
      "customer-training-test-0003",
    )).rejects.toThrow("ceiling");
    await expect(executeTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 1.5, ttlSeconds: 900 },
      "customer-training-test-0004",
    )).rejects.toThrow("steps");
    await expect(executeTinkerCustomerTraining(
      walletToken(),
      { maxUsdMicros: 50_000, steps: 1, ttlSeconds: 3_601 },
      "customer-training-test-0005",
    )).rejects.toThrow("lifetime");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects forbidden response fields before lifecycle parsing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({
      ...accountStatus("requested"),
      upstream_api_key: "must-never-arrive",
    })));

    await expect(fetchCurrentTinkerAccount(walletToken()))
      .rejects.toThrow("forbidden field");
  });

  it("contains no browser path to reservation or internal activation/finalization", () => {
    expect(tinkerCustomerSource)
      .not.toContain('"/tinker/customer/reservations"');
    expect(tinkerCustomerSource).not.toContain('"/tinker/internal/');
    expect(tinkerCustomerSource).not.toMatch(
      /\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b/,
    );
  });
});

describe("Tinker retained training attempt", () => {
  const mutableDeployment = deployment as unknown as { delegateUrl: string };
  let originalDelegateUrl = "";
  const draft = { maxUsdMicros: "50000", steps: "2", ttlSeconds: "600" };
  const identity = () => ({
    accountId: ACCOUNT_ID,
    credentialId: CREDENTIAL_ID,
    credentialToken: walletToken(),
    walletSession: {
      accessToken: walletToken(),
      address: WALLET_ADDRESS,
      issuedAt: NOW - 5,
      expiresAt: NOW + 300,
      walletAuthorizationVersion: 7,
    },
  });

  beforeEach(() => {
    originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
  });

  afterEach(() => {
    mutableDeployment.delegateUrl = originalDelegateUrl;
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("captures immutable canonical controls and a public tombstone before any egress", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const authority = identity();
    const mutableDraft = { ...draft };
    const snapshot = attempt.begin(authority, mutableDraft, "50000");
    mutableDraft.steps = "3";
    expect(snapshot.controls).toEqual({ maxUsdMicros: 50000, steps: 2, ttlSeconds: 600 });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.controls)).toBe(true);
    expect(attempt.matches(authority)).toBe(true);
    expect(JSON.stringify(snapshot)).not.toContain(authority.credentialToken);
    expect(JSON.stringify(snapshot)).not.toContain("walletSession");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [{ ...draft, maxUsdMicros: "0" }, "50000"],
    [{ ...draft, maxUsdMicros: "50001" }, "50000"],
    [{ ...draft, steps: "1.5" }, "50000"],
    [{ ...draft, steps: "0x10" }, "50000"],
    [{ ...draft, ttlSeconds: "3e2" }, "50000"],
    [{ ...draft, ttlSeconds: "3601" }, "50000"],
    [draft, "invalid"],
  ])("rejects invalid drafts before request identity allocation or egress: %j", (invalid, cap) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const random = vi.spyOn(crypto, "randomUUID");
    const attempt = new TinkerTrainingAttempt();
    expect(() => attempt.begin(identity(), invalid, cap)).toThrow();
    expect(attempt.snapshot()).toBeUndefined();
    expect(random).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(parseTinkerTrainingDraft(draft, "50000").steps).toBe(2);
  });

  it("keeps a lost-response request and replays the same body, bearer, and key only explicitly", async () => {
    const fetchMock = vi.fn<(
      input: RequestInfo | URL, init?: RequestInit,
    ) => Promise<Response>>()
      .mockRejectedValueOnce(new TypeError("Network response lost"))
      .mockResolvedValueOnce(jsonResponse(trainingExecutionReceipt({ idempotent_replay: true })));
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const authority = identity();
    const snapshot = attempt.begin(authority, draft, "50000");
    await expect(attempt.execute(() => attempt.matches(authority))).rejects.toThrow("response lost");
    expect(attempt.snapshot()).toBe(snapshot);
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(() => attempt.begin(authority, { ...draft, steps: "3" }, "50000"))
      .toThrow("cannot be replaced");
    await expect(attempt.execute(() => attempt.matches(authority)))
      .resolves.toMatchObject({ status: "settled", idempotent_replay: true });
    const first = fetchMock.mock.calls[0][1] as RequestInit;
    const retry = fetchMock.mock.calls[1][1] as RequestInit;
    expect(retry.body).toBe(first.body);
    expect(retry.headers).toEqual(first.headers);
    expect(attempt.snapshot()).toBeUndefined();
    expect(attempt.begin(authority, draft, "50000").idempotencyKey)
      .not.toBe(snapshot.idempotencyKey);
  });

  it("retains the attempt after the actual request timeout signal aborts", async () => {
    const controller = new AbortController();
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValue(controller.signal);
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => (
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      })
    ));
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const snapshot = attempt.begin(identity(), draft, "50000");
    const running = attempt.execute(() => true);
    const rejection = expect(running).rejects.toMatchObject({ name: "TimeoutError" });
    controller.abort(new DOMException("Request deadline reached", "TimeoutError"));
    await rejection;
    expect(timeout).toHaveBeenCalledWith(12_000);
    expect(attempt.snapshot()).toBe(snapshot);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it.each([401, 403, 409, 422, 500, 503])("does not treat HTTP %i as proof that a prior request was never claimed", async (status) => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ detail: "Request rejected" }, status)));
    const attempt = new TinkerTrainingAttempt();
    const snapshot = attempt.begin(identity(), draft, "50000");
    await expect(attempt.execute(() => true)).rejects.toBeInstanceOf(TinkerRequestError);
    expect(attempt.snapshot()).toBe(snapshot);
  });

  it("does not unlock on malformed or mismatched terminal results", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ result: "not a receipt" }))
      .mockResolvedValueOnce(jsonResponse(trainingExecutionReceipt({ reserved_policy_units: "40000" })));
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const snapshot = attempt.begin(identity(), draft, "50000");
    await expect(attempt.execute(() => true)).rejects.toThrow();
    await expect(attempt.execute(() => true)).rejects.toThrow();
    expect(attempt.snapshot()).toBe(snapshot);
  });

  it("retains a parsed hold and rejects a later receipt for another claim", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ detail: trainingReconciliationReceipt() }, 409))
      .mockResolvedValueOnce(jsonResponse(trainingExecutionReceipt({ reservation_id: `tcr_${"d".repeat(24)}` })))
      .mockResolvedValueOnce(jsonResponse(trainingExecutionReceipt({ idempotent_replay: true })));
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const snapshot = attempt.begin(identity(), draft, "50000");
    await expect(attempt.execute(() => true)).rejects.toBeInstanceOf(TinkerTrainingReconciliationError);
    expect(attempt.snapshot()?.hold?.reservation_id).toBe(RESERVATION_ID);
    expect(attempt.snapshot()?.idempotencyKey).toBe(snapshot.idempotencyKey);
    await expect(attempt.execute(() => true)).rejects.toThrow("differs from the retained claim");
    expect(attempt.snapshot()?.hold?.reservation_id).toBe(RESERVATION_ID);
    await expect(attempt.execute(() => true)).resolves.toMatchObject({ status: "settled" });
    expect(attempt.snapshot()).toBeUndefined();
  });

  it("unlocks after a validated full pre-dispatch release", async () => {
    const settled = trainingExecutionReceipt();
    const released = trainingExecutionReceipt({
      status: "released",
      actual_policy_units: "0",
      released_policy_units: "50000",
      training_result: {
        ...settled.training_result as Record<string, unknown>,
        success: false,
        outcome: "policy_denied",
        furthest_stage: "policy_checked",
        steps_completed: 0,
        checkpoint_saved: false,
        error_kind: "policy_denied",
        bounded_message: "policy_denied",
        provider_dispatch_attempted: false,
        provider_dispatch_performed: false,
      },
      settlement: {
        ...settled.settlement as Record<string, unknown>,
        status: "released",
        provider_dispatch_performed: false,
      },
    });
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(released)));
    const attempt = new TinkerTrainingAttempt();
    attempt.begin(identity(), draft, "50000");
    await expect(attempt.execute(() => true)).resolves.toMatchObject({
      status: "released",
      released_policy_units: "50000",
      training_result: { provider_dispatch_performed: false },
    });
    expect(attempt.snapshot()).toBeUndefined();
  });

  it("allows only one in-flight submission and ignores a stale successful reply", async () => {
    let complete!: (response: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => { complete = resolve; }));
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const authority = identity();
    const snapshot = attempt.begin(authority, draft, "50000");
    let current = true;
    const running = attempt.execute(() => current);
    await expect(attempt.execute(() => current)).rejects.toThrow("already in progress");
    current = false;
    complete(jsonResponse(trainingExecutionReceipt()));
    await expect(running).resolves.toBeUndefined();
    expect(attempt.snapshot()).toBe(snapshot);
    expect(attempt.matches(authority)).toBe(false);
    await expect(attempt.execute(() => true)).rejects.toThrow("missing or changed");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("drops authority on clearing while keeping the unresolved request blocked", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const attempt = new TinkerTrainingAttempt();
    const authority = identity();
    const snapshot = attempt.begin(authority, draft, "50000");
    for (const changed of [
      { ...authority, accountId: `tca_${"d".repeat(24)}` },
      { ...authority, credentialId: `tcc_${"d".repeat(24)}` },
      { ...authority, credentialToken: `${authority.credentialToken}x` },
      { ...authority, walletSession: { ...authority.walletSession } },
    ]) expect(attempt.matches(changed)).toBe(false);
    attempt.clearAuthority();
    expect(attempt.snapshot()).toBe(snapshot);
    expect(attempt.matches(authority)).toBe(false);
    await expect(attempt.execute(() => true)).rejects.toThrow("missing or changed");
    expect(() => attempt.begin(authority, draft, "50000")).toThrow("cannot be replaced");
    expect(fetchMock).not.toHaveBeenCalled();
    attempt.dispose();
    expect(attempt.snapshot()).toBeUndefined();
  });

  it("suppresses a stale failed response after the authority has been cleared", async () => {
    let fail!: (cause: unknown) => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((_resolve, reject) => { fail = reject; })));
    const attempt = new TinkerTrainingAttempt();
    const snapshot = attempt.begin(identity(), draft, "50000");
    const running = attempt.execute(() => true);
    attempt.clearAuthority();
    fail(new TypeError("Late transport error"));
    await expect(running).resolves.toBeUndefined();
    expect(attempt.snapshot()).toBe(snapshot);
  });
});

describe("Tinker credential capsule authentication", () => {
  beforeEach(() => {
    vi.setSystemTime(new Date(NOW * 1_000));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("decrypts only after authenticating device, cap, account, release, and token claims", async () => {
    const { device, receipt, token } = await capsuleFixture();

    await expect(decryptTinkerCredentialCapsule(receipt, device))
      .resolves.toBe(token);

    await expect(decryptTinkerCredentialCapsule({
      ...receipt,
      max_operation_policy_units: "1",
    }, device)).rejects.toThrow("binding does not match");

    await expect(decryptTinkerCredentialCapsule({
      ...receipt,
      gate: {
        ...receipt.gate,
        release_policy_tuple_digest: digest("d"),
      },
    }, device)).rejects.toThrow("binding does not match");

    const otherDevice = await generateTinkerDeviceKey();
    await expect(decryptTinkerCredentialCapsule(receipt, otherDevice))
      .rejects.toThrow("recipient commitment");
  });

  it("rejects token-claim extension inside an otherwise authenticated capsule", async () => {
    const { device, receipt } = await capsuleFixture({
      future_authority: "not-accepted",
    });

    await expect(decryptTinkerCredentialCapsule(receipt, device))
      .rejects.toThrow("unsupported fields");
  });
});

describe("Tinker in-memory session and replay identity", () => {
  const session: TinkerCustomerSession = {
    accessToken: walletToken(),
    address: WALLET_ADDRESS,
    issuedAt: NOW - 5,
    expiresAt: NOW + 300,
    walletAuthorizationVersion: 7,
  };

  it("invalidates on wallet, authorization-version, expiry, or future-issue drift", () => {
    expect(tinkerSessionIsCurrent(session, {
      account: WALLET_ADDRESS.toUpperCase(),
      authorizationVersion: 7,
      nowSeconds: NOW,
    })).toBe(true);
    expect(tinkerSessionIsCurrent(session, {
      account: `0x${"2".repeat(40)}`,
      authorizationVersion: 7,
      nowSeconds: NOW,
    })).toBe(false);
    expect(tinkerSessionIsCurrent(session, {
      account: WALLET_ADDRESS,
      authorizationVersion: 8,
      nowSeconds: NOW,
    })).toBe(false);
    expect(tinkerSessionIsCurrent(session, {
      account: WALLET_ADDRESS,
      authorizationVersion: 7,
      nowSeconds: session.expiresAt,
    })).toBe(false);
    expect(tinkerSessionIsCurrent({
      ...session,
      issuedAt: NOW + 1,
    }, {
      account: WALLET_ADDRESS,
      authorizationVersion: 7,
      nowSeconds: NOW,
    })).toBe(false);
  });

  it("reuses only the same unresolved idempotent request", () => {
    const attempt = new TinkerIdempotencyAttempt();
    const first = attempt.keyFor("credential", `${ACCOUNT_ID}:900:${HUGE_CAP}`);

    expect(attempt.keyFor("credential", `${ACCOUNT_ID}:900:${HUGE_CAP}`))
      .toBe(first);
    const changed = attempt.keyFor(
      "credential",
      `${ACCOUNT_ID}:600:${HUGE_CAP}`,
    );
    expect(changed).not.toBe(first);
    attempt.resolve(changed);
    expect(attempt.keyFor("credential", `${ACCOUNT_ID}:600:${HUGE_CAP}`))
      .not.toBe(changed);
  });
});
