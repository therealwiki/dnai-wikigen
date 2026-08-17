import { describe, expect, it, vi } from "vitest";
import type { Address, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  ExecutionPolicyAnchorObservation,
  RollbackAnchorStatus,
} from "./executionPolicyAnchor";
import {
  executionPolicyApproverHash,
  executionPolicyApproverRootHash,
  executionPolicyDecisionHash,
  executionPolicyEvaluationIdempotencyKey,
  executionPolicySignatureHash,
  parsePolicyBundleText,
  recoverExecutionPolicyWorkflow,
  runExecutionPolicyWorkflow,
  ExecutionPolicyIntentExpiredError,
  ExecutionPolicyRecoveryMismatchError,
  type ExecutionPolicyRecord,
  type ExecutionPolicySurface,
  type PolicyBundle,
  type PreparedExecutionPolicyIntent,
} from "./policy";
import {
  POLICY_CANONICALIZATION_VERSION,
  computePolicyCommitments,
  pythonCanonicalJson,
  type PolicyCommitments,
} from "./policyCommitments";

const ACCOUNT = privateKeyToAccount(`0x${"11".repeat(32)}`);
const ADDRESS = ACCOUNT.address as Address;
const APPROVAL_DOMAIN_HASH = "d".repeat(64);
const APPROVER_HASH = "1009bba2b1502c323821da8e7f99ff40220369300267bd3e32c446546049305a";
const APPROVER_ROOT_HASH = "148ff2e8c6ff55a87af7eedb890ca63d17bd212121cba04604c5b040cf65fa92";
const ANCHOR_ADDRESS = "0xa00000000000000000000000000000000000000a" as Address;
const ANCHOR_WRITER = "0xb00000000000000000000000000000000000000b" as Address;
const ANCHOR_CODE_HASH = `0x${"c".repeat(64)}` as Hex;
const ANCHOR_RELEASE_COMMITMENT = `0x${"e".repeat(64)}` as Hex;
const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Hex;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const ANCHOR_RELEASE = {
  address: ANCHOR_ADDRESS,
  runtimeCodeHash: ANCHOR_CODE_HASH,
  writer: ANCHOR_WRITER,
  writerReleaseCommitment: ANCHOR_RELEASE_COMMITMENT,
  confirmations: 12,
  maxBlockAgeSeconds: 300,
  maxFutureBlockSkewSeconds: 30,
} as const;
const POLICY_TRUST = {
  approvalDomainHash: APPROVAL_DOMAIN_HASH,
  approverRootHash: APPROVER_ROOT_HASH,
  approvedApproverHashes: [APPROVER_HASH] as const,
  anchorRelease: ANCHOR_RELEASE,
  anchorObserver: async (status: RollbackAnchorStatus): Promise<ExecutionPolicyAnchorObservation> => ({
    chainId: 84_532,
    latestBlockNumber: status.block_number + 11,
    rpcFinalizedBlockNumber: status.rpc_finalized_block_number,
    reportedFinalizedBlockHash: status.rpc_finalized_block_hash,
    blockNumber: status.block_number,
    blockHash: status.block_hash,
    blockTimestamp: status.block_timestamp,
    runtimeCodeHash: status.runtime_code_hash,
    writer: status.writer,
    writerReleaseCommitment: status.writer_release_commitment,
    pendingWriter: ZERO_ADDRESS,
    pendingWriterReleaseCommitment: ZERO_BYTES32,
    pendingWriterActivatesAt: 0,
    writerRotationsFrozen: true,
    paused: false,
    globalSequence: status.global_sequence,
    globalHead: status.global_head,
    resourceDecisionHead: status.resource_decision_head,
    resourceSequence: status.resource_sequence,
    decisionSequence: status.decision_sequence,
  }),
};
const encoder = new TextEncoder();

const bundle: PolicyBundle = {
  request: {
    request_id: "request-private-7",
    requester_ref: "agent-private-7",
    purpose: "rank-candidates",
    pipeline: "bounded-rerank-v1",
    data_classes: ["assay-summary"],
    output_schema: "score-band-v1",
    operations: ["score"],
    risk_tags: [],
  },
  policy: {
    policy_id: "private-corpus-policy-v1",
    version: "policy-kernel/v1",
    corpus_ref: "corpus://private-atlas",
    allowed_purposes: ["rank-candidates"],
    denied_purposes: [],
    allowed_pipelines: ["bounded-rerank-v1"],
    allowed_output_schemas: ["score-band-v1"],
    allowed_operations: ["score"],
    known_data_classes: ["assay-summary"],
    restricted_categories: [],
    hold_categories: [],
    ambiguous_categories: [],
    hold_routes: {},
  },
};

const holdBundle: PolicyBundle = {
  request: { ...bundle.request, data_classes: ["clinical-summary"] },
  policy: {
    ...bundle.policy,
    known_data_classes: ["assay-summary", "clinical-summary"],
    hold_categories: ["clinical-summary"],
    hold_routes: { "clinical-summary": "expert-in-the-loop" },
  },
};

function hash(character: string): string {
  return character.repeat(64);
}

function rollbackAnchor(resourceHash: string, decisionHash = "", sequence = 0): RollbackAnchorStatus {
  return {
    schema: "dnai-wikigen/execution-policy-anchor-status/v1" as const,
    status: "rpc_reported_finalized_release_match" as const,
    verification_model: "single_rpc_reported_finalized_with_confirmation_depth" as const,
    chain_id: 84_532 as const,
    latest_block_number: 12_356,
    rpc_finalized_block_number: 12_345,
    rpc_finalized_block_hash: `0x${"b".repeat(64)}` as Hex,
    minimum_confirmation_depth: 12,
    observed_confirmation_depth: 12,
    block_number: 12_345,
    block_hash: `0x${"b".repeat(64)}` as const,
    block_timestamp: Math.floor(Date.now() / 1_000),
    contract_address: ANCHOR_ADDRESS,
    runtime_code_hash: ANCHOR_CODE_HASH,
    writer: ANCHOR_WRITER,
    writer_release_commitment: ANCHOR_RELEASE_COMMITMENT,
    writer_rotations_frozen: true as const,
    paused: false as const,
    global_sequence: sequence,
    global_head: sequence === 0 ? ZERO_BYTES32 : `0x${"a".repeat(64)}` as Hex,
    resource_id_hash: resourceHash,
    resource_decision_head: decisionHash ? `0x${decisionHash}` as Hex : ZERO_BYTES32,
    resource_sequence: sequence,
    decision_hash: decisionHash,
    decision_sequence: sequence,
    opaque_commitments_only: true as const,
    independent_rpc_quorum_verified: false as const,
    consensus_proof_verified: false as const,
    raw_resource_id_egress: false as const,
    raw_policy_egress: false as const,
  };
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function policyRecord(
  commitments: PolicyCommitments,
  surface: ExecutionPolicySurface,
  expiresAt: number,
  signature: string,
  executionContextHash: string,
): Promise<ExecutionPolicyRecord> {
  const { local_evaluation: local } = commitments;
  const record: ExecutionPolicyRecord = {
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    sequence: 1,
    surface,
    resource_id_hash: commitments.resource_id_hash,
    decision: local.decision,
    reason_code: local.reason_code,
    request_hash: commitments.request_hash,
    policy_hash: commitments.policy_hash,
    execution_context_hash: executionContextHash,
    recorded_at: Math.min(Math.floor(Date.now() / 1000), expiresAt - 1),
    expires_at: expiresAt,
    approver_hash: local.decision === "pass" ? await executionPolicyApproverHash(ADDRESS) : "",
    approval_hash: local.decision === "pass" ? await executionPolicySignatureHash(signature) : "",
    approval_domain_hash: local.decision === "pass" ? APPROVAL_DOMAIN_HASH : "",
    approver_root_hash: local.decision === "pass" ? APPROVER_ROOT_HASH : "",
    previous_decision_hash: "0".repeat(64),
    decision_hash: "0".repeat(64),
    raw_policy_egress: false,
    raw_resource_id_egress: false,
    rollback_anchor: rollbackAnchor(commitments.resource_id_hash),
  };
  record.decision_hash = await executionPolicyDecisionHash(record);
  record.rollback_anchor = rollbackAnchor(record.resource_id_hash, record.decision_hash, record.sequence);
  return record;
}

async function policyResponses(
  sourceBundle: PolicyBundle,
  surface: ExecutionPolicySurface,
  resourceId: string,
  expiresAt: number,
): Promise<{
  preflight: Record<string, unknown>;
  approval: Record<string, unknown>;
  evaluation: Record<string, unknown>;
  status: Record<string, unknown>;
  signature: string;
}> {
  const commitments = await computePolicyCommitments(sourceBundle, surface, resourceId);
  const { local_evaluation: local } = commitments;
  const executionContextHash = surface === "compute_dispatch"
    ? hash("7")
    : "0".repeat(64);
  const payload = {
    schema: "dnai-wikigen/execution-policy-approval/v3",
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    approval_domain_hash: APPROVAL_DOMAIN_HASH,
    approver_root_hash: APPROVER_ROOT_HASH,
    surface,
    resource_id_hash: commitments.resource_id_hash,
    decision: local.decision,
    request_hash: commitments.request_hash,
    policy_hash: commitments.policy_hash,
    execution_context_hash: executionContextHash,
    previous_decision_hash: "0".repeat(64),
    expires_at: expiresAt,
  };
  const approvalMessage = `DNAI Wikigen execution policy approval\n${pythonCanonicalJson(payload)}`;
  const signature = await ACCOUNT.signMessage({ message: approvalMessage });
  const record = await policyRecord(
    commitments,
    surface,
    expiresAt,
    signature,
    executionContextHash,
  );
  return {
    signature,
    preflight: {
      surface: "execution_policy_status",
      schema_version: 3,
      canonicalization_version: POLICY_CANONICALIZATION_VERSION,
      approval_domain_hash: APPROVAL_DOMAIN_HASH,
      approver_root_hash: APPROVER_ROOT_HASH,
      found: false,
      resource_id_hash: commitments.resource_id_hash,
      current_pass: false,
      raw_resource_id_egress: false,
      record: null,
      rollback_anchor: rollbackAnchor(commitments.resource_id_hash),
    },
    approval: {
      surface: "execution_policy_approval_message",
      schema_version: 3,
      canonicalization_version: POLICY_CANONICALIZATION_VERSION,
      decision: local.decision,
      request_hash: commitments.request_hash,
      policy_hash: commitments.policy_hash,
      execution_context_hash: executionContextHash,
      resource_id_hash: commitments.resource_id_hash,
      previous_decision_hash: "0".repeat(64),
      expires_at: expiresAt,
      approval_message: approvalMessage,
      approval_message_hash: await sha256(approvalMessage),
      approval_domain_hash: APPROVAL_DOMAIN_HASH,
      approver_root_hash: APPROVER_ROOT_HASH,
      raw_policy_egress: false,
      raw_resource_id_egress: false,
      rollback_anchor: rollbackAnchor(commitments.resource_id_hash),
    },
    evaluation: {
    surface: "policy_kernel",
      schema_version: 3,
      canonicalization_version: POLICY_CANONICALIZATION_VERSION,
      approval_domain_hash: APPROVAL_DOMAIN_HASH,
      approver_root_hash: APPROVER_ROOT_HASH,
      decision: local.decision,
      stage: local.stage,
      reason_code: local.reason_code,
      routed_role: local.routed_role,
      request_hash: commitments.request_hash,
      policy_hash: commitments.policy_hash,
      execution_context_hash: executionContextHash,
      purpose_hash: commitments.purpose_hash,
      pipeline_hash: commitments.pipeline_hash,
      output_schema_hash: commitments.output_schema_hash,
      corpus_ref_hash: commitments.corpus_ref_hash,
      outcomes: local.outcomes,
      raw_secret_egress: false,
      raw_policy_egress: false,
      execution_binding: record,
    },
    status: {
      surface: "execution_policy_status",
      schema_version: 3,
      canonicalization_version: POLICY_CANONICALIZATION_VERSION,
      approval_domain_hash: APPROVAL_DOMAIN_HASH,
      approver_root_hash: APPROVER_ROOT_HASH,
      found: true,
      resource_id_hash: commitments.resource_id_hash,
      current_pass: local.decision === "pass",
      raw_resource_id_egress: false,
      record,
      rollback_anchor: record.rollback_anchor,
    },
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("execution-policy bundle boundary", () => {
  it("accepts only the strict kernel request and policy shape", () => {
    expect(parsePolicyBundleText(JSON.stringify(bundle))).toEqual(bundle);

    expect(() => parsePolicyBundleText(JSON.stringify({ ...bundle, raw_artifact: "secret" })))
      .toThrow(/unsupported fields/);
    expect(() => parsePolicyBundleText(JSON.stringify({
      ...bundle,
      request: { ...bundle.request, raw_private_artifact: "secret" },
    }))).toThrow(/unsupported or missing fields/);
    expect(() => parsePolicyBundleText(JSON.stringify({
      ...bundle,
      policy: { ...bundle.policy, raw_policy_text: "secret" },
    }))).toThrow(/unsupported or missing fields/);
    expect(() => parsePolicyBundleText(JSON.stringify({
      ...bundle,
      request: { ...bundle.request, data_classes: ["assay-summary", "assay-summary"] },
    }))).toThrow(/duplicate entries/);
    expect(() => parsePolicyBundleText(JSON.stringify({
      ...bundle,
      request: { ...bundle.request, requester_ref: "agent-\ud800" },
    }))).toThrow(/bounded string/);
    expect(() => parsePolicyBundleText(JSON.stringify({
      ...bundle,
      policy: { ...bundle.policy, hold_routes: { "assay-summary": "private-reviewer" } },
    }))).toThrow(/public review role/);
    const astralClasses = Array.from({ length: 64 }, (_, index) => "🧬".repeat(60) + `-${index}`);
    expect(() => parsePolicyBundleText(JSON.stringify({
      request: { ...bundle.request, data_classes: [astralClasses[0]] },
      policy: { ...bundle.policy, known_data_classes: astralClasses },
    }))).toThrow(/payload limit/);
    expect(() => parsePolicyBundleText(`{"request":"${"x".repeat(66_000)}"}`)).toThrow(/64 KiB/);
  });
});

describe("live execution-policy workflow", () => {
  it("matches the release signer-root vector and refuses an unlisted approver before transport", async () => {
    expect(await executionPolicyApproverRootHash([APPROVER_HASH])).toBe(APPROVER_ROOT_HASH);
    const outsider = privateKeyToAccount(`0x${"22".repeat(32)}`);
    const fetchMock = vi.fn(async () => jsonResponse({}));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface: "deal_evaluation",
      resourceId: "deal-outsider-7",
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      bundle,
      approverAddress: outsider.address,
      personalSign: async (message) => outsider.signMessage({ message }),
    })).rejects.toThrow(/immutable signer set/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires personal_sign for PASS and returns only bounded hashes and records", async () => {
    const surface = "arena_execution" as const;
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const resourceId = "private-submission-7";
    const { preflight, approval, evaluation, status, signature } = await policyResponses(bundle, surface, resourceId, expiresAt);
    const responses = [preflight, approval, evaluation, status];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(responses.shift()));
    const personalSign = vi.fn(async () => signature);
    const runtimeBearer = "private-runtime-bearer-7";

    const result = await runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer,
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    });

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(personalSign).toHaveBeenCalledOnce();
    expect(personalSign).toHaveBeenCalledWith(approval.approval_message);
    expect(String(fetchMock.mock.calls[0][0])).toBe("https://delegate.example/policy/status");
    expect(String(fetchMock.mock.calls[1][0])).toBe("https://delegate.example/policy/approval-message");
    expect(String(fetchMock.mock.calls[2][0])).toBe("https://delegate.example/policy/evaluate");
    expect(String(fetchMock.mock.calls[3][0])).toBe("https://delegate.example/policy/status");

    const approvalInit = fetchMock.mock.calls[1][1] as RequestInit;
    const evaluationInit = fetchMock.mock.calls[2][1] as RequestInit;
    const statusInit = fetchMock.mock.calls[3][1] as RequestInit;
    expect(approvalInit.credentials).toBe("omit");
    expect(approvalInit.headers).toMatchObject({ Authorization: `Bearer ${runtimeBearer}` });
    expect(JSON.parse(String(evaluationInit.body))).toMatchObject({
      approver_address: ADDRESS,
      approval_signature: signature,
      previous_decision_hash: "0".repeat(64),
    });
    expect(JSON.parse(String(statusInit.body))).toEqual({ surface, resource_id: resourceId });

    const rendered = JSON.stringify(result);
    for (const privateValue of [
      resourceId,
      runtimeBearer,
      signature,
      String(approval.approval_message),
      String(bundle.policy.corpus_ref),
      String(bundle.request.requester_ref),
    ]) expect(rendered).not.toContain(privateValue);
    expect(result.approval.approval_domain_hash).toBe(APPROVAL_DOMAIN_HASH);
    expect(result.status.current_pass).toBe(true);
    expect(result.status.record?.approver_root_hash).toBe(APPROVER_ROOT_HASH);
    expect(result.status.rollback_anchor.decision_hash).toBe(result.status.record?.decision_hash);
  });

  it("keeps execution-policy approval on the exact 65-byte EOA signature path", async () => {
    const surface = "arena_execution" as const;
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const resourceId = "private-submission-contract-signature";
    const { preflight, approval } = await policyResponses(
      bundle,
      surface,
      resourceId,
      expiresAt,
    );
    const responses = [preflight, approval];
    const fetchMock = vi.fn(async () => jsonResponse(responses.shift()));

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "private-runtime-bearer-7",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => `0x${"ab".repeat(66)}`,
    })).rejects.toThrow(/invalid personal_sign signature/);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("stops before persistence when the operator rejects the PASS signature", async () => {
    const surface = "deal_evaluation" as const;
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const bounded = await policyResponses(bundle, surface, "deal-7", expiresAt);
    const responses = [bounded.preflight, bounded.approval];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(responses.shift()));
    const personalSign = vi.fn(async () => { throw new Error("Operator rejected signature"); });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId: "deal-7",
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/Operator rejected signature/);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(personalSign).toHaveBeenCalledOnce();
  });

  it("refuses release-domain or browser-computed commitment drift before asking the wallet to sign", async () => {
    const surface = "arena_execution" as const;
    const resourceId = "submission-drift-7";
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    const personalSign = vi.fn(async () => bounded.signature);
    const wrongDomainResponses = [bounded.preflight, {
      ...bounded.approval,
      approval_domain_hash: hash("c"),
    }];
    const wrongDomainFetch = vi.fn(async () => jsonResponse(wrongDomainResponses.shift()));

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: wrongDomainFetch as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/release-pinned deployment/);
    expect(personalSign).not.toHaveBeenCalled();

    const wrongRootFetch = vi.fn(async () => jsonResponse({
      ...bounded.preflight,
      approver_root_hash: hash("e"),
    }));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: wrongRootFetch as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/approver root drifted/);
    expect(personalSign).not.toHaveBeenCalled();

    const wrongCommitmentResponses = [bounded.preflight, {
      ...bounded.approval,
      request_hash: hash("a"),
    }];
    const wrongCommitmentFetch = vi.fn(async () => jsonResponse(wrongCommitmentResponses.shift()));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: wrongCommitmentFetch as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/browser evaluation/);
    expect(personalSign).not.toHaveBeenCalled();

    const wrongContextResponses = [bounded.preflight, {
      ...bounded.approval,
      execution_context_hash: hash("9"),
    }];
    const wrongContextFetch = vi.fn(async () => jsonResponse(wrongContextResponses.shift()));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: wrongContextFetch as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/browser evaluation/);
    expect(personalSign).not.toHaveBeenCalled();
  });

  it("requires an authoritative context before any Compute policy transport", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({}));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface: "compute_dispatch",
      resourceId: "compute-job-context-required",
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async (message) => ACCOUNT.signMessage({ message }),
    })).rejects.toThrow(/context hash/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a delegate evaluation that changes after a valid wallet approval", async () => {
    const surface = "deal_evaluation" as const;
    const resourceId = "deal-drift-8";
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    const responses = [
      bounded.preflight,
      bounded.approval,
      { ...bounded.evaluation, reason_code: "unsupported_operation" },
    ];
    const fetchMock = vi.fn(async () => jsonResponse(responses.shift()));
    const personalSign = vi.fn(async () => bounded.signature);

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign,
    })).rejects.toThrow(/browser's deterministic evaluation/);
    expect(personalSign).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("persists HOLD without a signature while still requiring a connected wallet boundary", async () => {
    const surface = "compute_dispatch" as const;
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const resourceId = "compute-job-7";
    const bounded = await policyResponses(holdBundle, surface, resourceId, expiresAt);
    const responses = [bounded.preflight, bounded.approval, bounded.evaluation, bounded.status];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(responses.shift()));
    const personalSign = vi.fn(async () => bounded.signature);

    const result = await runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      executionContextHash: hash("7"),
      expiresAt,
      bundle: holdBundle,
      approverAddress: ADDRESS,
      personalSign,
    });

    expect(personalSign).not.toHaveBeenCalled();
    expect(JSON.parse(String((fetchMock.mock.calls[2][1] as RequestInit).body))).toMatchObject({
      approver_address: "",
      approval_signature: "",
    });
    expect(result.approval.wallet_signature_required).toBe(false);
    expect(result.status.current_pass).toBe(false);
    expect(result.evaluation.execution_binding.approval_domain_hash).toBe("");
    expect(result.evaluation.execution_binding.approver_root_hash).toBe("");
  });

  it("fails closed on unbounded delegate fields and missing live prerequisites", async () => {
    const surface = "deal_evaluation" as const;
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const bounded = await policyResponses(bundle, surface, "deal-7", expiresAt);
    const malformedApproval = {
      ...bounded.approval,
      raw_policy: bundle.policy,
    };
    const malformedResponses = [bounded.preflight, malformedApproval];
    const malformedFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(malformedResponses.shift()));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: malformedFetch as typeof fetch,
      surface,
      resourceId: "deal-7",
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
    })).rejects.toThrow(/unsupported fields/);

    const neverFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({}));
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: neverFetch as typeof fetch,
      surface,
      resourceId: "deal-7",
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
    })).rejects.toThrow(/not configured/);
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime bearer with spaces",
      ...POLICY_TRUST,
      fetchImpl: neverFetch as typeof fetch,
      surface,
      resourceId: "deal-7",
      expiresAt,
      bundle,
      approverAddress: "",
      personalSign: async () => bounded.signature,
    })).rejects.toThrow(/Connect an EIP-1193 wallet/);
    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      approvalDomainHash: "",
      fetchImpl: neverFetch as typeof fetch,
      surface,
      resourceId: "deal-7",
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
    })).rejects.toThrow(/Release-pinned/);
    expect(neverFetch).not.toHaveBeenCalled();
  });

  it("derives and submits one domain-separated idempotency commitment from the signed approval", async () => {
    const surface = "arena_execution" as const;
    const resourceId = "private-submission-idempotency";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    const responses = [bounded.preflight, bounded.approval, bounded.evaluation, bounded.status];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => (
      jsonResponse(responses.shift())
    ));
    let prepared: PreparedExecutionPolicyIntent | undefined;

    await runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    });

    expect(prepared).toBeDefined();
    const expected = await executionPolicyEvaluationIdempotencyKey(
      String(bounded.approval.approval_message_hash),
    );
    expect(expected).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(prepared?.evaluationIdempotencyKey).toBe(expected);
    expect(JSON.parse(String((fetchMock.mock.calls[2][1] as RequestInit).body))).toMatchObject({
      idempotency_key: expected,
      expires_at: expiresAt,
      previous_decision_hash: "0".repeat(64),
      approval_signature: bounded.signature,
    });
    for (const [, init] of fetchMock.mock.calls) {
      expect(init).toMatchObject({
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    }
  });

  it("recovers a committed decision from status after the mutation response is lost without appending twice", async () => {
    const surface = "arena_execution" as const;
    const resourceId = "private-submission-committed-response-lost";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    let statusReads = 0;
    let evaluationCalls = 0;
    let prepared: PreparedExecutionPolicyIntent | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/policy/status") {
        statusReads += 1;
        return jsonResponse(statusReads === 1 ? bounded.preflight : bounded.status);
      }
      if (path === "/policy/approval-message") return jsonResponse(bounded.approval);
      if (path === "/policy/evaluate") {
        evaluationCalls += 1;
        throw new Error("connection reset after commit");
      }
      throw new Error(`unexpected policy path ${path}`);
    });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    })).rejects.toThrow(/connection reset after commit/);

    expect(prepared).toBeDefined();
    const recovered = await recoverExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      approverAddress: ADDRESS,
      intent: prepared!,
    });

    expect(evaluationCalls).toBe(1);
    expect(statusReads).toBe(2);
    expect(recovered.status.record?.decision_hash)
      .toBe(bounded.status.record && (bounded.status.record as ExecutionPolicyRecord).decision_hash);
    expect(recovered.evaluation.execution_binding.sequence).toBe(1);
  });

  it("replays byte-identical evaluate bytes only when status still proves the exact prior head", async () => {
    const surface = "deal_evaluation" as const;
    const resourceId = "deal-exact-replay";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    let statusReads = 0;
    let evaluationCalls = 0;
    const evaluationBodies: string[] = [];
    let prepared: PreparedExecutionPolicyIntent | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      if (path === "/policy/status") {
        statusReads += 1;
        return jsonResponse(statusReads < 3 ? bounded.preflight : bounded.status);
      }
      if (path === "/policy/approval-message") return jsonResponse(bounded.approval);
      if (path === "/policy/evaluate") {
        evaluationCalls += 1;
        evaluationBodies.push(String(init?.body));
        if (evaluationCalls === 1) throw new Error("connection closed before commit");
        return jsonResponse(bounded.evaluation);
      }
      throw new Error(`unexpected policy path ${path}`);
    });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    })).rejects.toThrow(/connection closed before commit/);

    const recovered = await recoverExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      approverAddress: ADDRESS,
      intent: prepared!,
    });

    expect(statusReads).toBe(3);
    expect(evaluationCalls).toBe(2);
    expect(evaluationBodies[1]).toBe(evaluationBodies[0]);
    expect(JSON.parse(evaluationBodies[1])).toMatchObject({
      idempotency_key: prepared?.evaluationIdempotencyKey,
      expires_at: prepared?.expiresAt,
      previous_decision_hash: prepared?.approval.previous_decision_hash,
      approval_signature: prepared?.approvalSignature,
    });
    expect(recovered.status.record?.decision_hash)
      .toBe((bounded.status.record as ExecutionPolicyRecord).decision_hash);
  });

  it("refuses recovery when current status is neither the retained decision nor its exact prior head", async () => {
    const surface = "arena_execution" as const;
    const resourceId = "private-submission-head-drift";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    const conflicting = await policyResponses(holdBundle, surface, resourceId, expiresAt);
    let statusReads = 0;
    let evaluationCalls = 0;
    let prepared: PreparedExecutionPolicyIntent | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/policy/status") {
        statusReads += 1;
        return jsonResponse(statusReads === 1 ? bounded.preflight : conflicting.status);
      }
      if (path === "/policy/approval-message") return jsonResponse(bounded.approval);
      if (path === "/policy/evaluate") {
        evaluationCalls += 1;
        throw new Error("ambiguous mutation");
      }
      throw new Error(`unexpected policy path ${path}`);
    });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    })).rejects.toThrow(/ambiguous mutation/);

    await expect(recoverExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      approverAddress: ADDRESS,
      intent: prepared!,
    })).rejects.toBeInstanceOf(ExecutionPolicyRecoveryMismatchError);
    expect(statusReads).toBe(2);
    expect(evaluationCalls).toBe(1);
  });

  it("keeps pending-anchor and expired recoveries read-only", async () => {
    const surface = "deal_evaluation" as const;
    const resourceId = "deal-pending-or-expired";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    let statusReads = 0;
    let evaluationCalls = 0;
    let prepared: PreparedExecutionPolicyIntent | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/policy/status") {
        statusReads += 1;
        if (statusReads === 1) return jsonResponse(bounded.preflight);
        if (statusReads === 2) return jsonResponse({}, 503);
        return jsonResponse(bounded.preflight);
      }
      if (path === "/policy/approval-message") return jsonResponse(bounded.approval);
      if (path === "/policy/evaluate") {
        evaluationCalls += 1;
        throw new Error("ambiguous mutation");
      }
      throw new Error(`unexpected policy path ${path}`);
    });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    })).rejects.toThrow(/ambiguous mutation/);

    const recoveryInput = {
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: fetchMock as typeof fetch,
      approverAddress: ADDRESS,
      intent: prepared!,
    };
    await expect(recoverExecutionPolicyWorkflow(recoveryInput))
      .rejects.toThrow(/trust roots are unavailable/);
    expect(evaluationCalls).toBe(1);

    await expect(recoverExecutionPolicyWorkflow({
      ...recoveryInput,
      now: expiresAt,
    })).rejects.toBeInstanceOf(ExecutionPolicyIntentExpiredError);
    expect(statusReads).toBe(3);
    expect(evaluationCalls).toBe(1);
  });

  it("rejects a conflicting retained idempotency key before any recovery transport", async () => {
    const surface = "deal_evaluation" as const;
    const resourceId = "deal-conflicting-idempotency";
    const expiresAt = Math.floor(Date.now() / 1_000) + 600;
    const bounded = await policyResponses(bundle, surface, resourceId, expiresAt);
    const initialResponses = [bounded.preflight, bounded.approval];
    let prepared: PreparedExecutionPolicyIntent | undefined;
    const initialFetch = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/policy/evaluate") throw new Error("ambiguous mutation");
      return jsonResponse(initialResponses.shift());
    });

    await expect(runExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: initialFetch as typeof fetch,
      surface,
      resourceId,
      expiresAt,
      bundle,
      approverAddress: ADDRESS,
      personalSign: async () => bounded.signature,
      onPreparedIntent: (intent) => { prepared = intent; },
    })).rejects.toThrow(/ambiguous mutation/);

    const neverFetch = vi.fn(async () => jsonResponse({}));
    const conflictingIntent = {
      ...prepared!,
      evaluationIdempotencyKey: `sha256:${"f".repeat(64)}`,
    } as PreparedExecutionPolicyIntent;
    await expect(recoverExecutionPolicyWorkflow({
      delegateUrl: "https://delegate.example",
      runtimeBearer: "runtime-bearer",
      ...POLICY_TRUST,
      fetchImpl: neverFetch as typeof fetch,
      approverAddress: ADDRESS,
      intent: conflictingIntent,
    })).rejects.toBeInstanceOf(ExecutionPolicyRecoveryMismatchError);
    expect(neverFetch).not.toHaveBeenCalled();
  });
});
