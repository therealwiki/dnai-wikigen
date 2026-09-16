import { describe, expect, it, vi } from "vitest";
import { keccak256, type Address, type Hex } from "viem";
import { deployment } from "../config";
import {
  ARENA_SAFE_IR_STARTER_FILENAME,
  ARENA_QUEUE_REASONS,
  ARENA_QUEUE_STATES,
  appendArenaLeaderboardPageRows,
  appendArenaQueuePageRows,
  arenaSafeIrStarterCandidateBytes,
  arenaReleaseApprovedChallengeSetSha256,
  arenaChallengeRegistryAuthorizationSha256,
  arenaChallengeRegistryAuthorizationSnapshot,
  arenaWorkerHeartbeatBindingSha256,
  arenaWorkerPresenceMatchesRegistryPreflight as arenaWorkerMatchesRegistryAuthorization,
  arenaWorkerReleaseBindingSha256,
  arenaCandidateAad,
  arenaIdempotencyKeyHash,
  arenaProtocolIdentity,
  arenaSubmissionManifestHash,
  cancelArenaOwnerSubmission,
  candidateCommitment,
  encryptArenaCandidateBytes,
  fetchArenaLeaderboard,
  fetchArenaQueue,
  parseArenaCatalog,
  parseArenaChallengeRegistryBindings,
  parseArenaLeaderboard,
  parseArenaCiphertextErasure,
  parseArenaOwnerCancellation,
  parseArenaOwnerSubmissions,
  parseArenaQueue,
  parseArenaSubmissionResult,
  parseArenaWorkerCapability,
  readBoundedArenaResponseText,
  retryArenaCiphertextErasure,
  validateArenaSafeIrCandidateBytes,
  runArenaChallengeRegistryBrowserPreflight as verifyArenaChallengeRegistryAuthorization,
  type ArenaCandidateBinding,
  type ArenaChallengeManifest,
  type ArenaChallengeRegistryBrowserPreflight as ArenaChallengeRegistryAuthorization,
  type ArenaChallengeRegistryReader,
  type ArenaChallengeRegistryState,
  type ArenaChallengeRegistryVersionState,
  type ArenaExecutionCapability,
  type ArenaQueueReason,
  type ArenaQueueState,
  type ArenaSubmissionManifest,
} from "./arena";

const capability: ArenaExecutionCapability = {
  status: "modeled",
  isolation: "non_hardened",
  backend: "local_ast_subprocess_demo",
  warning: "Modeled only",
  hostile_code_ready: false,
  live_execution: false,
  worker_connected: false,
};

const challenge: ArenaChallengeManifest = {
  surface: "arena_challenge_manifest",
  schema_version: 1,
  challenge_id: "synthetic-bio-assay-qc",
  version: "1.0.0",
  slug: "synthetic-assay-qc-season-01",
  title: "Synthetic Assay QC",
  summary: "Bounded synthetic challenge",
  environment: "bio_assay_program_qc",
  candidate: { kind: "python_assay_qc_program", runtime: "python3.11", entrypoint: "process", max_source_bytes: 8192 },
  evaluation: {
    metric: "z_prime_factor",
    direction: "higher_is_better",
    release_mechanism: "fixed_eta_ladder",
    exact_reward_egress: false,
    ladder_policy: { step_denominator: 20, max_submissions: 32, max_improvement_steps: 20 },
  },
  data_policy: { synthetic_only: true, raw_data_egress: false },
  execution_capability: capability,
  manifest_hash: "a".repeat(64),
  product_status: "modeled",
  execution_assurance: "projection_only_no_hardened_executor",
  raw_secret_egress: false,
};

const unobservedExecutionProvenance = {
  status: "not_executed",
  outcome: null,
  runtime: "python3.11",
  runtime_policy_commitment: null,
  challenge_manifest_hash: null,
  compose_hash: null,
  app_id: null,
  os_image_hash: null,
  quote_sha256: null,
  verifier_address: null,
  verdict_digest: null,
  tee_signer_address: null,
  chain_id: null,
  challenge_registry_address: null,
  evidence_classification: "none",
  independently_verified_by_client: false,
  raw_tdx_quote_egress: false,
  exact_score_egress: false,
  exact_timing_egress: false,
} as const;

const workerReportedExecutionProvenance = {
  status: "worker_reported",
  outcome: "completed",
  runtime: "dnai-safe-ir-v1",
  runtime_policy_commitment: `sha256:${"1".repeat(64)}`,
  challenge_manifest_hash: "2".repeat(64),
  compose_hash: "3".repeat(64),
  app_id: "dnai-dnaseq-safe-ir",
  os_image_hash: "4".repeat(64),
  quote_sha256: `sha256:${"5".repeat(64)}`,
  verifier_address: `0x${"6".repeat(40)}`,
  verdict_digest: `0x${"7".repeat(64)}`,
  tee_signer_address: `0x${"8".repeat(40)}`,
  chain_id: 84532,
  challenge_registry_address: `0x${"9".repeat(40)}`,
  evidence_classification: "worker_reported_qvl_binding_not_independently_verified",
  independently_verified_by_client: false,
  raw_tdx_quote_egress: false,
  exact_score_egress: false,
  exact_timing_egress: false,
} as const;

const queueReasonForState: Readonly<Record<ArenaQueueState, ArenaQueueReason>> = {
  submitted: "caller_submitted",
  policy_screen: "policy_check_started",
  queued: "policy_passed",
  provisioning: "worker_claimed",
  public_tests: "public_tests_started",
  sealed_eval: "sealed_evaluation_started",
  review_hold: "human_review_required",
  completed: "evaluation_completed",
  failed: "execution_failed",
  withheld: "policy_withheld",
  cancelled: "caller_cancelled",
  expired: "queue_expired",
  dead_letter: "retry_exhausted",
};

function publicQueueHistory(
  states: readonly ArenaQueueState[],
): Array<{
  sequence: number;
  from_state: ArenaQueueState | null;
  to_state: ArenaQueueState;
  reason: ArenaQueueReason;
}> {
  return states.map((state, index) => ({
    sequence: index + 1,
    from_state: index === 0 ? null : states[index - 1],
    to_state: state,
    reason: queueReasonForState[state],
  }));
}

function publicQueueSubmissionFixture(
  state: ArenaQueueState = "submitted",
  queueEvents = publicQueueHistory(["submitted"]),
): Record<string, unknown> {
  return {
    surface: "arena_submission",
    schema_version: 2,
    submission_id: `sub_${"a".repeat(24)}`,
    challenge_id: challenge.challenge_id,
    challenge_version: challenge.version,
    identity: {
      wallet_address_hash: "b".repeat(64),
      project_id_hash: "c".repeat(64),
    },
    candidate_commitment: `sha256:${"d".repeat(64)}`,
    manifest: {
      schema_version: 1,
      challenge_manifest_hash: challenge.manifest_hash,
      candidate_kind: challenge.candidate.kind,
      runtime: challenge.candidate.runtime,
      entrypoint: challenge.candidate.entrypoint,
      mode: "test",
      private_size_egress: false,
    },
    state,
    queue_events: queueEvents,
    ladder_release: null,
    execution_capability: structuredClone(capability),
    execution_provenance: structuredClone(unobservedExecutionProvenance),
    product_status: "modeled",
    execution_assurance: "projection_only_no_hardened_executor",
    exact_timing_egress: false,
    encrypted_reference_public: false,
    raw_candidate_accepted: false,
    raw_secret_egress: false,
  };
}

function publicQueueFixture(submission: unknown): Record<string, unknown> {
  return {
    surface: "arena_public_queue",
    schema_version: 2,
    challenge_id: challenge.challenge_id,
    challenge_version: challenge.version,
    submission_count: 1,
    submissions: [submission],
    has_more: false,
    next_cursor: null,
    product_status: "per_row",
    execution_assurance: "per_submission_execution_provenance",
    raw_candidate_egress: false,
    exact_timing_egress: false,
    execution_capability: structuredClone(capability),
  };
}

const registryAddress = `0x${"1".repeat(40)}` as Address;
const finalizedBlockHash = `0x${"f".repeat(64)}` as Hex;
const runtimeBytecode = "0x60016000556002600055" as Hex;
const registryCodeHash = keccak256(runtimeBytecode);
const metadataHash = `0x${challenge.manifest_hash}` as Hex;
const sealedArtifactCommitment = `0x${"b".repeat(64)}` as Hex;
const evaluatorCommitment = `0x${"c".repeat(64)}` as Hex;
const releasePolicyCommitment = `0x${"d".repeat(64)}` as Hex;
const registryChallenge: ArenaChallengeRegistryState = {
  controller: `0x${"2".repeat(40)}`,
  pendingController: `0x${"0".repeat(40)}`,
  lifecycle: 1,
  createdAt: 100n,
  updatedAt: 110n,
  latestVersion: 7,
  paused: false,
  configurationFrozen: true,
};
const registryVersion: ArenaChallengeRegistryVersionState = {
  metadataURI: "ipfs://bafy-arena-manifest",
  metadataHash,
  sealedArtifactCommitment,
  evaluatorCommitment,
  releasePolicyCommitment,
  createdAt: 105n,
};
const registryBindings = JSON.stringify({
  [`${challenge.challenge_id}@${challenge.version}`]: {
    registry_challenge_id: "1",
    registry_version: 7,
    controller_address: registryChallenge.controller,
    pending_controller_address: registryChallenge.pendingController,
    lifecycle: "open",
    paused: false,
    configuration_frozen: true,
    catalog_manifest_hash: challenge.manifest_hash,
    metadata_uri: registryVersion.metadataURI,
    metadata_hash: metadataHash,
    sealed_artifact_commitment: sealedArtifactCommitment,
    evaluator_commitment: evaluatorCommitment,
    release_policy_commitment: releasePolicyCommitment,
  },
});
const approvedChallengeSetSha256 = arenaReleaseApprovedChallengeSetSha256(
  parseArenaChallengeRegistryBindings(registryBindings),
);

function registryReader(overrides: Partial<ArenaChallengeRegistryReader> = {}): ArenaChallengeRegistryReader {
  return {
    getChainId: async () => 84532,
    getFinalizedBlock: async () => ({
      number: 12_345n,
      hash: finalizedBlockHash,
      timestamp: 1_700_000_000n,
    }),
    getBytecode: async () => runtimeBytecode,
    registryPaused: async () => false,
    challengeExists: async () => true,
    getChallenge: async () => registryChallenge,
    getVersion: async () => registryVersion,
    ...overrides,
  };
}

function registryOptions(reader: ArenaChallengeRegistryReader = registryReader()) {
  return {
    reader,
    registryAddress,
    registryCodeHash,
    bindingsJson: registryBindings,
    approvedChallengeSetSha256,
  };
}

describe("Arena browser boundary", () => {
  it("matches the release-approved challenge-set cross-runtime digest vector", () => {
    const bindings = parseArenaChallengeRegistryBindings(JSON.stringify({
      "dnaseq-variant-qc-safe-ir@1.0.0": {
        registry_challenge_id: "1",
        registry_version: 7,
        controller_address: `0x${"1".repeat(40)}`,
        pending_controller_address: `0x${"0".repeat(40)}`,
        lifecycle: "open",
        paused: false,
        configuration_frozen: true,
        catalog_manifest_hash: "a".repeat(64),
        metadata_uri: "ipfs://approved-1",
        metadata_hash: `0x${"a".repeat(64)}`,
        sealed_artifact_commitment: `0x${"b".repeat(64)}`,
        evaluator_commitment: `0x${"c".repeat(64)}`,
        release_policy_commitment: `0x${"d".repeat(64)}`,
      },
    }));
    expect(arenaReleaseApprovedChallengeSetSha256(bindings)).toBe(
      "sha256:868e658d8d7eceed7993a9751ed65ed94806ea8434c985b1f24e13ab2c686780",
    );
  });

  it("streams bounded JSON text and cancels before an oversized body is parsed", async () => {
    const encoded = new TextEncoder();
    let overflowCancelled = false;
    const overflow = new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoded.encode("123456"));
        controller.enqueue(encoded.encode("789012"));
      },
      cancel() { overflowCancelled = true; },
    }));
    await expect(readBoundedArenaResponseText(overflow, 10)).rejects.toThrow(/size limit/);
    expect(overflowCancelled).toBe(true);

    let declaredCancelled = false;
    const declared = new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(encoded.encode("{}")); },
      cancel() { declaredCancelled = true; },
    }), { headers: { "Content-Length": "999" } });
    await expect(readBoundedArenaResponseText(declared, 10)).rejects.toThrow(/size limit/);
    expect(declaredCancelled).toBe(true);

    const valid = new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoded.encode('{"ok":'));
        controller.enqueue(encoded.encode("true}"));
        controller.close();
      },
    }));
    await expect(readBoundedArenaResponseText(valid, 32)).resolves.toBe('{"ok":true}');
  });

  it("uses a bounded iterative scan for forbidden public fields", () => {
    let nested: Record<string, unknown> = {};
    for (let index = 0; index < 70; index += 1) nested = { nested };
    expect(() => parseArenaCatalog({
      surface: "arena_challenge_catalog",
      schema_version: 1,
      challenge_count: 1,
      challenges: [challenge],
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      raw_secret_egress: false,
      extra: nested,
    })).toThrow(/nesting limit/);

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => parseArenaCatalog(cyclic)).toThrow(/reference cycle/);
  });

  it("computes the SHA-256 commitment required by the Arena API", async () => {
    await expect(candidateCommitment(new TextEncoder().encode("abc"))).resolves.toBe(
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("accepts the explicitly modeled challenge catalog", () => {
    const parsed = parseArenaCatalog({
      surface: "arena_challenge_catalog",
      schema_version: 1,
      challenge_count: 1,
      challenges: [challenge],
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      raw_secret_egress: false,
    });
    expect(parsed.challenges[0].candidate.max_source_bytes).toBe(8192);
  });

  it("rejects a backend that upgrades modeled execution to a live claim", () => {
    expect(() => parseArenaCatalog({
      surface: "arena_challenge_catalog",
      schema_version: 1,
      challenge_count: 1,
      challenges: [{ ...challenge, execution_capability: { ...capability, live_execution: true } }],
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      raw_secret_egress: false,
    })).toThrow(/unsupported execution-assurance claim/);
  });

  it("rejects forbidden data in a public leaderboard projection", () => {
    expect(() => parseArenaLeaderboard({
      surface: "arena_public_leaderboard",
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      row_count: 1,
      rows: [{ wallet_address: "0x" + "1".repeat(40) }],
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      raw_candidate_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      encrypted_reference_egress: false,
      execution_capability: capability,
    })).toThrow(/forbidden field wallet_address/);
  });

  it("accepts only timing-free Arena queue and leaderboard projections", async () => {
    const queue = {
      surface: "arena_public_queue",
      schema_version: 2,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      submission_count: 0,
      submissions: [],
      product_status: "per_row",
      execution_assurance: "per_submission_execution_provenance",
      raw_candidate_egress: false,
      exact_timing_egress: false,
      execution_capability: capability,
    } as const;
    const board = {
      surface: "arena_public_leaderboard",
      schema_version: 2,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      challenge_manifest_hash: challenge.manifest_hash,
      release_mechanism: "fixed_eta_ladder_accepted_improvements_only",
      step_denominator: 20,
      row_count: 0,
      rows: [],
      product_status: "per_row",
      execution_assurance: "per_submission_execution_provenance",
      raw_candidate_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      encrypted_reference_egress: false,
      execution_capability: capability,
    } as const;

    expect(parseArenaQueue(queue)).toMatchObject({
      submissions: [],
      has_more: false,
      next_cursor: null,
    });
    expect(parseArenaLeaderboard(board)).toMatchObject({
      rows: [],
      has_more: false,
      next_cursor: null,
    });
    expect(parseArenaQueue({ ...queue, has_more: false, next_cursor: null })).toMatchObject({
      has_more: false,
      next_cursor: null,
    });
    expect(parseArenaLeaderboard({ ...board, has_more: false, next_cursor: null })).toMatchObject({
      has_more: false,
      next_cursor: null,
    });
    expect(() => parseArenaQueue({ ...queue, has_more: false })).toThrow(/incomplete pagination boundary/);
    expect(() => parseArenaLeaderboard({ ...board, next_cursor: null })).toThrow(/incomplete pagination boundary/);
    expect(() => parseArenaQueue({ ...queue, has_more: true, next_cursor: null })).toThrow(/contradictory pagination boundary/);
    expect(() => parseArenaLeaderboard({
      ...board,
      has_more: true,
      next_cursor: "arena_page_v1.invalid cursor",
    })).toThrow(/malformed opaque cursor/);
    expect(() => parseArenaLeaderboard({
      ...board,
      has_more: true,
      next_cursor: `arena_page_v1.${"a".repeat(512)}`,
    })).toThrow(/malformed opaque cursor/);
    await expect(fetchArenaQueue(challenge.challenge_id, challenge.version, {
      cursor: "arena cursor with spaces",
    })).rejects.toThrow(/cursor is malformed/);
    await expect(fetchArenaLeaderboard(challenge.challenge_id, challenge.version, {
      limit: 101,
    })).rejects.toThrow(/page limit is invalid/);
    for (const key of ["created_at", "updated_at", "occurred_at", "ladder_released_at"] as const) {
      expect(() => parseArenaQueue({ ...queue, submissions: [{ [key]: 123 }], submission_count: 1 })).toThrow(new RegExp(`forbidden field ${key}`));
      expect(() => parseArenaLeaderboard({ ...board, rows: [{ [key]: 123 }], row_count: 1 })).toThrow(new RegExp(`forbidden field ${key}`));
    }
  });

  it("fail-closes the public queue state, event, reason, and transition vocabulary", () => {
    expect(ARENA_QUEUE_STATES).toEqual([
      "submitted",
      "policy_screen",
      "queued",
      "provisioning",
      "public_tests",
      "sealed_eval",
      "review_hold",
      "completed",
      "failed",
      "withheld",
      "cancelled",
      "expired",
      "dead_letter",
    ]);
    expect(ARENA_QUEUE_REASONS).toEqual([
      "caller_submitted",
      "policy_check_started",
      "policy_passed",
      "worker_claimed",
      "public_tests_started",
      "sealed_evaluation_started",
      "human_review_required",
      "evaluation_completed",
      "execution_failed",
      "policy_withheld",
      "caller_cancelled",
      "queue_expired",
      "retry_exhausted",
    ]);

    expect(parseArenaQueue(publicQueueFixture(
      publicQueueSubmissionFixture(),
    )).submissions[0].state).toBe("submitted");

    expect(() => parseArenaQueue(publicQueueFixture({
      ...publicQueueSubmissionFixture(),
      state: "future_scheduler_state",
    }))).toThrow(/bounded schema checks/);
    expect(() => parseArenaQueue(publicQueueFixture({
      ...publicQueueSubmissionFixture(),
      queue_events: [{
        sequence: 1,
        from_state: null,
        to_state: "future_scheduler_state",
        reason: "caller_submitted",
      }],
    }))).toThrow(/queue history is malformed/);
    expect(() => parseArenaQueue(publicQueueFixture({
      ...publicQueueSubmissionFixture(),
      queue_events: [{
        sequence: 1,
        from_state: null,
        to_state: "submitted",
        reason: "submission_received",
      }],
    }))).toThrow(/queue history is malformed/);
    expect(() => parseArenaQueue(publicQueueFixture(
      publicQueueSubmissionFixture(
        "queued",
        publicQueueHistory(["submitted", "policy_screen"]),
      ),
    ))).toThrow(/does not end at its current state/);
    expect(() => parseArenaQueue(publicQueueFixture(
      publicQueueSubmissionFixture("completed", [
        ...publicQueueHistory(["submitted"]),
        {
          sequence: 2,
          from_state: "submitted",
          to_state: "completed",
          reason: "evaluation_completed",
        },
      ]),
    ))).toThrow(/invalid transition/);
  });

  it("accepts every backend terminal queue state only through its bounded history", () => {
    const terminalPaths = {
      completed: [
        "submitted",
        "policy_screen",
        "queued",
        "provisioning",
        "public_tests",
        "sealed_eval",
        "completed",
      ],
      failed: ["submitted", "failed"],
      withheld: ["submitted", "policy_screen", "withheld"],
      cancelled: ["submitted", "cancelled"],
      expired: ["submitted", "policy_screen", "queued", "expired"],
      dead_letter: ["submitted", "policy_screen", "queued", "dead_letter"],
    } as const satisfies Readonly<
      Record<string, readonly ArenaQueueState[]>
    >;

    for (const [terminalState, path] of Object.entries(terminalPaths)) {
      const parsed = parseArenaQueue(publicQueueFixture(
        publicQueueSubmissionFixture(
          terminalState as ArenaQueueState,
          publicQueueHistory(path),
        ),
      ));
      expect(parsed.submissions[0].state).toBe(terminalState);
    }
  });

  it("binds a live leaderboard label to bounded worker-reported row evidence", () => {
    const row = {
      rank: 1,
      submission_id: `sub_${"1".repeat(24)}`,
      identity: { wallet_address_hash: "2".repeat(64), project_id_hash: "3".repeat(64) },
      candidate_commitment: `sha256:${"4".repeat(64)}`,
      leaderboard_step_index: 14,
      step_denominator: 20,
      improvement_steps_so_far: 2,
      ladder_submission_index: 3,
      execution_provenance: workerReportedExecutionProvenance,
      product_status: "live",
      execution_assurance: "worker_reported_qvl_binding_not_independently_verified",
    } as const;
    const board = {
      surface: "arena_public_leaderboard",
      schema_version: 2,
      challenge_id: "dnaseq-variant-qc-safe-ir",
      challenge_version: "1.0.0",
      challenge_manifest_hash: workerReportedExecutionProvenance.challenge_manifest_hash,
      release_mechanism: "fixed_eta_ladder_accepted_improvements_only",
      step_denominator: 20,
      row_count: 1,
      rows: [row],
      product_status: "per_row",
      execution_assurance: "per_submission_execution_provenance",
      raw_candidate_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      encrypted_reference_egress: false,
      execution_capability: capability,
    } as const;

    const firstPage = parseArenaLeaderboard({
      ...board,
      has_more: true,
      next_cursor: `arena_page_v1.${"a".repeat(96)}`,
    });
    expect(firstPage.rows[0].execution_provenance.status).toBe("worker_reported");
    expect(firstPage.rows[0].execution_provenance.independently_verified_by_client).toBe(false);
    const secondRow = {
      ...row,
      rank: 2,
      submission_id: `sub_${"2".repeat(24)}`,
      identity: { wallet_address_hash: "3".repeat(64), project_id_hash: "4".repeat(64) },
      candidate_commitment: `sha256:${"5".repeat(64)}`,
    } as const;
    const secondPage = parseArenaLeaderboard({
      ...board,
      row_count: 1,
      rows: [secondRow],
      has_more: false,
      next_cursor: null,
    });
    expect(appendArenaLeaderboardPageRows(firstPage.rows, firstPage, secondPage).map((item) => item.rank)).toEqual([1, 2]);
    expect(() => appendArenaLeaderboardPageRows(firstPage.rows, firstPage, parseArenaLeaderboard({
      ...secondPage,
      rows: [row],
    }))).toThrow(/repeated a previously loaded submission/);
    expect(() => appendArenaLeaderboardPageRows(firstPage.rows, firstPage, parseArenaLeaderboard({
      ...secondPage,
      rows: [{ ...secondRow, rank: 3 }],
    }))).toThrow(/global rank continuity/);
    expect(() => appendArenaLeaderboardPageRows(firstPage.rows, firstPage, parseArenaLeaderboard({
      ...secondPage,
      challenge_id: "other-challenge",
    }))).toThrow(/crossed its surface or challenge-version boundary/);
    expect(() => parseArenaLeaderboard({
      ...board,
      rows: [{ ...row, execution_provenance: { ...workerReportedExecutionProvenance, independently_verified_by_client: true } }],
    })).toThrow(/bounded evidence boundary/);
    expect(() => parseArenaLeaderboard({
      ...board,
      rows: [{ ...row, execution_provenance: unobservedExecutionProvenance }],
    })).toThrow(/upgraded a row without execution evidence/);
  });

  it("accepts only the bounded wallet-owner page and rejects sealed or timing fields", () => {
    const ownerSubmission = {
      surface: "arena_owner_submission",
      schema_version: 3,
      submission_id: `sub_${"1".repeat(24)}`,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      identity: { wallet_address_hash: "2".repeat(64), project_id_hash: "3".repeat(64) },
      candidate_commitment: `sha256:${"4".repeat(64)}`,
      manifest: {
        schema_version: 1,
        challenge_manifest_hash: challenge.manifest_hash,
        candidate_kind: challenge.candidate.kind,
        runtime: challenge.candidate.runtime,
        entrypoint: challenge.candidate.entrypoint,
        mode: "leaderboard",
        private_size_egress: false,
      },
      state: "queued",
      bounded_result: null,
      execution_capability: capability,
      execution_provenance: unobservedExecutionProvenance,
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      ciphertext_lifecycle: {
        state: "retained",
        retention_policy: "terminal_immediate_unlink_with_bounded_retry",
        max_terminal_retention_seconds: 3600,
        unlink_attempts: 0,
        current_state_evidence: "none",
        retryable: false,
        receipt: {
          blob_sha256: `sha256:${"5".repeat(64)}`,
          ciphertext_sha256: `sha256:${"6".repeat(64)}`,
          key_id: `sha256:${"7".repeat(64)}`,
        },
        ciphertext_egress: false,
        sealed_reference_egress: false,
        physical_erasure_claimed: false,
      },
      owner_actions: {
        can_cancel: true,
        can_retry_ciphertext_erasure: false,
      },
      raw_candidate_egress: false,
      encrypted_reference_egress: false,
      exact_score_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      internal_error_egress: false,
    } as const;
    const page = {
      surface: "arena_owner_submissions",
      schema_version: 3,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      owner_identity: "2".repeat(64),
      page_count: 1,
      submissions: [ownerSubmission],
      has_more: false,
      next_cursor: null,
      scope: "authenticated_wallet_challenge_version",
      product_status: "per_row",
      execution_assurance: "per_submission_execution_provenance",
      raw_candidate_egress: false,
      encrypted_reference_egress: false,
      exact_score_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      internal_error_egress: false,
    } as const;

    expect(parseArenaOwnerSubmissions(page).submissions[0].state).toBe("queued");
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{ ...ownerSubmission, encrypted_reference: "sealed://private/object" }],
    })).toThrow(/forbidden field encrypted_reference/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{ ...ownerSubmission, created_at: 123 }],
    })).toThrow(/forbidden field created_at/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      has_more: true,
      next_cursor: null,
    })).toThrow(/bounded schema/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{ ...ownerSubmission, challenge_id: "other" }],
    })).toThrow(/bounded schema/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{
        ...ownerSubmission,
        ciphertext_lifecycle: {
          ...ownerSubmission.ciphertext_lifecycle,
          physical_erasure_claimed: true,
        },
      }],
    })).toThrow(/bounded schema/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{
        ...ownerSubmission,
        ciphertext_lifecycle: {
          ...ownerSubmission.ciphertext_lifecycle,
          state: "erasure_retry_required",
          unlink_attempts: 1,
          current_state_evidence: "unlink_failed",
          retryable: true,
        },
      }],
    })).toThrow(/bounded schema/);
    expect(() => parseArenaOwnerSubmissions({
      ...page,
      submissions: [{
        ...ownerSubmission,
        ciphertext_lifecycle: {
          ...ownerSubmission.ciphertext_lifecycle,
          sealed_reference: "sealed://arena/private",
        },
      }],
    })).toThrow(/fields do not match the versioned protocol/);
  });

  it("strictly parses owner cancellation and unlink retry receipts without physical-erasure claims", () => {
    const submissionId = `sub_${"1".repeat(24)}`;
    const lifecycle = {
      state: "unlinked",
      retention_policy: "terminal_immediate_unlink_with_bounded_retry",
      max_terminal_retention_seconds: 3600,
      unlink_attempts: 1,
      current_state_evidence: "directory_entry_unlinked",
      retryable: false,
      receipt: {
        blob_sha256: `sha256:${"5".repeat(64)}`,
        ciphertext_sha256: `sha256:${"6".repeat(64)}`,
        key_id: `sha256:${"7".repeat(64)}`,
      },
      ciphertext_egress: false,
      sealed_reference_egress: false,
      physical_erasure_claimed: false,
    } as const;
    const submission = {
      surface: "arena_owner_submission",
      schema_version: 3,
      submission_id: submissionId,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      identity: { wallet_address_hash: "2".repeat(64), project_id_hash: "3".repeat(64) },
      candidate_commitment: `sha256:${"4".repeat(64)}`,
      manifest: {
        schema_version: 1,
        challenge_manifest_hash: challenge.manifest_hash,
        candidate_kind: challenge.candidate.kind,
        runtime: challenge.candidate.runtime,
        entrypoint: challenge.candidate.entrypoint,
        mode: "leaderboard",
        private_size_egress: false,
      },
      state: "cancelled",
      bounded_result: null,
      execution_capability: capability,
      execution_provenance: unobservedExecutionProvenance,
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      ciphertext_lifecycle: lifecycle,
      owner_actions: {
        can_cancel: false,
        can_retry_ciphertext_erasure: false,
      },
      raw_candidate_egress: false,
      encrypted_reference_egress: false,
      exact_score_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      internal_error_egress: false,
    } as const;
    const cancellation = {
      surface: "arena_owner_cancellation",
      schema_version: 1,
      changed: true,
      idempotent_replay: false,
      submission,
      ciphertext_lifecycle: {
        ...lifecycle,
        receipt: lifecycle.receipt ? { ...lifecycle.receipt } : null,
      },
      worker_transition_authority: false,
      raw_candidate_egress: false,
      encrypted_reference_egress: false,
      physical_erasure_claimed: false,
    } as const;
    const erasure = {
      surface: "arena_ciphertext_erasure",
      schema_version: 1,
      submission_id: submissionId,
      state: "unlinked",
      changed: true,
      idempotent_replay: false,
      ciphertext_lifecycle: lifecycle,
      worker_transition_authority: false,
      ciphertext_egress: false,
      encrypted_reference_egress: false,
      physical_erasure_claimed: false,
    } as const;

    expect(parseArenaOwnerCancellation(cancellation, {
      challengeId: challenge.challenge_id,
      version: challenge.version,
      submissionId,
    }).submission.state).toBe("cancelled");
    expect(parseArenaCiphertextErasure(erasure, submissionId).state).toBe("unlinked");
    expect(() => parseArenaOwnerCancellation({
      ...cancellation,
      physical_erasure_claimed: true,
    }, {
      challengeId: challenge.challenge_id,
      version: challenge.version,
      submissionId,
    })).toThrow(/bounded schema/);
    expect(() => parseArenaCiphertextErasure({
      ...erasure,
      ciphertext_lifecycle: {
        ...lifecycle,
        unlink_attempts: 0,
      },
    }, submissionId)).toThrow(/bounded schema/);
  });

  it("posts wallet-authenticated cancellation and cleanup retries to exact challenge-version routes", async () => {
    const submissionId = `sub_${"1".repeat(24)}`;
    const lifecycle = {
      state: "unlinked",
      retention_policy: "terminal_immediate_unlink_with_bounded_retry",
      max_terminal_retention_seconds: 3600,
      unlink_attempts: 1,
      current_state_evidence: "directory_entry_absent",
      retryable: false,
      receipt: {
        blob_sha256: `sha256:${"5".repeat(64)}`,
        ciphertext_sha256: `sha256:${"6".repeat(64)}`,
        key_id: `sha256:${"7".repeat(64)}`,
      },
      ciphertext_egress: false,
      sealed_reference_egress: false,
      physical_erasure_claimed: false,
    } as const;
    const submission = {
      surface: "arena_owner_submission",
      schema_version: 3,
      submission_id: submissionId,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      identity: { wallet_address_hash: "2".repeat(64), project_id_hash: "3".repeat(64) },
      candidate_commitment: `sha256:${"4".repeat(64)}`,
      manifest: {
        schema_version: 1,
        challenge_manifest_hash: challenge.manifest_hash,
        candidate_kind: challenge.candidate.kind,
        runtime: challenge.candidate.runtime,
        entrypoint: challenge.candidate.entrypoint,
        mode: "leaderboard",
        private_size_egress: false,
      },
      state: "cancelled",
      bounded_result: null,
      execution_capability: capability,
      execution_provenance: unobservedExecutionProvenance,
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      ciphertext_lifecycle: lifecycle,
      owner_actions: { can_cancel: false, can_retry_ciphertext_erasure: false },
      raw_candidate_egress: false,
      encrypted_reference_egress: false,
      exact_score_egress: false,
      exact_reward_egress: false,
      exact_timing_egress: false,
      internal_error_egress: false,
    } as const;
    const responses = [
      {
        surface: "arena_owner_cancellation",
        schema_version: 1,
        changed: true,
        idempotent_replay: false,
        submission,
        ciphertext_lifecycle: lifecycle,
        worker_transition_authority: false,
        raw_candidate_egress: false,
        encrypted_reference_egress: false,
        physical_erasure_claimed: false,
      },
      {
        surface: "arena_ciphertext_erasure",
        schema_version: 1,
        submission_id: submissionId,
        state: "unlinked",
        changed: false,
        idempotent_replay: true,
        ciphertext_lifecycle: lifecycle,
        worker_transition_authority: false,
        ciphertext_egress: false,
        encrypted_reference_egress: false,
        physical_erasure_claimed: false,
      },
    ];
    const fetchMock = vi.fn(async () => new Response(
      JSON.stringify(responses.shift()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    const originalDelegateUrl = Object.getOwnPropertyDescriptor(
      deployment,
      "delegateUrl",
    );
    Object.defineProperty(deployment, "delegateUrl", {
      value: "https://delegate.test",
      configurable: true,
    });
    try {
      const token = "header.payload.signature";
      await expect(cancelArenaOwnerSubmission(
        challenge.challenge_id,
        challenge.version,
        submissionId,
        token,
      )).resolves.toMatchObject({ changed: true });
      await expect(retryArenaCiphertextErasure(
        challenge.challenge_id,
        challenge.version,
        submissionId,
        token,
      )).resolves.toMatchObject({ idempotent_replay: true });
      const firstCall = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      const secondCall = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
      expect(firstCall[0]).toBe(
        `https://delegate.test/arena/challenges/${challenge.challenge_id}/versions/${challenge.version}/submissions/${submissionId}/cancel`,
      );
      expect(secondCall[0]).toBe(
        `https://delegate.test/arena/challenges/${challenge.challenge_id}/versions/${challenge.version}/submissions/${submissionId}/ciphertext-erasure/retry`,
      );
      for (const [, init] of [firstCall, secondCall]) {
        expect(init.method).toBe("POST");
        expect(init.cache).toBe("no-store");
        expect(init.credentials).toBe("omit");
        expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${token}`);
      }
    } finally {
      if (originalDelegateUrl) {
        Object.defineProperty(
          deployment,
          "delegateUrl",
          originalDelegateUrl,
        );
      }
      vi.unstubAllGlobals();
    }
  });

  it("accepts the schema-v2 ciphertext receipt without inventing execution evidence", () => {
    const submission = {
      surface: "arena_submission",
      schema_version: 2,
      submission_id: `sub_${"a".repeat(24)}`,
      challenge_id: "dnaseq-variant-qc-safe-ir",
      challenge_version: "1.0.0",
      identity: { wallet_address_hash: "b".repeat(64), project_id_hash: "c".repeat(64) },
      candidate_commitment: `sha256:${"d".repeat(64)}`,
      manifest: {
        schema_version: 1,
        challenge_manifest_hash: "e".repeat(64),
        candidate_kind: "json_dnaseq_variant_qc_program",
        runtime: "dnai-safe-ir-v1",
        entrypoint: "select_variant_evidence",
        mode: "leaderboard",
        private_size_egress: false,
      },
      state: "submitted",
      queue_events: [{ sequence: 1, from_state: null, to_state: "submitted", reason: "caller_submitted" }],
      ladder_release: null,
      execution_capability: capability,
      execution_provenance: { ...unobservedExecutionProvenance, runtime: "dnai-safe-ir-v1" },
      product_status: "modeled",
      execution_assurance: "projection_only_no_hardened_executor",
      exact_timing_egress: false,
      encrypted_reference_public: false,
      raw_candidate_accepted: false,
      raw_secret_egress: false,
    } as const;
    const response = {
      surface: "arena_submission_result",
      created: true,
      idempotent_replay: false,
      registry_ingress_boundary: {
        surface: "arena_registry_ingress_boundary",
        schema_version: 1,
        status: "proxy_independently_verified_at_finalized_block",
        verification_model: "single_rpc_reported_finalized_pinned_block",
        browser_preflight_accepted_as_authority: false,
        proxy_registry_authorized: true,
        worker_registry_authorized: false,
        registry_authorization_sha256: `sha256:${"4".repeat(64)}`,
        chain_id: 84532,
        block_number: "12345",
        block_hash: finalizedBlockHash,
        registry_address: registryAddress,
        registry_challenge_id: "1",
        registry_version: 7,
        independent_rpc_quorum_verified: false,
        consensus_proof_verified: false,
      },
      candidate_ingress: {
        surface: "arena_candidate_ingress_receipt",
        schema_version: 1,
        blob_sha256: `sha256:${"1".repeat(64)}`,
        ciphertext_sha256: `sha256:${"2".repeat(64)}`,
        key_id: `sha256:${"3".repeat(64)}`,
        created: true,
        idempotent_replay: false,
        sealed_reference_public: false,
        plaintext_candidate_accepted: false,
        product_status: "modeled",
        execution_assurance: "projection_only_no_hardened_executor",
        raw_secret_egress: false,
        private_size_egress: false,
      },
      submission,
      raw_candidate_accepted: false,
      encrypted_reference_egress: false,
      raw_secret_egress: false,
    } as const;

    const parsedResult = parseArenaSubmissionResult(response);
    expect(parsedResult.submission.execution_provenance.status).toBe("not_executed");
    const firstQueuePage = parseArenaQueue({
      surface: "arena_public_queue",
      schema_version: 2,
      challenge_id: submission.challenge_id,
      challenge_version: submission.challenge_version,
      submission_count: 1,
      submissions: [parsedResult.submission],
      has_more: true,
      next_cursor: `arena_page_v1.${"b".repeat(96)}`,
      product_status: "per_row",
      execution_assurance: "per_submission_execution_provenance",
      raw_candidate_egress: false,
      exact_timing_egress: false,
      execution_capability: structuredClone(capability),
    });
    const nextSubmission = {
      ...structuredClone(parsedResult.submission),
      submission_id: `sub_${"b".repeat(24)}`,
      identity: { wallet_address_hash: "c".repeat(64), project_id_hash: "d".repeat(64) },
      candidate_commitment: `sha256:${"f".repeat(64)}`,
    };
    const secondQueuePage = parseArenaQueue({
      ...firstQueuePage,
      submission_count: 2,
      submissions: [parsedResult.submission, nextSubmission],
      has_more: false,
      next_cursor: null,
    });
    expect(appendArenaQueuePageRows(
      firstQueuePage.submissions,
      firstQueuePage,
      secondQueuePage,
    ).map((item) => item.submission_id)).toEqual([
      parsedResult.submission.submission_id,
      nextSubmission.submission_id,
    ]);
    const crossChallengePage = parseArenaQueue({
      ...secondQueuePage,
      challenge_id: "other-challenge",
      submission_count: 1,
      submissions: [{
        ...nextSubmission,
        challenge_id: "other-challenge",
      }],
    });
    expect(() => appendArenaQueuePageRows(
      firstQueuePage.submissions,
      firstQueuePage,
      crossChallengePage,
    )).toThrow(/crossed its surface or challenge-version boundary/);
    expect(parseArenaSubmissionResult(response).registry_ingress_boundary.proxy_registry_authorized).toBe(true);
    expect(() => parseArenaSubmissionResult({
      ...response,
      registry_ingress_boundary: {
        ...response.registry_ingress_boundary,
        browser_preflight_accepted_as_authority: true,
      },
    })).toThrow(/unsupported authorization claim/);
    expect(() => parseArenaSubmissionResult({
      ...response,
      submission: {
        ...submission,
        execution_provenance: workerReportedExecutionProvenance,
        product_status: "live",
        execution_assurance: "worker_reported_qvl_binding_not_independently_verified",
      },
    })).toThrow(/does not bind its manifest|receipt is malformed/);
  });

  it("accepts live presence only for exact release-bound safe-IR evidence", () => {
    const modeled = {
      surface: "arena_worker_capability",
      schema_version: 2,
      challenge_id: challenge.challenge_id,
      challenge_version: challenge.version,
      status: "modeled",
      backend: "source_ready_preview",
      isolation: "not_connected",
      live_execution: false,
      worker_connected: false,
      safe_ir_execution_ready: false,
      hostile_general_code_ready: false,
      python_preview_live: false,
      freshness: "unavailable",
      evidence_authenticity: "unverified",
      evidence_classification: "authenticated_worker_presence_not_tdx_attestation",
      gate_reason: "python_preview_only",
      heartbeat_observed_at: null,
      heartbeat_binding_sha256: null,
      release_binding_sha256: null,
      release_binding: null,
      warning: "Source ready only",
      product_status: "modeled",
      exact_timing_egress: false,
      internal_error_egress: false,
      raw_candidate_egress: false,
      tdx_attestation_egress: false,
    } as const;
    expect(parseArenaWorkerCapability(modeled).live_execution).toBe(false);

    const live = {
      ...modeled,
      challenge_id: "dnaseq-variant-qc-safe-ir",
      status: "live",
      backend: "release_bound_safe_ir_worker",
      isolation: "independent_job_gate_required",
      live_execution: true,
      worker_connected: true,
      safe_ir_execution_ready: true,
      freshness: "fresh",
      evidence_authenticity: "hmac_verified",
      gate_reason: "ready",
      product_status: "live",
      release_binding: {
        release_sha: "1".repeat(40),
        image_digest: `sha256:${"2".repeat(64)}`,
        release_manifest_sha256: `sha256:${"3".repeat(64)}`,
        approved_challenge_set_sha256: `sha256:${"a".repeat(64)}`,
        approved_challenge_key: "dnaseq-variant-qc-safe-ir@1.0.0",
        release_policy_commitment: `0x${"4".repeat(64)}`,
        catalog_manifest_hash: "0812d8ab6cb26d60f1c28f6696773bd05a47e89fecc0ac6f28447ab0624f058f",
        runtime: "dnai-safe-ir-v1",
        runtime_policy_commitment: "sha256:9fcffd04eeece1398970e4a144807df95f31408b2337d71cc8377048b2ec114e",
        compose_hash: "5".repeat(64),
        app_id: "app_arena_safe_ir",
        os_image_hash: "6".repeat(64),
      },
      heartbeat_observed_at: 1_899_999_998,
      release_binding_sha256: "sha256:dda813e4a5aa72ad6b8058447919e78d9bc8b07291679d147f536ba6c59ddc99",
      heartbeat_binding_sha256: "sha256:63a4a9a1ba70fb1027860faa4e25498c2ea9397ecbe9f17c3d38d82f68f4e4d0",
      warning: "Authenticated presence; not TDX evidence",
    } as const;
    const parsedLive = parseArenaWorkerCapability(live);
    expect(parsedLive.live_execution).toBe(true);
    expect(arenaWorkerReleaseBindingSha256(live.release_binding)).toBe(
      live.release_binding_sha256,
    );
    expect(arenaWorkerHeartbeatBindingSha256(
      live.challenge_id,
      live.challenge_version,
      live.heartbeat_observed_at,
      live.release_binding_sha256,
    )).toBe(live.heartbeat_binding_sha256);
    const authorization = {
      status: "browser_preflight_passed",
      verificationScope: "browser_only",
      proxyIndependentlyVerified: false,
      workerAuthorized: false,
      catalogChallengeId: live.challenge_id,
      catalogChallengeVersion: live.challenge_version,
      approvedChallengeSetSha256: live.release_binding.approved_challenge_set_sha256,
      catalogManifestHash: live.release_binding.catalog_manifest_hash,
      releasePolicyCommitment: live.release_binding.release_policy_commitment,
    } as ArenaChallengeRegistryAuthorization;
    expect(arenaWorkerMatchesRegistryAuthorization(parsedLive, authorization)).toBe(true);
    expect(arenaWorkerMatchesRegistryAuthorization(parsedLive, {
      ...authorization,
      approvedChallengeSetSha256: `sha256:${"b".repeat(64)}`,
    })).toBe(false);
    expect(arenaWorkerMatchesRegistryAuthorization(parsedLive, {
      ...authorization,
      releasePolicyCommitment: `0x${"7".repeat(64)}`,
    })).toBe(false);
    expect(() => parseArenaWorkerCapability({ ...live, challenge_id: challenge.challenge_id })).toThrow(/release binding is invalid/);
    expect(() => parseArenaWorkerCapability({ ...live, freshness: "unavailable" })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({ ...live, tdx_verified: true })).toThrow(/fields do not match/);
    expect(() => parseArenaWorkerCapability({ ...modeled, live_execution: true })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({ ...live, schema_version: 1 })).toThrow(/unsupported execution claim/);
    const legacyV1: Record<string, unknown> = { ...modeled, schema_version: 1 };
    delete legacyV1.heartbeat_observed_at;
    delete legacyV1.heartbeat_binding_sha256;
    delete legacyV1.release_binding_sha256;
    expect(() => parseArenaWorkerCapability(legacyV1)).toThrow();
    expect(() => parseArenaWorkerCapability({ ...live, heartbeat_observed_at: live.heartbeat_observed_at - 1 })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({ ...live, heartbeat_binding_sha256: `sha256:${"0".repeat(64)}` })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({ ...live, release_binding_sha256: `sha256:${"0".repeat(64)}` })).toThrow(/release binding digest is invalid/);
    expect(() => parseArenaWorkerCapability({
      ...live,
      release_binding: { ...live.release_binding, app_id: "app_arena_safe_ir_tampered" },
    })).toThrow(/release binding digest is invalid/);
    expect(() => parseArenaWorkerCapability({
      ...live,
      evidence_classification: "tdx_attestation",
    })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({
      ...modeled,
      heartbeat_observed_at: live.heartbeat_observed_at,
    })).toThrow(/unsupported execution claim/);
    expect(() => parseArenaWorkerCapability({
      ...live,
      heartbeat: { observed_at: live.heartbeat_observed_at },
    })).toThrow(/fields do not match/);
    expect(() => parseArenaWorkerCapability({
      ...live,
      mac: "do-not-expose",
    })).toThrow(/fields do not match/);
  });

  it("passes browser preflight only for the exact frozen current Open ChallengeRegistry version", async () => {
    const preflight = await verifyArenaChallengeRegistryAuthorization(challenge, registryOptions());
    expect(preflight).toEqual({
      status: "browser_preflight_passed",
      verificationScope: "browser_only",
      proxyIndependentlyVerified: false,
      workerAuthorized: false,
      chainId: 84532,
      verifiedBlockNumber: 12_345n,
      verifiedBlockHash: finalizedBlockHash,
      verifiedBlockTimestamp: 1_700_000_000n,
      registryAddress,
      registryCodeHash,
      approvedChallengeSetSha256,
      registryChallengeId: "1",
      registryVersion: 7,
      controllerAddress: registryChallenge.controller,
      pendingControllerAddress: registryChallenge.pendingController,
      catalogChallengeId: challenge.challenge_id,
      catalogChallengeVersion: challenge.version,
      catalogManifestHash: challenge.manifest_hash,
      metadataURI: registryVersion.metadataURI,
      metadataHash,
      sealedArtifactCommitment,
      evaluatorCommitment,
      releasePolicyCommitment,
      registryPaused: false,
      challengePaused: false,
      lifecycle: 1,
      configurationFrozen: true,
      latestVersion: 7,
    });
    const snapshot = arenaChallengeRegistryAuthorizationSnapshot(preflight);
    expect(snapshot).toMatchObject({
      verification_model: "single_rpc_reported_finalized_pinned_block",
      chain_id: 84532,
      block_number: "12345",
      block_hash: finalizedBlockHash,
      block_timestamp: "1700000000",
      registry_address: registryAddress,
      registry_challenge_id: "1",
      registry_version: 7,
      release_policy_commitment: releasePolicyCommitment,
      registry_paused: false,
      challenge_paused: false,
      lifecycle: 1,
      configuration_frozen: true,
    });
    const snapshotSha256 = await arenaChallengeRegistryAuthorizationSha256(snapshot);
    expect(snapshotSha256).toBe(
      "sha256:d4c6af23c3c5ae81c11d78f65b32285a01fb69cac6a5d2c3befb959a5b66a3ce",
    );
    await expect(arenaChallengeRegistryAuthorizationSha256({
      ...snapshot,
      block_hash: `0x${"e".repeat(64)}`,
    })).resolves.not.toBe(snapshotSha256);
  });

  it.each([undefined, "0x" as Hex])("rejects a registry address without runtime bytecode (%s)", async (bytecode) => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({ getBytecode: async () => bytecode })),
    )).rejects.toThrow(/no runtime bytecode/);
  });

  it("rejects runtime bytecode that does not match the deployment pin", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({ getBytecode: async () => "0x6000" })),
    )).rejects.toThrow(/runtime bytecode does not match/);
  });

  it("fails closed when any required registry build pin is absent", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(challenge, {
      ...registryOptions(),
      registryAddress: "" as Address,
    })).rejects.toThrow(/address is not pinned/);
    await expect(verifyArenaChallengeRegistryAuthorization(challenge, {
      ...registryOptions(),
      registryCodeHash: "" as Hex,
    })).rejects.toThrow(/code hash is not pinned/);
    await expect(verifyArenaChallengeRegistryAuthorization(challenge, {
      ...registryOptions(),
      bindingsJson: "",
    })).rejects.toThrow(/bindings are not pinned/);
    await expect(verifyArenaChallengeRegistryAuthorization(challenge, {
      ...registryOptions(),
      approvedChallengeSetSha256: undefined,
    })).rejects.toThrow(/challenge-set digest is not pinned/);
    await expect(verifyArenaChallengeRegistryAuthorization(challenge, {
      ...registryOptions(),
      approvedChallengeSetSha256: `sha256:${"f".repeat(64)}`,
    })).rejects.toThrow(/challenge-set digest does not match/);
  });

  it("rejects an RPC endpoint that is not Base Sepolia", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({ getChainId: async () => 8453 })),
    )).rejects.toThrow(/expected Base Sepolia 84532/);
  });

  it("rejects a globally paused registry and a missing challenge", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({ registryPaused: async () => true })),
    )).rejects.toThrow(/Registry is paused/);
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({ challengeExists: async () => false })),
    )).rejects.toThrow(/does not exist/);
  });

  it.each([
    ["controller", { controller: `0x${"3".repeat(40)}` as Address }, /controller does not match/],
    ["pending controller", { pendingController: `0x${"3".repeat(40)}` as Address }, /pending controller does not match/],
    ["non-Open lifecycle", { lifecycle: 0 }, /not Open/],
    ["challenge pause", { paused: true }, /challenge is paused/],
    ["unfrozen configuration", { configurationFrozen: false }, /not frozen/],
  ] as const)("rejects %s", async (_label, stateOverride, expected) => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({
        getChallenge: async () => ({ ...registryChallenge, ...stateOverride }),
      })),
    )).rejects.toThrow(expected);
  });

  it("rejects a superseded registry version and an unbound catalog version", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({
        getChallenge: async () => ({ ...registryChallenge, latestVersion: 8 }),
      })),
    )).rejects.toThrow(/current version is 8; expected 7/);
    await expect(verifyArenaChallengeRegistryAuthorization(
      { ...challenge, version: "1.0.1" },
      registryOptions(),
    )).rejects.toThrow(/has no exact ChallengeRegistry binding/);
  });

  it("rejects a backend catalog manifest that differs from the build binding", async () => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      { ...challenge, manifest_hash: "f".repeat(64) },
      registryOptions(),
    )).rejects.toThrow(/manifest does not match/);
  });

  it.each([
    ["metadata URI", { metadataURI: "ipfs://different" }, /metadata URI/],
    ["metadata commitment", { metadataHash: `0x${"e".repeat(64)}` as Hex }, /metadata commitment/],
    ["sealed artifact commitment", { sealedArtifactCommitment: `0x${"e".repeat(64)}` as Hex }, /sealed artifact commitment/],
    ["evaluator commitment", { evaluatorCommitment: `0x${"e".repeat(64)}` as Hex }, /evaluator commitment/],
    ["release policy commitment", { releasePolicyCommitment: `0x${"e".repeat(64)}` as Hex }, /release policy commitment/],
  ] as const)("rejects an on-chain %s mismatch", async (_label, versionOverride, expected) => {
    await expect(verifyArenaChallengeRegistryAuthorization(
      challenge,
      registryOptions(registryReader({
        getVersion: async () => ({ ...registryVersion, ...versionOverride }),
      })),
    )).rejects.toThrow(expected);
  });

  it("rejects permissive or noncanonical binding configuration", () => {
    const decoded = JSON.parse(registryBindings) as Record<string, Record<string, unknown>>;
    decoded[`${challenge.challenge_id}@${challenge.version}`].unexpected = true;
    expect(() => parseArenaChallengeRegistryBindings(JSON.stringify(decoded))).toThrow(/fields do not match/);

    const uppercase = JSON.parse(registryBindings) as Record<string, Record<string, unknown>>;
    uppercase[`${challenge.challenge_id}@${challenge.version}`].evaluator_commitment = evaluatorCommitment.toUpperCase();
    expect(() => parseArenaChallengeRegistryBindings(JSON.stringify(uppercase))).toThrow(/lowercase bytes32/);

    const staleAuthority = JSON.parse(registryBindings) as Record<string, Record<string, unknown>>;
    staleAuthority[`${challenge.challenge_id}@${challenge.version}`].configuration_frozen = false;
    expect(() => parseArenaChallengeRegistryBindings(JSON.stringify(staleAuthority))).toThrow(/Open, unpaused, frozen/);
  });

  it("preflights the exact capability-free safe-IR candidate language", () => {
    const encoder = new TextEncoder();
    const source = encoder.encode(
      '{"negative_pipeline":[{"op":"mad_filter","threshold_milli":3000}],"positive_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
    );
    expect(() => validateArenaSafeIrCandidateBytes(source)).not.toThrow();
    for (const invalid of [
      '{"negative_pipeline":[], "positive_pipeline":[],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
      '{"negative_pipeline":[],"positive_pipeline":[{"op":"open","path":"/etc/passwd"}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
      '{"negative_pipeline":[],"positive_pipeline":[{"offset":2,"op":"stride","step":2}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
      '{"negative_pipeline":[],"positive_pipeline":[],"schema":"dnai.dnaseq-variant-qc-safe-ir.v2"}',
    ]) {
      expect(() => validateArenaSafeIrCandidateBytes(encoder.encode(invalid))).toThrow(/Safe-IR/);
    }
  });

  it("ships a byte-exact starter candidate accepted by the browser parser", () => {
    const starter = arenaSafeIrStarterCandidateBytes();
    expect(ARENA_SAFE_IR_STARTER_FILENAME).toBe("dnai-dnaseq-variant-qc-safe-ir-v1.json");
    expect(() => validateArenaSafeIrCandidateBytes(starter)).not.toThrow();
    const source = new TextDecoder().decode(starter);
    expect(JSON.stringify(JSON.parse(source))).toBe(source);
    expect(source.endsWith("\n")).toBe(false);
  });

  it("matches the backend's byte-exact X25519/HKDF/AES-GCM interoperability vector", async () => {
    const source = new TextEncoder().encode(
      "def process(positive_wells, negative_wells):\n    return positive_wells, negative_wells\n",
    );
    const walletAddress = `0x${"ab".repeat(20)}`;
    const projectId = `personal-${"cd".repeat(16)}`;
    const identity = await arenaProtocolIdentity(walletAddress, projectId);
    expect(identity).toEqual({
      wallet_address_hash: "7c881fa2a5c15b14c4c72f50881110d574b578390ae7cc57e4d9b8f9215e3c51",
      project_id_hash: "0b84b7e2e9845831a7d6e22e73d203234e6e3169518e14c74bbd5f52dd126e02",
    });

    const manifest: ArenaSubmissionManifest = {
      schema_version: 1,
      challenge_manifest_hash: "d381d2c9bbaad6ed756f0083d2a6004f76990d351754e492f96fa7c7f2d17345",
      candidate_kind: "python_assay_qc_program",
      runtime: "python3.11",
      entrypoint: "process",
      source_bytes: source.length,
      mode: "leaderboard",
    };
    const manifestHash = await arenaSubmissionManifestHash(manifest);
    expect(manifestHash).toBe("sha256:4da59dff0de75fb89aae4ec73fe28e06abae4370f0b9aa58a1b2266e2cf57b0c");
    const commitment = await candidateCommitment(source);
    const idempotencyHash = await arenaIdempotencyKeyHash(
      "synthetic-bio-assay-qc",
      "1.0.0",
      identity,
      "candidate-vector-1",
    );
    expect(idempotencyHash).toBe("sha256:7a57ba69f49f62a10aeb2b6cdebd0da66d2bda435744834c39415eaefc9d0856");
    const binding: ArenaCandidateBinding = {
      service: "dnai-wikigen",
      context: "arena_candidate_ingress",
      schema_version: 1,
      challenge_id: "synthetic-bio-assay-qc",
      challenge_version: "1.0.0",
      challenge_manifest_hash: manifest.challenge_manifest_hash,
      submission_manifest_hash: manifestHash,
      candidate_commitment: commitment,
      identity,
      idempotency_key_hash: idempotencyHash,
      key_id: "sha256:aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041",
      attestation_report_data_sha256: "sha256:4be27ebd9f45b86d00689cb48249afabaa8e0c20e6441052b90f32fe8faf8263",
      registry_authorization_sha256: `sha256:${"e".repeat(64)}`,
    };
    const aad = arenaCandidateAad(binding);
    expect(aad.length).toBe(1020);
    const aadHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", aad.slice().buffer)))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    expect(aadHash).toBe("fd9d0cda126ef79d36d491bc4ff4088b37b86fff63b29655a337403d1da75a92");

    const privateBytes = Uint8Array.from({ length: 32 }, (_, index) => index + 33);
    const pkcs8Prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
    const pkcs8 = new Uint8Array(pkcs8Prefix.length + privateBytes.length);
    pkcs8.set(pkcs8Prefix);
    pkcs8.set(privateBytes, pkcs8Prefix.length);
    const ephemeralPrivateKey = await crypto.subtle.importKey("pkcs8", pkcs8.buffer, { name: "X25519" }, false, ["deriveBits"]);
    const ephemeralPublicBytes = Uint8Array.from(
      "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b".match(/../g) ?? [],
      (pair) => Number.parseInt(pair, 16),
    );
    const ephemeralPublicKey = await crypto.subtle.importKey("raw", ephemeralPublicBytes.buffer, { name: "X25519" }, true, []);
    const encrypted = await encryptArenaCandidateBytes(
      source,
      "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
      aad,
      {
        ephemeralPrivateKey,
        ephemeralPublicKey,
        nonce: Uint8Array.from({ length: 12 }, (_, index) => index),
      },
    );
    expect(encrypted.ciphertextBytes).toBe(103);
    expect(encrypted.ciphertext).toBe(
      "jkk46xPX0_Vgxkw5XQ5UKHHj0eWhSzGlL5p7fQCXY_YjT50nmAZAtu_78LCPEdc3GO8zFdK4cQaHhCjBv3yKgPzUAf7yTSWYmDGJW2kxjrLi4ydowUIywFKICAPfupsIACLc90gqTw",
    );
  });

  it("keeps generated Arena ephemeral X25519 private keys non-exportable", async () => {
    const generateKey = vi.spyOn(crypto.subtle, "generateKey");
    const exportKey = vi.spyOn(crypto.subtle, "exportKey");
    try {
      await encryptArenaCandidateBytes(
        new TextEncoder().encode("bounded candidate"),
        "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
        new TextEncoder().encode("bounded arena aad"),
      );
      expect(generateKey).toHaveBeenCalledWith({ name: "X25519" }, false, ["deriveBits"]);
      const generatedCall = generateKey.mock.calls.findIndex((call) => (
        typeof call[0] === "object"
        && call[0] !== null
        && "name" in call[0]
        && call[0].name === "X25519"
      ));
      expect(generatedCall).toBeGreaterThanOrEqual(0);
      const generated = await (generateKey.mock.results[generatedCall]?.value as Promise<CryptoKeyPair>);
      expect(generated.privateKey.extractable).toBe(false);
      expect(generated.publicKey.extractable).toBe(true);
      expect(exportKey.mock.calls.some(([, key]) => key.type === "private")).toBe(false);
      await expect(crypto.subtle.exportKey("pkcs8", generated.privateKey)).rejects.toThrow();
    } finally {
      generateKey.mockRestore();
      exportKey.mockRestore();
    }
  });

  it("does not commit the exact private source size into the public manifest hash", async () => {
    const base: ArenaSubmissionManifest = {
      schema_version: 1,
      challenge_manifest_hash: "d381d2c9bbaad6ed756f0083d2a6004f76990d351754e492f96fa7c7f2d17345",
      candidate_kind: "python_assay_qc_program",
      runtime: "python3.11",
      entrypoint: "process",
      source_bytes: 1,
      mode: "leaderboard",
    };

    await expect(arenaSubmissionManifestHash(base)).resolves.toBe(
      await arenaSubmissionManifestHash({ ...base, source_bytes: 8_192 }),
    );
  });

  it("rejects exact private sizes anywhere in an Arena public receipt", () => {
    expect(() => parseArenaSubmissionResult({
      surface: "arena_submission_result",
      candidate_ingress: { ciphertext_bytes: 117 },
    })).toThrow(/forbidden field ciphertext_bytes/);
    expect(() => parseArenaSubmissionResult({
      surface: "arena_submission_result",
      submission: { manifest: { source_bytes: 101 } },
    })).toThrow(/forbidden field source_bytes/);
  });
});
