import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { ethereumKeccak256Hex } from "../../../../scripts/ethereum-keccak.mjs";
import {
  classifyRoyaltyAuthorityState,
  classifyRoyaltyRelease,
  collectRoyaltyReleaseFinality,
  normalizeForgeBroadcastArtifact,
  normalizeRoyaltyPhasePlanReceipt,
  normalizeRpcEndpoints,
  royaltyUnpauseRecoveryEvidenceSha256,
  verifyRoyaltyReleaseDryRun,
} from "./royalty-release-finality.mjs";

const address = (character) => `0x${character.repeat(40)}`;
const word = (character) => `0x${character.repeat(64)}`;
const digest = (character) => `sha256:${character.repeat(64)}`;
const ZERO_ADDRESS = address("0");
const ZERO_WORD = word("0");
const DISTRIBUTOR_CODE = "0x6000";
const ANCHOR_CODE = "0x6001";
const DISTRIBUTOR_RUNTIME = ethereumKeccak256Hex(
  Buffer.from(DISTRIBUTOR_CODE.slice(2), "hex"),
);
const ANCHOR_RUNTIME = ethereumKeccak256Hex(Buffer.from(ANCHOR_CODE.slice(2), "hex"));
const FINALIZED_BLOCK = 200;
const FINALIZED_HASH = word("f");
const PLAN_VALID_AFTER_SECONDS = Date.parse("2026-07-25T12:00:00.000Z") / 1_000;
const TX_TIMESTAMP = PLAN_VALID_AFTER_SECONDS + 60;
const FINALIZED_TIMESTAMP = PLAN_VALID_AFTER_SECONDS + 300;
const PHASE_TWO_VALID_AFTER = "2026-07-27T12:02:00.000Z";
const PHASE_TWO_TX_TIMESTAMP = Date.parse("2026-07-27T12:03:00.000Z") / 1_000;
const PHASE_TWO_FINALIZED_TIMESTAMP = PHASE_TWO_TX_TIMESTAMP + 240;
const selector = (signature) =>
  ethereumKeccak256Hex(Buffer.from(signature, "utf8")).slice(0, 10);
const rawSha256 = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const uintWord = (value) => BigInt(value).toString(16).padStart(64, "0");
const addressWord = (value) => value.slice(2).padStart(64, "0");

function policyCommitment(authority) {
  const type =
    "RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)";
  return ethereumKeccak256Hex(Buffer.from([
    ethereumKeccak256Hex(Buffer.from(type, "utf8")).slice(2),
    uintWord(84532),
    addressWord(authority.distributor_address),
    uintWord(authority.authority_nonce),
    addressWord(authority.settlement_verifier),
    addressWord(authority.qvl_verifier),
    addressWord(authority.anchor_address),
    authority.anchor_writer_release_commitment.slice(2),
  ].join(""), "hex"));
}

function actionCalldata(action, authority) {
  if (action === "propose_authority_binding") {
    return `${selector("proposeAuthorityBinding(address,address,address,bytes32)")}`
      + addressWord(authority.settlement_verifier)
      + addressWord(authority.qvl_verifier)
      + addressWord(authority.anchor_address)
      + authority.anchor_writer_release_commitment.slice(2);
  }
  if (action === "activate_authority_proposal") return selector("activateAuthorityProposal()");
  if (action === "unpause") return `${selector("setPaused(bool)")}${uintWord(0)}`;
  throw new Error("unsupported test action");
}

const AUTHORITY_BASE = {
  distributor_address: address("1"),
  distributor_runtime_code_hash: DISTRIBUTOR_RUNTIME,
  owner: address("2"),
  settlement_verifier: address("3"),
  qvl_verifier: address("4"),
  anchor_address: address("5"),
  anchor_runtime_code_hash: ANCHOR_RUNTIME,
  anchor_writer: address("6"),
  anchor_writer_release_commitment: word("c"),
  authority_nonce: "1",
};
const AUTHORITY = Object.freeze({
  ...AUTHORITY_BASE,
  release_policy_commitment: policyCommitment(AUTHORITY_BASE),
});

const uintHex = (value) => `0x${BigInt(value).toString(16)}`;
const abiUint = (value) => `0x${BigInt(value).toString(16).padStart(64, "0")}`;
const abiAddress = (value) => `0x${value.slice(2).padStart(64, "0")}`;
const abiBool = (value) => abiUint(value ? 1 : 0);
const abiBytes32 = (value) => value;

function prerequisite() {
  return {
    phase_one_plan_sha256: digest("1"),
    phase_one_history_record_sha256: digest("2"),
    phase_one_finalized_at: "2026-07-25T12:00:00.000Z",
    finalized_authority_receipt_sha256: digest("3"),
    ledger_sha256: digest("4"),
    ledger_revision: 3,
    ledger_revision_receipt_sha256: digest("5"),
    proposal_tx_hash: word("9"),
    proposal_block_number: "100",
    proposal_block_hash: word("8"),
    pending_authority_activates_at: String(TX_TIMESTAMP + 172_800),
  };
}

function planReceipt({
  phase = 1,
  mode = phase === 1 ? "stage_authority" : "activate_and_unpause",
  nonce = phase === 1 ? 7 : 8,
  recovery = null,
} = {}) {
  const actions = phase === 1
    ? ["propose_authority_binding"]
    : mode === "activate_and_unpause"
      ? ["activate_authority_proposal", "unpause"]
      : ["unpause"];
  const validAfter = phase === 1 ? "2026-07-25T12:00:00.000Z" : PHASE_TWO_VALID_AFTER;
  const expiresAt = phase === 1
    ? "2026-07-25T12:10:00.000Z"
    : "2026-07-27T12:12:00.000Z";
  return {
    schema: "dnai.royalty-release-phase-plan-verification-receipt.v2",
    status: "valid_current_two_reviewer_exact_royalty_phase_plan",
    plan_sha256: digest("6"),
    release_sha: "a".repeat(40),
    chain_id: 84532,
    phase,
    execution_mode: mode,
    valid_after: validAfter,
    expires_at: expiresAt,
    deployment_intent_sha256: digest("9"),
    fresh_contract_deployment_receipt_sha256: digest("a"),
    royalty_release_prescriptive_authority_sha256: digest("b"),
    reviewer_authority_genesis_acceptance_sha256: digest("d"),
    reviewer_authority_current_status_epoch: 3,
    reviewer_authority_current_status_sha256: digest("c"),
    reviewer_root_hash: "d".repeat(64),
    reviewer_set_sha256: digest("e"),
    authority: structuredClone(AUTHORITY),
    phase_one_prerequisite: phase === 1 ? null : prerequisite(),
    phase_two_recovery: recovery,
    transactions: actions.map((action, sequence) => ({
      sequence,
      action,
      signer_address: AUTHORITY.owner,
      nonce: String(nonce + sequence),
      to: AUTHORITY.distributor_address,
      value_wei: "0",
      calldata: actionCalldata(action, AUTHORITY),
      calldata_sha256: rawSha256(Buffer.from(actionCalldata(action, AUTHORITY).slice(2), "hex")),
    })),
    signing_payload_sha256: digest("f"),
    verified_signers: [
      { controller_id: "reviewer.alpha", address: address("7"), signature_sha256: digest("1") },
      { controller_id: "reviewer.beta", address: address("8"), signature_sha256: digest("2") },
    ],
    truth_status:
      "reviewer_signatures_and_exact_plan_validated_not_onchain_execution_finality_or_tdx_evidence",
  };
}

function anchorState() {
  return {
    address: AUTHORITY.anchor_address,
    runtimeCodeHash: AUTHORITY.anchor_runtime_code_hash,
    owner: AUTHORITY.owner,
    pendingOwner: ZERO_ADDRESS,
    deploymentIntentSha256: word("9"),
    reviewerAuthorityGenesisAcceptanceSha256: word("d"),
    writer: AUTHORITY.anchor_writer,
    writerReleaseCommitment: AUTHORITY.anchor_writer_release_commitment,
    pendingWriter: ZERO_ADDRESS,
    pendingWriterReleaseCommitment: ZERO_WORD,
    pendingWriterActivatesAt: 0,
    writerRotationsFrozen: true,
    paused: false,
    globalSequence: 0,
    globalHead: ZERO_WORD,
  };
}

function distributorState(kind) {
  const active = kind.startsWith("phase2");
  const pending = kind === "phase1_exact_pending";
  return {
    address: AUTHORITY.distributor_address,
    runtimeCodeHash: AUTHORITY.distributor_runtime_code_hash,
    owner: AUTHORITY.owner,
    pendingOwner: ZERO_ADDRESS,
    paused: kind === "fresh_empty" || pending || kind === "phase2_exact_active_paused",
    settlementVerifier: active ? AUTHORITY.settlement_verifier : ZERO_ADDRESS,
    qvlVerifier: active ? AUTHORITY.qvl_verifier : ZERO_ADDRESS,
    executionPolicyAnchor: active ? AUTHORITY.anchor_address : ZERO_ADDRESS,
    anchorWriterReleaseCommitment:
      active ? AUTHORITY.anchor_writer_release_commitment : ZERO_WORD,
    releasePolicyCommitment: active ? AUTHORITY.release_policy_commitment : ZERO_WORD,
    authorityNonce: active ? 1 : 0,
    pendingSettlementVerifier: pending ? AUTHORITY.settlement_verifier : ZERO_ADDRESS,
    pendingQvlVerifier: pending ? AUTHORITY.qvl_verifier : ZERO_ADDRESS,
    pendingExecutionPolicyAnchor: pending ? AUTHORITY.anchor_address : ZERO_ADDRESS,
    pendingAnchorWriterReleaseCommitment:
      pending ? AUTHORITY.anchor_writer_release_commitment : ZERO_WORD,
    pendingReleasePolicyCommitment: pending ? AUTHORITY.release_policy_commitment : ZERO_WORD,
    pendingAuthorityNonce: pending ? 1 : 0,
    pendingAuthorityActivatesAt: pending ? TX_TIMESTAMP + 172_800 : 0,
    pendingAuthorityRevocation: false,
    settlementVerifierEverConfigured: active,
    qvlVerifierEverConfigured: active,
    anchorWriterEverConfigured: active,
  };
}

function authorityState(kind) {
  return {
    executionPolicyAnchor: anchorState(),
    royaltyDistributor: distributorState(kind),
  };
}

function resultForCall(target, data, state, provider, { stateDrift = false } = {}) {
  const key = data.slice(0, 10);
  if (target === AUTHORITY.distributor_address) {
    const value = state.royaltyDistributor;
    const values = new Map([
      [selector("owner()"), abiAddress(stateDrift && provider === "secondary" ? address("e") : value.owner)],
      [selector("pendingOwner()"), abiAddress(value.pendingOwner)],
      [selector("paused()"), abiBool(value.paused)],
      [selector("settlementVerifier()"), abiAddress(value.settlementVerifier)],
      [selector("qvlVerifier()"), abiAddress(value.qvlVerifier)],
      [selector("executionPolicyAnchor()"), abiAddress(value.executionPolicyAnchor)],
      [selector("anchorWriterReleaseCommitment()"), abiBytes32(value.anchorWriterReleaseCommitment)],
      [selector("releasePolicyCommitment()"), abiBytes32(value.releasePolicyCommitment)],
      [selector("authorityNonce()"), abiUint(value.authorityNonce)],
      [selector("pendingSettlementVerifier()"), abiAddress(value.pendingSettlementVerifier)],
      [selector("pendingQvlVerifier()"), abiAddress(value.pendingQvlVerifier)],
      [selector("pendingExecutionPolicyAnchor()"), abiAddress(value.pendingExecutionPolicyAnchor)],
      [selector("pendingAnchorWriterReleaseCommitment()"), abiBytes32(value.pendingAnchorWriterReleaseCommitment)],
      [selector("pendingReleasePolicyCommitment()"), abiBytes32(value.pendingReleasePolicyCommitment)],
      [selector("pendingAuthorityNonce()"), abiUint(value.pendingAuthorityNonce)],
      [selector("pendingAuthorityActivatesAt()"), abiUint(value.pendingAuthorityActivatesAt)],
      [selector("pendingAuthorityRevocation()"), abiBool(value.pendingAuthorityRevocation)],
      [selector("settlementVerifierEverConfigured(address)"), abiBool(value.settlementVerifierEverConfigured)],
      [selector("qvlVerifierEverConfigured(address)"), abiBool(value.qvlVerifierEverConfigured)],
      [selector("anchorWriterEverConfigured(address)"), abiBool(value.anchorWriterEverConfigured)],
    ]);
    assert.ok(values.has(key), `unexpected distributor selector ${key}`);
    return values.get(key);
  }
  assert.equal(target, AUTHORITY.anchor_address);
  const value = state.executionPolicyAnchor;
  const values = new Map([
    [selector("owner()"), abiAddress(value.owner)],
    [selector("pendingOwner()"), abiAddress(value.pendingOwner)],
    [selector("deploymentIntentSha256()"), abiBytes32(value.deploymentIntentSha256)],
    [selector("reviewerAuthorityGenesisAcceptanceSha256()"), abiBytes32(value.reviewerAuthorityGenesisAcceptanceSha256)],
    [selector("writer()"), abiAddress(value.writer)],
    [selector("writerReleaseCommitment()"), abiBytes32(value.writerReleaseCommitment)],
    [selector("pendingWriter()"), abiAddress(value.pendingWriter)],
    [selector("pendingWriterReleaseCommitment()"), abiBytes32(value.pendingWriterReleaseCommitment)],
    [selector("pendingWriterActivatesAt()"), abiUint(value.pendingWriterActivatesAt)],
    [selector("writerRotationsFrozen()"), abiBool(value.writerRotationsFrozen)],
    [selector("paused()"), abiBool(value.paused)],
    [selector("globalSequence()"), abiUint(value.globalSequence)],
    [selector("globalHead()"), abiBytes32(value.globalHead)],
  ]);
  assert.ok(values.has(key), `unexpected anchor selector ${key}`);
  return values.get(key);
}

function rpcTransaction(
  reviewed,
  hash,
  blockNumber = 190,
  transactionIndex = 0,
  blockHash = word("b"),
) {
  return {
    hash,
    from: reviewed.signer_address,
    to: reviewed.to,
    nonce: uintHex(reviewed.nonce),
    value: "0x0",
    input: reviewed.calldata,
    blockNumber: uintHex(blockNumber),
    blockHash,
    transactionIndex: uintHex(transactionIndex),
    chainId: "0x14a34",
  };
}

function rpcReceipt(
  reviewed,
  hash,
  blockNumber = 190,
  transactionIndex = 0,
  status = 1,
  blockHash = word("b"),
) {
  return {
    transactionHash: hash,
    from: reviewed.signer_address,
    to: reviewed.to,
    status: uintHex(status),
    blockNumber: uintHex(blockNumber),
    blockHash,
    transactionIndex: uintHex(transactionIndex),
  };
}

function forgeArtifact(reviewed, hash, { includeHash = true } = {}) {
  const entry = {
    transactionType: "CALL",
    transaction: {
      from: reviewed.signer_address,
      to: reviewed.to,
      nonce: uintHex(reviewed.nonce),
      value: "0x0",
      input: reviewed.calldata,
      chainId: "0x14a34",
    },
  };
  if (includeHash) entry.hash = hash;
  return { transactions: [entry] };
}

function mockFetch({
  kind,
  signerNonce,
  nonceByTag = {},
  transactions = new Map(),
  blocks = new Map(),
  stateDrift = false,
  runtimeDrift = false,
  txTimestamp = TX_TIMESTAMP,
  finalizedTimestamp = FINALIZED_TIMESTAMP,
} = {}) {
  const state = authorityState(kind);
  return async (url, options) => {
    const provider = new URL(url).hostname.startsWith("one") ? "primary" : "secondary";
    const request = JSON.parse(options.body);
    let result;
    if (request.method === "eth_chainId") {
      result = "0x14a34";
    } else if (request.method === "eth_getBlockByNumber") {
      const tag = request.params[0];
      if (tag === "finalized" || tag === uintHex(FINALIZED_BLOCK)) {
        result = {
          number: uintHex(FINALIZED_BLOCK),
          hash: FINALIZED_HASH,
          timestamp: uintHex(finalizedTimestamp),
        };
      } else if (blocks.has(tag)) {
        result = blocks.get(tag);
      } else if (tag === uintHex(190)) {
        result = { number: uintHex(190), hash: word("b"), timestamp: uintHex(txTimestamp) };
      } else {
        assert.fail(`unexpected block tag ${tag}`);
      }
    } else if (request.method === "eth_getCode") {
      const target = request.params[0];
      result = target === AUTHORITY.distributor_address
        ? (runtimeDrift && provider === "secondary" ? "0x6002" : DISTRIBUTOR_CODE)
        : ANCHOR_CODE;
    } else if (request.method === "eth_call") {
      result = resultForCall(
        request.params[0].to,
        request.params[0].data,
        state,
        provider,
        { stateDrift },
      );
    } else if (request.method === "eth_getTransactionCount") {
      result = uintHex(nonceByTag[request.params[1]] ?? signerNonce);
    } else if (request.method === "eth_getTransactionByHash") {
      result = transactions.get(request.params[0])?.transaction ?? null;
    } else if (request.method === "eth_getTransactionReceipt") {
      result = transactions.get(request.params[0])?.receipt ?? null;
    } else {
      assert.fail(`unexpected RPC method ${request.method}`);
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

const RPC = {
  primaryRpc: "https://one.example/rpc?token=secret-one",
  secondaryRpc: "https://two.example/rpc?token=secret-two",
};

test("strict plan and RPC normalization rejects schema, role, calldata, and origin drift", () => {
  const valid = planReceipt();
  assert.equal(normalizeRoyaltyPhasePlanReceipt(valid).authority.owner, AUTHORITY.owner);

  const missingAnchorPin = structuredClone(valid);
  delete missingAnchorPin.reviewer_authority_genesis_acceptance_sha256;
  assert.throws(
    () => normalizeRoyaltyPhasePlanReceipt(missingAnchorPin),
    /exact schema/,
  );

  const wrongRole = structuredClone(valid);
  wrongRole.authority.qvl_verifier = wrongRole.authority.settlement_verifier;
  assert.throws(() => normalizeRoyaltyPhasePlanReceipt(wrongRole), /roles must be distinct/);

  const wrongCalldata = structuredClone(valid);
  wrongCalldata.transactions[0].calldata = "0x552d3bd4";
  assert.throws(() => normalizeRoyaltyPhasePlanReceipt(wrongCalldata), /calldata or digest/);

  assert.throws(
    () => normalizeRpcEndpoints("http://one.example", "https://two.example"),
    /must be HTTPS/,
  );
  assert.throws(
    () => normalizeRpcEndpoints("https://one.example/a", "https://one.example/b"),
    /distinct HTTPS origins/,
  );
});

test("pure state classifier covers fresh, pending, active-paused, active, and divergence", () => {
  const plan = planReceipt();
  for (const kind of [
    "fresh_empty",
    "phase1_exact_pending",
    "phase2_exact_active_paused",
    "phase2_exact_active_unpaused",
  ]) {
    assert.equal(classifyRoyaltyAuthorityState(authorityState(kind), plan), kind);
  }
  const drift = authorityState("fresh_empty");
  drift.executionPolicyAnchor.writer = address("e");
  assert.equal(classifyRoyaltyAuthorityState(drift, plan), "diverged");
});

test("classify proves one common finalized state without exposing RPC query credentials", async () => {
  const plan = planReceipt();
  const receipt = await classifyRoyaltyRelease({
    planReceipt: plan,
    ...RPC,
    fetchImpl: mockFetch({ kind: "fresh_empty", signerNonce: 7 }),
  });
  assert.equal(receipt.classification, "fresh_empty");
  assert.equal(receipt.executionScope, "full_plan");
  assert.equal(receipt.signerNonce, "7");
  assert.equal(receipt.planSha256, plan.plan_sha256);
  assert.deepEqual(receipt.providerConfirmations.map((entry) => entry.rpcOrigin), [
    "https://one.example",
    "https://two.example",
  ]);
  assert.doesNotMatch(JSON.stringify(receipt), /secret-one|secret-two/);

  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      ...RPC,
      fetchImpl: mockFetch({ kind: "fresh_empty", signerNonce: 7, stateDrift: true }),
    }),
    /disagree on finalized Royalty state/,
  );
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      ...RPC,
      fetchImpl: mockFetch({ kind: "fresh_empty", signerNonce: 7, runtimeDrift: true }),
    }),
    /runtime code differs/,
  );
});

test("every full-plan scope rejects pending or replacement use of its first reviewed nonce", async () => {
  const phaseOne = planReceipt();
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: phaseOne,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "fresh_empty",
        signerNonce: 7,
        nonceByTag: { pending: 8 },
      }),
    }),
    /first remaining reviewed nonce is already mined, pending, replaced/,
  );

  const phaseTwo = planReceipt({ phase: 2, mode: "activate_and_unpause", nonce: 8 });
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: phaseTwo,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase1_exact_pending",
        signerNonce: 8,
        nonceByTag: { latest: 9, pending: 9 },
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /first remaining reviewed nonce is already mined, pending, replaced/,
  );

  const recovery = {
    prior_phase_two_plan_sha256: digest("3"),
    finalized_recovery_evidence_sha256: digest("4"),
    activation_tx_hash: word("a"),
    activation_block_number: "180",
    activation_block_hash: word("7"),
    reverted_unpause_tx_hash: word("c"),
    reverted_unpause_block_number: "181",
    reverted_unpause_block_hash: word("8"),
    prior_unpause_nonce: "10",
  };
  const recoveryPlan = planReceipt({
    phase: 2,
    mode: "recover_reverted_unpause",
    nonce: 11,
    recovery,
  });
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: recoveryPlan,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 11,
        nonceByTag: { pending: 12 },
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /first remaining reviewed nonce is already mined, pending, replaced/,
  );
});

test("active-paused suffix requires the exact finalized activation and free unpause nonce", async () => {
  const plan = planReceipt({ phase: 2, mode: "activate_and_unpause", nonce: 8 });
  const reviewed = plan.transactions[0];
  const hash = word("a");
  const transactions = new Map([[hash, {
    transaction: rpcTransaction(reviewed, hash),
    receipt: rpcReceipt(reviewed, hash),
  }]]);
  const artifact = forgeArtifact(reviewed, hash);
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 9,
        transactions,
        txTimestamp: PHASE_TWO_TX_TIMESTAMP,
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /requires the prior activation Forge artifact/,
  );

  const receipt = await classifyRoyaltyRelease({
    planReceipt: plan,
    broadcastArtifact: artifact,
    ...RPC,
    fetchImpl: mockFetch({
      kind: "phase2_exact_active_paused",
      signerNonce: 9,
      transactions,
      txTimestamp: PHASE_TWO_TX_TIMESTAMP,
      finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
    }),
  });
  assert.equal(receipt.executionScope, "reviewed_unpause_suffix");
  assert.deepEqual(receipt.remainingTransactions, [plan.transactions[1]]);
  assert.equal(receipt.reviewedActivationReceipt.transactionHash, hash);

  const containsUnpause = structuredClone(artifact);
  containsUnpause.transactions.push({
    transactionType: "CALL",
    transaction: {
      from: plan.transactions[1].signer_address,
      to: plan.transactions[1].to,
      nonce: uintHex(plan.transactions[1].nonce),
      value: "0x0",
      input: plan.transactions[1].calldata,
      chainId: "0x14a34",
    },
    hash: word("c"),
  });
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      broadcastArtifact: containsUnpause,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 9,
        transactions,
        txTimestamp: PHASE_TWO_TX_TIMESTAMP,
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /unexpected transaction set/,
  );

  const revertedTransactions = new Map([[hash, {
    transaction: rpcTransaction(reviewed, hash),
    receipt: rpcReceipt(reviewed, hash, 190, 0, 0),
  }]]);
  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      broadcastArtifact: artifact,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 9,
        transactions: revertedTransactions,
        txTimestamp: PHASE_TWO_TX_TIMESTAMP,
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /differs from the reviewed finalized mutation/,
  );

  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      broadcastArtifact: artifact,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 9,
        nonceByTag: { pending: 10 },
        transactions,
        txTimestamp: PHASE_TWO_TX_TIMESTAMP,
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /already mined, pending, replaced/,
  );

  await assert.rejects(
    classifyRoyaltyRelease({
      planReceipt: plan,
      broadcastArtifact: artifact,
      ...RPC,
      fetchImpl: mockFetch({
        kind: "phase2_exact_active_paused",
        signerNonce: 10,
        transactions,
        txTimestamp: PHASE_TWO_TX_TIMESTAMP,
        finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
      }),
    }),
    /already mined, pending, replaced/,
  );
});

test("collect authenticates the Forge hash against both finalized providers", async () => {
  const plan = planReceipt();
  const reviewed = plan.transactions[0];
  const hash = word("a");
  const transactions = new Map([[hash, {
    transaction: rpcTransaction(reviewed, hash),
    receipt: rpcReceipt(reviewed, hash),
  }]]);
  const artifact = await collectRoyaltyReleaseFinality({
    planReceipt: plan,
    broadcastArtifact: forgeArtifact(reviewed, hash),
    ...RPC,
    fetchImpl: mockFetch({
      kind: "phase1_exact_pending",
      signerNonce: 8,
      transactions,
    }),
  });
  assert.equal(artifact.schema, "dnai.base-sepolia-royalty-finalized-authority.v1");
  assert.equal(artifact.transactionReceipts.length, 1);
  assert.equal(artifact.transactionReceipts[0].transactionHash, hash);
  assert.equal(artifact.transactionReceipts[0].status, "success");
  assert.equal(artifact.providerConfirmations.length, 2);

  const driftedForge = forgeArtifact(reviewed, hash);
  driftedForge.transactions[0].transaction.input = "0x552d3bd4";
  assert.throws(
    () => normalizeForgeBroadcastArtifact(driftedForge, plan.transactions),
    /differs from the reviewed/,
  );
});

test("recovery collect binds the successful activation, reverted unpause, and later unpause", async () => {
  const activationHash = word("a");
  const revertedHash = word("c");
  const currentHash = word("e");
  const activationBlockHash = word("7");
  const revertedBlockHash = word("8");
  const activationReviewed = {
    sequence: 0,
    action: "activate_authority_proposal",
    signer_address: AUTHORITY.owner,
    nonce: "9",
    to: AUTHORITY.distributor_address,
    value_wei: "0",
    calldata: actionCalldata("activate_authority_proposal", AUTHORITY),
  };
  activationReviewed.calldata_sha256 = rawSha256(
    Buffer.from(activationReviewed.calldata.slice(2), "hex"),
  );
  const revertedReviewed = {
    sequence: 1,
    action: "unpause",
    signer_address: AUTHORITY.owner,
    nonce: "10",
    to: AUTHORITY.distributor_address,
    value_wei: "0",
    calldata: actionCalldata("unpause", AUTHORITY),
  };
  revertedReviewed.calldata_sha256 = rawSha256(
    Buffer.from(revertedReviewed.calldata.slice(2), "hex"),
  );
  const activationReceipt = {
    sequence: 0,
    action: "activate_authority_proposal",
    sender: AUTHORITY.owner,
    target: AUTHORITY.distributor_address,
    nonce: "9",
    valueWei: "0",
    calldata: activationReviewed.calldata,
    calldataSha256: activationReviewed.calldata_sha256,
    transactionHash: activationHash,
    status: "success",
    blockNumber: 180,
    blockHash: activationBlockHash,
    blockTimestamp: 1_800_000,
    transactionIndex: 0,
  };
  const revertedUnpauseReceipt = {
    sequence: 1,
    action: "unpause",
    sender: AUTHORITY.owner,
    target: AUTHORITY.distributor_address,
    nonce: "10",
    valueWei: "0",
    calldata: revertedReviewed.calldata,
    calldataSha256: revertedReviewed.calldata_sha256,
    transactionHash: revertedHash,
    status: "reverted",
    blockNumber: 181,
    blockHash: revertedBlockHash,
    blockTimestamp: 1_810_000,
    transactionIndex: 0,
  };
  const evidenceCore = {
    schema: "dnai.base-sepolia-royalty-unpause-recovery-evidence.v1",
    evidenceSha256: digest("f"),
    priorPhaseTwoPlanSha256: digest("3"),
    activationReceipt,
    revertedUnpauseReceipt,
  };
  const recovery = {
    prior_phase_two_plan_sha256: evidenceCore.priorPhaseTwoPlanSha256,
    finalized_recovery_evidence_sha256:
      royaltyUnpauseRecoveryEvidenceSha256(evidenceCore),
    activation_tx_hash: activationHash,
    activation_block_number: "180",
    activation_block_hash: activationBlockHash,
    reverted_unpause_tx_hash: revertedHash,
    reverted_unpause_block_number: "181",
    reverted_unpause_block_hash: revertedBlockHash,
    prior_unpause_nonce: "10",
  };
  const plan = planReceipt({
    phase: 2,
    mode: "recover_reverted_unpause",
    nonce: 11,
    recovery,
  });
  const currentReviewed = plan.transactions[0];
  const transactions = new Map([
    [activationHash, {
      transaction: rpcTransaction(
        activationReviewed,
        activationHash,
        180,
        0,
        activationBlockHash,
      ),
      receipt: rpcReceipt(
        activationReviewed,
        activationHash,
        180,
        0,
        1,
        activationBlockHash,
      ),
    }],
    [revertedHash, {
      transaction: rpcTransaction(
        revertedReviewed,
        revertedHash,
        181,
        0,
        revertedBlockHash,
      ),
      receipt: rpcReceipt(
        revertedReviewed,
        revertedHash,
        181,
        0,
        0,
        revertedBlockHash,
      ),
    }],
    [currentHash, {
      transaction: rpcTransaction(currentReviewed, currentHash),
      receipt: rpcReceipt(currentReviewed, currentHash),
    }],
  ]);
  const blocks = new Map([
    [uintHex(180), {
      number: uintHex(180),
      hash: activationBlockHash,
      timestamp: uintHex(1_800_000),
    }],
    [uintHex(181), {
      number: uintHex(181),
      hash: revertedBlockHash,
      timestamp: uintHex(1_810_000),
    }],
  ]);
  const artifact = await collectRoyaltyReleaseFinality({
    planReceipt: plan,
    broadcastArtifact: forgeArtifact(currentReviewed, currentHash),
    ...RPC,
    fetchImpl: mockFetch({
      kind: "phase2_exact_active_unpaused",
      signerNonce: 12,
      transactions,
      blocks,
      txTimestamp: PHASE_TWO_TX_TIMESTAMP,
      finalizedTimestamp: PHASE_TWO_FINALIZED_TIMESTAMP,
    }),
  });
  assert.equal(
    artifact.phaseTwoRecoveryEvidence.evidenceSha256,
    recovery.finalized_recovery_evidence_sha256,
  );
  assert.equal(
    artifact.phaseTwoRecoveryEvidence.revertedUnpauseReceipt.status,
    "reverted",
  );
  assert.equal(artifact.transactionReceipts[0].transactionHash, currentHash);
});

test("dry-run proof admits only the classified remaining transaction slice", async () => {
  const plan = planReceipt();
  const classification = await classifyRoyaltyRelease({
    planReceipt: plan,
    ...RPC,
    fetchImpl: mockFetch({ kind: "fresh_empty", signerNonce: 7 }),
  });
  const dryRun = forgeArtifact(plan.transactions[0], word("a"), { includeHash: false });
  const receipt = verifyRoyaltyReleaseDryRun({
    planReceipt: plan,
    classification,
    broadcastArtifact: dryRun,
  });
  assert.equal(
    receipt.status,
    "dry_run_exactly_matches_classified_remaining_transactions",
  );
  assert.deepEqual(receipt.actions, ["propose_authority_binding"]);

  const extra = structuredClone(dryRun);
  extra.transactions.push(structuredClone(extra.transactions[0]));
  assert.throws(
    () => verifyRoyaltyReleaseDryRun({
      planReceipt: plan,
      classification,
      broadcastArtifact: extra,
    }),
    /unexpected transaction set/,
  );
});
