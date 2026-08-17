import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA,
  collectRoyaltyFinalizedHistoryEvidence,
  normalizeRoyaltyFinalizedHistoryEvidence,
  normalizeRoyaltyHistoryRpcEndpoints,
  readRoyaltyHistoryBoundedResponseText,
  royaltyHistoryContractConfigurationSha256,
  royaltyHistoryFullSuiteStateSha256,
  royaltyHistoryLatestStateRecheckSha256,
} from "./royalty-release-finalized-history-evidence.mjs";
import { syntheticRoyaltyFinalizedHistoryEvidence } from "./royalty-release-history-receipt.fixture.mjs";

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function rawDomainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(`${JSON.stringify(sorted(value), null, 2)}\n`, "utf8")
    .digest("hex")}`;
}

function refreshSuiteDigests(evidence, { raw = false } = {}) {
  const proof = evidence.collection_proof;
  const suiteSha256 = raw
    ? (suite) => rawDomainSha256(
      "dnai-wikigen/base-sepolia-royalty-full-suite-state/v1\0",
      suite,
    )
    : royaltyHistoryFullSuiteStateSha256;
  proof.primary_full_suite_state_sha256 = suiteSha256(proof.primary_full_suite_state);
  proof.secondary_full_suite_state_sha256 = suiteSha256(proof.secondary_full_suite_state);
  evidence.common_finalized_state.primary_state_sha256 =
    proof.primary_full_suite_state_sha256;
  evidence.common_finalized_state.secondary_state_sha256 =
    proof.secondary_full_suite_state_sha256;
  evidence.common_finalized_state.canonical_state_sha256 =
    proof.primary_full_suite_state_sha256;
  proof.latest_state_recheck_sha256 = raw
    ? rawDomainSha256(
      "dnai-wikigen/base-sepolia-royalty-latest-state-recheck/v1\0",
      {
        primary_finalized_head: proof.primary_finalized_head,
        secondary_finalized_head: proof.secondary_finalized_head,
        primary: proof.latest_primary_full_suite_state,
        secondary: proof.latest_secondary_full_suite_state,
      },
    )
    : royaltyHistoryLatestStateRecheckSha256(
      proof.latest_primary_full_suite_state,
      proof.latest_secondary_full_suite_state,
      proof.primary_finalized_head,
      proof.secondary_finalized_head,
    );
  evidence.common_finalized_state.latest_state_recheck_sha256 =
    proof.latest_state_recheck_sha256;
}

test("production evidence normalizes exact normal and recovery H-v2 projections", async () => {
  for (const executionMode of ["activate_and_unpause", "recover_reverted_unpause"]) {
    const evidence = await syntheticRoyaltyFinalizedHistoryEvidence({ executionMode });
    const normalized = normalizeRoyaltyFinalizedHistoryEvidence(evidence);
    assert.equal(normalized.schema, ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA);
    assert.equal(normalized.execution_mode, executionMode);
    assert.equal(normalized.contracts.length, 7);
    assert.equal(normalized.collection_proof.primary_full_suite_state
      .contract_configurations.length, 7);
  }
});

test("evidence rejects v1/disguised modes, contract drift, arbitrary configuration, and recheck pins", async () => {
  const base = await syntheticRoyaltyFinalizedHistoryEvidence();
  const rejected = (mutate, pattern) => {
    const value = structuredClone(base);
    mutate(value);
    assert.throws(() => normalizeRoyaltyFinalizedHistoryEvidence(value), pattern);
  };
  rejected((value) => {
    value.royalty_release_history.schema = "dnai.royalty-release-history.v1";
    delete value.royalty_release_history.execution_mode;
  }, /H v2|schema|execution/i);
  rejected((value) => { value.execution_mode = "recover_reverted_unpause"; }, /mode|schema|H v2/i);
  rejected((value) => { value.contracts.push(structuredClone(value.contracts[0])); }, /seven|suite|contract/i);
  rejected((value) => {
    value.collection_proof.primary_full_suite_state.contract_configurations[0]
      .getter_observations[0].result = `0x${"9".repeat(64)}`;
  }, /configuration|observations|disagree|control getter|malformed address/i);
  rejected((value) => {
    value.common_finalized_state.latest_state_recheck_sha256 =
      `sha256:${"8".repeat(64)}`;
  }, /recheck|proof/i);
  rejected((value) => {
    value.collection_proof.latest_secondary_full_suite_state.block_hash =
      `0x${"7".repeat(64)}`;
  }, /observations disagree|changed|suite/i);
  rejected((value) => {
    for (const field of [
      "primary_full_suite_state", "secondary_full_suite_state",
      "latest_primary_full_suite_state", "latest_secondary_full_suite_state",
    ]) {
      value.collection_proof[field].block_number += 123;
      value.collection_proof[field].block_hash = `0x${"7".repeat(64)}`;
    }
    refreshSuiteDigests(value);
  }, /checkpoint|H projection|observations disagree|suite/i);
  rejected((value) => {
    const proof = value.collection_proof;
    proof.primary_finalized_head.block_number -= 1;
    proof.primary_finalized_head.block_hash = `0x${"6".repeat(64)}`;
    proof.primary_finalized_head.block_timestamp -= 1;
    proof.primary_finalized_head_sha256 = rawDomainSha256(
      "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0",
      proof.primary_finalized_head,
    );
    refreshSuiteDigests(value, { raw: true });
  }, /checkpoint|full-suite observations disagree|finalized/i);
  rejected((value) => {
    for (const field of [
      "primary_full_suite_state", "secondary_full_suite_state",
      "latest_primary_full_suite_state", "latest_secondary_full_suite_state",
    ]) {
      const suite = value.collection_proof[field];
      const configuration = suite.contract_configurations[0];
      const observation = configuration.getter_observations.find(
        (entry) => entry.signature === "initialDeveloper()",
      );
      observation.result = "0x01";
      const core = structuredClone(configuration);
      delete core.configuration_sha256;
      configuration.configuration_sha256 =
        royaltyHistoryContractConfigurationSha256(core);
      suite.contracts[0].configuration_sha256 = configuration.configuration_sha256;
    }
    value.contracts[0].configuration_sha256 = value.collection_proof
      .primary_full_suite_state.contracts[0].configuration_sha256;
    refreshSuiteDigests(value, { raw: true });
  }, /ABI word|getter result|configuration/i);
});

test("configuration/full-suite/recheck digests are independently domain separated", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const proof = evidence.collection_proof;
  const configuration = structuredClone(
    proof.primary_full_suite_state.contract_configurations[0],
  );
  const recorded = configuration.configuration_sha256;
  delete configuration.configuration_sha256;
  assert.equal(royaltyHistoryContractConfigurationSha256(configuration), recorded);
  assert.equal(
    royaltyHistoryFullSuiteStateSha256(proof.primary_full_suite_state),
    proof.primary_full_suite_state_sha256,
  );
  assert.equal(
    royaltyHistoryLatestStateRecheckSha256(
      proof.latest_primary_full_suite_state,
      proof.latest_secondary_full_suite_state,
      proof.primary_finalized_head,
      proof.secondary_finalized_head,
    ),
    proof.latest_state_recheck_sha256,
  );
  assert.notEqual(recorded, proof.primary_full_suite_state_sha256);
  assert.notEqual(proof.primary_full_suite_state_sha256, proof.latest_state_recheck_sha256);
});

test("RPC authority normalization is HTTPS, distinct-origin, bounded, and credential-safe", () => {
  assert.deepEqual(
    normalizeRoyaltyHistoryRpcEndpoints(
      "https://primary.example/rpc/secret-a",
      "https://secondary.example/rpc/secret-b",
    ),
    {
      primary: {
        url: "https://primary.example/rpc/secret-a",
        origin: "https://primary.example",
        hostname: "primary.example",
      },
      secondary: {
        url: "https://secondary.example/rpc/secret-b",
        origin: "https://secondary.example",
        hostname: "secondary.example",
      },
    },
  );
  assert.throws(() => normalizeRoyaltyHistoryRpcEndpoints(
    "http://primary.example/rpc",
    "https://secondary.example/rpc",
  ), /HTTPS/);
  assert.throws(() => normalizeRoyaltyHistoryRpcEndpoints(
    "https://primary.example/a",
    "https://primary.example/b",
  ), /distinct/);
  assert.throws(() => normalizeRoyaltyHistoryRpcEndpoints(
    "https://primary.example:443/a",
    "https://primary.example:8443/b",
  ), /distinct/);
  assert.throws(() => normalizeRoyaltyHistoryRpcEndpoints(
    "https://user:password@primary.example/rpc",
    "https://secondary.example/rpc",
  ), (error) => {
    assert.doesNotMatch(error.message, /password/);
    return true;
  });
});

test("RPC bodies are cancelled while streaming once the byte cap is crossed", async () => {
  let cancelled = false;
  let emitted = 0;
  const body = new ReadableStream({
    pull(controller) {
      emitted += 1;
      controller.enqueue(new Uint8Array(128 * 1024));
      if (emitted > 32) controller.close();
    },
    cancel() { cancelled = true; },
  });
  await assert.rejects(
    readRoyaltyHistoryBoundedResponseText(new Response(body), "adversarial RPC"),
    /byte bound/,
  );
  assert.equal(cancelled, true);
});

test("collector fails before network when the ceremony ledger is mutable or unfinalized", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  let fetched = false;
  await assert.rejects(() => collectRoyaltyFinalizedHistoryEvidence({
    repositoryRoot: "/private/tmp/repo",
    sourceManifestPath: "/private/tmp/manifest.json",
    ledgerPath: "/private/tmp/ledger.json",
    evidenceRoot: "/private/tmp/evidence",
    lockRoot: "/private/tmp/locks",
    releaseSha: evidence.release_sha,
    deploymentIntentSha256: evidence.deployment_intent_sha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      evidence.reviewer_authority_genesis_acceptance_sha256,
    tinkerAccountBindingCeremonyReceiptSha256:
      evidence.tinker_account_binding_ceremony_receipt_sha256,
    royaltyReleasePrescription: evidence.royalty_release_prescriptive_authority,
    primaryRpc: "https://primary.example/rpc",
    secondaryRpc: "https://secondary.example/rpc",
    frozenLedgerLoader: () => ({
      replay: {
        finalized: false,
        ledger_mode: "0600",
        finalization_receipt_sha256: null,
      },
      ledger: {},
    }),
    fetchImpl: async () => { fetched = true; throw new Error("must not run"); },
  }), /finalized frozen ledger/);
  assert.equal(fetched, false);
});
