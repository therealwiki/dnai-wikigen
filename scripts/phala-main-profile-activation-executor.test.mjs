import assert from "node:assert/strict";
import test from "node:test";

import {
  CVM_MAIN_DISABLED_PROFILE_POLICY,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA,
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS,
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH,
  normalizePhalaLiveDealProfileActivationGate,
  phalaAccountGenesisCompletionSha256,
} from "./phala-main-profile-activation-core.mjs";
import {
  executePhalaAccountGenesisProfileSequenceWithTestAdapter,
  executePhalaLiveDealProfileTransitionWithTestAdapter,
  executeProductionPhalaAccountGenesisProfileSequence,
} from "./phala-main-profile-activation-executor.mjs";
import {
  syntheticPhalaAccountGenesisFixture,
} from "./phala-main-profile-activation.fixture.mjs";

function clone(value) {
  return structuredClone(value);
}

function successfulMutation({ from, name, to }) {
  return {
    mutation_name: name,
    from_profile: from,
    to_profile: to,
    post_restart_target_matched: true,
    attestation_quote_present: true,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  };
}

test("account-genesis executor performs start, evidence validation, and mandatory retirement", async () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  const calls = [];
  const result =
    await executePhalaAccountGenesisProfileSequenceWithTestAdapter({
      accountGenesisAuthority: fixture.authority,
      accountGenesisAuthorityOptions: fixture.authorityOptions,
      accountGenesisExpected: fixture.completionExpected,
      collectEvidence: async () => clone(fixture.evidence),
    }, {
      mutate: async (input) => {
        calls.push(input.name);
        return successfulMutation(input);
      },
    });
  assert.deepEqual(calls, [
    "account_genesis_start",
    "account_genesis_retire",
  ]);
  assert.equal(
    result.status,
    "account_genesis_completed_and_profiles_retired_non_live",
  );
  assert.deepEqual(result.terminal_profile, CVM_MAIN_DISABLED_PROFILE_POLICY);
  assert.equal(result.private_shares_present_after_retirement, false);
  assert.equal(result.live_traffic_authorized, false);
});

test("account-genesis executor attempts retirement even when start is ambiguous", async () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  const calls = [];
  await assert.rejects(
    executePhalaAccountGenesisProfileSequenceWithTestAdapter({
      accountGenesisAuthority: fixture.authority,
      accountGenesisAuthorityOptions: fixture.authorityOptions,
      accountGenesisExpected: fixture.completionExpected,
      collectEvidence: async () => {
        throw new Error("evidence must not run");
      },
    }, {
      mutate: async (input) => {
        calls.push(input.name);
        if (input.name === "account_genesis_start") {
          throw new Error("ambiguous start observation");
        }
        return successfulMutation(input);
      },
    }),
    /ambiguous start observation/,
  );
  assert.deepEqual(calls, [
    "account_genesis_start",
    "account_genesis_retire",
  ]);
});

test("account-genesis executor requires explicit reconciliation when retirement is ambiguous", async () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  await assert.rejects(
    executePhalaAccountGenesisProfileSequenceWithTestAdapter({
      accountGenesisAuthority: fixture.authority,
      accountGenesisAuthorityOptions: fixture.authorityOptions,
      accountGenesisExpected: fixture.completionExpected,
      collectEvidence: async () => clone(fixture.evidence),
    }, {
      mutate: async (input) => {
        if (input.name === "account_genesis_retire") {
          throw new Error("restart response lost");
        }
        return successfulMutation(input);
      },
    }),
    /requires explicit reconciliation:restart response lost/,
  );
});

test("production account-genesis path rejects caller-supplied signature verifier and clock", async () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  await assert.rejects(
    executeProductionPhalaAccountGenesisProfileSequence({
      accountGenesisAuthorityOptions: fixture.authorityOptions,
    }),
    /production account-genesis authority options must contain exactly/,
  );
});

test("live-deal executor rejects a merely well-shaped, unproven gate", async () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  const forged = normalizePhalaLiveDealProfileActivationGate({
    schema: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA,
    status: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS,
    truth_status: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH,
    release_sha: fixture.completionExpected.release_sha,
    chain_id: 84_532,
    target: fixture.target,
    from_profile: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    to_profile: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
    live_activation_authority_sha256: `sha256:${"1".repeat(64)}`,
    nonlive_activation_execution_receipt_sha256:
      `sha256:${"2".repeat(64)}`,
    account_genesis_completion_sha256:
      phalaAccountGenesisCompletionSha256(fixture.completion, {
        expected: fixture.completionExpected,
      }),
    diligence_release_gate_sha256: `sha256:${"3".repeat(64)}`,
    diligence_finalized_through_block: 123,
    mutation_performed: false,
    post_restart_service_presence_verified: false,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
  let called = false;
  await assert.rejects(
    executePhalaLiveDealProfileTransitionWithTestAdapter(
      { gate: forged },
      {
        mutate: async () => {
          called = true;
          throw new Error("must not mutate");
        },
      },
    ),
    /locally derived live-deal gate/,
  );
  assert.equal(called, false);
});
