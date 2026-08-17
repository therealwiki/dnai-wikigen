import assert from "node:assert/strict";
import test from "node:test";

import {
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
  CVM_MAIN_DISABLED_PROFILE_POLICY,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
  CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA,
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS,
  PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH,
  accountGenesisActivationSigningMessage,
  buildPhalaAccountGenesisCompletion,
  normalizePhalaAccountGenesisActivationAuthority,
  normalizePhalaAccountGenesisCompletion,
  normalizePhalaLiveDealProfileActivationGate,
  phalaAccountGenesisActivationAuthoritySha256,
  phalaAccountGenesisCompletionSha256,
} from "./phala-main-profile-activation-core.mjs";
import {
  syntheticPhalaAccountGenesisFixture,
} from "./phala-main-profile-activation.fixture.mjs";

function clone(value) {
  return structuredClone(value);
}

test("production profile policy is a complete four-transition replacement sequence", () => {
  assert.deepEqual(CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS, [
    {
      sequence: 1,
      name: "account_genesis_start",
      from: CVM_MAIN_DISABLED_PROFILE_POLICY,
      to: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
      one_shot: true,
      live_traffic_after_transition: false,
    },
    {
      sequence: 2,
      name: "account_genesis_retire",
      from: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
      to: CVM_MAIN_DISABLED_PROFILE_POLICY,
      one_shot: true,
      live_traffic_after_transition: false,
    },
    {
      sequence: 3,
      name: "nonlive_runtime_start",
      from: CVM_MAIN_DISABLED_PROFILE_POLICY,
      to: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
      one_shot: false,
      live_traffic_after_transition: false,
    },
    {
      sequence: 4,
      name: "deal_runtime_start",
      from: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
      to: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
      one_shot: false,
      live_traffic_after_transition: false,
    },
  ]);
  assert.equal(
    CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY.compose_profiles_value,
    "mailbox-genesis,tinker-account-genesis",
  );
  assert.equal(
    CVM_MAIN_LIVE_DEAL_PROFILE_POLICY.compose_profiles_value,
    "arena-runtime,collaboration-execution,compute-execution,deal-settlement,review-operations",
  );
});

test("signed account-genesis authority binds two reviewers and exact start/retire transitions", () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  const normalized = normalizePhalaAccountGenesisActivationAuthority(
    fixture.authority,
    fixture.authorityOptions,
  );
  assert.equal(normalized.live_traffic_authorized, false);
  assert.equal(normalized.automatic_retry_authorized, false);
  assert.deepEqual(
    normalized.transition_sequence,
    CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS.slice(0, 2),
  );
  const { signatures: _signatures, ...authorityBody } = fixture.authority;
  assert.match(
    accountGenesisActivationSigningMessage(authorityBody),
    /^dnai-wikigen phala account genesis activation v1:sha256:/,
  );
  assert.equal(
    phalaAccountGenesisActivationAuthoritySha256(
      normalized,
      fixture.authorityOptions,
    ),
    fixture.completionExpected.genesis_authorization_sha256,
  );
});

for (const [name, mutate, pattern] of [
  [
    "profile widening",
    (value) => {
      value.transition_sequence[0].to.profile_names.push("deal-settlement");
      value.transition_sequence[0].to.compose_profiles_value +=
        ",deal-settlement";
    },
    /omitted, reordered, substituted, or widened/,
  ],
  [
    "transition reordering",
    (value) => {
      value.transition_sequence.reverse();
    },
    /transition order or truth boundary drifted/,
  ],
  [
    "reviewer substitution",
    (value) => {
      value.signatures[0].address = `0x${"3".repeat(40)}`;
    },
    /exact reviewer order/,
  ],
  [
    "additive unreviewed field",
    (value) => {
      value.operator_override = true;
    },
    /exactly the frozen fields/,
  ],
]) {
  test(`account-genesis authority rejects ${name}`, () => {
    const fixture = syntheticPhalaAccountGenesisFixture();
    const value = clone(fixture.authority);
    mutate(value);
    assert.throws(
      () => normalizePhalaAccountGenesisActivationAuthority(
        value,
        fixture.authorityOptions,
      ),
      pattern,
    );
  });
}

test("account-genesis authority rejects an otherwise valid authority without five-minute headroom", () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  assert.throws(
    () => normalizePhalaAccountGenesisActivationAuthority(
      fixture.authority,
      {
        ...fixture.authorityOptions,
        checkedAt: Date.parse("2026-07-23T10:41:00Z") / 1_000,
      },
    ),
    /stale or outside current reviewer authority/,
  );
});

test("bounded account-genesis completion binds all five create-only artifacts", () => {
  const fixture = syntheticPhalaAccountGenesisFixture();
  const normalized = normalizePhalaAccountGenesisCompletion(
    fixture.completion,
    { expected: fixture.completionExpected },
  );
  assert.equal(normalized.live_traffic_authorized, false);
  assert.equal(normalized.automatic_retry_authorized, false);
  assert.equal(
    normalized.handoff_retirement
      .handoff_path_absent_after_directory_fsync,
    true,
  );
  assert.match(
    phalaAccountGenesisCompletionSha256(normalized, {
      expected: fixture.completionExpected,
    }),
    /^sha256:[0-9a-f]{64}$/,
  );
});

for (const [name, mutate, pattern] of [
  [
    "mailbox raw-secret egress",
    (value) => {
      value.mailboxReceipt.raw_secret_egress = true;
    },
    /mailbox-genesis raw_secret_egress/,
  ],
  [
    "account retry permission",
    (value) => {
      value.accountRetirement.retry_permitted = true;
    },
    /account retirement retry marker/,
  ],
  [
    "missing handoff unlink proof",
    (value) => {
      value.handoffRetirement
        .handoff_path_absent_after_directory_fsync = false;
    },
    /handoff unlink proof/,
  ],
  [
    "runtime substitution",
    (value) => {
      value.accountReceipt.runtime.compose_hash = "f".repeat(64);
    },
    /runtime differs from the exact main CVM/,
  ],
  [
    "retirement before account completion",
    (value) => {
      value.accountRetirement.retired_at = 99;
    },
    /evidence ordering is invalid/,
  ],
]) {
  test(`account-genesis completion rejects ${name}`, () => {
    const fixture = syntheticPhalaAccountGenesisFixture();
    const boundedEvidence = clone(fixture.evidence);
    mutate(boundedEvidence);
    assert.throws(
      () => buildPhalaAccountGenesisCompletion({
        ...boundedEvidence,
        expected: fixture.completionExpected,
      }),
      pattern,
    );
  });
}
