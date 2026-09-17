import assert from "node:assert/strict";
import test from "node:test";

import {
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture as currentFixture,
} from "./current-cvm-authority-v5.fixture.mjs";
import {
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture as historicalV4Fixture,
} from "./current-cvm-authority-v4.fixture.mjs";
import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture as historicalV3Fixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import * as historicalV4 from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import * as historicalV3 from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v5-core.mjs";

test("release v5 binds descriptor v3's exact expected runtime hashes, not candidate audit hashes", () => {
  const authority = currentFixture();
  assert.equal(PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
    "dnai.phala-seven-cvm-release-verification-authority.v5");
  assert.equal(authority.cvm_descriptor_runtime_authority.schema, "dnai.cvm-descriptor-runtime-authority.v3");
  for (const descriptor of authority.descriptors) {
    const runtime = authority.cvm_descriptor_runtime_authority;
    assert.equal(descriptor.compose_hash, runtime.app_compose_hash_by_domain[descriptor.domain]);
    assert.notEqual(descriptor.compose_hash, runtime.pre_transform_app_compose_hash_by_domain[descriptor.domain]);
  }
  assert.deepEqual(normalizePhalaSevenCvmReleaseVerificationAuthority(
    JSON.parse(canonicalPhalaSevenCvmReleaseVerificationAuthorityText(authority))), authority);
  assert.match(phalaSevenCvmReleaseVerificationAuthoritySha256(authority), /^sha256:[0-9a-f]{64}$/);
  assert.equal(Object.isFrozen(authority.cvm_descriptor_runtime_authority.compose_hash_semantics), true);
});

test("historical release v3/v4 retain their own schema/digest normalizers and cannot become current by relabeling", () => {
  for (const [fixture, module, schema] of [
    [historicalV3Fixture, historicalV3, "dnai.phala-seven-cvm-release-verification-authority.v3"],
    [historicalV4Fixture, historicalV4, "dnai.phala-seven-cvm-release-verification-authority.v4"],
  ]) {
    const historical = fixture();
    assert.equal(module.normalizePhalaSevenCvmReleaseVerificationAuthority(historical).schema, schema);
    assert.match(module.phalaSevenCvmReleaseVerificationAuthoritySha256(historical), /^sha256:[0-9a-f]{64}$/);
    assert.throws(() => normalizePhalaSevenCvmReleaseVerificationAuthority(historical));
    const relabeled = structuredClone(historical);
    relabeled.schema = PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
    assert.throws(() => normalizePhalaSevenCvmReleaseVerificationAuthority(relabeled));
  }
});

for (const [label, mutate] of [
  ["candidate hash substituted for observed runtime", (value) => {
    value.descriptors[0].compose_hash = value.cvm_descriptor_runtime_authority
      .pre_transform_app_compose_hash_by_domain[value.descriptors[0].domain];
  }],
  ["descriptor v2 relabel", (value) => { value.cvm_descriptor_runtime_authority.schema = "dnai.cvm-descriptor-runtime-authority.v2"; }],
  ["missing audit hash map", (value) => { delete value.cvm_descriptor_runtime_authority.pre_transform_app_compose_hash_by_domain; }],
  ["wire transform drift", (value) => { value.cvm_descriptor_runtime_authority.compose_hash_semantics.transform_rule = "no_transform"; }],
  ["assumed server defaults", (value) => { value.cvm_descriptor_runtime_authority.compose_hash_semantics.server_defaults_assumed = true; }],
  ["current release downgraded to v4", (value) => { value.schema = "dnai.phala-seven-cvm-release-verification-authority.v4"; }],
]) {
  test(`release v5 rejects ${label}`, () => {
    const value = structuredClone(currentFixture());
    mutate(value);
    assert.throws(() => normalizePhalaSevenCvmReleaseVerificationAuthority(value));
  });
}
