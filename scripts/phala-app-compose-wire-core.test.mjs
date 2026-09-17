import assert from "node:assert/strict";
import test from "node:test";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY, CVM_LAUNCH_DOMAINS, createPhalaDstackComposeHashInput,
} from "./cvm-launch-intent-core.mjs";
import { getComposeHash, provisionCvm } from "./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs";
import {
  PHALA_APP_COMPOSE_PRE_TRANSFORM_KEYS, PHALA_APP_COMPOSE_WIRE_KEYS,
  PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS,
  normalizePhalaPreTransformAppCompose, normalizePhalaWireAppCompose,
  projectPhalaAppComposeWire, phalaAppComposePreTransformHash,
  phalaAppComposeExpectedRuntimeHash, phalaWireAppComposeHash,
} from "./phala-app-compose-wire-core.mjs";

function fixture(domain = "main_runtime_cvm") {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  return createPhalaDstackComposeHashInput(policy.app_compose_candidate,
    "services:\n  synthetic:\n    image: example.invalid/a@sha256:" + "1".repeat(64) + "\n",
    policy.exact_allowed_environment_keys);
}

for (const domain of CVM_LAUNCH_DOMAINS) {
  test(`${domain}: exact pure projection matches actual pinned SDK wire and dstack hash offline`, async () => {
    const pre = fixture(domain);
    let wire;
    const observed = await provisionCvm({ post: async (requestPath, body) => {
      assert.equal(requestPath, "/cvms/provision");
      wire = body.compose_file;
      return { compose_hash: getComposeHash(wire) };
    } }, { name: pre.name, kms: "PHALA", kms_contract_id: "kc_Synthetic", compose_file: pre });
    assert.deepEqual(projectPhalaAppComposeWire(pre), wire);
    assert.deepEqual(Object.keys(pre), PHALA_APP_COMPOSE_PRE_TRANSFORM_KEYS);
    assert.deepEqual(Object.keys(projectPhalaAppComposeWire(pre)), PHALA_APP_COMPOSE_WIRE_KEYS);
    assert.equal(pre.tproxy_enabled, false);
    assert.equal(Object.hasOwn(wire, "tproxy_enabled"), false);
    assert.equal(phalaAppComposePreTransformHash(pre), getComposeHash(pre));
    assert.equal(phalaAppComposeExpectedRuntimeHash(pre), observed.compose_hash);
    assert.equal(phalaWireAppComposeHash(wire), observed.compose_hash);
    assert.notEqual(phalaAppComposePreTransformHash(pre), observed.compose_hash);
    assert.equal(wire.docker_compose_file, pre.docker_compose_file);
    assert.deepEqual(wire.allowed_envs, pre.allowed_envs);
  });
}

test("wire semantics never claim unauthenticated server normalization or staging evidence", () => {
  assert.equal(PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS.server_defaults_assumed, false);
  assert.equal(PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS.authenticated_staging_server_hash_equality_required, true);
  assert.equal(PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS.hash_normalize, false);
});

test("canonical projector is immutable, key-order independent, and exact-byte sensitive", () => {
  const value = fixture();
  const reordered = Object.fromEntries(Object.entries(value).reverse());
  assert.equal(phalaAppComposeExpectedRuntimeHash(reordered), phalaAppComposeExpectedRuntimeHash(value));
  assert.equal(Object.isFrozen(projectPhalaAppComposeWire(value).allowed_envs), true);
  assert.notEqual(phalaAppComposeExpectedRuntimeHash({ ...value, docker_compose_file: value.docker_compose_file + "\n" }),
    phalaAppComposeExpectedRuntimeHash(value));
  assert.deepEqual(normalizePhalaWireAppCompose(projectPhalaAppComposeWire(value)), projectPhalaAppComposeWire(value));
});

for (const [label, mutate] of [
  ["missing deprecated input", (value) => { delete value.tproxy_enabled; }],
  ["extra request-only member", (value) => { value.listed = false; }],
  ["unsorted environment keys", (value) => { value.allowed_envs.reverse(); }],
  ["duplicate environment key", (value) => { value.allowed_envs.push(value.allowed_envs[0]); }],
  ["invalid environment key", (value) => { value.allowed_envs = ["bad-key"]; }],
  ["nonstring environment key", (value) => { value.allowed_envs = [["KEY"]]; }],
  ["empty descriptor", (value) => { value.docker_compose_file = ""; }],
  ["oversized descriptor", (value) => { value.docker_compose_file = "a".repeat(200 * 1024 + 1); }],
  ["nonstring descriptor", (value) => { value.docker_compose_file = ["services: {}"]; }],
  ["runner drift", (value) => { value.runner = "bash"; }],
  ["manifest drift", (value) => { value.manifest_version = 1; }],
  ["invalid name", (value) => { value.name = "Example"; }],
  ["public logs", (value) => { value.public_logs = true; }],
  ["missing secure time", (value) => { delete value.secure_time; }],
  ["different tproxy branch", (value) => { value.tproxy_enabled = true; }],
  ["missing gateway", (value) => { delete value.gateway_enabled; }],
]) {
  test(`rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => normalizePhalaPreTransformAppCompose(value));
    assert.throws(() => phalaAppComposeExpectedRuntimeHash(value));
  });
}

test("wire hash rejects pre-transform input instead of accepting either meaning", () => {
  assert.throws(() => phalaWireAppComposeHash(fixture()), /fields are not exact/);
  assert.throws(() => phalaAppComposePreTransformHash(projectPhalaAppComposeWire(fixture())), /fields are not exact/);
});

test("accessors and proxies are rejected before any property access", () => {
  let invoked = false;
  const value = fixture();
  Object.defineProperty(value, "name", { enumerable: true, get() { invoked = true; return "test"; } });
  assert.throws(() => projectPhalaAppComposeWire(value), /accessors/);
  assert.equal(invoked, false);
  const proxy = new Proxy(fixture(), { get() { invoked = true; return true; } });
  assert.throws(() => projectPhalaAppComposeWire(proxy), /Proxy/);
  assert.equal(invoked, false);
});
