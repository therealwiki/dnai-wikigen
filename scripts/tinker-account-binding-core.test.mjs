import assert from "node:assert/strict";
import test from "node:test";

import {
  TINKER_ACCOUNT_BINDING_CHAIN_ID,
  TINKER_ACCOUNT_BINDING_SCHEMA,
  TINKER_ACCOUNT_BINDING_TYPE,
  TINKER_ACCOUNT_BINDING_TYPEHASH,
  TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
  TINKER_PROVIDER_NAMESPACE,
  TINKER_PROVIDER_NAMESPACE_LABEL,
  deriveTinkerAccountBindingRoot,
  deriveTinkerAccountCommitment,
} from "./tinker-account-binding-core.mjs";

const ROOT_ONE = `0x${"00".repeat(31)}01`;

test("Tinker account binding constants freeze the exact provider domain", () => {
  assert.equal(TINKER_ACCOUNT_BINDING_SCHEMA, "dnai.tinker-account-binding.v1");
  assert.equal(
    TINKER_ACCOUNT_BINDING_TYPE,
    "DnaiTinkerAccountBindingV1(uint256 chainId,bytes32 providerNamespace,bytes32 bindingRoot)",
  );
  assert.equal(TINKER_PROVIDER_NAMESPACE_LABEL, "thinking-machines/tinker");
  assert.equal(TINKER_ACCOUNT_BINDING_CHAIN_ID, 84_532n);
  assert.equal(
    TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
    "dnai-wikigen/tinker-account-binding/v1",
  );
  assert.match(TINKER_ACCOUNT_BINDING_TYPEHASH, /^0x[0-9a-f]{64}$/);
  assert.match(TINKER_PROVIDER_NAMESPACE, /^0x[0-9a-f]{64}$/);
});

test("Tinker account binding root requires two distinct shares and ignores input order", () => {
  const first = Buffer.alloc(32, 0x11);
  const second = Buffer.alloc(32, 0x22);
  const root = deriveTinkerAccountBindingRoot([first, second]);
  assert.equal(root.length, 32);
  assert.notDeepEqual(root, Buffer.alloc(32));
  assert.deepEqual(root, deriveTinkerAccountBindingRoot([second, first]));
  assert.equal(
    deriveTinkerAccountCommitment(root),
    "0x30f8a29b35be70acdb3eb4f513dc60f3f1bdc3c62aa5dbd3d53738a824eb04c8",
  );
});

test("Tinker account binding has one frozen cross-language known answer", () => {
  assert.equal(
    deriveTinkerAccountCommitment(ROOT_ONE),
    "0xa5c3b464917302dc58881695681975aea0bfbac6d3ebc3c7aab27854c64130d9",
  );
});

test("Tinker account binding is separated by root and chain", () => {
  const rootTwo = `0x${"00".repeat(31)}02`;
  assert.notEqual(
    deriveTinkerAccountCommitment(ROOT_ONE),
    deriveTinkerAccountCommitment(rootTwo),
  );
  assert.notEqual(
    deriveTinkerAccountCommitment(ROOT_ONE),
    deriveTinkerAccountCommitment(ROOT_ONE, { chainId: 1n }),
  );
});

test("Tinker account binding rejects absent, zero, malformed, and unsafe roots", () => {
  for (const value of [
    undefined,
    "",
    `0x${"00".repeat(32)}`,
    `0X${"11".repeat(32)}`,
    `0x${"AA".repeat(32)}`,
    `0x${"11".repeat(31)}`,
    Buffer.alloc(31, 1),
    Buffer.alloc(32),
  ]) {
    assert.throws(() => deriveTinkerAccountCommitment(value), /binding root/);
  }
  for (const chainId of [
    0,
    -1,
    true,
    "1",
    "not-a-chain",
    Number.MAX_SAFE_INTEGER + 1,
    1n << 256n,
  ]) {
    assert.throws(
      () => deriveTinkerAccountCommitment(ROOT_ONE, { chainId }),
      /chain id/,
    );
  }
  assert.throws(() => deriveTinkerAccountBindingRoot([]), /exactly two/);
  assert.throws(
    () => deriveTinkerAccountBindingRoot([Buffer.alloc(32, 1), Buffer.alloc(32, 1)]),
    /distinct/,
  );
  assert.throws(
    () => deriveTinkerAccountBindingRoot([Buffer.alloc(31, 1), Buffer.alloc(32, 2)]),
    /share\[0\]/,
  );
});
