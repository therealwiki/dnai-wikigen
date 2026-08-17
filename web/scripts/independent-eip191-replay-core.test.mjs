import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  recoverIndependentEip191PersonalSigner,
  recoverIndependentEip191PersonalSignerFromRawDigest,
} from "./independent-eip191-replay-core.mjs";

const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const account = privateKeyToAccount(PRIVATE_KEY);

test("static recovery matches viem signing for UTF-8 personal messages", async () => {
  const message = "dnai-wikigen independent historical EIP-191 replay";
  const signature = (await account.signMessage({ message })).toLowerCase();
  assert.equal(
    recoverIndependentEip191PersonalSigner({ message, signature }),
    account.address.toLowerCase(),
  );
  assert.deepEqual(INDEPENDENT_EIP191_REPLAY_VERIFIER.message_modes, [
    "utf8_eip191_personal_sign",
    "raw_bytes32_eip191_personal_sign",
  ]);
  assert.equal(INDEPENDENT_EIP191_REPLAY_VERIFIER.network_or_rpc_required, false);
});

test("raw bytes32 recovery is explicit and cannot be confused with digest text", async () => {
  const digest = `0x${"ab".repeat(32)}`;
  const signature = (await account.signMessage({
    message: { raw: digest },
  })).toLowerCase();
  assert.equal(
    recoverIndependentEip191PersonalSignerFromRawDigest({ digest, signature }),
    account.address.toLowerCase(),
  );
  assert.notEqual(
    recoverIndependentEip191PersonalSigner({ message: digest, signature }),
    account.address.toLowerCase(),
  );
});

test("both canonical Ethereum recovery bits are supported", async () => {
  const seen = new Set();
  for (let index = 0; index < 64 && seen.size < 2; index += 1) {
    const message = `independent-recovery-bit-${index}`;
    const signature = (await account.signMessage({ message })).toLowerCase();
    seen.add(signature.slice(-2));
    assert.equal(
      recoverIndependentEip191PersonalSigner({ message, signature }),
      account.address.toLowerCase(),
    );
  }
  assert.deepEqual([...seen].sort(), ["1b", "1c"]);
});

test("malformed, high-s, and noncanonical recovery signatures fail closed", async () => {
  const message = "canonical-low-s-boundary";
  const signature = (await account.signMessage({ message })).toLowerCase();
  const n = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  );
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const highS = (n - s).toString(16).padStart(64, "0");
  const flippedV = signature.endsWith("1b") ? "1c" : "1b";
  const malleated = `${signature.slice(0, 66)}${highS}${flippedV}`;
  for (const invalid of [
    signature.toUpperCase(),
    `${signature.slice(0, -2)}00`,
    malleated,
    "0x1234",
  ]) {
    assert.throws(
      () => recoverIndependentEip191PersonalSigner({
        message,
        signature: invalid,
      }),
      /signature/i,
    );
  }
  assert.throws(
    () => recoverIndependentEip191PersonalSignerFromRawDigest({
      digest: `0x${"00".repeat(32)}`,
      signature,
    }),
    /nonzero lowercase bytes32/i,
  );
});

test("recovery boundaries use snapshotted own data and never an accessor or divergent Proxy get view", async () => {
  const message = "descriptor-snapshot-boundary";
  const signature = (await account.signMessage({ message })).toLowerCase();

  let getterCalls = 0;
  const accessorInput = { signature };
  Object.defineProperty(accessorInput, "message", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return message;
    },
  });
  assert.throws(
    () => recoverIndependentEip191PersonalSigner(accessorInput),
    /own data fields/i,
  );
  assert.equal(getterCalls, 0);

  const inheritedInput = Object.create({ message });
  Object.defineProperty(inheritedInput, "signature", {
    value: signature,
    enumerable: true,
  });
  assert.throws(
    () => recoverIndependentEip191PersonalSigner(inheritedInput),
    /custom prototype|exact schema/i,
  );

  let proxyGetCalls = 0;
  let proxyDescriptorCalls = 0;
  const descriptorView = { message, signature };
  const divergentProxy = new Proxy(descriptorView, {
    get() {
      proxyGetCalls += 1;
      return "attacker-controlled get view";
    },
    getOwnPropertyDescriptor(target, property) {
      proxyDescriptorCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.equal(
    recoverIndependentEip191PersonalSigner(divergentProxy),
    account.address.toLowerCase(),
  );
  assert.equal(proxyGetCalls, 0);
  assert.equal(proxyDescriptorCalls, 2);
});

test("adapter closure and exact package pins remain static", () => {
  const source = readFileSync(
    new URL("./independent-eip191-replay-core.mjs", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /\bviem\b|\bfetch\s*\(|import\s*\(|node:/);
  const packageJson = JSON.parse(readFileSync(
    new URL("../package.json", import.meta.url),
    "utf8",
  ));
  const lock = JSON.parse(readFileSync(
    new URL("../package-lock.json", import.meta.url),
    "utf8",
  ));
  assert.equal(packageJson.dependencies["@noble/curves"], "1.9.1");
  assert.equal(packageJson.dependencies["@noble/hashes"], "1.8.0");
  assert.deepEqual(
    lock.packages["node_modules/@noble/curves"],
    {
      version: "1.9.1",
      resolved: "https://registry.npmjs.org/@noble/curves/-/curves-1.9.1.tgz",
      integrity: INDEPENDENT_EIP191_REPLAY_VERIFIER.curves_integrity,
      license: "MIT",
      dependencies: { "@noble/hashes": "1.8.0" },
      engines: { node: "^14.21.3 || >=16" },
      funding: { url: "https://paulmillr.com/funding/" },
    },
  );
  assert.equal(
    lock.packages["node_modules/@noble/hashes"].integrity,
    INDEPENDENT_EIP191_REPLAY_VERIFIER.hashes_integrity,
  );
  assert.equal(lock.packages["node_modules/@noble/hashes"].version, "1.8.0");
});
