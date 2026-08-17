import assert from "node:assert/strict";
import test from "node:test";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

test("canonical authority graph recursively freezes plain dense JSON data", () => {
  const value = { rows: [{ id: "one", hashes: ["a", "b"] }] };
  assert.equal(deepFreezeCanonicalPlainDataGraph(value), value);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.rows), true);
  assert.equal(Object.isFrozen(value.rows[0]), true);
  assert.equal(Object.isFrozen(value.rows[0].hashes), true);
  assert.throws(() => value.rows.push({}), TypeError);
  assert.throws(() => { value.rows[0].id = "two"; }, TypeError);
});

test("canonical authority graph rejects accessors, symbols, prototypes, sparse arrays, buffers, and cycles", () => {
  const accessor = {};
  Object.defineProperty(accessor, "value", { enumerable: true, get: () => "x" });
  const symbol = { ok: true };
  symbol[Symbol("hidden")] = true;
  const sparse = [];
  sparse.length = 2;
  sparse[1] = "x";
  const cycle = {};
  cycle.self = cycle;
  for (const value of [
    accessor,
    symbol,
    Object.create({ inherited: true }),
    sparse,
    Buffer.from("secret"),
    cycle,
  ]) {
    assert.throws(() => assertCanonicalPlainDataGraph(value));
  }
});

test("canonical authority graph rejects live and revoked Proxies without invoking traps", () => {
  let trapCalls = 0;
  const handler = new Proxy({}, {
    get(_target, trapName) {
      return () => {
        trapCalls += 1;
        throw new Error(`Proxy trap must not run: ${String(trapName)}`);
      };
    },
  });
  const liveProxy = new Proxy({ reviewed: true }, handler);
  assert.throws(
    () => assertCanonicalPlainDataGraph(liveProxy),
    /canonical plain-data graph: Proxy objects are forbidden/,
  );
  assert.equal(trapCalls, 0);

  const revocable = Proxy.revocable({ reviewed: true }, {});
  revocable.revoke();
  assert.throws(
    () => deepFreezeCanonicalPlainDataGraph(revocable.proxy),
    /canonical plain-data graph: Proxy objects are forbidden/,
  );
});
