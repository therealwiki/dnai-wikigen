import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import https from "node:https";
import { Readable } from "node:stream";
import test from "node:test";

function fakeHttpsRequest(options, callback) {
  const request = new EventEmitter();
  request.destroy = () => {};
  request.end = (body) => {
    const payload = JSON.parse(Buffer.from(body).toString("utf8"));
    const hash = `0x${"ab".repeat(32)}`;
    let result;
    if (payload.method === "eth_chainId") {
      result = "0x14a34";
    } else if (payload.method === "eth_getBlockByNumber") {
      result = { number: "0x7b", hash };
    } else {
      throw new Error(`unexpected method ${payload.method}`);
    }
    const response = Readable.from([
      Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result })),
    ]);
    response.statusCode = 200;
    response.headers = { "content-type": "application/json" };
    queueMicrotask(() => callback(response));
  };
  request.options = options;
  return request;
}

test("production collector privately brands one internally timed independent dual-RPC finalized head", async () => {
  const originalRequest = https.request;
  https.request = fakeHttpsRequest;
  try {
    const authority = await import(
      `./phala-production-finalized-readiness.mjs?mock=${Date.now()}`
    );
    const before = Date.now();
    const receipt = await authority.collectProductionFinalizedReadiness({
      primaryRpcUrl: "https://base-primary.example/rpc/private-a",
      secondaryRpcUrl: "https://base-secondary.example/rpc/private-b",
    });
    const after = Date.now();
    assert.equal(receipt.chain_id, 84_532);
    assert.equal(receipt.common_finalized_block_number, 123);
    assert.equal(receipt.common_finalized_block_hash, `0x${"ab".repeat(32)}`);
    assert.ok(Date.parse(receipt.checked_at) >= before);
    assert.ok(Date.parse(receipt.checked_at) <= after);
    assert.equal(
      Date.parse(receipt.expires_at) - Date.parse(receipt.checked_at),
      authority.PHALA_PRODUCTION_FINALIZED_READINESS_LIFETIME_MS,
    );
    assert.equal(JSON.stringify(receipt).includes("private-a"), false);
    assert.equal(JSON.stringify(receipt).includes("private-b"), false);
    assert.equal(
      authority.assertFreshProductionFinalizedReadiness(receipt),
      receipt,
    );
    assert.match(
      authority.productionFinalizedReadinessSha256(receipt),
      /^sha256:[0-9a-f]{64}$/,
    );

    const clone = structuredClone(receipt);
    assert.deepEqual(
      authority.normalizeProductionFinalizedReadiness(clone),
      receipt,
    );
    assert.throws(
      () => authority.assertFreshProductionFinalizedReadiness(clone),
      /privately branded/,
    );
    const tampered = structuredClone(receipt);
    tampered.common_finalized_block_number += 1;
    assert.throws(
      () => authority.assertFreshProductionFinalizedReadiness(tampered),
      /privately branded|digest/,
    );
  } finally {
    https.request = originalRequest;
  }
});

test("production collector rejects non-HTTPS, same-origin, callback, and clock injection surfaces", async () => {
  const authority = await import("./phala-production-finalized-readiness.mjs");
  await assert.rejects(
    authority.collectProductionFinalizedReadiness({
      primaryRpcUrl: "http://base-primary.example/rpc",
      secondaryRpcUrl: "https://base-secondary.example/rpc",
    }),
    /HTTPS/,
  );
  await assert.rejects(
    authority.collectProductionFinalizedReadiness({
      primaryRpcUrl: "https://same.example/one",
      secondaryRpcUrl: "https://same.example/two",
    }),
    /independent/,
  );
  for (const extra of [
    { nowMs: Date.now() },
    { request: fakeHttpsRequest },
    { client: {} },
  ]) {
    await assert.rejects(
      authority.collectProductionFinalizedReadiness({
        primaryRpcUrl: "https://base-primary.example/rpc",
        secondaryRpcUrl: "https://base-secondary.example/rpc",
        ...extra,
      }),
      /exactly the frozen fields/,
    );
  }
});

test("normalization rejects accessors before reading receipt fields", async () => {
  const authority = await import("./phala-production-finalized-readiness.mjs");
  const poison = {};
  Object.defineProperty(poison, "schema", {
    enumerable: true,
    get() {
      throw new Error("accessor executed");
    },
  });
  assert.throws(
    () => authority.normalizeProductionFinalizedReadiness(poison),
    /canonical plain data|accessor/i,
  );
});
