import assert from "node:assert/strict";
import test from "node:test";

import { ethereumKeccak256Hex } from "./ethereum-keccak.mjs";

test("Ethereum Keccak-256 matches the canonical empty and abc vectors", () => {
  assert.equal(
    ethereumKeccak256Hex(Buffer.alloc(0)),
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  );
  assert.equal(
    ethereumKeccak256Hex(Buffer.from("abc", "utf8")),
    "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
  );
});
