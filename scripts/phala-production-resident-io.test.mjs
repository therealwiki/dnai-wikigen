import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  assertNewResidentPrivateDirectoryPath,
  canonicalResidentJsonText,
  preflightResidentBoundFile,
  readStableCanonicalResident0600Json,
  residentRawSha256,
  waitForPinnedCanonicalResident0600Json,
} from "./phala-production-resident-io.mjs";

function privateRoot(t) {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-resident-io-")),
  );
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function write(root, basename, bytes, mode = 0o600) {
  const filePath = path.join(root, basename);
  fs.writeFileSync(filePath, bytes, { mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

test("stable resident input requires exact canonical owner-0600 single-link bytes", (t) => {
  const root = privateRoot(t);
  const value = { z: [3, { b: false, a: true }], a: "bound" };
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  const valid = write(root, "valid.json", bytes);
  assert.deepEqual(
    readStableCanonicalResident0600Json(valid, "valid resident input").value,
    value,
  );

  const writable = write(root, "writable.json", bytes, 0o644);
  assert.throws(
    () => readStableCanonicalResident0600Json(writable, "writable input"),
    /exact-mode-0600/,
  );
  const noncanonical = write(
    root,
    "noncanonical.json",
    Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"),
  );
  assert.throws(
    () => readStableCanonicalResident0600Json(noncanonical, "noncanonical input"),
    /recursively sorted/,
  );
  const hardlink = path.join(root, "hardlink.json");
  fs.linkSync(valid, hardlink);
  assert.throws(
    () => readStableCanonicalResident0600Json(valid, "hard-linked input"),
    /single-link/,
  );
  const symlink = path.join(root, "symlink.json");
  fs.symlinkSync(writable, symlink);
  assert.throws(
    () => readStableCanonicalResident0600Json(symlink, "symlink input"),
    /canonical and symlink-free/,
  );
});

test("bound-file preflight authenticates digest, mode, and identity before launch", (t) => {
  const root = privateRoot(t);
  const bytes = Buffer.from("{\"private\":true}\n", "utf8");
  const filePath = write(root, "phase.json", bytes);
  const binding = { path: filePath, sha256: residentRawSha256(bytes) };
  assert.deepEqual(
    preflightResidentBoundFile(binding, "phase", { exactMode: 0o600 }).bytes,
    bytes,
  );
  assert.throws(
    () => preflightResidentBoundFile(
      { ...binding, sha256: `sha256:${"ab".repeat(32)}` },
      "phase",
      { exactMode: 0o600 },
    ),
    /bytes or file identity changed/,
  );
  fs.chmodSync(filePath, 0o400);
  assert.throws(
    () => preflightResidentBoundFile(binding, "phase", { exactMode: 0o600 }),
    /file posture/,
  );
});

test("new private exchange paths require a new child of an exact-0700 parent", (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "exchange");
  assert.equal(
    assertNewResidentPrivateDirectoryPath(exchange, "test exchange"),
    exchange,
  );
  fs.mkdirSync(exchange, { mode: 0o700 });
  assert.throws(
    () => assertNewResidentPrivateDirectoryPath(exchange, "test exchange"),
    /must not already exist/,
  );
  const publicParent = path.join(root, "public-parent");
  fs.mkdirSync(publicParent, { mode: 0o755 });
  assert.throws(
    () => assertNewResidentPrivateDirectoryPath(
      path.join(publicParent, "child"),
      "unsafe exchange",
    ),
    /exact-mode-0700/,
  );
});

test("pinned file handoff waits only for absence and rejects malformed arrivals", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const value = { schema: "dnai.test-handoff.v1", ready: true };
  const timer = setTimeout(() => {
    createExclusivePhalaPinnedPrivateFile(
      handle,
      "response.json",
      Buffer.from(canonicalResidentJsonText(value), "utf8"),
      { mode: 0o600, maximum: 64 * 1024 },
    );
  }, 25);
  t.after(() => clearTimeout(timer));
  const observed = await waitForPinnedCanonicalResident0600Json({
    handle,
    fileName: "response.json",
    label: "test response",
    deadlineMs: Date.now() + 1_000,
    pollIntervalMilliseconds: 25,
    maximum: 64 * 1024,
  });
  assert.deepEqual(observed.value, value);

  createExclusivePhalaPinnedPrivateFile(
    handle,
    "malformed.json",
    Buffer.from('{"z":1,"a":2}\n', "utf8"),
    { mode: 0o600, maximum: 64 * 1024 },
  );
  await assert.rejects(
    waitForPinnedCanonicalResident0600Json({
      handle,
      fileName: "malformed.json",
      label: "malformed response",
      deadlineMs: Date.now() + 1_000,
      pollIntervalMilliseconds: 25,
      maximum: 64 * 1024,
    }),
    /recursively sorted/,
  );
});
