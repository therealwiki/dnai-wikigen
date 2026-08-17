import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFilePendingReady,
} from "./phala-pinned-private-directory.mjs";
import {
  assertNewResidentPrivateDirectoryPath,
  canonicalResidentJsonText,
  preflightResidentBoundFile,
  readStableCanonicalResident0600Json,
  residentRawSha256,
  waitForPinnedCanonicalResident0600Json,
  waitForPinnedCanonicalResident0600JsonPendingReady,
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

test("pinned handoff rejects a file first observed after its hard deadline", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "late-exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const originalNow = Date.now;
  let now = 1_000;
  Date.now = () => now;
  const timer = setTimeout(() => {
    createExclusivePhalaPinnedPrivateFile(
      handle,
      "late.json",
      Buffer.from(canonicalResidentJsonText({ ready: true }), "utf8"),
      { mode: 0o600, maximum: 64 * 1024 },
    );
    now = 1_100;
  }, 25);
  try {
    await assert.rejects(
      waitForPinnedCanonicalResident0600Json({
        handle,
        fileName: "late.json",
        label: "late response",
        deadlineMs: 1_050,
        pollIntervalMilliseconds: 25,
        maximum: 64 * 1024,
      }),
      /not supplied before the bounded deadline/,
    );
  } finally {
    clearTimeout(timer);
    Date.now = originalNow;
  }
});

test("pending-ready waiter never parses an interrupted 0200 manifest", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "pending-exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const bytes = Buffer.from(canonicalResidentJsonText({ ready: true }), "utf8");
  assert.throws(
    () => publishPhalaPinnedPrivateFilePendingReady(
      handle,
      "manifest.json",
      bytes,
      { maximum: 64 * 1024, faultStage: "before-ready" },
    ),
    /before readiness transition/,
  );
  const pending = fs.statSync(path.join(exchange, "manifest.json"), {
    bigint: true,
  });
  assert.equal(pending.mode & 0o777n, 0o200n);
  await assert.rejects(
    waitForPinnedCanonicalResident0600JsonPendingReady({
      handle,
      fileName: "manifest.json",
      label: "pending manifest",
      deadlineMs: Date.now() + 125,
      pollIntervalMilliseconds: 25,
      maximum: 64 * 1024,
    }),
    /not supplied before the bounded deadline/,
  );
  assert.equal(
    fs.statSync(path.join(exchange, "manifest.json")).mode & 0o777,
    0o200,
  );
});

test("pending-ready waiter accepts only the committed inode and rejects other modes", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "ready-exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const value = { schema: "dnai.pending-ready-test.v1" };
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  const timer = setTimeout(() => {
    publishPhalaPinnedPrivateFilePendingReady(
      handle,
      "manifest.json",
      bytes,
      { maximum: 64 * 1024 },
    );
  }, 25);
  t.after(() => clearTimeout(timer));
  const observed = await waitForPinnedCanonicalResident0600JsonPendingReady({
    handle,
    fileName: "manifest.json",
    label: "ready manifest",
    // The repository-wide Node run executes many cryptographic suites in
    // parallel; retain a bounded deadline without turning event-loop
    // starvation into a false failure of this inode-transition assertion.
    deadlineMs: Date.now() + 5_000,
    pollIntervalMilliseconds: 25,
    maximum: 64 * 1024,
  });
  assert.deepEqual(observed.value, value);
  assert.equal(observed.identity.mode, "0600");

  const wrongExchange = path.join(root, "wrong-mode-exchange");
  const wrongHandle = pinPhalaPrivateDirectory(wrongExchange);
  t.after(() => closePhalaPinnedPrivateDirectory(wrongHandle));
  createExclusivePhalaPinnedPrivateFile(
    wrongHandle,
    "manifest.json",
    bytes,
    { mode: 0o400, maximum: 64 * 1024 },
  );
  await assert.rejects(
    waitForPinnedCanonicalResident0600JsonPendingReady({
      handle: wrongHandle,
      fileName: "manifest.json",
      label: "wrong-mode manifest",
      deadlineMs: Date.now() + 1_000,
      pollIntervalMilliseconds: 25,
      maximum: 64 * 1024,
    }),
    /invalid 0400 readiness mode/,
  );
});

test("pending-ready waiter retains an observed 0200 inode through its 0600 commit", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "observed-pending-exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const filePath = path.join(exchange, "manifest.json");
  const value = { schema: "dnai.observed-pending.v1" };
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  const fd = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o200,
  );
  fs.fchmodSync(fd, 0o200);
  fs.writeFileSync(fd, bytes);
  fs.fsyncSync(fd);
  const pendingInode = fs.fstatSync(fd).ino;
  let closed = false;
  const commit = setTimeout(() => {
    fs.fchmodSync(fd, 0o600);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    closed = true;
  }, 0);
  try {
    const observed = await waitForPinnedCanonicalResident0600JsonPendingReady({
      handle,
      fileName: "manifest.json",
      label: "observed pending manifest",
      deadlineMs: Date.now() + 1_500,
      pollIntervalMilliseconds: 25,
      maximum: 64 * 1024,
    });
    assert.deepEqual(observed.value, value);
    assert.equal(observed.identity.inode, String(pendingInode));
  } finally {
    clearTimeout(commit);
    if (!closed) fs.closeSync(fd);
  }
});

test("pending-ready waiter rejects byte-identical replacement of an observed pending inode", async (t) => {
  const root = privateRoot(t);
  const exchange = path.join(root, "replaced-pending-exchange");
  const handle = pinPhalaPrivateDirectory(exchange);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const filePath = path.join(exchange, "manifest.json");
  const bytes = Buffer.from(
    canonicalResidentJsonText({ schema: "dnai.replaced-pending.v1" }),
    "utf8",
  );
  const fd = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o200,
  );
  fs.fchmodSync(fd, 0o200);
  fs.writeFileSync(fd, bytes);
  fs.fsyncSync(fd);
  fs.closeSync(fd);
  let replacementCount = 0;
  let replacementError = null;
  // Keep each replacement pending rather than making an unobserved replacement
  // ready. A replacement before the waiter's first authoritative observation is
  // allowed; a subsequent one after any O_WRONLY hold is acquired must fail.
  // Repeating the attack makes that causal boundary deterministic without a
  // production-only synchronization hook or reliance on scheduler timing.
  const replace = setInterval(() => {
    if (replacementError !== null) return;
    try {
      fs.unlinkSync(filePath);
      fs.writeFileSync(filePath, bytes, { mode: 0o200 });
      fs.chmodSync(filePath, 0o200);
      replacementCount += 1;
    } catch (error) {
      replacementError = error;
    }
  }, 75);
  try {
    await assert.rejects(
      waitForPinnedCanonicalResident0600JsonPendingReady({
        handle,
        fileName: "manifest.json",
        label: "replaced pending manifest",
        deadlineMs: Date.now() + 2_500,
        pollIntervalMilliseconds: 25,
        maximum: 64 * 1024,
      }),
      /single-link|replaced|disappeared/,
    );
    assert.equal(replacementError, null);
    assert.ok(replacementCount >= 1);
  } finally {
    clearInterval(replace);
  }
});
