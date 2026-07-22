import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  phalaPinnedPrivateDirectoryIdentityAnchorPath,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
  readPhalaPinnedPrivateFile,
  unlinkPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";

function fixture(t) {
  const parent = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-phala-pinned-directory-"),
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "state");
  fs.mkdirSync(directory, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, directory };
}

function runMutator(source, args) {
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", source, ...args],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
}

test("descriptor-relative writes stay on the pinned inode after cross-process path replacement", (t) => {
  const { parent, directory } = fixture(t);
  const held = path.join(parent, "held-state");
  const handle = pinPhalaPrivateDirectory(directory);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const lockIdentity = createExclusivePhalaPinnedPrivateFile(
    handle,
    "operation.lock.json",
    Buffer.from('{"owner":"original"}\n'),
  );

  runMutator([
    "import fs from 'node:fs';",
    "const [directory, held] = process.argv.slice(1);",
    "fs.renameSync(directory, held);",
    "fs.mkdirSync(directory, { mode: 0o700 });",
    "fs.writeFileSync(`${directory}/operation.lock.json`, '{\"owner\":\"replacement\"}\\n', { mode: 0o600 });",
    "fs.writeFileSync(`${directory}/replacement.sentinel`, 'replacement\\n', { mode: 0o600 });",
  ].join("\n"), [directory, held]);

  assert.throws(
    () => assertPinnedPhalaPrivateDirectoryPathIdentity(handle),
    /pathname or identity anchor no longer names its authenticated directory/,
  );

  publishPhalaPinnedPrivateFile(
    handle,
    "journal.json",
    Buffer.from('{"sequence":0}\n'),
    { publishMode: "create" },
  );
  assert.equal(fs.readFileSync(path.join(held, "journal.json"), "utf8"), '{"sequence":0}\n');
  assert.equal(fs.existsSync(path.join(directory, "journal.json")), false);

  unlinkPhalaPinnedPrivateFile(handle, "operation.lock.json", {
    expectedSha256: lockIdentity.sha256,
    expectedIdentity: lockIdentity,
  });
  assert.equal(fs.existsSync(path.join(held, "operation.lock.json")), false);
  assert.equal(
    fs.readFileSync(path.join(directory, "operation.lock.json"), "utf8"),
    '{"owner":"replacement"}\n',
  );
  assert.throws(
    () => pinPhalaPrivateDirectory(directory),
    /identity changed|automatic rebind is forbidden/,
  );
});

test("missing, replaced, and tampered identity anchors fail closed", (t) => {
  const { directory } = fixture(t);
  const first = pinPhalaPrivateDirectory(directory);
  const anchorPath = phalaPinnedPrivateDirectoryIdentityAnchorPath(directory);
  const anchorBytes = fs.readFileSync(anchorPath);
  fs.writeFileSync(anchorPath, "not canonical JSON\n", { mode: 0o600 });
  assert.throws(
    () => assertPinnedPhalaPrivateDirectoryPathIdentity(first),
    /pathname or identity anchor no longer names its authenticated directory/,
  );
  fs.writeFileSync(anchorPath, anchorBytes, { mode: 0o600 });
  fs.chmodSync(anchorPath, 0o600);
  assert.equal(assertPinnedPhalaPrivateDirectoryPathIdentity(first), first);
  closePhalaPinnedPrivateDirectory(first);

  fs.unlinkSync(anchorPath);
  assert.throws(
    () => pinPhalaPrivateDirectory(directory),
    /anchor disappeared/,
  );
  fs.writeFileSync(anchorPath, anchorBytes, { mode: 0o600 });
  fs.chmodSync(anchorPath, 0o600);

  const replacement = JSON.parse(anchorBytes.toString("utf8"));
  replacement.directory_inode = String(BigInt(replacement.directory_inode) + 1n);
  const replacementBytes = `${JSON.stringify(
    Object.fromEntries(Object.keys(replacement).sort().map((key) => [key, replacement[key]])),
    null,
    2,
  )}\n`;
  fs.unlinkSync(anchorPath);
  fs.writeFileSync(anchorPath, replacementBytes, { mode: 0o600 });
  assert.throws(
    () => pinPhalaPrivateDirectory(directory),
    /identity changed|anchor changed|automatic rebind/,
  );

  fs.unlinkSync(anchorPath);
  fs.writeFileSync(anchorPath, "not canonical JSON\n", { mode: 0o600 });
  assert.throws(
    () => pinPhalaPrivateDirectory(directory),
    /corrupt|identity anchor/,
  );
});

test("an old lock owner cannot remove an identical-byte replacement lock", (t) => {
  const { directory } = fixture(t);
  const handle = pinPhalaPrivateDirectory(directory);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const bytes = Buffer.from('{"owner":"same-digest"}\n');
  const original = createExclusivePhalaPinnedPrivateFile(
    handle,
    "operation.lock.json",
    bytes,
  );
  const originalInode = fs.statSync(path.join(directory, "operation.lock.json")).ino;

  runMutator([
    "import fs from 'node:fs';",
    "const [file, encoded] = process.argv.slice(1);",
    "fs.unlinkSync(file);",
    "fs.writeFileSync(file, Buffer.from(encoded, 'base64'), { mode: 0o600 });",
  ].join("\n"), [
    path.join(directory, "operation.lock.json"),
    bytes.toString("base64"),
  ]);

  const replacementInode = fs.statSync(path.join(directory, "operation.lock.json")).ino;
  assert.notEqual(replacementInode, originalInode);
  assert.throws(
    () => unlinkPhalaPinnedPrivateFile(handle, "operation.lock.json", {
      expectedSha256: original.sha256,
      expectedIdentity: original,
    }),
    /identity differs/,
  );
  assert.deepEqual(
    fs.readFileSync(path.join(directory, "operation.lock.json")),
    bytes,
  );
  assert.equal(fs.statSync(path.join(directory, "operation.lock.json")).ino, replacementInode);
});

test("an old lock owner rejects a same-inode metadata recycle", (t) => {
  const { directory } = fixture(t);
  const handle = pinPhalaPrivateDirectory(directory);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const file = path.join(directory, "operation.lock.json");
  const bytes = Buffer.from('{"owner":"metadata-recycled"}\n');
  const original = createExclusivePhalaPinnedPrivateFile(
    handle,
    "operation.lock.json",
    bytes,
  );
  const before = fs.statSync(file, { bigint: true });
  assert.equal(original.ctime_ns, String(before.ctimeNs));

  runMutator([
    "import fs from 'node:fs';",
    "const file = process.argv[1];",
    "fs.chmodSync(file, 0o640);",
    "fs.chmodSync(file, 0o600);",
  ].join("\n"), [file]);

  const after = fs.statSync(file, { bigint: true });
  assert.equal(after.ino, before.ino);
  assert.notEqual(after.ctimeNs, before.ctimeNs);
  assert.throws(
    () => unlinkPhalaPinnedPrivateFile(handle, "operation.lock.json", {
      expectedSha256: original.sha256,
      expectedIdentity: original,
    }),
    /identity differs/,
  );
  assert.deepEqual(fs.readFileSync(file), bytes);
  assert.equal(fs.statSync(file, { bigint: true }).ino, before.ino);
});

test("file hard links and live directory mode tampering are rejected", (t) => {
  const { directory } = fixture(t);
  const handle = pinPhalaPrivateDirectory(directory);
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const identity = createExclusivePhalaPinnedPrivateFile(
    handle,
    "journal.json",
    Buffer.from('{"sequence":0}\n'),
  );
  const alias = path.join(directory, "journal.alias.json");
  fs.linkSync(path.join(directory, "journal.json"), alias);
  assert.throws(
    () => readPhalaPinnedPrivateFile(handle, "journal.json", {
      expectedIdentity: identity,
    }),
    /single-link regular file/,
  );
  fs.unlinkSync(alias);

  fs.chmodSync(directory, 0o750);
  assert.throws(
    () => readPhalaPinnedPrivateFile(handle, "journal.json", {
      expectedIdentity: identity,
    }),
    /fd posture changed|mode is not exactly 0700/,
  );
  fs.chmodSync(directory, 0o700);
});

test("the sibling identity anchor requires an exact private parent directory", (t) => {
  const parent = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-phala-public-anchor-parent-"),
  ));
  const directory = path.join(parent, "state");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(parent, 0o755);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  assert.throws(
    () => pinPhalaPrivateDirectory(directory),
    /identity-anchor parent.*exact mode 0700/,
  );
});

test("cross-process reopen requires the externally authenticated anchor digest", (t) => {
  const { directory } = fixture(t);
  const handle = pinPhalaPrivateDirectory(directory);
  const expected = phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle);
  assert.throws(
    () => phalaPinnedPrivateDirectoryIdentityAnchorSha256({
      identity_anchor_sha256: expected,
    }),
    /exact live pinned private-directory authority/,
  );
  closePhalaPinnedPrivateDirectory(handle);
  const moduleUrl = new URL("./phala-pinned-private-directory.mjs", import.meta.url).href;
  const source = [
    "const [moduleUrl, directory, expected] = process.argv.slice(1);",
    "const { pinPhalaPrivateDirectory, closePhalaPinnedPrivateDirectory } = await import(moduleUrl);",
    "try {",
    "  const handle = pinPhalaPrivateDirectory(directory, expected === '-' ? {} : { expectedIdentityAnchorSha256: expected });",
    "  closePhalaPinnedPrivateDirectory(handle);",
    "  process.stdout.write('opened\\n');",
    "} catch (error) { process.stderr.write(`${error.message}\\n`); process.exitCode = 23; }",
  ].join("\n");

  const unauthenticated = spawnSync(process.execPath, [
    "--input-type=module", "-e", source, moduleUrl, directory, "-",
  ], { encoding: "utf8" });
  assert.equal(unauthenticated.status, 23);
  assert.match(unauthenticated.stderr, /externally authenticated directory identity anchor/);

  const authenticated = spawnSync(process.execPath, [
    "--input-type=module", "-e", source, moduleUrl, directory, expected,
  ], { encoding: "utf8" });
  assert.equal(authenticated.status, 0, authenticated.stderr);
  assert.equal(authenticated.stdout, "opened\n");
});

test("externally authenticated attach never creates an absent directory or anchor", (t) => {
  const parent = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-phala-strict-attach-"),
  ));
  fs.chmodSync(parent, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const directory = path.join(parent, "absent-exchange");
  const anchorPath = phalaPinnedPrivateDirectoryIdentityAnchorPath(directory);
  assert.throws(
    () => pinPhalaPrivateDirectory(directory, {
      expectedIdentityAnchorSha256: `sha256:${"91".repeat(32)}`,
    }),
    /must already exist/,
  );
  assert.equal(fs.existsSync(directory), false);
  assert.equal(fs.existsSync(anchorPath), false);
});

test("authenticated attach rejects a renamed and substituted directory pathname", (t) => {
  const { parent, directory } = fixture(t);
  const original = pinPhalaPrivateDirectory(directory);
  const anchor = phalaPinnedPrivateDirectoryIdentityAnchorSha256(original);
  closePhalaPinnedPrivateDirectory(original);
  const held = path.join(parent, "held-original");
  fs.renameSync(directory, held);
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, "replacement.sentinel"), "replacement\n", {
    mode: 0o600,
  });

  assert.throws(
    () => pinPhalaPrivateDirectory(directory, {
      expectedIdentityAnchorSha256: anchor,
    }),
    /identity changed|automatic rebind|differs from external authenticated authority/,
  );
  assert.equal(
    fs.readFileSync(path.join(directory, "replacement.sentinel"), "utf8"),
    "replacement\n",
  );
  assert.deepEqual(fs.readdirSync(held), []);
});
