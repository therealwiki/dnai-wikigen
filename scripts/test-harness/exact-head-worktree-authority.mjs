import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const GIT = "/usr/bin/git";
const MAX_GIT_OUTPUT = 64 * 1024 * 1024;
const READ_BUFFER_BYTES = 1024 * 1024;
const TREE_HEADER = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40}) +([0-9-]+)$/;
const INDEX_HEADER = /^(100644|100755|120000|160000) ([0-9a-f]{40}) ([0-3])$/;
const EXTRA_PROFILES = Object.freeze({
  "foundry-generated": Object.freeze([
    "web/dist",
    "web/node_modules",
    "⚙️/tinker-delegate/contracts/broadcast",
    "⚙️/tinker-delegate/contracts/cache",
    "⚙️/tinker-delegate/contracts/out",
  ]),
  none: Object.freeze([]),
  "web-generated": Object.freeze([
    "web/dist",
    "web/node_modules",
  ]),
});

function fail(message) {
  throw new Error(`exact HEAD worktree authority: ${message}`);
}

function git(root, args) {
  const result = spawnSync(GIT, [
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.ignoreStat=false",
    "-c", "core.trustctime=true",
    "-c", "core.checkStat=default",
    "-c", "core.fileMode=true",
    "-c", `core.worktree=${root}`,
    "-C", root,
    ...args,
  ], {
    cwd: root,
    encoding: null,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      HOME: root,
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
    maxBuffer: MAX_GIT_OUTPUT,
    timeout: 60_000,
  });
  if (result.status !== 0 || result.signal !== null || result.error) {
    fail(`reviewed Git query failed: ${args[0] || "unknown"}`);
  }
  return result.stdout;
}

function nulRecords(value, label) {
  if (!Buffer.isBuffer(value) || value.length === 0 || value.at(-1) !== 0) {
    fail(`${label} is not one nonempty NUL-terminated projection`);
  }
  const records = [];
  let start = 0;
  for (let offset = 0; offset < value.length; offset += 1) {
    if (value[offset] !== 0) continue;
    if (offset === start) fail(`${label} contains an empty record`);
    records.push(value.subarray(start, offset));
    start = offset + 1;
  }
  if (start !== value.length) fail(`${label} has trailing bytes`);
  return records;
}

function canonicalPath(record, tab, label) {
  const bytes = record.subarray(tab + 1);
  const relative = bytes.toString("utf8");
  if (!Buffer.from(relative, "utf8").equals(bytes)) {
    fail(`${label} path is not canonical UTF-8`);
  }
  if (
    relative.length === 0
    || relative.startsWith("/")
    || relative.includes("\\")
    || /[\p{Cc}\p{Cf}]/u.test(relative)
    || relative.normalize("NFC") !== relative
    || relative.split("/").some((part) => part === "" || part === "." || part === "..")
    || path.posix.normalize(relative) !== relative
  ) {
    fail(`${label} path is not a canonical repository-relative path`);
  }
  return relative;
}

function parseTree(value) {
  const records = [];
  for (const record of nulRecords(value, "HEAD tree")) {
    const tab = record.indexOf(0x09);
    if (tab <= 0) fail("HEAD tree record has no path separator");
    const header = record.subarray(0, tab).toString("ascii");
    const match = TREE_HEADER.exec(header);
    if (!match) fail("HEAD tree record header is invalid");
    const [, mode, type, oid, sizeText] = match;
    const relative = canonicalPath(record, tab, "HEAD tree");
    if ((mode === "160000") !== (type === "commit" && sizeText === "-")) {
      fail(`HEAD tree type is inconsistent for ${relative}`);
    }
    if (mode !== "160000" && (type !== "blob" || !/^(?:0|[1-9][0-9]*)$/.test(sizeText))) {
      fail(`HEAD blob size is invalid for ${relative}`);
    }
    const size = mode === "160000" ? null : Number(sizeText);
    if (size !== null && (!Number.isSafeInteger(size) || size < 0)) {
      fail(`HEAD blob size exceeds the exact projector bound: ${relative}`);
    }
    records.push({
      mode,
      oid,
      relative,
      size,
      type,
    });
  }
  if (new Set(records.map(({ relative }) => relative)).size !== records.length) {
    fail("HEAD tree paths are duplicate");
  }
  return records;
}

function parseIndex(value) {
  const records = [];
  for (const record of nulRecords(value, "stage index")) {
    const tab = record.indexOf(0x09);
    if (tab <= 0) fail("stage index record has no path separator");
    const header = record.subarray(0, tab).toString("ascii");
    const match = INDEX_HEADER.exec(header);
    if (!match) fail("stage index record header is invalid");
    const [, mode, oid, stage] = match;
    const relative = canonicalPath(record, tab, "stage index");
    if (stage !== "0") fail(`index contains a non-stage-zero entry: ${relative}`);
    records.push({ mode, oid, relative });
  }
  return records;
}

function stableMetadata(stat) {
  return [
    stat.dev,
    stat.ino,
    stat.mode,
    stat.nlink,
    stat.uid,
    stat.gid,
    stat.rdev,
    stat.size,
    stat.mtimeNs,
    stat.ctimeNs,
  ].join(":");
}

function expectedOwner() {
  if (typeof process.geteuid !== "function") fail("effective uid is unavailable");
  const uid = process.geteuid();
  if (!Number.isSafeInteger(uid) || uid < 0) fail("effective uid is invalid");
  return BigInt(uid);
}

function assertRegularBlob(root, entry, owner) {
  const absolute = path.join(root, ...entry.relative.split("/"));
  const namedBefore = fs.lstatSync(absolute, { bigint: true });
  const expectedMode = entry.mode === "100755" ? 0o755n : 0o644n;
  if (
    !namedBefore.isFile()
    || namedBefore.isSymbolicLink()
    || namedBefore.nlink !== 1n
    || namedBefore.uid !== owner
    || (namedBefore.mode & 0o777n) !== expectedMode
    || namedBefore.size !== BigInt(entry.size)
    || fs.realpathSync.native(absolute) !== absolute
  ) {
    fail(`tracked file type, owner, link count, mode, size, or path drifted: ${entry.relative}`);
  }
  const descriptor = fs.openSync(
    absolute,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const openedBefore = fs.fstatSync(descriptor, { bigint: true });
    if (stableMetadata(namedBefore) !== stableMetadata(openedBefore)) {
      fail(`tracked file changed while opening: ${entry.relative}`);
    }
    const digest = createHash("sha1");
    digest.update(Buffer.from(`blob ${entry.size}\0`, "utf8"));
    const buffer = Buffer.allocUnsafe(READ_BUFFER_BYTES);
    let offset = 0;
    while (offset < entry.size) {
      const length = fs.readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, entry.size - offset),
        offset,
      );
      if (length <= 0) fail(`tracked file ended early: ${entry.relative}`);
      digest.update(buffer.subarray(0, length));
      offset += length;
    }
    if (fs.readSync(descriptor, buffer, 0, 1, offset) !== 0) {
      fail(`tracked file grew during projection: ${entry.relative}`);
    }
    const openedAfter = fs.fstatSync(descriptor, { bigint: true });
    const namedAfter = fs.lstatSync(absolute, { bigint: true });
    if (
      stableMetadata(openedBefore) !== stableMetadata(openedAfter)
      || stableMetadata(namedBefore) !== stableMetadata(namedAfter)
      || digest.digest("hex") !== entry.oid
    ) {
      fail(`tracked file bytes or metadata do not match HEAD: ${entry.relative}`);
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertSymlinkBlob(root, entry, owner) {
  const absolute = path.join(root, ...entry.relative.split("/"));
  const before = fs.lstatSync(absolute, { bigint: true });
  const expectedMode = process.platform === "darwin"
    ? 0o755n
    : process.platform === "linux"
      ? 0o777n
      : fail("symlink projection requires Darwin or Linux");
  if (
    !before.isSymbolicLink()
    || before.nlink !== 1n
    || before.uid !== owner
    || (before.mode & 0o777n) !== expectedMode
  ) {
    fail(`tracked symlink type, owner, link count, or mode drifted: ${entry.relative}`);
  }
  const target = fs.readlinkSync(absolute, { encoding: "buffer" });
  const after = fs.lstatSync(absolute, { bigint: true });
  const oid = createHash("sha1")
    .update(Buffer.from(`blob ${target.length}\0`, "utf8"))
    .update(target)
    .digest("hex");
  if (
    stableMetadata(before) !== stableMetadata(after)
    || target.length !== entry.size
    || oid !== entry.oid
  ) {
    fail(`tracked symlink target or metadata does not match HEAD: ${entry.relative}`);
  }
}

function assertGitlinkBoundary(root, entry, owner) {
  const absolute = path.join(root, ...entry.relative.split("/"));
  let stat;
  try {
    stat = fs.lstatSync(absolute, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== owner
    || (stat.mode & 0o022n) !== 0n
    || fs.realpathSync.native(absolute) !== absolute
  ) {
    fail(`gitlink boundary is not an absent or safe real directory: ${entry.relative}`);
  }
  if (fs.readdirSync(absolute).length !== 0) {
    fail(`gitlink boundary must remain uninitialized and empty: ${entry.relative}`);
  }
}

function assertNoUnexpectedWorktreeEntries(root, tree, owner, extraProfile) {
  const allowedExtras = new Set(EXTRA_PROFILES[extraProfile]);
  const tracked = new Set(tree.map(({ relative }) => relative));
  const gitlinks = new Set(
    tree.filter(({ mode }) => mode === "160000").map(({ relative }) => relative),
  );
  const trackedDirectories = new Set();
  for (const { relative } of tree) {
    const parts = relative.split("/");
    for (let length = 1; length < parts.length; length += 1) {
      trackedDirectories.add(parts.slice(0, length).join("/"));
    }
  }
  function safeDirectory(absolute, relative, label) {
    const stat = fs.lstatSync(absolute, { bigint: true });
    if (
      !stat.isDirectory()
      || stat.isSymbolicLink()
      || stat.uid !== owner
      || (stat.mode & 0o022n) !== 0n
      || fs.realpathSync.native(absolute) !== absolute
    ) {
      fail(`${label} is not a safe real directory: ${relative}`);
    }
  }
  function walk(relativeDirectory) {
    const absoluteDirectory = relativeDirectory === ""
      ? root
      : path.join(root, ...relativeDirectory.split("/"));
    const entries = fs.readdirSync(absoluteDirectory, { withFileTypes: true })
      .sort((left, right) => Buffer.compare(
        Buffer.from(left.name, "utf8"),
        Buffer.from(right.name, "utf8"),
      ));
    for (const entry of entries) {
      const relative = relativeDirectory === ""
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      const absolute = path.join(root, ...relative.split("/"));
      if (relative === ".git") continue;
      if (gitlinks.has(relative)) continue;
      if (allowedExtras.has(relative)) {
        safeDirectory(absolute, relative, "allowed generated root");
        continue;
      }
      if (tracked.has(relative)) continue;
      if (trackedDirectories.has(relative)) {
        safeDirectory(absolute, relative, "tracked ancestor");
        walk(relative);
        continue;
      }
      fail(`worktree contains an untracked or ignored path: ${relative}`);
    }
  }
  walk("");
}

export function assertExactHeadWorktree({
  expectedHead = null,
  extraProfile = "none",
  root,
}) {
  if (
    process.execArgv.length !== 0
    || typeof root !== "string"
    || !path.isAbsolute(root)
    || fs.realpathSync.native(root) !== root
    || !Object.hasOwn(EXTRA_PROFILES, extraProfile)
  ) {
    fail("requires ordinary Node and one canonical absolute root");
  }
  if (expectedHead !== null && !/^[0-9a-f]{40}$/.test(expectedHead)) {
    fail("expected HEAD is invalid");
  }
  const head = git(root, ["rev-parse", "--verify", "HEAD"]).toString("utf8").trim();
  if (!/^[0-9a-f]{40}$/.test(head) || (expectedHead !== null && head !== expectedHead)) {
    fail("HEAD does not match the reviewed exact commit");
  }
  const tree = parseTree(git(root, ["ls-tree", "-r", "-z", "-l", "--full-tree", head]));
  const index = parseIndex(git(root, ["ls-files", "--stage", "-z"]));
  const expectedIndex = new Map(tree.map(({ mode, oid, relative }) => [
    relative,
    `${mode}:${oid}`,
  ]));
  const actualIndex = new Map(index.map(({ mode, oid, relative }) => [
    relative,
    `${mode}:${oid}`,
  ]));
  if (
    expectedIndex.size !== tree.length
    || actualIndex.size !== index.length
    || expectedIndex.size !== actualIndex.size
    || [...expectedIndex].some(([relative, identity]) => (
      actualIndex.get(relative) !== identity
    ))
  ) {
    fail("stage-zero index is not the exact immutable HEAD tree");
  }
  const owner = expectedOwner();
  for (const entry of tree) {
    if (entry.mode === "100644" || entry.mode === "100755") {
      assertRegularBlob(root, entry, owner);
    } else if (entry.mode === "120000") {
      assertSymlinkBlob(root, entry, owner);
    } else {
      assertGitlinkBoundary(root, entry, owner);
    }
  }
  assertNoUnexpectedWorktreeEntries(root, tree, owner, extraProfile);
  return Object.freeze({ extraProfile, head, trackedEntryCount: tree.length });
}

if (
  process.argv[1]
  && fs.realpathSync.native(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  if (process.argv.length !== 5) {
    fail("usage: exact-head-worktree-authority.mjs ROOT EXPECTED_HEAD_OR_DASH EXTRA_PROFILE");
  }
  const result = assertExactHeadWorktree({
    expectedHead: process.argv[3] === "-" ? null : process.argv[3],
    extraProfile: process.argv[4],
    root: process.argv[2],
  });
  process.stdout.write(
    `HEAD ${result.head} ${result.trackedEntryCount} ${result.extraProfile}\n`,
  );
}
