import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import test from "node:test";

import { durablyPublishJson, durablyRemoveJson } from "./durable-json-write.mjs";

function fixture() {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-durable-json-")),
  );
  const sourcePath = path.join(directory, "source.json");
  const outputPath = path.join(directory, "output.json");
  fs.writeFileSync(sourcePath, '{"status":"indeterminate_pending_validation","transactions":[]}\n');
  return { directory, sourcePath, outputPath };
}

test("durably creates then atomically replaces complete JSON", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));

  const created = durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
  });
  assert.equal(created.publishMode, "create");
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), fs.readFileSync(value.sourcePath, "utf8"));
  assert.equal(fs.statSync(value.outputPath).mode & 0o777, 0o600);

  fs.writeFileSync(value.sourcePath, '{"status":"validated_manifest_committed","transactions":[1]}\n');
  const replaced = durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "replace",
    fileMode: 0o600,
  });
  assert.equal(replaced.publishMode, "replace");
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), fs.readFileSync(value.sourcePath, "utf8"));
});

for (const faultStage of ["partial-write", "complete-write", "file-fsync", "publish"]) {
  test(`failure at ${faultStage} cannot publish a first journal`, (t) => {
    const value = fixture();
    t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
    assert.throws(() => durablyPublishJson({
      sourcePath: value.sourcePath,
      outputPath: value.outputPath,
      publishMode: "create",
      fileMode: 0o600,
      faultStage,
    }), /injected durable-write failure/);
    assert.equal(fs.existsSync(value.outputPath), false);
  });
}

test("directory fsync failure reports an indeterminate but complete first publication", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
    faultStage: "directory-fsync",
  }), /injected durable-write failure/);
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), fs.readFileSync(value.sourcePath, "utf8"));
});

test("failed replacement never truncates the previously durable journal", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
  });
  const previous = fs.readFileSync(value.outputPath);
  fs.writeFileSync(value.sourcePath, '{"status":"new-but-not-durable"}\n');
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "replace",
    fileMode: 0o600,
    faultStage: "file-fsync",
  }), /injected durable-write failure/);
  assert.deepEqual(fs.readFileSync(value.outputPath), previous);
});

test("create mode cannot replace a pre-existing artifact", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  fs.writeFileSync(value.outputPath, '{"status":"existing"}\n');
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o444,
  }), /already exists/);
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), '{"status":"existing"}\n');
});

test("symlink targets are never replaced", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  const outside = path.join(value.directory, "outside.json");
  fs.writeFileSync(outside, '{"status":"outside"}\n');
  fs.symlinkSync(outside, value.outputPath);
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "replace",
    fileMode: 0o600,
  }), /symlink/);
  assert.equal(fs.readFileSync(outside, "utf8"), '{"status":"outside"}\n');
});

test("lexical aliases and symlinked parent components fail closed", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  const child = path.join(value.directory, "child");
  fs.mkdirSync(child, { mode: 0o700 });
  assert.throws(() => durablyPublishJson({
    sourcePath: `${child}/../source.json`,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
  }), /lexically canonical/);

  const realOutput = path.join(value.directory, "real-output");
  const linkedOutput = path.join(value.directory, "linked-output");
  fs.mkdirSync(realOutput, { mode: 0o700 });
  fs.symlinkSync(realOutput, linkedOutput);
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: path.join(linkedOutput, "result.json"),
    publishMode: "create",
    fileMode: 0o600,
  }), /symlink|filesystem alias/);
});

test("hard-linked source and replacement targets fail closed", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  const sourceAlias = path.join(value.directory, "source-alias.json");
  fs.linkSync(value.sourcePath, sourceAlias);
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
  }), /exactly one hard link/);
  fs.unlinkSync(sourceAlias);

  fs.writeFileSync(value.outputPath, '{"status":"old"}\n');
  const targetAlias = path.join(value.directory, "target-alias.json");
  fs.linkSync(value.outputPath, targetAlias);
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "replace",
    fileMode: 0o600,
  }), /exactly one hard link/);
  assert.equal(fs.readFileSync(targetAlias, "utf8"), '{"status":"old"}\n');
});

test("group- or other-writable output directories fail closed", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  fs.chmodSync(value.directory, 0o770);
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "create",
    fileMode: 0o600,
  }), /group- or other-writable/);
});

test("replacement target swaps are detected before publication", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  fs.writeFileSync(value.outputPath, '{"status":"old"}\n');
  const attackerBytes = '{"status":"attacker"}\n';
  assert.throws(() => durablyPublishJson({
    sourcePath: value.sourcePath,
    outputPath: value.outputPath,
    publishMode: "replace",
    fileMode: 0o600,
    testHookBeforePublish() {
      fs.unlinkSync(value.outputPath);
      fs.writeFileSync(value.outputPath, attackerBytes, { mode: 0o600 });
    },
  }), /replacement target changed/);
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), attackerBytes);
});

test("durable removal requires the exact reviewed bytes, mode, and inode", (t) => {
  const value = fixture();
  t.after(() => fs.rmSync(value.directory, { recursive: true, force: true }));
  fs.writeFileSync(value.outputPath, '{"status":"pending"}\n', { mode: 0o600 });
  const digest = `sha256:${createHash("sha256")
    .update(fs.readFileSync(value.outputPath))
    .digest("hex")}`;
  assert.throws(() => durablyRemoveJson({
    filePath: value.outputPath,
    expectedSha256: `sha256:${"0".repeat(64)}`,
  }), /digest/);
  assert.equal(fs.existsSync(value.outputPath), true);
  assert.throws(() => durablyRemoveJson({
    filePath: value.outputPath,
    expectedSha256: digest,
    testHookBeforeRemove() {
      fs.unlinkSync(value.outputPath);
      fs.writeFileSync(value.outputPath, '{"status":"swapped"}\n', { mode: 0o600 });
    },
  }), /replacement target changed/);
  assert.equal(fs.readFileSync(value.outputPath, "utf8"), '{"status":"swapped"}\n');

  fs.unlinkSync(value.outputPath);
  fs.writeFileSync(value.outputPath, '{"status":"pending"}\n', { mode: 0o600 });
  const removed = durablyRemoveJson({
    filePath: value.outputPath,
    expectedSha256: digest,
  });
  assert.equal(removed.removedSha256, digest);
  assert.equal(fs.existsSync(value.outputPath), false);
});
