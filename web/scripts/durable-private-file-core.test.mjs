import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { durablyWritePrivateFile } from "./durable-private-file-core.mjs";

async function privateDirectory() {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-private-write-"));
  await fs.promises.chmod(directory, 0o700);
  return fs.realpathSync.native(directory);
}

test("private release output is complete, mode-600, replaceable, and directory-durable", async () => {
  const directory = await privateDirectory();
  const outputPath = path.join(directory, ".env.production.local");
  try {
    const created = durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=one\n",
    });
    assert.equal(created.mode, 0o600);
    assert.equal(await readFile(outputPath, "utf8"), "VITE_RELEASE_SHA=one\n");
    assert.equal((fs.lstatSync(outputPath).mode & 0o777), 0o600);

    durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=two\n",
    });
    assert.equal(await readFile(outputPath, "utf8"), "VITE_RELEASE_SHA=two\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("failures never replace the last complete private output", async () => {
  const directory = await privateDirectory();
  const outputPath = path.join(directory, ".env.production.local");
  try {
    await writeFile(outputPath, "VITE_RELEASE_SHA=stable\n", { mode: 0o600 });
    for (const faultStage of ["after-write", "after-file-fsync", "before-publish"]) {
      assert.throws(() => durablyWritePrivateFile({
        outputPath,
        allowedOutputPath: outputPath,
        content: `VITE_RELEASE_SHA=${faultStage}\n`,
        faultStage,
      }), /injected private output failure/);
      assert.equal(await readFile(outputPath, "utf8"), "VITE_RELEASE_SHA=stable\n");
      assert.deepEqual(
        fs.readdirSync(directory).sort(),
        [".env.production.local"],
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("no-clobber publication creates one durable file and refuses every replacement", async () => {
  const directory = await privateDirectory();
  const outputPath = path.join(directory, "frontend-build-candidate-receipt.json");
  try {
    durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: '{"schema":"candidate"}\n',
      requireAbsent: true,
    });
    assert.equal(
      await readFile(outputPath, "utf8"),
      '{"schema":"candidate"}\n',
    );
    assert.equal(fs.lstatSync(outputPath).nlink, 1);
    assert.throws(() => durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: '{"schema":"replacement"}\n',
      requireAbsent: true,
    }), /already exists and no-clobber publication was required/);
    assert.equal(
      await readFile(outputPath, "utf8"),
      '{"schema":"candidate"}\n',
    );
    assert.deepEqual(
      fs.readdirSync(directory).sort(),
      ["frontend-build-candidate-receipt.json"],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("no-clobber faults publish neither a partial target nor a temporary alias", async () => {
  for (const faultStage of ["after-write", "after-file-fsync", "before-publish"]) {
    const directory = await privateDirectory();
    const outputPath = path.join(directory, "frontend-build-candidate-receipt.json");
    try {
      assert.throws(() => durablyWritePrivateFile({
        outputPath,
        allowedOutputPath: outputPath,
        content: `{"fault":"${faultStage}"}\n`,
        faultStage,
        requireAbsent: true,
      }), /injected private output failure/);
      assert.deepEqual(fs.readdirSync(directory), []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("private writer rejects alternate paths, unsafe directories, symlinks, and hard links", async () => {
  const directory = await privateDirectory();
  const outputPath = path.join(directory, ".env.production.local");
  const alternatePath = path.join(directory, "alternate.env");
  try {
    assert.throws(() => durablyWritePrivateFile({
      outputPath: alternatePath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=alternate\n",
    }), /exact reviewed ignored path/);

    await writeFile(alternatePath, "unsafe\n", { mode: 0o600 });
    await symlink(alternatePath, outputPath);
    assert.throws(() => durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=symlink\n",
    }), /single-link regular file/);
    await fs.promises.unlink(outputPath);
    await fs.promises.link(alternatePath, outputPath);
    assert.throws(() => durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=hardlink\n",
    }), /single-link regular file/);
    await fs.promises.unlink(outputPath);

    await fs.promises.chmod(directory, 0o777);
    assert.throws(() => durablyWritePrivateFile({
      outputPath,
      allowedOutputPath: outputPath,
      content: "VITE_RELEASE_SHA=unsafe-dir\n",
    }), /not group\/other writable/);
  } finally {
    await fs.promises.chmod(directory, 0o700).catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});
