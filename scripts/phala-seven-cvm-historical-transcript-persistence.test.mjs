import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA,
  __test,
  assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt,
  loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt,
  normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt,
  persistProductionPhalaSevenCvmHistoricalTranscriptFiles,
  phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256,
  readDurablyPersistedPhalaSevenCvmHistoricalTranscriptTextEntries,
} from "./phala-seven-cvm-historical-transcript-persistence.mjs";
import {
  syntheticPhalaSevenCvmVerifierEvidenceFixture,
} from "./phala-seven-cvm-verifier-evidence.fixture.mjs";

const pin = (pair) => `sha256:${pair.repeat(32)}`;

function persistenceFixture(t) {
  const parent = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-phala-transcript-persistence-"),
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "recovery");
  fs.mkdirSync(directory, { mode: 0o700 });
  const initialHandle = pinPhalaPrivateDirectory(directory);
  const anchor = phalaPinnedPrivateDirectoryIdentityAnchorSha256(initialHandle);
  closePhalaPinnedPrivateDirectory(initialHandle);
  const textEntries = entries();
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
    textEntries,
  );
  const fileSetSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet);
  const evidenceSetSha256 = pin("33");
  const persistenceOptions = {
    directory,
    directoryIdentityAnchorSha256: anchor,
    sevenCvmVerifiedEvidenceSetSha256: evidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256: fileSetSha256,
    entries: textEntries,
  };
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return {
    parent,
    directory,
    anchor,
    textEntries,
    fileSet,
    fileSetSha256,
    evidenceSetSha256,
    persistenceOptions,
  };
}

function persistFixture(fixture, controls = null) {
  if (controls === null) {
    return __test.persistSyntheticPhalaSevenCvmHistoricalTranscriptFiles(
      fixture.persistenceOptions,
    );
  }
  return __test.persistSyntheticPhalaSevenCvmHistoricalTranscriptFilesWithControls({
    persistenceOptions: fixture.persistenceOptions,
    afterLock: controls.afterLock ?? null,
    afterEnvelope: controls.afterEnvelope ?? null,
    afterManifest: controls.afterManifest ?? null,
  });
}

function loadFixture(fixture) {
  return loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt({
    directory: fixture.directory,
    directoryIdentityAnchorSha256: fixture.anchor,
    expectedSevenCvmVerifiedEvidenceSetSha256: fixture.evidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256: fixture.fileSetSha256,
  });
}

function expectedPublishedBasenames() {
  return [
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
    ...PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
      (flag) => PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[flag],
    ),
  ].sort();
}

function entries() {
  return PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
    (flag, index) => ({
      flag,
      text: `${JSON.stringify({
        flag,
        index,
        schema: "dnai.synthetic-verifier-transcript-envelope.v1",
      }, null, 2)}\n`,
    }),
  );
}

function receiptFixture() {
  const transcriptFileSet =
    createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(entries());
  return {
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA,
    status: "exact_14_verified_envelopes_durably_persisted",
    truth_status:
      "live_branded_verifier_envelopes_written_once_and_reread_via_one_pinned_recovery_directory",
    phala_recovery_directory_identity_anchor_sha256: pin("11"),
    seven_cvm_verified_evidence_set_sha256: pin("22"),
    historical_transcript_file_set_sha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet),
    transcript_file_set: transcriptFileSet,
    file_basenames: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
      (flag) => ({
        flag,
        basename: `phala-transcript.${flag.slice(2)}.json`,
      }),
    ),
    file_mode: "0600",
    write_once: true,
    descriptor_relative_io: true,
    stable_reread_verified: true,
    raw_quote_public_egress: false,
    raw_secret_egress: false,
    live_traffic_authorized: false,
  };
}

test("transcript persistence receipt KAT binds exact14 names, hashes, and sizes", () => {
  const receipt = receiptFixture();
  assert.deepEqual(
    normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(receipt),
    receipt,
  );
  assert.equal(
    phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(receipt),
    "sha256:9f709508d51013a8cd602eba838711c0495092aef717a907bd53c71932a899a8",
  );
  for (const mutate of [
    (value) => { value.transcript_file_set.files.pop(); },
    (value) => { value.file_basenames.reverse(); },
    (value) => { value.file_mode = "0644"; },
    (value) => { value.write_once = false; },
    (value) => { value.stable_reread_verified = false; },
    (value) => { value.raw_quote_public_egress = true; },
    (value) => { value.live_traffic_authorized = true; },
  ]) {
    const drifted = structuredClone(receipt);
    mutate(drifted);
    assert.throws(
      () => normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(drifted),
    );
  }
});

test("exact14 envelopes persist create-only and reload through one anchored FD boundary", (t) => {
  const fixture = persistenceFixture(t);
  const receipt = persistFixture(fixture);
  assert.equal(
    assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(receipt),
    receipt,
  );
  assert.deepEqual(
    readDurablyPersistedPhalaSevenCvmHistoricalTranscriptTextEntries(receipt),
    fixture.textEntries,
  );
  assert.deepEqual(fs.readdirSync(fixture.directory).sort(), expectedPublishedBasenames());
  for (const basename of expectedPublishedBasenames()) {
    const stat = fs.lstatSync(path.join(fixture.directory, basename));
    assert.equal(stat.isFile(), true);
    assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.nlink, 1);
    assert.equal(stat.mode & 0o777, 0o600);
  }
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(
      fixture.directory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
    ), "utf8")),
    receipt,
  );
  assert.equal(
    fs.existsSync(path.join(
      fixture.directory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
    )),
    false,
  );
  const normalizedCopy =
    normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(receipt);
  assert.notEqual(normalizedCopy, receipt);
  assert.throws(
    () => assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(
      normalizedCopy,
    ),
    /durably persisted exact-14 transcript receipt/,
  );
  assert.throws(
    () => persistFixture(fixture),
    /explicit load or recovery/,
  );
  const loaded = loadFixture(fixture);
  assert.deepEqual(loaded, receipt);
  assert.equal(
    assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(loaded),
    loaded,
  );
});

test("production persistence reaches the real exporter and synthetic evidence stays non-exportable", async (t) => {
  const persistence = persistenceFixture(t);
  const verified = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  await assert.rejects(
    persistProductionPhalaSevenCvmHistoricalTranscriptFiles({
      directory: persistence.directory,
      directoryIdentityAnchorSha256: persistence.anchor,
      verifiedEvidenceSet: verified.evidenceSet,
      qvlIdentityEvidence: verified.qvlIdentityEvidence,
      workloadVerdictEvidence: verified.workloadVerdictEvidence,
    }),
    /synthetic seven-CVM evidence can never authorize a live release/,
  );
  assert.deepEqual(fs.readdirSync(persistence.directory), []);
});

test("a partial envelope write retains its lock and cannot be mistaken for absence", (t) => {
  const fixture = persistenceFixture(t);
  assert.throws(
    () => persistFixture(fixture, {
      afterEnvelope(index) {
        if (index === 0) throw new Error("injected crash after first envelope");
      },
    }),
    /injected crash after first envelope/,
  );
  assert.deepEqual(fs.readdirSync(fixture.directory).sort(), [
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[0]
    ],
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
  ].sort());
  assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
  assert.throws(() => persistFixture(fixture), /explicit load or recovery/);
});

test("pre-write cleanup retains its lock if another transcript entry appears", (t) => {
  const fixture = persistenceFixture(t);
  const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[0]
  ];
  assert.throws(
    () => persistFixture(fixture, {
      afterLock() {
        fs.writeFileSync(
          path.join(fixture.directory, basename),
          fixture.textEntries[0].text,
          { mode: 0o600 },
        );
        fs.chmodSync(path.join(fixture.directory, basename), 0o600);
        throw new Error("injected pre-write ambiguity");
      },
    }),
    /pre-write transcript cleanup found ambiguous state/,
  );
  assert.deepEqual(fs.readdirSync(fixture.directory).sort(), [
    basename,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
  ].sort());
  assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
});

test("a post-manifest fault retains the complete ambiguous set and its lock", (t) => {
  const fixture = persistenceFixture(t);
  assert.throws(
    () => persistFixture(fixture, {
      afterManifest() {
        throw new Error("injected crash after durable manifest");
      },
    }),
    /injected crash after durable manifest/,
  );
  assert.deepEqual(fs.readdirSync(fixture.directory).sort(), [
    ...expectedPublishedBasenames(),
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
  ].sort());
  assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
});

test("a manifest-less orphan and a release quarantine both demand recovery", async (t) => {
  await t.test("manifest-less orphan", (subtest) => {
    const fixture = persistenceFixture(subtest);
    const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[0]
    ];
    fs.writeFileSync(
      path.join(fixture.directory, basename),
      fixture.textEntries[0].text,
      { mode: 0o600 },
    );
    fs.chmodSync(path.join(fixture.directory, basename), 0o600);
    assert.throws(
      () => loadFixture(fixture),
      /partial historical transcript state without a manifest requires explicit recovery/,
    );
    assert.throws(() => persistFixture(fixture), /explicit load or recovery/);
  });

  await t.test("crash-left release quarantine", (subtest) => {
    const fixture = persistenceFixture(subtest);
    const quarantine = `.${PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME}.release-${"a".repeat(64)}`;
    fs.writeFileSync(path.join(fixture.directory, quarantine), "locked\n", {
      mode: 0o600,
    });
    fs.chmodSync(path.join(fixture.directory, quarantine), 0o600);
    assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
    assert.throws(() => persistFixture(fixture), /explicit load or recovery/);
  });
});

test("commit rejects an injected transcript namespace entry and retains ambiguity", (t) => {
  const fixture = persistenceFixture(t);
  const extra = "phala-transcript.unexpected.json";
  assert.throws(
    () => persistFixture(fixture, {
      afterManifest() {
        fs.writeFileSync(path.join(fixture.directory, extra), "{}\n", {
          mode: 0o600,
        });
        fs.chmodSync(path.join(fixture.directory, extra), 0o600);
      },
    }),
    /missing, extra, or substituted/,
  );
  assert.equal(
    fs.existsSync(path.join(
      fixture.directory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
    )),
    true,
  );
  assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
});

test("commit rejects canonical-path replacement while writes stay on the held FD", (t) => {
  const fixture = persistenceFixture(t);
  const held = path.join(fixture.parent, "held-recovery");
  assert.throws(
    () => persistFixture(fixture, {
      afterLock() {
        fs.renameSync(fixture.directory, held);
        fs.mkdirSync(fixture.directory, { mode: 0o700 });
        fs.writeFileSync(
          path.join(fixture.directory, "replacement.sentinel"),
          "replacement\n",
          { mode: 0o600 },
        );
      },
    }),
    /pathname or identity anchor no longer names its authenticated directory/,
  );
  assert.deepEqual(fs.readdirSync(fixture.directory), ["replacement.sentinel"]);
  assert.deepEqual(fs.readdirSync(held).sort(), [
    ...expectedPublishedBasenames(),
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
  ].sort());
});

test("commit cannot unlink an identical-byte replacement lock", (t) => {
  const fixture = persistenceFixture(t);
  let replacementBytes;
  assert.throws(
    () => persistFixture(fixture, {
      afterManifest() {
        const lockPath = path.join(
          fixture.directory,
          PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
        );
        replacementBytes = fs.readFileSync(lockPath);
        fs.unlinkSync(lockPath);
        fs.writeFileSync(lockPath, replacementBytes, { mode: 0o600 });
        fs.chmodSync(lockPath, 0o600);
      },
    }),
    /identity differs from the acquired lock/,
  );
  assert.deepEqual(
    fs.readFileSync(path.join(
      fixture.directory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
    )),
    replacementBytes,
  );
  assert.throws(() => loadFixture(fixture), /lock requires explicit recovery/);
});

test("reload rejects extra, missing, swapped, tampered, hardlinked, and symlinked files", (t) => {
  const fixture = persistenceFixture(t);
  const receipt = persistFixture(fixture);
  const [first, second] = receipt.file_basenames.map(({ basename }) =>
    path.join(fixture.directory, basename));
  const firstOriginal = fs.readFileSync(first);
  const secondOriginal = fs.readFileSync(second);

  const extra = path.join(fixture.directory, "phala-transcript.unexpected.json");
  fs.writeFileSync(extra, "{}\n", { mode: 0o600 });
  assert.throws(() => loadFixture(fixture), /missing, extra, or substituted/);
  fs.unlinkSync(extra);

  const missingBacking = path.join(fixture.directory, "missing.backing.json");
  fs.renameSync(first, missingBacking);
  assert.throws(() => loadFixture(fixture), /missing, extra, or substituted/);
  fs.renameSync(missingBacking, first);

  const swap = path.join(fixture.directory, "swap.tmp.json");
  fs.renameSync(first, swap);
  fs.renameSync(second, first);
  fs.renameSync(swap, second);
  assert.throws(() => loadFixture(fixture), /drifted from manifest/);
  fs.renameSync(second, swap);
  fs.renameSync(first, second);
  fs.renameSync(swap, first);

  const hardlink = path.join(fixture.directory, "unrelated.alias.json");
  fs.linkSync(first, hardlink);
  assert.throws(() => loadFixture(fixture), /single-link regular file/);
  fs.unlinkSync(hardlink);

  fs.writeFileSync(first, "{}\n", { mode: 0o600 });
  assert.throws(() => loadFixture(fixture), /drifted from manifest/);
  fs.writeFileSync(first, firstOriginal, { mode: 0o600 });

  const symlinkBacking = path.join(fixture.directory, "symlink.backing.json");
  fs.renameSync(first, symlinkBacking);
  fs.symlinkSync(path.basename(symlinkBacking), first);
  assert.throws(() => loadFixture(fixture));
  fs.unlinkSync(first);
  fs.renameSync(symlinkBacking, first);

  fs.chmodSync(first, 0o640);
  assert.throws(() => loadFixture(fixture), /exact private mode-0600/);
  fs.chmodSync(first, 0o600);

  const manifest = path.join(
    fixture.directory,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
  );
  const manifestOriginal = fs.readFileSync(manifest);
  fs.writeFileSync(manifest, "{}\n", { mode: 0o600 });
  assert.throws(() => loadFixture(fixture));
  fs.writeFileSync(manifest, manifestOriginal, { mode: 0o600 });
  const manifestAlias = path.join(fixture.directory, "manifest.alias.json");
  fs.linkSync(manifest, manifestAlias);
  assert.throws(() => loadFixture(fixture), /single-link regular file/);
  fs.unlinkSync(manifestAlias);

  assert.deepEqual(fs.readFileSync(first), firstOriginal);
  assert.deepEqual(fs.readFileSync(second), secondOriginal);
  assert.deepEqual(loadFixture(fixture), receipt);
});
