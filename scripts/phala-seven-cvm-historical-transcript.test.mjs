import assert from "node:assert/strict";
import test from "node:test";

import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_DOMAIN,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
  canonicalPhalaSevenCvmHistoricalTranscriptFileSetText,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries,
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptBasename,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";

const KAT =
  "sha256:ba4490eac9523c9389e57dd6833c52c6b2be2cbbcda8e49738f9d058e84e3556";

function fileIdentityByFlag() {
  return Object.fromEntries(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag, index) => [
      flag,
      {
        sha256:
          `sha256:${(index + 1).toString(16).padStart(2, "0").repeat(32)}`,
        size: 1_000 + index,
      },
    ]),
  );
}

test("historical transcript schema, domain, exact order, and digest KAT are frozen", () => {
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
    "dnai.seven-cvm-historical-transcript-file-set.v2",
  );
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_DOMAIN,
    "dnai-wikigen/seven-cvm-historical-transcript-file-set/v2\0",
  );
  assert.equal(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length, 14);
  assert.equal(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES, 1024 * 1024);
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES,
    8 * 1024 * 1024,
  );
  const value = createPhalaSevenCvmHistoricalTranscriptFileSet(
    fileIdentityByFlag(),
  );
  assert.deepEqual(
    value.files.map(({ flag }) => flag),
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  );
  assert.equal(phalaSevenCvmHistoricalTranscriptFileSetSha256(value), KAT);
  assert.equal(
    canonicalPhalaSevenCvmHistoricalTranscriptFileSetText(value),
    `${JSON.stringify(value, null, 2)}\n`,
  );
  assert.ok(Object.isFrozen(value));
  assert.ok(Object.isFrozen(value.files));
  assert.ok(value.files.every(Object.isFrozen));
  assert.equal(
    phalaSevenCvmHistoricalTranscriptBasename(value.files[0].flag),
    "phala-transcript.main-runtime-qvl-challenge.json",
  );
});

test("historical transcript is pure corroboration and rejects any file-set drift", () => {
  const value = createPhalaSevenCvmHistoricalTranscriptFileSet(
    fileIdentityByFlag(),
  );
  for (const mutate of [
    (copy) => { copy.schema = "dnai.seven-cvm-verified-evidence-set.v1"; },
    (copy) => { copy.files.pop(); },
    (copy) => { copy.files.reverse(); },
    (copy) => { copy.files[0].flag = "--six-cvm-launch-completion-receipt"; },
    (copy) => { copy.files[0].sha256 = copy.files[1].sha256; },
    (copy) => { copy.files[0].sha256 = copy.files[0].sha256.slice(7); },
    (copy) => { copy.files[0].size = 0; },
    (copy) => { copy.files[0].size = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES + 1; },
    (copy) => { copy.live_traffic_authorized = true; },
  ]) {
    const copy = structuredClone(value);
    mutate(copy);
    assert.throws(() => normalizePhalaSevenCvmHistoricalTranscriptFileSet(copy));
  }
  const missing = fileIdentityByFlag();
  delete missing[PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[0]];
  assert.throws(
    () => createPhalaSevenCvmHistoricalTranscriptFileSet(missing),
    /exactly 14 flags/,
  );
  const accessor = structuredClone(value);
  Object.defineProperty(accessor.files[0], "sha256", {
    enumerable: true,
    get: () => value.files[0].sha256,
  });
  assert.throws(
    () => normalizePhalaSevenCvmHistoricalTranscriptFileSet(accessor),
    /accessors/,
  );
});

test("historical transcript exact text projection binds canonical bytes and size", () => {
  const entries = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
    (flag, index) => ({
      flag,
      text: `${JSON.stringify({ flag, index, schema: "dnai.test-envelope.v1" }, null, 2)}\n`,
    }),
  );
  const set = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(entries);
  assert.deepEqual(
    set.files.map(({ size }) => size),
    entries.map(({ text }) => Buffer.byteLength(text, "utf8")),
  );
  const drifted = structuredClone(entries);
  drifted[0].text = JSON.stringify(JSON.parse(drifted[0].text));
  assert.throws(
    () => createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(drifted),
    /canonical pretty JSON plus LF/,
  );
});
