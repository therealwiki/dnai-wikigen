import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA =
  "dnai.seven-cvm-historical-transcript-file-set.v2";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_DOMAIN =
  "dnai-wikigen/seven-cvm-historical-transcript-file-set/v2\0";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER = Object.freeze([
  "--main-runtime-qvl-challenge",
  "--main-runtime-independent-tdx-verdict",
  "--diligence-qvl-identity-request",
  "--diligence-qvl-identity-response",
  "--arena-qvl-identity-request",
  "--arena-qvl-identity-response",
  "--anchor-writer-qvl-identity-request",
  "--anchor-writer-qvl-identity-response",
  "--compute-workload-qvl-identity-request",
  "--compute-workload-qvl-identity-response",
  "--compute-metering-qvl-identity-request",
  "--compute-metering-qvl-identity-response",
  "--independent-metering-qvl-challenge",
  "--independent-metering-independent-tdx-verdict",
]);
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES =
  1024 * 1024;
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES =
  8 * 1024 * 1024;
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG =
  Object.freeze(Object.fromEntries(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag) => [
      flag,
      `phala-transcript.${flag.slice(2)}.json`,
    ]),
  ));

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function size(value, label) {
  if (!Number.isSafeInteger(value) || value < 2
    || value > PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES) {
    throw new TypeError(`${label} must be a bounded positive byte size`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalEnvelopeBytes(text, label) {
  if (typeof text !== "string"
    || Buffer.byteLength(text, "utf8") < 2
    || Buffer.byteLength(text, "utf8")
      > PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES) {
    throw new TypeError(`${label} must be bounded canonical UTF-8 JSON text`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError(`${label} must be canonical JSON`);
  }
  if (!isRecord(parsed)
    || `${JSON.stringify(sorted(parsed), null, 2)}\n` !== text) {
    throw new TypeError(`${label} must be sorted canonical pretty JSON plus LF`);
  }
  return Buffer.from(text, "utf8");
}

export function phalaSevenCvmHistoricalTranscriptBasename(flag) {
  const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[flag];
  if (!basename) {
    throw new TypeError("historical transcript flag has no frozen basename");
  }
  return basename;
}

export function normalizePhalaSevenCvmHistoricalTranscriptFileSet(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "seven-CVM historical transcript file set input",
  });
  const parsed = exactRecord(
    value,
    ["files", "schema"],
    "seven-CVM historical transcript file set",
  );
  if (parsed.schema !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA
    || !Array.isArray(parsed.files)
    || parsed.files.length
      !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length) {
    throw new TypeError(
      "seven-CVM historical transcript file set schema or cardinality is invalid",
    );
  }
  const files = parsed.files.map((entry, index) => {
    const file = exactRecord(
      entry,
      ["flag", "sha256", "size"],
      `seven-CVM historical transcript file ${index}`,
    );
    const expectedFlag = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[index];
    if (file.flag !== expectedFlag) {
      throw new TypeError(
        "seven-CVM historical transcript files are omitted, reordered, or substituted",
      );
    }
    return {
      flag: expectedFlag,
      sha256: digest(
        file.sha256,
        `seven-CVM historical transcript ${expectedFlag}`,
      ),
      size: size(
        file.size,
        `seven-CVM historical transcript ${expectedFlag}`,
      ),
    };
  });
  if (new Set(files.map(({ sha256 }) => sha256)).size !== files.length) {
    throw new TypeError(
      "seven-CVM historical transcript files must have pairwise-distinct byte digests",
    );
  }
  if (files.reduce((total, file) => total + file.size, 0)
      > PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES) {
    throw new TypeError(
      "seven-CVM historical transcript files exceed the aggregate byte bound",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
    files,
  }, { label: "seven-CVM historical transcript file set" });
}

export function createPhalaSevenCvmHistoricalTranscriptFileSet(
  fileIdentityByFlag,
) {
  assertCanonicalPlainDataGraph(fileIdentityByFlag, {
    label: "seven-CVM historical transcript file-identity map",
  });
  if (!isRecord(fileIdentityByFlag)
    || JSON.stringify(Object.keys(fileIdentityByFlag).sort())
      !== JSON.stringify([...PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER].sort())) {
    throw new TypeError(
      "seven-CVM historical transcript identity map must contain exactly 14 flags",
    );
  }
  return normalizePhalaSevenCvmHistoricalTranscriptFileSet({
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
    files: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag) => ({
      flag,
      ...exactRecord(
        fileIdentityByFlag[flag],
        ["sha256", "size"],
        `seven-CVM historical transcript identity ${flag}`,
      ),
    })),
  });
}

export function createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
  entries,
) {
  if (!Array.isArray(entries)
    || entries.length !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length) {
    throw new TypeError("historical transcript exporter must return exactly 14 entries");
  }
  const identities = {};
  for (let index = 0; index < entries.length; index += 1) {
    const entry = exactRecord(
      entries[index],
      ["flag", "text"],
      `historical transcript exporter entry ${index}`,
    );
    const flag = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[index];
    if (entry.flag !== flag) {
      throw new TypeError("historical transcript exporter entries are reordered or substituted");
    }
    const bytes = canonicalEnvelopeBytes(
      entry.text,
      `historical transcript exporter ${flag}`,
    );
    identities[flag] = {
      sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      size: bytes.length,
    };
  }
  return createPhalaSevenCvmHistoricalTranscriptFileSet(identities);
}

export function canonicalPhalaSevenCvmHistoricalTranscriptFileSetText(value) {
  return `${JSON.stringify(
    normalizePhalaSevenCvmHistoricalTranscriptFileSet(value),
    null,
    2,
  )}\n`;
}

export function phalaSevenCvmHistoricalTranscriptFileSetSha256(value) {
  return `sha256:${createHash("sha256")
    .update(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_DOMAIN, "utf8")
    .update(canonicalPhalaSevenCvmHistoricalTranscriptFileSetText(value), "utf8")
    .digest("hex")}`;
}
