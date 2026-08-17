import { createHash } from "node:crypto";
import path from "node:path";

import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
  canonicalPhalaSevenCvmHistoricalTranscriptFileSetText,
  createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries,
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  pinPhalaPrivateDirectory,
  readPhalaPinnedPrivateFile,
  unlinkPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";

export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA =
  "dnai.phala-seven-cvm-historical-transcript-persistence-receipt.v2";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-historical-transcript-persistence-receipt/v2\0";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_PREFLIGHT_SCHEMA =
  "dnai.phala-seven-cvm-historical-transcript-persistence-preflight.v1";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME =
  "phala-transcript-set.manifest.json";
export const PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME =
  "phala-transcript-set.lock";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const MANIFEST_MAX_BYTES = 128 * 1024;
const RECEIPTS = new WeakMap();
const PREPARED_PERSISTENCE = new WeakMap();

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
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

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sorted(value)), "utf8")
    .digest("hex")}`;
}

function frozenBasenames() {
  return PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag) => ({
    flag,
    basename: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[flag],
  }));
}

function normalizeBasenames(value) {
  if (!Array.isArray(value)
    || value.length !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length) {
    throw new Error("transcript persistence basenames must contain exactly 14 entries");
  }
  const expected = frozenBasenames();
  return value.map((entry, index) => {
    const parsed = exactRecord(
      entry,
      ["flag", "basename"],
      `transcript persistence basename ${index}`,
    );
    if (parsed.flag !== expected[index].flag
      || parsed.basename !== expected[index].basename
      || path.basename(parsed.basename) !== parsed.basename) {
      throw new Error("transcript persistence basenames are reordered or widened");
    }
    return Object.freeze({ ...expected[index] });
  });
}

export function normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(
  value,
) {
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "phala_recovery_directory_identity_anchor_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "historical_transcript_file_set_sha256",
    "transcript_file_set",
    "file_basenames",
    "file_mode",
    "write_once",
    "descriptor_relative_io",
    "stable_reread_verified",
    "private_historical_transcript_persisted",
    "private_historical_transcript_contains_raw_quote_and_collateral",
    "raw_quote_publicly_disclosed",
    "raw_collateral_publicly_disclosed",
    "raw_secret_egress",
    "live_traffic_authorized",
  ], "historical transcript persistence receipt");
  if (parsed.schema !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA
    || parsed.status !== "exact_14_verified_envelopes_durably_persisted"
    || parsed.truth_status
      !== "live_branded_verifier_envelopes_written_once_and_reread_via_one_pinned_recovery_directory"
    || parsed.file_mode !== "0600"
    || parsed.write_once !== true
    || parsed.descriptor_relative_io !== true
    || parsed.stable_reread_verified !== true
    || parsed.private_historical_transcript_persisted !== true
    || parsed.private_historical_transcript_contains_raw_quote_and_collateral
      !== true
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false
    || parsed.live_traffic_authorized !== false) {
    throw new Error("historical transcript persistence truth boundary is invalid");
  }
  const fileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    parsed.transcript_file_set,
  );
  const fileSetSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet);
  if (parsed.historical_transcript_file_set_sha256 !== fileSetSha256) {
    throw new Error("historical transcript persistence file-set digest drifted");
  }
  return Object.freeze({
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA,
    status: "exact_14_verified_envelopes_durably_persisted",
    truth_status:
      "live_branded_verifier_envelopes_written_once_and_reread_via_one_pinned_recovery_directory",
    phala_recovery_directory_identity_anchor_sha256: sha256(
      parsed.phala_recovery_directory_identity_anchor_sha256,
      "transcript recovery-directory identity anchor",
    ),
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "transcript verified evidence set",
    ),
    historical_transcript_file_set_sha256: fileSetSha256,
    transcript_file_set: fileSet,
    file_basenames: Object.freeze(normalizeBasenames(parsed.file_basenames)),
    file_mode: "0600",
    write_once: true,
    descriptor_relative_io: true,
    stable_reread_verified: true,
    private_historical_transcript_persisted: true,
    private_historical_transcript_contains_raw_quote_and_collateral: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
    live_traffic_authorized: false,
  });
}

function persistenceReceiptCandidate({
  directoryIdentityAnchorSha256,
  sevenCvmVerifiedEvidenceSetSha256,
  transcriptFileSet,
}) {
  const fileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    transcriptFileSet,
  );
  return normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt({
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_SCHEMA,
    status: "exact_14_verified_envelopes_durably_persisted",
    truth_status:
      "live_branded_verifier_envelopes_written_once_and_reread_via_one_pinned_recovery_directory",
    phala_recovery_directory_identity_anchor_sha256:
      directoryIdentityAnchorSha256,
    seven_cvm_verified_evidence_set_sha256:
      sevenCvmVerifiedEvidenceSetSha256,
    historical_transcript_file_set_sha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet),
    transcript_file_set: fileSet,
    file_basenames: frozenBasenames(),
    file_mode: "0600",
    write_once: true,
    descriptor_relative_io: true,
    stable_reread_verified: true,
    private_historical_transcript_persisted: true,
    private_historical_transcript_contains_raw_quote_and_collateral: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
    live_traffic_authorized: false,
  });
}

export function normalizePhalaSevenCvmHistoricalTranscriptPersistencePreflight(
  value,
) {
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "phala_recovery_directory_identity_anchor_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "historical_transcript_file_set_sha256",
    "transcript_file_set",
    "anticipated_persistence_receipt_sha256",
    "private_historical_transcript_required",
    "durable_persistence_completed",
    "raw_quote_publicly_disclosed",
    "raw_collateral_publicly_disclosed",
    "raw_secret_egress",
    "live_traffic_authorized",
  ], "historical transcript persistence preflight");
  if (parsed.schema
      !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_PREFLIGHT_SCHEMA
    || parsed.status !== "exact_14_verified_envelopes_prepared_not_persisted"
    || parsed.truth_status
      !== "live_branded_verifier_envelopes_validated_in_memory_before_first_descriptor_relative_write"
    || parsed.private_historical_transcript_required !== true
    || parsed.durable_persistence_completed !== false
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false
    || parsed.live_traffic_authorized !== false) {
    throw new Error("historical transcript persistence preflight truth boundary is invalid");
  }
  const anchor = sha256(
    parsed.phala_recovery_directory_identity_anchor_sha256,
    "transcript preflight recovery-directory identity anchor",
  );
  const evidenceSetSha256 = sha256(
    parsed.seven_cvm_verified_evidence_set_sha256,
    "transcript preflight verified evidence set",
  );
  const fileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    parsed.transcript_file_set,
  );
  const fileSetSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet);
  if (parsed.historical_transcript_file_set_sha256 !== fileSetSha256) {
    throw new Error("historical transcript persistence preflight file-set digest drifted");
  }
  const candidate = persistenceReceiptCandidate({
    directoryIdentityAnchorSha256: anchor,
    sevenCvmVerifiedEvidenceSetSha256: evidenceSetSha256,
    transcriptFileSet: fileSet,
  });
  const anticipated = phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(
    candidate,
  );
  if (parsed.anticipated_persistence_receipt_sha256 !== anticipated) {
    throw new Error("historical transcript persistence preflight receipt digest drifted");
  }
  return Object.freeze({
    schema: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_PREFLIGHT_SCHEMA,
    status: "exact_14_verified_envelopes_prepared_not_persisted",
    truth_status:
      "live_branded_verifier_envelopes_validated_in_memory_before_first_descriptor_relative_write",
    phala_recovery_directory_identity_anchor_sha256: anchor,
    seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
    historical_transcript_file_set_sha256: fileSetSha256,
    transcript_file_set: fileSet,
    anticipated_persistence_receipt_sha256: anticipated,
    private_historical_transcript_required: true,
    durable_persistence_completed: false,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
    live_traffic_authorized: false,
  });
}

export function phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(value) {
  return digest(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_DOMAIN,
    normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(value),
  );
}

function manifestBytes(receipt) {
  const bytes = Buffer.from(canonicalText(receipt), "utf8");
  if (bytes.length > MANIFEST_MAX_BYTES) {
    throw new Error("historical transcript persistence manifest exceeds its byte bound");
  }
  return bytes;
}

function exactOwnedBasenames() {
  return new Set([
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
    ...Object.values(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG),
  ]);
}

function transcriptPersistenceEntries(pinnedDirectory) {
  return listPhalaPinnedPrivateEntries(pinnedDirectory)
    .filter((entry) => entry.startsWith("phala-transcript")
      || entry.startsWith(".phala-transcript"));
}

function rejectExistingTranscriptState(pinnedDirectory, {
  allowExactLock = false,
} = {}) {
  const existing = transcriptPersistenceEntries(pinnedDirectory)
    .filter((entry) => !(allowExactLock
      && entry === PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME));
  if (existing.length > 0) {
    throw new Error(
      "existing historical transcript state requires explicit load or recovery",
    );
  }
}

function assertExactTranscriptNamespace(pinnedDirectory, { includeLock }) {
  const expected = exactOwnedBasenames();
  if (!includeLock) {
    expected.delete(PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME);
  }
  const observed = transcriptPersistenceEntries(pinnedDirectory);
  if (observed.length !== expected.size
    || observed.some((entry) => !expected.has(entry))) {
    throw new Error("persisted transcript set is missing, extra, or substituted");
  }
  return observed;
}

function assertLockOnlyTranscriptNamespace(pinnedDirectory) {
  const observed = transcriptPersistenceEntries(pinnedDirectory);
  if (observed.length !== 1
    || observed[0] !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME) {
    throw new Error(
      "pre-write transcript cleanup found ambiguous state; its lock was retained",
    );
  }
}

function validateExportedEntries(entries) {
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
    entries,
  );
  return {
    entries: entries.map((entry) => Object.freeze({ ...entry })),
    fileSet,
    fileSetSha256: phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet),
  };
}

function persistExportedEntries(options = {}, {
  afterLock = null,
  afterEnvelope = null,
  afterManifest = null,
  authorizeReceipt = false,
} = {}) {
  for (const [name, callback] of Object.entries({
    afterLock,
    afterEnvelope,
    afterManifest,
  })) {
    if (callback !== null && typeof callback !== "function") {
      throw new Error(`historical transcript test control ${name} is invalid`);
    }
  }
  if (typeof authorizeReceipt !== "boolean") {
    throw new Error("historical transcript receipt authorization mode is invalid");
  }
  const {
    directory,
    directoryIdentityAnchorSha256,
    sevenCvmVerifiedEvidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256,
    entries,
  } = exactRecord(options, [
    "directory",
    "directoryIdentityAnchorSha256",
    "sevenCvmVerifiedEvidenceSetSha256",
    "expectedHistoricalTranscriptFileSetSha256",
    "entries",
  ], "historical transcript persistence input");
  const anchor = sha256(
    directoryIdentityAnchorSha256,
    "transcript persistence expected recovery-directory anchor",
  );
  const evidenceSetSha256 = sha256(
    sevenCvmVerifiedEvidenceSetSha256,
    "transcript persistence expected evidence set",
  );
  const expectedFileSetSha256 = sha256(
    expectedHistoricalTranscriptFileSetSha256,
    "transcript persistence expected historical file set",
  );
  const exported = validateExportedEntries(entries);
  if (exported.fileSetSha256 !== expectedFileSetSha256) {
    throw new Error("exported exact-14 transcript bytes differ from verified evidence authority");
  }
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: anchor,
  });
  let lockIdentity;
  let writeStarted = false;
  let publicationComplete = false;
  let receipt;
  const writtenEnvelopes = [];
  try {
    rejectExistingTranscriptState(pinnedDirectory);
    const lockBytes = Buffer.from(canonicalText({
      schema: "dnai.phala-seven-cvm-historical-transcript-persistence-lock.v1",
      phala_recovery_directory_identity_anchor_sha256: anchor,
      seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
      historical_transcript_file_set_sha256: expectedFileSetSha256,
    }), "utf8");
    lockIdentity = createExclusivePhalaPinnedPrivateFile(
      pinnedDirectory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
      lockBytes,
      { mode: 0o600, maximum: 16 * 1024 },
    );
    rejectExistingTranscriptState(pinnedDirectory, { allowExactLock: true });
    afterLock?.();
    for (let index = 0; index < exported.entries.length; index += 1) {
      const entry = exported.entries[index];
      const identity = exported.fileSet.files[index];
      const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
        entry.flag
      ];
      const bytes = Buffer.from(entry.text, "utf8");
      writeStarted = true;
      const fileIdentity = createExclusivePhalaPinnedPrivateFile(
        pinnedDirectory,
        basename,
        bytes,
        {
          mode: 0o600,
          maximum: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
        },
      );
      const reread = readPhalaPinnedPrivateFile(pinnedDirectory, basename, {
        mode: 0o600,
        maximum: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
        minimum: 2,
        expectedIdentity: fileIdentity,
      });
      if (!reread.equals(bytes)
        || fileIdentity.sha256 !== identity.sha256
        || fileIdentity.size !== identity.size) {
        throw new Error("persisted transcript envelope differs on stable FD-relative reread");
      }
      writtenEnvelopes.push(Object.freeze({
        basename,
        bytes,
        fileIdentity,
      }));
      afterEnvelope?.(index);
    }
    receipt = persistenceReceiptCandidate({
      directoryIdentityAnchorSha256: anchor,
      sevenCvmVerifiedEvidenceSetSha256: evidenceSetSha256,
      transcriptFileSet: exported.fileSet,
    });
    const bytes = manifestBytes(receipt);
    const manifestIdentity = createExclusivePhalaPinnedPrivateFile(
      pinnedDirectory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
      bytes,
      { mode: 0o600, maximum: MANIFEST_MAX_BYTES },
    );
    const reread = readPhalaPinnedPrivateFile(
      pinnedDirectory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
      {
        mode: 0o600,
        maximum: MANIFEST_MAX_BYTES,
        minimum: 2,
        expectedIdentity: manifestIdentity,
      },
    );
    if (!reread.equals(bytes)) {
      throw new Error("transcript persistence manifest differs on stable reread");
    }
    afterManifest?.();
    assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedDirectory);
    assertExactTranscriptNamespace(pinnedDirectory, { includeLock: true });
    for (const written of writtenEnvelopes) {
      const finalReread = readPhalaPinnedPrivateFile(
        pinnedDirectory,
        written.basename,
        {
          mode: 0o600,
          maximum: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
          minimum: 2,
          expectedIdentity: written.fileIdentity,
        },
      );
      if (!finalReread.equals(written.bytes)) {
        throw new Error(
          "persisted transcript envelope changed before the commit boundary",
        );
      }
    }
    const finalManifestReread = readPhalaPinnedPrivateFile(
      pinnedDirectory,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
      {
        mode: 0o600,
        maximum: MANIFEST_MAX_BYTES,
        minimum: 2,
        expectedIdentity: manifestIdentity,
      },
    );
    if (!finalManifestReread.equals(bytes)) {
      throw new Error(
        "transcript persistence manifest changed before the commit boundary",
      );
    }
    publicationComplete = true;
  } finally {
    if (lockIdentity && (!writeStarted || publicationComplete)) {
      try {
        assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedDirectory);
        if (publicationComplete) {
          assertExactTranscriptNamespace(pinnedDirectory, { includeLock: true });
        } else {
          assertLockOnlyTranscriptNamespace(pinnedDirectory);
        }
        unlinkPhalaPinnedPrivateFile(
          pinnedDirectory,
          PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME,
          {
            expectedIdentity: lockIdentity,
            expectedSha256: lockIdentity.sha256,
            mode: 0o600,
            maximum: 16 * 1024,
          },
        );
        assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedDirectory);
      } finally {
        closePhalaPinnedPrivateDirectory(pinnedDirectory);
      }
    } else {
      closePhalaPinnedPrivateDirectory(pinnedDirectory);
    }
  }
  if (!publicationComplete || !receipt) {
    throw new Error("historical transcript publication did not reach its commit boundary");
  }
  if (authorizeReceipt) {
    RECEIPTS.set(receipt, Object.freeze({
      directory,
      directory_identity_anchor_sha256: anchor,
      seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
      historical_transcript_file_set_sha256: expectedFileSetSha256,
      receipt_sha256:
        phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(receipt),
      text_entries: Object.freeze(exported.entries),
    }));
  }
  return receipt;
}

function assertEmptyAnchoredTranscriptDirectory(directory, anchor) {
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: anchor,
  });
  try {
    rejectExistingTranscriptState(pinnedDirectory);
    assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedDirectory);
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

function prepareExportedTranscriptEntries(options = {}) {
  const {
    directory,
    directoryIdentityAnchorSha256,
    sevenCvmVerifiedEvidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256,
    entries,
  } = exactRecord(options, [
    "directory",
    "directoryIdentityAnchorSha256",
    "sevenCvmVerifiedEvidenceSetSha256",
    "expectedHistoricalTranscriptFileSetSha256",
    "entries",
  ], "exported historical transcript persistence preflight input");
  const anchor = sha256(
    directoryIdentityAnchorSha256,
    "transcript persistence preflight recovery-directory anchor",
  );
  const evidenceSetSha256 = sha256(
    sevenCvmVerifiedEvidenceSetSha256,
    "transcript persistence preflight evidence set",
  );
  const expectedFileSetSha256 = sha256(
    expectedHistoricalTranscriptFileSetSha256,
    "transcript persistence preflight historical file set",
  );
  const exported = validateExportedEntries(entries);
  if (exported.fileSetSha256 !== expectedFileSetSha256) {
    throw new Error(
      "exported exact-14 transcript bytes differ from verified evidence authority",
    );
  }
  const candidate = persistenceReceiptCandidate({
    directoryIdentityAnchorSha256: anchor,
    sevenCvmVerifiedEvidenceSetSha256: evidenceSetSha256,
    transcriptFileSet: exported.fileSet,
  });
  const anticipatedReceiptSha256 =
    phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(candidate);
  const preflight =
    normalizePhalaSevenCvmHistoricalTranscriptPersistencePreflight({
      schema:
        PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_PERSISTENCE_PREFLIGHT_SCHEMA,
      status: "exact_14_verified_envelopes_prepared_not_persisted",
      truth_status:
        "live_branded_verifier_envelopes_validated_in_memory_before_first_descriptor_relative_write",
      phala_recovery_directory_identity_anchor_sha256: anchor,
      seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
      historical_transcript_file_set_sha256: exported.fileSetSha256,
      transcript_file_set: exported.fileSet,
      anticipated_persistence_receipt_sha256: anticipatedReceiptSha256,
      private_historical_transcript_required: true,
      durable_persistence_completed: false,
      raw_quote_publicly_disclosed: false,
      raw_collateral_publicly_disclosed: false,
      raw_secret_egress: false,
      live_traffic_authorized: false,
    });
  assertEmptyAnchoredTranscriptDirectory(directory, anchor);
  PREPARED_PERSISTENCE.set(preflight, Object.freeze({
    directory,
    directory_identity_anchor_sha256: anchor,
    seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
    historical_transcript_file_set_sha256: exported.fileSetSha256,
    anticipated_persistence_receipt_sha256: anticipatedReceiptSha256,
    entries: Object.freeze(exported.entries),
  }));
  return preflight;
}

export function assertPreparedProductionPhalaSevenCvmHistoricalTranscriptPersistence(
  value,
) {
  const state = value && PREPARED_PERSISTENCE.get(value);
  if (!state) {
    throw new Error(
      "a live one-shot exact-14 transcript persistence preflight is required",
    );
  }
  const normalized =
    normalizePhalaSevenCvmHistoricalTranscriptPersistencePreflight(value);
  if (canonicalText(normalized) !== canonicalText(value)
    || normalized.anticipated_persistence_receipt_sha256
      !== state.anticipated_persistence_receipt_sha256
    || normalized.phala_recovery_directory_identity_anchor_sha256
      !== state.directory_identity_anchor_sha256
    || normalized.seven_cvm_verified_evidence_set_sha256
      !== state.seven_cvm_verified_evidence_set_sha256
    || normalized.historical_transcript_file_set_sha256
      !== state.historical_transcript_file_set_sha256) {
    throw new Error("exact-14 transcript persistence preflight authority drifted");
  }
  return value;
}

export async function prepareProductionPhalaSevenCvmHistoricalTranscriptPersistence(
  options = {},
) {
  const {
    directory,
    directoryIdentityAnchorSha256,
    verifiedEvidenceSet: verifiedEvidenceSetValue,
    qvlIdentityEvidence,
    workloadVerdictEvidence,
  } = exactRecord(options, [
    "directory",
    "directoryIdentityAnchorSha256",
    "verifiedEvidenceSet",
    "qvlIdentityEvidence",
    "workloadVerdictEvidence",
  ], "production historical transcript persistence preflight input");
  const anchor = sha256(
    directoryIdentityAnchorSha256,
    "transcript persistence preflight recovery-directory anchor",
  );

  // This first pinned-FD pass is intentionally non-mutating. It proves that
  // the externally authenticated recovery directory is empty before any raw
  // quote/collateral transcript bytes are even exported into process memory.
  assertEmptyAnchoredTranscriptDirectory(directory, anchor);

  const verifier = await import("./phala-seven-cvm-verifier-evidence.mjs");
  if (typeof verifier.exportPhalaSevenCvmHistoricalTranscriptFiles !== "function"
    || typeof verifier.assertProductionPhalaSevenCvmEvidenceSet !== "function"
    || typeof verifier.phalaSevenCvmVerifiedEvidenceSetSha256 !== "function") {
    throw new Error("the frozen exact-14 verifier transcript exporter is unavailable");
  }
  const entries = await verifier.exportPhalaSevenCvmHistoricalTranscriptFiles({
    verifiedEvidenceSet: verifiedEvidenceSetValue,
    qvlIdentityEvidence,
    workloadVerdictEvidence,
  });
  const evidenceSet = verifier.assertProductionPhalaSevenCvmEvidenceSet(
    verifiedEvidenceSetValue,
  );
  const evidenceSetSha256 = verifier.phalaSevenCvmVerifiedEvidenceSetSha256(
    evidenceSet,
  );
  // The exporter and evidence checks may await local verifier work. Reopen the
  // path and authenticate the same sibling identity anchor again immediately
  // before returning a persistence capability.
  return prepareExportedTranscriptEntries({
    directory,
    directoryIdentityAnchorSha256: anchor,
    sevenCvmVerifiedEvidenceSetSha256: evidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256:
      evidenceSet.historical_transcript_file_set_sha256,
    entries,
  });
}

export function persistPreparedProductionPhalaSevenCvmHistoricalTranscriptFiles(
  options = {},
) {
  const { preflight } = exactRecord(options, [
    "preflight",
  ], "prepared production historical transcript persistence input");
  const prepared =
    assertPreparedProductionPhalaSevenCvmHistoricalTranscriptPersistence(
      preflight,
    );
  const state = PREPARED_PERSISTENCE.get(prepared);

  // Burn before entering the first create-only write. A partial write, lock,
  // manifest, or release-quarantine failure can never reuse the same in-memory
  // persistence capability.
  PREPARED_PERSISTENCE.delete(prepared);
  const receipt = persistExportedEntries({
    directory: state.directory,
    directoryIdentityAnchorSha256: state.directory_identity_anchor_sha256,
    sevenCvmVerifiedEvidenceSetSha256:
      state.seven_cvm_verified_evidence_set_sha256,
    expectedHistoricalTranscriptFileSetSha256:
      state.historical_transcript_file_set_sha256,
    entries: state.entries,
  }, {
    authorizeReceipt: true,
  });
  if (phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(receipt)
      !== state.anticipated_persistence_receipt_sha256) {
    throw new Error(
      "durable transcript receipt differs from its complete pre-write preflight",
    );
  }
  return receipt;
}

export async function persistProductionPhalaSevenCvmHistoricalTranscriptFiles(
  options = {},
) {
  const preflight =
    await prepareProductionPhalaSevenCvmHistoricalTranscriptPersistence(
      options,
    );
  return persistPreparedProductionPhalaSevenCvmHistoricalTranscriptFiles({
    preflight,
  });
}

function readManifestFromPinnedDirectory(pinnedDirectory) {
  const bytes = readPhalaPinnedPrivateFile(
    pinnedDirectory,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MANIFEST_BASENAME,
    {
      mode: 0o600,
      maximum: MANIFEST_MAX_BYTES,
      minimum: 2,
      allowMissing: true,
    },
  );
  if (bytes === null) return null;
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("historical transcript persistence manifest is not JSON");
  }
  const receipt = normalizePhalaSevenCvmHistoricalTranscriptPersistenceReceipt(
    parsed,
  );
  if (!bytes.equals(manifestBytes(receipt))) {
    throw new Error("historical transcript persistence manifest bytes are not canonical");
  }
  return receipt;
}

export function loadPhalaSevenCvmHistoricalTranscriptPersistenceReceipt(
  options = {},
) {
  const {
    directory,
    directoryIdentityAnchorSha256,
    expectedSevenCvmVerifiedEvidenceSetSha256,
    expectedHistoricalTranscriptFileSetSha256,
  } = exactRecord(options, [
    "directory",
    "directoryIdentityAnchorSha256",
    "expectedSevenCvmVerifiedEvidenceSetSha256",
    "expectedHistoricalTranscriptFileSetSha256",
  ], "historical transcript persistence load input");
  const anchor = sha256(
    directoryIdentityAnchorSha256,
    "transcript load recovery-directory anchor",
  );
  const evidenceSetSha256 = sha256(
    expectedSevenCvmVerifiedEvidenceSetSha256,
    "transcript load expected evidence set",
  );
  const fileSetSha256 = sha256(
    expectedHistoricalTranscriptFileSetSha256,
    "transcript load expected file set",
  );
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: anchor,
  });
  try {
    const observedTranscriptEntries = transcriptPersistenceEntries(pinnedDirectory);
    if (observedTranscriptEntries.some((entry) =>
      entry === PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME
      || entry.startsWith(
        `.${PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_LOCK_BASENAME}.release-`,
      ))) {
      throw new Error("historical transcript persistence lock requires explicit recovery");
    }
    const receipt = readManifestFromPinnedDirectory(pinnedDirectory);
    if (!receipt) {
      if (observedTranscriptEntries.length !== 0) {
        throw new Error(
          "partial historical transcript state without a manifest requires explicit recovery",
        );
      }
      return null;
    }
    if (receipt.phala_recovery_directory_identity_anchor_sha256 !== anchor
      || receipt.seven_cvm_verified_evidence_set_sha256 !== evidenceSetSha256
      || receipt.historical_transcript_file_set_sha256 !== fileSetSha256) {
      throw new Error("persisted transcript manifest differs from external authority");
    }
    assertExactTranscriptNamespace(pinnedDirectory, { includeLock: false });
    const entries = receipt.transcript_file_set.files.map((identity) => {
      const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
        identity.flag
      ];
      const bytes = readPhalaPinnedPrivateFile(pinnedDirectory, basename, {
        mode: 0o600,
        maximum: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
        minimum: 2,
      });
      const observedSha256 = `sha256:${createHash("sha256")
        .update(bytes)
        .digest("hex")}`;
      if (bytes.length !== identity.size || observedSha256 !== identity.sha256) {
        throw new Error("persisted transcript envelope bytes drifted from manifest");
      }
      return Object.freeze({ flag: identity.flag, text: bytes.toString("utf8") });
    });
    const reprojected = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
      entries,
    );
    if (canonicalPhalaSevenCvmHistoricalTranscriptFileSetText(reprojected)
      !== canonicalPhalaSevenCvmHistoricalTranscriptFileSetText(
        receipt.transcript_file_set,
      )) {
      throw new Error("persisted transcript envelope set failed canonical replay");
    }
    assertExactTranscriptNamespace(pinnedDirectory, { includeLock: false });
    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      const identity = receipt.transcript_file_set.files[index];
      const basename = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_BASENAME_BY_FLAG[
        identity.flag
      ];
      const finalReread = readPhalaPinnedPrivateFile(pinnedDirectory, basename, {
        mode: 0o600,
        maximum: PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
        minimum: 2,
      });
      if (!finalReread.equals(Buffer.from(entry.text, "utf8"))) {
        throw new Error("persisted transcript envelope changed during stable reload");
      }
    }
    const finalManifest = readManifestFromPinnedDirectory(pinnedDirectory);
    if (finalManifest === null
      || phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(finalManifest)
        !== phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(receipt)) {
      throw new Error("historical transcript manifest changed during stable reload");
    }
    assertExactTranscriptNamespace(pinnedDirectory, { includeLock: false });
    assertPinnedPhalaPrivateDirectoryPathIdentity(pinnedDirectory);
    RECEIPTS.set(receipt, Object.freeze({
      directory,
      directory_identity_anchor_sha256: anchor,
      seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
      historical_transcript_file_set_sha256: fileSetSha256,
      receipt_sha256:
        phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(receipt),
      text_entries: Object.freeze(entries),
    }));
    return receipt;
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

export function assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(
  value,
) {
  const provenance = value && RECEIPTS.get(value);
  if (!provenance
    || provenance.directory_identity_anchor_sha256
      !== value.phala_recovery_directory_identity_anchor_sha256
    || provenance.seven_cvm_verified_evidence_set_sha256
      !== value.seven_cvm_verified_evidence_set_sha256
    || provenance.historical_transcript_file_set_sha256
      !== value.historical_transcript_file_set_sha256
    || provenance.receipt_sha256
      !== phalaSevenCvmHistoricalTranscriptPersistenceReceiptSha256(value)) {
    throw new Error("a durably persisted exact-14 transcript receipt is required");
  }
  return value;
}

export function readDurablyPersistedPhalaSevenCvmHistoricalTranscriptTextEntries(
  value,
) {
  assertDurablyPersistedPhalaSevenCvmHistoricalTranscriptReceipt(value);
  return RECEIPTS.get(value).text_entries;
}

/**
 * Exercise the descriptor-relative persistence machinery without minting the
 * module-private production receipt brand. This is intentionally useful to
 * fault-injection harnesses, but its result cannot satisfy
 * `assertDurablyPersisted...`; production authority is created only after the
 * branded verifier preflight or an authenticated crash-recovery reload.
 */
export function persistUnbrandedPhalaSevenCvmHistoricalTranscriptFilesForHarness(
  options = {},
) {
  const parsed = exactRecord(options, [
    "persistenceOptions",
    "afterLock",
    "afterEnvelope",
    "afterManifest",
  ], "controlled synthetic transcript persistence input");
  const receipt = persistExportedEntries(parsed.persistenceOptions, {
    afterLock: parsed.afterLock,
    afterEnvelope: parsed.afterEnvelope,
    afterManifest: parsed.afterManifest,
    authorizeReceipt: false,
  });
  if (RECEIPTS.has(receipt)) {
    throw new Error("unbranded transcript harness unexpectedly minted authority");
  }
  return receipt;
}
