#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const ROYALTY_PHASE_ONE_LEDGER_BINDING_RECEIPT_SCHEMA =
  "dnai.royalty-phase-one-ledger-binding-verification-receipt.v1";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const MAX_FILE_BYTES = 4 * 1024 * 1024;

export class RoyaltyReleaseLedgerBindingError extends Error {}

function fail(message) {
  throw new RoyaltyReleaseLedgerBindingError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

export function canonicalJsonSha256(value) {
  return `sha256:${createHash("sha256")
    .update(`${JSON.stringify(sorted(value), null, 2)}\n`, "utf8")
    .digest("hex")}`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)
      || value === `sha256:${"0".repeat(64)}`) {
    fail(`${label} must be a canonical nonzero SHA-256 digest`);
  }
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)
      || value === `0x${"0".repeat(40)}`) {
    fail(`${label} must be a canonical lowercase nonzero address`);
  }
  return value;
}

function canonicalFinalizedTimestamp(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail("phase-one common-finalized block timestamp must be a positive safe integer");
  }
  const milliseconds = value * 1000;
  if (!Number.isSafeInteger(milliseconds)) {
    fail("phase-one common-finalized block timestamp is outside the canonical date range");
  }
  const date = new Date(milliseconds);
  if (Number.isNaN(date.getTime())) {
    fail("phase-one common-finalized block timestamp is not a valid UTC instant");
  }
  return date.toISOString();
}

function normalizedPlanCore(phasePlan) {
  if (!isRecord(phasePlan)
      || phasePlan.schema !== "dnai.royalty-release-phase-plan.v2"
      || !isRecord(phasePlan.core)
      || phasePlan.core.schema !== "dnai.royalty-release-phase-plan-core.v2") {
    fail("Royalty phase plan is not the exact v2 reviewed-plan shape");
  }
  const { core } = phasePlan;
  if (core.phase !== 1 && core.phase !== 2) fail("Royalty phase must equal 1 or 2");
  if (!isRecord(core.authority)) fail("Royalty plan authority is missing");
  canonicalAddress(core.authority.distributor_address, "Royalty distributor address");
  sha256(phasePlan.plan_sha256, "Royalty phase-plan digest");
  if (core.phase === 1) {
    if (core.phase_one_prerequisite !== null) {
      fail("phase one must not claim a phase-one prerequisite");
    }
  } else if (!isRecord(core.phase_one_prerequisite)) {
    fail("phase two must carry its exact phase-one prerequisite");
  }
  return core;
}

function contractHistory(ledger, distributorAddress) {
  if (!isRecord(ledger) || !Array.isArray(ledger.royaltyReleaseHistory ?? [])) {
    fail("release ledger royaltyReleaseHistory must be an array");
  }
  return (ledger.royaltyReleaseHistory ?? []).filter((entry) =>
    isRecord(entry) && entry.royaltyDistributorAddress === distributorAddress);
}

export function verifyPhaseOneLedgerBinding({ phasePlan, ledger }) {
  const core = normalizedPlanCore(phasePlan);
  const distributorAddress = core.authority.distributor_address;
  const history = contractHistory(ledger, distributorAddress);

  if (core.phase === 1) {
    if (history.length !== 0) {
      fail("phase one requires an empty Royalty history for the reviewed distributor");
    }
    return {
      schema: ROYALTY_PHASE_ONE_LEDGER_BINDING_RECEIPT_SCHEMA,
      status: "phase_one_exact_empty_history_validated",
      truthStatus:
        "external_ledger_history_only_not_rpc_execution_finality_or_tdx_evidence",
      phase: 1,
      planSha256: phasePlan.plan_sha256,
      distributorAddress,
      phaseOneHistoryRecordSha256: null,
      finalizedAuthorityReceiptSha256: null,
      phaseOneFinalizedAt: null,
    };
  }

  if (history.length !== 1) {
    fail("phase two requires exactly one prior Royalty history record for the distributor");
  }
  const record = history[0];
  if (record.phase !== 1 || record.executionMode !== "stage_authority"
      || record.phasePlanSha256 !== core.phase_one_prerequisite.phase_one_plan_sha256
      || !isRecord(record.finalizedAuthority)) {
    fail("phase-two predecessor is not the exact recorded phase-one release");
  }

  const historyRecordSha256 = canonicalJsonSha256(record);
  const finalizedAuthorityReceiptSha256 = canonicalJsonSha256(record.finalizedAuthority);
  const phaseOneFinalizedAt = canonicalFinalizedTimestamp(
    record.finalizedAuthority.finalizedBlockTimestamp,
  );
  const prerequisite = core.phase_one_prerequisite;

  if (sha256(prerequisite.phase_one_history_record_sha256,
    "signed phase-one history-record digest") !== historyRecordSha256) {
    fail("signed phase-one history-record digest does not match the canonical ledger record");
  }
  if (sha256(prerequisite.finalized_authority_receipt_sha256,
    "signed phase-one finalized-authority digest") !== finalizedAuthorityReceiptSha256) {
    fail("signed phase-one finalized-authority digest does not match the canonical ledger receipt");
  }
  if (prerequisite.phase_one_finalized_at !== phaseOneFinalizedAt) {
    fail("signed phase-one finalized timestamp does not match the common-finalized block time");
  }

  return {
    schema: ROYALTY_PHASE_ONE_LEDGER_BINDING_RECEIPT_SCHEMA,
    status: "phase_two_exact_phase_one_record_and_finality_validated",
    truthStatus:
      "canonical_external_ledger_record_and_embedded_finality_only_not_fresh_rpc_or_tdx_evidence",
    phase: 2,
    planSha256: phasePlan.plan_sha256,
    distributorAddress,
    phaseOneHistoryRecordSha256: historyRecordSha256,
    finalizedAuthorityReceiptSha256,
    phaseOneFinalizedAt,
  };
}

function readJsonFile(filePath, label) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be absolute and normalized`);
  }
  let canonical;
  try {
    canonical = fs.realpathSync.native(filePath);
  } catch {
    fail(`${label} path does not exist`);
  }
  if (canonical !== filePath) fail(`${label} path must be canonical and symlink-free`);
  const before = fs.lstatSync(filePath);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.uid !== expectedUid || (before.mode & 0o022) !== 0
      || before.size < 2 || before.size > MAX_FILE_BYTES) {
    fail(`${label} must be an operator-owned bounded single-link non-writable regular file`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      fail(`${label} changed while opening`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) fail(`${label} ended during its bounded read`);
      offset += count;
    }
    const afterFd = fs.fstatSync(fd);
    const afterPath = fs.lstatSync(filePath);
    if (afterFd.dev !== opened.dev || afterFd.ino !== opened.ino
        || afterPath.dev !== opened.dev || afterPath.ino !== opened.ino
        || afterFd.size !== opened.size || afterFd.mtimeMs !== opened.mtimeMs
        || afterFd.ctimeMs !== opened.ctimeMs) {
      fail(`${label} changed during its bounded read`);
    }
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch {
      fail(`${label} is not valid JSON`);
    }
  } finally {
    fs.closeSync(fd);
  }
}

function parseArgs(argv) {
  if (argv[0] !== "verify") fail("usage: royalty-release-ledger-binding.mjs verify --plan PATH --ledger PATH");
  const values = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if ((key !== "--plan" && key !== "--ledger") || value === undefined || values[key]) {
      fail("usage: royalty-release-ledger-binding.mjs verify --plan PATH --ledger PATH");
    }
    values[key] = value;
  }
  if (Object.keys(values).length !== 2) {
    fail("usage: royalty-release-ledger-binding.mjs verify --plan PATH --ledger PATH");
  }
  return values;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const receipt = verifyPhaseOneLedgerBinding({
    phasePlan: readJsonFile(args["--plan"], "Royalty phase plan"),
    ledger: readJsonFile(args["--ledger"], "release ledger"),
  });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (process.argv[1]
    && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
