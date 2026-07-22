import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertSecretFreeExecutorStructure,
} from "./phala-production-posture-core.mjs";

/**
 * Deterministic, unbranded executor-state structure.
 *
 * This module deliberately does not prove durable-journal provenance, current
 * mutation readiness, SDK authenticity, or recovery state. Production code
 * must continue to obtain those guarantees from the executor facade. The
 * historical release validator may use this leaf only to normalize and hash
 * already-persisted state under an enclosing signed authority chain.
 */
export const PHALA_EXECUTOR_STATE_SCHEMA = "dnai.phala-executor-state.v3";
export const PHALA_EXECUTOR_STATE_DOMAIN =
  "dnai-wikigen/phala-executor-state/v3\0";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the allowed fields`);
  }
  return value;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactAppId(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (!APP_ID.test(normalized)) {
    throw new Error(`${label} must be exactly 20 nonzero bytes`);
  }
  return normalized;
}

function exactIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function normalizeReservation(value, index) {
  const item = exactRecord(
    value,
    ["domain", "app_id", "nonce"],
    `reservation[${index}]`,
  );
  if (item.domain !== PHALA_EXECUTION_ORDER[index]
    || !Number.isSafeInteger(item.nonce) || item.nonce < 0) {
    throw new Error(
      "app-id reservations must match exact domain order and valid nonces",
    );
  }
  return {
    domain: item.domain,
    app_id: exactAppId(item.app_id, `reservation[${index}].app_id`),
    nonce: item.nonce,
  };
}

export function normalizeCompletedPhalaExecutorState(value) {
  assertCanonicalPlainDataGraph(value, { label: "completed executor state" });
  const state = exactRecord(value, [
    "schema",
    "status",
    "sequence",
    "batch_id",
    "bootstrap_authorization_id",
    "bootstrap_authorization_receipt_sha256",
    "release_sha",
    "launch_intent_sha256",
    "target_authority_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "reservations",
    "preparations",
    "signed_key_bindings",
    "committed_prefix",
    "pending_mutation",
    "reconciliation",
    "posture_receipts",
    "preparations_validation_sha256",
  ], "completed executor state");
  if (state.schema !== PHALA_EXECUTOR_STATE_SCHEMA
    || state.status
      !== "complete_seven_commits_posture_observed_attestation_unverified"
    || state.sequence !== 38
    || state.pending_mutation !== null
    || state.reconciliation !== null
    || typeof state.release_sha !== "string"
    || !/^(?!0{40}$)[0-9a-f]{40}$/.test(state.release_sha)) {
    throw new Error(
      "executor state is not the exact complete seven-CVM pre-attestation state",
    );
  }
  const exactDomainArray = (entries, fields, label, projector) => {
    if (!Array.isArray(entries)
      || entries.length !== PHALA_EXECUTION_ORDER.length) {
      throw new Error(
        `${label} must contain the exact seven-domain execution order`,
      );
    }
    return entries.map((raw, index) => {
      const entry = exactRecord(raw, fields, `${label}[${index}]`);
      if (entry.domain !== PHALA_EXECUTION_ORDER[index]) {
        throw new Error(`${label} must follow supporting-six-then-main order`);
      }
      return projector(entry, index);
    });
  };
  const reservations = exactDomainArray(
    state.reservations,
    ["domain", "app_id", "nonce"],
    "completed executor reservations",
    (entry, index) => normalizeReservation(entry, index),
  );
  const preparations = exactDomainArray(
    state.preparations,
    [
      "domain",
      "request_sha256",
      "readiness_sha256",
      "attempted_at",
      "observed_at",
      "observation_sha256",
    ],
    "completed executor preparations",
    (entry) => {
      const attemptedAt = canonicalTimestamp(
        entry.attempted_at,
        "completed executor provision attempted_at",
      );
      const observedAt = canonicalTimestamp(
        entry.observed_at,
        "completed executor provision observed_at",
      );
      if (Date.parse(observedAt) < Date.parse(attemptedAt)
        || Date.parse(observedAt) - Date.parse(attemptedAt) > 60_000) {
        throw new Error(
          "completed executor provision time window is invalid",
        );
      }
      return {
        domain: entry.domain,
        request_sha256: exactDigest(
          entry.request_sha256,
          "completed executor provision request",
        ),
        readiness_sha256: exactDigest(
          entry.readiness_sha256,
          "completed executor provision readiness",
        ),
        attempted_at: attemptedAt,
        observed_at: observedAt,
        observation_sha256: exactDigest(
          entry.observation_sha256,
          "completed executor preparation observation",
        ),
      };
    },
  );
  const signedKeyBindings = exactDomainArray(
    state.signed_key_bindings,
    ["domain", "binding_sha256", "public_key_sha256"],
    "completed executor signed key bindings",
    (entry) => ({
      domain: entry.domain,
      binding_sha256: exactDigest(
        entry.binding_sha256,
        "completed executor signed key binding",
      ),
      public_key_sha256: exactDigest(
        entry.public_key_sha256,
        "completed executor signed public key",
      ),
    }),
  );
  const committedPrefix = exactDomainArray(
    state.committed_prefix,
    [
      "domain",
      "cvm_id",
      "request_sha256",
      "readiness_sha256",
      "attempted_at",
      "observed_at",
      "observation_sha256",
    ],
    "completed executor committed prefix",
    (entry) => {
      const attemptedAt = canonicalTimestamp(
        entry.attempted_at,
        "completed executor commit attempted_at",
      );
      const observedAt = canonicalTimestamp(
        entry.observed_at,
        "completed executor commit observed_at",
      );
      if (Date.parse(observedAt) < Date.parse(attemptedAt)
        || Date.parse(observedAt) - Date.parse(attemptedAt) > 60_000) {
        throw new Error("completed executor commit time window is invalid");
      }
      return {
        domain: entry.domain,
        cvm_id: exactIdentifier(entry.cvm_id, "completed executor CVM id"),
        request_sha256: exactDigest(
          entry.request_sha256,
          "completed executor commit request",
        ),
        readiness_sha256: exactDigest(
          entry.readiness_sha256,
          "completed executor commit readiness",
        ),
        attempted_at: attemptedAt,
        observed_at: observedAt,
        observation_sha256: exactDigest(
          entry.observation_sha256,
          "completed executor commit observation",
        ),
      };
    },
  );
  const postureReceipts = exactDomainArray(
    state.posture_receipts,
    ["domain", "receipt_sha256"],
    "completed executor posture receipts",
    (entry) => ({
      domain: entry.domain,
      receipt_sha256: exactDigest(
        entry.receipt_sha256,
        "completed executor posture receipt",
      ),
    }),
  );
  if (new Set(reservations.map(({ app_id: appId }) => appId)).size
      !== PHALA_EXECUTION_ORDER.length
    || new Set(reservations.map(({ nonce }) => nonce)).size
      !== PHALA_EXECUTION_ORDER.length
    || new Set(committedPrefix.map(({ cvm_id: cvmId }) => cvmId)).size
      !== PHALA_EXECUTION_ORDER.length
    || new Set(signedKeyBindings.map(({ public_key_sha256: digest }) => digest))
      .size !== PHALA_EXECUTION_ORDER.length) {
    throw new Error(
      "completed executor app IDs, nonces, CVM IDs, and signed keys must be distinct",
    );
  }
  for (let index = 1; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    if (Date.parse(preparations[index].attempted_at)
        < Date.parse(preparations[index - 1].observed_at)
      || Date.parse(committedPrefix[index].attempted_at)
        < Date.parse(committedPrefix[index - 1].observed_at)) {
      throw new Error(
        "completed executor mutations do not follow exact domain order",
      );
    }
  }
  if (Date.parse(committedPrefix[0].attempted_at)
      < Date.parse(preparations.at(-1).observed_at)) {
    throw new Error(
      "completed executor committed before all seven preparations completed",
    );
  }
  const normalized = {
    schema: PHALA_EXECUTOR_STATE_SCHEMA,
    status: "complete_seven_commits_posture_observed_attestation_unverified",
    sequence: 38,
    batch_id: exactDigest(state.batch_id, "completed executor batch"),
    bootstrap_authorization_id: exactDigest(
      state.bootstrap_authorization_id,
      "completed executor bootstrap authorization",
    ),
    bootstrap_authorization_receipt_sha256: exactDigest(
      state.bootstrap_authorization_receipt_sha256,
      "completed executor bootstrap receipt",
    ),
    release_sha: state.release_sha,
    launch_intent_sha256: exactDigest(
      state.launch_intent_sha256,
      "completed executor launch intent",
    ),
    target_authority_sha256: exactDigest(
      state.target_authority_sha256,
      "completed executor target authority",
    ),
    phala_recovery_directory_identity_anchor_sha256: exactDigest(
      state.phala_recovery_directory_identity_anchor_sha256,
      "completed executor Phala recovery-directory identity anchor",
    ),
    reservations,
    preparations,
    signed_key_bindings: signedKeyBindings,
    committed_prefix: committedPrefix,
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: postureReceipts,
    preparations_validation_sha256: exactDigest(
      state.preparations_validation_sha256,
      "completed executor preparations validation",
    ),
  };
  assertSecretFreeExecutorStructure(normalized, "completed executor state");
  return deepFreezeCanonicalPlainDataGraph(normalized, {
    label: "normalized completed executor state",
  });
}

export function phalaExecutorStateDigest(state) {
  assertCanonicalPlainDataGraph(state, { label: "executor state digest input" });
  assertSecretFreeExecutorStructure(state, "executor state");
  return `sha256:${createHash("sha256")
    .update(Buffer.from(PHALA_EXECUTOR_STATE_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(state)), "utf8"))
    .digest("hex")}`;
}
