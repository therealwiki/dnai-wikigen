#!/usr/bin/env node

import { createHash } from "node:crypto";
import path from "node:path";

import {
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  assertFreshBrandedPreCeremonyRuntimeAuthority,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  canonicalArtifactSha256,
  DEPLOYMENT_TOOLCHAIN_AUTHORITY,
  deploymentIntentReviewerAuthorityCurrentStatusBinding,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  RELEASE_CEREMONY_LOCK_PROTOCOL,
} from "./release-ceremony-lock.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  freshContractDeploymentReceiptDigest,
  CVM_LAUNCH_DOMAINS,
  normalizeFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";

export {
  historicalCeremonyAuthorizationCoreSha256,
  historicalCeremonyAuthorizationReviewSigningPayload,
  historicalCeremonyAuthorizationReviewSubjectSha256,
  historicalReleaseAuthorityReviewSigningMessage,
  historicalReleaseAuthorityReviewSigningPayloadSha256,
  normalizeHistoricalCeremonyAuthorizationCore,
  normalizeHistoricalCeremonyExpectedContext,
  normalizeHistoricalReviewerAuthority,
  projectHistoricalCeremonyExpectedContext,
} from "./release-authority-historical-core.mjs";
export {
  assertExact37GenesisReviewerStatusCurrentForLiveActivation,
} from "./release-authority-current-reviewer-facade.mjs";

export const CEREMONY_AUTHORIZATION_CORE_SCHEMA =
  "dnai.ceremony-authorization-core.v1";
export const CEREMONY_AUTHORIZATION_CORE_STATUS =
  "pre_ceremony_authorized";
export const CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND =
  "ceremony_authorization";
export const CEREMONY_AUTHORIZATION_CORE_DOMAIN =
  "dnai-wikigen/ceremony-authorization-core/v1\0";
export const CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN =
  "dnai-wikigen/ceremony-authorization-review-subject/v1\0";

export const LIVE_ACTIVATION_AUTHORITY_SCHEMA =
  "dnai.live-activation-authority.v5";
export const LIVE_ACTIVATION_AUTHORITY_STATUS =
  "live_activation_authorized";
export const LIVE_ACTIVATION_REVIEW_SUBJECT_KIND =
  "live_activation_authority";
export const LIVE_ACTIVATION_AUTHORITY_DOMAIN =
  "dnai-wikigen/live-activation-authority/v5\0";
export const LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN =
  "dnai-wikigen/live-activation-review-subject/v5\0";

export const RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA =
  "dnai.release-authority-cryptographic-review.v1";
export const RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA =
  "dnai.release-authority-review-signing-payload.v1";
export const RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN =
  "dnai-wikigen/release-authority-cryptographic-review-signing/v1\0";
export const RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX =
  "dnai-wikigen release-authority cryptographic review v1:";
export const RELEASE_AUTHORITY_SIGNATURE_SCHEME =
  PINNED_EIP191_SIGNATURE_SCHEME;
export const RELEASE_AUTHORITY_SIGNATURE_VERIFIER = Object.freeze({
  ...PINNED_CAST_SIGNATURE_VERIFIER,
});

export const RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA =
  "dnai.release-ceremony-transaction-plan.v1";

const CHAIN_ID = 84_532;
const NETWORK_NAME = "base-sepolia";
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_TRANSACTIONS = 512;
// Stage 1 authorizes irreversible on-chain mutations and Stage 2 authorizes
// opening the live service boundary.  These are short execution leases, not
// week-long review declarations.
export const MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS = 60 * 60 * 1_000;
export const MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS = 5 * 60 * 1_000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;
const LOGS_BLOOM = /^0x[0-9a-f]{512}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

export const RELEASE_CEREMONY_MUTATION_WRITERS = Object.freeze([
  "challenge_registry_release",
  "compute_release",
  "diligence_release",
  "email_oracle_release",
  "execution_policy_anchor_release",
  "tinker_release",
]);


const STAGE_ONE_DEPENDENCY_KINDS = Object.freeze([
  "deployment_intent",
  "reviewer_authority_genesis",
  "reviewer_authority_genesis_acceptance",
  "fresh_contract_deployment_receipt",
  "immutable_deployment_manifest",
  "ceremony_ledger_initialization_receipt",
  "ceremony_ledger_initial",
  "ceremony_transaction_plan",
  "cvm_launch_intent",
  "cvm_nonlive_bootstrap_authorization_receipt",
  "pre_ceremony_runtime_authority",
]);


export class ReleaseAuthorityValidationError extends TypeError {}

function fail(message) {
  throw new ReleaseAuthorityValidationError(message);
}

function currentStatusValidationInstant(checkedAtMs) {
  if (!Number.isFinite(checkedAtMs)) {
    fail("reviewer current-status validation time is invalid");
  }
  return new Date(Math.floor(checkedAtMs / 1_000) * 1_000)
    .toISOString()
    .replace(".000Z", "Z");
}

function deploymentRoleSeparation(deploymentIntent) {
  const validation = validateDeploymentIntentCore(deploymentIntent);
  if (!validation.ok) {
    fail("reviewer authority requires the exact valid deployment intent dependency");
  }
  return Object.freeze({
    deploymentRoleAddresses: Object.freeze([...new Set([
      deploymentIntent.deploymentControl.operatorAddress,
      deploymentIntent.staticContractInputs.computeCreditVault.developer,
    ])].sort()),
    deploymentRoleControllerIds: Object.freeze([
      deploymentIntent.deploymentControl.controllerId,
    ]),
  });
}

export function normalizeReleaseReviewerAuthorityForStage({
  reviewerGenesis,
  reviewerGenesisAcceptance,
  reviewerStatusHistory = [],
  deploymentIntent,
  checkedAtMs,
  enforceFreshness,
}) {
  const roleSeparation = deploymentRoleSeparation(deploymentIntent);
  const anchoredHead = deploymentIntentReviewerAuthorityCurrentStatusBinding(
    deploymentIntent,
  );
  const separatedGenesis =
    assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
      reviewerGenesis,
      roleSeparation,
    );
  const acceptanceOptions = {
    reviewerGenesis: separatedGenesis,
    statusHistory: reviewerStatusHistory,
    ...roleSeparation,
  };
  const acceptance = enforceFreshness
    ? assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
      reviewerGenesisAcceptance,
      {
        ...acceptanceOptions,
        now: currentStatusValidationInstant(checkedAtMs),
        expectedCurrentStatusEpoch:
          anchoredHead.reviewerAuthorityCurrentStatusEpoch,
        expectedCurrentStatusSha256:
          anchoredHead.reviewerAuthorityCurrentStatusSha256,
      },
    )
    : normalizeReleaseReviewerAuthorityGenesisAcceptance(
      reviewerGenesisAcceptance,
      acceptanceOptions,
    );
  const status = acceptance.reviewer_authority_current_status;
  const statusSha256 = releaseReviewerAuthorityCurrentStatusSha256(status, {
    reviewerGenesis: separatedGenesis,
    statusHistory: reviewerStatusHistory,
    ...roleSeparation,
  });
  if (status.epoch
      !== anchoredHead.reviewerAuthorityCurrentStatusEpoch
    || statusSha256
      !== anchoredHead.reviewerAuthorityCurrentStatusSha256) {
    fail("reviewer current-status is stale or forked from the deployment-intent head");
  }
  return {
    acceptance,
    genesis: separatedGenesis,
    roleSeparation,
    authority: normalizeExpectedReviewerAuthority({
      approved_reviewers: status.active_reviewers,
      approved_reviewer_hashes: status.approved_reviewer_hashes,
      reviewer_root_hash: status.reviewer_root_hash,
      reviewer_set_sha256: status.reviewer_set_sha256,
    }, {
      expectedReviewerRootHash: status.reviewer_root_hash,
      expectedReviewerSetSha256: status.reviewer_set_sha256,
    }),
  };
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, keys, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function assertBoundedJson(value, label) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    fail(`${label} must be an acyclic JSON value`);
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) fail(`${label} exceeds the byte bound`);
  const pending = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const entry = pending.pop();
    nodes += 1;
    if (nodes > 20_000 || entry.depth > 20) fail(`${label} exceeds structural bounds`);
    if (entry.value === null || typeof entry.value === "number") {
      if (entry.value === null || !Number.isSafeInteger(entry.value) || Object.is(entry.value, -0)) {
        fail(`${label} contains unsupported null or numeric values`);
      }
    } else if (typeof entry.value === "string" || typeof entry.value === "boolean") {
      // Accepted after field-specific normalization.
    } else if (Array.isArray(entry.value)) {
      if (entry.value.length > MAX_TRANSACTIONS * 4) fail(`${label} array is too large`);
      for (const child of entry.value) pending.push({ value: child, depth: entry.depth + 1 });
    } else if (isRecord(entry.value)) {
      if (Object.keys(entry.value).length > 128) fail(`${label} object is too large`);
      for (const child of Object.values(entry.value)) {
        pending.push({ value: child, depth: entry.depth + 1 });
      }
    } else {
      fail(`${label} contains non-JSON values`);
    }
  }
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function sha256(value, label) {
  if (!SHA256.test(value) || value === ZERO_SHA256) fail(`${label} must be a nonzero SHA-256 pin`);
  return value;
}

function bareSha256(value, label) {
  if (!BARE_SHA256.test(value) || value === "0".repeat(64)) fail(`${label} must be a nonzero bare SHA-256`);
  return value;
}

function address(value, label, { allowZero = false } = {}) {
  if (!ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) fail(`${label} must be a canonical address`);
  return value;
}

function bytes32(value, label) {
  if (!BYTES32.test(value) || value === `0x${"0".repeat(64)}`) fail(`${label} must be nonzero bytes32`);
  return value;
}

function hexData(value, label, maximumBytes = 65_536) {
  if (!HEX_DATA.test(value) || (value.length - 2) / 2 > maximumBytes) {
    fail(`${label} must be bounded canonical lowercase hex data`);
  }
  return value;
}

function decimal(value, label) {
  if (!DECIMAL.test(value)) fail(`${label} must be a canonical uint256 decimal string`);
  try {
    if (BigInt(value) >= (1n << 256n)) fail(`${label} exceeds uint256`);
  } catch {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function canonicalPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value) {
    fail(`${label} must be a canonical absolute path without aliases`);
  }
  return value;
}

function network(value, label) {
  const parsed = exact(value, ["chain_id", "name"], label);
  return {
    chain_id: integer(parsed.chain_id, `${label}.chain_id`, CHAIN_ID, CHAIN_ID),
    name: exactString(parsed.name, NETWORK_NAME, `${label}.name`),
  };
}

function normalizeToolchain(value) {
  const parsed = exact(value, ["foundry", "solidity"], "deployment toolchain");
  const foundry = exact(
    parsed.foundry,
    ["buildProfile", "castExecutableSha256", "castVersion", "commitSha", "forgeVersion"],
    "deployment toolchain foundry",
  );
  const solidity = exact(
    parsed.solidity,
    [
      "bytecodeHash", "cborMetadata", "compilerVersion", "configuredVersion",
      "evmVersion", "libraries", "optimizer", "optimizerRuns", "profile",
      "useLiteralContent", "viaIr",
    ],
    "deployment toolchain solidity",
  );
  if (JSON.stringify(foundry) !== JSON.stringify(DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry)
    || JSON.stringify(solidity) !== JSON.stringify(DEPLOYMENT_TOOLCHAIN_AUTHORITY.solidity)) {
    fail("deployment toolchain must equal the exact v3 authority");
  }
  return { foundry: { ...foundry }, solidity: { ...solidity, libraries: [] } };
}

function normalizePlanTransaction(value, index) {
  const parsed = exact(value, [
    "calldata_sha256", "nonce", "sequence", "signer_address", "to",
    "value_wei", "writer_id",
  ], `ceremony transaction plan entry ${index}`);
  if (parsed.sequence !== index) fail("ceremony transaction plan sequence must be contiguous from zero");
  if (!RELEASE_CEREMONY_MUTATION_WRITERS.includes(parsed.writer_id)) {
    fail("ceremony transaction plan writer is unsupported");
  }
  return {
    sequence: index,
    writer_id: parsed.writer_id,
    signer_address: address(parsed.signer_address, `plan[${index}].signer_address`),
    nonce: decimal(parsed.nonce, `plan[${index}].nonce`),
    to: address(parsed.to, `plan[${index}].to`),
    value_wei: decimal(parsed.value_wei, `plan[${index}].value_wei`),
    calldata_sha256: sha256(parsed.calldata_sha256, `plan[${index}].calldata_sha256`),
  };
}

export function releaseCeremonyTransactionPlanSha256({ releaseSha, chainId, transactions }) {
  if (!SHA40.test(releaseSha)) fail("transaction-plan release SHA is invalid");
  integer(chainId, "transaction-plan chain ID", CHAIN_ID, CHAIN_ID);
  const normalized = transactions.map(normalizePlanTransaction);
  return domainDigest("dnai-wikigen/release-ceremony-transaction-plan/v1\0", {
    schema: RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
    release_sha: releaseSha,
    chain_id: chainId,
    transactions: normalized,
  });
}

function normalizeTransactionPlan(value, releaseSha) {
  const parsed = exact(value, ["plan_sha256", "schema", "transactions"], "ceremony transaction plan");
  exactString(parsed.schema, RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA, "transaction plan schema");
  if (!Array.isArray(parsed.transactions)
    || parsed.transactions.length !== RELEASE_CEREMONY_MUTATION_WRITERS.length) {
    fail("ceremony transaction plan must contain exactly the six canonical mutations");
  }
  const transactions = parsed.transactions.map(normalizePlanTransaction);
  for (let index = 0; index < RELEASE_CEREMONY_MUTATION_WRITERS.length; index += 1) {
    if (transactions[index].writer_id !== RELEASE_CEREMONY_MUTATION_WRITERS[index]) {
      fail("ceremony transaction plan writers must appear once in canonical order");
    }
  }
  const lastNonce = new Map();
  for (const entry of transactions) {
    const nonce = BigInt(entry.nonce);
    const prior = lastNonce.get(entry.signer_address);
    if (prior !== undefined && nonce !== prior + 1n) {
      fail("ceremony transaction plan nonces must be contiguous per signer");
    }
    lastNonce.set(entry.signer_address, nonce);
  }
  const expected = releaseCeremonyTransactionPlanSha256({
    releaseSha,
    chainId: CHAIN_ID,
    transactions,
  });
  if (parsed.plan_sha256 !== expected) fail("ceremony transaction plan digest is invalid");
  return { schema: parsed.schema, plan_sha256: expected, transactions };
}

export function timestamp(value, label) {
  if (!UTC_MILLISECONDS.test(value)) fail(`${label} must be canonical millisecond UTC`);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) fail(`${label} is invalid`);
  return time;
}

function normalizeSignatureVerifier(value) {
  const parsed = exact(value, [
    "build_profile", "commit_sha", "executable_sha256",
    "executable_user_relative_path", "tool", "version",
  ], "signature verifier");
  if (JSON.stringify(parsed) !== JSON.stringify(RELEASE_AUTHORITY_SIGNATURE_VERIFIER)) {
    fail("signature verifier must equal the pinned cast authority");
  }
  return { ...parsed };
}

function normalizeDependencyList(value, kinds, expectedPins) {
  if (!Array.isArray(value) || value.length !== kinds.length) {
    fail("cryptographic review dependencies are incomplete");
  }
  return value.map((entry, index) => {
    const parsed = exact(entry, ["kind", "sha256"], `review dependency ${index}`);
    exactString(parsed.kind, kinds[index], `review dependency ${index} kind`);
    const pin = sha256(parsed.sha256, `review dependency ${index} digest`);
    if (pin !== expectedPins[index]) fail(`review dependency ${parsed.kind} does not match the subject`);
    return { kind: parsed.kind, sha256: pin };
  });
}

export function reviewSigningPayload(value) {
  const parsed = exact(value, [
    "approved_reviewer_hashes", "chain_id", "dependencies", "expires_at",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256", "schema", "signature_scheme", "signature_verifier", "signed_at", "stage",
    "subject_kind", "subject_sha256",
  ], "cryptographic review signing payload");
  if (parsed.schema !== RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA
    || ![CEREMONY_AUTHORIZATION_CORE_STATUS, LIVE_ACTIVATION_AUTHORITY_STATUS].includes(parsed.stage)
    || ![CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND, LIVE_ACTIVATION_REVIEW_SUBJECT_KIND].includes(parsed.subject_kind)
    || parsed.signature_scheme !== RELEASE_AUTHORITY_SIGNATURE_SCHEME) {
    fail("cryptographic review signing payload stage or scheme is invalid");
  }
  if (!SHA40.test(parsed.release_sha)) fail("review release SHA is invalid");
  integer(parsed.chain_id, "review chain ID", CHAIN_ID, CHAIN_ID);
  sha256(parsed.subject_sha256, "review subject digest");
  sha256(parsed.reviewer_authority_genesis_sha256, "reviewer authority genesis digest");
  sha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "reviewer authority genesis acceptance digest",
  );
  bareSha256(parsed.reviewer_root_hash, "reviewer root");
  sha256(parsed.reviewer_set_sha256, "reviewer set digest");
  normalizeSignatureVerifier(parsed.signature_verifier);
  if (!Array.isArray(parsed.approved_reviewer_hashes)
    || parsed.approved_reviewer_hashes.length < 2
    || parsed.approved_reviewer_hashes.some((entry) => !BARE_SHA256.test(entry))) {
    fail("review approved reviewer hashes are invalid");
  }
  const hashes = [...parsed.approved_reviewer_hashes].sort();
  if (JSON.stringify(hashes) !== JSON.stringify(parsed.approved_reviewer_hashes)
    || new Set(hashes).size !== hashes.length
    || executionPolicyReviewerRootHash(hashes) !== parsed.reviewer_root_hash) {
    fail("review approved reviewer hashes do not match their canonical root");
  }
  timestamp(parsed.signed_at, "review signed_at");
  timestamp(parsed.expires_at, "review expires_at");
  return {
    schema: parsed.schema,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    subject_sha256: parsed.subject_sha256,
    dependencies: parsed.dependencies,
    reviewer_authority_genesis_sha256: parsed.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: normalizeSignatureVerifier(parsed.signature_verifier),
  };
}

export function releaseAuthorityReviewSigningPayloadSha256(value) {
  return eip191AuthorizationSigningDigest({
    domain: RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN,
    payload: reviewSigningPayload(value),
  });
}

export function releaseAuthorityReviewSigningMessage(value) {
  return eip191AuthorizationSigningMessage({
    prefix: RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX,
    digest: releaseAuthorityReviewSigningPayloadSha256(value),
  });
}

export function normalizeCryptographicReview(value, {
  stage,
  subjectKind,
  subjectSha256,
  releaseSha,
  dependencies,
  reviewerAuthority,
  reviewerGenesis,
  reviewerGenesisAcceptance,
  reviewerStatusHistory = [],
  reviewerRoleSeparation = {},
  checkedAtMs,
  enforceFreshness,
}) {
  const parsed = exact(value, [
    "approved_reviewer_hashes", "chain_id", "dependencies", "expires_at",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256", "schema", "signature_scheme", "signature_verifier", "signatures", "signed_at",
    "signing_payload_sha256", "stage", "subject_kind", "subject_sha256",
  ], "cryptographic authority review");
  exactString(parsed.schema, RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA, "review schema");
  exactString(parsed.stage, stage, "review stage");
  exactString(parsed.subject_kind, subjectKind, "review subject kind");
  if (parsed.release_sha !== releaseSha || parsed.chain_id !== CHAIN_ID
    || parsed.subject_sha256 !== subjectSha256) {
    fail("cryptographic review release, chain, stage, or subject binding is invalid");
  }
  const genesisSha256 = releaseReviewerAuthorityGenesisSha256(reviewerGenesis);
  const acceptanceSha256 = releaseReviewerAuthorityGenesisAcceptanceSha256(
    reviewerGenesisAcceptance,
    {
      reviewerGenesis,
      statusHistory: reviewerStatusHistory,
      ...reviewerRoleSeparation,
    },
  );
  if (parsed.reviewer_authority_genesis_sha256 !== genesisSha256
    || parsed.reviewer_authority_genesis_acceptance_sha256 !== acceptanceSha256
    || parsed.reviewer_root_hash !== reviewerAuthority.reviewer_root_hash
    || parsed.reviewer_set_sha256 !== reviewerAuthority.reviewer_set_sha256
    || JSON.stringify(parsed.approved_reviewer_hashes)
      !== JSON.stringify(reviewerAuthority.approved_reviewer_hashes)) {
    fail("cryptographic review does not match the reviewed signer authority/root");
  }
  const normalizedDependencies = normalizeDependencyList(
    parsed.dependencies,
    dependencies.map((entry) => entry.kind),
    dependencies.map((entry) => entry.sha256),
  );
  const signingPayload = reviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    subject_sha256: parsed.subject_sha256,
    dependencies: normalizedDependencies,
    reviewer_authority_genesis_sha256: parsed.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    approved_reviewer_hashes: parsed.approved_reviewer_hashes,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: parsed.signature_verifier,
  });
  const payloadSha256 = releaseAuthorityReviewSigningPayloadSha256(signingPayload);
  if (parsed.signing_payload_sha256 !== payloadSha256) fail("review signing payload digest is invalid");
  const signedAt = timestamp(parsed.signed_at, "review signed_at");
  const expiresAt = timestamp(parsed.expires_at, "review expires_at");
  if (expiresAt <= signedAt
    || expiresAt - signedAt > MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS
    || (enforceFreshness && (
      !Number.isFinite(checkedAtMs)
      || signedAt > checkedAtMs + MAX_FUTURE_SKEW_MS
      || expiresAt - checkedAtMs < MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS
    ))) {
    fail("cryptographic review is expired or outside its bounded lifetime");
  }
  if (!Array.isArray(parsed.signatures) || parsed.signatures.length !== 2) {
    fail("cryptographic review requires exactly two signatures");
  }
  const signatures = parsed.signatures.map((entry, index) => {
    const signature = exact(entry, ["address", "controller_id", "signature"], `review signature ${index}`);
    const signer = address(signature.address, `review signature ${index} address`);
    if (!CONTROLLER.test(signature.controller_id)) fail("review controller ID is invalid");
    return { address: signer, controller_id: signature.controller_id, signature: signature.signature };
  });
  const message = releaseAuthorityReviewSigningMessage(signingPayload);
  verifyPinnedTwoSignerAuthorization({ signatures, message, reviewerAuthority });
  return {
    schema: parsed.schema,
    stage: parsed.stage,
    subject_kind: parsed.subject_kind,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    subject_sha256: parsed.subject_sha256,
    dependencies: normalizedDependencies,
    reviewer_authority_genesis_sha256: parsed.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    approved_reviewer_hashes: [...parsed.approved_reviewer_hashes],
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    signed_at: parsed.signed_at,
    expires_at: parsed.expires_at,
    signature_scheme: parsed.signature_scheme,
    signature_verifier: normalizeSignatureVerifier(parsed.signature_verifier),
    signing_payload_sha256: payloadSha256,
    signatures,
  };
}

export function assertReviewSignedUnderAnchoredReviewerStatus(review, {
  reviewerGenesis,
  reviewerGenesisAcceptance,
  reviewerStatusHistory,
  deploymentIntent,
}) {
  normalizeReleaseReviewerAuthorityForStage({
    reviewerGenesis,
    reviewerGenesisAcceptance,
    reviewerStatusHistory,
    deploymentIntent,
    checkedAtMs: timestamp(review.signed_at, "review signed_at"),
    enforceFreshness: true,
  });
}

function assertCeremonyReviewInsideRuntimeAuthorityWindow(
  review,
  preCeremonyRuntimeAuthority,
) {
  const signedAtMs = timestamp(review.signed_at, "ceremony review signed_at");
  const expiresAtMs = timestamp(review.expires_at, "ceremony review expires_at");
  if (signedAtMs < preCeremonyRuntimeAuthority.issued_at * 1_000
    || signedAtMs
      >= preCeremonyRuntimeAuthority.activation_evidence_lease_expires_at * 1_000
    || expiresAtMs
      > preCeremonyRuntimeAuthority.activation_evidence_lease_expires_at * 1_000) {
    fail("ceremony review is outside the pre-ceremony runtime-authority proof window");
  }
}

function stageOneDependencies(body) {
  return STAGE_ONE_DEPENDENCY_KINDS.map((kind) => ({
    kind,
    sha256: ({
      deployment_intent: body.deployment_authority.deployment_intent_sha256,
      reviewer_authority_genesis:
        body.deployment_authority.reviewer_authority_genesis_sha256,
      reviewer_authority_genesis_acceptance:
        body.deployment_authority.reviewer_authority_genesis_acceptance_sha256,
      fresh_contract_deployment_receipt:
        body.deployment_authority.fresh_contract_deployment_receipt_sha256,
      immutable_deployment_manifest:
        body.deployment_authority.immutable_deployment_manifest.sha256,
      ceremony_ledger_initialization_receipt:
        body.ceremony_ledger_initialization.initialization_receipt_sha256,
      ceremony_ledger_initial: body.ceremony_ledger_initialization.ledger_initial_sha256,
      ceremony_transaction_plan: body.ceremony_transaction_plan.plan_sha256,
      cvm_launch_intent: body.cvm_launch_intent_sha256,
      cvm_nonlive_bootstrap_authorization_receipt:
        body.cvm_bootstrap_authorization_receipt_sha256,
      pre_ceremony_runtime_authority: body.pre_ceremony_runtime_authority_sha256,
    })[kind],
  }));
}

function normalizeStageOneBody(value) {
  const parsed = exact(value, [
    "ceremony_ledger_initialization", "ceremony_transaction_plan",
    "cvm_bootstrap_authorization_receipt_sha256", "cvm_launch_intent_sha256", "deployment_authority", "lock_protocol",
    "network", "pre_ceremony_runtime_authority_sha256", "release_sha",
    "schema", "status", "truth_status",
  ], "ceremony authorization body");
  exactString(parsed.schema, CEREMONY_AUTHORIZATION_CORE_SCHEMA, "ceremony authorization schema");
  exactString(parsed.status, CEREMONY_AUTHORIZATION_CORE_STATUS, "ceremony authorization status");
  exactString(
    parsed.truth_status,
    "pre_ceremony_authorization_not_finalized_ceremony_or_live_activation",
    "ceremony authorization truth status",
  );
  if (!SHA40.test(parsed.release_sha)) fail("ceremony authorization release SHA is invalid");
  const normalizedNetwork = network(parsed.network, "ceremony authorization network");
  exactString(parsed.lock_protocol, RELEASE_CEREMONY_LOCK_PROTOCOL, "ceremony lock protocol");
  const deployment = exact(parsed.deployment_authority, [
    "deployment_intent_sha256", "fresh_contract_deployment_receipt_sha256",
    "immutable_deployment_manifest", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "toolchain",
  ], "deployment authority");
  const manifest = exact(deployment.immutable_deployment_manifest, [
    "bytes", "mode", "path", "schema_version", "sha256",
  ], "immutable deployment manifest");
  const normalizedManifest = {
    path: canonicalPath(manifest.path, "immutable deployment manifest path"),
    sha256: sha256(manifest.sha256, "immutable deployment manifest digest"),
    bytes: integer(manifest.bytes, "immutable deployment manifest bytes", 2, MAX_BYTES),
    mode: integer(manifest.mode, "immutable deployment manifest mode", 0o444, 0o444),
    schema_version: integer(manifest.schema_version, "immutable deployment manifest schema", 2, 2),
  };
  const ledger = exact(parsed.ceremony_ledger_initialization, [
    "initialization_receipt_path", "initialization_receipt_sha256", "ledger_initial_bytes",
    "ledger_initial_sha256", "ledger_mode", "ledger_path", "lock_protocol",
    "source_manifest_sha256",
  ], "ceremony ledger initialization");
  const normalizedLedger = {
    initialization_receipt_path: canonicalPath(
      ledger.initialization_receipt_path,
      "ceremony ledger initialization receipt path",
    ),
    initialization_receipt_sha256: sha256(
      ledger.initialization_receipt_sha256,
      "ceremony ledger initialization receipt digest",
    ),
    ledger_path: canonicalPath(ledger.ledger_path, "ceremony ledger path"),
    ledger_initial_sha256: sha256(ledger.ledger_initial_sha256, "initial ceremony ledger digest"),
    ledger_initial_bytes: integer(ledger.ledger_initial_bytes, "initial ceremony ledger bytes", 2, MAX_BYTES),
    ledger_mode: integer(ledger.ledger_mode, "ceremony ledger mode", 0o600, 0o600),
    source_manifest_sha256: sha256(ledger.source_manifest_sha256, "ceremony ledger source digest"),
    lock_protocol: exactString(ledger.lock_protocol, RELEASE_CEREMONY_LOCK_PROTOCOL, "ledger lock protocol"),
  };
  if (normalizedLedger.source_manifest_sha256 !== normalizedManifest.sha256
    || normalizedLedger.ledger_initial_sha256 !== normalizedManifest.sha256
    || normalizedLedger.ledger_initial_bytes !== normalizedManifest.bytes
    || normalizedLedger.ledger_path === normalizedManifest.path) {
    fail("ceremony ledger initialization must be the exact separate byte-for-byte manifest copy");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    network: normalizedNetwork,
    deployment_authority: {
      deployment_intent_sha256: sha256(deployment.deployment_intent_sha256, "deployment intent digest"),
      reviewer_authority_genesis_sha256: sha256(
        deployment.reviewer_authority_genesis_sha256,
        "reviewer authority genesis digest",
      ),
      reviewer_authority_genesis_acceptance_sha256: sha256(
        deployment.reviewer_authority_genesis_acceptance_sha256,
        "reviewer authority genesis acceptance digest",
      ),
      fresh_contract_deployment_receipt_sha256: sha256(
        deployment.fresh_contract_deployment_receipt_sha256,
        "fresh contract receipt digest",
      ),
      immutable_deployment_manifest: normalizedManifest,
      toolchain: normalizeToolchain(deployment.toolchain),
    },
    cvm_launch_intent_sha256: sha256(parsed.cvm_launch_intent_sha256, "CVM launch intent digest"),
    cvm_bootstrap_authorization_receipt_sha256: sha256(
      parsed.cvm_bootstrap_authorization_receipt_sha256,
      "non-live CVM bootstrap authorization receipt digest",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "pre-ceremony runtime authority digest",
    ),
    ceremony_ledger_initialization: normalizedLedger,
    ceremony_transaction_plan: normalizeTransactionPlan(
      parsed.ceremony_transaction_plan,
      parsed.release_sha,
    ),
    lock_protocol: parsed.lock_protocol,
  };
}

export function ceremonyAuthorizationReviewSubjectSha256(value) {
  return domainDigest(CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN, normalizeStageOneBody(value));
}

export function ceremonyAuthorizationReviewSigningPayload(unsignedBody, reviewMetadata) {
  const body = normalizeStageOneBody(unsignedBody);
  return reviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: CEREMONY_AUTHORIZATION_CORE_STATUS,
    subject_kind: CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
    release_sha: body.release_sha,
    chain_id: CHAIN_ID,
    subject_sha256: ceremonyAuthorizationReviewSubjectSha256(body),
    dependencies: stageOneDependencies(body),
    ...reviewMetadata,
    signature_scheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    signature_verifier: RELEASE_AUTHORITY_SIGNATURE_VERIFIER,
  });
}

/**
 * Production-only Stage-B signing projection. The ordinary projection above is
 * intentionally pure so historical bytes remain replayable; this entry point
 * refuses parsed/cloned R values and therefore cannot authorize activation from
 * a synthetically reconstructed pre-ceremony dependency.
 */
export function ceremonyAuthorizationReviewSigningPayloadForProduction(
  unsignedBody,
  reviewMetadata,
  { preCeremonyRuntimeAuthority } = {},
) {
  const authority = assertFreshBrandedPreCeremonyRuntimeAuthority(
    preCeremonyRuntimeAuthority,
  );
  const body = normalizeStageOneBody(unsignedBody);
  if (body.release_sha !== authority.release_sha
    || body.deployment_authority.deployment_intent_sha256
      !== authority.deployment_intent_sha256
    || body.cvm_launch_intent_sha256 !== authority.cvm_launch_intent_sha256
    || body.pre_ceremony_runtime_authority_sha256
      !== preCeremonyRuntimeAuthoritySha256(authority)) {
    fail("production ceremony signing body does not bind the exact fresh branded R");
  }
  assertCeremonyReviewInsideRuntimeAuthorityWindow(
    reviewMetadata,
    authority,
  );
  return ceremonyAuthorizationReviewSigningPayload(body, reviewMetadata);
}

export function normalizeCeremonyAuthorizationCore(value, {
  deploymentIntent,
  freshContractDeploymentReceipt: freshContractDeploymentReceiptValue,
  reviewerGenesis: reviewerGenesisValue,
  reviewerGenesisAcceptance: reviewerGenesisAcceptanceValue,
  reviewerStatusHistory = [],
  preCeremonyRuntimeAuthority: preCeremonyRuntimeAuthorityValue,
  checkedAtMs = Date.now(),
  enforceFreshness = true,
} = {}) {
  assertBoundedJson(value, "ceremony authorization core");
  const parsed = exact(value, [
    "ceremony_ledger_initialization", "ceremony_transaction_plan",
    "cvm_bootstrap_authorization_receipt_sha256", "cvm_launch_intent_sha256", "deployment_authority", "lock_protocol", "network",
    "pre_ceremony_runtime_authority_sha256", "release_sha", "review", "schema",
    "status", "truth_status",
  ], "ceremony authorization core");
  const intentValidation = validateDeploymentIntentCore(deploymentIntent);
  if (!intentValidation.ok) {
    fail("ceremony authorization requires the exact valid deployment intent dependency");
  }
  let reviewerGenesis;
  let reviewerGenesisAcceptance;
  let freshContractDeploymentReceipt;
  let preCeremonyRuntimeAuthority;
  try {
    reviewerGenesis = normalizeReleaseReviewerAuthorityGenesis(reviewerGenesisValue);
    ({
      acceptance: reviewerGenesisAcceptance,
      genesis: reviewerGenesis,
    } =
      normalizeReleaseReviewerAuthorityForStage({
        reviewerGenesis,
        reviewerGenesisAcceptance: reviewerGenesisAcceptanceValue,
        reviewerStatusHistory,
        deploymentIntent,
        checkedAtMs,
        enforceFreshness,
      }));
    preCeremonyRuntimeAuthority = normalizePreCeremonyRuntimeAuthority(
      preCeremonyRuntimeAuthorityValue,
    );
  } catch (error) {
    fail(`ceremony authorization dependency is invalid: ${error.message}`);
  }
  const reviewerGenesisSha = releaseReviewerAuthorityGenesisSha256(reviewerGenesis);
  const reviewerGenesisAcceptanceSha = releaseReviewerAuthorityGenesisAcceptanceSha256(
    reviewerGenesisAcceptance,
    {
      reviewerGenesis,
      statusHistory: reviewerStatusHistory,
      ...deploymentRoleSeparation(deploymentIntent),
    },
  );
  const deploymentIntentSha = canonicalArtifactSha256(deploymentIntent);
  try {
    freshContractDeploymentReceipt = normalizeFreshContractDeploymentReceipt(
      freshContractDeploymentReceiptValue,
      {
        expectedDeploymentIntentSha256: deploymentIntentSha,
        expectedReviewerAuthorityGenesisAcceptanceSha256:
          reviewerGenesisAcceptanceSha,
      },
    );
  } catch (error) {
    fail(`ceremony authorization fresh deployment receipt is invalid: ${error.message}`);
  }
  if (deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256
    !== reviewerGenesisAcceptanceSha) {
    fail("deployment intent does not precommit the exact signed reviewer-authority genesis acceptance");
  }
  const {
    authority: reviewerAuthority,
    roleSeparation: reviewerRoleSeparation,
  } =
    normalizeReleaseReviewerAuthorityForStage({
      reviewerGenesis,
      reviewerGenesisAcceptance,
      reviewerStatusHistory,
      deploymentIntent,
      checkedAtMs,
      enforceFreshness: false,
    });
  const body = normalizeStageOneBody(Object.fromEntries(
    Object.entries(parsed).filter(([key]) => key !== "review"),
  ));
  const runtimeAuthoritySha = preCeremonyRuntimeAuthoritySha256(
    preCeremonyRuntimeAuthority,
  );
  const freshContractDeploymentReceiptSha = `sha256:${freshContractDeploymentReceiptDigest(
    freshContractDeploymentReceipt,
    {
      expectedDeploymentIntentSha256: deploymentIntentSha,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        reviewerGenesisAcceptanceSha,
    },
  )}`;
  if (body.release_sha !== deploymentIntent.release.releaseSha
    || body.release_sha !== freshContractDeploymentReceipt.release_sha
    || body.release_sha !== reviewerGenesis.release_sha
    || body.release_sha !== preCeremonyRuntimeAuthority.release_sha
    || body.deployment_authority.deployment_intent_sha256 !== deploymentIntentSha
    || body.deployment_authority.reviewer_authority_genesis_sha256 !== reviewerGenesisSha
    || body.deployment_authority.reviewer_authority_genesis_acceptance_sha256
      !== reviewerGenesisAcceptanceSha
    || body.deployment_authority.fresh_contract_deployment_receipt_sha256
      !== freshContractDeploymentReceiptSha
    || body.pre_ceremony_runtime_authority_sha256 !== runtimeAuthoritySha
    || preCeremonyRuntimeAuthority.deployment_intent_sha256 !== deploymentIntentSha
    || preCeremonyRuntimeAuthority.cvm_launch_intent_sha256 !== body.cvm_launch_intent_sha256) {
    fail("ceremony authorization transitive intent/genesis-acceptance/runtime dependencies drifted");
  }
  const subjectSha = ceremonyAuthorizationReviewSubjectSha256(body);
  const review = normalizeCryptographicReview(parsed.review, {
    stage: CEREMONY_AUTHORIZATION_CORE_STATUS,
    subjectKind: CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
    subjectSha256: subjectSha,
    releaseSha: body.release_sha,
    dependencies: stageOneDependencies(body),
    reviewerAuthority,
    reviewerGenesis,
    reviewerGenesisAcceptance,
    reviewerStatusHistory,
    reviewerRoleSeparation,
    checkedAtMs,
    enforceFreshness,
  });
  assertReviewSignedUnderAnchoredReviewerStatus(review, {
    reviewerGenesis,
    reviewerGenesisAcceptance,
    reviewerStatusHistory,
    deploymentIntent,
  });
  assertCeremonyReviewInsideRuntimeAuthorityWindow(
    review,
    preCeremonyRuntimeAuthority,
  );
  return { ...body, review };
}

export function canonicalCeremonyAuthorizationCoreArtifactText(value, options) {
  return canonicalText(normalizeCeremonyAuthorizationCore(value, {
    ...options,
    enforceFreshness: false,
  }));
}

export function ceremonyAuthorizationCoreDigest(value, options) {
  return domainDigest(CEREMONY_AUTHORIZATION_CORE_DOMAIN, normalizeCeremonyAuthorizationCore(value, {
    ...options,
    enforceFreshness: false,
  })).slice(7);
}

export function ceremonyAuthorizationCoreSha256(value, options) {
  return `sha256:${ceremonyAuthorizationCoreDigest(value, options)}`;
}

export function assertFreshProductionCeremonyAuthorizationCore(value, options = {}) {
  assertFreshBrandedPreCeremonyRuntimeAuthority(
    options.preCeremonyRuntimeAuthority,
  );
  return normalizeCeremonyAuthorizationCore(value, {
    ...options,
    enforceFreshness: true,
  });
}

export function frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization(
  value,
  options,
) {
  const ceremonyAuthorization = normalizeCeremonyAuthorizationCore(value, options);
  const observationSha256 = sha256(
    options?.computeWorkloadActivationObservationSha256,
    "frontend build compute-workload activation observation digest",
  );
  return Object.freeze({
    releaseSha: ceremonyAuthorization.release_sha,
    deploymentIntentSha256:
      ceremonyAuthorization.deployment_authority.deployment_intent_sha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      ceremonyAuthorization.deployment_authority
        .reviewer_authority_genesis_acceptance_sha256,
    ceremonyAuthorizationSha256: ceremonyAuthorizationCoreSha256(value, options),
    runtimeAuthorityDependencySha256:
      ceremonyAuthorization.pre_ceremony_runtime_authority_sha256,
    computeWorkloadActivationObservationSha256: observationSha256,
  });
}
