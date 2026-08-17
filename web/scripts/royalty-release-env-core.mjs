import {
  normalizeRoyaltyReleaseAuthority,
  normalizeRoyaltyReleaseState,
} from "../../scripts/royalty-release-authority-core.mjs";
import {
  normalizeRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "../../scripts/royalty-release-history-receipt-core.mjs";

export const ROYALTY_RELEASE_BROWSER_ENV_KEYS = Object.freeze([
  "VITE_ROYALTY_RELEASE_AUTHORITY_JSON",
  "VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON",
  "VITE_ROYALTY_RELEASE_HISTORY_SHA256",
  "VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256",
]);

const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

function fail(message) {
  throw new TypeError(message);
}

function exactAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    fail(`${label} must be a canonical lowercase address`);
  }
  return value;
}

function exactBytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    fail(`${label} must be canonical lowercase bytes32`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value) || value === ZERO_SHA256) {
    fail(`${label} must be a nonzero sha256 pin`);
  }
  return value;
}

function parseCanonicalJson(value, label) {
  if (typeof value !== "string" || value.length < 2 || value.length > 32_768) {
    fail(`${label} must be bounded canonical JSON`);
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(`${label} must be valid JSON`);
  }
  return parsed;
}

function same(value, expected, label) {
  if (value !== expected) fail(`${label} does not match the Royalty release receipt`);
}

function royaltyContract(receipt) {
  const contract = receipt.contracts.find((entry) =>
    entry.contract_key === "royalty_distributor");
  if (!contract) fail("Royalty release receipt omits RoyaltyDistributor");
  return contract;
}

function executionPolicyAnchorContract(receipt) {
  const contract = receipt.contracts.find((entry) =>
    entry.contract_key === "execution_policy_anchor");
  if (!contract) fail("Royalty release receipt omits ExecutionPolicyAnchor");
  return contract;
}

/**
 * Project only public, deterministic fields from independently normalized
 * post-transaction/pre-D artifact H. H is dual-RPC release evidence; it is not
 * signed live authority and this projector never upgrades it to TDX/QVL proof.
 */
export function projectRoyaltyReleaseBrowserEnv(value, expected = {}) {
  const receipt = normalizeRoyaltyReleaseHistoryReceipt(value);
  const authority = receipt.royalty_release_authority;
  const activeState = receipt.royalty_release_active_state;
  const historySha256 = receipt.royalty_release_history_sha256;
  const historyReceiptSha256 = royaltyReleaseHistoryReceiptSha256(receipt);
  const royalty = royaltyContract(receipt);
  const anchor = executionPolicyAnchorContract(receipt);

  if (authority.distributor_address !== royalty.address
    || activeState.contract_address !== royalty.address
    || authority.owner !== royalty.control_address
    || activeState.owner !== royalty.control_address
    || authority.execution_policy_anchor !== anchor.address) {
    fail("Royalty release receipt drifts from its exact contract configuration set");
  }
  if (expected.royaltyDistributorAddress !== undefined) {
    same(
      royalty.address,
      exactAddress(expected.royaltyDistributorAddress, "expected RoyaltyDistributor"),
      "RoyaltyDistributor address",
    );
  }
  if (expected.royaltyDistributorCodeHash !== undefined) {
    same(
      royalty.runtime_code_hash,
      exactBytes32(expected.royaltyDistributorCodeHash, "expected RoyaltyDistributor runtime"),
      "RoyaltyDistributor runtime hash",
    );
  }
  if (expected.executionPolicyAnchorAddress !== undefined) {
    same(
      authority.execution_policy_anchor,
      exactAddress(expected.executionPolicyAnchorAddress, "expected execution-policy anchor"),
      "Royalty execution-policy anchor",
    );
  }
  if (expected.executionPolicyAnchorWriter !== undefined) {
    same(
      authority.anchor_writer,
      exactAddress(expected.executionPolicyAnchorWriter, "expected execution-policy writer"),
      "Royalty anchor writer",
    );
  }
  if (expected.executionPolicyAnchorWriterReleaseCommitment !== undefined) {
    same(
      authority.anchor_writer_release_commitment,
      exactBytes32(
        expected.executionPolicyAnchorWriterReleaseCommitment,
        "expected execution-policy writer release",
      ),
      "Royalty anchor-writer release commitment",
    );
  }
  return Object.freeze({
    VITE_ROYALTY_RELEASE_AUTHORITY_JSON: JSON.stringify(authority),
    VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON: JSON.stringify(activeState),
    VITE_ROYALTY_RELEASE_HISTORY_SHA256: historySha256,
    VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256: historyReceiptSha256,
  });
}

/**
 * Revalidate the generated public env at the Cloudflare boundary. The caller
 * must additionally prove that signed C binds both returned digests and the
 * exact serialized environment/build.
 */
export function normalizeRoyaltyReleaseBrowserEnv(env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    fail("Royalty release environment must be an object");
  }
  const authorityRaw = parseCanonicalJson(
    env.VITE_ROYALTY_RELEASE_AUTHORITY_JSON,
    "Royalty release authority env",
  );
  const authority = normalizeRoyaltyReleaseAuthority(authorityRaw);
  const activeRaw = parseCanonicalJson(
    env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_JSON,
    "Royalty active state env",
  );
  const activeState = normalizeRoyaltyReleaseState(activeRaw, {
    authority,
    phase: "phase_two_active",
  });
  if (JSON.stringify(authorityRaw) !== JSON.stringify(authority)
    || JSON.stringify(activeRaw) !== JSON.stringify(activeState)) {
    fail("Royalty release environment JSON is not the canonical current projection");
  }
  const historySha256 = sha256(
    env.VITE_ROYALTY_RELEASE_HISTORY_SHA256,
    "Royalty release history digest",
  );
  const historyReceiptSha256 = sha256(
    env.VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256,
    "Royalty release H receipt digest",
  );
  if (historySha256 === historyReceiptSha256) {
    fail("Royalty release history and H receipt digests must be distinct");
  }
  same(
    authority.distributor_address,
    exactAddress(env.VITE_ROYALTY_DISTRIBUTOR_ADDRESS, "RoyaltyDistributor env address"),
    "RoyaltyDistributor address",
  );
  exactBytes32(
    env.VITE_ROYALTY_DISTRIBUTOR_CODE_HASH,
    "RoyaltyDistributor env runtime hash",
  );
  same(
    authority.execution_policy_anchor,
    exactAddress(env.VITE_EXECUTION_POLICY_ANCHOR_ADDRESS, "execution-policy anchor env address"),
    "Royalty execution-policy anchor",
  );
  same(
    authority.anchor_writer,
    exactAddress(env.VITE_EXECUTION_POLICY_ANCHOR_WRITER, "execution-policy writer env address"),
    "Royalty anchor writer",
  );
  same(
    authority.anchor_writer_release_commitment,
    exactBytes32(
      env.VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT,
      "execution-policy writer release env commitment",
    ),
    "Royalty anchor-writer release commitment",
  );
  return Object.freeze({
    authority,
    activeState,
    historySha256,
    historyReceiptSha256,
  });
}
