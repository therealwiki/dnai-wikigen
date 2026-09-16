import { createHash } from "node:crypto";
import https from "node:https";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import { BASE_SEPOLIA_CHAIN_ID } from "./cvm-launch-intent-core.mjs";

export const PHALA_PRODUCTION_FINALIZED_READINESS_SCHEMA =
  "dnai.phala-production-finalized-readiness.v1";
export const PHALA_PRODUCTION_FINALIZED_READINESS_DOMAIN =
  "dnai-wikigen/phala-production-finalized-readiness/v1\0";
export const PHALA_PRODUCTION_FINALIZED_READINESS_LIFETIME_MS = 30_000;

const RESPONSE_DOMAIN =
  "dnai-wikigen/phala-production-finalized-readiness-rpc-response/v1\0";
const ENDPOINT_DOMAIN =
  "dnai-wikigen/phala-production-finalized-readiness-rpc-endpoint/v1\0";
const ORIGIN_DOMAIN =
  "dnai-wikigen/phala-production-finalized-readiness-rpc-origin/v1\0";
const MAX_RPC_URL_BYTES = 4_096;
const MAX_RPC_RESPONSE_BYTES = 1024 * 1024;
const RPC_TIMEOUT_MS = 20_000;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const ISO_MILLISECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const FRESH_FINALIZED_READINESS = new WeakMap();

// Capture the built-in transport at module evaluation. The production API has
// no client, callback, fetch, or transport injection surface.
const HTTPS_REQUEST = https.request.bind(https);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_MILLISECOND.test(value)
    || !Number.isFinite(Date.parse(value))
    || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC millisecond timestamp`);
  }
  return value;
}

function parseRpcEndpoint(value, label) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 9
    || Buffer.byteLength(value, "utf8") > MAX_RPC_URL_BYTES
    || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error(`${label} must be a bounded exact HTTPS endpoint`);
  }
  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTPS endpoint`);
  }
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password
    || endpoint.hash || endpoint.toString() !== value
    || !endpoint.hostname || endpoint.port === "80") {
    throw new Error(`${label} must be an exact credential-free-authority HTTPS URL`);
  }
  return endpoint;
}

function endpointDigest(endpoint) {
  return domainDigest(ENDPOINT_DOMAIN, { endpoint: endpoint.toString() });
}

function originDigest(endpoint) {
  return domainDigest(ORIGIN_DOMAIN, { origin: endpoint.origin });
}

function exactQuantity(value, label) {
  if (typeof value !== "string" || !QUANTITY.test(value)) {
    throw new Error(`${label} is not a canonical JSON-RPC quantity`);
  }
  const parsed = Number.parseInt(value.slice(2), 16);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} exceeds the safe integer range`);
  }
  return parsed;
}

function exactBlock(value, label) {
  if (!isRecord(value)) throw new Error(`${label} is not a block object`);
  const number = exactQuantity(value.number, `${label}.number`);
  if (number < 1 || typeof value.hash !== "string"
    || !BYTES32.test(value.hash) || value.hash !== value.hash.toLowerCase()) {
    throw new Error(`${label} number or hash is invalid`);
  }
  return { number, hash: value.hash };
}

function responseDigest(method, result) {
  return domainDigest(RESPONSE_DOMAIN, { method, result });
}

function appendQuery(endpoint, params) {
  const url = new URL(endpoint);
  for (const [key, value] of Object.entries(params || {})) {
    if (Array.isArray(value)) {
      value.forEach((entry) => url.searchParams.append(key, String(entry)));
    } else if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function requestJsonRpc(endpoint, method, params, id) {
  const body = Buffer.from(JSON.stringify({
    jsonrpc: "2.0",
    id,
    method,
    params,
  }), "utf8");
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (message) => {
      if (settled) return;
      settled = true;
      reject(new Error(message));
    };
    const request = HTTPS_REQUEST({
      protocol: "https:",
      hostname: endpoint.hostname,
      port: endpoint.port || 443,
      method: "POST",
      path: `${endpoint.pathname}${endpoint.search}`,
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "content-length": String(body.length),
        "user-agent": "dnai-phala-production-readiness/1",
      },
      timeout: RPC_TIMEOUT_MS,
      agent: false,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        if (settled) return;
        const bytes = Buffer.from(chunk);
        length += bytes.length;
        if (length > MAX_RPC_RESPONSE_BYTES) {
          response.destroy();
          fail("Base Sepolia JSON-RPC response exceeded the bounded size");
          return;
        }
        chunks.push(bytes);
      });
      response.on("error", () => fail("Base Sepolia JSON-RPC response failed"));
      response.on("end", () => {
        if (settled) return;
        if (response.statusCode !== 200) {
          fail("Base Sepolia JSON-RPC returned a non-200 status");
          return;
        }
        let parsed;
        try {
          parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          fail("Base Sepolia JSON-RPC returned invalid JSON");
          return;
        }
        if (!isRecord(parsed)
          || JSON.stringify(Object.keys(parsed).sort())
            !== JSON.stringify(["id", "jsonrpc", "result"])
          || parsed.jsonrpc !== "2.0" || parsed.id !== id
          || parsed.result === null || parsed.result === undefined) {
          fail("Base Sepolia JSON-RPC envelope is not exact or contains an error");
          return;
        }
        settled = true;
        resolve(parsed.result);
      });
    });
    request.on("timeout", () => {
      request.destroy();
      fail("Base Sepolia JSON-RPC request timed out");
    });
    request.on("error", () => fail("Base Sepolia JSON-RPC transport failed"));
    request.end(body);
  });
}

function normalizeRpcObservation(value, label) {
  const parsed = exactRecord(value, [
    "endpoint_sha256",
    "origin_sha256",
    "chain_id_response_sha256",
    "finalized_response_sha256",
    "numbered_block_response_sha256",
  ], label);
  return {
    endpoint_sha256: exactDigest(parsed.endpoint_sha256, `${label}.endpoint_sha256`),
    origin_sha256: exactDigest(parsed.origin_sha256, `${label}.origin_sha256`),
    chain_id_response_sha256: exactDigest(
      parsed.chain_id_response_sha256,
      `${label}.chain_id_response_sha256`,
    ),
    finalized_response_sha256: exactDigest(
      parsed.finalized_response_sha256,
      `${label}.finalized_response_sha256`,
    ),
    numbered_block_response_sha256: exactDigest(
      parsed.numbered_block_response_sha256,
      `${label}.numbered_block_response_sha256`,
    ),
  };
}

export function normalizeProductionFinalizedReadiness(value) {
  assertCanonicalPlainDataGraph(value, { label: "production finalized readiness" });
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "chain_id",
    "common_finalized_block_number",
    "common_finalized_block_hash",
    "checked_at",
    "expires_at",
    "primary_rpc",
    "secondary_rpc",
    "transport",
    "invariants",
  ], "production finalized readiness");
  if (parsed.schema !== PHALA_PRODUCTION_FINALIZED_READINESS_SCHEMA
    || parsed.status !== "fresh_authenticated_dual_rpc_finalized_readiness"
    || parsed.truth_status
      !== "dual_https_rpc_finalized_chain_observation_not_phala_or_tdx_evidence"
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || !Number.isSafeInteger(parsed.common_finalized_block_number)
    || parsed.common_finalized_block_number < 1
    || typeof parsed.common_finalized_block_hash !== "string"
    || !BYTES32.test(parsed.common_finalized_block_hash)
    || parsed.common_finalized_block_hash
      !== parsed.common_finalized_block_hash.toLowerCase()) {
    throw new Error("production finalized readiness identity or block is invalid");
  }
  const checkedAt = exactTimestamp(parsed.checked_at, "readiness checked_at");
  const expiresAt = exactTimestamp(parsed.expires_at, "readiness expires_at");
  if (Date.parse(expiresAt) - Date.parse(checkedAt)
      !== PHALA_PRODUCTION_FINALIZED_READINESS_LIFETIME_MS) {
    throw new Error("production finalized readiness lifetime is not exact");
  }
  const primary = normalizeRpcObservation(parsed.primary_rpc, "primary RPC");
  const secondary = normalizeRpcObservation(parsed.secondary_rpc, "secondary RPC");
  if (primary.endpoint_sha256 === secondary.endpoint_sha256
    || primary.origin_sha256 === secondary.origin_sha256) {
    throw new Error("production finalized readiness requires independent RPC endpoints and origins");
  }
  const transport = exactRecord(parsed.transport, [
    "protocol",
    "timeout_ms",
    "retry",
    "redirect",
    "maximum_response_bytes",
  ], "finalized readiness transport");
  if (transport.protocol !== "node_https"
    || transport.timeout_ms !== RPC_TIMEOUT_MS
    || transport.retry !== 0 || transport.redirect !== "error"
    || transport.maximum_response_bytes !== MAX_RPC_RESPONSE_BYTES) {
    throw new Error("finalized readiness transport is not exact and fail-closed");
  }
  const invariants = exactRecord(parsed.invariants, [
    "both_chain_ids_match",
    "both_finalized_heads_match",
    "common_numbered_block_rechecked",
    "caller_supplied_timestamp",
    "caller_supplied_client_or_callback",
    "rpc_urls_present_in_receipt",
  ], "finalized readiness invariants");
  const expectedInvariants = {
    both_chain_ids_match: true,
    both_finalized_heads_match: true,
    common_numbered_block_rechecked: true,
    caller_supplied_timestamp: false,
    caller_supplied_client_or_callback: false,
    rpc_urls_present_in_receipt: false,
  };
  if (JSON.stringify(invariants) !== JSON.stringify(expectedInvariants)) {
    throw new Error("finalized readiness invariants are invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_PRODUCTION_FINALIZED_READINESS_SCHEMA,
    status: "fresh_authenticated_dual_rpc_finalized_readiness",
    truth_status:
      "dual_https_rpc_finalized_chain_observation_not_phala_or_tdx_evidence",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    common_finalized_block_number: parsed.common_finalized_block_number,
    common_finalized_block_hash: parsed.common_finalized_block_hash,
    checked_at: checkedAt,
    expires_at: expiresAt,
    primary_rpc: primary,
    secondary_rpc: secondary,
    transport: {
      protocol: "node_https",
      timeout_ms: RPC_TIMEOUT_MS,
      retry: 0,
      redirect: "error",
      maximum_response_bytes: MAX_RPC_RESPONSE_BYTES,
    },
    invariants: expectedInvariants,
  }, { label: "normalized production finalized readiness" });
}

export function canonicalProductionFinalizedReadinessText(value) {
  return canonicalText(normalizeProductionFinalizedReadiness(value));
}

export function productionFinalizedReadinessSha256(value) {
  return domainDigest(
    PHALA_PRODUCTION_FINALIZED_READINESS_DOMAIN,
    normalizeProductionFinalizedReadiness(value),
  );
}

export async function collectProductionFinalizedReadiness(input = {}) {
  const options = exactRecord(
    input,
    ["primaryRpcUrl", "secondaryRpcUrl"],
    "production finalized readiness input",
  );
  const primaryEndpoint = parseRpcEndpoint(options.primaryRpcUrl, "primary RPC");
  const secondaryEndpoint = parseRpcEndpoint(options.secondaryRpcUrl, "secondary RPC");
  const primaryEndpointSha256 = endpointDigest(primaryEndpoint);
  const secondaryEndpointSha256 = endpointDigest(secondaryEndpoint);
  const primaryOriginSha256 = originDigest(primaryEndpoint);
  const secondaryOriginSha256 = originDigest(secondaryEndpoint);
  if (primaryEndpointSha256 === secondaryEndpointSha256
    || primaryOriginSha256 === secondaryOriginSha256) {
    throw new Error("primary and secondary RPC endpoints and origins must be independent");
  }

  const [primaryChainRaw, secondaryChainRaw] = await Promise.all([
    requestJsonRpc(primaryEndpoint, "eth_chainId", [], 1),
    requestJsonRpc(secondaryEndpoint, "eth_chainId", [], 1),
  ]);
  const primaryChain = exactQuantity(primaryChainRaw, "primary RPC chain id");
  const secondaryChain = exactQuantity(secondaryChainRaw, "secondary RPC chain id");
  if (primaryChain !== BASE_SEPOLIA_CHAIN_ID
    || secondaryChain !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error("both finalized readiness RPCs must authenticate Base Sepolia");
  }

  const [primaryFinalizedRaw, secondaryFinalizedRaw] = await Promise.all([
    requestJsonRpc(primaryEndpoint, "eth_getBlockByNumber", ["finalized", false], 2),
    requestJsonRpc(secondaryEndpoint, "eth_getBlockByNumber", ["finalized", false], 2),
  ]);
  const primaryFinalized = exactBlock(primaryFinalizedRaw, "primary finalized block");
  const secondaryFinalized = exactBlock(secondaryFinalizedRaw, "secondary finalized block");
  if (primaryFinalized.number !== secondaryFinalized.number
    || primaryFinalized.hash !== secondaryFinalized.hash) {
    throw new Error("dual Base Sepolia RPCs do not agree on one finalized head");
  }
  const blockQuantity = `0x${primaryFinalized.number.toString(16)}`;
  const [primaryNumberedRaw, secondaryNumberedRaw] = await Promise.all([
    requestJsonRpc(primaryEndpoint, "eth_getBlockByNumber", [blockQuantity, false], 3),
    requestJsonRpc(secondaryEndpoint, "eth_getBlockByNumber", [blockQuantity, false], 3),
  ]);
  const primaryNumbered = exactBlock(primaryNumberedRaw, "primary numbered block");
  const secondaryNumbered = exactBlock(secondaryNumberedRaw, "secondary numbered block");
  if (primaryNumbered.number !== primaryFinalized.number
    || secondaryNumbered.number !== primaryFinalized.number
    || primaryNumbered.hash !== primaryFinalized.hash
    || secondaryNumbered.hash !== primaryFinalized.hash) {
    throw new Error("common finalized block failed the dual numbered-block recheck");
  }
  const checkedMs = Date.now();
  const receipt = normalizeProductionFinalizedReadiness({
    schema: PHALA_PRODUCTION_FINALIZED_READINESS_SCHEMA,
    status: "fresh_authenticated_dual_rpc_finalized_readiness",
    truth_status:
      "dual_https_rpc_finalized_chain_observation_not_phala_or_tdx_evidence",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    common_finalized_block_number: primaryFinalized.number,
    common_finalized_block_hash: primaryFinalized.hash,
    checked_at: new Date(checkedMs).toISOString(),
    expires_at: new Date(
      checkedMs + PHALA_PRODUCTION_FINALIZED_READINESS_LIFETIME_MS,
    ).toISOString(),
    primary_rpc: {
      endpoint_sha256: primaryEndpointSha256,
      origin_sha256: primaryOriginSha256,
      chain_id_response_sha256: responseDigest("eth_chainId", primaryChainRaw),
      finalized_response_sha256: responseDigest(
        "eth_getBlockByNumber:finalized",
        primaryFinalizedRaw,
      ),
      numbered_block_response_sha256: responseDigest(
        `eth_getBlockByNumber:${blockQuantity}`,
        primaryNumberedRaw,
      ),
    },
    secondary_rpc: {
      endpoint_sha256: secondaryEndpointSha256,
      origin_sha256: secondaryOriginSha256,
      chain_id_response_sha256: responseDigest("eth_chainId", secondaryChainRaw),
      finalized_response_sha256: responseDigest(
        "eth_getBlockByNumber:finalized",
        secondaryFinalizedRaw,
      ),
      numbered_block_response_sha256: responseDigest(
        `eth_getBlockByNumber:${blockQuantity}`,
        secondaryNumberedRaw,
      ),
    },
    transport: {
      protocol: "node_https",
      timeout_ms: RPC_TIMEOUT_MS,
      retry: 0,
      redirect: "error",
      maximum_response_bytes: MAX_RPC_RESPONSE_BYTES,
    },
    invariants: {
      both_chain_ids_match: true,
      both_finalized_heads_match: true,
      common_numbered_block_rechecked: true,
      caller_supplied_timestamp: false,
      caller_supplied_client_or_callback: false,
      rpc_urls_present_in_receipt: false,
    },
  });
  FRESH_FINALIZED_READINESS.set(
    receipt,
    productionFinalizedReadinessSha256(receipt),
  );
  return receipt;
}

export function assertFreshProductionFinalizedReadiness(value) {
  const brandedDigest = value && FRESH_FINALIZED_READINESS.get(value);
  if (!brandedDigest) {
    throw new Error("a privately branded dual-RPC finalized readiness receipt is required");
  }
  const normalized = normalizeProductionFinalizedReadiness(value);
  if (productionFinalizedReadinessSha256(normalized) !== brandedDigest
    || canonicalText(normalized) !== canonicalText(value)
    || Date.now() >= Date.parse(normalized.expires_at)) {
    throw new Error("dual-RPC finalized readiness brand, digest, or freshness failed");
  }
  return value;
}
