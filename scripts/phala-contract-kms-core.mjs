import { createPublicKey, ECDH } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import { parseCanonicalPublicHttpsUrl } from "./canonical-public-https-url-core.mjs";

const MAX_ITEMS = 512;
const MAX_TARGETS = 32;
const HASH = /^(?!0{64}$)[0-9a-f]{64}$/;
const SLUG = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

function fail(label, reason) {
  throw new Error(`${label}: ${reason}`);
}

function plain(value, label) {
  assertCanonicalPlainDataGraph(value, {
    label,
    maximumDepth: 24,
    maximumNodes: 40_000,
  });
  return value;
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(label, "must be an object");
  }
  return value;
}

function own(value, key, label) {
  if (!Object.hasOwn(value, key)) fail(label, `missing explicit ${key}`);
  return value[key];
}

function text(value, label, maximum = 256) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
    || value !== value.trim() || /[^\x20-\x7e]/.test(value)) {
    fail(label, "must be a bounded nonempty ASCII string");
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = 1_000_000_000) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0)
    || value < minimum || value > maximum) {
    fail(label, "must be an explicit bounded integer");
  }
  return value;
}

function identifier(value, prefix, label) {
  if (typeof value !== "string"
    || !new RegExp(`^${prefix}_[A-Za-z0-9]{1,128}$`).test(value)) {
    fail(label, `must be an opaque ${prefix}_ identifier`);
  }
  return value;
}

function slug(value, label) {
  if (!SLUG.test(text(value, label, 128))) fail(label, "is not a canonical slug");
  return value;
}

function endpoint(value, label) {
  return parseCanonicalPublicHttpsUrl(value, { label, allowPort: true }).href;
}

function array(value, label, minimum = 0, maximum = MAX_ITEMS) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    fail(label, "must be a bounded array");
  }
  return value;
}

function unique(items, key, label) {
  const seen = new Map();
  for (const item of items) {
    const identity = key(item);
    if (seen.has(identity)) fail(label, "duplicate or conflicting identity");
    seen.set(identity, item);
  }
  return seen;
}

function freeze(value) {
  return deepFreezeCanonicalPlainDataGraph(value, { label: "Phala contract KMS projection" });
}

function compare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function digest(value, label) {
  if (typeof value !== "string" || !HASH.test(value)) fail(label, "must be a nonzero canonical 32-byte digest");
  return value;
}

function imageNames(value, label) {
  return array(value, label).map((entry) => text(entry, label, 128));
}

function compressedK256(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "").toLowerCase() : "";
  if (!/^0[23][0-9a-f]{64}$/.test(hex)) fail("KMS k256_pubkey", "must be a compressed secp256k1 key");
  try {
    if (ECDH.convertKey(hex, "secp256k1", "hex", "hex", "compressed") !== hex) {
      fail("KMS k256_pubkey", "must be canonical");
    }
  } catch {
    fail("KMS k256_pubkey", "is not a valid secp256k1 point");
  }
  return `0x${hex}`;
}

function caDer(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "").toLowerCase() : "";
  if (!/^(?:[0-9a-f]{2}){32,4096}$/.test(hex)) fail("KMS ca_pubkey", "must be bounded DER public-key hex");
  try {
    const key = createPublicKey({ key: Buffer.from(hex, "hex"), format: "der", type: "spki" });
    if (key.type !== "public"
      || key.export({ format: "der", type: "spki" }).toString("hex") !== hex) {
      fail("KMS ca_pubkey", "must be a canonical DER SubjectPublicKeyInfo");
    }
  } catch {
    fail("KMS ca_pubkey", "is not a canonical DER SubjectPublicKeyInfo");
  }
  return hex;
}

/** Validate shape and cryptographic encoding only; callers must pin reviewed keys. */
export function normalizePhalaKmsContract(value) {
  plain(value, "KMS contract");
  const entry = record(value, "KMS contract");
  if (entry.slug !== "phala" || entry.contract_address !== "phala" || entry.chain_id !== 0) {
    fail("KMS contract", "must be the explicit centralized Phala contract");
  }
  const label = own(entry, "label", "KMS contract");
  return freeze({
    id: identifier(entry.id, "kc", "KMS contract id"),
    slug: "phala",
    label: label === null ? null : text(label, "KMS contract label"),
    contract_address: "phala",
    chain_id: 0,
    k256_pubkey: compressedK256(entry.k256_pubkey),
    ca_pubkey: caDer(entry.ca_pubkey),
    node_count: integer(entry.node_count, "KMS contract node_count", 1, MAX_ITEMS),
  });
}

function replica(value, { allowMissingSlug = false } = {}) {
  const entry = record(value, "KMS replica");
  if (entry.kms_type !== "phala") fail("KMS replica", "must have explicit phala type");
  const replicaSlug = allowMissingSlug && !Object.hasOwn(entry, "slug") ? null
    : own(entry, "slug", "KMS replica");
  return {
    id: identifier(entry.id, "kms", "KMS replica id"),
    slug: replicaSlug === null ? null : slug(replicaSlug, "KMS replica slug"),
    url: endpoint(entry.url, "KMS replica URL"),
    version: text(entry.version, "KMS replica version", 128),
    kms_type: "phala",
  };
}

/** The node endpoint is unpaginated; total and contract.node_count must both match. */
export function normalizePhalaKmsContractNodes(value, { contract } = {}) {
  const authority = normalizePhalaKmsContract(contract);
  plain(value, "KMS contract node inventory");
  const inventory = record(value, "KMS contract node inventory");
  const items = array(inventory.items, "KMS replicas", 1).map((entry) => replica(entry));
  if (integer(inventory.total, "KMS inventory total", 1, MAX_ITEMS) !== items.length
    || authority.node_count !== items.length) {
    fail("KMS node inventory", "must be complete and match the exact contract count");
  }
  unique(items, (entry) => entry.id, "KMS replica ids");
  unique(items.filter((entry) => entry.slug !== null), (entry) => entry.slug, "KMS replica slugs");
  unique(items, (entry) => entry.url, "KMS replica URLs");
  return freeze(items.sort((left, right) => compare(left.id, right.id)));
}

function normalizeOsImage(value) {
  const os = record(value, "reviewed OS image");
  if (os.is_dev !== false || os.requires_gpu !== false) {
    fail("reviewed OS image", "must bind the exact non-dev CPU image hash");
  }
  return {
    name: text(os.name, "reviewed OS name", 128),
    slug: slug(os.slug, "reviewed OS slug"),
    version: text(os.version, "reviewed OS version", 64),
    os_image_hash: digest(os.os_image_hash, "reviewed OS hash"),
  };
}

function imageAvailable(host, os) {
  const matches = array(host.images, "host OS images").filter((image) => (
    record(image, "host OS image").name === os.name
    || image.slug === os.slug || image.os_image_hash === os.os_image_hash
  ));
  if (!matches.length) return false;
  if (matches.length !== 1) fail("host OS images", "reviewed image is ambiguous");
  const image = matches[0];
  const version = array(image.version, "host OS version", 3, 4)
    .map((part) => integer(part, "host OS version component", 0, 1_000)).join(".");
  if (image.name !== os.name || image.slug !== os.slug || version !== os.version
    || image.os_image_hash !== os.os_image_hash || image.is_dev !== false
    || image.requires_gpu !== false || image.supports_cpu !== true || image.enabled !== true) {
    fail("host OS image", "differs from the exact enabled reviewed non-dev CPU image");
  }
  return true;
}

function deviceIds(host) {
  const entries = array(host.device_ids, "host device_ids", 1, 16).map((entry) => {
    record(entry, "host device identity");
    if (typeof entry.enabled !== "boolean") {
      fail("host device identity", "must have an explicit digest and enabled posture");
    }
    return {
      device_id: digest(entry.device_id, "host device_id"),
      algorithm_version: text(entry.algorithm_version, "device algorithm version", 64),
      enabled: entry.enabled,
    };
  });
  unique(entries, (entry) => entry.device_id, "host device identities");
  unique(entries, (entry) => entry.algorithm_version, "host device algorithms");
  const enabled = entries.filter((entry) => entry.enabled);
  if (!enabled.length) fail("host device identities", "no enabled device identity");
  if (host.device_id !== undefined && host.device_id !== null
    && !enabled.some((entry) => entry.device_id === host.device_id)) {
    fail("host device identity", "legacy device_id differs from enabled matrix");
  }
  return enabled.sort((left, right) => compare(left.device_id, right.device_id));
}

function gatewayAppId(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "").toLowerCase() : "";
  if (!/^(?!0{40}$)[0-9a-f]{40}$/.test(hex)) fail("gateway app id", "must be a nonzero 20-byte id");
  return `0x${hex}`;
}

function requestedTargets(value) {
  record(value, "resource targets");
  const domains = Object.keys(value).sort();
  if (domains.length < 1 || domains.length > MAX_TARGETS) fail("resource targets", "invalid target count");
  return domains.map((domain) => {
    if (!/^[a-z][a-z0-9_]{0,127}$/.test(domain)) fail("resource domain", "invalid identity");
    const target = record(value[domain], "resource target");
    if (typeof target.gateway_required !== "boolean") fail("resource target", "missing explicit gateway_required");
    if (target.placement !== undefined && (target.placement?.selection_mode !== "automatic_best_match"
      || target.placement.node_id !== null || target.placement.region !== null)) {
      fail("resource target", "must retain automatic placement without an implicit node override");
    }
    return {
      domain,
      instance_type: text(target.instance_type, "target instance type", 128),
      disk_size: integer(target.disk_size, "target disk_size", 1),
      gateway_required: target.gateway_required,
    };
  });
}

function targets(value, instanceTypes, capacity) {
  const catalog = unique(array(instanceTypes, "instance-type catalog", 1), (entry) => {
    record(entry, "instance type");
    return text(entry.id, "instance type id", 128);
  }, "instance-type catalog");
  return requestedTargets(value).map((target) => {
    const type = catalog.get(target.instance_type);
    if (!type || type.requires_gpu !== false || type.requires_gpu_count !== 0) {
      fail("resource target", "missing exact CPU instance type");
    }
    const disk = target.disk_size;
    if (disk < integer(type.default_disk_size_gb, "instance default disk", 1)
      || disk > integer(capacity.max_disk_each, "quota max_disk_each", 1)) {
      fail("resource target", "disk violates explicit default or per-instance quota");
    }
    const memory = integer(type.memory_mb, "instance memory_mb", 1);
    if (memory > integer(capacity.max_memory_each, "quota max_memory_each", 1)) {
      fail("resource target", "memory exceeds per-instance quota");
    }
    return {
      domain: target.domain,
      instance_type: target.instance_type,
      disk_size: disk,
      vcpu: integer(type.vcpu, "instance vcpu", 1, 1_024),
      memory_mb: memory,
      gateway_required: target.gateway_required,
    };
  });
}

function normalizeGateways(entries, contractId) {
  const catalog = unique(array(entries, "gateway catalog"), (entry) => {
    record(entry, "gateway");
    return identifier(entry.id, "gn", "gateway id");
  }, "gateway catalog");
  const result = [];
  for (const entry of catalog.values()) {
    if (entry.kms_contract_id !== contractId) continue;
    if (typeof entry.enabled !== "boolean") fail("gateway", "missing explicit enabled posture");
    if (!entry.enabled) continue;
    const suffix = text(entry.domain_suffix, "gateway domain_suffix", 253);
    const domain = parseCanonicalPublicHttpsUrl(`https://${suffix}`, { label: "gateway domain_suffix", originOnly: true });
    if (domain.hostname !== suffix) fail("gateway domain_suffix", "must be a public DNS name only");
    result.push({
      id: entry.id,
      kms_contract_id: contractId,
      node_id: entry.node_id == null ? null : integer(entry.node_id, "gateway node_id", 1),
      teepod_id: entry.teepod_id == null ? null : integer(entry.teepod_id, "gateway teepod_id", 1),
      rpc_url: endpoint(entry.rpc_url, "gateway RPC URL"),
      domain_suffix: suffix,
      enabled: true,
    });
  }
  unique(result, (entry) => entry.rpc_url, "gateway RPC identities");
  unique(result, (entry) => entry.domain_suffix, "gateway domain identities");
  return result.sort((left, right) => compare(left.id, right.id));
}

/**
 * Pure authenticated-catalog projection, NOT launch authority or readiness proof.
 * Each target must explicitly state gateway_required. Keys and contract identity
 * must still equal independently reviewed authority at the integration boundary.
 * Capacity is an observation, not a reservation or a guarantee of later placement.
 */
export function buildPhalaContractKmsProjection({
  contract,
  contractNodes,
  resources,
  osImage,
  resourceTargets,
} = {}) {
  plain({ contract, contractNodes, resources, osImage, resourceTargets }, "KMS catalog inputs");
  const authority = normalizePhalaKmsContract(contract);
  const replicas = normalizePhalaKmsContractNodes(contractNodes, { contract: authority });
  const replicaById = new Map(replicas.map((entry) => [entry.id, entry]));
  record(resources, "CVM resource graph");
  const capacity = record(resources.capacity, "resource quota");
  const requested = targets(resourceTargets, resources.instance_types, capacity);
  const limits = [
    [requested.length, "max_instances"],
    [requested.reduce((sum, entry) => sum + entry.vcpu, 0), "max_vcpu"],
    [requested.reduce((sum, entry) => sum + entry.memory_mb, 0), "max_memory"],
    [requested.reduce((sum, entry) => sum + entry.disk_size, 0), "max_disk"],
  ];
  for (const [required, key] of limits) {
    if (required > integer(capacity[key], `resource quota ${key}`, 1)) fail("resource quota", `insufficient ${key}`);
  }
  const os = normalizeOsImage(osImage);
  const kmsCatalog = unique(array(resources.kms_nodes, "resource KMS catalog", 1), (entry) => {
    record(entry, "resource KMS");
    return identifier(entry.id, "kms", "resource KMS id");
  }, "resource KMS catalog");
  const selectedKms = new Map();
  for (const entry of kmsCatalog.values()) {
    if (entry.kms_contract_id !== authority.id && !replicaById.has(entry.id)) continue;
    const expected = replicaById.get(entry.id);
    if (!expected || entry.kms_contract_id !== authority.id || entry.chain_id !== null
      || (entry.kms_contract_address !== "" && entry.kms_contract_address !== null)
      || JSON.stringify(replica(entry, { allowMissingSlug: true })) !== JSON.stringify(expected)) {
      fail("resource KMS", "replica identity or contract binding conflicts with inventory");
    }
    imageNames(entry.supported_os_images, "KMS supported OS images");
    selectedKms.set(entry.id, entry);
  }
  const hosts = array(resources.nodes, "resource hosts", 1);
  const hostByTeepod = unique(hosts, (host) => {
    record(host, "resource host");
    return integer(host.teepod_id, "host teepod_id", 1);
  }, "host teepod identities");
  unique(hosts, (host) => integer(host.node_id, "host node_id", 1), "host node identities");
  const gateways = normalizeGateways(resources.gateway_nodes, authority.id);
  const relations = array(resources.node_kms_relations, "node KMS relations", 1);
  unique(relations, (entry) => {
    record(entry, "node KMS relation");
    return `${integer(entry.teepod_id, "relation teepod_id", 1)}:${identifier(entry.kms_id, "kms", "relation kms_id")}`;
  }, "node KMS relations");
  const placements = [];
  for (const relation of relations) {
    if (relation.kms_contract_id !== authority.id && !replicaById.has(relation.kms_id)) continue;
    const kms = selectedKms.get(relation.kms_id);
    const host = hostByTeepod.get(relation.teepod_id);
    if (!kms || !host || relation.kms_contract_id !== authority.id || relation.kms_type !== "phala"
      || (relation.kms_contract_address !== "" && relation.kms_contract_address !== null)) {
      fail("node KMS relation", "missing or conflicting exact contract/replica/host identity");
    }
    const supported = imageNames(relation.supported_os_images, "relation supported OS images");
    if (!supported.includes(os.name) || !kms.supported_os_images.includes(os.name)
      || !imageAvailable(host, os)) continue;
    const hostCapacity = {
      remaining_vcpu: integer(host.remaining_vcpu, "host remaining_vcpu"),
      remaining_memory_mb: integer(host.remaining_memory, "host remaining_memory"),
      remaining_cvm_slots: integer(host.remaining_cvm_slots, "host remaining_cvm_slots"),
    };
    const eligibleTargets = requested.filter((target) => (
      hostCapacity.remaining_vcpu >= target.vcpu
      && hostCapacity.remaining_memory_mb >= target.memory_mb
      && hostCapacity.remaining_cvm_slots >= 1
      && (!target.gateway_required || gateways.length > 0)
    ));
    if (!eligibleTargets.length) continue;
    const deviceMatrix = deviceIds(host);
    const requiresGateway = eligibleTargets.some((entry) => entry.gateway_required);
    placements.push({
      node_id: host.node_id,
      teepod_id: host.teepod_id,
      kms_id: kms.id,
      kms_contract_id: authority.id,
      os_image_hash: os.os_image_hash,
      target_domains: eligibleTargets.map((entry) => entry.domain),
      target_requirements: eligibleTargets.map((entry) => ({ ...entry })),
      capacity: hostCapacity,
      device_ids: deviceMatrix,
      gateway_app_id: requiresGateway ? gatewayAppId(kms.gateway_app_id) : null,
    });
  }
  for (const target of requested) {
    if (!placements.some((entry) => entry.target_domains.includes(target.domain))) {
      fail("resource target", `${target.domain} has no eligible authenticated placement`);
    }
  }
  placements.sort((left, right) => left.teepod_id - right.teepod_id
    || compare(left.kms_id, right.kms_id));
  const gatewayIds = new Set(placements.map((entry) => entry.gateway_app_id).filter(Boolean));
  if (gatewayIds.size > 1) fail("gateway app identity", "conflicts across eligible replicas");
  return normalizePhalaContractKmsProjection({
    contract: authority, replicas, eligible_placements: placements, gateways,
  }, { osImage, resourceTargets });
}

function exactRecord(value, keys, label) {
  record(value, label);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail(label, "must contain exactly the normalized fields");
  }
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function equal(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

/**
 * Revalidate a persisted canonical projection without manufacturing API evidence.
 * CPU/memory requirements are retained observed catalog facts, not independent
 * trust anchors. If the caller also supplies reviewed vcpu/memory_mb on targets,
 * those must match. The signed observation binding remains the caller's duty.
 */
export function normalizePhalaContractKmsProjection(value, { osImage, resourceTargets } = {}) {
  plain({ value, osImage, resourceTargets }, "persisted KMS projection");
  const os = normalizeOsImage(osImage);
  return normalizedProjection(value, { osImageHash: os.os_image_hash, resourceTargets });
}

function normalizedProjection(value, { osImageHash, resourceTargets }) {
  exactRecord(value, ["contract", "replicas", "eligible_placements", "gateways"], "KMS projection");
  exactRecord(value.contract, ["id", "slug", "label", "contract_address", "chain_id",
    "k256_pubkey", "ca_pubkey", "node_count"], "projected KMS contract");
  const contract = normalizePhalaKmsContract(value.contract);
  const rawReplicas = array(value.replicas, "projected replicas", 1);
  rawReplicas.forEach((entry) => exactRecord(entry,
    ["id", "slug", "url", "version", "kms_type"], "projected replica"));
  const replicas = normalizePhalaKmsContractNodes({ items: rawReplicas, total: rawReplicas.length }, { contract });
  const replicaById = new Map(replicas.map((entry) => [entry.id, entry]));
  const expectedHash = digest(osImageHash, "projection OS hash");
  const requested = requestedTargets(resourceTargets);
  const targetByDomain = new Map(requested.map((entry) => [entry.domain, entry]));
  array(value.gateways, "projected gateways").forEach((entry) => exactRecord(entry,
    ["id", "kms_contract_id", "node_id", "teepod_id", "rpc_url", "domain_suffix", "enabled"],
    "projected gateway"));
  const gateways = normalizeGateways(value.gateways, contract.id);
  const requirementsByDomain = new Map();
  const placements = array(value.eligible_placements, "eligible placements", 1).map((entry) => {
    exactRecord(entry, ["node_id", "teepod_id", "kms_id", "kms_contract_id", "os_image_hash",
      "target_domains", "target_requirements", "capacity", "device_ids", "gateway_app_id"],
    "eligible placement");
    if (entry.kms_contract_id !== contract.id || !replicaById.has(entry.kms_id)
      || entry.os_image_hash !== expectedHash) {
      fail("eligible placement", "contract, replica, or reviewed OS identity drifted");
    }
    const capacity = exactRecord(entry.capacity,
      ["remaining_vcpu", "remaining_memory_mb", "remaining_cvm_slots"], "placement capacity");
    const normalizedCapacity = {
      remaining_vcpu: integer(capacity.remaining_vcpu, "placement remaining_vcpu", 1),
      remaining_memory_mb: integer(capacity.remaining_memory_mb, "placement remaining_memory_mb", 1),
      remaining_cvm_slots: integer(capacity.remaining_cvm_slots, "placement remaining_cvm_slots", 1),
    };
    const requirements = array(entry.target_requirements, "placement target requirements", 1, MAX_TARGETS)
      .map((requirement) => {
        exactRecord(requirement, ["domain", "instance_type", "disk_size", "vcpu", "memory_mb", "gateway_required"],
          "placement target requirement");
        const expected = targetByDomain.get(requirement.domain);
        if (!expected || requirement.instance_type !== expected.instance_type
          || requirement.disk_size !== expected.disk_size || requirement.gateway_required !== expected.gateway_required) {
          fail("placement target requirement", "differs from the exact reviewed target");
        }
        const result = {
          domain: expected.domain,
          instance_type: expected.instance_type,
          disk_size: expected.disk_size,
          vcpu: integer(requirement.vcpu, "target requirement vcpu", 1, 1_024),
          memory_mb: integer(requirement.memory_mb, "target requirement memory_mb", 1),
          gateway_required: expected.gateway_required,
        };
        for (const field of ["vcpu", "memory_mb"]) {
          if (Object.hasOwn(resourceTargets[expected.domain], field)
            && resourceTargets[expected.domain][field] !== result[field]) {
            fail("placement target requirement", `observed ${field} differs from reviewed target`);
          }
        }
        if (result.vcpu > normalizedCapacity.remaining_vcpu
          || result.memory_mb > normalizedCapacity.remaining_memory_mb
          || (result.gateway_required && gateways.length === 0)) {
          fail("eligible placement", "does not have observed capacity or required gateway evidence");
        }
        const previous = requirementsByDomain.get(result.domain);
        if (previous && !equal(previous, result)) fail("target requirements", "conflict across placements");
        requirementsByDomain.set(result.domain, result);
        return result;
      });
    unique(requirements, (requirement) => requirement.domain, "placement target domains");
    requirements.sort((left, right) => compare(left.domain, right.domain));
    const targetDomains = requirements.map((requirement) => requirement.domain);
    if (!equal(array(entry.target_domains, "placement target domains", 1, MAX_TARGETS), targetDomains)) {
      fail("eligible placement", "target domain list differs from exact sorted requirements");
    }
    const requiredGateway = requirements.some((requirement) => requirement.gateway_required);
    if (!requiredGateway && entry.gateway_app_id !== null) {
      fail("eligible placement", "gateway-free placement must not invent gateway app authority");
    }
    array(entry.device_ids, "projected device identities", 1, 16).forEach((device) => exactRecord(device,
      ["device_id", "algorithm_version", "enabled"], "projected device identity"));
    return {
      node_id: integer(entry.node_id, "placement node_id", 1),
      teepod_id: integer(entry.teepod_id, "placement teepod_id", 1),
      kms_id: entry.kms_id,
      kms_contract_id: contract.id,
      os_image_hash: expectedHash,
      target_domains: targetDomains,
      target_requirements: requirements,
      capacity: normalizedCapacity,
      device_ids: deviceIds({ device_ids: entry.device_ids }),
      gateway_app_id: requiredGateway ? gatewayAppId(entry.gateway_app_id) : null,
    };
  });
  unique(placements, (entry) => `${entry.teepod_id}:${entry.kms_id}`, "eligible placements");
  const hostByTeepod = new Map();
  const teepodByNode = new Map();
  const hostByDevice = new Map();
  for (const entry of placements) {
    const host = { node_id: entry.node_id, teepod_id: entry.teepod_id,
      capacity: entry.capacity, device_ids: entry.device_ids };
    const prior = hostByTeepod.get(entry.teepod_id);
    if ((prior && !equal(prior, host))
      || (teepodByNode.has(entry.node_id) && teepodByNode.get(entry.node_id) !== entry.teepod_id)) {
      fail("placement host identities", "conflicting node/teepod namespace or host facts");
    }
    hostByTeepod.set(entry.teepod_id, host);
    teepodByNode.set(entry.node_id, entry.teepod_id);
    for (const device of entry.device_ids) {
      if (hostByDevice.has(device.device_id) && hostByDevice.get(device.device_id) !== entry.teepod_id) {
        fail("placement device identity", "conflicts across distinct hosts");
      }
      hostByDevice.set(device.device_id, entry.teepod_id);
    }
  }
  for (const gateway of gateways) {
    if (gateway.node_id === null || gateway.teepod_id === null) continue;
    const host = hostByTeepod.get(gateway.teepod_id);
    if ((host && host.node_id !== gateway.node_id)
      || (teepodByNode.has(gateway.node_id) && teepodByNode.get(gateway.node_id) !== gateway.teepod_id)) {
      fail("gateway host identities", "conflict with known node/teepod namespace");
    }
  }
  const gatewayIds = new Set(placements.map((entry) => entry.gateway_app_id).filter(Boolean));
  if (gatewayIds.size > 1) fail("gateway app identity", "conflicts across eligible replicas");
  for (const target of requested) {
    if (!requirementsByDomain.has(target.domain)) fail("eligible placements", `missing target coverage for ${target.domain}`);
  }
  placements.sort((left, right) => left.teepod_id - right.teepod_id || compare(left.kms_id, right.kms_id));
  const result = { contract, replicas, eligible_placements: placements, gateways };
  if (!equal(value, result)) fail("KMS projection", "must already have exact canonical normalized shape and ordering");
  return freeze(result);
}

/**
 * Bind an SDK-transformed prepare response to an already independently reviewed
 * canonical catalog projection. No app/compose/instance/OS or env-key signature
 * authorization occurs here. In particular, an absent/null optional k256_pubkey is
 * not root-key proof; verify the env-key signature against the pinned root before
 * encrypting anything. rawPlacement must come from this response's raw transport
 * capture before the SDK aliases teepod_id to node_id.
 */
export function assertPhalaPreparedKmsBinding({ response, rawPlacement, domain, kmsProjection } = {}) {
  plain({ response, rawPlacement, domain, kmsProjection }, "prepared KMS binding");
  record(response, "prepared response");
  record(rawPlacement, "raw prepare placement");
  const rawFields = Object.keys(rawPlacement);
  if (rawFields.length === 0 || rawFields.some((key) => !["node_id", "teepod_id"].includes(key))) {
    fail("raw prepare placement", "must contain explicit raw node_id and/or teepod_id only");
  }
  for (const field of rawFields) {
    if (rawPlacement[field] !== null) integer(rawPlacement[field], `raw prepare ${field}`, 1);
  }
  const identifiedFields = rawFields.filter((field) => rawPlacement[field] !== null);
  if (identifiedFields.length === 0) {
    fail("raw prepare placement", "requires at least one positive non-null placement identity");
  }
  const transformedNode = Object.hasOwn(rawPlacement, "teepod_id")
    ? rawPlacement.teepod_id : rawPlacement.node_id;
  if (Object.hasOwn(response, "teepod_id") || response.node_id !== transformedNode) {
    fail("prepared response", "does not match the SDK's exact raw teepod/node transformation");
  }

  // Revalidate exact canonical projection shape and internal consistency without
  // inventing independently reviewed targets. The caller pins this whole record.
  const targetsByDomain = {};
  const rawPlacements = array(record(kmsProjection, "prepared KMS projection").eligible_placements,
    "prepared KMS placements", 1);
  for (const placement of rawPlacements) {
    record(placement, "prepared KMS placement");
    for (const requirement of array(placement.target_requirements, "prepared target requirements", 1, MAX_TARGETS)) {
      record(requirement, "prepared target requirement");
      if (typeof requirement.domain !== "string" || !/^[a-z][a-z0-9_]{0,127}$/.test(requirement.domain)) {
        fail("prepared target requirement", "invalid domain");
      }
      const { domain: targetDomain, ...target } = requirement;
      if (Object.hasOwn(targetsByDomain, targetDomain) && !equal(targetsByDomain[targetDomain], target)) {
        fail("prepared target requirements", "conflict across placements");
      }
      Object.defineProperty(targetsByDomain, targetDomain, {
        value: target, enumerable: true, configurable: true, writable: true,
      });
    }
  }
  const projection = normalizedProjection(kmsProjection, {
    osImageHash: rawPlacements[0].os_image_hash,
    resourceTargets: targetsByDomain,
  });
  if (typeof domain !== "string" || !Object.hasOwn(targetsByDomain, domain)) {
    fail("prepared domain", "must identify an exact reviewed resource target");
  }
  if (response.kms_contract_id !== projection.contract.id) {
    fail("prepared KMS contract", "differs from the exact reviewed contract");
  }
  const info = record(response.kms_info, "prepared kms_info");
  if (info.id !== response.kms_id || info.chain_id !== null
    || (info.kms_contract_address !== null && info.kms_contract_address !== "")
    || (Object.hasOwn(info, "kms_type") && info.kms_type !== "phala")
    || (Object.hasOwn(info, "kms_contract_id") && info.kms_contract_id !== projection.contract.id)) {
    fail("prepared kms_info", "has inconsistent centralized contract/replica identity");
  }
  const observedReplica = replica({ ...info, kms_type: "phala" });
  const reviewedReplicas = projection.replicas.filter((entry) => entry.id === response.kms_id);
  if (reviewedReplicas.length !== 1 || !equal(observedReplica, reviewedReplicas[0])) {
    fail("prepared KMS replica", "does not exactly match one reviewed inventory identity");
  }
  if (info.k256_pubkey !== undefined && info.k256_pubkey !== null
    && compressedK256(info.k256_pubkey) !== projection.contract.k256_pubkey) {
    fail("prepared KMS root", "differs from the reviewed contract root");
  }
  const candidates = projection.eligible_placements.filter((placement) => (
    placement.kms_id === response.kms_id
    && placement.target_domains.includes(domain)
    && identifiedFields.every((field) => placement[field] === rawPlacement[field])
  ));
  if (candidates.length !== 1) {
    fail("prepared placement", "must exactly match one eligible replica/domain/host placement");
  }
  const placement = candidates[0];
  const device = digest(response.device_id, "prepared device_id");
  if (!placement.device_ids.some((entry) => entry.enabled === true && entry.device_id === device)) {
    fail("prepared device identity", "is not an enabled reviewed device for the exact host");
  }
  const requiresGateway = targetsByDomain[domain].gateway_required;
  const gateway = requiresGateway ? gatewayAppId(info.gateway_app_id) : null;
  if (requiresGateway && gateway !== placement.gateway_app_id) {
    fail("prepared gateway app identity", "differs from the exact reviewed gateway");
  }
  if (requiresGateway && Object.hasOwn(response, "gateway_app_id")
    && gatewayAppId(response.gateway_app_id) !== gateway) {
    fail("prepared gateway app identity", "conflicts with the response's gateway identity");
  }
  return freeze({
    kms_contract_id: projection.contract.id,
    kms_id: reviewedReplicas[0].id,
    kms_url: reviewedReplicas[0].url,
    node_id: placement.node_id,
    teepod_id: placement.teepod_id,
    device_id: device,
    gateway_app_id: gateway,
  });
}

/**
 * Pass the RAW workspace response before any SDK defaults, not a reconstructed
 * object. This pure function cannot attest transport provenance; the caller must
 * bind raw response capture and authenticated subject to the same session.
 */
export function assertPhalaWorkspaceActiveBilling({ workspace, authenticatedSubject } = {}) {
  plain({ workspace, authenticatedSubject }, "raw workspace billing observation");
  record(workspace, "raw workspace");
  const subject = record(record(authenticatedSubject, "authenticated subject").workspace,
    "authenticated subject workspace");
  if (own(workspace, "billing_status", "raw workspace") !== "active") {
    fail("raw workspace billing", "must explicitly be active; no defaults or suspended/abandoned state");
  }
  const id = text(own(workspace, "id", "raw workspace"), "workspace id", 128);
  const workspaceSlug = slug(own(workspace, "slug", "raw workspace"), "workspace slug");
  if (id !== own(subject, "id", "authenticated workspace")
    || workspaceSlug !== own(subject, "slug", "authenticated workspace")) {
    fail("raw workspace billing", "workspace identity differs from the authenticated subject");
  }
  return freeze({ workspace_id: id, workspace_slug: workspaceSlug, billing_status: "active" });
}
