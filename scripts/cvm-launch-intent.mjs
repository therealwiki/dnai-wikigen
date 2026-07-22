#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  bareSha256,
  canonicalFreshContractDeploymentReceiptText,
  canonicalCvmLaunchIntentCoreArtifactText,
  createDraftCvmLaunchIntentCore,
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_INTENT_CORE_SCHEMA,
  CVM_LAUNCH_TRUTH_STATUS,
  createPhalaDstackComposeHashInput,
  CVM_TOPOLOGY_SCHEMA,
  cvmLaunchIntentCoreDigest,
  cvmLaunchIntentValidationReceipt,
  freshContractDeploymentReceiptDigest,
  phalaDstackComposeHash,
  parseCvmLaunchIntentCoreText,
  projectFreshContractDeploymentReceipt,
  rawSha256,
  releaseSha,
} from "./cvm-launch-intent-core.mjs";
import {
  DEPLOYMENT_INTENT_CORE_SCHEMA,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";

const USAGE = `Usage:
  node scripts/cvm-launch-intent.mjs build --topology FILE --ledger FILE --out FILE --contract-receipt-out FILE
  node scripts/cvm-launch-intent.mjs init-template --out FILE
  node scripts/cvm-launch-intent.mjs check --in FILE [--receipt-out FILE]
  node scripts/cvm-launch-intent.mjs hash --in FILE

build validates and byte-binds one canonical rendered topology, its seven exact
descriptor files, image manifest, attestation bundle, deployment intent, and a
fresh Base Sepolia contract ledger. The launch artifact carries public
structural policy, key names, digests, and an exact sealed-execution policy,
but no environment values. A companion output carries the exact normalized seven-contract receipt used by the launch
digest (addresses, runtime hashes, transaction/block proof, and deployer). It
never reads an env file, secret value, wallet, RPC endpoint, CVM ID, TEE
identity, quote, or Phala compose hash, and it never contacts Phala.`;

const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const CREATED_SCHEMA = "dnai.cvm-launch-intent-created.v1";
const OPERATION_ERROR_SCHEMA = "dnai.cvm-launch-intent-operation-error.v1";

function exactAliasOccurrence(service, destinationEnvironmentKey, interpolationSuffix) {
  return Object.freeze({
    service,
    destination_environment_key: destinationEnvironmentKey,
    path: `$.services.${service}.environment.${destinationEnvironmentKey}`,
    interpolation_suffix: interpolationSuffix,
  });
}

function exactAliasContractEntry(sourceEnvironmentKey, occurrences) {
  return Object.freeze({
    source_environment_key: sourceEnvironmentKey,
    occurrences: Object.freeze(occurrences),
  });
}

// These are aliases of one release-authorized source namespace into the exact
// Settings names consumed by the Arena worker. This is deliberately a closed
// path contract, not permission to duplicate arbitrary environment references.
export const CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT = Object.freeze([
  exactAliasContractEntry("TINKER_COMPUTE_WORKLOAD_CVM_ID", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_COMPUTE_WORKLOAD_CVM_ID",
      ":?Canonical main runtime CVM ID required",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_MAIN_RUNTIME_CVM_ID",
      ":?Canonical main runtime CVM ID required",
    ),
  ]),
  exactAliasContractEntry("TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
      ":?Signed seven-CVM deployment intent required",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256",
      ":?Signed seven-CVM deployment intent required",
    ),
  ]),
  exactAliasContractEntry("TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
      ":-",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_RELEASE_AUTHORITY_SHA256",
      ":-",
    ),
  ]),
  exactAliasContractEntry("TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
      ":?Release ceremony nonce required",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_RELEASE_CEREMONY_NONCE",
      ":?Release ceremony nonce required",
    ),
  ]),
  exactAliasContractEntry(
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    [
      exactAliasOccurrence(
        "delegate",
        "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
        ":-",
      ),
      exactAliasOccurrence(
        "delegate",
        "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
        ":-",
      ),
      exactAliasOccurrence(
        "arena-worker",
        "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
        ":-",
      ),
    ],
  ),
  exactAliasContractEntry("TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
      ":-",
    ),
    exactAliasOccurrence(
      "arena-policy-init",
      "TINKER_ARENA_PROVISION_RELEASE_SHA256",
      ":-",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
      ":-",
    ),
  ]),
  exactAliasContractEntry("TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT", [
    exactAliasOccurrence(
      "delegate",
      "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
      ":-",
    ),
    exactAliasOccurrence(
      "arena-worker",
      "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
      ":-",
    ),
  ]),
]);

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const values = {
    command: command === "--help" || command === "-h" ? "help" : command,
    input: "",
    output: "",
    receiptOutput: "",
    contractReceiptOutput: "",
    topology: "",
    ledger: "",
  };
  const flags = new Set([
    "--in",
    "--out",
    "--receipt-out",
    "--contract-receipt-out",
    "--topology",
    "--ledger",
  ]);
  const seen = new Set();
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    if (flag === "--help" || flag === "-h") {
      values.command = "help";
      continue;
    }
    if (!flags.has(flag) || seen.has(flag)) throw new Error("unsupported or duplicate argument");
    seen.add(flag);
    const next = rest[index + 1];
    if (!next || next.startsWith("-")) throw new Error(`missing value for ${flag}`);
    if (flag === "--in") values.input = next;
    else if (flag === "--out") values.output = next;
    else if (flag === "--receipt-out") values.receiptOutput = next;
    else if (flag === "--contract-receipt-out") values.contractReceiptOutput = next;
    else if (flag === "--topology") values.topology = next;
    else values.ledger = next;
    index += 1;
  }
  return values;
}

async function readBoundedRegularFile(filePath, label, maximum = MAX_INPUT_BYTES) {
  if (!filePath || filePath.includes("\0")) throw new Error(`${label} path is required`);
  const resolved = path.resolve(filePath);
  const resolvedBefore = await realpath(resolved);
  if (resolvedBefore !== resolved) throw new Error(`${label} path must not contain symbolic links`);
  const handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > maximum) {
      throw new Error(`${label} must be a bounded nonempty regular file`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length !== before.size
      || after.size !== before.size
      || after.ino !== before.ino
      || after.mtimeMs !== before.mtimeMs
      || await realpath(resolved) !== resolvedBefore) {
      throw new Error(`${label} changed while being read`);
    }
    return { path: resolved, bytes, text: bytes.toString("utf8") };
  } finally {
    await handle.close();
  }
}

async function writeNewRegularFile(filePath, text) {
  if (!filePath || filePath.includes("\0")) throw new Error("output path is required");
  const resolved = path.resolve(filePath);
  const directory = path.dirname(resolved);
  if (await realpath(directory) !== directory) throw new Error("output path must not contain symbolic links");
  const temporary = path.join(
    directory,
    `.${path.basename(resolved)}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
  );
  let handle;
  let published = false;
  try {
    handle = await open(temporary, "wx", 0o644);
    await handle.writeFile(text, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporary, resolved);
    published = true;
    const directoryHandle = await open(directory, constants.O_RDONLY);
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    if (published) await unlink(resolved).catch(() => {});
    throw error;
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return resolved;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalJson(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]),
  );
}

function canonicalJsonText(value) {
  return `${JSON.stringify(canonicalJson(value), null, 2)}\n`;
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function assertNoDuplicateJsonObjectKeys(text, label) {
  let index = 0;
  const skipWhitespace = () => {
    while (/\s/.test(text[index] || "")) index += 1;
  };
  const parseString = () => {
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      index += 1;
    }
    throw new Error(`${label} contains an unterminated JSON string`);
  };
  const parseValue = () => {
    skipWhitespace();
    if (text[index] === "{") {
      index += 1;
      const keys = new Set();
      skipWhitespace();
      if (text[index] === "}") { index += 1; return; }
      while (index < text.length) {
        skipWhitespace();
        if (text[index] !== '"') throw new Error(`${label} contains malformed JSON`);
        const key = parseString();
        if (keys.has(key)) throw new Error(`${label} repeats JSON object key ${key}`);
        keys.add(key);
        skipWhitespace();
        if (text[index] !== ":") throw new Error(`${label} contains malformed JSON`);
        index += 1;
        parseValue();
        skipWhitespace();
        if (text[index] === "}") { index += 1; return; }
        if (text[index] !== ",") throw new Error(`${label} contains malformed JSON`);
        index += 1;
      }
      throw new Error(`${label} contains malformed JSON`);
    }
    if (text[index] === "[") {
      index += 1;
      skipWhitespace();
      if (text[index] === "]") { index += 1; return; }
      while (index < text.length) {
        parseValue();
        skipWhitespace();
        if (text[index] === "]") { index += 1; return; }
        if (text[index] !== ",") throw new Error(`${label} contains malformed JSON`);
        index += 1;
      }
      throw new Error(`${label} contains malformed JSON`);
    }
    if (text[index] === '"') {
      parseString();
      return;
    }
    const start = index;
    while (index < text.length && !/[\s,\]}]/.test(text[index])) index += 1;
    if (start === index) throw new Error(`${label} contains malformed JSON`);
  };
  parseValue();
  skipWhitespace();
  if (index !== text.length) throw new Error(`${label} contains trailing JSON data`);
}

function parseJson(text, label) {
  try {
    const value = JSON.parse(text);
    assertNoDuplicateJsonObjectKeys(text, label);
    return value;
  } catch {
    throw new Error(`${label} must be valid unambiguous JSON without duplicate keys`);
  }
}

function validateTopology(topology, topologyText, topologyDirectory) {
  if (topologyText !== canonicalJsonText(topology)) {
    throw new Error("topology must be canonical sorted two-space JSON with one trailing newline");
  }
  const value = record(topology, "topology");
  if (value.schema !== CVM_TOPOLOGY_SCHEMA || value.status !== "rendered_not_deployed") {
    throw new Error(`topology must be ${CVM_TOPOLOGY_SCHEMA} and rendered_not_deployed`);
  }
  const sourceRelease = releaseSha(value.release_sha, "topology.release_sha");
  const deploymentIntentSha256 = value.deploymentIntentSha256;
  if (!/^sha256:[0-9a-f]{64}$/.test(deploymentIntentSha256)) {
    throw new Error("topology deploymentIntentSha256 is invalid");
  }
  const checks = record(value.checks, "topology.checks");
  const expectedChecks = {
    deployment_attempted: false,
    literal_digest_pins: true,
    linux_amd64_only: true,
    local_build_contexts: false,
    purpose_separated_qvl_descriptors: true,
    raw_secret_values_embedded: false,
    seven_cvm_descriptors: true,
    tdx_verification_claimed: false,
  };
  for (const [key, expected] of Object.entries(expectedChecks)) {
    if (checks[key] !== expected) throw new Error(`topology check ${key} is not fail-closed`);
  }
  const deploymentIntent = record(value.deploymentIntent, "topology.deploymentIntent");
  if (deploymentIntent.file !== "dnai-deployment-intent-core.json"
    || deploymentIntent.schema !== DEPLOYMENT_INTENT_CORE_SCHEMA
    || `sha256:${bareSha256(deploymentIntent.sha256, "topology deployment intent hash")}`
      !== deploymentIntentSha256) {
    throw new Error("topology deployment-intent binding is inconsistent");
  }
  const imageManifest = record(value.image_manifest, "topology.image_manifest");
  const imageBundle = record(
    value.image_manifest_attestation,
    "topology.image_manifest_attestation",
  );
  if (imageManifest.file !== "dnai-tee-image-release.json"
    || imageManifest.schema !== "dnai.tee-image-release.v1") {
    throw new Error("topology image manifest reference is not canonical");
  }
  if (imageBundle.file !== "dnai-tee-image-release.bundle.json"
    || imageBundle.predicate_type !== "https://slsa.dev/provenance/v1") {
    throw new Error("topology image attestation reference is not canonical");
  }
  const trustDomains = record(value.trust_domains, "topology.trust_domains");
  if (JSON.stringify(Object.keys(trustDomains).sort())
    !== JSON.stringify([...CVM_LAUNCH_DOMAINS].sort())) {
    throw new Error("topology must contain exactly seven canonical trust domains");
  }
  return {
    sourceRelease,
    deploymentIntentSha256,
    deploymentIntent,
    imageManifest,
    imageBundle,
    trustDomains,
    topologyDirectory,
  };
}

function stripYamlComment(line) {
  let singleQuoted = false;
  let doubleQuoted = false;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (doubleQuoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (!doubleQuoted && character === "'") singleQuoted = !singleQuoted;
    else if (!singleQuoted && character === '"') doubleQuoted = !doubleQuoted;
    else if (!singleQuoted && !doubleQuoted && character === "#"
      && (index === 0 || /\s/.test(line[index - 1]))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function leadingSpaces(line, label) {
  const prefix = line.match(/^[ \t]*/)?.[0] || "";
  if (prefix.includes("\t")) {
    throw new Error(`${label} uses ambiguous tab indentation`);
  }
  return prefix.length;
}

function unquotedProfileName(value, label) {
  let normalized = value.trim();
  if ((normalized.startsWith('"') && normalized.endsWith('"'))
    || (normalized.startsWith("'") && normalized.endsWith("'"))) {
    normalized = normalized.slice(1, -1);
  }
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(normalized)) {
    throw new Error(`${label} is not a canonical literal Compose profile`);
  }
  return normalized;
}

function serviceProfileLocations(lines) {
  const servicesHeaders = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (/^services:\s*$/.test(lines[index])) servicesHeaders.push(index);
  }
  if (servicesHeaders.length !== 1) {
    throw new Error("descriptor must contain one unambiguous top-level services mapping");
  }
  const servicesHeader = servicesHeaders[0];
  const blocks = [];
  let serviceIndent;
  let current;
  for (let index = servicesHeader + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    const indent = leadingSpaces(line, `descriptor line ${index + 1}`);
    if (indent === 0) break;
    const mapping = line.match(/^([ ]*)([A-Za-z0-9][A-Za-z0-9_.-]*):\s*$/);
    if (serviceIndent === undefined) {
      if (!mapping) {
        throw new Error("descriptor services mapping has an ambiguous first service");
      }
      serviceIndent = indent;
    }
    if (indent === serviceIndent) {
      if (!mapping) {
        throw new Error(`descriptor line ${index + 1} is ambiguous at service indentation`);
      }
      if (current) current.end = index;
      current = {
        name: mapping[2],
        start: index,
        end: lines.length,
        profiles: [],
      };
      blocks.push(current);
    } else if (indent < serviceIndent) {
      break;
    }
  }
  if (current) {
    const nextTopLevel = lines.findIndex((line, index) => (
      index > current.start && line.trim() && leadingSpaces(line, `descriptor line ${index + 1}`) === 0
    ));
    current.end = nextTopLevel === -1 ? lines.length : nextTopLevel;
  }
  if (!blocks.length || new Set(blocks.map(({ name }) => name)).size !== blocks.length) {
    throw new Error("descriptor services must be a nonempty duplicate-free literal mapping");
  }
  for (const block of blocks) {
    let environmentDeclarations = 0;
    for (let index = block.start + 1; index < block.end; index += 1) {
      const line = lines[index];
      const environment = line.match(/^([ ]*)environment:\s*$/);
      if (!environment) continue;
      const environmentIndent = environment[1].length;
      let parentLine = -1;
      for (let cursor = index - 1; cursor >= block.start; cursor -= 1) {
        if (!lines[cursor].trim()) continue;
        if (leadingSpaces(lines[cursor], `descriptor line ${cursor + 1}`)
          >= environmentIndent) continue;
        parentLine = cursor;
        break;
      }
      if (parentLine === block.start) environmentDeclarations += 1;
    }
    if (environmentDeclarations > 1) {
      throw new Error(
        `descriptor service ${block.name} declares environment more than once`,
      );
    }

    let profilesDeclaration = -1;
    for (let index = block.start + 1; index < block.end; index += 1) {
      const line = lines[index];
      const match = line.match(/^([ ]*)profiles:\s*(.*?)\s*$/);
      if (!match || leadingSpaces(line, `descriptor line ${index + 1}`) <= serviceIndent) continue;
      if (profilesDeclaration !== -1) {
        throw new Error(`descriptor service ${block.name} declares profiles more than once`);
      }
      profilesDeclaration = index;
      const profileIndent = match[1].length;
      const inline = match[2];
      if (inline) {
        if (!inline.startsWith("[") || !inline.endsWith("]")) {
          throw new Error(`descriptor service ${block.name} profiles must be a literal list`);
        }
        const body = inline.slice(1, -1).trim();
        block.profiles = body
          ? body.split(",").map((profile) => unquotedProfileName(
            profile,
            `descriptor service ${block.name} profile`,
          ))
          : [];
        continue;
      }
      for (let cursor = index + 1; cursor < block.end; cursor += 1) {
        const profileLine = lines[cursor];
        if (!profileLine.trim()) continue;
        const item = profileLine.match(/^([ ]*)-\s+(.+?)\s*$/);
        const itemIndent = leadingSpaces(
          profileLine,
          `descriptor line ${cursor + 1}`,
        );
        if (item && itemIndent >= profileIndent) {
          block.profiles.push(unquotedProfileName(
            item[2],
            `descriptor service ${block.name} profile`,
          ));
          continue;
        }
        if (itemIndent <= profileIndent) break;
      }
    }
    if (new Set(block.profiles).size !== block.profiles.length) {
      throw new Error(`descriptor service ${block.name} has duplicate profiles`);
    }
  }
  const serviceByLine = Array(lines.length).fill(null);
  for (const block of blocks) {
    for (let index = block.start; index < block.end; index += 1) {
      serviceByLine[index] = block.name;
    }
  }
  return {
    blocks,
    serviceByLine,
    profilesByService: new Map(blocks.map(({ name, profiles }) => [name, profiles])),
  };
}

function jsonDescriptorLocations(source) {
  assertNoDuplicateJsonObjectKeys(source, "JSON Compose descriptor");
  let descriptor;
  try {
    descriptor = JSON.parse(source);
  } catch {
    throw new Error("JSON Compose descriptor is malformed");
  }
  const services = record(descriptor.services, "JSON Compose descriptor services");
  const blocks = Object.entries(services).map(([name, service]) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) {
      throw new Error(`JSON Compose descriptor service ${name} is not a canonical literal name`);
    }
    const parsedService = record(service, `JSON Compose descriptor service ${name}`);
    const profileValues = parsedService.profiles === undefined ? [] : parsedService.profiles;
    if (!Array.isArray(profileValues)) {
      throw new Error(`JSON Compose descriptor service ${name} profiles must be a literal list`);
    }
    const profiles = profileValues.map((profile) => unquotedProfileName(
      String(profile),
      `JSON Compose descriptor service ${name} profile`,
    ));
    if (new Set(profiles).size !== profiles.length) {
      throw new Error(`JSON Compose descriptor service ${name} has duplicate profiles`);
    }
    return { name, profiles, value: parsedService };
  });
  if (!blocks.length) throw new Error("JSON Compose descriptor services must be nonempty");
  return { descriptor, blocks };
}

function yamlEnvironmentMappingLocation({
  lines,
  blocks,
  lineIndex,
}) {
  const block = blocks.find(({ start, end }) => lineIndex > start && lineIndex < end);
  if (!block) return null;
  const mapping = lines[lineIndex].match(/^([ ]*)([A-Z][A-Z0-9_]*):\s*(.*?)\s*$/);
  if (!mapping) return null;

  const keyIndent = mapping[1].length;
  let environmentLine = -1;
  for (let cursor = lineIndex - 1; cursor > block.start; cursor -= 1) {
    if (!lines[cursor].trim()) continue;
    if (leadingSpaces(lines[cursor], `descriptor line ${cursor + 1}`) >= keyIndent) continue;
    environmentLine = cursor;
    break;
  }
  if (environmentLine === -1) return null;
  const environment = lines[environmentLine].match(/^([ ]*)environment:\s*$/);
  if (!environment) return null;

  const environmentIndent = environment[1].length;
  let parentLine = -1;
  for (let cursor = environmentLine - 1; cursor >= block.start; cursor -= 1) {
    if (!lines[cursor].trim()) continue;
    if (leadingSpaces(lines[cursor], `descriptor line ${cursor + 1}`) >= environmentIndent) continue;
    parentLine = cursor;
    break;
  }
  if (parentLine !== block.start) return null;
  let scalar = mapping[3].trim();
  if ((scalar.startsWith('"') && scalar.endsWith('"'))
    || (scalar.startsWith("'") && scalar.endsWith("'"))) {
    scalar = scalar.slice(1, -1);
  }
  return {
    path: `$.services.${block.name}.environment.${mapping[2]}`,
    scalar,
  };
}

function yamlExactEnvironmentInterpolationPath({
  lines,
  blocks,
  lineIndex,
  name,
  suffix,
}) {
  const mapping = yamlEnvironmentMappingLocation({ lines, blocks, lineIndex });
  if (!mapping || mapping.scalar !== `\${${name}${suffix}}`) return null;
  return mapping.path;
}

function interpolationOccurrencesInJson(source) {
  const { descriptor, blocks } = jsonDescriptorLocations(source);
  const occurrences = [];
  const environmentDestinationPaths = [];
  const pattern = /(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}/g;
  const scan = (value, service, location) => {
    if (typeof value === "string") {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(value)) !== null) {
        occurrences.push({
          name: match[1],
          suffix: match[2],
          exact_environment_scalar:
            value === `\${${match[1]}${match[2]}}`,
          line: null,
          location,
          path: location,
          service,
        });
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => scan(item, service, `${location}[${index}]`));
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, item] of Object.entries(value)) {
      scan(key, service, `${location}.<key>`);
      scan(item, service, `${location}.${key}`);
    }
  };
  for (const [key, value] of Object.entries(descriptor)) {
    if (key === "services") {
      for (const block of blocks) {
        const environment = block.value.environment;
        if (environment && typeof environment === "object" && !Array.isArray(environment)) {
          for (const destination of Object.keys(environment)) {
            environmentDestinationPaths.push(
              `$.services.${block.name}.environment.${destination}`,
            );
          }
        }
        scan(block.value, block.name, `$.services.${block.name}`);
      }
    } else {
      scan(key, null, "$.<key>");
      scan(value, null, `$.${key}`);
    }
  }
  return {
    occurrences,
    environmentDestinationPaths,
    blocks: blocks.map(({ name, profiles }) => ({ name, profiles })),
    profilesByService: new Map(blocks.map(({ name, profiles }) => [name, profiles])),
  };
}

function referencedEnvironmentKeys(text) {
  const all = new Set();
  const nonemptyRequired = new Set();
  const emptyDefault = new Set();
  const fallbackDefault = new Set();
  const semanticLines = text.split(/\r?\n/).map(stripYamlComment);
  const semanticSource = semanticLines.join("\n").trim();
  const jsonLocations = semanticSource.startsWith("{")
    ? interpolationOccurrencesInJson(semanticSource)
    : null;
  const locations = jsonLocations || serviceProfileLocations(semanticLines);
  const pattern = /(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}/g;
  const occurrences = jsonLocations ? [...jsonLocations.occurrences] : [];
  const environmentDestinationPaths = jsonLocations
    ? [...jsonLocations.environmentDestinationPaths]
    : semanticLines.flatMap((_, lineIndex) => {
      const mapping = yamlEnvironmentMappingLocation({
        lines: semanticLines,
        blocks: locations.blocks,
        lineIndex,
      });
      return mapping ? [mapping.path] : [];
    });
  if (!jsonLocations) {
    for (let line = 0; line < semanticLines.length; line += 1) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(semanticLines[line])) !== null) {
        const path = yamlExactEnvironmentInterpolationPath({
          lines: semanticLines,
          blocks: locations.blocks,
          lineIndex: line,
          name: match[1],
          suffix: match[2],
        });
        occurrences.push({
          name: match[1],
          suffix: match[2],
          exact_environment_scalar: path !== null,
          line: line + 1,
          location: `line ${line + 1}`,
          path,
          service: locations.serviceByLine[line],
        });
      }
    }
  }
  for (const { name, suffix } of occurrences) {
    all.add(name);
    if (suffix.startsWith(":?")) nonemptyRequired.add(name);
    else if (suffix === ":-" || suffix === "-") emptyDefault.add(name);
    else fallbackDefault.add(name);
  }
  return {
    all: [...all].sort(),
    nonemptyRequired: [...nonemptyRequired].sort(),
    emptyDefault: [...emptyDefault].sort(),
    fallbackDefault: [...fallbackDefault].sort(),
    nonStrict: [...new Set([...emptyDefault, ...fallbackDefault])].sort(),
    occurrences,
    environmentDestinationPaths,
    serviceBlocks: locations.blocks,
    profilesByService: locations.profilesByService,
  };
}

function assertRenderedComposeName(domain, descriptorText) {
  const expected = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate.name;
  const semanticLines = descriptorText.split(/\r?\n/).map(stripYamlComment);
  const semanticSource = semanticLines.join("\n").trim();
  let actual;
  if (semanticSource.startsWith("{")) {
    actual = jsonDescriptorLocations(semanticSource).descriptor.name;
  } else {
    const names = semanticLines.flatMap((line) => {
      const match = line.match(/^name:\s*([^\s#]+)\s*$/);
      return match ? [match[1].replace(/^["']|["']$/g, "")] : [];
    });
    if (names.length !== 1) {
      throw new Error(`${domain} descriptor must contain one exact top-level Compose name`);
    }
    [actual] = names;
  }
  if (actual !== expected) {
    throw new Error(`${domain} descriptor Compose name is not the reviewed AppCompose name`);
  }
}

function assertExactMainEnvironmentReferenceAliases(domain, references) {
  if (domain !== "main_runtime_cvm") return new Set();
  const contractedSources = new Set();
  for (const contract of CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT) {
    contractedSources.add(contract.source_environment_key);
    const actual = references.occurrences.filter(
      ({ name }) => name === contract.source_environment_key,
    );
    const exactMatches = contract.occurrences.every((expected) => (
      actual.filter((occurrence) => (
        occurrence.service === expected.service
        && occurrence.path === expected.path
        && occurrence.suffix === expected.interpolation_suffix
        && occurrence.exact_environment_scalar === true
      )).length === 1
      && references.environmentDestinationPaths.filter(
        (path) => path === expected.path,
      ).length === 1
    ));
    if (actual.length !== contract.occurrences.length || !exactMatches) {
      throw new Error(
        `${domain} environment source ${contract.source_environment_key} must use only its exact immutable canonical-and-alias reference contract`,
      );
    }
  }
  return contractedSources;
}

function assertEnvironmentClassification(domain, descriptorText) {
  assertRenderedComposeName(domain, descriptorText);
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const references = referencedEnvironmentKeys(descriptorText);
  const expectedReferences = [...new Set([
    ...policy.exact_allowed_environment_keys.filter((key) => key !== "COMPOSE_PROFILES"),
    ...policy.public_environment_key_classification.descriptor_defaulted_keys,
  ])].sort();
  if (JSON.stringify(references.all) !== JSON.stringify(expectedReferences)) {
    const actual = new Set(references.all);
    const expected = new Set(expectedReferences);
    const missing = expectedReferences.filter((key) => !actual.has(key));
    const unexpected = references.all.filter((key) => !expected.has(key));
    throw new Error(
      `${domain} descriptor environment references do not equal the canonical allowed-plus-defaulted key contract; missing=${missing.join(",") || "none"}; unexpected=${unexpected.join(",") || "none"}`,
    );
  }
  const exactAliasSources = assertExactMainEnvironmentReferenceAliases(
    domain,
    references,
  );
  for (const key of references.nonemptyRequired) {
    if (references.nonStrict.includes(key) && !exactAliasSources.has(key)) {
      throw new Error(`${domain} environment input ${key} cannot mix strict and fallback interpolation modes`);
    }
  }
  for (const key of references.emptyDefault) {
    if (references.fallbackDefault.includes(key)) {
      throw new Error(`${domain} environment input ${key} cannot mix empty and nonempty fallback interpolation modes`);
    }
  }
  const strictDescriptorInputs = [...new Set([
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.public_environment_key_classification.provisioning_result_keys,
  ])];
  for (const key of strictDescriptorInputs) {
    if (!references.nonemptyRequired.includes(key)) {
      throw new Error(`${domain} bootstrap/provisioning environment input ${key} must use strict nonempty \${KEY:?} interpolation`);
    }
  }
  const lateDescriptorInputs = [...new Set([
    ...policy.public_environment_key_classification.post_measurement_deferred_keys,
    ...Object.entries(policy.encrypted_secret_environment_keys_by_phase)
      .filter(([phase]) => phase !== "bootstrap_provision")
      .flatMap(([, keys]) => keys),
  ])];
  for (const key of lateDescriptorInputs) {
    if (!references.emptyDefault.includes(key)
      || (!exactAliasSources.has(key)
        && references.nonemptyRequired.includes(key))
      || references.fallbackDefault.includes(key)) {
      throw new Error(`${domain} post-measurement environment input ${key} must use exact empty-default \${KEY:-} interpolation`);
    }
  }
  const disabledProfiles = new Set(policy.launch_settings.initially_disabled_profiles);
  const initialServices = new Set(policy.launch_settings.initial_services);
  const boundedActiveServiceLateInputs = new Set(
    CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  );
  if (domain === "main_runtime_cvm") {
    for (const key of boundedActiveServiceLateInputs) {
      if (exactAliasSources.has(key)) continue;
      const occurrences = references.occurrences.filter(({ name }) => name === key);
      const expectedPath = `$.services.delegate.environment.${key}`;
      if (occurrences.length !== 1
        || occurrences[0].service !== "delegate"
        || occurrences[0].path !== expectedPath) {
        throw new Error(
          `${domain} active-service late input ${key} must occur exactly once at ${expectedPath} with the mapping key equal to ${key}`,
        );
      }
    }
  }
  for (const occurrence of references.occurrences) {
    if (!lateDescriptorInputs.includes(occurrence.name)) continue;
    const profiles = occurrence.service === null
      ? []
      : references.profilesByService.get(occurrence.service) || [];
    // Compute-workload ingress and ChallengeRegistry admission are implemented
    // by the already-active delegate, not new sidecars. These values remain
    // empty at bootstrap and both request paths fail closed until their exact
    // post-measurement authority projectors install them. No other late value
    // may appear in an initially active service.
    const boundedActiveDelegateInput = domain === "main_runtime_cvm"
      && occurrence.service === "delegate"
      && boundedActiveServiceLateInputs.has(occurrence.name);
    if (!boundedActiveDelegateInput && (occurrence.service === null
      || initialServices.has(occurrence.service)
      || profiles.length !== 1
      || !disabledProfiles.has(profiles[0]))) {
      throw new Error(
        `${domain} post-measurement environment input ${occurrence.name} at ${occurrence.location || `line ${occurrence.line}`} must occur only inside a service with one exact initially-disabled profile`,
      );
    }
  }
  const noFallbackInputs = [
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.public_environment_key_classification.provisioning_result_keys,
  ];
  for (const key of noFallbackInputs) {
    if (references.nonStrict.includes(key)) {
      throw new Error(`${domain} initial environment input ${key} cannot have an optional or empty fallback`);
    }
  }
  if (references.all.includes("PHALA_CLOUD_API_KEY")) {
    throw new Error(`${domain} attempts to pass the Phala control-plane credential into a CVM`);
  }
  const activeServiceNames = references.serviceBlocks
    .filter(({ profiles }) => profiles.length === 0)
    .map(({ name }) => name)
    .sort();
  if (JSON.stringify(activeServiceNames)
    !== JSON.stringify([...policy.launch_settings.initial_services].sort())) {
    throw new Error(`${domain} initially active services do not equal launch_settings.initial_services`);
  }
  const observedProfiles = [...new Set(references.serviceBlocks.flatMap(({ profiles }) => profiles))]
    .sort();
  if (references.serviceBlocks.some(({ profiles }) => profiles.length > 1)
    || JSON.stringify(observedProfiles)
      !== JSON.stringify([...policy.launch_settings.initially_disabled_profiles].sort())) {
    throw new Error(`${domain} service profiles do not equal the exact initially-disabled profile set`);
  }
}

async function validateReferencedFile(directory, reference, expectedBareSha, label) {
  if (path.basename(reference) !== reference) throw new Error(`${label} filename is not canonical`);
  const file = await readBoundedRegularFile(path.join(directory, reference), label);
  const digest = rawSha256(file.bytes);
  if (digest !== `sha256:${bareSha256(expectedBareSha, `${label} topology hash`)}`) {
    throw new Error(`${label} bytes do not match the topology hash`);
  }
  return { ...file, digest };
}

export async function buildCvmLaunchIntentBundleFromFiles({ topologyPath, ledgerPath }) {
  const topologyFile = await readBoundedRegularFile(topologyPath, "topology");
  const topologyValue = parseJson(topologyFile.text, "topology");
  const topology = validateTopology(
    topologyValue,
    topologyFile.text,
    path.dirname(topologyFile.path),
  );
  const ledgerFile = await readBoundedRegularFile(ledgerPath, "contract ledger");
  const ledgerValue = parseJson(ledgerFile.text, "contract ledger");
  const deploymentIntentFile = await validateReferencedFile(
    topology.topologyDirectory,
    topology.deploymentIntent.file,
    topology.deploymentIntent.sha256,
    "deployment intent",
  );
  if (deploymentIntentFile.digest !== topology.deploymentIntentSha256) {
    throw new Error("copied deployment-intent bytes differ from the reviewed topology digest");
  }
  const deploymentIntentValidation = parseDeploymentIntentCoreText(
    deploymentIntentFile.text,
  );
  if (!deploymentIntentValidation.ok
    || deploymentIntentValidation.receipt.deploymentIntentSha256
      !== topology.deploymentIntentSha256
    || deploymentIntentValidation.receipt.releaseSha !== topology.sourceRelease
    || deploymentIntentValidation.receipt.chainId !== 84_532) {
    throw new Error(
      `topology deployment-intent artifact is not the exact canonical ${DEPLOYMENT_INTENT_CORE_SCHEMA} release intent`,
    );
  }
  const contractDeploymentReceiptAuthorityPins = {
    expectedDeploymentIntentSha256: topology.deploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      deploymentIntentValidation.intent.release
        .reviewerAuthorityGenesisAcceptanceSha256,
  };
  const contractDeploymentReceipt = projectFreshContractDeploymentReceipt(
    ledgerValue,
    {
      releaseSha: topology.sourceRelease,
      ...contractDeploymentReceiptAuthorityPins,
    },
  );
  const imageManifestFile = await validateReferencedFile(
    topology.topologyDirectory,
    topology.imageManifest.file,
    topology.imageManifest.sha256,
    "image release manifest",
  );
  const imageBundleFile = await validateReferencedFile(
    topology.topologyDirectory,
    topology.imageBundle.file,
    topology.imageBundle.sha256,
    "image attestation bundle",
  );
  const descriptors = [];
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const topologyDomain = record(topology.trustDomains[domain], `topology ${domain}`);
    if (topologyDomain.compose !== CVM_LAUNCH_DESCRIPTOR_FILES[domain]) {
      throw new Error(`${domain} topology descriptor filename is not canonical`);
    }
    const file = await validateReferencedFile(
      topology.topologyDirectory,
      topologyDomain.compose,
      topologyDomain.sha256,
      `${domain} descriptor`,
    );
    assertEnvironmentClassification(domain, file.text);
    const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
    const appComposeCandidate = {
      ...structuredClone(policy.app_compose_candidate),
      docker_compose_file_sha256: file.digest,
      docker_compose_file_byte_length: file.bytes.length,
    };
    appComposeCandidate.expected_compose_hash = phalaDstackComposeHash(
      createPhalaDstackComposeHashInput(
        appComposeCandidate,
        file.text,
        policy.exact_allowed_environment_keys,
      ),
    );
    descriptors.push({
      trust_domain: domain,
      descriptor_file: policy.descriptor_file,
      descriptor_sha256: file.digest,
      descriptor_hash_semantics: "raw_descriptor_bytes_sha256_not_phala_compose_hash",
      launch_settings: structuredClone(policy.launch_settings),
      public_environment_key_classification: structuredClone(
        policy.public_environment_key_classification,
      ),
      public_environment_value_authority: structuredClone(
        policy.public_environment_value_authority,
      ),
      app_compose_candidate: appComposeCandidate,
      encrypted_secret_environment_keys_by_phase: structuredClone(
        policy.encrypted_secret_environment_keys_by_phase,
      ),
      exact_allowed_environment_keys: [...policy.exact_allowed_environment_keys],
      exact_allowed_environment_keys_sha256: policy.exact_allowed_environment_keys_sha256,
    });
  }
  const canonicalLaunchDraft = createDraftCvmLaunchIntentCore();
  const artifact = {
    schema: CVM_LAUNCH_INTENT_CORE_SCHEMA,
    truth_status: CVM_LAUNCH_TRUTH_STATUS,
    release_sha: topology.sourceRelease,
    network: { chain_id: 84_532, name: "base-sepolia" },
    deployment_intent_sha256: topology.deploymentIntentSha256,
    contract_deployment_receipt_sha256:
      `sha256:${freshContractDeploymentReceiptDigest(
        contractDeploymentReceipt,
        contractDeploymentReceiptAuthorityPins,
      )}`,
    topology_sha256: rawSha256(topologyFile.bytes),
    image_release_manifest_sha256: imageManifestFile.digest,
    image_attestation_bundle_sha256: imageBundleFile.digest,
    phala_control_plane_authority: structuredClone(
      canonicalLaunchDraft.phala_control_plane_authority,
    ),
    phala_workspace_account_target_authority: structuredClone(
      canonicalLaunchDraft.phala_workspace_account_target_authority,
    ),
    phala_sdk_debug_secret_logging_policy: structuredClone(
      canonicalLaunchDraft.phala_sdk_debug_secret_logging_policy,
    ),
    phala_cloud_sdk_wire_transform_authority: structuredClone(
      canonicalLaunchDraft.phala_cloud_sdk_wire_transform_authority,
    ),
    phala_provision_request_authority: structuredClone(
      canonicalLaunchDraft.phala_provision_request_authority,
    ),
    compose_hash_authority: structuredClone(
      canonicalLaunchDraft.compose_hash_authority,
    ),
    sealed_production_execution_policy: structuredClone(
      canonicalLaunchDraft.sealed_production_execution_policy,
    ),
    dynamic_runtime_authorities: {
      endpoint_origins: [],
      os_image_hashes: [],
      phala_app_ids: [],
      phala_cvm_ids: [],
      platform_compose_hashes: [],
      qvl_release_policy_hashes: [],
      tee_identities: [],
      verifier_addresses: [],
    },
    descriptors,
  };
  return {
    artifact: parseCvmLaunchIntentCoreText(
      canonicalCvmLaunchIntentCoreArtifactText(artifact),
    ),
    contractDeploymentReceipt,
    contractDeploymentReceiptAuthorityPins,
  };
}

export async function buildCvmLaunchIntentFromFiles(options) {
  return (await buildCvmLaunchIntentBundleFromFiles(options)).artifact;
}

function draftText() {
  return `${JSON.stringify(canonicalJson(createDraftCvmLaunchIntentCore()), null, 2)}\n`;
}

function operationError(operation, error) {
  return `${JSON.stringify({
    schema: OPERATION_ERROR_SCHEMA,
    status: "operation_failed",
    truthStatus: "no_cvm_launch_or_deployment_authority_created",
    operation,
    message: String(error?.message || "operation failed").replace(/[\r\n]+/g, " ").slice(0, 260),
  }, null, 2)}\n`;
}

export async function runCvmLaunchIntentCli(argv, io = {}) {
  const stdout = io.stdout || ((value) => process.stdout.write(value));
  const stderr = io.stderr || ((value) => process.stderr.write(value));
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    stderr(`${error.message}\n${USAGE}\n`);
    return 2;
  }
  if (!args.command || args.command === "help") {
    stdout(`${USAGE}\n`);
    return args.command ? 0 : 2;
  }
  try {
    if (args.command === "init-template") {
      if (!args.output || args.input || args.receiptOutput || args.contractReceiptOutput
        || args.topology || args.ledger) {
        throw new Error("init-template requires only --out FILE");
      }
      const output = await writeNewRegularFile(args.output, draftText());
      stdout(`${JSON.stringify({
        schema: "dnai.cvm-launch-intent-template-created.v1",
        status: "incomplete_template_created",
        truthStatus: "no_cvm_launch_or_deployment_authority_created",
        output,
      }, null, 2)}\n`);
      return 0;
    }
    if (args.command === "build") {
      if (!args.topology || !args.ledger || !args.output || !args.contractReceiptOutput
        || args.input || args.receiptOutput) {
        throw new Error("build requires only --topology FILE --ledger FILE --out FILE --contract-receipt-out FILE");
      }
      if (path.resolve(args.output) === path.resolve(args.contractReceiptOutput)) {
        throw new Error("launch intent and contract receipt outputs must be distinct paths");
      }
      const {
        artifact,
        contractDeploymentReceipt,
        contractDeploymentReceiptAuthorityPins,
      } =
        await buildCvmLaunchIntentBundleFromFiles({
        topologyPath: args.topology,
        ledgerPath: args.ledger,
      });
      let output;
      let contractReceiptOutput;
      try {
        contractReceiptOutput = await writeNewRegularFile(
          args.contractReceiptOutput,
          canonicalFreshContractDeploymentReceiptText(
            contractDeploymentReceipt,
            contractDeploymentReceiptAuthorityPins,
          ),
        );
        output = await writeNewRegularFile(
          args.output,
          canonicalCvmLaunchIntentCoreArtifactText(artifact),
        );
      } catch (error) {
        if (output) await unlink(output).catch(() => {});
        if (contractReceiptOutput) await unlink(contractReceiptOutput).catch(() => {});
        throw error;
      }
      const receipt = cvmLaunchIntentValidationReceipt(artifact);
      stdout(`${JSON.stringify({
        schema: CREATED_SCHEMA,
        status: "canonical_launch_intent_created_not_deployed",
        truthStatus: "hash_and_key_name_bindings_only_no_environment_values_or_tdx_claim",
        output,
        contractReceiptOutput,
        contractDeploymentReceiptSha256:
          `sha256:${freshContractDeploymentReceiptDigest(
            contractDeploymentReceipt,
            contractDeploymentReceiptAuthorityPins,
          )}`,
        cvmLaunchIntentSha256: receipt.cvmLaunchIntentSha256,
        descriptorCount: receipt.descriptorCount,
      }, null, 2)}\n`);
      return 0;
    }
    if (args.command !== "check" && args.command !== "hash") {
      stderr(`unknown command\n${USAGE}\n`);
      return 2;
    }
    if (!args.input || args.output || args.topology || args.ledger
      || args.contractReceiptOutput
      || (args.command === "hash" && args.receiptOutput)) {
      throw new Error(`${args.command} received the wrong flags`);
    }
    const input = await readBoundedRegularFile(args.input, "CVM launch intent", 98_304);
    const artifact = parseCvmLaunchIntentCoreText(input.text);
    if (args.command === "hash") {
      stdout(`${JSON.stringify({
        schema: "dnai.cvm-launch-intent-digest.v1",
        kind: "cvm_launch_intent",
        sha256: `sha256:${cvmLaunchIntentCoreDigest(artifact)}`,
      }, null, 2)}\n`);
      return 0;
    }
    const receipt = cvmLaunchIntentValidationReceipt(artifact);
    const receiptText = `${JSON.stringify(receipt, null, 2)}\n`;
    if (args.receiptOutput) await writeNewRegularFile(args.receiptOutput, receiptText);
    stdout(receiptText);
    return 0;
  } catch (error) {
    stdout(operationError(args.command || "unknown", error));
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runCvmLaunchIntentCli(process.argv.slice(2));
}
