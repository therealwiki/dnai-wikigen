import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
} from "./cvm-release-descriptor-set-v3.mjs";
import { IMAGE_NAMES } from "./build-tee-image-release.mjs";
import {
  createPinnedPhalaPreProvisionStagingSession,
  observePinnedPhalaCompatibility,
  publishPinnedPhalaPreProvisionStagingReceipt,
  projectPinnedSdkCompatibilityIdentity,
  resolvePinnedPhalaPackageIdentity,
} from "./phala-production-sdk-adapter.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  normalizePhalaCompatibilityReceipt,
  canonicalPhalaSdkWireTransformStagingReceiptText,
  phalaCompatibilityReceiptDigest,
} from "./phala-production-target-authority.mjs";
import {
  PHALA_PRODUCER_EXPECTED_BOOTSTRAP_PUBLIC_VALUE_KEYS,
  canonicalPhalaProducerJsonText,
  capturePhalaSdkWireTransformStagingReceipt,
  createBootstrapPublicEnvironmentReviewInput,
  createPhalaProductionTargetReviewInput,
  finalizeBootstrapPublicEnvironmentAuthority,
  finalizePhalaProductionTargetAuthority,
  phalaProductionTargetReviewInputDigest,
} from "./phala-pre-provision-authority-producer-core.mjs";
import {
  assertBootstrapReviewInputMatchesFreshSources,
  assertTargetReviewInputMatchesFreshSources,
  normalizeOpaqueDeploymentTransactionPlan,
  parsePhalaPreProvisionAuthorityProducerArgs,
  publishCanonicalPhalaProducerArtifact,
  readStableBytes,
  runPhalaPreProvisionAuthorityProducer,
} from "./phala-pre-provision-authority-producer.mjs";

const SCRIPT = fileURLToPath(new URL(
  "./phala-pre-provision-authority-producer.mjs",
  import.meta.url,
));
const digest = (character) => `sha256:${character.repeat(64)}`;
const second = (offset = 0) => new Date(
  Math.floor(Date.now() / 1_000) * 1_000 + offset * 1_000,
).toISOString().replace(".000Z", "Z");

const CURRENT_USER = Object.freeze({
  user: Object.freeze({
    username: "staging-reviewer",
    email: "staging-reviewer@example.test",
    role: "admin",
    avatar: "",
    email_verified: true,
    totp_enabled: true,
    has_backup_codes: true,
    flag_has_password: true,
  }),
  workspace: Object.freeze({
    id: "workspace-isolated-staging",
    name: "DNAI Isolated Staging",
    slug: "dnai-isolated-staging",
    tier: "production",
    role: "owner",
    avatar: null,
  }),
  credits: Object.freeze({
    balance: "100",
    granted_balance: "0",
    is_post_paid: false,
    outstanding_amount: null,
  }),
});

const KMS = Object.freeze({
  id: "kms-production-1",
  slug: "phala",
  url: "https://kms.phala.network/",
  version: "0.5.9",
  chain_id: null,
  kms_contract_address: null,
  gateway_app_id: "1".repeat(40),
});

function resourceGraph() {
  return {
    tier: "production",
    capacity: {
      max_instances: 20,
      max_vcpu: 100,
      max_memory: 200_000,
      max_disk: 2_048,
    },
    nodes: [],
    kms_nodes: [],
    node_kms_relations: [],
    gateway_nodes: [],
    instance_types: ["tdx.large", "tdx.small"].map((name, index) => ({
      id: `instance-${index + 1}`,
      name,
      vcpu: name === "tdx.large" ? 2 : 1,
      memory_mb: name === "tdx.large" ? 4096 : 2048,
      default_disk_size_gb: 20,
      requires_gpu: false,
      requires_gpu_count: 0,
      family: "tdx",
      display_order: index + 1,
    })),
    gpu_availability: {
      has_reserved_gpus: false,
      reserved_gpu_count: 0,
      has_public_gpus: false,
      public_gpu_count: 0,
    },
  };
}

function osImages() {
  return {
    items: [{ ...PHALA_OS_IMAGE_CATALOG_ENTRY }],
    total: 1,
    page: 1,
    page_size: 100,
    pages: 1,
  };
}

function kmsList() {
  return { items: [{ ...KMS }], total: 1, page: 1, page_size: 100, pages: 1 };
}

function installCredentialHome(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "dnai-producer-home-"));
  const credentialDirectory = path.join(root, ".phala-cloud");
  fs.mkdirSync(credentialDirectory, { mode: 0o700 });
  fs.chmodSync(credentialDirectory, 0o700);
  fs.writeFileSync(path.join(credentialDirectory, "credentials.json"), `${JSON.stringify({
    schema_version: 1,
    current_profile: "isolated-staging",
    profiles: {
      "isolated-staging": {
        token: `phak_${"s".repeat(40)}`,
        api_prefix: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
        workspace: {
          name: CURRENT_USER.workspace.name,
          slug: CURRENT_USER.workspace.slug,
        },
        user: {
          username: CURRENT_USER.user.username,
          email: CURRENT_USER.user.email,
        },
        updated_at: second(-60),
      },
    },
  }, null, 2)}\n`, { mode: 0o600 });
  const originalHome = process.env.HOME;
  process.env.HOME = root;
  t.after(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return path.join(credentialDirectory, "credentials.json");
}

function installFakeHttps(t, handler) {
  const original = https.request;
  https.request = (options, callback) => {
    const request = new EventEmitter();
    const chunks = [];
    request.write = (chunk) => { chunks.push(Buffer.from(chunk)); return true; };
    request.destroy = () => {};
    request.end = () => queueMicrotask(() => {
      try {
        const result = handler(options, Buffer.concat(chunks));
        const bytes = Buffer.from(JSON.stringify(result.body), "utf8");
        const response = Readable.from([bytes]);
        response.statusCode = result.status ?? 200;
        response.headers = {
          "content-type": "application/json; charset=utf-8",
          "content-length": String(bytes.length),
        };
        callback(response);
      } catch (error) {
        request.emit("error", error);
      }
    });
    return request;
  };
  t.after(() => { https.request = original; });
}

function compatibilityHandler(calls) {
  return (options) => {
    calls.push({
      method: options.method,
      path: options.path,
      hostname: options.hostname,
      version: options.headers["X-Phala-Version"],
      credential: options.headers["X-API-Key"],
    });
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === "/api/v1/teepods/cvm-create-resources") {
      return { body: resourceGraph() };
    }
    if (options.path === "/api/v1/kms?page=1&page_size=100&is_onchain=false") {
      return { body: kmsList() };
    }
    if (options.path === `/api/v1/kms/${KMS.id}`) return { body: KMS };
    if (options.path === "/api/v1/os-images?page=1&page_size=100&is_dev=false") {
      return { body: osImages() };
    }
    throw new Error(`unexpected compatibility request ${options.path}`);
  };
}

async function observedCompatibility(t) {
  installCredentialHome(t);
  const calls = [];
  installFakeHttps(t, compatibilityHandler(calls));
  return { receipt: await observePinnedPhalaCompatibility(), calls };
}

function targetInput(compatibility) {
  return createPhalaProductionTargetReviewInput({
    compatibilityReceipt: compatibility,
    releaseSha: "a".repeat(40),
    cvmLaunchIntentSha256: digest("2"),
    reviewEnvelopeSha256: digest("3"),
    reviewEvidenceSha256: digest("4"),
    kmsSignerK256: `0x02${"5".repeat(64)}`,
    kmsSignerProvenanceSha256: digest("6"),
    kmsSignerValidFrom: second(-3_600),
    kmsSignerValidUntil: second(3_600),
  });
}

function descriptorMaterials() {
  return CVM_LAUNCH_DOMAINS.map((domain, index) => ({
    domain,
    docker_compose_file:
      `services:\n  app:\n    image: example.invalid/${index}@sha256:${String(index + 1).repeat(64)}`,
    allowed_environment_keys:
      [...CVM_LAUNCH_DESCRIPTOR_POLICY[domain].exact_allowed_environment_keys].sort(),
  }));
}

function installStagingHttps(t, calls, {
  committedCvmTotal = 0,
  failProvisionAt = null,
  onRequest = null,
} = {}) {
  let provisionIndex = 0;
  installFakeHttps(t, (options, bytes) => {
    calls.push({ method: options.method, path: options.path });
    onRequest?.(options);
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === "/api/v1/cvms/paginated?page=1&page_size=100") {
      return {
        body: {
          items: [],
          total: committedCvmTotal,
          page: 1,
          page_size: 100,
          pages: committedCvmTotal === 0 ? 0 : 1,
        },
      };
    }
    if (options.path === "/api/v1/kms/phala/next_app_id?counts=7") {
      return {
        body: {
          app_ids: CVM_LAUNCH_DOMAINS.map((_, index) => ({
            app_id: (index + 1).toString(16).repeat(40),
            nonce: 100 + index,
          })),
        },
      };
    }
    if (options.path === "/api/v1/cvms/provision") {
      const currentProvision = provisionIndex;
      provisionIndex += 1;
      if (currentProvision === failProvisionAt) {
        throw new Error("injected prepare failure");
      }
      const body = JSON.parse(bytes.toString("utf8"));
      const canonical = (value) => {
        if (Array.isArray(value)) return value.map(canonical);
        if (!value || typeof value !== "object") return value;
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
      };
      return {
        body: {
          app_id: body.app_id,
          compose_hash: createHash("sha256")
            .update(JSON.stringify(canonical(body.compose_file)), "utf8")
            .digest("hex"),
          instance_type: body.instance_type,
          node_id: 7,
          kms_id: body.kms_id,
          os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
          app_env_encrypt_pubkey: "9".repeat(64),
        },
      };
    }
    throw new Error(`unexpected staging request ${options.path}`);
  });
}

function stagingSessionOptions(t, compatibility, input = targetInput(compatibility)) {
  const parent = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "dnai-producer-staging-journal-",
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "attempt");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return {
    outputPath: path.join(directory, "staging-receipt.json"),
    releaseSha: input.release_sha,
    targetReviewInputSha256: phalaProductionTargetReviewInputDigest(input, {
      compatibilityReceipt: compatibility,
    }),
    sourceManifest: {
      target_sources: {
        cvm_launch_intent: digest("1"),
        deployment_intent: digest("2"),
        fresh_contract_deployment_receipt: digest("3"),
        tinker_account_binding_ceremony_receipt: digest("4"),
        cvm_launch_review_envelope: digest("5"),
        cvm_launch_review_evidence: digest("6"),
        kms_signer_provenance: digest("7"),
        target_review_input: digest("8"),
      },
      descriptor_materials: descriptorMaterials().map((material) => ({
        domain: material.domain,
        descriptor_material_sha256: `sha256:${createHash("sha256")
          .update(canonicalPhalaProducerJsonText(material), "utf8")
          .digest("hex")}`,
      })),
    },
    operatorAssertedDedicatedWorkspace: true,
  };
}

async function stagingFixture(t, compatibility) {
  const calls = [];
  installStagingHttps(t, calls);
  const input = targetInput(compatibility);
  const options = stagingSessionOptions(t, compatibility, input);
  const session = await createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: compatibility,
    ...options,
  });
  const receipt = await capturePhalaSdkWireTransformStagingReceipt({
    compatibilityReceipt: compatibility,
    targetReviewInput: input,
    descriptorMaterials: descriptorMaterials(),
    stagingSession: session,
  });
  return { receipt, calls, session, input, options };
}

test("authenticated compatibility uses the exact origin, versions, calls, and secret-free output", async (t) => {
  const { receipt, calls } = await observedCompatibility(t);
  assert.equal(calls.length, PHALA_API_CANDIDATE_VERSIONS.length * 5);
  assert.deepEqual(calls.map(({ version }) => version), [
    ...Array(5).fill(PHALA_API_CANDIDATE_VERSIONS[0]),
    ...Array(5).fill(PHALA_API_CANDIDATE_VERSIONS[1]),
  ]);
  assert.equal(calls.every(({ hostname }) => hostname === "cloud-api.phala.network"), true);
  assert.equal(calls.every(({ method }) => method === "GET"), true);
  assert.equal(receipt.api_origin, PHALA_CONTROL_PLANE_AUTHORITY.api_origin);
  assert.equal(receipt.selected_api_version, PHALA_CONTROL_PLANE_AUTHORITY.api_version);
  assert.equal(receipt.workspace.workspace_id, CURRENT_USER.workspace.id);
  assert.equal(JSON.stringify(receipt).includes("phak_"), false);
  assert.equal(JSON.stringify(receipt).includes(CURRENT_USER.user.email), false);
  assert.deepEqual(receipt.mutation_calls, []);
});

test("compatibility and staging fail closed on origin, version, and capsule drift", async (t) => {
  const { receipt } = await observedCompatibility(t);
  const wrongOrigin = structuredClone(receipt);
  wrongOrigin.api_origin = "https://example.invalid/api/v1";
  assert.throws(() => normalizePhalaCompatibilityReceipt(wrongOrigin), /origin/);
  const wrongVersion = structuredClone(receipt);
  wrongVersion.selected_api_version = PHALA_API_CANDIDATE_VERSIONS[1];
  assert.throws(() => normalizePhalaCompatibilityReceipt(wrongVersion), /selected API version/);
  const dependencyDrift = structuredClone(receipt);
  dependencyDrift.sdk_identity.sdk_runtime_capsule_sha256 = digest("f");
  await assert.rejects(
    createPinnedPhalaPreProvisionStagingSession({
      compatibilityReceipt: dependencyDrift,
    }),
    /SDK identity differs from the reviewed runtime capsule/,
  );
  assert.notDeepEqual(
    projectPinnedSdkCompatibilityIdentity(resolvePinnedPhalaPackageIdentity()),
    dependencyDrift.sdk_identity,
  );
  const stagingCalls = [];
  installStagingHttps(t, stagingCalls);
  const session = await createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: receipt,
    ...stagingSessionOptions(t, receipt),
  });
  const originalPath = process.env.PATH;
  try {
    process.env.PATH = "/dependency-drift-no-phala-bin";
    await session.reserveAppIds();
  } finally {
    process.env.PATH = originalPath;
  }
  assert.deepEqual(stagingCalls.map(({ method, path: requestPath }) => ({
    method,
    path: requestPath,
  })), [
    { method: "GET", path: "/api/v1/auth/me" },
    { method: "GET", path: "/api/v1/cvms/paginated?page=1&page_size=100" },
    { method: "GET", path: "/api/v1/kms/phala/next_app_id?counts=7" },
  ], "ambient PATH must not select the SDK implementation");

  const expired = structuredClone(receipt);
  expired.checked_at = second(-120);
  expired.expires_at = second(-60);
  await assert.rejects(createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: expired,
  }), /fresh authenticated compatibility/);
});

test("staging session emits exactly seven wire captures, exposes no commit, and rejects extra calls", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const { receipt, calls, session, options } = await stagingFixture(t, compatibility);
  assert.equal(receipt.provision_call_count, 7);
  assert.deepEqual(receipt.commit_calls, []);
  assert.equal(session.commitCvmProvision, undefined);
  assert.deepEqual(calls.map(({ path: value }) => value), [
    "/api/v1/auth/me",
    "/api/v1/cvms/paginated?page=1&page_size=100",
    "/api/v1/kms/phala/next_app_id?counts=7",
    ...Array(7).fill("/api/v1/cvms/provision"),
  ]);
  await assert.rejects(session.reserveAppIds(), /exactly once/);
  await assert.rejects(session.captureProvisionBatch([]), /fresh reservation/);
  assert.equal(calls.length, 10, "rejected extra calls must not reach HTTPS");
  assert.equal(JSON.stringify(receipt).includes("docker_compose_file"), false);
  assert.equal(JSON.stringify(receipt).includes("phak_"), false);
  assert.equal(receipt.workspace_preflight.total, 0);
  assert.equal(receipt.workspace_preflight.exclusive_workspace_control_proven, false);
  assert.equal(Object.hasOwn(receipt, "staging_account_isolated"), false);

  const directory = path.dirname(options.outputPath);
  const journalNames = fs.readdirSync(directory)
    .filter((name) => name.startsWith("phala-staging-journal."))
    .sort();
  assert.equal(journalNames.length, 31);
  let previous = `sha256:${createHash("sha256")
    .update(fs.readFileSync(options.outputPath))
    .digest("hex")}`;
  const events = [];
  for (const [index, name] of journalNames.entries()) {
    const bytes = fs.readFileSync(path.join(directory, name));
    const record = JSON.parse(bytes.toString("utf8"));
    assert.equal(record.sequence, index);
    assert.equal(record.previous_record_sha256, previous);
    assert.equal(JSON.stringify(record).includes("phak_"), false);
    assert.equal(JSON.stringify(record).includes(CURRENT_USER.user.email), false);
    assert.equal(JSON.stringify(record).includes("docker_compose_file"), false);
    previous = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    events.push(record.event);
  }
  assert.equal(events[0], "attempt_header");
  assert.equal(events.at(-1), "prepare_batch_complete");
  assert.equal(receipt.journal_final_sha256, previous);

  const forgedEvidence = structuredClone(receipt);
  forgedEvidence.domains[0].prepare_response_sha256 = digest("f");
  assert.throws(() => publishPinnedPhalaPreProvisionStagingReceipt({
    stagingSession: session,
    canonicalReceiptText: canonicalPhalaSdkWireTransformStagingReceiptText(
      forgedEvidence,
      { compatibilityReceipt: compatibility },
    ),
  }), /completed durable journal/);
  const forgedTime = structuredClone(receipt);
  forgedTime.captured_at = new Date(Date.parse(receipt.captured_at) + 1_000)
    .toISOString().replace(".000Z", "Z");
  assert.throws(() => publishPinnedPhalaPreProvisionStagingReceipt({
    stagingSession: session,
    canonicalReceiptText: canonicalPhalaSdkWireTransformStagingReceiptText(
      forgedTime,
      { compatibilityReceipt: compatibility },
    ),
  }), /completed durable journal/);
});

test("partial prepare failure is durably terminal and blocks retry before another SDK call", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const calls = [];
  installStagingHttps(t, calls, { failProvisionAt: 2 });
  const input = targetInput(compatibility);
  const options = stagingSessionOptions(t, compatibility, input);
  const session = await createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: compatibility,
    ...options,
  });
  await assert.rejects(capturePhalaSdkWireTransformStagingReceipt({
    compatibilityReceipt: compatibility,
    targetReviewInput: input,
    descriptorMaterials: descriptorMaterials(),
    stagingSession: session,
  }), /pinned Phala HTTPS request failed/);
  const journalNames = fs.readdirSync(path.dirname(options.outputPath))
    .filter((name) => name.startsWith("phala-staging-journal."))
    .sort();
  const terminal = JSON.parse(fs.readFileSync(
    path.join(path.dirname(options.outputPath), journalNames.at(-1)),
    "utf8",
  ));
  assert.equal(terminal.event, "partial_prepare_failure");
  assert.equal(terminal.payload.successful_prepare_count, 2);
  assert.equal(terminal.payload.commit_call_count, 0);
  assert.equal(terminal.payload.server_cleanup_claimed, false);
  assert.equal(terminal.payload.automatic_retry_authorized, false);
  assert.equal(terminal.payload.pending_server_state, "pending_server_state_unknown");
  const callsBeforeRetry = calls.length;
  await assert.rejects(createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: compatibility,
    ...options,
  }), /automatic retry is forbidden|operator reconciliation/);
  assert.equal(calls.length, callsBeforeRetry);
});

test("same-UID output reservation substitution cannot receive the final staging receipt", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const { receipt, session, options } = await stagingFixture(t, compatibility);
  const displaced = `${options.outputPath}.displaced`;
  fs.renameSync(options.outputPath, displaced);
  const attackerBytes = Buffer.from("{\"replacement\":true}\n", "utf8");
  fs.writeFileSync(options.outputPath, attackerBytes, { mode: 0o600 });
  fs.chmodSync(options.outputPath, 0o600);
  assert.throws(() => publishPinnedPhalaPreProvisionStagingReceipt({
    stagingSession: session,
    canonicalReceiptText: canonicalPhalaSdkWireTransformStagingReceiptText(
      receipt,
      { compatibilityReceipt: compatibility },
    ),
  }), /reservation identity/);
  assert.deepEqual(fs.readFileSync(options.outputPath), attackerBytes);
});

test("nonempty authenticated workspace and pathname replacement stop before reservation", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const nonemptyCalls = [];
  installStagingHttps(t, nonemptyCalls, { committedCvmTotal: 1 });
  const input = targetInput(compatibility);
  const nonemptyOptions = stagingSessionOptions(t, compatibility, input);
  const nonemptySession = await createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: compatibility,
    ...nonemptyOptions,
  });
  await assert.rejects(nonemptySession.reserveAppIds(), /empty committed-CVM listing/);
  assert.deepEqual(nonemptyCalls.map(({ path: value }) => value), [
    "/api/v1/auth/me",
    "/api/v1/cvms/paginated?page=1&page_size=100",
  ]);

  const swapCalls = [];
  const swapOptions = stagingSessionOptions(t, compatibility, input);
  const originalDirectory = path.dirname(swapOptions.outputPath);
  const displaced = `${originalDirectory}.displaced`;
  let swapped = false;
  installStagingHttps(t, swapCalls, {
    onRequest(options) {
      if (!swapped && options.path === "/api/v1/auth/me") {
        fs.renameSync(originalDirectory, displaced);
        fs.mkdirSync(originalDirectory, { mode: 0o700 });
        fs.chmodSync(originalDirectory, 0o700);
        swapped = true;
      }
    },
  });
  const swapSession = await createPinnedPhalaPreProvisionStagingSession({
    compatibilityReceipt: compatibility,
    ...swapOptions,
  });
  await assert.rejects(swapSession.reserveAppIds(), /pathname or identity anchor/);
  assert.equal(swapCalls.length, 1);
  assert.equal(fs.readdirSync(originalDirectory).length, 0);
});

test("target finalization binds staging and rejects expired or extra authority input", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const { receipt: staging, input } = await stagingFixture(t, compatibility);
  const target = finalizePhalaProductionTargetAuthority({
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    targetReviewInput: input,
    nowMs: Date.parse(staging.captured_at),
  });
  assert.equal(target.compatibility_receipt_sha256,
    phalaCompatibilityReceiptDigest(compatibility));
  assert.equal(assertTargetReviewInputMatchesFreshSources(input, input), input);
  const rewrittenSourceProjection = structuredClone(input);
  rewrittenSourceProjection.review_evidence_sha256 = digest("e");
  assert.throws(
    () => assertTargetReviewInputMatchesFreshSources(
      input,
      rewrittenSourceProjection,
    ),
    /freshly revalidated source artifacts/,
  );
  const extra = structuredClone(input);
  extra.commit_calls = [];
  assert.throws(() => finalizePhalaProductionTargetAuthority({
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    targetReviewInput: extra,
    nowMs: Date.parse(staging.captured_at),
  }), /exactly the reviewed fields/);
  assert.throws(() => finalizePhalaProductionTargetAuthority({
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    targetReviewInput: input,
    nowMs: Date.parse(staging.expires_at),
  }), /outside its reviewed dependency lifetime/);
  const futureSigner = structuredClone(input);
  futureSigner.kms.valid_from = second(120);
  const reboundStaging = structuredClone(staging);
  reboundStaging.target_review_input_sha256 =
    phalaProductionTargetReviewInputDigest(futureSigner, {
      compatibilityReceipt: compatibility,
    });
  assert.throws(() => finalizePhalaProductionTargetAuthority({
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: reboundStaging,
    targetReviewInput: futureSigner,
    nowMs: Date.parse(staging.captured_at),
  }), /outside its reviewed dependency lifetime/);
});

function descriptorReceipt(releaseSha) {
  return {
    schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status: "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: structuredClone(CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY),
    release_sha: releaseSha,
    source_ref: "refs/heads/main",
    image_manifest_sha256: digest("1"),
    image_manifest_sigstore_bundle_sha256: digest("2"),
    topology_sha256: digest("3"),
    tinker_account_binding_ceremony_receipt_sha256: digest("4"),
    descriptor_sha256_by_domain: Object.fromEntries(CVM_LAUNCH_DOMAINS.map(
      (domain, index) => [domain, digest((index + 1).toString(16))],
    )),
    service_matrix: structuredClone(CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX),
    image_references: IMAGE_NAMES.map((name, index) => (
      `ghcr.io/therealwiki/dnai-wikigen/${name}@sha256:${(index + 8).toString(16).repeat(64)}`
    )),
    invariants: {
      all_seven_generated_files_present: true,
      exact_raw_hashes_bound_by_topology: true,
      exact_service_matrices: true,
      exact_clean_ci_image_digests: true,
      embedded_secret_values: false,
      deployment_claimed: false,
      tdx_attestation_claimed: false,
    },
  };
}

function publicValue(key) {
  if (key === "TINKER_CORS_ALLOWED_ORIGINS") {
    return "https://wikigen.me,https://wikigenme.pages.dev,https://www.wikigen.me";
  }
  if (key.endsWith("_ADDRESS")) return `0x${"a".repeat(40)}`;
  if (key.endsWith("_APP_ID")) return "b".repeat(40);
  if (key.endsWith("_CVM_ID")) return "cvm-production-0001";
  if (key.endsWith("_COMPOSE_HASH") || key.endsWith("_OS_IMAGE_HASH")) {
    return "c".repeat(64);
  }
  if (key.endsWith("_SHA256")) return digest("d");
  if (key.endsWith("_EPOCH")) return "1";
  if (key.endsWith("_URL")) return "https://authority.example/path";
  if (key.endsWith("_RUNTIME_CODE_HASH")) return `0x${"e".repeat(64)}`;
  if (key.endsWith("_IMAGE_DIGEST")) return digest("f");
  if (key.endsWith("_RELEASE_SHA")) return "a".repeat(40);
  if (key.endsWith("_CEREMONY_NONCE")) return `0x${"1".repeat(64)}`;
  if (key.endsWith("_MANIFEST_PATH")) return "/release/manifest.json";
  return `reviewed-${key.toLowerCase()}`;
}

test("bootstrap init enumerates every key and finalize rejects placeholders, secrets, accessors, and drift", async (t) => {
  const { receipt: compatibility } = await observedCompatibility(t);
  const { receipt: staging, input: productionTargetInput } =
    await stagingFixture(t, compatibility);
  const target = finalizePhalaProductionTargetAuthority({
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    targetReviewInput: productionTargetInput,
    nowMs: Date.parse(staging.captured_at),
  });
  const input = createBootstrapPublicEnvironmentReviewInput({
    descriptorSetReceipt: descriptorReceipt(target.release_sha),
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    lineage: {
      deployment_intent_sha256: digest("5"),
      deployment_transaction_plan_sha256: digest("6"),
      fresh_contract_deployment_receipt_sha256: digest("7"),
      image_release_sigstore_verification_receipt_sha256: digest("8"),
      cvm_launch_intent_sha256: target.cvm_launch_intent_sha256,
      cvm_launch_review_receipt_sha256: digest("9"),
      qvl_measurement_policy_set_sha256: digest("a"),
    },
  });
  assert.deepEqual(input.domains.map((entry) => Object.keys(entry.values)),
    CVM_LAUNCH_DOMAINS.map((domain) =>
      PHALA_PRODUCER_EXPECTED_BOOTSTRAP_PUBLIC_VALUE_KEYS[domain]));
  assert.equal(input.domains.reduce(
    (total, entry) => total + Object.keys(entry.values).length,
    0,
  ), 41);
  assert.throws(() => finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: input,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
  }), /placeholder|bounded non-placeholder|final-release/);
  const reviewed = structuredClone(input);
  for (const entry of reviewed.domains) {
    for (const key of Object.keys(entry.values)) entry.values[key] = publicValue(key);
  }
  assertBootstrapReviewInputMatchesFreshSources(reviewed, input);
  const immutableLineageDrift = structuredClone(reviewed);
  immutableLineageDrift.deployment_transaction_plan_sha256 = digest("f");
  assert.throws(
    () => assertBootstrapReviewInputMatchesFreshSources(
      immutableLineageDrift,
      input,
    ),
    /immutable lineage/,
  );
  const authority = finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: reviewed,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
  });
  assert.equal(authority.domains.length, 7);
  const secret = structuredClone(reviewed);
  secret.domains[0].values.TINKER_CORS_ALLOWED_ORIGINS = "phak_abcdefghijk";
  assert.throws(() => finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: secret,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
  }));
  const accessor = structuredClone(reviewed);
  Object.defineProperty(accessor, "release_sha", { enumerable: true, get: () => target.release_sha });
  assert.throws(() => finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: accessor,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
  }), /accessors/);
  const drift = structuredClone(reviewed);
  drift.production_target_authority_sha256 = digest("f");
  assert.throws(() => finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: drift,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
  }), /drifted/);
  assert.throws(() => finalizeBootstrapPublicEnvironmentAuthority({
    reviewInput: reviewed,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    productionTargetAuthority: target,
    nowMs: Date.parse(target.reviewed_at),
    lifetimeSeconds: 601,
  }), /ten-minute bound/);
});

test("CLI rejects secret-bearing and generic-call arguments without echoing them", () => {
  const secret = `phak_${"x".repeat(32)}`;
  let stderr = "";
  try {
    execFileSync(process.execPath, [SCRIPT, "observe-compatibility", "--api-token", secret], {
      encoding: "utf8",
      env: { ...process.env, HOME: os.tmpdir() },
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.fail("secret-bearing CLI input unexpectedly succeeded");
  } catch (error) {
    stderr = String(error.stderr);
  }
  assert.equal(stderr.includes(secret), false);
  assert.equal(stderr, "phala_pre_provision_authority_producer_failed:observe-compatibility\n");
  try {
    execFileSync(process.execPath, [SCRIPT, secret], {
      encoding: "utf8",
      env: { ...process.env, HOME: os.tmpdir() },
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.fail("secret-shaped command unexpectedly succeeded");
  } catch (error) {
    assert.equal(String(error.stderr).includes(secret), false);
    assert.equal(
      String(error.stderr),
      "phala_pre_provision_authority_producer_failed:unknown-command\n",
    );
  }
  assert.throws(() => parsePhalaPreProvisionAuthorityProducerArgs([
    "observe-compatibility", "--out", "/tmp/x", "--request", "commitCvmProvision",
  ]), /unknown or duplicated/);
  assert.throws(() => parsePhalaPreProvisionAuthorityProducerArgs([
    "init-bootstrap-input",
    "--deployment-intent-sha256", digest("1"),
  ]), /unknown or duplicated/);
});

test("every artifact command rejects unsafe process hooks before producing bytes", async () => {
  const original = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = "--no-warnings";
  try {
    for (const command of [
      "observe-compatibility",
      "init-kms-signer-provenance",
      "init-target-input",
      "observe-staging",
      "finalize-target",
      "init-bootstrap-input",
      "finalize-bootstrap",
    ]) {
      await assert.rejects(
        runPhalaPreProvisionAuthorityProducer([command], { stdout() {} }),
        /environment overrides must be absent/,
      );
    }
  } finally {
    if (original === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = original;
  }
});

test("KMS signer public choices are materialized canonically without hand-authored JSON", async (t) => {
  const parent = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "dnai-producer-kms-provenance-",
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "authority");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const output = path.join(directory, "kms-signer-provenance.json");
  await runPhalaPreProvisionAuthorityProducer([
    "init-kms-signer-provenance",
    "--env-encrypt-signer-k256", `0x02${"5".repeat(64)}`,
    "--valid-from", "2026-09-15T00:00:00Z",
    "--valid-until", "2026-09-16T00:00:00Z",
    "--out", output,
  ], { stdout() {} });
  assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")), {
    env_encrypt_signer_k256: `0x02${"5".repeat(64)}`,
    valid_from: "2026-09-15T00:00:00Z",
    valid_until: "2026-09-16T00:00:00Z",
  });
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
});

test("opaque transaction-plan bytes never become semantic or reviewer authority", () => {
  const plan = {
    status: "opaque_bytes_hash_only_not_semantically_validated_or_transaction_authority",
    operator_note: "review separately under an external transaction policy",
  };
  assert.deepEqual(normalizeOpaqueDeploymentTransactionPlan(plan), plan);
  assert.throws(
    () => normalizeOpaqueDeploymentTransactionPlan({
      ...plan,
      status: "reviewed_transaction_authority",
    }),
    /without semantic or transaction authority/,
  );
  assert.throws(
    () => normalizeOpaqueDeploymentTransactionPlan({
      ...plan,
      api_token: `phak_${"x".repeat(20)}`,
    }),
    /secret/,
  );
});

test("source reads are descriptor-relative and reject writable, linked, or aliased files", (t) => {
  const parent = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "dnai-producer-input-",
  ));
  fs.chmodSync(parent, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const source = path.join(parent, "source.json");
  fs.writeFileSync(source, "{\"ok\":true}\n", { mode: 0o600 });
  assert.equal(readStableBytes(source, "test source").toString("utf8"), "{\"ok\":true}\n");
  fs.chmodSync(source, 0o622);
  assert.throws(() => readStableBytes(source, "test source"), /non-writable/);
  fs.chmodSync(source, 0o600);
  const linked = path.join(parent, "linked.json");
  fs.linkSync(source, linked);
  assert.throws(() => readStableBytes(source, "test source"), /single-link/);
  fs.unlinkSync(linked);
  const alias = path.join(parent, "alias.json");
  fs.symlinkSync(source, alias);
  assert.throws(() => readStableBytes(alias, "test source"), /symlink|alias/);
});

test("create-only publication remains bound to the pinned directory across alias replacement", (t) => {
  const parent = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "dnai-producer-output-parent-"));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "authority");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const displaced = `${directory}.displaced`;
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  assert.throws(() => publishCanonicalPhalaProducerArtifact({
    outputPath: path.join(directory, "noncanonical.json"),
    text: "{\n  \"z\": true,\n  \"a\": true\n}\n",
  }), /bounded canonical JSON/);
  assert.throws(() => publishCanonicalPhalaProducerArtifact({
    outputPath: path.join(directory, "receipt.json"),
    text: "{\n  \"ok\": true\n}\n",
    beforePublish() {
      fs.renameSync(directory, displaced);
      fs.mkdirSync(directory, { mode: 0o700 });
      fs.chmodSync(directory, 0o700);
    },
  }), /filesystem alias|pathname or identity anchor/);
  assert.equal(fs.existsSync(path.join(directory, "receipt.json")), false);
  assert.equal(fs.existsSync(path.join(displaced, "receipt.json")), false);
});
