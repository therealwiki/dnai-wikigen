import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  buildExactProvisionRequest,
  buildExplicitAppCompose,
  dstackCanonicalComposeHash,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_AUTHENTICATED_SDK_OBSERVATION_SCHEMA,
  PHALA_SDK_ACTION_REQUEST_POLICY,
  assertAuthenticatedPhalaSdkObservation,
  assertPinnedSdkActionRequestMatches,
  assertPinnedSdkActionVersionHeaders,
  assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  assertPinnedPhalaProductionSdkAdapter,
  authenticatedPhalaSdkObservationSha256,
  bindPinnedPhalaCommittedEnvironmentKeyLookup,
  createPinnedPhalaProductionSdkAdapter,
  createPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  phalaAuthenticatedAccountSubjectSha256,
  phalaSdkJsonBodySemanticDigest,
  phalaSdkActionRequestPolicySha256,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  projectPinnedPhalaProductionSdkAdapterIdentity,
  projectPinnedProvisionWireBody,
  projectPinnedSdkActionRequest,
  projectPinnedSdkRawIdentityFields,
  projectPinnedSdkCompatibilityIdentity,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
} from "./phala-production-sdk-adapter.mjs";
import {
  verifyProductionCvmPostureObservation,
} from "./phala-production-posture-receipt.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
  PHALA_PROVISION_REQUEST_TARGET_SHA256,
  PHALA_READ_ONLY_COMPATIBILITY_CALLS,
  PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetReviewInputProjectionDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";
import {
  PHALA_REVIEWED_CAPSULE_EXPORTS,
  PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
  assertReviewedCapsuleSourceCapabilityBoundary,
  importReviewedPhalaSdkRuntimeCapsule,
  loadReviewedPhalaSdkRuntimeCapsule,
  verifyReviewedPhalaSdkRuntimeCapsuleMaterial,
} from "./phala-sdk-runtime-capsule.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
import {
  createSyntheticPhalaContractKmsFixture,
  createSyntheticPhalaContractKmsProjection,
  SYNTHETIC_PHALA_K256,
} from "./phala-contract-kms-test-fixture.mjs";

const CURRENT_USER = Object.freeze({
  user: Object.freeze({
    username: "adapter-reviewer",
    email: "adapter-reviewer@example.test",
    role: "admin",
    avatar: "",
    email_verified: true,
    totp_enabled: true,
    has_backup_codes: true,
    flag_has_password: true,
  }),
  workspace: Object.freeze({
    id: "workspace-production-1",
    name: "DNAI Production",
    slug: "dnai-production",
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

const ACTIVE_WORKSPACE_RESPONSE = Object.freeze({
  id: CURRENT_USER.workspace.id,
  name: CURRENT_USER.workspace.name,
  slug: CURRENT_USER.workspace.slug,
  avatar_url: null,
  tier: CURRENT_USER.workspace.tier,
  role: CURRENT_USER.workspace.role,
  is_default: true,
  created_at: "2026-07-21T12:00:00Z",
  confidential_models_enabled: true,
  billing_status: "active",
  suspended_at: null,
});

function buildRealisticPreparedCvmResponse({
  authorities,
  domain,
  appId,
  composeHash,
  instanceType,
} = {}) {
  const fixture = createSyntheticPhalaContractKmsFixture();
  const projection = authorities.targetAuthority.kms;
  const placement = projection.eligible_placements.find(
    (entry) => entry.target_domains.includes(domain),
  );
  assert.ok(placement, "shared KMS fixture must provide a reviewed placement");
  const replica = fixture.resources.kms_nodes.find(
    (entry) => entry.id === placement.kms_id,
  );
  const host = fixture.resources.nodes.find(
    (entry) => entry.node_id === placement.node_id
      && entry.teepod_id === placement.teepod_id,
  );
  assert.ok(replica, "shared KMS fixture must provide the selected replica");
  assert.ok(host, "shared KMS fixture must provide the selected node/teepod host");
  return {
    app_id: appId,
    compose_hash: composeHash,
    instance_type: instanceType,
    node_id: host.node_id,
    teepod_id: host.teepod_id,
    kms_id: replica.id,
    kms_contract_id: fixture.contract.id,
    kms_info: {
      ...replica,
      k256_pubkey: fixture.contract.k256_pubkey,
    },
    device_id: host.device_id,
    gateway_app_id: replica.gateway_app_id,
    os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    app_env_encrypt_pubkey: "3".repeat(64),
  };
}

function syntheticPreparedBinding(authorities, domain) {
  const projection = authorities.targetAuthority.kms;
  const placement = projection.eligible_placements.find(
    (entry) => entry.target_domains.includes(domain),
  );
  assert.ok(placement, "shared KMS fixture must cover the posture domain");
  const replica = projection.replicas.find((entry) => entry.id === placement.kms_id);
  assert.ok(replica, "shared KMS fixture must retain the prepared replica");
  const device = placement.device_ids.find(
    (entry) => entry.enabled === true && entry.algorithm_version === "v3.0.0",
  );
  assert.ok(device, "shared KMS fixture must retain one enabled reviewed device");
  return {
    kms_contract_id: projection.contract.id,
    kms_id: replica.id,
    kms_url: replica.url,
    node_id: placement.node_id,
    teepod_id: placement.teepod_id,
    device_id: device.device_id,
    gateway_app_id: placement.gateway_app_id,
  };
}

function buildPinnedSdkFullCvmInfoResponse({
  authorities,
  domain,
  cvmId,
  appId,
  composeHash,
  environmentPublicKey,
} = {}) {
  const preparedBinding = syntheticPreparedBinding(authorities, domain);
  const resource = authorities.targetAuthority.resource_targets[domain];
  return {
    id: cvmId,
    name: "synthetic-main",
    status: "running",
    gateway: {},
    app_id: appId,
    compose_hash: composeHash,
    kms_type: "phala",
    kms_info: {
      chain_id: null,
      dstack_kms_address: null,
      dstack_app_address: null,
      deployer_address: null,
      rpc_endpoint: preparedBinding.kms_url,
      encrypted_env_pubkey: environmentPublicKey,
    },
    node_info: {
      object_type: "node",
      id: preparedBinding.node_id,
      device_ids: [{
        device_id: preparedBinding.device_id,
        algorithm_version: "v3.0.0",
        enabled: true,
      }],
    },
    os: {
      is_dev: false,
      os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    },
    resource: {
      instance_type: resource.instance_type,
      disk_in_gb: resource.disk_size,
    },
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  };
}

function secondTimestamp(offsetSeconds) {
  return new Date(Math.floor(Date.now() / 1_000) * 1_000 + offsetSeconds * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function authorityFixture() {
  const packageIdentity = resolvePinnedPhalaPackageIdentity();
  const sdkIdentity = projectPinnedSdkCompatibilityIdentity(packageIdentity);
  const compatibility = {
    schema: PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_read_only_compatibility_observation_not_launch_authority",
    checked_at: secondTimestamp(-60),
    expires_at: secondTimestamp(600),
    api_origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
    probed_versions: PHALA_API_CANDIDATE_VERSIONS.map((version) => ({
      version,
      authenticated: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      strict_schema_valid: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      response_origin_valid: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      read_only_calls_complete: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
    })),
    selected_api_version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
    read_only_calls: [...PHALA_READ_ONLY_COMPATIBILITY_CALLS],
    workspace: {
      workspace_id: CURRENT_USER.workspace.id,
      account_subject_sha256: phalaAuthenticatedAccountSubjectSha256(CURRENT_USER),
      authenticated: true,
      billing_status: "active",
    },
    sdk_identity: sdkIdentity,
    kms: createSyntheticPhalaContractKmsProjection(),
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_catalog: [...new Set(
      Object.values(PHALA_CVM_RESOURCE_TARGETS).map(({ instance_type: value }) => value),
    )].sort().map((name) => ({
      name,
      default_disk_size_gb: 20,
      maximum_disk_size_gb: 2_048,
      requires_gpu: false,
    })),
    quota: {
      max_instances: 7,
      max_disk_gb: 2_048,
      catalog_reports_sufficient_capacity: true,
    },
    staging_provision_performed: false,
    mutation_calls: [],
  };
  const staging = {
    schema: PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_empty_operator_designated_staging_workspace_wire_capture_not_exclusive_isolation_proof_production_cvm_commit_tdx_attestation_or_launch_authority",
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    captured_at: secondTimestamp(-50),
    expires_at: secondTimestamp(550),
    api_origin: compatibility.api_origin,
    api_version: compatibility.selected_api_version,
    workspace: {
      workspace_id: compatibility.workspace.workspace_id,
      account_subject_sha256: compatibility.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(sdkIdentity),
    capture_method:
      "authenticated_transport_interceptor_after_sdk_transform_before_http_serialization",
    target_review_input_sha256: digest("e"),
    workspace_preflight: {
      authenticated_committed_cvm_count_before_prepare: 0,
      page: 1,
      page_size: 100,
      pages: 0,
      items_count: 0,
      total: 0,
      response_sha256: digest("d"),
      operator_asserted_dedicated_workspace: true,
      exclusive_workspace_control_proven: false,
    },
    provision_call_count: 7,
    commit_calls: [],
    journal_final_sha256: digest("f"),
    journal_successful_prepare_count: 7,
    server_cleanup_claimed: false,
    pending_server_state_status:
      "seven_prepares_succeeded_uncommitted_operator_reconciliation_required",
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => {
      const pre = (index + 8).toString(16);
      const post = (index + 1).toString(16);
      const response = ((index + 7) % 15 + 1).toString(16);
      return {
        domain,
        http_method: "POST",
        request_target_sha256: PHALA_PROVISION_REQUEST_TARGET_SHA256,
        request_semantics_sha256: digest((index + 1).toString(16)),
        pre_transform_request_sha256: digest(pre),
        expected_post_transform_body_sha256: digest(post),
        captured_post_transform_body_sha256: digest(post),
        pre_transform_compose_hash: pre.repeat(64),
        expected_post_transform_compose_hash: post.repeat(64),
        prepare_server_compose_hash: post.repeat(64),
        prepare_response_sha256: digest(response),
      };
    }),
  };
  const target = {
    schema: PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
    truth_status:
      "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt",
    release_sha: "a".repeat(40),
    cvm_launch_intent_sha256: digest("5"),
    review_envelope_sha256: digest("6"),
    review_evidence_sha256: digest("7"),
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    staging_compose_hash_receipt_sha256: digest("b"),
    api: {
      origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
      version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      timeout_ms: 20_000,
      retry: 0,
      redirect: "error",
    },
    workspace: {
      workspace_id: compatibility.workspace.workspace_id,
      account_subject_sha256: compatibility.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(sdkIdentity),
    kms: {
      ...structuredClone(compatibility.kms),
      env_encrypt_signer_k256: SYNTHETIC_PHALA_K256,
      signer_provenance_sha256: digest("a"),
      valid_from: secondTimestamp(-3_600),
      valid_until: secondTimestamp(3_600),
    },
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_targets: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
      domain,
      {
        ...structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
        authority_status: "reviewed_authenticated_catalog_and_quota_validated",
      },
    ])),
    app_compose_profiles: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => {
      const candidate = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate;
      return [domain, {
        name: candidate.name,
        manifest_version: 2,
        runner: "docker-compose",
        kms_enabled: true,
        gateway_enabled: candidate.gateway_enabled,
        tproxy_enabled: false,
        skip_gateway: !candidate.gateway_enabled,
        storage_fs: "ext4",
        secure_time: true,
        public_logs: false,
        public_sysinfo: false,
        public_tcbinfo: false,
      }];
    })),
    reviewed_at: secondTimestamp(-40),
    expires_at: secondTimestamp(500),
  };
  staging.target_review_input_sha256 =
    phalaProductionTargetReviewInputProjectionDigest(target);
  target.staging_compose_hash_receipt_sha256 =
    phalaSdkWireTransformStagingReceiptDigest(staging, {
      compatibilityReceipt: compatibility,
    });
  return { targetAuthority: target, compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging };
}

function installCanonicalCredentialHome(t, { fileMode = 0o600, directoryMode = 0o700 } = {}) {
  const originalHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    ".dnai-phala-adapter-",
  ));
  const directory = path.join(home, ".phala-cloud");
  fs.mkdirSync(directory, { mode: directoryMode });
  fs.chmodSync(directory, directoryMode);
  const credentialPath = path.join(directory, "credentials.json");
  fs.writeFileSync(credentialPath, `${JSON.stringify({
    schema_version: 1,
    current_profile: "production",
    profiles: {
      production: {
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
        updated_at: secondTimestamp(-120),
      },
    },
  }, null, 2)}\n`, { mode: fileMode });
  fs.chmodSync(credentialPath, fileMode);
  process.env.HOME = home;
  t.after(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    fs.rmSync(home, { recursive: true, force: true });
  });
  return { home, directory, credentialPath };
}

function installFakeHttps(t, handler) {
  const original = https.request;
  https.request = (options, callback) => {
    const request = new EventEmitter();
    const chunks = [];
    request.write = (chunk) => {
      chunks.push(Buffer.from(chunk));
      return true;
    };
    request.destroy = () => {};
    request.end = () => {
      queueMicrotask(() => {
        let result;
        try {
          result = handler(options, Buffer.concat(chunks));
        } catch (error) {
          request.emit("error", error);
          return;
        }
        const bytes = Buffer.from(JSON.stringify(result.body), "utf8");
        const response = Readable.from([bytes]);
        response.statusCode = result.status ?? 200;
        response.headers = {
          "content-type": "application/json; charset=utf-8",
          "content-length": String(bytes.length),
        };
        callback(response);
      });
    };
    return request;
  };
  t.after(() => { https.request = original; });
}

function capsuleMaterial() {
  return {
    authorityBytes: fs.readFileSync(new URL(
      "../deployments/phala-sdk-runtime-capsule-authority.json",
      import.meta.url,
    )),
    registryEvidenceBytes: fs.readFileSync(new URL(
      "../deployments/phala-sdk-upstream-registry-evidence.json",
      import.meta.url,
    )),
    capsuleBytes: fs.readFileSync(new URL(
      "./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs",
      import.meta.url,
    )),
    legalNoticeBytes: fs.readFileSync(new URL(
      "./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs.LEGAL.txt",
      import.meta.url,
    )),
    cloudTarballBytes: fs.readFileSync(new URL(
      "./vendor/npm/phala-cloud-0.4.0.tgz",
      import.meta.url,
    )),
    dstackTarballBytes: fs.readFileSync(new URL(
      "./vendor/npm/phala-dstack-sdk-0.5.8.tgz",
      import.meta.url,
    )),
  };
}

function corrupted(bytes) {
  const copy = Buffer.from(bytes);
  copy[Math.floor(copy.length / 2)] ^= 1;
  return copy;
}

test("reviewed SDK capsule pins authority, bundle, npm tarballs, capabilities, and exports", async () => {
  const material = capsuleMaterial();
  const verified = verifyReviewedPhalaSdkRuntimeCapsuleMaterial(material);
  assert.match(verified.authority_sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.match(verified.capsule_sha256, /^sha256:[0-9a-f]{64}$/u);
  for (const field of Object.keys(material)) {
    assert.throws(() => verifyReviewedPhalaSdkRuntimeCapsuleMaterial({
      ...material,
      [field]: corrupted(material[field]),
    }), /digest|reviewed (?:static )?pin|source package/u);
  }

  assert.doesNotThrow(() => assertReviewedCapsuleSourceCapabilityBoundary(
    material.capsuleBytes,
  ));
  const sourcePrefix = Buffer.from(
    'import {} from "crypto";\nimport {} from "node:crypto";\n',
    "utf8",
  );
  const forbiddenCases = [
    'fetch("https://example.test")',
    'globalThis["fetch"]("https://example.test")',
    'import("node:https")',
    'require("node:fs")',
    'process?.env.HOME',
    '(0, eval)("1")',
    'Function?.("return 1")',
    'WebAssembly.compile(new Uint8Array())',
    'Deno.open("/tmp/x")',
    'const addon = "escape.node"',
    'import fs from "node:fs";',
    'import https from "node:https";',
    'import net from "node:net";',
    'import tls from "node:tls";',
    'import childProcess from "node:child_process";',
    'import module from "node:module";',
  ];
  for (const source of forbiddenCases) {
    assert.throws(() => assertReviewedCapsuleSourceCapabilityBoundary(
      Buffer.concat([sourcePrefix, Buffer.from(`${source}\n`, "utf8")]),
    ), /forbidden direct capability|unreviewed runtime module/u, source);
  }

  const identity = loadReviewedPhalaSdkRuntimeCapsule();
  const module = await importReviewedPhalaSdkRuntimeCapsule(identity);
  assert.deepEqual(Object.keys(module).sort(), [...PHALA_REVIEWED_CAPSULE_EXPORTS]);
  assert.equal(
    phalaSdkActionRequestPolicySha256(),
    PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
  );
  assert.equal(PHALA_SDK_ACTION_REQUEST_POLICY.length, 18);
});

test("capsule import uses verified captured bytes and ignores fake PATH package graphs", async (t) => {
  const fakeRoot = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "dnai-fake-phala-path-",
  ));
  t.after(() => fs.rmSync(fakeRoot, { recursive: true, force: true }));
  const fakeBin = path.join(fakeRoot, "bin");
  const fakeCloud = path.join(fakeBin, "node_modules", "@phala", "cloud");
  const fakeDstack = path.join(fakeBin, "node_modules", "@phala", "dstack-sdk");
  fs.mkdirSync(path.join(fakeCloud, "dist"), { recursive: true });
  fs.mkdirSync(path.join(fakeDstack, "dist"), { recursive: true });
  const marker = path.join(fakeRoot, "executed-marker");
  fs.writeFileSync(path.join(fakeBin, "phala"),
    `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 91\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, "package.json"), JSON.stringify({
    name: "phala", version: "1.1.19", bin: { phala: "phala" },
  }));
  fs.writeFileSync(path.join(fakeCloud, "package.json"), JSON.stringify({
    name: "@phala/cloud", version: "0.4.0",
  }));
  fs.writeFileSync(path.join(fakeCloud, "dist", "index.mjs"),
    `import "fake-transitive";\nawait import("node:fs").then(({writeFileSync}) => writeFileSync(${JSON.stringify(marker)}, "bad"));\n`);
  fs.writeFileSync(path.join(fakeDstack, "package.json"), JSON.stringify({
    name: "@phala/dstack-sdk", version: "0.5.8",
  }));
  fs.writeFileSync(path.join(fakeDstack, "dist", "index.mjs"), "throw new Error('fake');\n");

  const originalPath = process.env.PATH;
  const originalOpen = fs.openSync;
  const originalAccess = fs.accessSync;
  const touchedFakePaths = [];
  process.env.PATH = `${fakeBin}${path.delimiter}${originalPath ?? ""}`;
  fs.openSync = (...args) => {
    if (String(args[0]).startsWith(fakeRoot)) touchedFakePaths.push(String(args[0]));
    return originalOpen(...args);
  };
  fs.accessSync = (...args) => {
    if (String(args[0]).startsWith(fakeRoot)) touchedFakePaths.push(String(args[0]));
    return originalAccess(...args);
  };
  try {
    const adapterIdentity = resolvePinnedPhalaPackageIdentity();
    assert.equal(
      projectPinnedSdkCompatibilityIdentity(adapterIdentity)
        .sdk_runtime_capsule_sha256,
      verifyReviewedPhalaSdkRuntimeCapsuleMaterial(capsuleMaterial()).capsule_sha256,
    );
  } finally {
    fs.openSync = originalOpen;
    fs.accessSync = originalAccess;
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  }
  assert.deepEqual(touchedFakePaths, []);
  assert.equal(fs.existsSync(marker), false);

  const capsuleIdentity = loadReviewedPhalaSdkRuntimeCapsule();
  const originalRead = fs.readFileSync;
  fs.openSync = () => { throw new Error("filesystem reread forbidden after capture"); };
  fs.readFileSync = () => { throw new Error("filesystem reread forbidden after capture"); };
  try {
    const module = await importReviewedPhalaSdkRuntimeCapsule(capsuleIdentity);
    assert.deepEqual(Object.keys(module).sort(), [...PHALA_REVIEWED_CAPSULE_EXPORTS]);
  } finally {
    fs.openSync = originalOpen;
    fs.readFileSync = originalRead;
  }
});

test("every reviewed capsule action emits one exact request and route drift rejects before I/O", async () => {
  const authorities = authorityFixture();
  const domain = "diligence_qvl_cvm";
  const profile = authorities.targetAuthority.app_compose_profiles[domain];
  const compose = buildExplicitAppCompose({
    profile,
    dockerComposeFile:
      `services:\n  qvl:\n    image: example.invalid/qvl@sha256:${"4".repeat(64)}`,
    allowedEnvironmentKeys: ["A"],
  });
  const appId = "2".repeat(40);
  const provisionRequest = buildExactProvisionRequest({
    domain,
    applicationName: profile.name,
    resourceTarget: authorities.targetAuthority.resource_targets[domain],
    appCompose: compose,
    activeEnvironmentKeys: ["A"],
    appId,
    nonce: 42,
    kmsContractId: authorities.targetAuthority.kms.contract.id,
  });
  const actionArguments = {
    commitCvmProvision: [{ app_id: appId, compose_hash: "3".repeat(64) }],
    getAppEnvEncryptPubKey: [{ kms: "phala", app_id: appId }],
    getCvmAttestation: [{ id: "cvm-main-0001" }],
    getCvmCreateResources: [],
    getCvmInfo: [{ id: "cvm-main-0001" }],
    getCvmList: [{ page: 1, page_size: 100 }],
    getCurrentUser: [],
    getKmsContract: [{ slug: "kc_production1" }],
    getKmsInfo: [{ kms_id: "kms-production-1" }],
    getKmsList: [{ page: 1, page_size: 100, is_onchain: false }],
    getOsImages: [{ page: 1, page_size: 100, is_dev: false }],
    getWorkspace: [CURRENT_USER.workspace.slug],
    listKmsContractNodes: [{ slug: "kc_production1" }],
    listKmsContracts: [{ page: 1, page_size: 100, is_onchain: false }],
    nextAppIds: [{ counts: 7 }],
    provisionCvm: [provisionRequest],
    restartCvm: [{ id: "cvm-main-0001", force: false }],
    updateCvmEnvs: [{ id: "cvm-main-0001", encrypted_env: "ab".repeat(96) }],
  };
  const capsule = await importReviewedPhalaSdkRuntimeCapsule(
    loadReviewedPhalaSdkRuntimeCapsule(),
  );
  for (const policy of PHALA_SDK_ACTION_REQUEST_POLICY) {
    const calls = [];
    const sentinel = new Error(`captured ${policy.action}`);
    const capture = (method, requestPath, body, options) => {
      const url = new URL(`https://cloud-api.phala.network/api/v1${requestPath}`);
      for (const [key, value] of Object.entries(options?.params ?? {})) {
        url.searchParams.append(key, String(value));
      }
      calls.push({
        action: policy.action,
        http_method: method,
        path_and_query: `${url.pathname}${url.search}`,
        body: body === undefined ? null : JSON.parse(JSON.stringify(body)),
        api_version_header: assertPinnedSdkActionVersionHeaders({
          action: policy.action, headers: options?.headers,
        }),
      });
      throw sentinel;
    };
    const client = {
      config: { version: PHALA_CONTROL_PLANE_AUTHORITY.api_version },
      get: (requestPath, options) => capture("GET", requestPath, undefined, options),
      post: (requestPath, body, options) => capture("POST", requestPath, body, options),
      patch: (requestPath, body, options) => capture("PATCH", requestPath, body, options),
    };
    await assert.rejects(
      capsule[policy.action](client, ...actionArguments[policy.action]),
      (error) => error === sentinel,
    );
    assert.deepEqual(calls, [projectPinnedSdkActionRequest(
      policy.action,
      actionArguments[policy.action],
    )]);
  }

  let networkCalls = 0;
  const exact = projectPinnedSdkActionRequest("getCurrentUser", []);
  for (const drift of [
    { httpMethod: "POST", pathAndQuery: exact.path_and_query, body: null },
    { httpMethod: "GET", pathAndQuery: "/api/v1/cvms", body: null },
    { httpMethod: "GET", pathAndQuery: `${exact.path_and_query}?extra=1`, body: null },
    { httpMethod: "GET", pathAndQuery: exact.path_and_query, body: { extra: true } },
  ]) {
    assert.throws(() => {
      assertPinnedSdkActionRequestMatches({
        action: "getCurrentUser",
        actionArguments: [],
        ...drift,
      });
      networkCalls += 1;
    }, /outside its reviewed policy/u);
  }
  assert.equal(networkCalls, 0);
});

test("actual capsule transport records per-action version without contaminating the next call", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  const calls = [];
  const kms = {
    ...authorities.targetAuthority.kms.replicas[0],
    chain_id: null, kms_contract_address: null, gateway_app_id: "1".repeat(40),
  };
  installFakeHttps(t, (options) => {
    assert.deepEqual(Object.keys(options.headers).sort(), [
      "Accept", "Content-Type", "X-API-Key", "X-Phala-Version",
    ]);
    calls.push({ path: options.path, version: options.headers["X-Phala-Version"] });
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/kms/${kms.id}`) return { body: kms };
    throw new Error("unexpected transport request");
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  const first = await adapter.getCurrentUser();
  const middle = await adapter.getKmsInfo({ kmsId: kms.id });
  const last = await adapter.getCurrentUser();
  const versions = [PHALA_CONTROL_PLANE_AUTHORITY.api_version, "2026-05-22", PHALA_CONTROL_PLANE_AUTHORITY.api_version];
  assert.deepEqual(calls.map((entry) => entry.version), versions);
  assert.deepEqual([first, middle, last].map((entry) => entry.api_version), versions);
  assert.deepEqual([first, middle, last].map((entry) => entry.call_sequence), [1, 2, 3]);
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(middle, {
    adapter, method: "getKmsInfo",
  }), kms);
});

test("action headers reject missing, extra, case-shifted, and cross-version authority before I/O", () => {
  let calls = 0;
  for (const policy of PHALA_SDK_ACTION_REQUEST_POLICY) {
    const expected = policy.api_version_header;
    const headers = expected === null ? undefined : { "X-Phala-Version": expected };
    assert.equal(assertPinnedSdkActionVersionHeaders({ action: policy.action, headers }), expected);
    const invalid = expected === null
      ? [{}, { "X-Phala-Version": "2026-06-23" }, { Authorization: "test" }]
      : [undefined, {}, { "x-phala-version": expected },
        { "X-Phala-Version": expected === "2026-06-23" ? "2026-05-22" : "2026-06-23" },
        { "X-Phala-Version": expected, "X-API-Key": "test" }];
    for (const badHeaders of invalid) {
      assert.throws(() => {
        assertPinnedSdkActionVersionHeaders({ action: policy.action, headers: badHeaders });
        calls += 1;
      }, /reviewed|exact pinned fields/);
    }
  }
  assert.equal(calls, 0);
});

test("contract and workspace paths do not permit node IDs, fallback node aliases, or path injection", () => {
  for (const [action, args] of [
    ["getKmsContract", [{ slug: "kms_node1" }]],
    ["getKmsContract", [{ slug: "phala-prod5" }]],
    ["listKmsContractNodes", [{ slug: "phala" }]],
    ["listKmsContractNodes", [{ slug: "kc_prod/other" }]],
    ["getWorkspace", ["../auth/me"]],
    ["getWorkspace", ["dnai?other=true"]],
  ]) assert.throws(() => projectPinnedSdkActionRequest(action, args));
});

test("raw workspace billing cannot become active through SDK defaults", async () => {
  const capsule = await importReviewedPhalaSdkRuntimeCapsule(loadReviewedPhalaSdkRuntimeCapsule());
  const raw = {
    ...CURRENT_USER.workspace, is_default: false, created_at: "2026-09-16T00:00:00Z",
  };
  const guardedClient = (response) => ({ get: async () => {
    projectPinnedSdkRawIdentityFields("getWorkspace", response);
    return response;
  } });
  await assert.rejects(capsule.getWorkspace(guardedClient(raw), raw.slug), /explicitly report/);
  for (const billing_status of [null, "", "unknown", true]) {
    await assert.rejects(capsule.getWorkspace(guardedClient({ ...raw, billing_status }), raw.slug), /explicitly report/);
  }
  for (const billing_status of ["active", "suspended", "abandoned"]) {
    const parsed = await capsule.getWorkspace(guardedClient({ ...raw, billing_status }), raw.slug);
    assert.equal(parsed.billing_status, billing_status);
  }
});

test("reservation and mutation stay blocked without explicit active billing for the authenticated workspace", async (t) => {
  const missingBilling = { ...ACTIVE_WORKSPACE_RESPONSE };
  delete missingBilling.billing_status;
  const cases = [
    {
      name: "missing billing that the SDK schema would otherwise default active",
      response: missingBilling,
      error: /explicitly report a known billing_status/,
    },
    {
      name: "suspended billing",
      response: {
        ...ACTIVE_WORKSPACE_RESPONSE,
        billing_status: "suspended",
        suspended_at: "2026-09-16T01:00:00Z",
      },
      error: /must explicitly be active/,
    },
    {
      name: "abandoned billing",
      response: { ...ACTIVE_WORKSPACE_RESPONSE, billing_status: "abandoned" },
      error: /must explicitly be active/,
    },
    {
      name: "different workspace id",
      response: { ...ACTIVE_WORKSPACE_RESPONSE, id: "workspace-other-1" },
      error: /workspace identity differs/,
    },
    {
      name: "different workspace slug",
      response: { ...ACTIVE_WORKSPACE_RESPONSE, slug: "other-production" },
      error: /workspace identity differs/,
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      installCanonicalCredentialHome(t);
      const requests = [];
      let reservationOrMutationRequests = 0;
      installFakeHttps(t, (options) => {
        requests.push(options.path);
        if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
        if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
          return { body: scenario.response };
        }
        reservationOrMutationRequests += 1;
        return { status: 500, body: { error: "mutation unexpectedly reached HTTPS" } };
      });
      const adapter = await createPinnedPhalaProductionSdkAdapter(authorityFixture());
      await adapter.getCurrentUser();
      await assert.rejects(adapter.getWorkspace(), scenario.error);
      await assert.rejects(
        adapter.nextAppIds(),
        /explicit active workspace billing must be verified/,
      );
      await assert.rejects(adapter.updateCvmEnvs({
        domain: "main_runtime_cvm",
        cvmId: "cvm-main-0001",
        request: { encrypted_env: "ab".repeat(96) },
      }), /explicit active workspace billing must be verified/);
      assert.equal(reservationOrMutationRequests, 0);
      assert.deepEqual(requests, [
        "/api/v1/auth/me",
        `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`,
      ]);
    });
  }
});

test("raw prepare placement preserves node and teepod namespaces and absence", () => {
  assert.deepEqual(projectPinnedSdkRawIdentityFields("provisionCvm", { node_id: 9, teepod_id: 18 }),
    { node_id: 9, teepod_id: 18 });
  assert.deepEqual(projectPinnedSdkRawIdentityFields("provisionCvm", { teepod_id: 18 }), { teepod_id: 18 });
  assert.deepEqual(projectPinnedSdkRawIdentityFields("provisionCvm", { node_id: null, teepod_id: 18 }),
    { node_id: null, teepod_id: 18 });
  assert.deepEqual(projectPinnedSdkRawIdentityFields("provisionCvm", {}), {});
  for (const value of [0, -1, undefined, "9", 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => projectPinnedSdkRawIdentityFields("provisionCvm", { node_id: value }), /canonical identity/);
  }
});

test("raw CVM privacy posture cannot be admitted through SDK false defaults", async (t) => {
  const fields = ["listed", "public_logs", "public_sysinfo", "public_tcbinfo"];
  const cases = fields.flatMap((field, index) => [
    {
      name: `missing ${field}`,
      mutate(value) { delete value[field]; },
    },
    {
      name: `non-boolean ${field}`,
      mutate(value) { value[field] = [0, "false", null, {}][index]; },
    },
  ]);

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      installCanonicalCredentialHome(t);
      const authorities = authorityFixture();
      const domain = "main_runtime_cvm";
      const cvmId = "cvm-production-main";
      const raw = buildPinnedSdkFullCvmInfoResponse({
        authorities,
        domain,
        cvmId,
        appId: "2".repeat(40),
        composeHash: "4".repeat(64),
        environmentPublicKey: "5".repeat(64),
      });
      scenario.mutate(raw);
      const requests = [];
      installFakeHttps(t, (options) => {
        requests.push(options.path);
        if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
        if (options.path === `/api/v1/cvms/${cvmId}`) return { body: raw };
        throw new Error(`unexpected fake request ${options.method} ${options.path}`);
      });
      const observer =
        await createPinnedPhalaHistoricalContinuityReadOnlySdkObserver(authorities);
      const first = await observer.getCurrentUser();
      await assert.rejects(
        observer.getCvmInfo({ domain, cvmId }),
        new RegExp(`must explicitly report ${scenario.name.split(" ").at(-1)}`),
      );
      const second = await observer.getCurrentUser();
      assert.deepEqual([first.call_sequence, second.call_sequence], [1, 2]);
      assert.deepEqual(requests, [
        "/api/v1/auth/me",
        `/api/v1/cvms/${cvmId}`,
        "/api/v1/auth/me",
      ]);
    });
  }
});

test("capsule loader rejects unsafe Node preload and inspector launch flags", () => {
  const original = [...process.execArgv];
  try {
    for (const flag of [
      "--import=data:text/javascript,throw%20new%20Error('bad')",
      "--require=/tmp/bad-preload.cjs",
      "--loader=/tmp/bad-loader.mjs",
      "--inspect=127.0.0.1:0",
      "--inspect-brk=127.0.0.1:0",
      "--inspect-wait=127.0.0.1:0",
      "--eval=globalThis.compromised=true",
      "--print=globalThis.compromised=true",
      "--interactive",
      "-eglobalThis.compromised=true",
      "-pglobalThis.compromised=true",
      "-r/tmp/bad-preload.cjs",
      "-i",
    ]) {
      process.execArgv.splice(0, process.execArgv.length, flag);
      assert.throws(() => loadReviewedPhalaSdkRuntimeCapsule(),
        /unsafe preload or inspector flag/u);
    }
  } finally {
    process.execArgv.splice(0, process.execArgv.length, ...original);
  }
});

test("adapter uses exact SDK actions over fake HTTPS and brands secret-free observations", async (t) => {
  installCanonicalCredentialHome(t);
  const calls = [];
  const reservation = {
    app_id: "2".repeat(40),
    nonce: 42,
  };
  let provisionBody;
  installFakeHttps(t, (options, bodyBytes) => {
    calls.push({ method: options.method, path: options.path });
    assert.equal(options.hostname, "cloud-api.phala.network");
    assert.equal(options.timeout, 20_000);
    assert.equal(options.agent, false);
    assert.match(options.headers["X-API-Key"], /^phak_/);
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    if (options.path === "/api/v1/kms/phala/next_app_id?counts=7") {
      return { body: { app_ids: [reservation] } };
    }
    if (options.path === "/api/v1/cvms/provision") {
      provisionBody = JSON.parse(bodyBytes.toString("utf8"));
      return {
        body: buildRealisticPreparedCvmResponse({
          authorities,
          domain: "diligence_qvl_cvm",
          appId: reservation.app_id,
          composeHash: dstackCanonicalComposeHash(provisionBody.compose_file),
          instanceType: provisionBody.instance_type,
        }),
      };
    }
    throw new Error(`unexpected fake request ${options.method} ${options.path}`);
  });

  const authorities = authorityFixture();
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  assert.equal(assertPinnedPhalaProductionSdkAdapter(adapter), adapter);
  const identity = projectPinnedPhalaProductionSdkAdapterIdentity(adapter);
  assert.match(pinnedPhalaProductionSdkAdapterIdentitySha256(adapter),
    /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(identity).includes("phak_"), false);

  await assert.rejects(adapter.nextAppIds(), /getCurrentUser/);
  const accountObservation = await adapter.getCurrentUser();
  assert.equal(accountObservation.schema, PHALA_AUTHENTICATED_SDK_OBSERVATION_SCHEMA);
  assert.equal(accountObservation.call_sequence, 1);
  assert.equal(accountObservation.captured_post_transform_body_sha256, null);
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(accountObservation, {
    adapter,
    method: "getCurrentUser",
    domain: null,
  }), CURRENT_USER);
  const workspaceObservation = await adapter.getWorkspace();
  assert.equal(workspaceObservation.call_sequence, 2);
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(workspaceObservation, {
    adapter,
    method: "getWorkspace",
    domain: null,
  }), ACTIVE_WORKSPACE_RESPONSE);
  const reservationObservation = await adapter.nextAppIds();
  assert.equal(reservationObservation.call_sequence, 3);
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(reservationObservation, {
    adapter,
    method: "nextAppIds",
    domain: null,
  }), { app_ids: [reservation] });

  const domain = "diligence_qvl_cvm";
  const profile = authorities.targetAuthority.app_compose_profiles[domain];
  const compose = buildExplicitAppCompose({
    profile,
    dockerComposeFile:
      `services:\n  qvl:\n    image: example.invalid/qvl@sha256:${"4".repeat(64)}`,
    allowedEnvironmentKeys: ["A"],
  });
  const provisionRequest = buildExactProvisionRequest({
    domain,
    applicationName: profile.name,
    resourceTarget: authorities.targetAuthority.resource_targets[domain],
    appCompose: compose,
    activeEnvironmentKeys: ["A"],
    appId: reservation.app_id,
    nonce: reservation.nonce,
    kmsContractId: authorities.targetAuthority.kms.contract.id,
  });
  const provisionObservation = await adapter.provisionCvm({
    domain,
    request: provisionRequest,
  });
  assert.equal(provisionObservation.call_sequence, 4);
  assert.equal(Object.hasOwn(provisionBody.compose_file, "tproxy_enabled"), false);
  assert.equal(
    provisionObservation.captured_post_transform_body_sha256,
    phalaSdkJsonBodySemanticDigest(projectPinnedProvisionWireBody(provisionRequest)),
  );
  assert.equal(
    provisionObservation.request_semantics_sha256,
    phalaAuthenticatedSdkRequestSemanticsSha256({
      httpMethod: "POST",
      pathAndQuery: "/api/v1/cvms/provision",
      body: projectPinnedProvisionWireBody(provisionRequest),
    }),
  );
  assert.match(provisionObservation.serialized_http_body_sha256,
    /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(provisionObservation).includes("phak_"), false);
  assert.equal(JSON.stringify(provisionObservation).includes("docker_compose_file"), false);

  const firstDigest = authenticatedPhalaSdkObservationSha256(accountObservation, {
    adapter,
    method: "getCurrentUser",
    domain: null,
  });
  assert.notEqual(firstDigest, authenticatedPhalaSdkObservationSha256(
    reservationObservation,
    { adapter, method: "nextAppIds", domain: null },
  ));
  assert.throws(() => assertAuthenticatedPhalaSdkObservation(
    structuredClone(accountObservation),
    { adapter, method: "getCurrentUser", domain: null },
  ), /locally authenticated/);
  assert.throws(() => assertAuthenticatedPhalaSdkObservation(
    provisionObservation,
    { adapter, method: "provisionCvm", domain: "arena_qvl_cvm" },
  ), /matching locally authenticated/);
  assert.deepEqual(calls.map(({ path: value }) => value), [
    "/api/v1/auth/me",
    `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`,
    "/api/v1/kms/phala/next_app_id?counts=7",
    "/api/v1/cvms/provision",
  ]);
});

test("environment key read requires the exact validated prepared replica binding", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  const domain = "diligence_qvl_cvm";
  const appId = "2".repeat(40);
  const profile = authorities.targetAuthority.app_compose_profiles[domain];
  const compose = buildExplicitAppCompose({
    profile,
    dockerComposeFile:
      `services:\n  qvl:\n    image: example.invalid/qvl@sha256:${"4".repeat(64)}`,
    allowedEnvironmentKeys: ["A"],
  });
  const provisionRequest = buildExactProvisionRequest({
    domain,
    applicationName: profile.name,
    resourceTarget: authorities.targetAuthority.resource_targets[domain],
    appCompose: compose,
    activeEnvironmentKeys: ["A"],
    appId,
    nonce: 42,
    kmsContractId: authorities.targetAuthority.kms.contract.id,
  });
  const placement = authorities.targetAuthority.kms.eligible_placements.find(
    (entry) => entry.target_domains.includes(domain),
  );
  assert.ok(placement);
  const signedKey = {
    public_key: "5".repeat(64),
    signature: `${"6".repeat(128)}00`,
  };
  const requests = [];
  let environmentKeyRequests = 0;
  installFakeHttps(t, (options, bodyBytes) => {
    requests.push(options.path);
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    if (options.path === "/api/v1/cvms/provision") {
      const body = JSON.parse(bodyBytes.toString("utf8"));
      return {
        body: buildRealisticPreparedCvmResponse({
          authorities,
          domain,
          appId,
          composeHash: dstackCanonicalComposeHash(body.compose_file),
          instanceType: body.instance_type,
        }),
      };
    }
    if (options.path === `/api/v1/kms/${placement.kms_id}/pubkey/${appId}`) {
      environmentKeyRequests += 1;
      return { body: signedKey };
    }
    throw new Error(`unexpected fake request ${options.method} ${options.path}`);
  });

  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  await adapter.getCurrentUser();
  await adapter.getWorkspace();
  await assert.rejects(adapter.getAppEnvEncryptPubKey({ domain, appId }),
    /validated prepared or committed replica binding/);
  assert.equal(environmentKeyRequests, 0);
  assert.equal(requests.length, 2);

  const prepared = await adapter.provisionCvm({ domain, request: provisionRequest });
  assert.equal(prepared.call_sequence, 3);
  for (const invocation of [
    { domain, appId: "3".repeat(40) },
    { domain: "arena_qvl_cvm", appId },
  ]) {
    await assert.rejects(adapter.getAppEnvEncryptPubKey(invocation),
      /validated prepared or committed replica binding/);
  }
  assert.equal(environmentKeyRequests, 0);
  assert.equal(requests.length, 3);

  const keyObservation = await adapter.getAppEnvEncryptPubKey({ domain, appId });
  assert.equal(keyObservation.call_sequence, 4);
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(keyObservation, {
    adapter,
    method: "getAppEnvEncryptPubKey",
    domain,
  }), signedKey);
  assert.equal(environmentKeyRequests, 1);
  assert.deepEqual(requests, [
    "/api/v1/auth/me",
    `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`,
    "/api/v1/cvms/provision",
    `/api/v1/kms/${placement.kms_id}/pubkey/${appId}`,
  ]);
});

test("commit metadata cannot reach HTTPS without the exact validated prepare binding", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  const domain = "diligence_qvl_cvm";
  const appId = "2".repeat(40);
  const profile = authorities.targetAuthority.app_compose_profiles[domain];
  const compose = buildExplicitAppCompose({
    profile,
    dockerComposeFile:
      `services:\n  qvl:\n    image: example.invalid/qvl@sha256:${"4".repeat(64)}`,
    allowedEnvironmentKeys: ["A"],
  });
  const provisionRequest = buildExactProvisionRequest({
    domain,
    applicationName: profile.name,
    resourceTarget: authorities.targetAuthority.resource_targets[domain],
    appCompose: compose,
    activeEnvironmentKeys: ["A"],
    appId,
    nonce: 42,
    kmsContractId: authorities.targetAuthority.kms.contract.id,
  });
  const composeHash = dstackCanonicalComposeHash(
    projectPinnedProvisionWireBody(provisionRequest).compose_file,
  );
  const commitRequest = {
    app_id: appId,
    compose_hash: composeHash,
    kms_contract_id: authorities.targetAuthority.kms.contract.id,
    env_keys: ["A"],
    encrypted_env: "ab".repeat(96),
  };
  const requests = [];
  let commitRequests = 0;
  installFakeHttps(t, (options, bodyBytes) => {
    requests.push(options.path);
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    if (options.path === "/api/v1/cvms/provision") {
      const body = JSON.parse(bodyBytes.toString("utf8"));
      return {
        body: buildRealisticPreparedCvmResponse({
          authorities,
          domain,
          appId,
          composeHash: dstackCanonicalComposeHash(body.compose_file),
          instanceType: body.instance_type,
        }),
      };
    }
    if (options.path === "/api/v1/cvms") {
      commitRequests += 1;
      return { status: 500, body: { error: "commit unexpectedly reached HTTPS" } };
    }
    throw new Error(`unexpected fake request ${options.method} ${options.path}`);
  });

  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  await adapter.getCurrentUser();
  await adapter.getWorkspace();
  await assert.rejects(adapter.commitCvmProvision({ domain, request: commitRequest }),
    /exact validated prepare binding/);
  assert.equal(commitRequests, 0);

  await adapter.provisionCvm({ domain, request: provisionRequest });
  for (const [label, request, error] of [
    ["app", { ...commitRequest, app_id: "3".repeat(40) }, /exact validated prepare binding/],
    ["compose", { ...commitRequest, compose_hash: "3".repeat(64) }, /exact validated prepare binding/],
    ["contract", { ...commitRequest, kms_contract_id: "kc_Substitute" }, /metadata differs/],
  ]) {
    await assert.rejects(
      adapter.commitCvmProvision({ domain, request }),
      error,
      `wrong ${label} must fail before commit HTTPS`,
    );
  }
  assert.equal(commitRequests, 0);
  assert.deepEqual(requests, [
    "/api/v1/auth/me",
    `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`,
    "/api/v1/cvms/provision",
  ]);
});

test("fresh committed posture reopens only the exact read-only environment-key lookup", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  const domain = "main_runtime_cvm";
  const cvmId = "cvm-production-main";
  const appId = "2".repeat(40);
  const composeHash = "4".repeat(64);
  const environmentPublicKey = "5".repeat(64);
  const preparedBinding = syntheticPreparedBinding(authorities, domain);
  const kmsProjection = Object.fromEntries([
    "contract",
    "replicas",
    "eligible_placements",
    "gateways",
  ].map((key) => [key, structuredClone(authorities.targetAuthority.kms[key])]));
  const baseline = buildPinnedSdkFullCvmInfoResponse({
    authorities,
    domain,
    cvmId,
    appId,
    composeHash,
    environmentPublicKey,
  });
  const changedCvm = structuredClone(baseline);
  changedCvm.id = "cvm-production-other";
  const changedReplica = structuredClone(baseline);
  changedReplica.kms_info.rpc_endpoint = authorities.targetAuthority.kms.replicas[1].url;
  const changedKey = structuredClone(baseline);
  changedKey.kms_info.encrypted_env_pubkey = "6".repeat(64);
  const changedDevice = structuredClone(baseline);
  changedDevice.node_info.device_ids[0].device_id = "2".repeat(64);
  const fullInfoResponses = [
    baseline,
    changedCvm,
    changedReplica,
    changedKey,
    changedDevice,
  ];
  const signedKey = {
    public_key: environmentPublicKey,
    signature: `${"6".repeat(128)}00`,
  };
  const requests = [];
  let mutationOrReservationRequests = 0;
  installFakeHttps(t, (options) => {
    requests.push({ method: options.method, path: options.path });
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/cvms/${cvmId}`) {
      const response = fullInfoResponses.shift();
      assert.ok(response, "each authenticated getCvmInfo call needs one fixture");
      return { body: response };
    }
    if (options.path === `/api/v1/kms/${preparedBinding.kms_id}/pubkey/${appId}`) {
      return { body: signedKey };
    }
    mutationOrReservationRequests += 1;
    return { status: 500, body: { error: "mutation unexpectedly reached HTTPS" } };
  });

  const observer =
    await createPinnedPhalaHistoricalContinuityReadOnlySdkObserver(authorities);
  assert.equal(observer.nextAppIds, undefined);
  assert.equal(observer.provisionCvm, undefined);
  assert.equal(observer.commitCvmProvision, undefined);
  await observer.getCurrentUser();
  const baselineObservation = await observer.getCvmInfo({ domain, cvmId });
  const baselineInfo = readAuthenticatedPhalaSdkObservationResponse(
    baselineObservation,
    { adapter: observer, method: "getCvmInfo", domain },
  );
  const postureReceipt = verifyProductionCvmPostureObservation({
    domain,
    cvmId,
    cvmInfo: baselineInfo,
    expected: {
      appId,
      composeHash,
      instanceType: authorities.targetAuthority.resource_targets[domain].instance_type,
      diskSize: authorities.targetAuthority.resource_targets[domain].disk_size,
      kmsProjection,
      preparedBinding,
      environmentPublicKey,
    },
  });

  assert.throws(() => bindPinnedPhalaCommittedEnvironmentKeyLookup({
    adapter: observer,
    cvmInfoObservation: baselineObservation,
    postureReceipt: structuredClone(postureReceipt),
  }), /not reconstructed from getCvmInfo/);
  assert.throws(() => bindPinnedPhalaCommittedEnvironmentKeyLookup({
    adapter: observer,
    cvmInfoObservation: structuredClone(baselineObservation),
    postureReceipt,
  }), /matching locally authenticated/);

  for (const label of ["CVM", "replica", "environment key", "device"]) {
    const driftedObservation = await observer.getCvmInfo({ domain, cvmId });
    assert.throws(() => bindPinnedPhalaCommittedEnvironmentKeyLookup({
      adapter: observer,
      cvmInfoObservation: driftedObservation,
      postureReceipt,
    }), undefined, `changed ${label} must not reopen key lookup`);
  }
  assert.equal(fullInfoResponses.length, 0);
  const requestsBeforeBinding = requests.length;
  assert.equal(bindPinnedPhalaCommittedEnvironmentKeyLookup({
    adapter: observer,
    cvmInfoObservation: baselineObservation,
    postureReceipt,
  }), observer);
  assert.equal(requests.length, requestsBeforeBinding);

  const keyObservation = await observer.getAppEnvEncryptPubKey({ domain, appId });
  assert.deepEqual(readAuthenticatedPhalaSdkObservationResponse(keyObservation, {
    adapter: observer,
    method: "getAppEnvEncryptPubKey",
    domain,
  }), signedKey);
  assert.equal(keyObservation.call_sequence, 7);
  assert.equal(mutationOrReservationRequests, 0);
  assert.deepEqual(requests.map(({ method }) => method), Array(requests.length).fill("GET"));
  assert.equal(requests.at(-1).path,
    `/api/v1/kms/${preparedBinding.kms_id}/pubkey/${appId}`);
});

test("adapter performs encrypted-env-only PATCH then force-false restart with exact semantics", async (t) => {
  installCanonicalCredentialHome(t);
  const cvmId = "cvm-main-0001";
  const encryptedEnvironment = "ab".repeat(96);
  const bodies = [];
  installFakeHttps(t, (options, bodyBytes) => {
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    if (options.path === `/api/v1/cvms/${cvmId}/envs`) {
      const body = JSON.parse(bodyBytes.toString("utf8"));
      bodies.push(body);
      assert.equal(options.method, "PATCH");
      assert.deepEqual(Object.keys(body), ["encrypted_env"]);
      return {
        body: {
          status: "in_progress",
          message: "accepted",
          correlation_id: "corr-main-0001",
          allowed_envs_changed: false,
        },
      };
    }
    if (options.path === `/api/v1/cvms/${cvmId}/restart`) {
      const body = JSON.parse(bodyBytes.toString("utf8"));
      bodies.push(body);
      assert.equal(options.method, "POST");
      assert.deepEqual(body, { force: false });
      return {
        body: {
          id: cvmId,
          name: "main-runtime",
          status: "restarting",
          teepod_id: 7,
          app_id: "2".repeat(40),
          vm_uuid: null,
          instance_id: null,
          vcpu: 2,
          memory: 4096,
          disk_size: 40,
          created_at: "2026-07-21T12:00:00Z",
          encrypted_env_pubkey: null,
        },
      };
    }
    throw new Error(`unexpected fake request ${options.method} ${options.path}`);
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorityFixture());
  await adapter.getCurrentUser();
  const workspaceObservation = await adapter.getWorkspace();
  assert.equal(workspaceObservation.call_sequence, 2);
  const patchObservation = await adapter.updateCvmEnvs({
    domain: "main_runtime_cvm",
    cvmId,
    request: { encrypted_env: encryptedEnvironment },
  });
  assert.equal(patchObservation.call_sequence, 3);
  assert.equal(
    patchObservation.request_semantics_sha256,
    phalaAuthenticatedSdkRequestSemanticsSha256({
      httpMethod: "PATCH",
      pathAndQuery: `/api/v1/cvms/${cvmId}/envs`,
      body: { encrypted_env: encryptedEnvironment },
    }),
  );
  assert.equal(
    patchObservation.captured_post_transform_body_sha256,
    phalaSdkJsonBodySemanticDigest({ encrypted_env: encryptedEnvironment }),
  );
  const restartObservation = await adapter.restartCvm({
    domain: "main_runtime_cvm",
    cvmId,
    force: false,
  });
  assert.equal(restartObservation.call_sequence, 4);
  assert.equal(
    restartObservation.request_semantics_sha256,
    phalaAuthenticatedSdkRequestSemanticsSha256({
      httpMethod: "POST",
      pathAndQuery: `/api/v1/cvms/${cvmId}/restart`,
      body: { force: false },
    }),
  );
  assert.deepEqual(bodies, [
    { encrypted_env: encryptedEnvironment },
    { force: false },
  ]);
});

test("successful observations have an internal gap-free sequence while failed calls consume none", async (t) => {
  installCanonicalCredentialHome(t);
  const originalNow = Date.now;
  const fixedNow = Math.floor(originalNow() / 1_000) * 1_000 + 250;
  Date.now = () => fixedNow;
  t.after(() => { Date.now = originalNow; });

  const authorities = authorityFixture();
  let reservationAttempts = 0;
  installFakeHttps(t, (options) => {
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    if (options.path === "/api/v1/kms/phala/next_app_id?counts=7") {
      reservationAttempts += 1;
      if (reservationAttempts === 1) {
        return { status: 503, body: { error: "temporary failure" } };
      }
      return {
        body: {
          app_ids: [{ app_id: "2".repeat(40), nonce: 42 }],
        },
      };
    }
    throw new Error(`unexpected fake request ${options.method} ${options.path}`);
  });

  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  const first = await adapter.getCurrentUser();
  const workspace = await adapter.getWorkspace();
  await assert.rejects(adapter.nextAppIds(), /status 503/);
  const second = await adapter.nextAppIds();
  const third = await adapter.getCurrentUser();

  assert.deepEqual(
    [first.call_sequence, workspace.call_sequence, second.call_sequence, third.call_sequence],
    [1, 2, 3, 4],
  );
  assert.equal(first.observed_at, workspace.observed_at);
  assert.equal(workspace.observed_at, second.observed_at);
  assert.equal(second.observed_at, third.observed_at);
  assert.notEqual(
    authenticatedPhalaSdkObservationSha256(first, {
      adapter,
      method: "getCurrentUser",
      domain: null,
    }),
    authenticatedPhalaSdkObservationSha256(third, {
      adapter,
      method: "getCurrentUser",
      domain: null,
    }),
  );
  assert.equal(assertAuthenticatedPhalaSdkObservation(second, {
    adapter,
    method: "nextAppIds",
    domain: null,
  }), second);
});

test("constructor rejects unsafe credential modes and caller-supplied adapter hooks", async (t) => {
  const { directory, credentialPath } = installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  await assert.rejects(createPinnedPhalaProductionSdkAdapter({
    ...authorities,
    client: {},
  }), /exact pinned fields/);

  fs.chmodSync(credentialPath, 0o644);
  await assert.rejects(
    createPinnedPhalaProductionSdkAdapter(authorities),
    /0600 regular file/,
  );
  fs.chmodSync(credentialPath, 0o600);
  fs.chmodSync(directory, 0o755);
  await assert.rejects(
    createPinnedPhalaProductionSdkAdapter(authorities),
    /0700/,
  );
  fs.chmodSync(directory, 0o700);
  const realCredentialPath = `${credentialPath}.real`;
  fs.renameSync(credentialPath, realCredentialPath);
  fs.symlinkSync(realCredentialPath, credentialPath);
  await assert.rejects(createPinnedPhalaProductionSdkAdapter(authorities));
});

test("authenticated account drift fails closed before any later SDK call", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  let calls = 0;
  installFakeHttps(t, (options) => {
    calls += 1;
    if (options.path === "/api/v1/auth/me") {
      return { body: { ...CURRENT_USER,
        workspace: { ...CURRENT_USER.workspace, id: "wrong-workspace" } } };
    }
    return { status: 302, body: { location: "https://example.invalid/" } };
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  await assert.rejects(adapter.getCurrentUser(), /does not match reviewed target/);
  await assert.rejects(adapter.nextAppIds(), /getCurrentUser/);
  assert.equal(calls, 1);
});

test("redirect response is not followed or retried after workspace authentication", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  let calls = 0;
  installFakeHttps(t, (options) => {
    calls += 1;
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
    if (options.path === `/api/v1/workspaces/${CURRENT_USER.workspace.slug}`) {
      return { body: ACTIVE_WORKSPACE_RESPONSE };
    }
    return { status: 302, body: { location: "https://example.invalid/" } };
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  await adapter.getCurrentUser();
  await adapter.getWorkspace();
  await assert.rejects(adapter.nextAppIds(), /status 302/);
  assert.equal(calls, 3);
});

test("credential file drift after construction invalidates the adapter before HTTPS", async (t) => {
  const { credentialPath } = installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  let calls = 0;
  installFakeHttps(t, () => {
    calls += 1;
    return { body: CURRENT_USER };
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  const credentials = JSON.parse(fs.readFileSync(credentialPath, "utf8"));
  credentials.profiles.production.updated_at = secondTimestamp(-1);
  fs.writeFileSync(credentialPath, `${JSON.stringify(credentials, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(credentialPath, 0o600);
  await assert.rejects(adapter.getCurrentUser(), /changed after adapter creation/);
  assert.equal(calls, 0);
});

test("expired historical authority can open only the four authenticated continuity reads", async (t) => {
  installCanonicalCredentialHome(t);
  const authorities = authorityFixture();
  const realNow = Date.now;
  Date.now = () => realNow() + 24 * 60 * 60 * 1_000;
  t.after(() => { Date.now = realNow; });
  let calls = 0;
  installFakeHttps(t, (options) => {
    calls += 1;
    assert.equal(options.path, "/api/v1/auth/me");
    return { body: CURRENT_USER };
  });
  await assert.rejects(
    createPinnedPhalaProductionSdkAdapter(authorities),
    /fresh compatibility, staging, and target authority/,
  );
  const observer =
    await createPinnedPhalaHistoricalContinuityReadOnlySdkObserver(authorities);
  assert.equal(
    assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver(observer),
    observer,
  );
  assert.deepEqual(Object.keys(observer).sort(), [
    "getAppEnvEncryptPubKey",
    "getCurrentUser",
    "getCvmAttestation",
    "getCvmInfo",
  ]);
  for (const forbidden of [
    "nextAppIds",
    "provisionCvm",
    "commitCvmProvision",
    "updateCvmEnvs",
    "restartCvm",
  ]) {
    assert.equal(observer[forbidden], undefined);
  }
  const account = await observer.getCurrentUser();
  assert.equal(account.call_sequence, 1);
  assert.equal(calls, 1);
});
