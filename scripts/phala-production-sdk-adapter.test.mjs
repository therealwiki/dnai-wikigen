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
  assertAuthenticatedPhalaSdkObservation,
  assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  assertPinnedPhalaProductionSdkAdapter,
  authenticatedPhalaSdkObservationSha256,
  createPinnedPhalaProductionSdkAdapter,
  createPinnedPhalaHistoricalContinuityReadOnlySdkObserver,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  phalaAuthenticatedAccountSubjectSha256,
  phalaSdkJsonBodySemanticDigest,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  projectPinnedPhalaProductionSdkAdapterIdentity,
  projectPinnedProvisionWireBody,
  projectPinnedSdkCompatibilityIdentity,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
} from "./phala-production-sdk-adapter.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
  PHALA_READ_ONLY_COMPATIBILITY_CALLS,
  PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
  phalaCompatibilityReceiptDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;

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
    },
    sdk_identity: sdkIdentity,
    kms: {
      id: "kms-production-1",
      slug: "phala",
      url: "https://kms.phala.network/",
      version: "0.5.8",
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: "1".repeat(40),
      catalog_match_count: 1,
    },
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
      "authenticated_staging_wire_capture_not_production_cvm_commit_tdx_attestation_or_launch_authority",
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
    staging_account_isolated: true,
    provision_call_count: 7,
    commit_calls: [],
    cleanup_receipt_sha256: digest("f"),
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => {
      const pre = (index + 8).toString(16);
      const post = (index + 1).toString(16);
      const response = ((index + 7) % 15 + 1).toString(16);
      return {
        domain,
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
    staging_compose_hash_receipt_sha256:
      phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      }),
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
      id: compatibility.kms.id,
      slug: compatibility.kms.slug,
      url: compatibility.kms.url,
      version: compatibility.kms.version,
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: compatibility.kms.gateway_app_id,
      env_encrypt_signer_k256: `0x02${"9".repeat(64)}`,
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
  return { targetAuthority: target, compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging };
}

function installCanonicalCredentialHome(t, { fileMode = 0o600, directoryMode = 0o700 } = {}) {
  const originalHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(
    fs.realpathSync(originalHome ?? os.homedir()),
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
    if (options.path === "/api/v1/kms/phala/next_app_id?counts=7") {
      return { body: { app_ids: [reservation] } };
    }
    if (options.path === "/api/v1/cvms/provision") {
      provisionBody = JSON.parse(bodyBytes.toString("utf8"));
      return {
        body: {
          app_id: reservation.app_id,
          compose_hash: dstackCanonicalComposeHash(provisionBody.compose_file),
          instance_type: provisionBody.instance_type,
          node_id: 7,
          kms_id: provisionBody.kms_id,
          os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
          app_env_encrypt_pubkey: "3".repeat(64),
        },
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
  const reservationObservation = await adapter.nextAppIds();
  assert.equal(reservationObservation.call_sequence, 2);
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
    kmsId: authorities.targetAuthority.kms.id,
  });
  const provisionObservation = await adapter.provisionCvm({
    domain,
    request: provisionRequest,
  });
  assert.equal(provisionObservation.call_sequence, 3);
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
    "/api/v1/kms/phala/next_app_id?counts=7",
    "/api/v1/cvms/provision",
  ]);
});

test("adapter performs encrypted-env-only PATCH then force-false restart with exact semantics", async (t) => {
  installCanonicalCredentialHome(t);
  const cvmId = "cvm-main-0001";
  const encryptedEnvironment = "ab".repeat(96);
  const bodies = [];
  installFakeHttps(t, (options, bodyBytes) => {
    if (options.path === "/api/v1/auth/me") return { body: CURRENT_USER };
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
  const patchObservation = await adapter.updateCvmEnvs({
    domain: "main_runtime_cvm",
    cvmId,
    request: { encrypted_env: encryptedEnvironment },
  });
  assert.equal(patchObservation.call_sequence, 2);
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
  assert.equal(restartObservation.call_sequence, 3);
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
  await assert.rejects(adapter.nextAppIds(), /status 503/);
  const second = await adapter.nextAppIds();
  const third = await adapter.getCurrentUser();

  assert.deepEqual(
    [first.call_sequence, second.call_sequence, third.call_sequence],
    [1, 2, 3],
  );
  assert.equal(first.observed_at, second.observed_at);
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
    return { status: 302, body: { location: "https://example.invalid/" } };
  });
  const adapter = await createPinnedPhalaProductionSdkAdapter(authorities);
  await adapter.getCurrentUser();
  await assert.rejects(adapter.nextAppIds(), /status 302/);
  assert.equal(calls, 2);
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
