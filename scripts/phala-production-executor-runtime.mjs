import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DOMAINS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  assertFreshCvmDescriptorRuntimeMaterials,
  createFreshCvmDescriptorRuntimeAuthority,
  readFreshCvmDescriptorRuntimeMaterials,
} from "./cvm-descriptor-runtime-authority.mjs";
import {
  assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  readReverifyDescriptorSetAndCheckpointPhalaBootstrap,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assembleAuthorizedPrivateBootstrapEnvironment,
} from "./phala-authorized-private-bootstrap-environment.mjs";
import {
  bootstrapPublicEnvironmentAuthorityDigest,
  assertPostCommitProvisioningEnvironmentAuthority,
  postCommitProvisioningEnvironmentAuthorityDigest,
  privateEnvironmentAssemblyReceipt,
  privateEnvironmentEntries,
  projectPostCommitProvisioningEnvironmentAuthority,
  projectProvisioningEnvironmentAuthority,
  provisioningEnvironmentAuthorityDigest,
  readExactPhaseSecretInputFile,
} from "./phala-production-environment-authority.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertPairwiseDistinctSignedEnvironmentKeys,
  assertPreparedCvmObservation,
  buildExactCommitMetadata,
  buildExactProvisionRequest,
  buildExplicitAppCompose,
  createInitialPhalaExecutorState,
  createProductionFinalizedPhalaMutationGate,
  assertProvenanceVerifiedCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
  transitionPhalaExecutorState,
} from "./phala-production-executor-core.mjs";
import {
  collectProductionFinalizedReadiness,
  productionFinalizedReadinessSha256,
} from "./phala-production-finalized-readiness.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  verifyProductionCvmPostureObservation,
  productionCvmPostureVerificationReceiptSha256,
} from "./phala-production-posture-receipt.mjs";
import {
  acquirePhalaRecoveryJournalLock,
  classifyPhalaRecoveryRequirement,
  ensurePhalaRecoveryJournalDirectory,
  loadPhalaRecoveryJournal,
  persistPhalaRecoveryJournal,
  releasePhalaRecoveryJournalLock,
} from "./phala-production-recovery-journal.mjs";
import {
  assertPinnedDstackComposeHash,
  authenticatedPhalaSdkObservationSha256,
  createPinnedPhalaProductionSdkAdapter,
  encryptExactEnvironmentWithPinnedDstack,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  projectPinnedProvisionWireBody,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
  verifyImmediatePinnedLegacyEnvironmentKeyRefetch,
  verifyPinnedLegacyEnvironmentKey,
} from "./phala-production-sdk-adapter.mjs";
import {
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
} from "./phala-pinned-private-directory.mjs";

export const PHALA_PRODUCTION_EXECUTOR_RUNTIME_RESULT_SCHEMA =
  "dnai.phala-production-executor-runtime-result.v3";
export const PHALA_PRODUCTION_EXECUTOR_RUNTIME_RESULT_DOMAIN =
  "dnai-wikigen/phala-production-executor-runtime-result/v3\0";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const MAX_CATALOG_ITEMS = 10_000;
const RUNTIME_RESULTS = new WeakMap();

const EXECUTION_PATH_FIELDS = Object.freeze([
  "repositoryRoot",
  "releaseDirectory",
  "imageReleaseManifestPath",
  "imageReleaseSigstoreBundlePath",
  "imageReleaseSigstoreVerificationReceiptPath",
  "authorizationPath",
  "bootstrapAuthorityPath",
  "deploymentIntentPath",
  "reviewerAuthorityGenesisPath",
  "reviewerAuthorityGenesisAcceptancePath",
  "freshContractDeploymentReceiptPath",
  "compatibilityReceiptPath",
  "sdkWireTransformStagingReceiptPath",
  "productionTargetAuthorityPath",
  "phaseSecretInputPaths",
  "recoveryDirectory",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonical(value) {
  return JSON.stringify(sorted(value));
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonical(value), "utf8")
    .digest("hex")}`;
}

function internalSecond() {
  return new Date(Math.floor(Date.now() / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function exactAppId(value, label) {
  const normalized = typeof value === "string" ? value.replace(/^0x/, "").toLowerCase() : "";
  if (!APP_ID.test(normalized)) throw new Error(`${label} must be exactly 20 nonzero bytes`);
  return normalized;
}

function exactObservationResponse(observation, adapter, method, domain = null) {
  return readAuthenticatedPhalaSdkObservationResponse(observation, {
    adapter,
    method,
    domain,
  });
}

function exactSelectedKms(value, label) {
  if (!isRecord(value)) throw new Error(`${label} is not an object`);
  return {
    id: value.id,
    slug: value.slug,
    url: value.url,
    version: value.version,
    chain_id: value.chain_id,
    kms_contract_address: value.kms_contract_address,
    gateway_app_id: typeof value.gateway_app_id === "string"
      ? value.gateway_app_id.replace(/^0x/, "").toLowerCase()
      : value.gateway_app_id,
  };
}

function sameKms(left, right) {
  return canonical(exactSelectedKms(left, "observed KMS"))
    === canonical(exactSelectedKms(right, "reviewed KMS"));
}

/**
 * Pure semantic check for the five authenticated read-only catalog responses.
 * It accepts no client, clock, credential, or origin input.
 */
export function validateAuthenticatedPhalaReadinessCatalog({
  resources,
  osImages,
  kmsList,
  kmsInfo,
  targetAuthority,
} = {}) {
  const target = targetAuthority;
  if (!isRecord(resources) || !Array.isArray(resources.instance_types)
    || resources.instance_types.length < 1
    || resources.instance_types.length > MAX_CATALOG_ITEMS
    || !isRecord(resources.capacity)
    || !Array.isArray(resources.kms_nodes)
    || resources.kms_nodes.length < 1
    || resources.kms_nodes.length > MAX_CATALOG_ITEMS) {
    throw new Error("authenticated CVM resource graph is incomplete or unbounded");
  }
  const instanceByName = new Map(resources.instance_types.map((entry) => [entry?.name, entry]));
  const totalDisk = PHALA_EXECUTION_ORDER.reduce((sum, domain) => {
    const reviewed = target.resource_targets?.[domain];
    const observed = instanceByName.get(reviewed?.instance_type);
    if (!reviewed || !observed || observed.name !== reviewed.instance_type
      || !Number.isSafeInteger(observed.default_disk_size_gb)
      || reviewed.disk_size < observed.default_disk_size_gb
      || observed.requires_gpu !== false) {
      throw new Error(`${domain} is absent from the fresh authenticated resource catalog`);
    }
    return sum + reviewed.disk_size;
  }, 0);
  if (!Number.isSafeInteger(resources.capacity.max_instances)
    || resources.capacity.max_instances < PHALA_EXECUTION_ORDER.length
    || !Number.isSafeInteger(resources.capacity.max_disk)
    || resources.capacity.max_disk < totalDisk) {
    throw new Error("fresh authenticated Phala capacity is insufficient for exact seven launch");
  }
  const matchingResourceKms = resources.kms_nodes.filter((entry) => (
    String(entry?.id) === target.kms.id && sameKms(entry, target.kms)
  ));
  if (matchingResourceKms.length !== 1) {
    throw new Error("resource graph does not contain exactly one reviewed Phala KMS");
  }

  if (!isRecord(osImages) || !Array.isArray(osImages.items)
    || osImages.items.length > MAX_CATALOG_ITEMS) {
    throw new Error("authenticated OS image catalog is invalid or unbounded");
  }
  const osMatches = osImages.items.filter((entry) => (
    entry?.name === target.os_image.name
    && entry?.slug === target.os_image.slug
    && entry?.version === target.os_image.version
    && entry?.os_image_hash === target.os_image.os_image_hash
    && entry?.is_dev === false
    && entry?.requires_gpu === false
  ));
  if (osMatches.length !== 1) {
    throw new Error("OS catalog does not contain exactly one reviewed production image");
  }

  if (!isRecord(kmsList) || !Array.isArray(kmsList.items)
    || kmsList.items.length > MAX_CATALOG_ITEMS) {
    throw new Error("authenticated KMS catalog is invalid or unbounded");
  }
  const kmsMatches = kmsList.items.filter((entry) => (
    String(entry?.id) === target.kms.id && sameKms(entry, target.kms)
  ));
  if (kmsMatches.length !== 1 || !sameKms(kmsInfo, target.kms)) {
    throw new Error("fresh KMS list and detail do not equal the reviewed KMS authority");
  }
  const projected = {
    workspace_id: target.workspace.workspace_id,
    kms_id: target.kms.id,
    os_image_hash: target.os_image.os_image_hash,
    capacity: {
      max_instances: resources.capacity.max_instances,
      max_disk: resources.capacity.max_disk,
      reviewed_launch_disk: totalDisk,
    },
    resource_targets: Object.fromEntries(PHALA_EXECUTION_ORDER.map((domain) => [
      domain,
      {
        instance_type: target.resource_targets[domain].instance_type,
        disk_size: target.resource_targets[domain].disk_size,
      },
    ])),
  };
  return deepFreezeCanonicalPlainDataGraph(projected, {
    label: "authenticated Phala readiness catalog projection",
  });
}

function checkpointOptions(paths, checkpoint, expected = {}) {
  return {
    repositoryRoot: paths.repositoryRoot,
    releaseDirectory: paths.releaseDirectory,
    imageReleaseManifestPath: paths.imageReleaseManifestPath,
    imageReleaseSigstoreBundlePath: paths.imageReleaseSigstoreBundlePath,
    imageReleaseSigstoreVerificationReceiptPath:
      paths.imageReleaseSigstoreVerificationReceiptPath,
    authorizationPath: paths.authorizationPath,
    bootstrapAuthorityPath: paths.bootstrapAuthorityPath,
    deploymentIntentPath: paths.deploymentIntentPath,
    reviewerAuthorityGenesisPath: paths.reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath:
      paths.reviewerAuthorityGenesisAcceptancePath,
    freshContractDeploymentReceiptPath: paths.freshContractDeploymentReceiptPath,
    compatibilityReceiptPath: paths.compatibilityReceiptPath,
    sdkWireTransformStagingReceiptPath: paths.sdkWireTransformStagingReceiptPath,
    productionTargetAuthorityPath: paths.productionTargetAuthorityPath,
    checkpoint,
    ...expected,
  };
}

function exactSecretPathMap(value) {
  return exactRecord(value, CVM_LAUNCH_DOMAINS, "phase secret input path map");
}

function readPhaseSecret(paths, domain, receipt) {
  return readExactPhaseSecretInputFile(paths.phaseSecretInputPaths[domain], {
    expectedDomain: domain,
    expectedPhase: "bootstrap_provision",
    expectedBatchId: receipt.batch_id,
    expectedCvmLaunchIntentSha256: receipt.cvm_launch_intent_sha256,
  });
}

async function collectBoundFinalizedReadiness(paths, receipt, rpcAuthority) {
  const mainSecret = readPhaseSecret(paths, "main_runtime_cvm", receipt);
  const primaryRpcUrl = mainSecret.values.BASE_SEPOLIA_RPC_URL;
  const secondaryRpcUrl = mainSecret.values.BASE_SEPOLIA_RPC_URL_SECONDARY;
  if (typeof primaryRpcUrl !== "string" || typeof secondaryRpcUrl !== "string") {
    throw new Error("main runtime bootstrap secrets omit the two reviewed Base Sepolia RPCs");
  }
  const readiness = await collectProductionFinalizedReadiness({
    primaryRpcUrl,
    secondaryRpcUrl,
  });
  const endpoints = {
    primary_endpoint_sha256: readiness.primary_rpc.endpoint_sha256,
    primary_origin_sha256: readiness.primary_rpc.origin_sha256,
    secondary_endpoint_sha256: readiness.secondary_rpc.endpoint_sha256,
    secondary_origin_sha256: readiness.secondary_rpc.origin_sha256,
  };
  if (rpcAuthority.current === null) rpcAuthority.current = Object.freeze(endpoints);
  else if (canonical(rpcAuthority.current) !== canonical(endpoints)) {
    throw new Error("Base Sepolia RPC endpoint authority changed during the seven-CVM batch");
  }
  return readiness;
}

function exactInitialStateAuthority(state, initial) {
  for (const field of [
    "batch_id",
    "bootstrap_authorization_id",
    "bootstrap_authorization_receipt_sha256",
    "release_sha",
    "launch_intent_sha256",
    "target_authority_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
  ]) {
    if (state[field] !== initial[field]) {
      throw new Error(`recovery journal ${field} differs from the freshly reverified authority`);
    }
  }
  return state;
}

function buildPostureProjection(raw, cvmId) {
  return {
    id: String(raw.id ?? cvmId),
    app_id: raw.app_id,
    compose_hash: raw.compose_hash,
    kms_info: { id: raw.kms_info?.id },
    kms_type: raw.kms_type,
    os: {
      os_image_hash: raw.os?.os_image_hash,
      is_dev: raw.os?.is_dev,
    },
    resource: {
      instance_type: raw.resource?.instance_type,
      disk_in_gb: raw.resource?.disk_in_gb,
    },
    listed: raw.listed,
    public_logs: raw.public_logs,
    public_sysinfo: raw.public_sysinfo,
    public_tcbinfo: raw.public_tcbinfo,
  };
}

function markMutationAmbiguous({ state, domain, action, directory, lock }) {
  const ambiguous = transitionPhalaExecutorState(state, {
    type: "mutation_outcome_ambiguous",
    domain,
    action,
    reason_code: "authenticated_sdk_mutation_outcome_unresolved",
  });
  const journal = persistPhalaRecoveryJournal({ directory, state: ambiguous, lock });
  return { state: ambiguous, journal };
}

export async function executePhalaSevenCvmProductionLaunch(input = {}) {
  const paths = exactRecord(input, EXECUTION_PATH_FIELDS, "production executor runtime input");
  exactSecretPathMap(paths.phaseSecretInputPaths);

  const predictionAuthority = await readReverifyDescriptorSetAndCheckpointPhalaBootstrap(
    checkpointOptions(paths, "before_prediction"),
  );
  const receipt = predictionAuthority.receipt;
  const bootstrapPublicEnvironmentAuthority =
    predictionAuthority.bootstrap_public_environment_authority;
  if (!bootstrapPublicEnvironmentAuthority
    || bootstrapPublicEnvironmentAuthorityDigest(
      bootstrapPublicEnvironmentAuthority,
    ) !== receipt.bootstrap_public_environment_authority_sha256) {
    throw new Error(
      "full signed bootstrap public environment authority is unavailable before production mutation",
    );
  }
  const targetEvidence = predictionAuthority.target_authority_evidence;
  const target = targetEvidence.productionTargetAuthority;
  const compatibility = targetEvidence.compatibilityReceipt;
  const staging = targetEvidence.sdkWireTransformStagingReceipt;
  const expectedCheckpoint = {
    expectedBatchId: receipt.batch_id,
    expectedAuthorizationId: receipt.authorization_id,
    expectedTargetAuthoritySha256: targetEvidence.productionTargetAuthoritySha256,
    expectedStagingReceiptSha256: targetEvidence.sdkWireTransformStagingReceiptSha256,
  };

  const descriptorRuntimeAuthority = await createFreshCvmDescriptorRuntimeAuthority({
    releaseDirectory: paths.releaseDirectory,
    expectedReleaseSha: receipt.release_sha,
  });
  const descriptorMaterials = await readFreshCvmDescriptorRuntimeMaterials({
    authority: descriptorRuntimeAuthority,
    releaseDirectory: paths.releaseDirectory,
  });
  assertFreshCvmDescriptorRuntimeMaterials(descriptorMaterials, {
    authority: descriptorRuntimeAuthority,
  });
  const materialByDomain = new Map(descriptorMaterials.map((entry) => [entry.domain, entry]));
  const appComposeByDomain = new Map(PHALA_EXECUTION_ORDER.map((domain) => {
    const material = materialByDomain.get(domain);
    const appCompose = buildExplicitAppCompose({
      profile: target.app_compose_profiles[domain],
      dockerComposeFile: material.docker_compose_file,
      allowedEnvironmentKeys: material.allowed_environment_keys,
    });
    return [domain, appCompose];
  }));

  const adapter = await createPinnedPhalaProductionSdkAdapter({
    targetAuthority: target,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  const pinnedDstackIdentity = resolvePinnedPhalaPackageIdentity();
  ensurePhalaRecoveryJournalDirectory(paths.recoveryDirectory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory: paths.recoveryDirectory,
    batchId: receipt.batch_id,
    authorizationId: receipt.authorization_id,
    acquiredAt: internalSecond(),
  });
  const recoveryDirectoryIdentityAnchorSha256 =
    phalaPinnedPrivateDirectoryIdentityAnchorSha256(lock.pinnedDirectory);
  const initialState = createInitialPhalaExecutorState({
    batchId: receipt.batch_id,
    bootstrapAuthorizationId: receipt.authorization_id,
    bootstrapAuthorizationReceiptSha256:
      phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt),
    releaseSha: receipt.release_sha,
    launchIntentSha256: receipt.cvm_launch_intent_sha256,
    targetAuthoritySha256: targetEvidence.productionTargetAuthoritySha256,
    phalaRecoveryDirectoryIdentityAnchorSha256:
      recoveryDirectoryIdentityAnchorSha256,
  });

  let state;
  let journal;
  try {
    const existing = loadPhalaRecoveryJournal({
      directory: paths.recoveryDirectory,
      batchId: receipt.batch_id,
      directoryIdentityAnchorSha256: recoveryDirectoryIdentityAnchorSha256,
    });
    if (existing) {
      exactInitialStateAuthority(existing.state, initialState);
      const recovery = classifyPhalaRecoveryRequirement(existing);
      throw new Error(
        `existing production recovery journal requires explicit operator workflow:${recovery.action}`,
      );
    }
    state = initialState;
    journal = persistPhalaRecoveryJournal({
      directory: paths.recoveryDirectory,
      state,
      lock,
    });

    const account = await adapter.getCurrentUser();
    const resourcesObservation = await adapter.getCvmCreateResources();
    const osImagesObservation = await adapter.getOsImages();
    const kmsListObservation = await adapter.getKmsList();
    const kmsInfoObservation = await adapter.getKmsInfo();
    const catalogProjection = validateAuthenticatedPhalaReadinessCatalog({
      resources: exactObservationResponse(
        resourcesObservation, adapter, "getCvmCreateResources",
      ),
      osImages: exactObservationResponse(osImagesObservation, adapter, "getOsImages"),
      kmsList: exactObservationResponse(kmsListObservation, adapter, "getKmsList"),
      kmsInfo: exactObservationResponse(kmsInfoObservation, adapter, "getKmsInfo"),
      targetAuthority: target,
    });

    await readReverifyDescriptorSetAndCheckpointPhalaBootstrap(
      checkpointOptions(paths, "before_prediction", expectedCheckpoint),
    );
    const reservationObservation = await adapter.nextAppIds();
    const reservationResponse = exactObservationResponse(
      reservationObservation,
      adapter,
      "nextAppIds",
    );
    if (!isRecord(reservationResponse)
      || !Array.isArray(reservationResponse.app_ids)
      || reservationResponse.app_ids.length !== PHALA_EXECUTION_ORDER.length) {
      throw new Error("nextAppIds did not reserve exactly seven applications");
    }
    const reservations = PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: exactAppId(reservationResponse.app_ids[index]?.app_id, `${domain} app id`),
      nonce: reservationResponse.app_ids[index]?.nonce,
    }));
    state = transitionPhalaExecutorState(state, {
      type: "app_ids_observed",
      reservations,
    });
    journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });

    const rpcAuthority = { current: null };
    const mutationGates = [];
    const provisionObservations = [];
    const preparedByDomain = new Map();
    for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
      const domain = PHALA_EXECUTION_ORDER[index];
      const reservation = reservations[index];
      const checkpoint = await readReverifyDescriptorSetAndCheckpointPhalaBootstrap(
        checkpointOptions(paths, "before_each_provision", expectedCheckpoint),
      );
      const readiness = await collectBoundFinalizedReadiness(
        paths, receipt, rpcAuthority,
      );
      const gate = createProductionFinalizedPhalaMutationGate({
        authorizationRecheck: checkpoint.recheck,
        action: "provisionCvm",
        domain,
        finalizedReadiness: readiness,
      });
      mutationGates.push({ action: "provisionCvm", domain, gate });
      const appCompose = appComposeByDomain.get(domain);
      const request = buildExactProvisionRequest({
        domain,
        applicationName: target.app_compose_profiles[domain].name,
        resourceTarget: target.resource_targets[domain],
        appCompose,
        activeEnvironmentKeys: materialByDomain.get(domain).allowed_environment_keys,
        appId: reservation.app_id,
        nonce: reservation.nonce,
        kmsId: target.kms.id,
      });
      const requestSha256 = phalaAuthenticatedSdkRequestSemanticsSha256({
        httpMethod: "POST",
        pathAndQuery: "/api/v1/cvms/provision",
        body: projectPinnedProvisionWireBody(request),
      });
      state = transitionPhalaExecutorState(state, {
        type: "provision_attempt",
        domain,
        request_sha256: requestSha256,
        readiness_sha256: productionFinalizedReadinessSha256(readiness),
        attempted_at: internalSecond(),
      });
      journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });
      let observation;
      try {
        observation = await adapter.provisionCvm({ domain, request });
        if (observation.request_semantics_sha256 !== requestSha256) {
          throw new Error(`${domain} provision transport semantics drifted`);
        }
        const raw = exactObservationResponse(observation, adapter, "provisionCvm", domain);
        const prepared = assertPreparedCvmObservation({
          response: {
            app_id: raw.app_id,
            compose_hash: raw.compose_hash,
            kms_id: raw.kms_id ?? raw.kms_info?.id,
            instance_type: raw.instance_type,
            os_image_hash: raw.os_image_hash,
            node_id: raw.node_id,
            device_id: raw.device_id,
            app_env_encrypt_pubkey: raw.app_env_encrypt_pubkey,
          },
          appId: reservation.app_id,
          expectedComposeHash: materialByDomain.get(domain).app_compose_hash,
          expectedKmsId: target.kms.id,
          expectedInstanceType: target.resource_targets[domain].instance_type,
          expectedOsImageHash: target.os_image.os_image_hash,
        });
        await assertPinnedDstackComposeHash({
          identity: pinnedDstackIdentity,
          appCompose,
          observedComposeHash: prepared.compose_hash,
        });
        preparedByDomain.set(domain, prepared);
      } catch (error) {
        ({ state, journal } = markMutationAmbiguous({
          state, domain, action: "provisionCvm", directory: paths.recoveryDirectory, lock,
        }));
        throw new Error(`${domain} provision outcome requires manual reconciliation`, {
          cause: error,
        });
      }
      provisionObservations.push(observation);
      state = transitionPhalaExecutorState(state, {
        type: "provision_observed",
        domain,
        observed_at: observation.observed_at,
        observation_sha256: authenticatedPhalaSdkObservationSha256(observation, {
          adapter,
          method: "provisionCvm",
          domain,
        }),
      });
      journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });
    }

    const preparationProjection = PHALA_EXECUTION_ORDER.map((domain) => ({
      domain,
      ...preparedByDomain.get(domain),
      observation_sha256: state.preparations.find((entry) => entry.domain === domain)
        .observation_sha256,
    }));
    const validationSha256 = domainDigest(
      "dnai-wikigen/phala-seven-cvm-preparations-validation/v1\0",
      { catalog: catalogProjection, preparations: preparationProjection },
    );
    state = transitionPhalaExecutorState(state, {
      type: "preparations_validated",
      validation_sha256: validationSha256,
    });
    journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });

    const provisioningAuthority = projectProvisioningEnvironmentAuthority({
      batchId: receipt.batch_id,
      targetAuthoritySha256: targetEvidence.productionTargetAuthoritySha256,
      cvmLaunchIntentSha256: receipt.cvm_launch_intent_sha256,
      bootstrapAuthoritySha256: bootstrapPublicEnvironmentAuthorityDigest(
        bootstrapPublicEnvironmentAuthority,
      ),
      preparedAt: internalSecond(),
      prepareObservations: CVM_LAUNCH_DOMAINS.map((domain) => ({
        domain,
        app_id: preparedByDomain.get(domain).app_id,
        compose_hash: preparedByDomain.get(domain).compose_hash,
        os_image_hash: preparedByDomain.get(domain).os_image_hash,
        prepare_response_sha256: state.preparations.find((entry) => entry.domain === domain)
          .observation_sha256,
      })),
    });

    const firstKeyObservations = [];
    const firstKeyBindings = [];
    for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
      const domain = PHALA_EXECUTION_ORDER[index];
      const appId = reservations[index].app_id;
      const observation = await adapter.getAppEnvEncryptPubKey({ domain, appId });
      const response = exactObservationResponse(
        observation, adapter, "getAppEnvEncryptPubKey", domain,
      );
      const binding = await verifyPinnedLegacyEnvironmentKey({
        identity: pinnedDstackIdentity,
        appId,
        response,
        pinnedSigner: target.kms.env_encrypt_signer_k256,
      });
      firstKeyObservations.push(observation);
      firstKeyBindings.push(binding);
      const bindingSha256 = domainDigest(
        "dnai-wikigen/phala-signed-environment-key-binding/v1\0",
        binding,
      );
      state = transitionPhalaExecutorState(state, {
        type: "signed_key_observed",
        domain,
        binding_sha256: bindingSha256,
        public_key_sha256: binding.public_key_sha256,
      });
      journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });
    }
    assertPairwiseDistinctSignedEnvironmentKeys(firstKeyBindings);

    const refetchKeyObservations = [];
    const commitObservations = [];
    const privateEnvironmentReceipts = [];
    for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
      const domain = PHALA_EXECUTION_ORDER[index];
      const reservation = reservations[index];
      const checkpoint = await readReverifyDescriptorSetAndCheckpointPhalaBootstrap(
        checkpointOptions(paths, "before_each_commit", expectedCheckpoint),
      );
      const readiness = await collectBoundFinalizedReadiness(
        paths, receipt, rpcAuthority,
      );
      const gate = createProductionFinalizedPhalaMutationGate({
        authorizationRecheck: checkpoint.recheck,
        action: "commitCvmProvision",
        domain,
        finalizedReadiness: readiness,
      });
      mutationGates.push({ action: "commitCvmProvision", domain, gate });
      const refetchObservation = await adapter.getAppEnvEncryptPubKey({
        domain,
        appId: reservation.app_id,
      });
      const firstResponse = exactObservationResponse(
        firstKeyObservations[index], adapter, "getAppEnvEncryptPubKey", domain,
      );
      const secondResponse = exactObservationResponse(
        refetchObservation, adapter, "getAppEnvEncryptPubKey", domain,
      );
      const binding = await verifyImmediatePinnedLegacyEnvironmentKeyRefetch({
        identity: pinnedDstackIdentity,
        appId: reservation.app_id,
        firstResponse,
        secondResponse,
        pinnedSigner: target.kms.env_encrypt_signer_k256,
      });
      refetchKeyObservations.push(refetchObservation);

      const secretInput = readPhaseSecret(paths, domain, receipt);
      const assemblyNowMs = Date.now();
      const environmentAssembly = assembleAuthorizedPrivateBootstrapEnvironment({
        authorizationReceipt: checkpoint.receipt,
        checkpoint: "before_each_commit",
        nowMs: assemblyNowMs,
        expectedAuthorizationId: receipt.authorization_id,
        expectedTargetAuthoritySha256: targetEvidence.productionTargetAuthoritySha256,
        expectedStagingReceiptSha256:
          targetEvidence.sdkWireTransformStagingReceiptSha256,
        environmentAssembly: {
          domain,
          now: new Date(Math.floor(assemblyNowMs / 1_000) * 1_000)
            .toISOString().replace(".000Z", "Z"),
          bootstrapAuthority: bootstrapPublicEnvironmentAuthority,
          provisioningAuthority,
          secretInput,
        },
      });
      const environmentReceipt = privateEnvironmentAssemblyReceipt(environmentAssembly);
      privateEnvironmentReceipts.push(environmentReceipt);
      const entriesObject = privateEnvironmentEntries(environmentAssembly);
      const entries = Object.keys(entriesObject).sort().map((key) => ({
        key,
        value: entriesObject[key],
      }));
      let encryptedEnvironment = await encryptExactEnvironmentWithPinnedDstack({
        identity: pinnedDstackIdentity,
        entries,
        publicKey: binding.public_key,
      });
      const metadata = buildExactCommitMetadata({
        appId: reservation.app_id,
        composeHash: preparedByDomain.get(domain).compose_hash,
        kmsId: target.kms.id,
        environmentKeys: entries.map(({ key }) => key),
      });
      const request = { ...metadata, encrypted_env: encryptedEnvironment };
      const requestSha256 = phalaAuthenticatedSdkRequestSemanticsSha256({
        httpMethod: "POST",
        pathAndQuery: "/api/v1/cvms",
        body: request,
      });
      state = transitionPhalaExecutorState(state, {
        type: "commit_attempt",
        domain,
        request_sha256: requestSha256,
        readiness_sha256: productionFinalizedReadinessSha256(readiness),
        attempted_at: internalSecond(),
      });
      journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });
      let observation;
      let cvmId;
      try {
        observation = await adapter.commitCvmProvision({ domain, request });
        encryptedEnvironment = null;
        if (observation.request_semantics_sha256 !== requestSha256) {
          throw new Error(`${domain} commit transport semantics drifted`);
        }
        const raw = exactObservationResponse(
          observation, adapter, "commitCvmProvision", domain,
        );
        if (exactAppId(raw.app_id, `${domain} committed app id`) !== reservation.app_id
          || (typeof raw.id !== "string" && !Number.isSafeInteger(raw.id))) {
          throw new Error(`${domain} commit response differs from predicted application`);
        }
        cvmId = String(raw.id);
      } catch (error) {
        encryptedEnvironment = null;
        ({ state, journal } = markMutationAmbiguous({
          state, domain, action: "commitCvmProvision", directory: paths.recoveryDirectory, lock,
        }));
        throw new Error(`${domain} commit outcome requires manual reconciliation`, {
          cause: error,
        });
      }
      commitObservations.push(observation);
      state = transitionPhalaExecutorState(state, {
        type: "commit_observed",
        domain,
        cvm_id: cvmId,
        observed_at: observation.observed_at,
        observation_sha256: authenticatedPhalaSdkObservationSha256(observation, {
          adapter,
          method: "commitCvmProvision",
          domain,
        }),
      });
      journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });
    }

    const postureReceipts = [];
    const cvmInfoObservations = [];
    for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
      const domain = PHALA_EXECUTION_ORDER[index];
      const committed = state.committed_prefix[index];
      const observation = await adapter.getCvmInfo({ domain, cvmId: committed.cvm_id });
      const raw = exactObservationResponse(observation, adapter, "getCvmInfo", domain);
      const posture = verifyProductionCvmPostureObservation({
        domain,
        cvmId: committed.cvm_id,
        cvmInfo: buildPostureProjection(raw, committed.cvm_id),
        expected: {
          appId: reservations[index].app_id,
          composeHash: preparedByDomain.get(domain).compose_hash,
          kmsId: target.kms.id,
          instanceType: target.resource_targets[domain].instance_type,
          diskSize: target.resource_targets[domain].disk_size,
        },
      });
      cvmInfoObservations.push(observation);
      postureReceipts.push(posture);
    }
    state = transitionPhalaExecutorState(state, {
      type: "posture_validated",
      receipts: PHALA_EXECUTION_ORDER.map((domain, index) => ({
        domain,
        receipt_sha256:
          productionCvmPostureVerificationReceiptSha256(postureReceipts[index]),
      })),
    });
    journal = persistPhalaRecoveryJournal({ directory: paths.recoveryDirectory, state, lock });

    const attestationObservations = [];
    for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
      const domain = PHALA_EXECUTION_ORDER[index];
      const cvmId = state.committed_prefix[index].cvm_id;
      const observation = await adapter.getCvmAttestation({ domain, cvmId });
      const response = exactObservationResponse(
        observation, adapter, "getCvmAttestation", domain,
      );
      if (!isRecord(response)) {
        throw new Error(`${domain} authenticated getCvmAttestation response is invalid`);
      }
      attestationObservations.push(observation);
    }

    const {
      persistProductionExecutionReplay,
      productionExecutionReplayReceiptSha256,
    } = await import(
      "./phala-production-execution-replay.mjs"
    );
    const provisionGates = mutationGates
      .filter(({ action }) => action === "provisionCvm")
      .map(({ gate }) => gate);
    const commitGates = mutationGates
      .filter(({ action }) => action === "commitCvmProvision")
      .map(({ gate }) => gate);
    const replayObservations = {
      globals: {
        getCurrentUser: account,
        getCvmCreateResources: resourcesObservation,
        getOsImages: osImagesObservation,
        getKmsList: kmsListObservation,
        getKmsInfo: kmsInfoObservation,
        nextAppIds: reservationObservation,
      },
      provisions: provisionObservations,
      first_environment_keys: firstKeyObservations,
      immediate_environment_key_refetches: refetchKeyObservations,
      commits: commitObservations,
      cvm_infos: cvmInfoObservations,
      cvm_attestations: attestationObservations,
    };
    const executionReplay = persistProductionExecutionReplay({
      directory: paths.recoveryDirectory,
      state,
      journal,
      lock,
      adapter,
      provisionGates,
      commitGates,
      observations: replayObservations,
    });
    const { registerProvenanceVerifiedCompletedPhalaExecutorState } = await import(
      "./phala-production-executor-core.mjs"
    );
    state = await registerProvenanceVerifiedCompletedPhalaExecutorState({
      state,
      replayReceipt: executionReplay,
      directory: paths.recoveryDirectory,
      journal,
      lock,
      adapter,
      provisionGates,
      commitGates,
      observations: replayObservations,
    });
    const postcommitProvisioningAuthority =
      projectPostCommitProvisioningEnvironmentAuthority({
        executorFinalState: state,
        provisioningAuthority,
        observedAt: state.committed_prefix.at(-1).observed_at,
      });

    const result = deepFreezeCanonicalPlainDataGraph({
      schema: PHALA_PRODUCTION_EXECUTOR_RUNTIME_RESULT_SCHEMA,
      status: "exact_seven_cvm_nonlive_bootstrap_committed_and_provenance_replayed",
      truth_status:
        "seven_authenticated_phala_commits_posture_and_attestation_observations_not_live_traffic_or_late_secret_activation",
      release_sha: receipt.release_sha,
      batch_id: receipt.batch_id,
      bootstrap_authorization_id: receipt.authorization_id,
      executor_final_state_sha256: phalaExecutorStateDigest(state),
      phala_recovery_directory_identity_anchor_sha256:
        recoveryDirectoryIdentityAnchorSha256,
      provisioning_environment_authority: provisioningAuthority,
      provisioning_environment_authority_sha256:
        provisioningEnvironmentAuthorityDigest(provisioningAuthority),
      postcommit_provisioning_environment_authority:
        postcommitProvisioningAuthority,
      postcommit_provisioning_environment_authority_sha256:
        postCommitProvisioningEnvironmentAuthorityDigest(
          postcommitProvisioningAuthority,
        ),
      rpc_endpoint_authority: rpcAuthority.current,
      private_environment_receipts: privateEnvironmentReceipts,
      posture_receipts: postureReceipts,
      state,
      journal_state_sha256: journal.state_sha256,
      execution_replay_sha256:
        productionExecutionReplayReceiptSha256(executionReplay),
      live_traffic_authorized: false,
      late_secret_activation_authorized: false,
      raw_secret_egress: false,
      ciphertext_persisted: false,
    }, { label: "production executor runtime result" });
    const dependencies = Object.freeze({
      signed_a_receipt: receipt,
      bootstrap_public_environment_authority:
        bootstrapPublicEnvironmentAuthority,
      cvm_descriptor_runtime_authority: descriptorRuntimeAuthority,
      cvm_descriptor_runtime_materials: descriptorMaterials,
      provisioning_environment_authority: provisioningAuthority,
      postcommit_provisioning_environment_authority:
        postcommitProvisioningAuthority,
      executor_final_state: state,
      production_posture_receipts: result.posture_receipts,
      authenticated_cvm_info_observations:
        Object.freeze([...cvmInfoObservations]),
      authenticated_cvm_attestation_observations:
        Object.freeze([...attestationObservations]),
      pinned_phala_sdk_adapter: adapter,
      production_target_authority_evidence: targetEvidence,
    });
    RUNTIME_RESULTS.set(result, Object.freeze({
      executor_final_state_sha256: phalaExecutorStateDigest(state),
      dependencies,
    }));
    return result;
  } finally {
    releasePhalaRecoveryJournalLock(lock);
  }
}

export function assertCompletedPhalaProductionExecutorRuntimeResult(value) {
  const provenance = value && RUNTIME_RESULTS.get(value);
  const expected = provenance?.executor_final_state_sha256;
  const dependencies = provenance?.dependencies;
  if (!expected || !dependencies
    || value.schema !== PHALA_PRODUCTION_EXECUTOR_RUNTIME_RESULT_SCHEMA
    || value.executor_final_state_sha256 !== expected
    || value.state !== dependencies.executor_final_state
    || value.provisioning_environment_authority
      !== dependencies.provisioning_environment_authority
    || value.postcommit_provisioning_environment_authority
      !== dependencies.postcommit_provisioning_environment_authority
    || value.posture_receipts !== dependencies.production_posture_receipts
    || value.phala_recovery_directory_identity_anchor_sha256
      !== value.state.phala_recovery_directory_identity_anchor_sha256
    || provisioningEnvironmentAuthorityDigest(
      value.provisioning_environment_authority,
    ) !== value.provisioning_environment_authority_sha256
    || postCommitProvisioningEnvironmentAuthorityDigest(
      assertPostCommitProvisioningEnvironmentAuthority(
        value.postcommit_provisioning_environment_authority,
      ),
    ) !== value.postcommit_provisioning_environment_authority_sha256
    || value.live_traffic_authorized !== false
    || value.late_secret_activation_authorized !== false
    || value.raw_secret_egress !== false
    || value.ciphertext_persisted !== false) {
    throw new Error("a completed locally replayed production executor result is required");
  }
  return value;
}

/**
 * Returns the exact same-process authority and authenticated-observation
 * dependencies retained behind a completed runtime result. No serialized or
 * cloned runtime result can reach this view because the public result itself
 * must still carry the private RUNTIME_RESULTS identity brand.
 */
export function readPhalaProductionExecutorRuntimeDependencies(value) {
  const result = assertCompletedPhalaProductionExecutorRuntimeResult(value);
  const dependencies = RUNTIME_RESULTS.get(result).dependencies;
  const receipt = assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
    dependencies.signed_a_receipt,
  );
  const bootstrapAuthority =
    dependencies.bootstrap_public_environment_authority;
  const state = assertProvenanceVerifiedCompletedPhalaExecutorState(
    dependencies.executor_final_state,
  );
  assertFreshCvmDescriptorRuntimeMaterials(
    dependencies.cvm_descriptor_runtime_materials,
    { authority: dependencies.cvm_descriptor_runtime_authority },
  );
  assertPostCommitProvisioningEnvironmentAuthority(
    dependencies.postcommit_provisioning_environment_authority,
  );
  if (receipt.authorization_id !== result.bootstrap_authorization_id
    || receipt.batch_id !== result.batch_id
    || receipt.release_sha !== result.release_sha
    || receipt.cvm_launch_intent_sha256 !== state.launch_intent_sha256
    || receipt.production_target_authority_sha256
      !== state.target_authority_sha256
    || phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt)
      !== state.bootstrap_authorization_receipt_sha256
    || bootstrapPublicEnvironmentAuthorityDigest(bootstrapAuthority)
      !== receipt.bootstrap_public_environment_authority_sha256
    || bootstrapAuthority.release_sha !== result.release_sha
    || bootstrapAuthority.deployment_intent_sha256
      !== receipt.deployment_intent_sha256
    || bootstrapAuthority.cvm_launch_intent_sha256
      !== state.launch_intent_sha256
    || bootstrapAuthority.production_target_authority_sha256
      !== state.target_authority_sha256
    || dependencies.cvm_descriptor_runtime_authority.release_sha
      !== result.release_sha
    || dependencies.production_target_authority_evidence
      .productionTargetAuthoritySha256 !== state.target_authority_sha256
    || dependencies.authenticated_cvm_info_observations.length
      !== PHALA_EXECUTION_ORDER.length
    || dependencies.authenticated_cvm_attestation_observations.length
      !== PHALA_EXECUTION_ORDER.length
    || dependencies.production_posture_receipts.length
      !== PHALA_EXECUTION_ORDER.length) {
    throw new Error("production executor runtime dependency lineage drifted");
  }
  for (const [index, domain] of PHALA_EXECUTION_ORDER.entries()) {
    const posture = assertVerifiedProductionCvmPostureReceipt(
      dependencies.production_posture_receipts[index],
    );
    if (posture.domain !== domain) {
      throw new Error("production executor posture dependency order drifted");
    }
    authenticatedPhalaSdkObservationSha256(
      dependencies.authenticated_cvm_info_observations[index],
      {
        adapter: dependencies.pinned_phala_sdk_adapter,
        method: "getCvmInfo",
        domain,
      },
    );
    authenticatedPhalaSdkObservationSha256(
      dependencies.authenticated_cvm_attestation_observations[index],
      {
        adapter: dependencies.pinned_phala_sdk_adapter,
        method: "getCvmAttestation",
        domain,
      },
    );
  }
  return dependencies;
}

export function phalaProductionExecutorRuntimeResultSha256(value) {
  const result = assertCompletedPhalaProductionExecutorRuntimeResult(value);
  assertCanonicalPlainDataGraph(result, { label: "production executor runtime result" });
  return domainDigest(PHALA_PRODUCTION_EXECUTOR_RUNTIME_RESULT_DOMAIN, result);
}
