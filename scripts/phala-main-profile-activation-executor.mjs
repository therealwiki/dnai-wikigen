import {
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
  CVM_MAIN_DISABLED_PROFILE_POLICY,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
} from "./cvm-launch-intent-core.mjs";
import {
  assemblePrivateAccountGenesisEnvironment,
  assemblePrivateAccountGenesisRetirementEnvironment,
  assemblePrivateLiveDealEnvironment,
  privatePostMeasurementEnvironmentEntries,
} from "./phala-production-environment-authority.mjs";
import {
  createPrivatePostMeasurementEncryptedUpdate,
  destroyPrivatePostMeasurementEncryptedUpdate,
  readPrivatePostMeasurementEncryptedUpdateCiphertext,
  registerPrivatePostMeasurementEncryptedUpdateObservation,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  authenticatedPhalaSdkObservationSha256,
  createPinnedPhalaProductionSdkAdapter,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  readAuthenticatedPhalaSdkObservationResponse,
  resolvePinnedPhalaPackageIdentity,
  verifyImmediatePinnedLegacyEnvironmentKeyRefetch,
} from "./phala-production-sdk-adapter.mjs";
import {
  assertFreshProductionFinalizedReadiness,
  collectProductionFinalizedReadiness,
  productionFinalizedReadinessSha256,
} from "./phala-production-finalized-readiness.mjs";
import {
  assertLocallyCreatedPhalaLiveDealProfileActivationGate,
  buildPhalaAccountGenesisCompletion,
  normalizePhalaAccountGenesisActivationAuthority,
  phalaAccountGenesisActivationAuthoritySha256,
  phalaLiveDealProfileActivationGateSha256,
} from "./phala-main-profile-activation-core.mjs";

export const PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_SCHEMA =
  "dnai.phala-account-genesis-profile-execution-result.v1";
export const PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_STATUS =
  "account_genesis_completed_and_profiles_retired_non_live";
export const PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_TRUTH =
  "signed_authority_exact_profile_mutations_and_bounded_one_shot_evidence_observed_not_live_traffic";

export const PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_SCHEMA =
  "dnai.phala-live-deal-profile-execution-result.v1";
export const PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_STATUS =
  "deal_profile_patch_restart_observed_pending_independent_service_presence";
export const PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_TRUTH =
  "signed_live_gate_exact_complete_profile_patch_restart_and_authenticated_phala_quote_presence_observed_not_independent_tdx_or_deal_service_presence";

const PRODUCTION_MUTATORS = new WeakMap();
const PROFILE = Object.freeze({
  account_genesis_start: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
  account_genesis_retire: CVM_MAIN_DISABLED_PROFILE_POLICY,
  deal_runtime_start: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
});

function fail(message) {
  throw new Error(message);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function profileMatches(value, expected) {
  return JSON.stringify(value) === JSON.stringify(expected);
}

function assertMutationObservation(value, {
  from,
  name,
  to,
} = {}) {
  const parsed = exactRecord(value, [
    "attestation_quote_present",
    "automatic_retry_authorized",
    "from_profile",
    "live_traffic_authorized",
    "mutation_name",
    "post_restart_target_matched",
    "to_profile",
  ], `${name} profile mutation observation`);
  if (parsed.mutation_name !== name
    || !profileMatches(parsed.from_profile, from)
    || !profileMatches(parsed.to_profile, to)
    || parsed.attestation_quote_present !== true
    || parsed.post_restart_target_matched !== true
    || parsed.automatic_retry_authorized !== false
    || parsed.live_traffic_authorized !== false) {
    fail(`${name} profile mutation was not observed under the exact boundary`);
  }
  return Object.freeze({
    mutation_name: name,
    from_profile: from,
    to_profile: to,
    post_restart_target_matched: true,
    attestation_quote_present: true,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

function internalSecond() {
  return new Date(Math.floor(Date.now() / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function observationResponse(observation, adapter, method) {
  return readAuthenticatedPhalaSdkObservationResponse(observation, {
    adapter,
    method,
    domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
  });
}

function observationDigest(observation, adapter, method) {
  return authenticatedPhalaSdkObservationSha256(observation, {
    adapter,
    method,
    domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
  });
}

function assertPatchAccepted(value) {
  if (!isRecord(value)
    || value.status !== "in_progress"
    || value.allowed_envs_changed !== false
    || typeof value.correlation_id !== "string"
    || value.correlation_id.length < 1
    || value.correlation_id.length > 512) {
    fail("main profile encrypted-only PATCH was not accepted");
  }
}

function assertRestartAccepted(value, cvmId) {
  if (!isRecord(value) || String(value.id) !== cvmId) {
    fail("main profile restart did not identify the exact main CVM");
  }
}

function hasQuotedCertificate(value) {
  return Array.isArray(value?.app_certificates)
    && value.app_certificates.some((entry) => (
      typeof entry?.quote === "string" && entry.quote.length > 0
    ));
}

function assertPostRestartTarget(info, attestation, target) {
  if (!isRecord(info)
    || String(info.id) !== target.cvm_id
    || String(info.app_id).replace(/^0x/, "").toLowerCase() !== target.app_id
    || info.compose_hash !== target.compose_hash
    || info.os?.os_image_hash !== target.os_image_hash
    || !isRecord(attestation)
    || attestation.is_online !== true
    || attestation.error !== null
    || !isRecord(attestation.tcb_info)
    || !hasQuotedCertificate(attestation)) {
    fail("main profile post-restart Phala observations differ from the exact target");
  }
}

function assemblyForMutation(state, name) {
  if (name === "account_genesis_start") {
    return assemblePrivateAccountGenesisEnvironment({
      accountGenesisAuthoritySha256: state.accountGenesisAuthoritySha256,
      baseAssembly: state.baseAssembly,
      secretInput: state.accountGenesisSecretInput,
    });
  }
  if (name === "account_genesis_retire") {
    return assemblePrivateAccountGenesisRetirementEnvironment({
      accountGenesisAuthoritySha256: state.accountGenesisAuthoritySha256,
      baseAssembly: state.baseAssembly,
    });
  }
  if (name === "deal_runtime_start") {
    return assemblePrivateLiveDealEnvironment({
      accountGenesisAuthoritySha256: state.accountGenesisAuthoritySha256,
      baseAssembly: state.baseAssembly,
    });
  }
  fail("main profile mutation name is unsupported");
}

/**
 * Construct the mutation-capable adapter used by the profile drivers. The
 * caller cannot choose a profile string: each invocation is matched against a
 * code-owned transition, and every mutation is journaled through the supplied
 * create-only callbacks before the external SDK call.
 */
export async function createProductionPhalaMainProfileMutator({
  accountGenesisAuthoritySha256,
  accountGenesisSecretInput,
  baseAssembly,
  compatibilityReceipt,
  recordMutationAttempt,
  recordMutationObservation,
  sdkWireTransformStagingReceipt,
  target,
  targetAuthority,
} = {}) {
  if (typeof recordMutationAttempt !== "function"
    || typeof recordMutationObservation !== "function") {
    fail("production main profile mutation requires durable attempt and observation journals");
  }
  const adapter = await createPinnedPhalaProductionSdkAdapter({
    targetAuthority,
    compatibilityReceipt,
    sdkWireTransformStagingReceipt,
  });
  const pinnedDstackIdentity = resolvePinnedPhalaPackageIdentity();
  const publicMutator = Object.freeze({
    async mutate({ authoritySha256, from, name, to } = {}) {
      const expectedTo = PROFILE[name];
      if (!expectedTo || !profileMatches(to, expectedTo)
        || !profileMatches(from, {
          account_genesis_start: CVM_MAIN_DISABLED_PROFILE_POLICY,
          account_genesis_retire: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
          deal_runtime_start: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
        }[name])
        || !/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(authoritySha256)) {
        fail("production main profile mutation differs from code-owned transition");
      }
      const assembly = assemblyForMutation(
        PRODUCTION_MUTATORS.get(publicMutator),
        name,
      );
      const entries = privatePostMeasurementEnvironmentEntries(assembly);
      const primaryRpcUrl = entries.BASE_SEPOLIA_RPC_URL;
      const secondaryRpcUrl = entries.BASE_SEPOLIA_RPC_URL_SECONDARY;
      if (typeof primaryRpcUrl !== "string"
        || typeof secondaryRpcUrl !== "string") {
        fail("main profile mutation lacks both reviewed Base Sepolia RPCs");
      }
      const currentUserObservation = await adapter.getCurrentUser();
      observationResponse(currentUserObservation, adapter, "getCurrentUser");
      await recordMutationObservation(Object.freeze({
        mutation_name: name,
        sdk_action: "getCurrentUser",
        observation_sha256: observationDigest(
          currentUserObservation,
          adapter,
          "getCurrentUser",
        ),
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      }));
      const firstEnvironmentKey = await adapter.getAppEnvEncryptPubKey({
        domain: "main_runtime_cvm",
        appId: target.app_id,
      });
      const refetchedEnvironmentKey = await adapter.getAppEnvEncryptPubKey({
        domain: "main_runtime_cvm",
        appId: target.app_id,
      });
      const signedKey = await verifyImmediatePinnedLegacyEnvironmentKeyRefetch({
        identity: pinnedDstackIdentity,
        appId: target.app_id,
        firstResponse: observationResponse(
          firstEnvironmentKey,
          adapter,
          "getAppEnvEncryptPubKey",
        ),
        secondResponse: observationResponse(
          refetchedEnvironmentKey,
          adapter,
          "getAppEnvEncryptPubKey",
        ),
        pinnedSigner: targetAuthority.kms.env_encrypt_signer_k256,
      });
      const patchReadiness = await collectProductionFinalizedReadiness({
        primaryRpcUrl,
        secondaryRpcUrl,
      });
      const encryptedUpdate =
        await createPrivatePostMeasurementEncryptedUpdate({
          assembly,
          pinnedDstackIdentity,
          publicKey: signedKey.public_key,
          activationPlanSha256: authoritySha256,
          targetCvmId: target.cvm_id,
        });
      let encryptedEnvironment =
        readPrivatePostMeasurementEncryptedUpdateCiphertext(encryptedUpdate);
      let patchInvocation = {
        domain: "main_runtime_cvm",
        cvmId: target.cvm_id,
        request: { encrypted_env: encryptedEnvironment },
      };
      const patchRequestSemanticsSha256 =
        phalaAuthenticatedSdkRequestSemanticsSha256({
          httpMethod: "PATCH",
          pathAndQuery: `/api/v1/cvms/${target.cvm_id}/envs`,
          body: { encrypted_env: encryptedEnvironment },
        });
      await recordMutationAttempt(Object.freeze({
        mutation_name: name,
        sdk_action: "updateCvmEnvs",
        request_semantics_sha256: patchRequestSemanticsSha256,
        finalized_readiness_sha256:
          productionFinalizedReadinessSha256(patchReadiness),
        finalized_block_number:
          patchReadiness.common_finalized_block_number,
        finalized_block_hash: patchReadiness.common_finalized_block_hash,
        recorded_at: internalSecond(),
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      }));
      let patchObservation;
      try {
        assertFreshProductionFinalizedReadiness(patchReadiness);
        patchObservation = await adapter.updateCvmEnvs(patchInvocation);
        registerPrivatePostMeasurementEncryptedUpdateObservation({
          encryptedUpdate,
          adapter,
          patchObservation,
        });
      } catch (error) {
        destroyPrivatePostMeasurementEncryptedUpdate(encryptedUpdate);
        throw error;
      } finally {
        patchInvocation.request.encrypted_env = null;
        patchInvocation = null;
        encryptedEnvironment = null;
      }
      assertPatchAccepted(
        observationResponse(patchObservation, adapter, "updateCvmEnvs"),
      );
      await recordMutationObservation(Object.freeze({
        mutation_name: name,
        sdk_action: "updateCvmEnvs",
        observation_sha256: authenticatedPhalaSdkObservationSha256(
          patchObservation,
          {
            adapter,
            method: "updateCvmEnvs",
            domain: "main_runtime_cvm",
          },
        ),
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      }));

      const restartRequestSemanticsSha256 =
        phalaAuthenticatedSdkRequestSemanticsSha256({
          httpMethod: "POST",
          pathAndQuery: `/api/v1/cvms/${target.cvm_id}/restart`,
          body: { force: false },
        });
      const restartReadiness = await collectProductionFinalizedReadiness({
        primaryRpcUrl,
        secondaryRpcUrl,
      });
      await recordMutationAttempt(Object.freeze({
        mutation_name: name,
        sdk_action: "restartCvm",
        request_semantics_sha256: restartRequestSemanticsSha256,
        finalized_readiness_sha256:
          productionFinalizedReadinessSha256(restartReadiness),
        finalized_block_number:
          restartReadiness.common_finalized_block_number,
        finalized_block_hash: restartReadiness.common_finalized_block_hash,
        recorded_at: internalSecond(),
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      }));
      assertFreshProductionFinalizedReadiness(restartReadiness);
      const restartObservation = await adapter.restartCvm({
        domain: "main_runtime_cvm",
        cvmId: target.cvm_id,
        force: false,
      });
      assertRestartAccepted(
        observationResponse(restartObservation, adapter, "restartCvm"),
        target.cvm_id,
      );
      await recordMutationObservation(Object.freeze({
        mutation_name: name,
        sdk_action: "restartCvm",
        observation_sha256: authenticatedPhalaSdkObservationSha256(
          restartObservation,
          {
            adapter,
            method: "restartCvm",
            domain: "main_runtime_cvm",
          },
        ),
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      }));

      const infoObservation = await adapter.getCvmInfo({
        domain: "main_runtime_cvm",
        cvmId: target.cvm_id,
      });
      const attestationObservation = await adapter.getCvmAttestation({
        domain: "main_runtime_cvm",
        cvmId: target.cvm_id,
      });
      const info = observationResponse(infoObservation, adapter, "getCvmInfo");
      const attestation = observationResponse(
        attestationObservation,
        adapter,
        "getCvmAttestation",
      );
      assertPostRestartTarget(info, attestation, target);
      return Object.freeze({
        mutation_name: name,
        from_profile: from,
        to_profile: to,
        post_restart_target_matched: true,
        attestation_quote_present: true,
        automatic_retry_authorized: false,
        live_traffic_authorized: false,
      });
    },
  });
  PRODUCTION_MUTATORS.set(publicMutator, Object.freeze({
    accountGenesisAuthoritySha256,
    accountGenesisSecretInput,
    baseAssembly,
  }));
  return publicMutator;
}

function assertProductionMutator(value) {
  if (!value || !PRODUCTION_MUTATORS.has(value)
    || typeof value.mutate !== "function") {
    fail("a locally created production main profile mutator is required");
  }
  return value;
}

async function executeAccountGenesisSequence({
  accountGenesisAuthority,
  accountGenesisAuthorityOptions,
  accountGenesisExpected,
  collectEvidence,
  mutator,
} = {}) {
  const fixedCheckedAt = accountGenesisAuthorityOptions?.checkedAt
    ?? Math.floor(Date.now() / 1_000);
  const fixedAuthorityOptions = {
    ...accountGenesisAuthorityOptions,
    checkedAt: fixedCheckedAt,
  };
  const authority = normalizePhalaAccountGenesisActivationAuthority(
    accountGenesisAuthority,
    fixedAuthorityOptions,
  );
  const authoritySha256 = phalaAccountGenesisActivationAuthoritySha256(
    authority,
    fixedAuthorityOptions,
  );
  if (accountGenesisExpected?.genesis_authorization_sha256 !== authoritySha256) {
    fail("account-genesis expected environment digest does not equal signed authority");
  }
  if (typeof collectEvidence !== "function") {
    fail("account-genesis execution requires a bounded evidence collector");
  }
  let start;
  let completion;
  let executionFailure;
  try {
    start = assertMutationObservation(await mutator.mutate({
      authoritySha256,
      from: CVM_MAIN_DISABLED_PROFILE_POLICY,
      name: "account_genesis_start",
      to: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    }), {
      from: CVM_MAIN_DISABLED_PROFILE_POLICY,
      name: "account_genesis_start",
      to: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    });
    const evidence = exactRecord(await collectEvidence({
      authority,
      authoritySha256,
    }), [
      "accountReceipt",
      "accountRetirement",
      "handoffRetirement",
      "mailboxReceipt",
      "mailboxRetirement",
    ], "account-genesis bounded evidence set");
    completion = buildPhalaAccountGenesisCompletion({
      ...evidence,
      expected: accountGenesisExpected,
    });
  } catch (error) {
    executionFailure = error;
  }
  let retirement;
  try {
    retirement = assertMutationObservation(await mutator.mutate({
      authoritySha256,
      from: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
      name: "account_genesis_retire",
      to: CVM_MAIN_DISABLED_PROFILE_POLICY,
    }), {
      from: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
      name: "account_genesis_retire",
      to: CVM_MAIN_DISABLED_PROFILE_POLICY,
    });
  } catch (retirementError) {
    fail(
      "account-genesis profile retirement requires explicit reconciliation:"
        + `${retirementError.message}`
        + (executionFailure
          ? `; preceding execution failure:${executionFailure.message}`
          : ""),
    );
  }
  if (executionFailure) throw executionFailure;
  return Object.freeze({
    schema: PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_SCHEMA,
    status: PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_STATUS,
    truth_status: PHALA_ACCOUNT_GENESIS_PROFILE_EXECUTION_RESULT_TRUTH,
    release_sha: authority.release_sha,
    account_genesis_activation_authority_sha256: authoritySha256,
    start,
    completion,
    retirement,
    terminal_profile: CVM_MAIN_DISABLED_PROFILE_POLICY,
    private_shares_present_after_retirement: false,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

export async function executeProductionPhalaAccountGenesisProfileSequence(
  input = {},
) {
  const productionAuthorityOptions = exactRecord(
    input.accountGenesisAuthorityOptions,
    ["expected"],
    "production account-genesis authority options",
  );
  return executeAccountGenesisSequence({
    ...input,
    accountGenesisAuthorityOptions: productionAuthorityOptions,
    mutator: assertProductionMutator(input.mutator),
  });
}

export async function executePhalaAccountGenesisProfileSequenceWithTestAdapter(
  input = {},
  {
    mutate,
  } = {},
) {
  if (typeof mutate !== "function") fail("test profile mutator is required");
  return executeAccountGenesisSequence({
    ...input,
    mutator: Object.freeze({ mutate }),
  });
}

async function executeLiveDealTransition({
  gate,
  mutator,
} = {}) {
  const normalizedGate =
    assertLocallyCreatedPhalaLiveDealProfileActivationGate(gate);
  const gateSha256 = phalaLiveDealProfileActivationGateSha256(normalizedGate);
  const mutation = assertMutationObservation(await mutator.mutate({
    authoritySha256: gateSha256,
    from: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    name: "deal_runtime_start",
    to: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
  }), {
    from: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    name: "deal_runtime_start",
    to: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
  });
  return Object.freeze({
    schema: PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_SCHEMA,
    status: PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_STATUS,
    truth_status: PHALA_LIVE_DEAL_PROFILE_EXECUTION_RESULT_TRUTH,
    release_sha: normalizedGate.release_sha,
    live_deal_profile_activation_gate_sha256: gateSha256,
    mutation,
    terminal_profile: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
    authenticated_phala_quote_presence_observed: true,
    independent_tdx_verdict_verified: false,
    deal_runtime_service_presence_verified: false,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

export async function executeProductionPhalaLiveDealProfileTransition(
  input = {},
) {
  return executeLiveDealTransition({
    ...input,
    mutator: assertProductionMutator(input.mutator),
  });
}

export async function executePhalaLiveDealProfileTransitionWithTestAdapter(
  input = {},
  {
    mutate,
  } = {},
) {
  if (typeof mutate !== "function") fail("test profile mutator is required");
  return executeLiveDealTransition({
    ...input,
    mutator: Object.freeze({ mutate }),
  });
}
