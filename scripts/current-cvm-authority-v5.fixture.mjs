import { createHash } from "node:crypto";

import {
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES,
  cvmDescriptorDomainRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256,
  cvmDescriptorRuntimeFactsSha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-v3-core.mjs";
import {
  PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS,
} from "./phala-app-compose-wire-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-v5-core.mjs";
import {
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture as
    syntheticHistoricalV4ReleaseFixture,
} from "./current-cvm-authority-v4.fixture.mjs";

export {
  CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
} from "./current-cvm-authority-v4.fixture.mjs";

/** Synthetic structure only: these hashes are not measured SDK/CVM evidence. */
export function syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture(
  options = {},
) {
  const raw = structuredClone(syntheticHistoricalV4ReleaseFixture(options));
  const runtime = raw.cvm_descriptor_runtime_authority;
  runtime.schema = CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA;
  runtime.compose_hash_semantics = structuredClone(PHALA_APP_COMPOSE_WIRE_HASH_SEMANTICS);
  runtime.fact_sources = structuredClone(CVM_DESCRIPTOR_RUNTIME_FACT_SOURCES);
  runtime.pre_transform_app_compose_hash_by_domain = {};
  for (const descriptor of runtime.descriptors) {
    descriptor.pre_transform_app_compose_hash = createHash("sha256")
      .update("synthetic-v5-pre-transform-not-runtime:")
      .update(descriptor.domain)
      .update(descriptor.app_compose_hash)
      .digest("hex");
    runtime.pre_transform_app_compose_hash_by_domain[descriptor.domain] =
      descriptor.pre_transform_app_compose_hash;
    descriptor.runtime_facts_sha256 = cvmDescriptorDomainRuntimeFactsSha256(descriptor);
  }
  runtime.descriptor_runtime_facts_sha256 = cvmDescriptorRuntimeFactsSha256(runtime);
  raw.schema = PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA;
  raw.cvm_descriptor_runtime_authority = normalizeCvmDescriptorRuntimeAuthority(runtime);
  raw.cvm_descriptor_runtime_authority_sha256 =
    cvmDescriptorRuntimeAuthoritySha256(raw.cvm_descriptor_runtime_authority);
  return normalizePhalaSevenCvmReleaseVerificationAuthority(raw);
}
