import {
  CVM_LAUNCH_DESCRIPTOR_FILES,
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";

export const CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA =
  "dnai.cvm-release-descriptor-set-validation.v2";
export const CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN =
  "dnai-wikigen/cvm-release-descriptor-set-validation/v2\0";

export const CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY = Object.freeze({
  tracked_source_status: "reviewed_repo_sources_only",
  generated_output_status: "ignored_release_evidence_not_source_controlled",
  generated_output_directory: ".release",
  deployment_claimed: false,
  tdx_attestation_claimed: false,
});

export const CVM_RELEASE_DESCRIPTOR_TRACKED_SOURCE_FILES = Object.freeze([
  ".github/workflows/build-tee-images.yml",
  "scripts/build-tee-image-release.mjs",
  "⚙️/tinker-delegate/tinker_delegate/release_composes.py",
  "⚙️/tinker-delegate/docker-compose.all.phala.yaml",
  "⚙️/tinker-delegate/docker-compose.all.dstack.yaml",
  "⚙️/attestation-qvl/docker-compose.production.yml",
  "⚙️/compute-metering/docker-compose.production.yml",
]);

export const CVM_RELEASE_DESCRIPTOR_GENERATED_FILES = Object.freeze([
  ...CVM_LAUNCH_DOMAINS.map((domain) => CVM_LAUNCH_DESCRIPTOR_FILES[domain]),
  "dnai-tee-image-release.json",
  "dnai-tee-image-release.bundle.json",
  "dnai-deployment-intent-core.json",
  "dnai-cvm-topology.json",
]);

export const CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX = Object.freeze({
  main_runtime_cvm: Object.freeze([
    "neko",
    "oracle",
    "delegate",
    "diligence-policy-init",
    "arena-policy-init",
    "arena-worker",
    "anchor-writer-evidence",
    "deal-runtime",
    "compute-execution-worker",
  ]),
  diligence_qvl_cvm: Object.freeze(["policy-init", "qvl"]),
  arena_qvl_cvm: Object.freeze(["policy-init", "qvl"]),
  anchor_writer_qvl_cvm: Object.freeze(["policy-init", "qvl"]),
  compute_workload_qvl_cvm: Object.freeze(["policy-init", "qvl"]),
  compute_metering_qvl_cvm: Object.freeze(["policy-init", "qvl"]),
  independent_metering_cvm: Object.freeze(["policy-init", "state-init", "metering"]),
});
