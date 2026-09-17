import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import { buildPhalaContractKmsProjection } from "./phala-contract-kms-core.mjs";

// Public SEC/NIST generator points only. These synthetic fixtures are not
// production identities, independent signer provenance, or Phala observations.
export const SYNTHETIC_PHALA_K256 =
  "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
export const SYNTHETIC_PHALA_CA_PUBKEY =
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
  + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
export const SYNTHETIC_PHALA_KMS_CONTRACT_ID = "kc_SyntheticRoot";

export function createSyntheticPhalaContractKmsFixture({
  osImage = PHALA_OS_IMAGE_CATALOG_ENTRY,
  resourceTargets = Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [domain, {
    ...structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
    gateway_required: CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate.gateway_enabled,
  }])),
} = {}) {
  const contract = {
    id: SYNTHETIC_PHALA_KMS_CONTRACT_ID,
    slug: "phala",
    label: "Synthetic Phala KMS root",
    contract_address: "phala",
    chain_id: 0,
    k256_pubkey: SYNTHETIC_PHALA_K256.slice(2),
    ca_pubkey: SYNTHETIC_PHALA_CA_PUBKEY,
    node_count: 2,
  };
  const replicas = [1, 2].map((index) => ({
    id: `kms_Synthetic${index}`,
    slug: `phala-synthetic${index}`,
    url: `https://kms-${index}.phala.network/`,
    version: "v0.6.0-rc0 (git:abcdef1234567890)",
    kms_type: "phala",
  }));
  const resources = {
    tier: "production",
    capacity: {
      max_instances: 20,
      max_vcpu: 100,
      max_memory: 200_000,
      max_disk: 2_048,
      max_memory_each: 65_536,
      max_disk_each: 2_048,
    },
    instance_types: ["tdx.large", "tdx.small"].map((id) => ({
      id,
      name: id === "tdx.large" ? "Large TDX Instance" : "Small TDX Instance",
      vcpu: id === "tdx.large" ? 4 : 1,
      memory_mb: id === "tdx.large" ? 8_192 : 2_048,
      default_disk_size_gb: 20,
      requires_gpu: false,
      requires_gpu_count: 0,
      family: "cpu",
      display_order: null,
    })),
    kms_nodes: replicas.map((replica) => ({
      ...replica,
      chain_id: null,
      kms_contract_id: contract.id,
      kms_contract_address: "",
      gateway_app_id: `0x${"1".repeat(40)}`,
      supported_os_images: [osImage.name],
    })),
    nodes: [1, 2].map((index) => ({
      node_id: index + 6,
      teepod_id: index + 20,
      name: `synthetic${index}`,
      listed: true,
      resource_score: 100,
      remaining_vcpu: 32,
      remaining_memory: 65_536,
      remaining_cvm_slots: 10,
      images: [{
        ...structuredClone(osImage),
        version: osImage.version.split(".").map(Number),
        supports_cpu: true,
        enabled: true,
      }],
      device_id: String(index).repeat(64),
      device_ids: [
        { device_id: String(index).repeat(64), algorithm_version: "v3.0.0", enabled: true },
        { device_id: String(index + 2).repeat(64), algorithm_version: "v2.0.0", enabled: true },
      ],
      kms_list: [],
    })),
    node_kms_relations: replicas.map((replica, index) => ({
      teepod_id: index + 21,
      kms_id: replica.id,
      kms_type: "phala",
      kms_contract_id: contract.id,
      kms_contract_address: "",
      supported_os_images: [osImage.name],
    })),
    gateway_nodes: [{
      id: "gn_Synthetic1",
      node_id: 7,
      teepod_id: 21,
      kms_contract_id: contract.id,
      enabled: true,
      rpc_url: "https://gateway-rpc.phala.network/",
      domain_suffix: "gateway.phala.network",
    }],
    gpu_availability: {
      has_reserved_gpus: false,
      reserved_gpu_count: 0,
      has_public_gpus: false,
      public_gpu_count: 0,
    },
  };
  return {
    contract,
    contractNodes: { items: replicas, total: replicas.length },
    resources,
    osImage: structuredClone(osImage),
    resourceTargets: structuredClone(resourceTargets),
  };
}

export function createSyntheticPhalaContractKmsProjection(options) {
  return structuredClone(buildPhalaContractKmsProjection(
    createSyntheticPhalaContractKmsFixture(options),
  ));
}
