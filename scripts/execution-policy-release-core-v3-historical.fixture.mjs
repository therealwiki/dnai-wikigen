export const KNOWN_VECTOR_JSON = String.raw`
{
  "arena_registry_bindings": {
    "synthetic-bio-assay-qc@1.0.0": {
      "catalog_manifest_hash": "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1",
      "configuration_frozen": true,
      "controller_address": "0x0000000000000000000000000000000000000001",
      "evaluator_commitment": "0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3",
      "lifecycle": "open",
      "metadata_hash": "0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1",
      "metadata_uri": "ipfs://bafy-arena-release-core-vector",
      "paused": false,
      "pending_controller_address": "0x0000000000000000000000000000000000000000",
      "registry_challenge_id": "1",
      "registry_version": 1,
      "release_policy_commitment": "0xd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
      "sealed_artifact_commitment": "0xd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
    }
  },
  "contracts": {
    "challenge_registry": {
      "address": "0x0000000000000000000000000000000000000003",
      "expected_challenge_count": 1,
      "minimum_version_review_delay_seconds": 172800,
      "owner": "0x0000000000000000000000000000000000000001",
      "pending_owner": "0x0000000000000000000000000000000000000000",
      "registry_paused": false,
      "runtime_code_hash": "0x0202020202020202020202020202020202020202020202020202020202020202"
    },
    "compute_credit_vault": {
      "address": "0x0000000000000000000000000000000000000006",
      "compose_hash": "3333333333333333333333333333333333333333333333333333333333333333",
      "developer": "0x000000000000000000000000000000000000000a",
      "developer_fee_bps": 100,
      "metering_binding_frozen": true,
      "metering_policy_set_hash": "0x5656565656565656565656565656565656565656565656565656565656565656",
      "metering_qvl_verifier": "0x0000000000000000000000000000000000000014",
      "metering_verifier": "0x000000000000000000000000000000000000000b",
      "owner": "0x0000000000000000000000000000000000000001",
      "rate_policies": {
        "erc20": {
          "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
          "commitment": "0x5555555555555555555555555555555555555555555555555555555555555555",
          "developer_fee_bps": 100,
          "provider": "0x0000000000000000000000000000000000000013"
        },
        "native": {
          "asset": "0x0000000000000000000000000000000000000000",
          "commitment": "0x4444444444444444444444444444444444444444444444444444444444444444",
          "developer_fee_bps": 100,
          "provider": "0x0000000000000000000000000000000000000012"
        }
      },
      "runtime_code_hash": "0x0505050505050505050505050505050505050505050505050505050505050505",
      "tee_identity": "0x000000000000000000000000000000000000000c"
    },
    "diligence_room": {
      "address": "0x0000000000000000000000000000000000000002",
      "attestation_binding_frozen": true,
      "attestation_release_policy_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "attestation_verifier": "0x0000000000000000000000000000000000000009",
      "developer": "0x0000000000000000000000000000000000000015",
      "evaluator_policy_commitments": [
        "0xb4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4",
        "0xb5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
        "0xb6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6"
      ],
      "evaluator_policy_set_root": "0x24d034ce2bdfb43484ddbb0c37427872c59e047fd9fab10e548f0bc5a9151230",
      "release_admission": {
        "additions_frozen": true,
        "approved_compose_count": 1,
        "approved_tee_identity_count": 1,
        "compose_hash": "3333333333333333333333333333333333333333333333333333333333333333",
        "tee_identity": "0x000000000000000000000000000000000000000c"
      },
      "result_verifier": "0x0000000000000000000000000000000000000008",
      "runtime_code_hash": "0x0101010101010101010101010101010101010101010101010101010101010101"
    },
    "email_oracle_auth": {
      "address": "0x0000000000000000000000000000000000000007",
      "consumer_address": "0x000000000000000000000000000000000000000c",
      "owner": "0x0000000000000000000000000000000000000001",
      "release": {
        "consumer_compose_hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "device_id": "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "external_evidence_sha256": "0xa9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9",
        "kms_contract_address": "0x000000000000000000000000000000000000000f",
        "kms_implementation_address": "0x0000000000000000000000000000000000000010",
        "kms_implementation_runtime_code_hash": "0xa3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        "kms_registration_block": 12345678,
        "kms_registration_block_hash": "0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "kms_registration_tx_hash": "0xa4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
        "kms_runtime_code_hash": "0xa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
        "oracle_compose_hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "restart_key_derivation_proof_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "target_boot": {
          "advisory_ids": [],
          "info_hash": "0xa8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
          "instance_id": "0x0000000000000000000000000000000000000011",
          "mr_aggregated": "0xa6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
          "mr_system": "0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
          "os_image_hash": "0x8888888888888888888888888888888888888888888888888888888888888888",
          "tcb_status": "UpToDate"
        }
      },
      "runtime_code_hash": "0x0606060606060606060606060606060606060606060606060606060606060606",
      "upgrade_delay_seconds": 172800
    },
    "royalty_distributor": {
      "address": "0x0000000000000000000000000000000000000004",
      "runtime_code_hash": "0x0303030303030303030303030303030303030303030303030303030303030303"
    },
    "tinker_account_encumbrance": {
      "account_commitment": "0x2222222222222222222222222222222222222222222222222222222222222222",
      "address": "0x0000000000000000000000000000000000000005",
      "approved_compose_count": 1,
      "approved_compose_hashes": [
        "0x3333333333333333333333333333333333333333333333333333333333333333"
      ],
      "approved_compose_root": "0x2323232323232323232323232323232323232323232323232323232323232323",
      "custodies_funds": false,
      "emergency_halted": false,
      "manager_count": 1,
      "manager_root": "0x2424242424242424242424242424242424242424242424242424242424242424",
      "managers": [
        "0x000000000000000000000000000000000000000c"
      ],
      "max_add_balance_wei": "1000000000000000000",
      "max_spend_wei": "250000000000000000",
      "owner": "0x0000000000000000000000000000000000000001",
      "per_operation_caps": true,
      "release_compose_count": 1,
      "release_compose_root": "0x2323232323232323232323232323232323232323232323232323232323232323",
      "release_manager_count": 1,
      "release_manager_root": "0x2424242424242424242424242424242424242424242424242424242424242424",
      "release_max_add_balance_wei": "1000000000000000000",
      "release_max_spend_wei": "250000000000000000",
      "release_policy_commitment": "0x2525252525252525252525252525252525252525252525252525252525252525",
      "release_policy_frozen": true,
      "runtime_code_hash": "0x0404040404040404040404040404040404040404040404040404040404040404"
    },
    "usdc": {
      "address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
      "decimals": 6,
      "runtime_code_hash": "0x0707070707070707070707070707070707070707070707070707070707070707",
      "symbol": "USDC"
    }
  },
  "cvm": {
    "allowed_browser_origins": [
      "https://www.wikigen.me",
      "https://wikigen.me",
      "https://wikigenme.pages.dev"
    ],
    "app_id": "app_release_core_vector_1_🧬",
    "compose_hash": "3333333333333333333333333333333333333333333333333333333333333333",
    "compute_workload_ingress": {
      "max_verdict_age_seconds": 300,
      "revoked_quote_hashes": []
    },
    "cvm_id": "cvm_release_core_vector_1",
    "delegate_url": "https://delegate.example.com",
    "images": [
      {
        "image": "ghcr.io/therealwiki/dnai-wikigen/tee-email-oracle@sha256:c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "provenance_attestation": "verified",
        "repo": "therealwiki/dnai-wikigen",
        "sbom_attestation": "verified",
        "service": "oracle",
        "signer_workflow": "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
        "source_digest": "0123456789abcdef0123456789abcdef01234567",
        "source_ref": "refs/heads/main"
      },
      {
        "image": "ghcr.io/therealwiki/dnai-wikigen/tinker-delegate@sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "provenance_attestation": "verified",
        "repo": "therealwiki/dnai-wikigen",
        "sbom_attestation": "verified",
        "service": "delegate",
        "signer_workflow": "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
        "source_digest": "0123456789abcdef0123456789abcdef01234567",
        "source_ref": "refs/heads/main"
      },
      {
        "image": "ghcr.io/therealwiki/dnai-wikigen/neko-chrome@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "provenance_attestation": "verified",
        "repo": "therealwiki/dnai-wikigen",
        "sbom_attestation": "verified",
        "service": "neko",
        "signer_workflow": "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
        "source_digest": "0123456789abcdef0123456789abcdef01234567",
        "source_ref": "refs/heads/main"
      }
    ],
    "local_compose_hash": "6666666666666666666666666666666666666666666666666666666666666666",
    "os_image_hash": "8888888888888888888888888888888888888888888888888888888888888888",
    "os_is_dev": false,
    "public_logs": false,
    "public_sysinfo": false,
    "public_tcbinfo": false,
    "rendered_compose_sha256": "7777777777777777777777777777777777777777777777777777777777777777",
    "runtime_controls": {
      "artifact_ciphertext_only": true,
      "bootstrap_fail_open_disabled": true,
      "browser_ports_internal_only": true,
      "deal_settlement_enabled": false,
      "durable_arena_ingress_store": true,
      "durable_arena_store": true,
      "durable_compute_store": true,
      "hostile_candidate_execution_enabled": false,
      "nondefault_browser_credentials_required": true,
      "oracle_health_liveness_only": true,
      "oracle_internal_only": true,
      "oracle_pin_response_minimized": true,
      "oracle_private_metadata_egress_prohibited": true,
      "oracle_replay_fail_closed": true,
      "oracle_runtime_auth_required": true,
      "plaintext_artifact_endpoint_disabled": true,
      "plaintext_card_endpoint_disabled": true,
      "project_owned_browser_images": true,
      "provider_dispatch_enabled": false,
      "raw_secret_egress_prohibited": true,
      "remote_artifact_evaluator_enabled": false,
      "runtime_bearer_required": true,
      "wallet_auth_required": true
    },
    "tee_identity": "0x000000000000000000000000000000000000000c"
  },
  "cvm_launch_intent_sha256": "sha256:e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2",
  "deployment_intent_sha256": "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
  "execution_policy": {
    "api_schema_version": 3,
    "approval_schema": "dnai-wikigen/execution-policy-approval/v3",
    "approver_hashes": [
      "9191919191919191919191919191919191919191919191919191919191919191",
      "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
    ],
    "approver_root_hash": "013c34f9ab123ac6d7bb6ed0711bddb94806f04c02885cb9c2eeb7af2ac739d7",
    "canonicalization_version": "policy-kernel-canonicalization/v2",
    "rollback_anchor_target": {
      "chain_id": 84532,
      "confirmations": 12,
      "consensus_proof_verified": false,
      "contract_address": "0x000000000000000000000000000000000000000d",
      "independent_rpc_quorum_verified": false,
      "max_block_age_seconds": 3600,
      "max_future_block_skew_seconds": 30,
      "runtime_code_hash": "0x9999999999999999999999999999999999999999999999999999999999999999",
      "schema": "dnai.execution-policy-rollback-anchor.v1",
      "verification_model": "single_rpc_reported_finalized_with_confirmation_depth",
      "writer_address": "0x000000000000000000000000000000000000000e",
      "writer_custody": "dstack_derived_execution_policy_anchor_writer",
      "writer_key_path": "tinker/execution_policy_anchor_writer",
      "writer_release_commitment": "0xe2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
    },
    "store_schema_version": 5
  },
  "network": {
    "chain_id": 84532,
    "public_rpc_url": "https://sepolia.base.org"
  },
  "operator_address": "0x0000000000000000000000000000000000000001",
  "release_sha": "0123456789abcdef0123456789abcdef01234567",
  "requested_features": {
    "arena_submission": true,
    "artifact_upload": true,
    "collaboration": false,
    "compute_console": true,
    "compute_vault_authorization": true,
    "compute_vault_funding": true,
    "compute_workload_upload": true,
    "contract_writes": true,
    "tinker_customer": false
  },
  "schema": "dnai.final-release-authority-core.v3",
  "wallet_auth": {
    "domain": "www.wikigen.me",
    "uri": "https://www.wikigen.me",
    "walletconnect_project_id": "12121212121212121212121212121212"
  }
}
`;

const FIXTURE = JSON.parse(KNOWN_VECTOR_JSON);

export const KNOWN_VECTOR_ID =
  "dnai.final-release-authority-core.v3/known-answer-1";
export const KNOWN_DIGEST =
  "2e2c02e0748b66690eaee79e451ab5506246ef758fb0cf08437f75ef836f48f8";
export const RELEASE_SHA = FIXTURE.release_sha;
export const APPROVER_ROOT = FIXTURE.execution_policy.approver_root_hash;
export const USDC = FIXTURE.contracts.usdc.address;

export function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

export function word(pair, prefixed = true) {
  return `${prefixed ? "0x" : ""}${pair.repeat(32)}`;
}

export function knownVector() {
  return structuredClone(FIXTURE);
}
