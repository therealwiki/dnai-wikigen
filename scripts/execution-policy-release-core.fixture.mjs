import {
  ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  ROYALTY_INITIAL_AUTHORITY_NONCE,
  ROYALTY_RELEASE_AUTHORITY_SCHEMA,
  ROYALTY_RELEASE_STATE_SCHEMA,
  royaltyReleasePolicyCommitment,
  royaltyReleaseStateSha256,
} from "./royalty-release-authority-core.mjs";

const V3_BASE_VECTOR_JSON = String.raw`
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

const FIXTURE = JSON.parse(V3_BASE_VECTOR_JSON);

FIXTURE.schema = "dnai.final-release-authority-core.v4";
FIXTURE.cvm.app_id = "ab".repeat(20);
FIXTURE.execution_policy.store_schema_version = 6;
FIXTURE.execution_policy.store_contract = {
  surface: "execution_policy_store",
  schema_version: 6,
  payload_fields: ["sequence", "records", "royalty_confirmations"],
  policy_record_kind: "execution_policy_decision_v2",
  royalty_record_kind: "royalty_settlement_anchor_v1",
  local_record_sequence_semantics: "one_based_contiguous_local_sequence",
  previous_record_digest_field: "previous_record_digest",
  royalty_chain_sequence_field: "chain_sequence",
  royalty_authorization_plan_schema:
    "dnai.royalty-settlement-authorization-plan.v2",
  royalty_wallet_plan_record_schema:
    "dnai.royalty-settlement-wallet-plan-record.v1",
  royalty_confirmation_schema:
    "dnai.royalty-settlement-anchor-confirmation.v1",
  royalty_sponsor_dto_schema:
    "dnai.collaboration.royalty-settlement-wallet-plan.v1",
};
FIXTURE.execution_policy.release_marker_genesis = {
  schema: "dnai.execution-policy-release-marker-genesis.v1",
  required: true,
  resource_domain:
    "dnai-wikigen/execution-policy/final-release-authority/v1",
  resource_hash:
    "0xeedc26aa4ef06f5c30982cefc655d6b55caaae6d9af3d9712532233a86f41d8b",
  decision_environment_key: "TINKER_RELEASE_AUTHORITY_SHA256",
  decision_semantics: "exact_final_release_authority_core_sha256",
  anchor_binding_semantics:
    "rollback_anchor_target_contract_writer_and_writer_release_commitment",
  marker_chain_sequence: 1,
  local_store_first_sequence: 1,
  chain_sequence_offset: 1,
  first_local_record_chain_sequence: 2,
  royalty_anchor_sequence_semantics:
    "onchain_global_sequence_including_release_marker",
};
FIXTURE.execution_policy.rollback_anchor_target.schema =
  "dnai.execution-policy-rollback-anchor.v2";
FIXTURE.execution_policy.rollback_anchor_target.writer_gas_reserve_policy = {
  schema: "dnai.execution-policy-anchor-writer-gas-reserve.v1",
  release_marker_transaction_count: 1,
  expected_subsequent_anchor_count: 32,
  maximum_gas_per_transaction: 500_000,
  reviewed_max_fee_per_gas_wei: "2000000000",
  minimum_reserve_wei: "33000000000000000",
};
FIXTURE.requested_features.collaboration_execution = false;
FIXTURE.requested_features.royalty_settlement = false;
FIXTURE.requested_features.compute_workload_wallet_adoption = false;

FIXTURE.seven_cvm_release_verification_authority_sha256 =
  `sha256:${"69".repeat(32)}`;
FIXTURE.shared_release_lineage = {
  schema: "dnai.final-release-shared-lineage.v1",
  release_sha: FIXTURE.release_sha,
  deployment_intent_sha256: FIXTURE.deployment_intent_sha256,
  cvm_launch_intent_sha256: FIXTURE.cvm_launch_intent_sha256,
  seven_cvm_release_verification_authority_sha256:
    FIXTURE.seven_cvm_release_verification_authority_sha256,
  main_runtime_cvm_id: FIXTURE.cvm.cvm_id,
  main_runtime_compose_hash: FIXTURE.cvm.compose_hash,
  main_runtime_app_id: FIXTURE.cvm.app_id,
  main_runtime_os_image_hash: FIXTURE.cvm.os_image_hash,
};

const royaltyAuthorityInput = {
  chainId: FIXTURE.network.chain_id,
  distributorAddress: FIXTURE.contracts.royalty_distributor.address,
  authorityNonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
  settlementVerifier: address(30),
  qvlVerifier: address(31),
  executionPolicyAnchor:
    FIXTURE.execution_policy.rollback_anchor_target.contract_address,
  anchorWriterReleaseCommitment:
    FIXTURE.execution_policy.rollback_anchor_target.writer_release_commitment,
};
const royaltyReleasePolicy = royaltyReleasePolicyCommitment(
  royaltyAuthorityInput,
);
FIXTURE.royalty_release_authority = {
  schema: ROYALTY_RELEASE_AUTHORITY_SCHEMA,
  chain_id: FIXTURE.network.chain_id,
  distributor_address: FIXTURE.contracts.royalty_distributor.address,
  owner: FIXTURE.operator_address,
  settlement_verifier: royaltyAuthorityInput.settlementVerifier,
  qvl_verifier: royaltyAuthorityInput.qvlVerifier,
  execution_policy_anchor: royaltyAuthorityInput.executionPolicyAnchor,
  anchor_writer:
    FIXTURE.execution_policy.rollback_anchor_target.writer_address,
  anchor_writer_release_commitment:
    royaltyAuthorityInput.anchorWriterReleaseCommitment,
  authority_nonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
  authority_timelock_seconds: ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  release_policy_commitment: royaltyReleasePolicy,
};
FIXTURE.royalty_release_active_state = {
  schema: ROYALTY_RELEASE_STATE_SCHEMA,
  chain_id: FIXTURE.network.chain_id,
  contract_address: FIXTURE.contracts.royalty_distributor.address,
  block_number: 12_345_678,
  block_hash: word("70"),
  block_timestamp: 1_800_000_000,
  owner: FIXTURE.operator_address,
  pending_owner: address(0),
  paused: false,
  settlement_verifier: royaltyAuthorityInput.settlementVerifier,
  qvl_verifier: royaltyAuthorityInput.qvlVerifier,
  execution_policy_anchor: royaltyAuthorityInput.executionPolicyAnchor,
  anchor_writer_release_commitment:
    royaltyAuthorityInput.anchorWriterReleaseCommitment,
  release_policy_commitment: royaltyReleasePolicy,
  authority_nonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
  pending_settlement_verifier: address(0),
  pending_qvl_verifier: address(0),
  pending_execution_policy_anchor: address(0),
  pending_anchor_writer_release_commitment: word("00"),
  pending_release_policy_commitment: word("00"),
  pending_authority_nonce: 0,
  pending_authority_activates_at: 0,
  pending_authority_revocation: false,
  settlement_verifier_ever_configured: true,
  qvl_verifier_ever_configured: true,
  anchor_writer_ever_configured: true,
  computed_release_policy_commitment: royaltyReleasePolicy,
};
FIXTURE.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
  FIXTURE.royalty_release_active_state,
  {
    authority: FIXTURE.royalty_release_authority,
    phase: "phase_two_active",
  },
);
FIXTURE.royalty_release_history_sha256 = `sha256:${"71".repeat(32)}`;
FIXTURE.royalty_release_history_receipt_sha256 =
  `sha256:${"72".repeat(32)}`;

const royaltyQvlKeyId = word("73");
FIXTURE.royalty_settlement_release_binding_template = {
  schema: "dnai.royalty-settlement-release-binding-template.v1",
  chain_id: FIXTURE.network.chain_id,
  distributor_address: FIXTURE.contracts.royalty_distributor.address,
  distributor_runtime_code_hash:
    FIXTURE.contracts.royalty_distributor.runtime_code_hash,
  authority_nonce: ROYALTY_INITIAL_AUTHORITY_NONCE,
  settlement_verifier_address: royaltyAuthorityInput.settlementVerifier,
  settlement_verifier_key_path:
    "tinker/collaboration_royalty_settlement_signer",
  settlement_verifier_custody:
    "dstack_derived_main_runtime_royalty_settlement_signer",
  royalty_qvl_verifier_address: royaltyAuthorityInput.qvlVerifier,
  royalty_qvl_signer_key_id: royaltyQvlKeyId,
  royalty_qvl_signer_key_path:
    `dnai-wikigen/attestation-qvl/royalty-settlement-signer/v1/${royaltyQvlKeyId.slice(2)}`,
  royalty_qvl_signer_custody:
    "dstack_derived_diligence_qvl_royalty_settlement_signer",
  royalty_qvl_policy_template_sha256: `sha256:${"74".repeat(32)}`,
  qvl_release_policy_hash: word("75"),
  measurement_policy_sha256: `sha256:${"76".repeat(32)}`,
  execution_policy_anchor_address: royaltyAuthorityInput.executionPolicyAnchor,
  anchor_writer_release_commitment:
    royaltyAuthorityInput.anchorWriterReleaseCommitment,
  release_policy_commitment: royaltyReleasePolicy,
  main_runtime_cvm_id: FIXTURE.cvm.cvm_id,
  deployment_intent_sha256: FIXTURE.deployment_intent_sha256,
  ceremony_nonce: word("77"),
  compose_hash: `0x${FIXTURE.cvm.compose_hash}`,
  app_id: FIXTURE.cvm.app_id,
  os_image_hash: FIXTURE.cvm.os_image_hash,
  max_authorization_lifetime_seconds: 600,
};
FIXTURE.collaboration_execution = {
  schema: "dnai.collaboration-execution-release-authority.v1",
  service: "collaboration-execution-worker",
  profile: "collaboration-execution",
  enabled: FIXTURE.requested_features.collaboration_execution,
  release_sha: FIXTURE.release_sha,
  release_verification_sha256:
    FIXTURE.seven_cvm_release_verification_authority_sha256,
  authenticated_worker_required: true,
  heartbeat_claim_required: true,
  heartbeat_claim_semantics:
    "authenticated_worker_presence_not_tdx_attestation",
  tdx_attestation_claimed: false,
};
FIXTURE.compute_workload_wallet_adoption = {
  schema: "dnai.compute-workload-wallet-adoption-release-decision.v1",
  enabled: FIXTURE.requested_features.compute_workload_wallet_adoption,
  device_spend_authority: false,
  credential_uploader_attribution_preserved: true,
  device_ciphertext_upload_authority_preserved: true,
  wallet_funding_authority_required: true,
  workload_dispatch_authority_required: true,
};

export const KNOWN_VECTOR_JSON = JSON.stringify(FIXTURE, null, 2);

export const KNOWN_VECTOR_ID =
  "dnai.final-release-authority-core.v4/known-answer-1";
export const KNOWN_DIGEST =
  "2b0d68ced175dd7dad8e1354e668f52607256fd12bb29ba78c2fe7568d0a211b";
export const RELEASE_SHA = FIXTURE.release_sha;
export const APPROVER_ROOT = FIXTURE.execution_policy.approver_root_hash;
export const USDC = FIXTURE.contracts.usdc.address;

export function rebindKnownVectorV4AuthorityFixture(authority, {
  deploymentIntentSha256,
  cvmLaunchIntentSha256 = authority.cvm_launch_intent_sha256,
}) {
  const writerReleaseCommitment =
    `0x${cvmLaunchIntentSha256.slice("sha256:".length)}`;

  authority.deployment_intent_sha256 = deploymentIntentSha256;
  authority.cvm_launch_intent_sha256 = cvmLaunchIntentSha256;
  authority.execution_policy.rollback_anchor_target.writer_release_commitment =
    writerReleaseCommitment;

  Object.assign(authority.shared_release_lineage, {
    release_sha: authority.release_sha,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    seven_cvm_release_verification_authority_sha256:
      authority.seven_cvm_release_verification_authority_sha256,
    main_runtime_cvm_id: authority.cvm.cvm_id,
    main_runtime_compose_hash: authority.cvm.compose_hash,
    main_runtime_app_id: authority.cvm.app_id,
    main_runtime_os_image_hash: authority.cvm.os_image_hash,
  });
  Object.assign(authority.collaboration_execution, {
    enabled: authority.requested_features.collaboration_execution,
    release_sha: authority.release_sha,
    release_verification_sha256:
      authority.seven_cvm_release_verification_authority_sha256,
  });

  const royaltyAuthority = authority.royalty_release_authority;
  royaltyAuthority.anchor_writer_release_commitment = writerReleaseCommitment;
  const releasePolicyCommitment = royaltyReleasePolicyCommitment({
    chainId: royaltyAuthority.chain_id,
    distributorAddress: royaltyAuthority.distributor_address,
    authorityNonce: royaltyAuthority.authority_nonce,
    settlementVerifier: royaltyAuthority.settlement_verifier,
    qvlVerifier: royaltyAuthority.qvl_verifier,
    executionPolicyAnchor: royaltyAuthority.execution_policy_anchor,
    anchorWriterReleaseCommitment: writerReleaseCommitment,
  });
  royaltyAuthority.release_policy_commitment = releasePolicyCommitment;

  const activeState = authority.royalty_release_active_state;
  activeState.anchor_writer_release_commitment = writerReleaseCommitment;
  activeState.release_policy_commitment = releasePolicyCommitment;
  activeState.computed_release_policy_commitment = releasePolicyCommitment;
  authority.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
    activeState,
    { authority: royaltyAuthority, phase: "phase_two_active" },
  );

  Object.assign(authority.royalty_settlement_release_binding_template, {
    anchor_writer_release_commitment: writerReleaseCommitment,
    release_policy_commitment: releasePolicyCommitment,
    main_runtime_cvm_id: authority.cvm.cvm_id,
    deployment_intent_sha256: deploymentIntentSha256,
    compose_hash: `0x${authority.cvm.compose_hash}`,
    app_id: authority.cvm.app_id,
    os_image_hash: authority.cvm.os_image_hash,
  });
  return authority;
}

export function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

export function word(pair, prefixed = true) {
  return `${prefixed ? "0x" : ""}${pair.repeat(32)}`;
}

export function knownVector() {
  return structuredClone(FIXTURE);
}
