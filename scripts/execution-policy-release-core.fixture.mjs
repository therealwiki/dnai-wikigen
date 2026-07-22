export const KNOWN_VECTOR_ID =
  "dnai.final-release-authority-core.v2/known-answer-1";
export const KNOWN_DIGEST =
  "d1bab06a461597c4b0d12d9bbf50ea37549c2023b8c37b3e8ef7638b8c874fce";
export const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
export const APPROVER_ROOT =
  "013c34f9ab123ac6d7bb6ed0711bddb94806f04c02885cb9c2eeb7af2ac739d7";
export const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

export function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

export function word(pair, prefixed = true) {
  return `${prefixed ? "0x" : ""}${pair.repeat(32)}`;
}

function image(service, repository, digestPair) {
  return {
    service,
    image: `ghcr.io/therealwiki/dnai-wikigen/${repository}@sha256:${digestPair.repeat(32)}`,
    source_digest: RELEASE_SHA,
    source_ref: "refs/heads/main",
    repo: "therealwiki/dnai-wikigen",
    signer_workflow:
      "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    provenance_attestation: "verified",
    sbom_attestation: "verified",
  };
}

export function knownVector() {
  return {
    schema: "dnai.final-release-authority-core.v2",
    release_sha: RELEASE_SHA,
    network: {
      chain_id: 84_532,
      public_rpc_url: "https://sepolia.base.org",
    },
    operator_address: address(1),
    deployment_intent_sha256: `sha256:${"b1".repeat(32)}`,
    cvm_launch_intent_sha256: `sha256:${"e2".repeat(32)}`,
    contracts: {
      diligence_room: {
        address: address(2),
        runtime_code_hash: word("01"),
        developer: address(1),
        result_verifier: address(8),
        attestation_verifier: address(9),
        attestation_release_policy_hash: word("11"),
        attestation_binding_frozen: true,
        evaluator_policy_commitments: [word("b4"), word("b5"), word("b6")],
        evaluator_policy_set_root: diligenceEvaluatorPolicySetRoot([
          word("b4"), word("b5"), word("b6"),
        ]),
        release_admission: {
          tee_identity: address(12),
          compose_hash: word("33", false),
          approved_tee_identity_count: 1,
          approved_compose_count: 1,
          additions_frozen: true,
        },
      },
      challenge_registry: {
        address: address(3),
        runtime_code_hash: word("02"),
        owner: address(1),
        pending_owner: address(0),
        registry_paused: false,
        minimum_version_review_delay_seconds: 172_800,
        expected_challenge_count: 1,
      },
      royalty_distributor: {
        address: address(4),
        runtime_code_hash: word("03"),
      },
      tinker_account_encumbrance: {
        address: address(5),
        runtime_code_hash: word("04"),
        owner: address(1),
        account_commitment: word("22"),
        max_add_balance_wei: "1000000000000000000",
        max_spend_wei: "250000000000000000",
        approved_compose_hashes: [word("33")],
        approved_compose_root: word("23"),
        approved_compose_count: 1,
        managers: [address(12)],
        manager_root: word("24"),
        manager_count: 1,
        release_policy_commitment: word("25"),
        release_max_add_balance_wei: "1000000000000000000",
        release_max_spend_wei: "250000000000000000",
        release_compose_root: word("23"),
        release_compose_count: 1,
        release_manager_root: word("24"),
        release_manager_count: 1,
        release_policy_frozen: true,
        emergency_halted: false,
        per_operation_caps: true,
        custodies_funds: false,
      },
      compute_credit_vault: {
        address: address(6),
        runtime_code_hash: word("05"),
        owner: address(1),
        developer: address(10),
        metering_verifier: address(11),
        metering_qvl_verifier: address(20),
        metering_policy_set_hash: word("56"),
        metering_binding_frozen: true,
        developer_fee_bps: 500,
        tee_identity: address(12),
        compose_hash: word("33", false),
        rate_policies: {
          native: {
            commitment: word("44"),
            asset: address(0),
            provider: address(18),
            developer_fee_bps: 500,
          },
          erc20: {
            commitment: word("55"),
            asset: USDC,
            provider: address(19),
            developer_fee_bps: 500,
          },
        },
      },
      email_oracle_auth: {
        address: address(7),
        runtime_code_hash: word("06"),
        owner: address(1),
        consumer_address: address(12),
        upgrade_delay_seconds: 172_800,
        release: {
          oracle_compose_hash: word("33"),
          consumer_compose_hash: word("33"),
          device_id: word("a1"),
          kms_contract_address: address(15),
          kms_runtime_code_hash: word("a2"),
          kms_implementation_address: address(16),
          kms_implementation_runtime_code_hash: word("a3"),
          kms_registration_tx_hash: word("a4"),
          kms_registration_block: 12_345_678,
          kms_registration_block_hash: word("a5"),
          target_boot: {
            instance_id: address(17),
            mr_aggregated: word("a6"),
            mr_system: word("a7"),
            os_image_hash: word("88"),
            tcb_status: "UpToDate",
            advisory_ids: [],
            info_hash: word("a8"),
          },
          restart_key_derivation_proof_hash: word("aa"),
          external_evidence_sha256: word("a9"),
        },
      },
      usdc: {
        address: USDC,
        runtime_code_hash: word("07"),
        symbol: "USDC",
        decimals: 6,
      },
    },
    cvm: {
      app_id: "app_release_core_vector_1_🧬",
      cvm_id: "cvm_release_core_vector_1",
      compose_hash: word("33", false),
      local_compose_hash: word("66", false),
      rendered_compose_sha256: word("77", false),
      os_image_hash: word("88", false),
      os_is_dev: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
      tee_identity: address(12),
      delegate_url: "https://delegate.example.com",
      images: [
        image("oracle", "tee-email-oracle", "c3"),
        image("delegate", "tinker-delegate", "a1"),
        image("neko", "neko-chrome", "b2"),
      ],
      allowed_browser_origins: [
        "https://www.wikigen.me",
        "https://wikigen.me",
        "https://wikigenme.pages.dev",
      ],
      compute_workload_ingress: {
        max_verdict_age_seconds: 300,
        revoked_quote_hashes: [],
      },
      runtime_controls: {
        wallet_auth_required: true,
        runtime_bearer_required: true,
        durable_compute_store: true,
        durable_arena_store: true,
        durable_arena_ingress_store: true,
        artifact_ciphertext_only: true,
        plaintext_artifact_endpoint_disabled: true,
        plaintext_card_endpoint_disabled: true,
        bootstrap_fail_open_disabled: true,
        browser_ports_internal_only: true,
        nondefault_browser_credentials_required: true,
        project_owned_browser_images: true,
        oracle_internal_only: true,
        oracle_runtime_auth_required: true,
        oracle_health_liveness_only: true,
        oracle_pin_response_minimized: true,
        oracle_private_metadata_egress_prohibited: true,
        oracle_replay_fail_closed: true,
        provider_dispatch_enabled: false,
        hostile_candidate_execution_enabled: false,
        deal_settlement_enabled: false,
        remote_artifact_evaluator_enabled: false,
        raw_secret_egress_prohibited: true,
      },
    },
    arena_registry_bindings: {
      "synthetic-bio-assay-qc@1.0.0": {
        registry_challenge_id: "1",
        registry_version: 1,
        controller_address: address(1),
        pending_controller_address: address(0),
        lifecycle: "open",
        paused: false,
        configuration_frozen: true,
        catalog_manifest_hash: word("d1", false),
        metadata_uri: "ipfs://bafy-arena-release-core-vector",
        metadata_hash: word("d1"),
        sealed_artifact_commitment: word("d2"),
        evaluator_commitment: word("d3"),
        release_policy_commitment: word("d4"),
      },
    },
    wallet_auth: {
      domain: "www.wikigen.me",
      uri: "https://www.wikigen.me",
      walletconnect_project_id: "12".repeat(16),
    },
    requested_features: {
      contract_writes: true,
      artifact_upload: true,
      compute_console: true,
      compute_vault_funding: true,
      compute_vault_authorization: true,
      compute_workload_upload: true,
      arena_submission: true,
    },
    execution_policy: {
      canonicalization_version: "policy-kernel-canonicalization/v2",
      approval_schema: "dnai-wikigen/execution-policy-approval/v3",
      api_schema_version: 3,
      store_schema_version: 5,
      approver_hashes: [word("91", false), word("a2", false)],
      approver_root_hash: APPROVER_ROOT,
      rollback_anchor_target: {
        schema: "dnai.execution-policy-rollback-anchor.v1",
        chain_id: 84_532,
        contract_address: address(13),
        runtime_code_hash: word("99"),
        writer_address: address(14),
        writer_release_commitment: word("e2"),
        writer_custody: "dstack_derived_execution_policy_anchor_writer",
        writer_key_path: "tinker/execution_policy_anchor_writer",
        confirmations: 12,
        max_block_age_seconds: 3_600,
        max_future_block_skew_seconds: 30,
        verification_model:
          "single_rpc_reported_finalized_with_confirmation_depth",
        independent_rpc_quorum_verified: false,
        consensus_proof_verified: false,
      },
    },
  };
}
import { diligenceEvaluatorPolicySetRoot } from "./execution-policy-release-core.mjs";
