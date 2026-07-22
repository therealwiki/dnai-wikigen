from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

ARENA_REGISTRY_ENV_KEYS = (
    "TINKER_ARENA_REGISTRY_RPC_URL",
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    "TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS",
    "TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS",
)

ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS = (
    "TINKER_ARENA_REGISTRY_RPC_URL",
)

ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS = (
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
)

ARENA_REGISTRY_DESCRIPTOR_DEFAULTS = {
    "TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS": "300",
    "TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS": "30",
}


def _service_block(compose_text: str, service_name: str) -> str:
    lines = compose_text.splitlines()
    start = next(index for index, line in enumerate(lines) if line == f"  {service_name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def _javascript_array_block(source: str, marker: str, terminator: str) -> str:
    start = source.index(marker)
    end = source.index(terminator, start)
    return source[start:end]


def _environment_assignments(service_block: str, key: str) -> list[str]:
    return [
        line.strip()
        for line in service_block.splitlines()
        if line.strip().startswith(f"{key}:")
    ]


class ComposeHardeningTest(unittest.TestCase):
    def assert_service_disables_core_dumps(self, compose_name: str, service_name: str):
        compose = (ROOT / compose_name).read_text()
        block = _service_block(compose, service_name)

        self.assertIn("ulimits:", block)
        self.assertIn("core: 0", block)

    def test_local_delegate_compose_disables_core_dumps(self):
        self.assert_service_disables_core_dumps("docker-compose.yaml", "delegate")

    def test_arena_registry_admission_inputs_follow_release_authority_split(self):
        example_env = (ROOT.parents[1] / "example.env").read_text()
        for key in ARENA_REGISTRY_ENV_KEYS:
            with self.subTest(surface="example.env", key=key):
                self.assertEqual(example_env.count(f"{key}="), 1)
        for key in (
            *ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS,
            *ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS,
        ):
            self.assertIn(f"{key}=\n", example_env)
        for key, default in ARENA_REGISTRY_DESCRIPTOR_DEFAULTS.items():
            self.assertIn(f"{key}={default}\n", example_env)

        for compose_name in ("docker-compose.yaml", "docker-compose.all.yaml"):
            delegate = _service_block((ROOT / compose_name).read_text(), "delegate")
            for key in (
                *ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS,
                *ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS,
            ):
                with self.subTest(compose=compose_name, key=key):
                    self.assertEqual(
                        _environment_assignments(delegate, key),
                        [f"{key}: ${{{key}:-}}"],
                    )
            for key, default in ARENA_REGISTRY_DESCRIPTOR_DEFAULTS.items():
                with self.subTest(compose=compose_name, key=key):
                    self.assertEqual(
                        _environment_assignments(delegate, key),
                        [f"{key}: ${{{key}:-{default}}}"],
                    )

        for compose_name in (
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
        ):
            delegate = _service_block((ROOT / compose_name).read_text(), "delegate")
            for key in (
                *ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS,
                *ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS,
            ):
                with self.subTest(compose=compose_name, key=key):
                    self.assertEqual(
                        _environment_assignments(delegate, key),
                        [f"{key}: ${{{key}:-}}"],
                    )
            for key, default in ARENA_REGISTRY_DESCRIPTOR_DEFAULTS.items():
                with self.subTest(compose=compose_name, key=key):
                    self.assertEqual(
                        _environment_assignments(delegate, key),
                        [f"{key}: ${{{key}:-{default}}}"],
                    )

        # The narrow dstack development overlay inherits these inputs from
        # docker-compose.yaml; it must not silently replace that base policy.
        # A code-owned worker setting may reference the authorized challenge-
        # set digest by name without re-declaring that source authority.
        development_overlay = (ROOT / "docker-compose.dstack.yaml").read_text()
        development_delegate = _service_block(development_overlay, "delegate")
        development_worker = _service_block(development_overlay, "arena-worker")
        for key in ARENA_REGISTRY_ENV_KEYS:
            with self.subTest(compose="docker-compose.dstack.yaml", key=key):
                self.assertEqual(
                    _environment_assignments(development_delegate, key),
                    [],
                )
                self.assertEqual(
                    _environment_assignments(development_worker, key),
                    [],
                )

        launch_core = (ROOT.parents[1] / "scripts/cvm-launch-intent-core.mjs").read_text()
        authority_blocks = {
            "final_authority_secret": _javascript_array_block(
                launch_core,
                "final_authority_runtime: Object.freeze([",
                "]),",
            ),
            "deferred_public_authority": _javascript_array_block(
                launch_core,
                "const MAIN_DEFERRED_KEYS = Object.freeze([",
                "]);",
            ),
            "descriptor_default": _javascript_array_block(
                launch_core,
                "const MAIN_DESCRIPTOR_DEFAULTED_KEYS = Object.freeze([",
                "]);",
            ),
        }
        expected_classification = {
            **{
                key: "final_authority_secret"
                for key in ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS
            },
            **{
                key: "deferred_public_authority"
                for key in ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS
            },
            **{
                key: "descriptor_default"
                for key in ARENA_REGISTRY_DESCRIPTOR_DEFAULTS
            },
        }
        for key, expected_authority in expected_classification.items():
            classified_as = {
                authority
                for authority, block in authority_blocks.items()
                if f'"{key}"' in block
            }
            with self.subTest(surface="launch authority", key=key):
                self.assertEqual(classified_as, {expected_authority})

        active_late_inputs = _javascript_array_block(
            launch_core,
            "export const CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS = Object.freeze([",
            "]);",
        )
        for key in (
            *ARENA_REGISTRY_FINAL_AUTHORITY_SECRET_KEYS,
            *ARENA_REGISTRY_DEFERRED_PUBLIC_AUTHORITY_KEYS,
        ):
            self.assertIn(f'"{key}"', active_late_inputs)
        for key in ARENA_REGISTRY_DESCRIPTOR_DEFAULTS:
            self.assertNotIn(f'"{key}"', active_late_inputs)

    def test_all_in_one_local_compose_disables_core_dumps(self):
        for service in ("neko", "oracle", "delegate"):
            self.assert_service_disables_core_dumps("docker-compose.all.yaml", service)

    def test_phala_compose_disables_core_dumps(self):
        for service in ("neko", "oracle", "delegate"):
            self.assert_service_disables_core_dumps("docker-compose.all.phala.yaml", service)

    def test_dstack_diligence_hardening_replaces_duplicate_phala_list(self):
        overlay = _service_block(
            (ROOT / "docker-compose.all.dstack.yaml").read_text(),
            "diligence-policy-init",
        )
        phala = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "diligence-policy-init",
        )

        self.assertIn("security_opt: !override", overlay)
        self.assertEqual(overlay.count("- no-new-privileges:true"), 1)
        self.assertEqual(phala.count("- no-new-privileges:true"), 1)

    def test_dstack_overlays_run_one_internal_fail_closed_arena_worker(self):
        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                compose = (ROOT / compose_name).read_text()
                self.assertEqual(compose.count("\n  arena-policy-init:"), 1)
                self.assertEqual(compose.count("\n  arena-worker:"), 1)
                provisioner = _service_block(compose, "arena-policy-init")
                worker = _service_block(compose, "arena-worker")
                delegate = _service_block(compose, "delegate")

                self.assertIn('command: ["tinker-arena-provision"]', provisioner)
                self.assertIn('restart: "no"', provisioner)
                self.assertIn("network_mode: none", provisioner)
                self.assertIn("read_only: true", provisioner)
                self.assertIn("cap_drop:", provisioner)
                self.assertIn("- ALL", provisioner)
                self.assertIn("no-new-privileges:true", provisioner)
                self.assertIn("ulimits:", provisioner)
                self.assertIn("core: 0", provisioner)
                self.assertNotIn("ports:", provisioner)
                self.assertNotIn("expose:", provisioner)
                self.assertNotIn("networks:", provisioner)
                self.assertIn("arena-worker-sealed:/sealed", provisioner)
                self.assertNotIn("arena-worker-sealed:/sealed:ro", provisioner)
                self.assertNotIn("delegate-data", provisioner)
                self.assertNotIn("dstack.sock", provisioner)
                self.assertNotIn("TINKER_RUNTIME_AUTH_TOKEN", provisioner)
                self.assertNotIn("TINKER_ARENA_WORKER_QVL_AUTH_TOKEN", provisioner)
                for variable in (
                    "TINKER_ARENA_PROVISION_RELEASE_B64",
                    "TINKER_ARENA_PROVISION_EVALUATOR_B64",
                    "TINKER_ARENA_PROVISION_RELEASE_SHA256",
                    "TINKER_ARENA_PROVISION_EVALUATOR_SHA256",
                    "TINKER_ARENA_PROVISION_AUTH_KEY_B64",
                    "TINKER_ARENA_PROVISION_AUTH_TAG",
                ):
                    line = next(
                        item
                        for item in provisioner.splitlines()
                        if item.strip().startswith(f"{variable}:")
                    )
                    self.assertIn(": ${", line)
                    self.assertIn(":?", line)

                self.assertIn('command: ["tinker-arena-worker"]', worker)
                self.assertIn("ulimits:", worker)
                self.assertIn("core: 0", worker)
                self.assertNotIn("ports:", worker)
                self.assertNotIn("expose:", worker)
                self.assertIn("arena-policy-init:", worker)
                self.assertIn("condition: service_completed_successfully", worker)
                self.assertIn("delegate:", worker)
                self.assertIn("condition: service_healthy", worker)
                self.assertIn("delegate-data:/data", worker)
                self.assertIn("arena-worker-sealed:/sealed:ro", worker)
                self.assertNotIn("arena-worker-sealed", delegate)
                self.assertNotIn("TINKER_ARENA_PROVISION_", delegate)
                self.assertNotIn("TINKER_ARENA_PROVISION_", worker)
                self.assertIn(
                    "/var/run/dstack.sock:/var/run/dstack.sock",
                    worker,
                )
                self.assertIn('DSTACK_ENABLED: "true"', worker)
                self.assertIn('DSTACK_SIMULATOR_ENDPOINT: ""', worker)
                self.assertIn('TINKER_RUNTIME_AUTH_REQUIRED: "true"', delegate)
                self.assertNotIn("TINKER_RUNTIME_AUTH_TOKEN", worker)
                self.assertIn(
                    'TINKER_ARENA_CANDIDATE_INGRESS_LOCAL_KEY_FILE: ""',
                    worker,
                )
                self.assertIn(
                    'TINKER_ARENA_CANDIDATE_INGRESS_PRIVATE_KEY_HEX: ""',
                    worker,
                )
                self.assertIn(
                    'TINKER_ARENA_WORKER_QVL_VERDICT_PATH: ""',
                    worker,
                )
                self.assertIn(
                    "TINKER_ARENA_WORKER_QVL_VERDICT_URL: "
                    "${TINKER_ARENA_WORKER_QVL_VERDICT_URL:?",
                    worker,
                )
                self.assertIn(
                    "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN: "
                    "${TINKER_ARENA_WORKER_QVL_AUTH_TOKEN:?",
                    worker,
                )
                self.assertIn("/sealed/arena/release-v2.json", worker)
                self.assertIn(
                    "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256: "
                    "${TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256:?",
                    worker,
                )
                self.assertIn(
                    "/sealed/arena/sealed-evaluator-v1.json",
                    worker,
                )
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS: "
                    "${TINKER_EXECUTION_POLICY_APPROVED_SIGNERS:?",
                    worker,
                )
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN: "
                    "${TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN:?",
                    worker,
                )
                self.assertIn(
                    "TINKER_CHAIN_RPC_URL: ${TINKER_CHAIN_RPC_URL:?",
                    worker,
                )
                self.assertNotIn("quote_sha256", worker.lower())
                self.assertNotIn("--verified", worker)

    def test_narrow_dstack_arena_runtime_uses_only_code_owned_release_aliases(self):
        compose = (ROOT / "docker-compose.dstack.yaml").read_text()
        provisioner = _service_block(compose, "arena-policy-init")
        worker = _service_block(compose, "arena-worker")
        delegate = _service_block(compose, "delegate")
        anchor = _service_block(compose, "anchor-writer-evidence")
        compute = _service_block(compose, "compute-execution-worker")

        self.assertIn('profiles: ["arena-runtime"]', provisioner)
        self.assertIn('profiles: ["arena-runtime"]', worker)
        self.assertIn('profiles: ["anchor-writer-ceremony"]', anchor)
        self.assertIn('profiles: ["compute-execution"]', compute)
        self.assertNotIn("COMPOSE_PROFILES", compose)
        self.assertNotIn("\n  deal-runtime:", compose)

        expected_worker_environment = {
            "TINKER_MAIN_RUNTIME_CVM_ID": (
                "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}"
            ),
            "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256": (
                "${TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:?Signed seven-CVM deployment intent required}"
            ),
            "TINKER_RELEASE_AUTHORITY_SHA256": (
                "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:?Canonical release authority required}"
            ),
            "TINKER_RELEASE_CEREMONY_NONCE": (
                "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}"
            ),
            "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256": (
                "${TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256:?Linked Arena QVL measurement policy required}"
            ),
            "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
                "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:?Authorized ChallengeRegistry challenge-set digest required}"
            ),
            "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": '"true"',
        }
        for name, value in expected_worker_environment.items():
            with self.subTest(service="arena-worker", name=name):
                self.assertEqual(
                    _environment_assignments(worker, name),
                    [f"{name}: {value}"],
                )

        for name, value in {
            "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
                "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:?Authorized ChallengeRegistry challenge-set digest required}"
            ),
            "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": '"true"',
            "TINKER_ARENA_WORKER_HEARTBEAT_PATH": (
                "/data/arena_worker_heartbeat.json"
            ),
            "TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS": (
                "${TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS:-30}"
            ),
            "TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH": (
                "${TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH:-tinker/arena_worker_heartbeat}"
            ),
            "TINKER_ARENA_WORKER_HEARTBEAT_INTEGRITY_KEY": '""',
        }.items():
            with self.subTest(service="delegate", name=name):
                self.assertEqual(
                    _environment_assignments(delegate, name),
                    [f"{name}: {value}"],
                )

    def test_local_compose_does_not_start_production_arena_worker(self):
        for compose_name in ("docker-compose.yaml", "docker-compose.all.yaml"):
            with self.subTest(compose_name=compose_name):
                compose = (ROOT / compose_name).read_text()
                self.assertNotIn("  arena-worker:", compose)

    def test_local_delegate_defaults_match_the_vite_wallet_auth_contract(self):
        for compose_name in ("docker-compose.yaml", "docker-compose.all.yaml"):
            with self.subTest(compose_name=compose_name):
                delegate = _service_block(
                    (ROOT / compose_name).read_text(),
                    "delegate",
                )
                self.assertIn(
                    "TINKER_CORS_ALLOWED_ORIGINS: "
                    "${TINKER_CORS_ALLOWED_ORIGINS:-http://127.0.0.1:5175,"
                    "http://localhost:5175}",
                    delegate,
                )
                self.assertIn(
                    "TINKER_WALLET_AUTH_DOMAIN: "
                    "${TINKER_WALLET_AUTH_DOMAIN:-www.wikigen.me}",
                    delegate,
                )
                self.assertIn(
                    "TINKER_WALLET_AUTH_URI: "
                    "${TINKER_WALLET_AUTH_URI:-https://www.wikigen.me}",
                    delegate,
                )
                self.assertNotIn("http://localhost:3000", delegate)
                self.assertNotIn("dnai-wikigen-local", delegate)

    def test_primary_phala_does_not_reuse_stale_digest_for_arena_worker(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()

        self.assertIn("ARENA RELEASE GATE", compose)
        self.assertIn("predates the", compose)
        self.assertIn("tinker-arena-worker module/entrypoint", compose)
        self.assertIn("tinker-arena-provision initializer", compose)
        self.assertNotIn("  arena-worker:", compose)
        self.assertNotIn("  arena-policy-init:", compose)

    def test_phala_browser_is_project_owned_digest_pinned_and_internal_only(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()
        neko = _service_block(compose, "neko")
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("ghcr.io/g-structure/dnai-wikigen/neko-chrome@sha256:", neko)
        self.assertIn("not release-eligible for a new source SHA", neko)
        self.assertIn("rebuild from a reproducible", neko)
        self.assertNotIn("ghcr.io/m1k1o/neko/", neko)
        self.assertNotIn("mcr.microsoft.com/playwright", compose)
        self.assertNotIn("  delegate-browser:", compose)
        self.assertNotIn("ports:", neko)
        self.assertNotIn('"52000:8080"', compose)
        self.assertNotIn('"9222:9222"', compose)
        self.assertNotIn('"9222:9223"', compose)
        self.assertIn("ORACLE_CDP_URL: http://172.20.0.3:9222", oracle)
        self.assertIn('TINKER_BROWSER_WS_ENDPOINT: ""', delegate)
        self.assertIn("TINKER_CDP_URL: http://172.20.0.3:9222", delegate)

    def test_primary_phala_exposes_delegate_but_keeps_oracle_internal_only(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertNotIn("ports:", oracle)
        self.assertNotIn('"8000:8000"', compose)
        self.assertIn("ports:", delegate)
        self.assertIn('"8080:8080"', delegate)
        self.assertIn("TINKER_ORACLE_URL: http://172.20.0.4:8000", delegate)

    def test_phala_neko_credentials_are_required_and_default_values_fail_closed(self):
        neko = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "neko",
        )

        self.assertIn("${NEKO_PASSWORD:?", neko)
        self.assertIn("${NEKO_PASSWORD_ADMIN:?", neko)
        self.assertNotIn("${NEKO_PASSWORD:-neko}", neko)
        self.assertNotIn("${NEKO_PASSWORD_ADMIN:-admin}", neko)
        self.assertIn('"$${NEKO_PASSWORD}" = "neko"', neko)
        self.assertIn('"$${NEKO_PASSWORD_ADMIN}" = "admin"', neko)
        self.assertIn('"$${NEKO_PASSWORD}" = "$${NEKO_PASSWORD_ADMIN}"', neko)
        self.assertIn("refusing default Neko credentials", neko)
        self.assertIn("refusing identical Neko user and administrator credentials", neko)
        self.assertIn("exit 78", neko)

    def test_delegate_run_metadata_store_is_under_data_volume(self):
        for compose_name in (
            "docker-compose.yaml",
            "docker-compose.dstack.yaml",
            "docker-compose.all.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
            "docker-compose.selector-diagnostics.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn("TINKER_RUN_METADATA_STORE_PATH: /data/run_metadata.enc", block)

        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
            "docker-compose.selector-diagnostics.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn("TINKER_RUN_METADATA_KEY_PATH", block)
                self.assertIn("tinker/run_metadata", block)

    def test_delegate_browser_session_store_is_under_data_volume(self):
        for compose_name in (
            "docker-compose.yaml",
            "docker-compose.dstack.yaml",
            "docker-compose.all.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
            "docker-compose.mailbox-genesis.phala.yaml",
            "docker-compose.tinker-bootstrap.phala.yaml",
            "docker-compose.tinker-funding-validation.phala.yaml",
            "docker-compose.selector-diagnostics.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn("TINKER_BROWSER_SESSION_STORE_PATH: /data/browser_session.enc", block)

        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
            "docker-compose.mailbox-genesis.phala.yaml",
            "docker-compose.tinker-bootstrap.phala.yaml",
            "docker-compose.tinker-funding-validation.phala.yaml",
            "docker-compose.selector-diagnostics.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn("TINKER_BROWSER_SESSION_KEY_PATH", block)
                self.assertIn("tinker/browser_session", block)

    def test_delegate_funding_mode_defaults_to_manual_prefund(self):
        for compose_name in (
            "docker-compose.yaml",
            "docker-compose.dstack.yaml",
            "docker-compose.all.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
            "docker-compose.selector-diagnostics.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn("TINKER_FUNDING_MODE: ${TINKER_FUNDING_MODE:-manual_prefund}", block)

    def test_execution_policy_store_and_independent_roots_are_wired(self):
        for compose_name in (
            "docker-compose.yaml",
            "docker-compose.dstack.yaml",
            "docker-compose.all.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_STORE_PATH:", block
                )
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY_PATH:", block
                )
                self.assertIn(
                    "tinker/execution_policy_store_integrity", block
                )
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS:", block
                )
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN:", block
                )

        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                block = _service_block((ROOT / compose_name).read_text(), "delegate")
                self.assertIn(
                    'TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY: ""',
                    block,
                )

    def test_execution_policy_anchor_is_wired_without_worker_signing_custody(self):
        public_anchor_settings = (
            "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL",
            "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS",
            "TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
            "TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS",
            "TINKER_EXECUTION_POLICY_ANCHOR_POLL_INTERVAL_SECONDS",
            "TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATION_WAIT_SECONDS",
            "TINKER_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS",
            "TINKER_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS",
        )
        compose_names = (
            "docker-compose.yaml",
            "docker-compose.dstack.yaml",
            "docker-compose.all.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
        )
        for compose_name in compose_names:
            with self.subTest(compose_name=compose_name, service="delegate"):
                delegate = _service_block(
                    (ROOT / compose_name).read_text(), "delegate"
                )
                for variable in public_anchor_settings:
                    self.assertIn(f"{variable}:", delegate)
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH: "
                    "${TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH:-"
                    "tinker/execution_policy_anchor_writer}",
                    delegate,
                )

        required_worker_release_pins = public_anchor_settings[:5]
        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
        ):
            with self.subTest(compose_name=compose_name, service="arena-worker"):
                worker = _service_block(
                    (ROOT / compose_name).read_text(), "arena-worker"
                )
                for variable in public_anchor_settings:
                    self.assertIn(f"{variable}:", worker)
                for variable in required_worker_release_pins:
                    line = next(
                        item
                        for item in worker.splitlines()
                        if item.strip().startswith(f"{variable}:")
                    )
                    self.assertIn(":?", line)
                self.assertNotIn(
                    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH",
                    worker,
                )
                self.assertNotIn(
                    "TINKER_EXECUTION_POLICY_ANCHOR_PRIVATE_KEY",
                    worker,
                )

    def test_anchor_writer_qvl_ceremony_is_profile_gated_and_secret_isolated(self):
        secret = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"
        required_release_fields = (
            "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_URL",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_VERIFIER_ADDRESS",
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_RELEASE_POLICY_HASH",
            secret,
        )
        for compose_name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
        ):
            with self.subTest(compose_name=compose_name):
                compose = (ROOT / compose_name).read_text()
                self.assertEqual(compose.count("\n  anchor-writer-evidence:"), 1)
                ceremony = _service_block(compose, "anchor-writer-evidence")

                self.assertIn('profiles: ["anchor-writer-ceremony"]', ceremony)
                self.assertIn(
                    'command: ["tinker-execution-policy-anchor-writer"]',
                    ceremony,
                )
                self.assertIn('restart: "no"', ceremony)
                self.assertIn("read_only: true", ceremony)
                self.assertIn("cap_drop:", ceremony)
                self.assertIn("- ALL", ceremony)
                self.assertIn("no-new-privileges:true", ceremony)
                self.assertIn("ulimits:", ceremony)
                self.assertIn("core: 0", ceremony)
                self.assertNotIn("ports:", ceremony)
                self.assertNotIn("expose:", ceremony)
                self.assertIn(
                    "/var/run/dstack.sock:/var/run/dstack.sock",
                    ceremony,
                )
                self.assertNotIn("- delegate-data:", ceremony)
                self.assertNotIn("- arena-worker-sealed:", ceremony)
                self.assertNotIn("/data", ceremony)
                self.assertNotIn("/sealed", ceremony)
                self.assertIn('DSTACK_ENABLED: "true"', ceremony)
                self.assertIn('DSTACK_SIMULATOR_ENDPOINT: ""', ceremony)
                self.assertIn(
                    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH: "
                    "${TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH:-"
                    "tinker/execution_policy_anchor_writer}",
                    ceremony,
                )
                for variable in required_release_fields:
                    line = next(
                        item
                        for item in ceremony.splitlines()
                        if item.strip().startswith(f"{variable}:")
                    )
                    self.assertIn(":?", line)

                for long_running_service in (
                    "delegate",
                    "arena-worker",
                    "compute-execution-worker",
                ):
                    self.assertNotIn(
                        secret,
                        _service_block(compose, long_running_service),
                    )

        example_env = (ROOT.parents[1] / "example.env").read_text()
        self.assertEqual(example_env.count(f"{secret}="), 1)
        self.assertNotIn("TINKER_EXECUTION_POLICY_ANCHOR_PRIVATE_KEY", example_env)

    def test_pinned_phala_truthfully_blocks_writer_ceremony_until_new_digest(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()
        stale_digest = (
            "sha256:262938c3620a2c4931b7ff0e5da1f321e564e2deade4550bd41104a3885f0b98"
        )
        self.assertIn("ANCHOR-WRITER EVIDENCE RELEASE GATE", compose)
        self.assertIn(stale_digest, compose)
        self.assertNotIn("\n  anchor-writer-evidence:", compose)
        self.assertNotIn(
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN",
            _service_block(compose, "delegate"),
        )
        for required_step in (
            "publish/prove a new linux/amd64 delegate image in clean CI",
            "pin its literal",
            "isolated profile-gated one-shot service",
        ):
            self.assertIn(required_step, compose)

        runbook = (ROOT / "docs" / "DEPLOYMENT-RUNBOOK.md").read_text()
        anchor_docs = (ROOT / "docs" / "EXECUTION-POLICY-ANCHOR.md").read_text()
        for document in (runbook, anchor_docs):
            self.assertIn(stale_digest, document)
            self.assertIn("clean CI", document)
            self.assertIn("linux/amd64", document)
            self.assertIn("literal `repository@sha256:<digest>`", document)
            self.assertIn("anchor-writer-evidence", document)
            self.assertIn("Phala encrypted", document)

    def test_phala_delegate_does_not_bootstrap_signup_by_default(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "delegate",
        )

        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "false"', block)
        self.assertIn('TINKER_BOOTSTRAP_FAIL_OPEN: "false"', block)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "false"', block)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "false"', block)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "false"', block)

    def test_phala_delegate_enforces_runtime_wallet_and_cors_boundaries(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "delegate",
        )

        self.assertIn('TINKER_RUNTIME_AUTH_REQUIRED: "true"', block)
        self.assertIn("TINKER_RUNTIME_AUTH_KEY_PATH", block)
        self.assertIn("TINKER_CORS_ALLOWED_ORIGINS", block)
        self.assertIn("TINKER_WALLET_AUTH_KEY_PATH", block)
        self.assertIn("tinker/wallet_auth", block)
        self.assertIn("TINKER_WALLET_AUTH_CHAIN_ID", block)
        self.assertIn("84532", block)
        self.assertIn("TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS", block)
        self.assertNotIn("TINKER_WALLET_AUTH_SIGNING_KEY", block)

    def test_phala_oracle_credential_provisioning_is_disabled_by_default(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "oracle",
        )

        self.assertIn('ORACLE_AUTO_GENESIS: "false"', block)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', block)
        self.assertIn('ORACLE_CREDENTIAL_PROVISIONING_TOKEN: ""', block)

    def test_oracle_operator_docs_preserve_release_gate_and_rollback_residual(self):
        runbook = (ROOT / "docs" / "DEPLOYMENT-RUNBOOK.md").read_text()
        scope = (ROOT / "docs" / "ORACLE-AUTH-SCOPE.md").read_text()

        for document in (runbook, scope):
            self.assertIn("tinker-delegate.signup", document)
            self.assertIn("/data/email_auth_checkpoint.json", document)
            self.assertIn("84532", document)
            self.assertIn("900 seconds", document)
            self.assertIn("30 seconds", document)
            self.assertIn("persistent volume", document.lower())
            self.assertIn("hardware", document.lower())

        for variable in (
            "BASE_SEPOLIA_RPC_URL_SECONDARY",
            "EMAIL_ORACLE_AUTH_ADDRESS",
            "EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH",
            "EMAIL_ORACLE_CONSUMER_APP_ID",
            "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
        ):
            self.assertIn(variable, runbook)

        self.assertIn("same normalized host", runbook)
        self.assertIn("different normalized hosts", scope)
        self.assertIn(
            "signature, quote, or independently proven service identity",
            scope,
        )
        self.assertIn("not hardware-backed anti-rollback", runbook)

    def test_phala_deploy_critical_images_are_quote_bound_literals(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()
        neko = _service_block(compose, "neko")
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("ghcr.io/g-structure/dnai-wikigen/neko-chrome@sha256:", neko)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
        self.assertNotIn("${NEKO_IMAGE", neko)
        self.assertNotIn("${TINKER_ORACLE_IMAGE", oracle)
        self.assertNotIn("${TINKER_DELEGATE_IMAGE", delegate)

    def test_oracle_genesis_debug_compose_has_bounded_scope(self):
        compose = (ROOT / "docker-compose.oracle-genesis-debug.phala.yaml").read_text()
        oracle = _service_block(compose, "oracle")
        neko = _service_block(compose, "neko")

        self.assertIn("TEMPORARY DEBUG ONLY", compose)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("google-chrome@sha256:", neko)
        self.assertNotIn("  delegate:", compose)
        self.assertNotIn("  delegate-browser:", compose)
        self.assertIn('ORACLE_AUTO_GENESIS: "true"', oracle)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', oracle)
        self.assertIn('ORACLE_CREDENTIAL_PROVISIONING_TOKEN: ""', oracle)

    def test_mailbox_genesis_compose_keeps_tinker_and_billing_disabled(self):
        compose = (ROOT / "docker-compose.mailbox-genesis.phala.yaml").read_text()
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("Temporary Main-CVM Mailbox Genesis Compose", compose)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
        self.assertIn('ORACLE_AUTO_GENESIS: "true"', oracle)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', oracle)
        self.assertIn('ORACLE_CREDENTIAL_PROVISIONING_TOKEN: ""', oracle)
        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "false"', delegate)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "false"', delegate)

    def test_tinker_bootstrap_compose_only_enables_tinker_bootstrap(self):
        compose = (ROOT / "docker-compose.tinker-bootstrap.phala.yaml").read_text()
        neko = _service_block(compose, "neko")
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("Temporary Main-CVM Tinker Bootstrap Compose", compose)
        self.assertIn("neko-chrome@sha256:", neko)
        self.assertNotIn("google-chrome@sha256:", neko)
        self.assertNotIn("cdp_proxy.py", neko)
        self.assertIn('"9222:9222"', neko)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
        self.assertNotIn("  delegate-browser:", compose)
        self.assertNotIn("delegate-browser:", delegate)
        self.assertIn('ORACLE_AUTO_GENESIS: "false"', oracle)
        self.assertIn("ORACLE_CDP_URL: http://172.20.0.3:9222", oracle)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', oracle)
        self.assertIn('ORACLE_CREDENTIAL_PROVISIONING_TOKEN: ""', oracle)
        self.assertIn('TINKER_BROWSER_WS_ENDPOINT: ""', delegate)
        self.assertIn("TINKER_CDP_URL: http://172.20.0.3:9222", delegate)
        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "true"', delegate)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_BOOTSTRAP_FAIL_OPEN: "true"', delegate)
        self.assertIn('TINKER_LOCAL_BROWSER_FALLBACK: "false"', delegate)

    def test_tinker_funding_validation_compose_is_capped_and_auth_gated(self):
        compose = (ROOT / "docker-compose.tinker-funding-validation.phala.yaml").read_text()
        neko = _service_block(compose, "neko")
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("Temporary Main-CVM Tinker Funding Validation Compose", compose)
        self.assertIn("neko-chrome@sha256:", neko)
        self.assertNotIn("google-chrome@sha256:", neko)
        self.assertNotIn("cdp_proxy.py", neko)
        self.assertIn('"9222:9222"', neko)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
        self.assertNotIn("  delegate-browser:", compose)
        self.assertNotIn("mcr.microsoft.com/playwright", compose)
        self.assertIn('ORACLE_AUTO_GENESIS: "false"', oracle)
        self.assertIn('ORACLE_RUNTIME_AUTH_REQUIRED: "true"', oracle)
        self.assertIn("TINKER_CDP_URL: http://172.20.0.3:9222", delegate)
        self.assertIn('TINKER_RUNTIME_AUTH_REQUIRED: "true"', delegate)
        self.assertIn("TINKER_RUNTIME_AUTH_TOKEN: ${TINKER_RUNTIME_AUTH_TOKEN:-}", delegate)
        self.assertIn('TINKER_FUNDING_MODE: "operator_capped_validation"', delegate)
        self.assertIn('TINKER_MIN_ADD_BALANCE_USD: "10.0"', delegate)
        self.assertIn('TINKER_MAX_ADD_BALANCE_USD: "10.0"', delegate)
        self.assertIn("TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE: ${TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE:-false}", delegate)
        self.assertIn("TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY: ${TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY:-false}", delegate)
        self.assertIn("TINKER_PROXY_IDENTITY_REGISTRY_PATH: ${TINKER_PROXY_IDENTITY_REGISTRY_PATH:-/data/proxy_identity_registry.json}", delegate)
        self.assertIn("TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE: ${TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE:-false}", delegate)
        self.assertIn("TINKER_PROXY_IDENTITY_REGISTRY_SIGNER: ${TINKER_PROXY_IDENTITY_REGISTRY_SIGNER:-}", delegate)
        self.assertIn('TINKER_ENCUMBRANCE_REQUIRED: "true"', delegate)
        self.assertIn("TINKER_ENCUMBRANCE_COMPOSE_HASH: ${TINKER_ENCUMBRANCE_COMPOSE_HASH:-}", delegate)
        self.assertIn('TINKER_ALLOW_AUTH_AUTOMATION_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_ALLOW_PLAINTEXT_CARD_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "false"', delegate)
        self.assertIn('TINKER_BROWSER_WS_ENDPOINT: ""', delegate)

    def test_selector_diagnostics_compose_is_read_only_and_digest_pinned(self):
        compose = (ROOT / "docker-compose.selector-diagnostics.phala.yaml").read_text()
        neko = _service_block(compose, "neko")
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("Temporary Main-CVM Selector Diagnostics Compose", compose)
        self.assertIn("neko-chrome@sha256:", neko)
        self.assertNotIn("google-chrome@sha256:", neko)
        self.assertNotIn("cdp_proxy.py", neko)
        self.assertIn('"9222:9222"', neko)
        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
        self.assertNotIn("  delegate-browser:", compose)
        self.assertIn('ORACLE_AUTO_GENESIS: "false"', oracle)
        self.assertIn('ORACLE_RUNTIME_AUTH_REQUIRED: "true"', oracle)
        self.assertIn("ORACLE_CDP_URL: http://172.20.0.3:9222", oracle)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', oracle)
        self.assertIn('TINKER_RUNTIME_AUTH_REQUIRED: "true"', delegate)
        self.assertIn('TINKER_ALLOW_AUTH_AUTOMATION_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_PLAINTEXT_CARD_ENDPOINT: "false"', delegate)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "true"', delegate)
        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "false"', delegate)
        self.assertIn('TINKER_BROWSER_WS_ENDPOINT: ""', delegate)
        self.assertIn("TINKER_CDP_URL: http://172.20.0.3:9222", delegate)


if __name__ == "__main__":
    unittest.main()
