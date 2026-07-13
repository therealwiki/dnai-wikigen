from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


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


class ComposeHardeningTest(unittest.TestCase):
    def assert_service_disables_core_dumps(self, compose_name: str, service_name: str):
        compose = (ROOT / compose_name).read_text()
        block = _service_block(compose, service_name)

        self.assertIn("ulimits:", block)
        self.assertIn("core: 0", block)

    def test_local_delegate_compose_disables_core_dumps(self):
        self.assert_service_disables_core_dumps("docker-compose.yaml", "delegate")

    def test_all_in_one_local_compose_disables_core_dumps(self):
        for service in ("neko", "oracle", "delegate"):
            self.assert_service_disables_core_dumps("docker-compose.all.yaml", service)

    def test_phala_compose_disables_core_dumps(self):
        for service in ("neko", "oracle", "delegate", "delegate-browser"):
            self.assert_service_disables_core_dumps("docker-compose.all.phala.yaml", service)

    def test_phala_playwright_sidecar_is_digest_pinned(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "delegate-browser",
        )

        self.assertIn(
            "mcr.microsoft.com/playwright:v1.58.0-noble@sha256:",
            block,
        )

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

    def test_phala_delegate_does_not_bootstrap_signup_by_default(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "delegate",
        )

        self.assertIn('TINKER_BOOTSTRAP_SIGNUP: "false"', block)
        self.assertIn('TINKER_ALLOW_ADD_BALANCE_ENDPOINT: "false"', block)
        self.assertIn('TINKER_ALLOW_BROWSER_READINESS_ENDPOINT: "false"', block)
        self.assertIn('TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT: "false"', block)

    def test_phala_oracle_credential_provisioning_is_disabled_by_default(self):
        block = _service_block(
            (ROOT / "docker-compose.all.phala.yaml").read_text(),
            "oracle",
        )

        self.assertIn('ORACLE_AUTO_GENESIS: "false"', block)
        self.assertIn('ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT: "false"', block)
        self.assertIn('ORACLE_CREDENTIAL_PROVISIONING_TOKEN: ""', block)

    def test_phala_deploy_critical_images_are_quote_bound_literals(self):
        compose = (ROOT / "docker-compose.all.phala.yaml").read_text()
        oracle = _service_block(compose, "oracle")
        delegate = _service_block(compose, "delegate")

        self.assertIn("tee-email-oracle@sha256:", oracle)
        self.assertIn("tinker-delegate@sha256:", delegate)
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
