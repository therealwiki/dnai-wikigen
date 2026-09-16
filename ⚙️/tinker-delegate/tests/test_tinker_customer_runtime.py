from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from eth_hash.auto import keccak

from tinker_delegate.execution_policy_anchor import ZERO_BYTES32
from tinker_delegate.tinker_customer_adapter import (
    AttestedProvisioningResult,
    AttestedSettlementResult,
    CustomerAccountPolicy,
    CustomerStateAnchorHead,
    ExpectedTinkerRelease,
    RuntimeEvidence,
    RuntimeEvidencePolicy,
    TinkerCustomerAdapter,
    TinkerCustomerStore,
)
from tinker_delegate.tinker_customer_runtime import (
    ExecutionPolicyCustomerStateAnchor,
    SignedProvisioningResultProvider,
    SignedRuntimeEvidenceProvider,
    SignedSettlementResultProvider,
    TINKER_CUSTOMER_PROVISIONING_SCHEMA,
    TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
    TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA,
    TINKER_CUSTOMER_SETTLEMENT_SCHEMA,
    TinkerCustomerRuntimeError,
    _load_authority,
    build_tinker_customer_adapter,
)


NOW = 1_900_000_000
ACCOUNT_ID = "tca_" + "11" * 12
RESERVATION_ID = "tcr_" + "22" * 12


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _write_private(path: Path, value: object) -> bytes:
    raw = _canonical_json(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def _write_signed(
    path: Path,
    *,
    schema: str,
    private_key: Ed25519PrivateKey,
    payload: dict,
) -> None:
    public_key = _public_key(private_key)
    message = (schema + "\0").encode("ascii") + _canonical_json(payload)
    _write_private(
        path,
        {
            "schema": schema,
            "signer_public_key_hash": (
                "sha256:" + hashlib.sha256(public_key).hexdigest()
            ),
            "payload": payload,
            "signature": private_key.sign(message).hex(),
        },
    )


def _runtime_evidence() -> RuntimeEvidence:
    return RuntimeEvidence(
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        cvm_id_hash=_digest("cvm"),
        measurement_hash=_digest("measurement"),
        qvl_policy_hash=_digest("qvl"),
        release_authority_digest=_digest("release-authority"),
        roles_digest=_digest("roles"),
        customer_policy_digest=_digest("customer-policy"),
        release_policy_tuple_digest=_digest("release-policy-tuple"),
        account_commitment="0x" + "33" * 32,
        compose_hash="0x" + "44" * 32,
        manager="0x" + "55" * 20,
        enabled_operations=("training",),
        tdx_verified=True,
        qvl_pass=True,
    )


def _provisioning_result(
    account_id: str = ACCOUNT_ID,
) -> AttestedProvisioningResult:
    return AttestedProvisioningResult(
        account_id=account_id,
        request_commitment=_digest("request"),
        owner_address_hash=_digest("owner"),
        mode="create",
        account_commitment="0x" + "33" * 32,
        release_policy_tuple_digest=_digest("release-policy-tuple"),
        compose_hash="0x" + "44" * 32,
        manager="0x" + "55" * 20,
        provisioning_receipt_hash=_digest("provisioning-receipt"),
        runtime_evidence_digest=_digest("runtime-evidence"),
        account_binding_schema="dnai.tinker-account-binding.v1",
        account_binding_version=1,
        account_binding_chain_id=84_532,
        account_binding_type="TinkerAccountBinding",
        account_binding_typehash="0x" + "66" * 32,
        provider_namespace_label="tinker",
        provider_namespace="0x" + "77" * 32,
        account_binding_receipt_digest=_digest("binding-receipt"),
        sealed_binding_record_hash=_digest("sealed-binding"),
        account_binding_ceremony_receipt_digest=_digest("binding-ceremony"),
        deployment_intent_digest=_digest("deployment-intent"),
        account_binding_receipt_independently_attested=True,
        account_binding_handle_attested=True,
        provider_identity_checked=True,
        current_provider_session_rechecked=True,
        account_commitment_exact_match=True,
        provider_internal_identity_cryptographically_proven=False,
        raw_provider_account_id_egress=False,
        raw_binding_root_egress=False,
        raw_reviewer_share_egress=False,
        binding_root_or_share_digest_published=False,
        raw_provider_auth_egress=False,
        raw_provider_session_egress=False,
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        success=True,
        upstream_account_exists=True,
        raw_account_identifier_returned=False,
        raw_secret_egress=False,
    )


def _settlement_result(
    reservation_id: str = RESERVATION_ID,
) -> AttestedSettlementResult:
    return AttestedSettlementResult(
        reservation_id=reservation_id,
        reservation_commitment=_digest("reservation"),
        outcome="settled",
        actual_policy_units=50,
        usage_receipt_hash=_digest("usage"),
        release_policy_tuple_digest=_digest("release-policy-tuple"),
        runtime_evidence_digest=_digest("runtime-evidence"),
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        provider_dispatch_performed=True,
    )


class SignedCustomerEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_runtime_evidence_requires_exact_valid_signature(self):
        key = Ed25519PrivateKey.generate()
        path = self.root / "runtime.json"
        evidence = _runtime_evidence()
        _write_signed(
            path,
            schema=TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA,
            private_key=key,
            payload=asdict(evidence),
        )
        provider = SignedRuntimeEvidenceProvider(path, _public_key(key))

        self.assertEqual(provider.read(now=NOW), evidence)

        envelope = json.loads(path.read_text())
        envelope["payload"]["tdx_verified"] = False
        _write_private(path, envelope)
        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "signature is invalid",
        ):
            provider.read(now=NOW)

    def test_private_evidence_rejects_group_readability(self):
        key = Ed25519PrivateKey.generate()
        path = self.root / "runtime.json"
        _write_signed(
            path,
            schema=TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA,
            private_key=key,
            payload=asdict(_runtime_evidence()),
        )
        path.chmod(0o640)

        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "metadata is invalid",
        ):
            SignedRuntimeEvidenceProvider(
                path,
                _public_key(key),
            ).read(now=NOW)

    def test_provisioning_and_settlement_results_are_identity_bound(self):
        provisioning_key = Ed25519PrivateKey.generate()
        settlement_key = Ed25519PrivateKey.generate()
        provisioning_dir = self.root / "provisioning"
        settlement_dir = self.root / "settlement"
        provisioning_dir.mkdir(mode=0o700)
        settlement_dir.mkdir(mode=0o700)
        provisioning = _provisioning_result()
        settlement = _settlement_result()
        _write_signed(
            provisioning_dir / f"{ACCOUNT_ID}.json",
            schema=TINKER_CUSTOMER_PROVISIONING_SCHEMA,
            private_key=provisioning_key,
            payload=asdict(provisioning),
        )
        _write_signed(
            settlement_dir / f"{RESERVATION_ID}.json",
            schema=TINKER_CUSTOMER_SETTLEMENT_SCHEMA,
            private_key=settlement_key,
            payload=asdict(settlement),
        )

        provisioner = SignedProvisioningResultProvider(
            provisioning_dir,
            _public_key(provisioning_key),
        )
        settler = SignedSettlementResultProvider(
            settlement_dir,
            _public_key(settlement_key),
        )
        self.assertEqual(
            provisioner.consume(
                account_id=ACCOUNT_ID,
                request_commitment=_digest("request"),
                now=NOW,
            ),
            provisioning,
        )
        self.assertEqual(
            settler.consume(
                reservation_id=RESERVATION_ID,
                reservation_commitment=_digest("reservation"),
                now=NOW,
            ),
            settlement,
        )

        wrong = _provisioning_result("tca_" + "99" * 12)
        _write_signed(
            provisioning_dir / f"{ACCOUNT_ID}.json",
            schema=TINKER_CUSTOMER_PROVISIONING_SCHEMA,
            private_key=provisioning_key,
            payload=asdict(wrong),
        )
        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "identity differs",
        ):
            provisioner.consume(
                account_id=ACCOUNT_ID,
                request_commitment=_digest("request"),
                now=NOW,
            )

    def test_signed_training_result_recovers_partial_settlement_without_rewrite(
        self,
    ):
        settlement_key = Ed25519PrivateKey.generate()
        settlement_dir = self.root / "settlement-recovery"
        settlement_dir.mkdir(mode=0o700)
        provider = SignedSettlementResultProvider(
            settlement_dir,
            _public_key(settlement_key),
            signing_key=settlement_key,
        )
        settlement = _settlement_result()
        training_result = {
            "surface": "tinker_customer_training_result",
            "schema_version": 1,
            "success": True,
            "outcome": "training_completed",
            "raw_secret_egress": False,
        }

        provider.publish_training_result(
            settlement=settlement,
            training_result=training_result,
        )
        training_path = (
            settlement_dir / f"{RESERVATION_ID}.training.json"
        )
        settlement_path = settlement_dir / f"{RESERVATION_ID}.json"
        signed_training = training_path.read_bytes()
        settlement_path.unlink()

        recovered = provider.ensure_settlement_projection(
            reservation_id=RESERVATION_ID,
            reservation_commitment=settlement.reservation_commitment,
        )

        self.assertEqual(recovered["settlement"], settlement)
        self.assertEqual(recovered["training_result"], training_result)
        self.assertEqual(training_path.read_bytes(), signed_training)
        self.assertEqual(
            provider.consume(
                reservation_id=RESERVATION_ID,
                reservation_commitment=settlement.reservation_commitment,
                now=NOW,
            ),
            settlement,
        )
        provider.publish_training_result(
            settlement=settlement,
            training_result=training_result,
        )
        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "replay differs",
        ):
            provider.publish_training_result(
                settlement=settlement,
                training_result={
                    **training_result,
                    "success": False,
                },
            )

    def test_authority_document_is_exact_private_and_sha256_pinned(self):
        authority = {
            "schema": TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
            "status": "enabled",
            "expected_release": {},
            "account_policy": {},
            "runtime_evidence_policy": {},
            "evidence": {},
        }
        path = self.root / "authority.json"
        raw = _write_private(path, authority)
        settings = SimpleNamespace(
            tinker_customer_authority_path=str(path),
            tinker_customer_authority_sha256=(
                "sha256:" + hashlib.sha256(raw).hexdigest()
            ),
        )

        self.assertEqual(_load_authority(settings), authority)

        settings.tinker_customer_authority_sha256 = _digest("wrong")
        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "SHA-256 differs",
        ):
            _load_authority(settings)
        authority["unreviewed"] = True
        raw = _write_private(path, authority)
        settings.tinker_customer_authority_sha256 = (
            "sha256:" + hashlib.sha256(raw).hexdigest()
        )
        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "fields are not exact",
        ):
            _load_authority(settings)

    def test_builder_assembles_only_from_the_pinned_authority(self):
        runtime_key = Ed25519PrivateKey.generate()
        provisioning_key = Ed25519PrivateKey.generate()
        settlement_secret = "e" * 32
        settlement_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(
                b"dnai-wikigen/tinker-customer-settlement-evidence/v1\0"
                + settlement_secret.encode("utf-8")
            ).digest()
        )
        provisioning_dir = self.root / "provisioning"
        settlement_dir = self.root / "settlement"
        provisioning_dir.mkdir(mode=0o700)
        settlement_dir.mkdir(mode=0o700)
        runtime_path = self.root / "runtime.json"
        _write_signed(
            runtime_path,
            schema=TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA,
            private_key=runtime_key,
            payload=asdict(_runtime_evidence()),
        )
        account_policy = CustomerAccountPolicy(
            allowed_operations=("training",),
            max_operation_policy_units=10**18,
            max_outstanding_policy_units=2 * 10**18,
            max_lifetime_policy_units=3 * 10**18,
            credential_max_ttl_seconds=600,
            max_active_credentials=2,
        )
        expected_release = ExpectedTinkerRelease(
            contract_address="0x" + "11" * 20,
            runtime_code_hash="0x" + keccak(bytes.fromhex("6001600055")).hex(),
            owner="0x" + "22" * 20,
            account_commitment="0x" + "33" * 32,
            account_binding_ceremony_receipt_digest=_digest(
                "binding-ceremony"
            ),
            deployment_intent_digest=_digest("deployment-intent"),
            release_policy_commitment="0x" + "44" * 32,
            approved_compose_root="0x" + "55" * 32,
            approved_compose_hashes=("0x" + "66" * 32,),
            manager_root="0x" + "77" * 32,
            managers=("0x" + "88" * 20,),
            max_add_balance_policy_units=10**19,
            max_spend_policy_units=5 * 10**18,
        )
        evidence_policy = RuntimeEvidencePolicy(
            cvm_id_hash=_digest("cvm"),
            measurement_hash=_digest("measurement"),
            qvl_policy_hash=_digest("qvl"),
            release_authority_digest=_digest("release-authority"),
            roles_digest=_digest("roles"),
            customer_policy_digest=account_policy.digest,
            enabled_operations=("training",),
        )
        authority = {
            "schema": TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
            "status": "enabled",
            "expected_release": asdict(expected_release),
            "account_policy": asdict(account_policy),
            "runtime_evidence_policy": asdict(evidence_policy),
            "evidence": {
                "runtime_evidence_path": str(runtime_path),
                "runtime_evidence_public_key": _public_key(runtime_key).hex(),
                "provisioning_directory": str(provisioning_dir),
                "provisioning_public_key": _public_key(
                    provisioning_key
                ).hex(),
                "settlement_directory": str(settlement_dir),
                "settlement_public_key": _public_key(settlement_key).hex(),
                "state_anchor_resource_hash": "99" * 32,
            },
        }
        authority_path = self.root / "authority.json"
        raw = _write_private(authority_path, authority)
        fake_gateway = _SharedSequenceGateway()
        fake_gateway.latest.global_sequence = 0
        fake_gateway.latest.global_head = ZERO_BYTES32
        settings = SimpleNamespace(
            tinker_customer_enabled=True,
            tinker_customer_authority_path=str(authority_path),
            tinker_customer_authority_sha256=(
                "sha256:" + hashlib.sha256(raw).hexdigest()
            ),
            tinker_customer_store_path=str(self.root / "customer-state.json"),
            tinker_customer_store_integrity_key="s" * 32,
            tinker_customer_store_integrity_key_path=(
                "tinker/customer_store_integrity"
            ),
            tinker_customer_credential_signing_key="c" * 32,
            tinker_customer_credential_key_path="tinker/customer_credentials",
            tinker_customer_settlement_signing_key=settlement_secret,
            tinker_customer_settlement_key_path=(
                "tinker/customer_settlement_evidence"
            ),
            encumbrance_contract_address=expected_release.contract_address,
            wallet_auth_rpc_url="https://rpc-a.example",
            wallet_auth_rpc_url_secondary="https://rpc-b.example",
            wallet_auth_rpc_timeout_seconds=1.0,
            wallet_auth_rpc_max_response_bytes=65_536,
        )
        wallet_verifier = object()

        with (
            patch(
                "tinker_delegate.tinker_customer_runtime."
                "HttpsExecutionPolicyAnchorGateway.from_settings",
                return_value=fake_gateway,
            ),
            patch(
                "tinker_delegate.tinker_customer_runtime."
                "verify_live_execution_policy_release_binding"
            ) as verify_binding,
            patch(
                "tinker_delegate.tinker_customer_runtime."
                "dstack_utils.is_dstack_enabled",
                return_value=False,
            ),
        ):
            adapter = build_tinker_customer_adapter(
                settings,
                wallet_verifier=wallet_verifier,
            )
        try:
            self.assertIsInstance(adapter, TinkerCustomerAdapter)
            self.assertIs(adapter.wallet_verifier, wallet_verifier)
            self.assertEqual(adapter.expected_release, expected_release)
            self.assertEqual(adapter.account_policy, account_policy)
            self.assertEqual(
                adapter.evidence_policy,
                evidence_policy,
            )
            verify_binding.assert_called_once_with(settings, fake_gateway)
        finally:
            os.close(adapter.store._directory_fd)


class _SharedSequenceGateway:
    def __init__(self) -> None:
        self.closed = False
        self.latest = SimpleNamespace(
            global_sequence=9,
            global_head="0x" + "aa" * 32,
            resource_decision_head=ZERO_BYTES32,
            resource_sequence=0,
        )
        self.records = []

    def finalized_snapshot(self, *, resource_id_hash: str):
        self.finalized_resource = resource_id_hash
        return self.latest

    def latest_snapshot(
        self,
        *,
        resource_id_hash: str,
        decision_hash: str,
    ):
        self.latest_resource = resource_id_hash
        self.latest_decision = decision_hash
        return self.latest

    def anchor_record(self, *, prefix, record):
        self.records.append((prefix, record))
        return SimpleNamespace(
            resource_decision_head="0x" + record.decision_hash,
            decision_hash=record.decision_hash,
        )

    def close(self) -> None:
        self.closed = True


class CustomerStateAnchorTest(unittest.TestCase):
    def test_shared_global_sequence_does_not_replace_local_store_sequence(self):
        gateway = _SharedSequenceGateway()
        resource = "88" * 32
        anchor = ExecutionPolicyCustomerStateAnchor(
            gateway,
            resource_id_hash=resource,
        )

        initial = anchor.read_head()
        successor = anchor.compare_and_set(
            expected_sequence=0,
            expected_head_hash="sha256:" + "00" * 32,
            new_sequence=1,
            new_head_hash="sha256:" + "99" * 32,
        )

        self.assertEqual(initial.sequence, 0)
        self.assertEqual(initial.head_hash, "sha256:" + "00" * 32)
        self.assertEqual(successor.sequence, 1)
        self.assertEqual(successor.head_hash, "sha256:" + "99" * 32)
        prefix, record = gateway.records[0]
        self.assertEqual(prefix.sequence, 9)
        self.assertEqual(record.sequence, 10)
        self.assertEqual(record.resource_id_hash, resource)
        self.assertEqual(record.decision_hash, "99" * 32)

        anchor.close()
        self.assertTrue(gateway.closed)

    def test_compare_and_set_rejects_a_different_committed_predecessor(self):
        gateway = _SharedSequenceGateway()
        gateway.latest.resource_decision_head = "0x" + "77" * 32
        anchor = ExecutionPolicyCustomerStateAnchor(
            gateway,
            resource_id_hash="88" * 32,
        )

        with self.assertRaisesRegex(
            TinkerCustomerRuntimeError,
            "predecessor differs",
        ):
            anchor.compare_and_set(
                expected_sequence=0,
                expected_head_hash="sha256:" + "00" * 32,
                new_sequence=1,
                new_head_hash="sha256:" + "99" * 32,
            )
        self.assertEqual(gateway.records, [])

    def test_store_treats_anchor_sequence_as_advisory_when_head_matches(self):
        class SharedContractAnchor:
            def read_head(self):
                return CustomerStateAnchorHead(
                    sequence=417,
                    head_hash="sha256:" + "00" * 32,
                )

            def compare_and_set(self, **kwargs):
                raise AssertionError("read-only recovery must not write")

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            store = TinkerCustomerStore(
                directory / "customer-state.json",
                b"store-integrity-key".ljust(32, b"!"),
                anchor=SharedContractAnchor(),
            )
            try:
                state = store.read()
            finally:
                os.close(store._directory_fd)

        self.assertEqual(state["sequence"], 0)
        self.assertEqual(state["head_hash"], "sha256:" + "00" * 32)


if __name__ == "__main__":
    unittest.main()
