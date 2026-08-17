from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_hash.auto import keccak

import tinker_delegate.tinker_customer_adapter as customer_adapter_module
from tinker_delegate.crypto import _derive_aes_key
from tinker_delegate.tinker_account_binding import (
    TINKER_ACCOUNT_BINDING_CHAIN_ID,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    TINKER_ACCOUNT_BINDING_TYPE,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    TINKER_PROVIDER_NAMESPACE,
    TINKER_PROVIDER_NAMESPACE_LABEL,
)
from tinker_delegate.tinker_customer_adapter import (
    CUSTOMER_CREDENTIAL_HKDF_INFO,
    TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE,
    TC_PROVISIONING_PROVIDER_UNAVAILABLE,
    TC_RECIPIENT_X25519_INVALID,
    TC_RELEASE_READER_UNAVAILABLE,
    TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE,
    TC_SETTLEMENT_PROVIDER_UNAVAILABLE,
    TC_STATE_ANCHOR_READ_UNAVAILABLE,
    TC_STATE_ANCHOR_UPDATE_UNAVAILABLE,
    TC_WALLET_VERIFIER_UNAVAILABLE,
    TINKER_ACCOUNT_BINDING_VERSION,
    TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH,
    AttestedProvisioningResult,
    AttestedSettlementResult,
    CustomerStateAnchorHead,
    CustomerAccountPolicy,
    DualRpcTinkerReleaseReader,
    ExpectedTinkerRelease,
    MAX_CUSTOMER_CREDENTIAL_PAGE_BYTES,
    MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE,
    MAX_CUSTOMER_STORE_BYTES,
    RuntimeEvidence,
    RuntimeEvidencePolicy,
    TinkerCustomerAdapter,
    TinkerCustomerConflict,
    TinkerCustomerError,
    TinkerCustomerNotFound,
    TinkerCustomerStore,
    TinkerCustomerStoreCorrupt,
    TinkerCustomerUnavailable,
    TinkerReleaseSnapshot,
)


NOW = 1_900_000_000
OWNER = "0x" + "11" * 20
MANAGER = "0x" + "22" * 20
CONTRACT = "0x" + "33" * 20
ACCOUNT_COMMITMENT = "0x" + "44" * 32
RELEASE_COMMITMENT = "0x" + "55" * 32
COMPOSE = "0x" + "66" * 32
COMPOSE_ROOT = "0x" + "77" * 32
MANAGER_ROOT = "0x" + "88" * 32
BLOCK_HASH = "0x" + "99" * 32
RUNTIME_CODE = bytes.fromhex("6001600055")
RUNTIME_HASH = "0x" + keccak(RUNTIME_CODE).hex()


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def assert_canary_absent(service, canary: str) -> None:
    assert canary not in json.dumps(service["store"].read(), sort_keys=True)
    if service["store"].path.exists():
        assert canary not in service["store"].path.read_text()
    if service["store"]._pending_path.exists():
        assert canary not in service["store"]._pending_path.read_text()


def assert_fixed_boundary_error(error: BaseException, code: str, marker: str) -> None:
    assert str(error) == code
    assert marker not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def account_binding_result_fields() -> dict[str, object]:
    return {
        "account_binding_schema": TINKER_ACCOUNT_BINDING_SCHEMA,
        "account_binding_version": TINKER_ACCOUNT_BINDING_VERSION,
        "account_binding_chain_id": TINKER_ACCOUNT_BINDING_CHAIN_ID,
        "account_binding_type": TINKER_ACCOUNT_BINDING_TYPE,
        "account_binding_typehash": "0x" + TINKER_ACCOUNT_BINDING_TYPEHASH.hex(),
        "provider_namespace_label": TINKER_PROVIDER_NAMESPACE_LABEL,
        "provider_namespace": "0x" + TINKER_PROVIDER_NAMESPACE.hex(),
        "account_binding_receipt_digest": digest("account-binding-receipt"),
        "sealed_binding_record_hash": digest("sealed-account-binding-record"),
        "account_binding_ceremony_receipt_digest": digest(
            "account-binding-ceremony-receipt"
        ),
        "deployment_intent_digest": digest("deployment-intent"),
        "account_binding_receipt_independently_attested": True,
        "account_binding_handle_attested": True,
        "provider_identity_checked": True,
        "current_provider_session_rechecked": True,
        "account_commitment_exact_match": True,
        "provider_internal_identity_cryptographically_proven": False,
        "raw_provider_account_id_egress": False,
        "raw_binding_root_egress": False,
        "raw_reviewer_share_egress": False,
        "binding_root_or_share_digest_published": False,
        "raw_provider_auth_egress": False,
        "raw_provider_session_egress": False,
        "raw_account_identifier_returned": False,
        "raw_secret_egress": False,
    }


@dataclass(frozen=True)
class WalletClaims:
    address: str = OWNER
    scopes: tuple[str, ...] = ("compute:console",)
    issued_at: int = NOW - 10
    expires_at: int = NOW + 600


class FakeWalletVerifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify_token(self, token, *, required_scope="compute:console", now=None):
        self.calls += 1
        if token != "wallet-token" or required_scope != "compute:console":
            raise ValueError("bad wallet token")
        return WalletClaims()


class FakeReleaseReader:
    def __init__(self, snapshot: TinkerReleaseSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def read(self) -> TinkerReleaseSnapshot:
        self.calls += 1
        return self.snapshot


class FakeEvidenceProvider:
    def __init__(self, expected: ExpectedTinkerRelease, policy: RuntimeEvidencePolicy) -> None:
        self.expected = expected
        self.policy = policy
        self.calls = 0
        self.override: RuntimeEvidence | None = None

    def value(self, now: int) -> RuntimeEvidence:
        return RuntimeEvidence(
            issued_at=now - 1,
            expires_at=now + 60,
            cvm_id_hash=self.policy.cvm_id_hash,
            measurement_hash=self.policy.measurement_hash,
            qvl_policy_hash=self.policy.qvl_policy_hash,
            release_authority_digest=self.policy.release_authority_digest,
            roles_digest=self.policy.roles_digest,
            customer_policy_digest=self.policy.customer_policy_digest,
            release_policy_tuple_digest=self.expected.policy_tuple_digest,
            account_commitment=self.expected.account_commitment,
            compose_hash=self.expected.approved_compose_hashes[0],
            manager=self.expected.managers[0],
            enabled_operations=self.policy.enabled_operations,
            tdx_verified=True,
            qvl_pass=True,
        )

    def read(self, *, now: int) -> RuntimeEvidence:
        self.calls += 1
        return self.override or self.value(now)


class FakeProvisioner:
    def __init__(self) -> None:
        self.results: dict[str, AttestedProvisioningResult] = {}
        self.calls = 0

    def consume(self, *, account_id, request_commitment, now):
        self.calls += 1
        return self.results.pop(account_id)


class FakeSettlementProvider:
    def __init__(self) -> None:
        self.results: dict[str, AttestedSettlementResult] = {}
        self.calls = 0

    def consume(self, *, reservation_id, reservation_commitment, now):
        self.calls += 1
        return self.results.pop(reservation_id)


class MarkerFailure:
    def __init__(self, marker: str) -> None:
        self.marker = marker

    def verify_token(self, *args, **kwargs):
        raise RuntimeError(self.marker)

    def read(self, *args, **kwargs):
        raise RuntimeError(self.marker)

    def consume(self, *args, **kwargs):
        raise RuntimeError(self.marker)


class FakeAnchor:
    def __init__(self) -> None:
        self.head = CustomerStateAnchorHead(0, "sha256:" + "00" * 32)
        self.fail_after_commit = False

    def read_head(self) -> CustomerStateAnchorHead:
        return self.head

    def compare_and_set(
        self,
        *,
        expected_sequence,
        expected_head_hash,
        new_sequence,
        new_head_hash,
    ) -> CustomerStateAnchorHead:
        if self.head != CustomerStateAnchorHead(expected_sequence, expected_head_hash):
            raise RuntimeError("anchor conflict")
        self.head = CustomerStateAnchorHead(new_sequence, new_head_hash)
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise RuntimeError("ambiguous committed anchor")
        return self.head


def expected_release() -> ExpectedTinkerRelease:
    return ExpectedTinkerRelease(
        contract_address=CONTRACT,
        runtime_code_hash=RUNTIME_HASH,
        owner=OWNER,
        account_commitment=ACCOUNT_COMMITMENT,
        account_binding_ceremony_receipt_digest=digest(
            "account-binding-ceremony-receipt"
        ),
        deployment_intent_digest=digest("deployment-intent"),
        release_policy_commitment=RELEASE_COMMITMENT,
        approved_compose_root=COMPOSE_ROOT,
        approved_compose_hashes=(COMPOSE,),
        manager_root=MANAGER_ROOT,
        managers=(MANAGER,),
        max_add_balance_policy_units=10 * 10**18,
        max_spend_policy_units=5 * 10**18,
    )


def release_snapshot(expected: ExpectedTinkerRelease) -> TinkerReleaseSnapshot:
    return TinkerReleaseSnapshot(
        chain_id=84532,
        finalized_block_number=1234,
        finalized_block_hash=BLOCK_HASH,
        contract_address=expected.contract_address,
        runtime_code_hash=expected.runtime_code_hash,
        owner=expected.owner,
        pending_owner="0x" + "00" * 20,
        account_commitment=expected.account_commitment,
        release_policy_commitment=expected.release_policy_commitment,
        release_policy_frozen=True,
        emergency_halted=False,
        approved_compose_root=expected.approved_compose_root,
        approved_compose_hashes=expected.approved_compose_hashes,
        manager_root=expected.manager_root,
        managers=expected.managers,
        max_add_balance_policy_units=expected.max_add_balance_policy_units,
        max_spend_policy_units=expected.max_spend_policy_units,
        release_max_add_balance_policy_units=expected.max_add_balance_policy_units,
        release_max_spend_policy_units=expected.max_spend_policy_units,
    )


@pytest.fixture
def service(tmp_path: Path):
    expected = expected_release()
    account_policy = CustomerAccountPolicy(
        allowed_operations=("training",),
        max_operation_policy_units=10**18,
        max_outstanding_policy_units=2 * 10**18,
        max_lifetime_policy_units=3 * 10**18,
        credential_max_ttl_seconds=600,
        max_active_credentials=2,
    )
    evidence_policy = RuntimeEvidencePolicy(
        cvm_id_hash=digest("cvm"),
        measurement_hash=digest("measurement"),
        qvl_policy_hash=digest("qvl-policy"),
        release_authority_digest=digest("release-authority"),
        roles_digest=digest("roles"),
        customer_policy_digest=account_policy.digest,
        enabled_operations=("training",),
    )
    wallet = FakeWalletVerifier()
    reader = FakeReleaseReader(release_snapshot(expected))
    evidence = FakeEvidenceProvider(expected, evidence_policy)
    provisioner = FakeProvisioner()
    settlement = FakeSettlementProvider()
    anchor = FakeAnchor()
    store = TinkerCustomerStore(tmp_path / "customer.json", b"s" * 32, anchor=anchor)
    adapter = TinkerCustomerAdapter(
        wallet_verifier=wallet,
        release_reader=reader,
        expected_release=expected,
        evidence_provider=evidence,
        evidence_policy=evidence_policy,
        provisioning_provider=provisioner,
        settlement_provider=settlement,
        store=store,
        account_policy=account_policy,
        credential_signing_key=b"c" * 32,
    )
    return {
        "adapter": adapter,
        "expected": expected,
        "wallet": wallet,
        "reader": reader,
        "evidence": evidence,
        "provisioner": provisioner,
        "settlement": settlement,
        "store": store,
        "anchor": anchor,
        "policy": account_policy,
    }


def request_account(service, *, mode="create", key="account-request-0001"):
    return service["adapter"].request_account(
        wallet_token="wallet-token",
        mode=mode,
        idempotency_key=key,
        now=NOW,
    )


def adapter_for_expected(
    service,
    expected: ExpectedTinkerRelease,
) -> TinkerCustomerAdapter:
    return TinkerCustomerAdapter(
        wallet_verifier=service["wallet"],
        release_reader=service["reader"],
        expected_release=expected,
        evidence_provider=service["evidence"],
        evidence_policy=service["evidence"].policy,
        provisioning_provider=service["provisioner"],
        settlement_provider=service["settlement"],
        store=service["store"],
        account_policy=service["policy"],
        credential_signing_key=b"c" * 32,
    )


def valid_provisioning_result(service, request) -> AttestedProvisioningResult:
    account_id = request["account_id"]
    evidence = service["evidence"].value(NOW)
    return AttestedProvisioningResult(
        account_id=account_id,
        request_commitment=request["request_commitment"],
        owner_address_hash=request["owner_address_hash"],
        mode=request["mode"],
        account_commitment=service["expected"].account_commitment,
        release_policy_tuple_digest=service["expected"].policy_tuple_digest,
        compose_hash=service["expected"].approved_compose_hashes[0],
        manager=service["expected"].managers[0],
        provisioning_receipt_hash=digest("provisioned"),
        runtime_evidence_digest=evidence.public_digest(),
        **account_binding_result_fields(),
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        success=True,
        upstream_account_exists=True,
    )


def activate_account(service, request):
    account_id = request["account_id"]
    service["provisioner"].results[account_id] = valid_provisioning_result(
        service,
        request,
    )
    return service["adapter"].activate_account(
        account_id=account_id,
        idempotency_key="account-activate-0001",
        now=NOW,
    )


def recipient_keypair():
    private = X25519PrivateKey.generate()
    private_hex = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return private_hex, public_hex


def decrypt_capsule(capsule, private_hex):
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    encrypted = capsule["encrypted_token"]
    sender = X25519PublicKey.from_public_bytes(bytes.fromhex(encrypted["ephemeral_public_key"]))
    key = _derive_aes_key(private.exchange(sender), info=CUSTOMER_CREDENTIAL_HKDF_INFO)
    return AESGCM(key).decrypt(
        bytes.fromhex(encrypted["nonce"]),
        bytes.fromhex(encrypted["ciphertext"]),
        bytes.fromhex(capsule["associated_data"]),
    ).decode()


def issue_credential(service, account_id):
    private, public = recipient_keypair()
    receipt = service["adapter"].issue_credential(
        wallet_token="wallet-token",
        account_id=account_id,
        recipient_public_key=public,
        operations=["training"],
        ttl_seconds=300,
        idempotency_key="credential-issue-0001",
        now=NOW,
    )
    return receipt, decrypt_capsule(receipt["capsule"], private)


def test_request_is_not_activation_or_upstream_account_evidence(service):
    receipt = request_account(service, mode="link_existing")

    assert receipt["status"] == "requested"
    assert receipt["upstream_account_exists"] is False
    assert receipt["provisioning_performed"] is False
    assert receipt["browser_supplied_account_commitment_accepted"] is False
    assert receipt["hosted_card_funding"] == "roadmap"
    assert receipt["token_exchange"] == "roadmap"
    assert service["store"].read()["accounts"][receipt["account_id"]]["status"] == "requested"


@pytest.mark.parametrize("invalid_now", ("1900000000", 1_900_000_000.0, True))
def test_public_operation_time_requires_an_exact_integer(service, invalid_now):
    with pytest.raises(TinkerCustomerError, match="exact integer"):
        service["adapter"].request_account(
            wallet_token="wallet-token",
            mode="create",
            idempotency_key="account-request-0001",
            now=invalid_now,
        )
    assert service["store"].read()["accounts"] == {}


def test_account_request_is_exactly_idempotent_and_conflicts_on_reuse(service):
    first = request_account(service)
    second = request_account(service)

    assert second["account_id"] == first["account_id"]
    assert second["idempotent_replay"] is True
    assert service["store"].read()["sequence"] == 1
    with pytest.raises(TinkerCustomerConflict):
        request_account(service, mode="link_existing")


def test_requested_account_can_be_terminally_cancelled_without_false_activation(
    service,
):
    request = request_account(service)
    cancelled = service["adapter"].revoke_account(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        idempotency_key="account-cancel-0001",
        now=NOW,
    )
    persisted = service["store"].read()["accounts"][request["account_id"]]

    assert cancelled["status"] == "cancelled"
    assert cancelled["provisioning_result_attested"] is False
    assert cancelled["account_binding_authority_digest"] is None
    assert persisted["status"] == "cancelled"
    assert persisted["activated_at"] == 0
    assert persisted["provisioning_receipt_hash"] == ""
    assert persisted["account_binding_authority"] == {}
    with pytest.raises(TinkerCustomerConflict):
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-after-cancel-0001",
            now=NOW,
        )


def test_activation_requires_exact_independent_provisioning_result(service):
    request = request_account(service)
    account_id = request["account_id"]
    service["provisioner"].results[account_id] = replace(
        valid_provisioning_result(service, request),
        account_commitment="0x" + "ab" * 32,
        provisioning_receipt_hash=digest("bad-provision"),
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_PROVISIONING_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].activate_account(
            account_id=account_id,
            idempotency_key="account-activate-0001",
            now=NOW,
        )
    assert service["store"].read()["accounts"][account_id]["status"] == "requested"


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("account_binding_schema", "dnai.tinker-account-binding.v2"),
        ("account_binding_version", 2),
        ("account_binding_version", "1"),
        ("account_binding_chain_id", 1),
        ("account_binding_chain_id", "84532"),
        ("account_binding_type", "DnaiTinkerAccountBindingV2()"),
        ("account_binding_typehash", "0x" + "ab" * 32),
        ("provider_namespace_label", "another-provider/tinker"),
        ("provider_namespace", "0x" + "bc" * 32),
        ("account_binding_receipt_digest", "sha256:" + "00" * 32),
        (
            "account_binding_receipt_digest",
            digest("provisioned"),
        ),
        (
            "sealed_binding_record_hash",
            digest("account-binding-receipt"),
        ),
        ("account_binding_ceremony_receipt_digest", ""),
        ("account_binding_ceremony_receipt_digest", None),
        (
            "account_binding_ceremony_receipt_digest",
            digest("wrong-account-binding-ceremony"),
        ),
        ("deployment_intent_digest", ""),
        ("deployment_intent_digest", None),
        ("deployment_intent_digest", digest("wrong-deployment-intent")),
        ("account_binding_receipt_independently_attested", False),
        ("account_binding_receipt_independently_attested", "true"),
        ("account_binding_handle_attested", False),
        ("provider_identity_checked", False),
        ("provider_identity_checked", {"checked": True}),
        ("current_provider_session_rechecked", False),
        ("account_commitment_exact_match", False),
        ("provider_internal_identity_cryptographically_proven", True),
        ("provider_internal_identity_cryptographically_proven", 0),
        ("raw_provider_account_id_egress", True),
        ("raw_binding_root_egress", True),
        ("raw_reviewer_share_egress", True),
        ("binding_root_or_share_digest_published", True),
        ("raw_provider_auth_egress", True),
        ("raw_provider_session_egress", True),
        ("raw_provider_session_egress", []),
        ("raw_secret_egress", True),
    ),
)
def test_exact_commitment_alone_cannot_satisfy_account_binding_authority(
    service,
    field,
    invalid,
):
    request = request_account(service)
    account_id = request["account_id"]
    result = replace(
        valid_provisioning_result(service, request),
        **{field: invalid},
    )
    assert result.account_commitment == service["expected"].account_commitment
    service["provisioner"].results[account_id] = result

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_PROVISIONING_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].activate_account(
            account_id=account_id,
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    persisted = service["store"].read()["accounts"][account_id]
    assert persisted["status"] == "requested"
    assert persisted["account_binding_authority"] == {}


@pytest.mark.parametrize(
    "field",
    (
        "account_binding_typehash",
        "provider_namespace",
        "account_binding_receipt_digest",
        "sealed_binding_record_hash",
        "account_binding_ceremony_receipt_digest",
        "deployment_intent_digest",
        "provisioning_receipt_hash",
    ),
)
@pytest.mark.parametrize("mutation", ("uppercase", "whitespace"))
def test_provisioning_rejects_noncanonical_commitment_spellings(
    service,
    field,
    mutation,
):
    request = request_account(service)
    result = valid_provisioning_result(service, request)
    original = getattr(result, field)
    invalid = original.upper() if mutation == "uppercase" else f" {original}"
    service["provisioner"].results[request["account_id"]] = replace(
        result,
        **{field: invalid},
    )

    with pytest.raises(TinkerCustomerUnavailable):
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    persisted = service["store"].read()["accounts"][request["account_id"]]
    assert persisted["status"] == "requested"
    assert persisted["account_binding_authority"] == {}


@pytest.mark.parametrize(
    ("target", "source"),
    (
        ("provisioning_receipt_hash", "sealed_binding_record_hash"),
        ("provisioning_receipt_hash", "account_binding_ceremony_receipt_digest"),
        ("provisioning_receipt_hash", "deployment_intent_digest"),
        ("account_binding_receipt_digest", "account_binding_ceremony_receipt_digest"),
        ("account_binding_receipt_digest", "deployment_intent_digest"),
        ("sealed_binding_record_hash", "account_binding_ceremony_receipt_digest"),
        ("sealed_binding_record_hash", "deployment_intent_digest"),
    ),
)
def test_all_provisioning_semantic_commitments_are_pairwise_distinct(
    service,
    target,
    source,
):
    request = request_account(service)
    result = valid_provisioning_result(service, request)
    service["provisioner"].results[request["account_id"]] = replace(
        result,
        **{target: getattr(result, source)},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_PROVISIONING_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    assert (
        service["store"].read()["accounts"][request["account_id"]]["status"]
        == "requested"
    )


def test_expected_release_requires_distinct_ceremony_and_deployment_lineage():
    expected = expected_release()
    with pytest.raises(TinkerCustomerError, match="must be distinct"):
        replace(
            expected,
            deployment_intent_digest=expected.account_binding_ceremony_receipt_digest,
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("account_binding_ceremony_receipt_digest", digest("ceremony").upper()),
        ("deployment_intent_digest", f" {digest('deployment')}"),
        ("account_commitment", ACCOUNT_COMMITMENT.upper()),
        ("runtime_code_hash", f" {RUNTIME_HASH}"),
        ("owner", OWNER.upper()),
        ("chain_id", True),
    ),
)
def test_expected_release_rejects_noncanonical_release_primitives(field, invalid):
    with pytest.raises(TinkerCustomerError):
        replace(expected_release(), **{field: invalid})


@pytest.mark.parametrize(
    "invalid",
    (
        "sha256:" + "00" * 32,
        digest("measurement"),
    ),
)
def test_runtime_evidence_policy_requires_nonzero_pairwise_distinct_pins(
    service,
    invalid,
):
    with pytest.raises(
        TinkerCustomerError,
        match="^runtime evidence policy commitments must be nonzero and pairwise distinct$",
    ) as caught:
        replace(service["evidence"].policy, cvm_id_hash=invalid)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("success", "false"),
        ("success", 1),
        ("success", {"value": True}),
        ("upstream_account_exists", "false"),
        ("upstream_account_exists", 1),
        ("upstream_account_exists", [True]),
        ("raw_account_identifier_returned", 0),
        ("raw_account_identifier_returned", None),
        ("raw_account_identifier_returned", "false"),
    ),
)
def test_provisioning_truth_fields_require_exact_booleans(
    service,
    field,
    invalid,
):
    canary = "PROVISIONING-TRUTH-CANARY"
    request = request_account(service)
    result = valid_provisioning_result(service, request)
    if isinstance(invalid, dict):
        invalid = {"value": canary}
    elif isinstance(invalid, list):
        invalid = [canary]
    service["provisioner"].results[request["account_id"]] = replace(
        result,
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_PROVISIONING_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    persisted = service["store"].read()["accounts"][request["account_id"]]
    assert persisted["status"] == "requested"
    assert persisted["account_binding_authority"] == {}
    assert_canary_absent(service, canary)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("issued_at", "1899999999"),
        ("issued_at", 1_899_999_999.0),
        ("issued_at", True),
        ("expires_at", "1900000060"),
        ("expires_at", 1_900_000_060.0),
        ("expires_at", True),
    ),
)
def test_provisioning_timestamps_require_exact_integers(
    service,
    field,
    invalid,
):
    request = request_account(service)
    service["provisioner"].results[request["account_id"]] = replace(
        valid_provisioning_result(service, request),
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_PROVISIONING_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    assert (
        service["store"].read()["accounts"][request["account_id"]]["status"]
        == "requested"
    )


def test_activation_is_one_shot_and_exactly_idempotent(service):
    request = request_account(service)
    first = activate_account(service, request)
    second = service["adapter"].activate_account(
        account_id=request["account_id"],
        idempotency_key="account-activate-0001",
        now=NOW,
    )

    assert first["status"] == "active"
    assert first["upstream_account_exists"] is True
    assert first["raw_account_identifier_returned"] is False
    assert (
        first["release_lineage_digest"]
        == service["expected"].release_lineage_digest
    )
    assert first["account_binding_authority_digest"].startswith("sha256:")
    binding = first["account_binding_authority"]
    assert binding["truth_status"] == TINKER_CUSTOMER_ACCOUNT_BINDING_TRUTH
    assert binding["account_binding_schema"] == TINKER_ACCOUNT_BINDING_SCHEMA
    assert binding["account_binding_version"] == TINKER_ACCOUNT_BINDING_VERSION
    assert binding["account_binding_chain_id"] == TINKER_ACCOUNT_BINDING_CHAIN_ID
    assert binding["account_binding_type"] == TINKER_ACCOUNT_BINDING_TYPE
    assert binding["provider_namespace_label"] == TINKER_PROVIDER_NAMESPACE_LABEL
    assert binding["provider_namespace"] == "0x" + TINKER_PROVIDER_NAMESPACE.hex()
    assert (
        binding["account_binding_ceremony_receipt_digest"]
        == service["expected"].account_binding_ceremony_receipt_digest
    )
    assert (
        binding["deployment_intent_digest"]
        == service["expected"].deployment_intent_digest
    )
    assert binding["account_binding_receipt_independently_attested"] is True
    assert binding["account_binding_handle_attested"] is True
    assert binding["provider_identity_checked"] is True
    assert binding["current_provider_session_rechecked"] is True
    assert binding["account_commitment_exact_match"] is True
    assert binding["provider_internal_identity_cryptographically_proven"] is False
    assert binding["raw_provider_account_id_egress"] is False
    assert binding["raw_binding_root_egress"] is False
    assert binding["raw_reviewer_share_egress"] is False
    assert binding["binding_root_or_share_digest_published"] is False
    assert binding["raw_provider_auth_egress"] is False
    assert binding["raw_provider_session_egress"] is False
    assert binding["raw_secret_egress"] is False
    assert (
        first["account_binding_ceremony_receipt_digest"]
        == binding["account_binding_ceremony_receipt_digest"]
    )
    assert first["deployment_intent_digest"] == binding["deployment_intent_digest"]
    assert (
        service["store"].read()["accounts"][request["account_id"]][
            "account_binding_authority"
        ]
        == binding
    )
    assert second["idempotent_replay"] is True
    assert service["provisioner"].calls == 1


def test_credential_cannot_be_issued_before_activation(service):
    request = request_account(service)
    _, public = recipient_keypair()

    with pytest.raises(TinkerCustomerError, match="not active"):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-issue-0001",
            now=NOW,
        )


def test_scoped_credential_is_only_returned_encrypted_and_replays_same_capsule(service):
    request = request_account(service)
    activate_account(service, request)
    private, public = recipient_keypair()
    first = service["adapter"].issue_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        recipient_public_key=public,
        operations=["training"],
        ttl_seconds=300,
        idempotency_key="credential-issue-0001",
        now=NOW,
    )
    second = service["adapter"].issue_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        recipient_public_key=public,
        operations=["training"],
        ttl_seconds=300,
        idempotency_key="credential-issue-0001",
        now=NOW,
    )

    token = decrypt_capsule(first["capsule"], private)
    assert token.count(".") == 2
    assert "token" not in first
    assert first["token_returned_in_plaintext"] is False
    assert first["upstream_tinker_key_exposed"] is False
    assert first["upstream_project_exposed"] is False
    assert (
        first["release_lineage_digest"]
        == service["expected"].release_lineage_digest
    )
    assert (
        first["account_binding_ceremony_receipt_digest"]
        == service["expected"].account_binding_ceremony_receipt_digest
    )
    assert (
        first["deployment_intent_digest"]
        == service["expected"].deployment_intent_digest
    )
    assert first["account_binding_authority_digest"].startswith("sha256:")
    assert second["capsule"] == first["capsule"]
    assert second["idempotent_replay"] is True


def test_credential_cap_can_only_narrow_the_immutable_account_policy(service):
    request = request_account(service)
    activate_account(service, request)
    private, public = recipient_keypair()
    narrowed_cap = 25_000
    receipt = service["adapter"].issue_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        recipient_public_key=public,
        operations=["training"],
        ttl_seconds=300,
        max_operation_policy_units=narrowed_cap,
        idempotency_key="credential-narrow-cap-0001",
        now=NOW,
    )
    token = decrypt_capsule(receipt["capsule"], private)

    assert receipt["max_operation_policy_units"] == str(narrowed_cap)
    with pytest.raises(TinkerCustomerError, match="per-operation spend cap"):
        service["adapter"].reserve_spend(
            credential_token=token,
            operation="training",
            amount_policy_units=narrowed_cap + 1,
            workload_commitment=digest("over-narrowed-cap"),
            idempotency_key="reservation-over-narrowed-cap-0001",
            now=NOW,
        )

    _, another_public = recipient_keypair()
    with pytest.raises(TinkerCustomerError, match="exceeds"):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=another_public,
            operations=["training"],
            ttl_seconds=300,
            max_operation_policy_units=(
                service["policy"].max_operation_policy_units + 1
            ),
            idempotency_key="credential-expand-cap-0001",
            now=NOW,
        )


def test_current_account_and_credential_list_are_bounded_recovery_surfaces(service):
    with pytest.raises(TinkerCustomerError, match="not found"):
        service["adapter"].current_account_status(
            wallet_token="wallet-token",
            now=NOW,
        )

    request = request_account(service)
    activate_account(service, request)
    credential, _ = issue_credential(service, request["account_id"])
    current = service["adapter"].current_account_status(
        wallet_token="wallet-token",
        now=NOW,
    )
    listing = service["adapter"].list_credentials(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        now=NOW,
    )
    rendered = json.dumps(listing, sort_keys=True)

    assert current["account_id"] == request["account_id"]
    assert listing["surface"] == "tinker_customer_credentials"
    assert listing["schema_version"] == 2
    assert listing["account_status"] == "active"
    assert listing["total_credentials"] == 1
    assert listing["page_credential_count"] == 1
    assert listing["page_limit"] == 16
    assert listing["maximum_page_size"] == 64
    assert listing["has_more"] is False
    assert listing["next_cursor"] is None
    assert listing["snapshot_sequence"] == service["store"].read()["sequence"]
    assert listing["ordering"] == "issued_at_desc_then_credential_id_desc"
    assert listing["credential_capsules_returned"] is False
    assert listing["plaintext_token_egress"] is False
    assert listing["credentials"][0]["credential_id"] == credential["credential_id"]
    assert listing["credentials"][0]["status"] == "active"
    assert "encrypted_token" not in rendered
    assert all("capsule" not in item for item in listing["credentials"])


def test_foreign_and_missing_account_ids_share_one_non_enumerating_error(service):
    request = request_account(service)

    class OtherWalletVerifier:
        def verify_token(
            self,
            token,
            *,
            required_scope="compute:console",
            now=None,
        ):
            assert token == "other-wallet-token"
            assert required_scope == "compute:console"
            return replace(
                WalletClaims(),
                address="0x" + "aa" * 20,
            )

    other_wallet_adapter = TinkerCustomerAdapter(
        wallet_verifier=OtherWalletVerifier(),
        release_reader=service["reader"],
        expected_release=service["expected"],
        evidence_provider=service["evidence"],
        evidence_policy=service["evidence"].policy,
        provisioning_provider=service["provisioner"],
        settlement_provider=service["settlement"],
        store=service["store"],
        account_policy=service["policy"],
        credential_signing_key=b"c" * 32,
    )

    with pytest.raises(TinkerCustomerNotFound) as foreign:
        other_wallet_adapter.account_status(
            wallet_token="other-wallet-token",
            account_id=request["account_id"],
            now=NOW,
        )
    with pytest.raises(TinkerCustomerNotFound) as missing:
        other_wallet_adapter.account_status(
            wallet_token="other-wallet-token",
            account_id="tca_" + "ff" * 12,
            now=NOW,
        )

    assert str(foreign.value) == str(missing.value)


def test_credential_pages_are_complete_ordered_opaque_and_snapshot_bound(
    service,
):
    request = request_account(service)
    activate_account(service, request)
    issued = []
    for index in ("first", "second"):
        _private, public = recipient_keypair()
        issued.append(
            service["adapter"].issue_credential(
                wallet_token="wallet-token",
                account_id=request["account_id"],
                recipient_public_key=public,
                operations=["training"],
                ttl_seconds=300,
                idempotency_key=f"credential-list-bound-{index}-0001",
                now=NOW,
            )
        )
    first = service["adapter"].list_credentials(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        limit=1,
        now=NOW,
    )
    assert first["total_credentials"] == 2
    assert first["page_credential_count"] == 1
    assert first["has_more"] is True
    assert isinstance(first["next_cursor"], str)
    assert first["next_cursor"].startswith("tinker_credentials_v1.")
    second = service["adapter"].list_credentials(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        limit=1,
        cursor=first["next_cursor"],
        now=NOW,
    )
    combined = first["credentials"] + second["credentials"]
    assert second["page_credential_count"] == 1
    assert second["has_more"] is False
    assert second["next_cursor"] is None
    assert {item["credential_id"] for item in combined} == {
        item["credential_id"] for item in issued
    }
    assert [
        (item["issued_at"], item["credential_id"]) for item in combined
    ] == sorted(
        (
            (item["issued_at"], item["credential_id"])
            for item in combined
        ),
        reverse=True,
    )

    cursor = first["next_cursor"]
    tampered = cursor[:-1] + ("0" if cursor[-1] != "0" else "1")
    with pytest.raises(TinkerCustomerConflict, match="restart"):
        service["adapter"].list_credentials(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            limit=1,
            cursor=tampered,
            now=NOW,
        )
    with pytest.raises(TinkerCustomerConflict, match="restart"):
        service["store"].decode_credential_cursor(
            cursor,
            expected_account_id="tca_" + "ff" * 12,
            expected_snapshot_sequence=first["snapshot_sequence"],
        )

    service["adapter"].revoke_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        credential_id=issued[0]["credential_id"],
        idempotency_key="credential-page-revoke-0001",
        now=NOW,
    )
    with pytest.raises(TinkerCustomerConflict, match="restart"):
        service["adapter"].list_credentials(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            limit=1,
            cursor=cursor,
            now=NOW,
        )

    restarted = service["adapter"].list_credentials(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        limit=1,
        now=NOW + 301,
    )
    restarted_second = service["adapter"].list_credentials(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        limit=1,
        cursor=restarted["next_cursor"],
        now=NOW + 301,
    )
    retained_statuses = {
        item["status"]
        for item in restarted["credentials"] + restarted_second["credentials"]
    }
    assert retained_statuses == {"expired", "revoked"}

    maximum_shape = {
        **restarted,
        "total_credentials": MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE,
        "page_credential_count": MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE,
        "page_limit": MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE,
        "has_more": False,
        "next_cursor": None,
        "credentials": [
            {
                **restarted["credentials"][0],
                "credential_id": "tcc_" + f"{index:024x}",
            }
            for index in range(MAX_CUSTOMER_CREDENTIAL_PAGE_SIZE)
        ],
    }
    encoded = json.dumps(
        maximum_shape,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert len(encoded) < MAX_CUSTOMER_CREDENTIAL_PAGE_BYTES
    assert len(encoded) < 256 * 1024


def test_random_resource_identity_collisions_fail_without_overwrite(
    service,
    monkeypatch,
):
    request = request_account(service)
    activate_account(service, request)
    first, token = issue_credential(service, request["account_id"])
    state_before_credential = service["store"].read()
    _private, public = recipient_keypair()
    monkeypatch.setattr(
        customer_adapter_module.secrets,
        "token_hex",
        lambda size: first["credential_id"].removeprefix("tcc_"),
    )
    with pytest.raises(
        TinkerCustomerUnavailable,
        match="credential identity collision",
    ):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-collision-0001",
            now=NOW,
        )
    assert service["store"].read() == state_before_credential

    monkeypatch.undo()
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("first-collision-reservation"),
        idempotency_key="reservation-before-collision-0001",
        now=NOW,
    )
    state_before_reservation = service["store"].read()
    monkeypatch.setattr(
        customer_adapter_module.secrets,
        "token_hex",
        lambda size: reservation["reservation_id"].removeprefix("tcr_"),
    )
    with pytest.raises(
        TinkerCustomerUnavailable,
        match="reservation identity collision",
    ):
        service["adapter"].reserve_spend(
            credential_token=token,
            operation="training",
            amount_policy_units=1,
            workload_commitment=digest("second-collision-reservation"),
            idempotency_key="reservation-collision-0001",
            now=NOW,
        )
    assert service["store"].read() == state_before_reservation


def test_rotation_revokes_before_issue_and_exact_retry_never_overlaps_authority(service):
    request = request_account(service)
    activate_account(service, request)
    prior, prior_token = issue_credential(service, request["account_id"])
    replacement_private, replacement_public = recipient_keypair()
    first = service["adapter"].rotate_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        credential_id=prior["credential_id"],
        recipient_public_key=replacement_public,
        operations=["training"],
        ttl_seconds=300,
        max_operation_policy_units=50_000,
        idempotency_key="credential-rotation-0001",
        now=NOW,
    )
    sequence_after_first = service["store"].read()["sequence"]
    second = service["adapter"].rotate_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        credential_id=prior["credential_id"],
        recipient_public_key=replacement_public,
        operations=["training"],
        ttl_seconds=300,
        max_operation_policy_units=50_000,
        idempotency_key="credential-rotation-0001",
        now=NOW,
    )
    replacement_token = decrypt_capsule(first["capsule"], replacement_private)

    assert first["prior_credential_revoked"] is True
    assert first["rotation_order"] == "revoke_then_issue_no_authority_overlap"
    assert first["max_operation_policy_units"] == "50000"
    rotation_aad = json.loads(
        bytes.fromhex(first["capsule"]["associated_data"]).decode("ascii")
    )
    assert (
        rotation_aad["release_policy_tuple_digest"]
        == first["gate"]["release_policy_tuple_digest"]
    )
    assert second["credential_id"] == first["credential_id"]
    assert second["capsule"] == first["capsule"]
    assert second["idempotent_replay"] is True
    assert service["store"].read()["sequence"] == sequence_after_first
    with pytest.raises(TinkerCustomerError, match="revoked or expired"):
        service["adapter"].reserve_spend(
            credential_token=prior_token,
            operation="training",
            amount_policy_units=1,
            workload_commitment=digest("prior-authority-is-revoked"),
            idempotency_key="reservation-prior-authority-0001",
            now=NOW,
        )
    replacement = service["adapter"].reserve_spend(
        credential_token=replacement_token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("replacement-authority"),
        idempotency_key="reservation-replacement-authority-0001",
        now=NOW,
    )
    assert replacement["status"] == "reserved"


def test_rotation_rejects_bad_replacement_before_revoking_current_authority(service):
    request = request_account(service)
    activate_account(service, request)
    prior, _ = issue_credential(service, request["account_id"])
    sequence_before = service["store"].read()["sequence"]

    with pytest.raises(
        TinkerCustomerError,
        match=f"^{TC_RECIPIENT_X25519_INVALID}$",
    ):
        service["adapter"].rotate_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            credential_id=prior["credential_id"],
            recipient_public_key="00" * 32,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-rotation-invalid-key-0001",
            now=NOW,
        )

    state = service["store"].read()
    assert state["sequence"] == sequence_before
    assert state["credentials"][prior["credential_id"]]["status"] == "active"


def test_restart_and_active_operations_reject_ceremony_or_deployment_drift(
    service,
):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    changed = replace(
        service["expected"],
        account_binding_ceremony_receipt_digest=digest("replacement-ceremony"),
        deployment_intent_digest=digest("replacement-deployment-intent"),
    )
    with pytest.raises(TinkerCustomerUnavailable, match="release lineage"):
        adapter_for_expected(service, changed)

    changed_adapter = adapter_for_expected(service, service["expected"])
    changed_adapter.expected_release = changed
    _, public = recipient_keypair()
    before_sequence = service["store"].read()["sequence"]

    with pytest.raises(TinkerCustomerUnavailable, match="release lineage"):
        changed_adapter.issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-lineage-drift-0001",
            now=NOW,
        )

    before_gate_calls = (service["reader"].calls, service["evidence"].calls)
    with pytest.raises(
        TinkerCustomerError,
        match="different account-binding release lineage",
    ):
        changed_adapter.reserve_spend(
            credential_token=token,
            operation="training",
            amount_policy_units=1,
            workload_commitment=digest("lineage-drift-workload"),
            idempotency_key="reservation-lineage-drift-0001",
            now=NOW,
        )

    assert (service["reader"].calls, service["evidence"].calls) == before_gate_calls
    assert service["store"].read()["sequence"] == before_sequence


@pytest.mark.parametrize("recipient", ("00" * 32, "AB" * 32))
def test_credential_rejects_low_order_or_noncanonical_recipient_before_mutation(
    service,
    recipient,
):
    request = request_account(service)
    activate_account(service, request)
    before = service["store"].read()["sequence"]

    before_gate_calls = (service["reader"].calls, service["evidence"].calls)
    with pytest.raises(
        TinkerCustomerError,
        match=f"^{TC_RECIPIENT_X25519_INVALID}$",
    ) as caught:
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=recipient,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-invalid-recipient-0001",
            now=NOW,
        )

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert (service["reader"].calls, service["evidence"].calls) == before_gate_calls
    assert service["store"].read()["sequence"] == before


def test_credential_encryption_failure_is_fixed_and_non_reflective(
    service,
    monkeypatch,
):
    marker = "CREDENTIAL-ENCRYPTION-SECRET-CANARY"
    request = request_account(service)
    activate_account(service, request)
    _, public = recipient_keypair()
    before = service["store"].read()["sequence"]

    def fail_encryption(*args, **kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(
        customer_adapter_module,
        "encrypt_for_tee",
        fail_encryption,
    )
    with pytest.raises(TinkerCustomerUnavailable) as caught:
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-encryption-failure-0001",
            now=NOW,
        )

    assert_fixed_boundary_error(
        caught.value,
        TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE,
        marker,
    )
    assert service["store"].read()["sequence"] == before
    assert_canary_absent(service, marker)


def test_inference_is_explicitly_disabled(service):
    request = request_account(service)
    activate_account(service, request)
    _, public = recipient_keypair()

    with pytest.raises(TinkerCustomerUnavailable, match="inference"):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["inference"],
            ttl_seconds=300,
            idempotency_key="credential-infer-0001",
            now=NOW,
        )


def test_invalid_credential_is_rejected_before_live_release_or_evidence_reads(
    service,
):
    before = (service["reader"].calls, service["evidence"].calls)

    with pytest.raises(TinkerCustomerError, match="credential format"):
        service["adapter"].reserve_spend(
            credential_token="not-a-customer-credential",
            operation="training",
            amount_policy_units=1,
            workload_commitment=digest("invalid-credential-workload"),
            idempotency_key="invalid-credential-reservation-0001",
            now=NOW,
        )

    assert (service["reader"].calls, service["evidence"].calls) == before
    assert service["store"].read()["sequence"] == 0


def test_reservation_and_settlement_are_bounded_authority_receipts(service):
    request = request_account(service)
    activate_account(service, request)
    credential, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=7 * 10**17,
        workload_commitment=digest("workload"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    claim = service["adapter"].claim_reservation_dispatch(
        reservation_id=reservation["reservation_id"],
        reservation_commitment=reservation["reservation_commitment"],
        idempotency_key="reservation-dispatch-claim-0001",
        now=NOW,
    )
    service["settlement"].results[reservation["reservation_id"]] = AttestedSettlementResult(
        reservation_id=reservation["reservation_id"],
        reservation_commitment=reservation["reservation_commitment"],
        outcome="settled",
        actual_policy_units=5 * 10**17,
        usage_receipt_hash=digest("usage"),
        release_policy_tuple_digest=service["expected"].policy_tuple_digest,
        runtime_evidence_digest=claim["dispatch_runtime_evidence_digest"],
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        provider_dispatch_performed=True,
    )
    final = service["adapter"].finalize_reservation(
        reservation_id=reservation["reservation_id"],
        idempotency_key="reservation-final-0001",
        now=NOW,
    )

    assert reservation["provider_dispatch_performed"] is False
    assert reservation["provider_authoritative_billing"] is False
    assert claim["at_most_once_claim_committed"] is True
    assert claim["automatic_provider_redispatch"] is False
    assert final["status"] == "settled"
    assert final["reserved_policy_units"] == str(7 * 10**17)
    assert final["actual_policy_units"] == str(5 * 10**17)
    assert final["released_policy_units"] == str(2 * 10**17)
    assert final["provider_authoritative_billing"] is False
    assert final["authority_accounting_only"] is True
    for receipt in (credential, reservation, final):
        assert (
            receipt["release_lineage_digest"]
            == service["expected"].release_lineage_digest
        )
        assert (
            receipt["account_binding_ceremony_receipt_digest"]
            == service["expected"].account_binding_ceremony_receipt_digest
        )
        assert (
            receipt["deployment_intent_digest"]
            == service["expected"].deployment_intent_digest
        )
        assert receipt["account_binding_authority_digest"].startswith("sha256:")
    status = service["adapter"].account_status(
        wallet_token="wallet-token", account_id=request["account_id"], now=NOW
    )
    assert status["outstanding_policy_units"] == "0"
    assert status["settled_policy_units"] == str(5 * 10**17)
    assert credential["credential_id"] in service["store"].read()["credentials"]


def test_release_outcome_refunds_full_authority_reservation(service):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=10**18,
        workload_commitment=digest("workload-release"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    service["settlement"].results[reservation["reservation_id"]] = AttestedSettlementResult(
        reservation_id=reservation["reservation_id"],
        reservation_commitment=reservation["reservation_commitment"],
        outcome="released",
        actual_policy_units=0,
        usage_receipt_hash=digest("release"),
        release_policy_tuple_digest=service["expected"].policy_tuple_digest,
        runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        provider_dispatch_performed=False,
    )
    final = service["adapter"].finalize_reservation(
        reservation_id=reservation["reservation_id"],
        idempotency_key="reservation-final-0001",
        now=NOW,
    )

    assert final["status"] == "released"
    assert final["actual_policy_units"] == "0"
    assert final["released_policy_units"] == str(10**18)


def test_settlement_rejects_zero_usage_receipt_commitment(service):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("zero-usage-receipt-workload"),
        idempotency_key="reservation-zero-usage-create-0001",
        now=NOW,
    )
    service["settlement"].results[reservation["reservation_id"]] = (
        AttestedSettlementResult(
            reservation_id=reservation["reservation_id"],
            reservation_commitment=reservation["reservation_commitment"],
            outcome="settled",
            actual_policy_units=1,
            usage_receipt_hash="sha256:" + "00" * 32,
            release_policy_tuple_digest=service["expected"].policy_tuple_digest,
            runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
            issued_at=NOW - 1,
            expires_at=NOW + 60,
            provider_dispatch_performed=True,
        )
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_SETTLEMENT_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="reservation-zero-usage-final-0001",
            now=NOW,
        )

    assert (
        service["store"].read()["reservations"][reservation["reservation_id"]][
            "status"
        ]
        == "reserved"
    )


@pytest.mark.parametrize(
    "invalid",
    (
        "false",
        1,
        None,
        {"provider_session": "SETTLEMENT-EGRESS-CANARY"},
        ["SETTLEMENT-EGRESS-CANARY"],
    ),
)
def test_settlement_provider_dispatch_is_an_exact_boolean_before_projection(
    service,
    invalid,
):
    canary = "SETTLEMENT-EGRESS-CANARY"
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("settlement-dispatch-type"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    service["settlement"].results[reservation["reservation_id"]] = (
        AttestedSettlementResult(
            reservation_id=reservation["reservation_id"],
            reservation_commitment=reservation["reservation_commitment"],
            outcome="settled",
            actual_policy_units=1,
            usage_receipt_hash=digest("usage-dispatch-type"),
            release_policy_tuple_digest=service["expected"].policy_tuple_digest,
            runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
            issued_at=NOW - 1,
            expires_at=NOW + 60,
            provider_dispatch_performed=invalid,
        )
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_SETTLEMENT_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="reservation-final-0001",
            now=NOW,
        )

    persisted = service["store"].read()["reservations"][
        reservation["reservation_id"]
    ]
    assert persisted["status"] == "reserved"
    assert_canary_absent(service, canary)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("provider_authoritative_billing", "false"),
        ("provider_authoritative_billing", 0),
        ("provider_authoritative_billing", None),
        ("raw_secret_egress", "false"),
        ("raw_secret_egress", 0),
        ("raw_secret_egress", None),
    ),
)
def test_settlement_no_egress_truth_fields_are_exact_booleans(
    service,
    field,
    invalid,
):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("settlement-truth-type"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    result = AttestedSettlementResult(
        reservation_id=reservation["reservation_id"],
        reservation_commitment=reservation["reservation_commitment"],
        outcome="settled",
        actual_policy_units=1,
        usage_receipt_hash=digest("usage-truth-type"),
        release_policy_tuple_digest=service["expected"].policy_tuple_digest,
        runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        provider_dispatch_performed=True,
    )
    service["settlement"].results[reservation["reservation_id"]] = replace(
        result,
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_SETTLEMENT_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="reservation-final-0001",
            now=NOW,
        )

    assert (
        service["store"].read()["reservations"][reservation["reservation_id"]][
            "status"
        ]
        == "reserved"
    )


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("issued_at", "1899999999"),
        ("issued_at", 1_899_999_999.0),
        ("issued_at", True),
        ("expires_at", "1900000060"),
        ("expires_at", 1_900_000_060.0),
        ("expires_at", True),
        ("actual_policy_units", True),
    ),
)
def test_settlement_numeric_fields_require_exact_integers(service, field, invalid):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("settlement-integer-type"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    result = AttestedSettlementResult(
        reservation_id=reservation["reservation_id"],
        reservation_commitment=reservation["reservation_commitment"],
        outcome="settled",
        actual_policy_units=1,
        usage_receipt_hash=digest("usage-integer-type"),
        release_policy_tuple_digest=service["expected"].policy_tuple_digest,
        runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        provider_dispatch_performed=True,
    )
    service["settlement"].results[reservation["reservation_id"]] = replace(
        result,
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_SETTLEMENT_PROVIDER_UNAVAILABLE}$",
    ):
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="reservation-final-0001",
            now=NOW,
        )

    assert (
        service["store"].read()["reservations"][reservation["reservation_id"]][
            "status"
        ]
        == "reserved"
    )


def test_reservation_caps_fail_without_mutating_state(service):
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    sequence = service["store"].read()["sequence"]

    with pytest.raises(TinkerCustomerError, match="per-operation"):
        service["adapter"].reserve_spend(
            credential_token=token,
            operation="training",
            amount_policy_units=10**18 + 1,
            workload_commitment=digest("too-large"),
            idempotency_key="reservation-create-0001",
            now=NOW,
        )
    state = service["store"].read()
    assert state["sequence"] == sequence
    assert state["reservations"] == {}


def test_credential_and_account_revocation_are_monotonic(service):
    request = request_account(service)
    activate_account(service, request)
    credential, token = issue_credential(service, request["account_id"])
    revoke = service["adapter"].revoke_credential(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        credential_id=credential["credential_id"],
        idempotency_key="credential-revoke-0001",
        now=NOW,
    )
    assert revoke["status"] == "revoked"
    with pytest.raises(TinkerCustomerError, match="revoked or expired"):
        service["adapter"].reserve_spend(
            credential_token=token,
            operation="training",
            amount_policy_units=1,
            workload_commitment=digest("revoked"),
            idempotency_key="reservation-create-0001",
            now=NOW,
        )
    account_revoke = service["adapter"].revoke_account(
        wallet_token="wallet-token",
        account_id=request["account_id"],
        idempotency_key="account-revoke-0001",
        now=NOW,
    )
    assert account_revoke["new_authority_permitted"] is False
    _, public = recipient_keypair()
    with pytest.raises(TinkerCustomerError, match="not active"):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-issue-0002",
            now=NOW,
        )


def test_each_mutation_rechecks_release_and_fresh_runtime_evidence(service):
    request = request_account(service)
    assert service["reader"].calls == 1
    assert service["evidence"].calls == 1
    activate_account(service, request)
    assert service["reader"].calls == 2
    assert service["evidence"].calls == 2
    service["reader"].snapshot = replace(service["reader"].snapshot, emergency_halted=True)
    _, public = recipient_keypair()
    before = service["store"].read()["sequence"]
    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RELEASE_READER_UNAVAILABLE}$",
    ):
        service["adapter"].issue_credential(
            wallet_token="wallet-token",
            account_id=request["account_id"],
            recipient_public_key=public,
            operations=["training"],
            ttl_seconds=300,
            idempotency_key="credential-issue-0001",
            now=NOW,
        )
    assert service["store"].read()["sequence"] == before


def test_wallet_verifier_exception_is_non_reflective_and_not_persisted(service):
    marker = "WALLET-AUTH-SECRET-CANARY"
    service["adapter"].wallet_verifier = MarkerFailure(marker)

    with pytest.raises(TinkerCustomerError) as caught:
        request_account(service)

    assert_fixed_boundary_error(
        caught.value,
        TC_WALLET_VERIFIER_UNAVAILABLE,
        marker,
    )
    assert_canary_absent(service, marker)


@pytest.mark.parametrize(
    ("boundary", "code"),
    (
        ("release_reader", TC_RELEASE_READER_UNAVAILABLE),
        ("evidence_provider", TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE),
    ),
)
def test_gate_provider_exceptions_are_non_reflective_and_not_persisted(
    service,
    boundary,
    code,
):
    marker = f"{boundary.upper()}-SECRET-CANARY"
    setattr(service["adapter"], boundary, MarkerFailure(marker))

    with pytest.raises(TinkerCustomerUnavailable) as caught:
        request_account(service)

    assert_fixed_boundary_error(caught.value, code, marker)
    assert_canary_absent(service, marker)


def test_malformed_release_and_evidence_objects_cannot_reflect_exceptions(
    service,
):
    release_marker = "MALFORMED-RELEASE-RESULT-SECRET-CANARY"

    class ExplodingIterable:
        def __iter__(self):
            raise RuntimeError(release_marker)

    service["reader"].snapshot = replace(
        service["reader"].snapshot,
        approved_compose_hashes=ExplodingIterable(),
    )
    with pytest.raises(TinkerCustomerUnavailable) as release_error:
        request_account(service)
    assert_fixed_boundary_error(
        release_error.value,
        TC_RELEASE_READER_UNAVAILABLE,
        release_marker,
    )
    assert_canary_absent(service, release_marker)

    service["reader"].snapshot = release_snapshot(service["expected"])
    evidence_marker = "MALFORMED-EVIDENCE-RESULT-SECRET-CANARY"
    service["evidence"].override = replace(
        service["evidence"].value(NOW),
        tdx_verified={"verdict": evidence_marker},
    )
    with pytest.raises(TinkerCustomerUnavailable) as evidence_error:
        request_account(service)
    assert_fixed_boundary_error(
        evidence_error.value,
        TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE,
        evidence_marker,
    )
    assert_canary_absent(service, evidence_marker)


def test_malformed_provisioning_result_cannot_reflect_field_exceptions(service):
    marker = "MALFORMED-PROVISIONING-FIELD-SECRET-CANARY"

    class ExplodingEquality:
        def __eq__(self, other):
            raise RuntimeError(marker)

    request = request_account(service)
    service["provisioner"].results[request["account_id"]] = replace(
        valid_provisioning_result(service, request),
        account_id=ExplodingEquality(),
    )
    with pytest.raises(TinkerCustomerUnavailable) as caught:
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="malformed-provisioning-result-0001",
            now=NOW,
        )

    assert_fixed_boundary_error(
        caught.value,
        TC_PROVISIONING_PROVIDER_UNAVAILABLE,
        marker,
    )
    assert (
        service["store"].read()["accounts"][request["account_id"]]["status"]
        == "requested"
    )
    assert_canary_absent(service, marker)


def test_malformed_settlement_result_cannot_reflect_field_exceptions(service):
    marker = "MALFORMED-SETTLEMENT-FIELD-SECRET-CANARY"

    class ExplodingEquality:
        def __eq__(self, other):
            raise RuntimeError(marker)

    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("malformed-settlement-workload"),
        idempotency_key="malformed-settlement-reservation-0001",
        now=NOW,
    )
    service["settlement"].results[reservation["reservation_id"]] = replace(
        AttestedSettlementResult(
            reservation_id=reservation["reservation_id"],
            reservation_commitment=reservation["reservation_commitment"],
            outcome="settled",
            actual_policy_units=1,
            usage_receipt_hash=digest("malformed-settlement-usage"),
            release_policy_tuple_digest=service["expected"].policy_tuple_digest,
            runtime_evidence_digest=service["evidence"].value(NOW).public_digest(),
            issued_at=NOW - 1,
            expires_at=NOW + 60,
            provider_dispatch_performed=True,
        ),
        reservation_id=ExplodingEquality(),
    )
    with pytest.raises(TinkerCustomerUnavailable) as caught:
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="malformed-settlement-final-0001",
            now=NOW,
        )

    assert_fixed_boundary_error(
        caught.value,
        TC_SETTLEMENT_PROVIDER_UNAVAILABLE,
        marker,
    )
    assert (
        service["store"].read()["reservations"][reservation["reservation_id"]][
            "status"
        ]
        == "reserved"
    )
    assert_canary_absent(service, marker)


def test_provisioning_exception_is_non_reflective_and_not_persisted(service):
    marker = "PROVISIONER-SESSION-SECRET-CANARY"
    request = request_account(service)
    service["adapter"].provisioning_provider = MarkerFailure(marker)

    with pytest.raises(TinkerCustomerUnavailable) as caught:
        service["adapter"].activate_account(
            account_id=request["account_id"],
            idempotency_key="account-activate-0001",
            now=NOW,
        )

    assert_fixed_boundary_error(
        caught.value,
        TC_PROVISIONING_PROVIDER_UNAVAILABLE,
        marker,
    )
    persisted = service["store"].read()["accounts"][request["account_id"]]
    assert persisted["status"] == "requested"
    assert persisted["account_binding_authority"] == {}
    assert_canary_absent(service, marker)


def test_settlement_exception_is_non_reflective_and_not_persisted(service):
    marker = "SETTLEMENT-PROVIDER-AUTH-CANARY"
    request = request_account(service)
    activate_account(service, request)
    _, token = issue_credential(service, request["account_id"])
    reservation = service["adapter"].reserve_spend(
        credential_token=token,
        operation="training",
        amount_policy_units=1,
        workload_commitment=digest("settlement-provider-failure"),
        idempotency_key="reservation-create-0001",
        now=NOW,
    )
    service["adapter"].settlement_provider = MarkerFailure(marker)

    with pytest.raises(TinkerCustomerUnavailable) as caught:
        service["adapter"].finalize_reservation(
            reservation_id=reservation["reservation_id"],
            idempotency_key="reservation-final-0001",
            now=NOW,
        )

    assert_fixed_boundary_error(
        caught.value,
        TC_SETTLEMENT_PROVIDER_UNAVAILABLE,
        marker,
    )
    assert (
        service["store"].read()["reservations"][reservation["reservation_id"]][
            "status"
        ]
        == "reserved"
    )
    assert_canary_absent(service, marker)


def test_expired_or_failed_qvl_evidence_blocks_before_mutation(service):
    value = service["evidence"].value(NOW)
    service["evidence"].override = replace(value, qvl_pass=False)
    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE}$",
    ):
        request_account(service)
    assert service["store"].read()["accounts"] == {}


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("tdx_verified", "false"),
        ("tdx_verified", 1),
        ("tdx_verified", {"verdict": "pass"}),
        ("qvl_pass", "false"),
        ("qvl_pass", 1),
        ("qvl_pass", ["pass"]),
        ("raw_quote_publicly_disclosed", 0),
        ("raw_collateral_publicly_disclosed", None),
        ("raw_secret_egress", ""),
    ),
)
def test_runtime_evidence_booleans_are_exact_and_never_upgraded_to_pass(
    service,
    field,
    invalid,
):
    canary = "RUNTIME-EVIDENCE-CANARY"
    if isinstance(invalid, dict):
        invalid = {"verdict": canary}
    elif isinstance(invalid, list):
        invalid = [canary]
    value = service["evidence"].value(NOW)
    service["evidence"].override = replace(value, **{field: invalid})

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE}$",
    ):
        request_account(service)

    assert service["store"].read()["accounts"] == {}
    assert_canary_absent(service, canary)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("issued_at", "1899999999"),
        ("issued_at", 1_899_999_999.0),
        ("issued_at", True),
        ("expires_at", "1900000060"),
        ("expires_at", 1_900_000_060.0),
        ("expires_at", True),
    ),
)
def test_runtime_evidence_timestamps_require_exact_integers(
    service,
    field,
    invalid,
):
    service["evidence"].override = replace(
        service["evidence"].value(NOW),
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE}$",
    ):
        request_account(service)

    assert service["store"].read()["accounts"] == {}


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("release_policy_frozen", 1),
        ("emergency_halted", 0),
        ("finalized_block_number", True),
        ("max_spend_policy_units", 5.0),
    ),
)
def test_live_release_snapshot_requires_exact_primitives(service, field, invalid):
    service["reader"].snapshot = replace(
        service["reader"].snapshot,
        **{field: invalid},
    )

    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RELEASE_READER_UNAVAILABLE}$",
    ):
        request_account(service)

    assert service["store"].read()["accounts"] == {}


def test_customer_policy_digest_must_match_at_construction_and_runtime(service):
    mismatched_policy = replace(
        service["evidence"].policy,
        customer_policy_digest=digest("different-customer-policy"),
    )
    with pytest.raises(TinkerCustomerError, match="not bound by the release evidence policy"):
        TinkerCustomerAdapter(
            wallet_verifier=service["wallet"],
            release_reader=service["reader"],
            expected_release=service["expected"],
            evidence_provider=service["evidence"],
            evidence_policy=mismatched_policy,
            provisioning_provider=service["provisioner"],
            settlement_provider=service["settlement"],
            store=service["store"],
            account_policy=service["policy"],
            credential_signing_key=b"c" * 32,
        )

    live = service["evidence"].value(NOW)
    service["evidence"].override = replace(
        live,
        customer_policy_digest=digest("different-customer-policy"),
    )
    with pytest.raises(
        TinkerCustomerUnavailable,
        match=f"^{TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE}$",
    ):
        request_account(service)
    assert service["store"].read()["accounts"] == {}


def test_store_detects_tampering_and_uses_private_permissions(service):
    request_account(service)
    path = service["store"].path
    assert os.stat(path).st_mode & 0o777 == 0o600
    document = json.loads(path.read_text())
    document["state"]["sequence"] += 1
    path.write_text(json.dumps(document))
    with pytest.raises(TinkerCustomerStoreCorrupt, match="integrity"):
        service["store"].read()


@pytest.mark.parametrize("mode", (0o400, 0o700))
def test_store_requires_exact_mode_0600_on_every_read(service, mode):
    request_account(service)
    os.chmod(service["store"].path, mode)

    with pytest.raises(TinkerCustomerStoreCorrupt, match="metadata"):
        service["store"].read()


def test_store_recovers_ambiguous_anchor_commit_without_replaying_mutation(service):
    service["anchor"].fail_after_commit = True
    with pytest.raises(
        TinkerCustomerUnavailable,
        match=TC_STATE_ANCHOR_UPDATE_UNAVAILABLE,
    ) as caught:
        request_account(service)
    assert str(caught.value) == TC_STATE_ANCHOR_UPDATE_UNAVAILABLE
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None

    assert service["store"]._pending_path.exists()
    recovered = service["store"].read()
    assert recovered["sequence"] == 1
    assert len(recovered["accounts"]) == 1
    assert not service["store"]._pending_path.exists()
    replay = request_account(service)
    assert replay["idempotent_replay"] is True
    assert service["anchor"].head.sequence == 1


def test_anchor_exceptions_are_fixed_non_reflective_codes(service):
    read_marker = "ANCHOR-READ-SECRET-CANARY"
    original_read = service["anchor"].read_head

    def fail_read():
        raise RuntimeError(read_marker)

    service["anchor"].read_head = fail_read
    with pytest.raises(TinkerCustomerUnavailable) as read_error:
        service["store"].read()
    assert_fixed_boundary_error(
        read_error.value,
        TC_STATE_ANCHOR_READ_UNAVAILABLE,
        read_marker,
    )
    service["anchor"].read_head = original_read
    assert_canary_absent(service, read_marker)

    update_marker = "ANCHOR-UPDATE-SECRET-CANARY"
    original_compare = service["anchor"].compare_and_set

    def fail_compare(**kwargs):
        raise RuntimeError(update_marker)

    service["anchor"].compare_and_set = fail_compare
    with pytest.raises(TinkerCustomerUnavailable) as update_error:
        request_account(service)
    assert_fixed_boundary_error(
        update_error.value,
        TC_STATE_ANCHOR_UPDATE_UNAVAILABLE,
        update_marker,
    )
    service["anchor"].compare_and_set = original_compare
    service["store"].read()
    assert_canary_absent(service, update_marker)


@pytest.mark.parametrize(
    "secret_payload",
    (
        {"nested": {"upstream_api_key": "forbidden-value"}},
        {"nested": {"providerAccountId": "forbidden-value"}},
        {"nested": {"provider_session": "forbidden-value"}},
        {"nested": {"reviewer-share": "forbidden-value"}},
    ),
)
def test_store_recursively_rejects_secret_shaped_fields(service, secret_payload):
    with pytest.raises(TinkerCustomerError, match="forbidden"):
        service["store"].transact(
            lambda state: state["idempotency"].__setitem__(
                "forbidden-state-0001",
                {
                    "request_hash": digest("request"),
                    "result": secret_payload,
                },
            )
        )


def test_store_rejects_oversized_or_symlinked_files_and_parent(tmp_path: Path, service):
    request_account(service)
    with service["store"].path.open("r+b") as handle:
        handle.truncate(MAX_CUSTOMER_STORE_BYTES + 1)
    with pytest.raises(TinkerCustomerStoreCorrupt, match="metadata"):
        service["store"].read()

    real_parent = tmp_path / "real-private"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-private"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(TinkerCustomerUnavailable, match="symlink"):
        TinkerCustomerStore(linked_parent / "state.json", b"s" * 32, anchor=FakeAnchor())

    target = real_parent / "other.json"
    target.write_text("{}")
    os.chmod(target, 0o600)
    (real_parent / "state.json").symlink_to(target)
    symlink_store = TinkerCustomerStore(real_parent / "state.json", b"s" * 32, anchor=FakeAnchor())
    with pytest.raises(TinkerCustomerStoreCorrupt, match="regular file"):
        symlink_store.read()


class FakeRpc:
    def __init__(self, url: str, expected: ExpectedTinkerRelease, *, code=RUNTIME_CODE, block_hash=BLOCK_HASH):
        self.url = url
        self.expected = expected
        self.code = code
        self.block_hash = block_hash

    def request(self, method, params):
        if method == "eth_chainId":
            return hex(84532)
        if method == "eth_getBlockByNumber":
            return {"number": hex(16), "hash": self.block_hash}
        if method == "eth_getCode":
            assert params[1] == hex(16)
            return "0x" + self.code.hex()
        if method != "eth_call":
            raise AssertionError(method)
        call, block = params
        assert call["to"] == self.expected.contract_address
        assert block == hex(16)
        data = bytes.fromhex(call["data"][2:])
        selector = data[:4]
        getters = {
            keccak(b"owner()")[:4]: _address_abi(self.expected.owner),
            keccak(b"pendingOwner()")[:4]: bytes(32),
            keccak(b"accountCommitment()")[:4]: bytes.fromhex(self.expected.account_commitment[2:]),
            keccak(b"releasePolicyCommitment()")[:4]: bytes.fromhex(self.expected.release_policy_commitment[2:]),
            keccak(b"releasePolicyFrozen()")[:4]: _uint_abi(1),
            keccak(b"emergencyHalted()")[:4]: _uint_abi(0),
            keccak(b"approvedComposeRoot()")[:4]: bytes.fromhex(self.expected.approved_compose_root[2:]),
            keccak(b"approvedComposeCount()")[:4]: _uint_abi(len(self.expected.approved_compose_hashes)),
            keccak(b"managerRoot()")[:4]: bytes.fromhex(self.expected.manager_root[2:]),
            keccak(b"managerCount()")[:4]: _uint_abi(len(self.expected.managers)),
            keccak(b"maxAddBalanceWei()")[:4]: _uint_abi(self.expected.max_add_balance_policy_units),
            keccak(b"maxSpendWei()")[:4]: _uint_abi(self.expected.max_spend_policy_units),
            keccak(b"releaseMaxAddBalanceWei()")[:4]: _uint_abi(self.expected.max_add_balance_policy_units),
            keccak(b"releaseMaxSpendWei()")[:4]: _uint_abi(self.expected.max_spend_policy_units),
            keccak(b"approvedComposeHashAt(uint256)")[:4]: bytes.fromhex(self.expected.approved_compose_hashes[0][2:]),
            keccak(b"managerAt(uint256)")[:4]: _address_abi(self.expected.managers[0]),
            keccak(b"approvedComposeHashes(bytes32)")[:4]: _uint_abi(1),
            keccak(b"managers(address)")[:4]: _uint_abi(1),
        }
        return "0x" + getters[selector].hex()


def _uint_abi(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _address_abi(value: str) -> bytes:
    return bytes(12) + bytes.fromhex(value[2:])


def test_dual_rpc_reader_authenticates_same_numeric_finalized_policy_tuple():
    expected = expected_release()
    reader = DualRpcTinkerReleaseReader(
        FakeRpc("https://rpc-a.example", expected),
        FakeRpc("https://rpc-b.example", expected),
        expected,
    )
    snapshot = reader.read()

    assert snapshot.finalized_block_number == 16
    assert snapshot.finalized_block_hash == BLOCK_HASH
    assert snapshot.runtime_code_hash == expected.runtime_code_hash
    assert snapshot.policy_tuple_digest == expected.policy_tuple_digest


@pytest.mark.parametrize(
    ("secondary_head_number", "secondary_head_hash"),
    (
        (17, BLOCK_HASH),
        (16, "0x" + "aa" * 32),
    ),
)
def test_dual_rpc_reader_rejects_stale_or_hash_divergent_finalized_heads(
    secondary_head_number,
    secondary_head_hash,
):
    expected = expected_release()

    class DivergentHeadRpc(FakeRpc):
        def request(self, method, params):
            if method == "eth_getBlockByNumber" and params[0] == "finalized":
                return {
                    "number": hex(secondary_head_number),
                    "hash": secondary_head_hash,
                }
            return super().request(method, params)

    reader = DualRpcTinkerReleaseReader(
        FakeRpc("https://rpc-a.example", expected),
        DivergentHeadRpc("https://rpc-b.example", expected),
        expected,
    )
    with pytest.raises(TinkerCustomerUnavailable, match="exact finalized head"):
        reader.read()


def test_dual_rpc_reader_fails_closed_on_runtime_or_origin_divergence():
    expected = expected_release()
    with pytest.raises(TinkerCustomerUnavailable, match="distinct provider"):
        DualRpcTinkerReleaseReader(
            FakeRpc("https://same.example:8443", expected),
            FakeRpc("https://same.example:9443", expected),
            expected,
        )

    reader = DualRpcTinkerReleaseReader(
        FakeRpc("https://rpc-a.example", expected),
        FakeRpc("https://rpc-b.example", expected, code=b"\x60\x00"),
        expected,
    )
    with pytest.raises(TinkerCustomerUnavailable, match="runtime code"):
        reader.read()


def test_dual_rpc_reader_rejects_protocols_without_explicit_canonical_origins():
    expected = expected_release()

    class NoOriginRpc:
        def request(self, method, params):
            raise AssertionError("must fail before network use")

    with pytest.raises(TinkerCustomerUnavailable, match="expose canonical HTTPS URLs"):
        DualRpcTinkerReleaseReader(NoOriginRpc(), NoOriginRpc(), expected)


@pytest.mark.parametrize(
    "url",
    (
        "http://rpc-a.example",
        "https://RPC-A.example",
        "https://rpc-a.example.",
        "https://rpc-a.example/",
        "https://rpc-a.example/v2/key",
        "https://rpc-a.example?key=secret",
        "https://user:secret@rpc-a.example",
        "https://rpc-a.example:443",
    ),
)
def test_dual_rpc_reader_rejects_noncanonical_or_credential_bearing_urls(url):
    expected = expected_release()
    with pytest.raises(
        TinkerCustomerUnavailable,
        match="canonical credential-free HTTPS endpoints",
    ):
        DualRpcTinkerReleaseReader(
            FakeRpc(url, expected),
            FakeRpc("https://rpc-b.example", expected),
            expected,
        )
