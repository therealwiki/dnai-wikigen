"""Attestation-gated ciphertext ingress for exact-asset Compute workloads.

This module is a storage and authorization boundary, not a provider adapter.
The public API accepts only a strict X25519/HKDF-SHA256/AES-256-GCM envelope
whose AAD binds the authenticated project actor, immutable workload manifest,
plaintext commitment, resource caps, recipient key, and a fresh independently
verified recipient activation.  It never accepts or decrypts a prompt, SFT
example, dataset, or model output.

The execution CVM is responsible for decrypting a stored envelope and calling
``validate_compute_workload_plaintext`` before any future provider operation.
Provider dispatch remains separately disabled until its own replay-conformance
gate passes.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.exceptions import InvalidTag

from tinker_delegate import dstack_utils
from tinker_delegate.crypto import EncryptedPayload, TEEKeyPair
from tinker_delegate.result_verifier import (
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    ResultVerifierError,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_digest,
)


WORKLOAD_INGRESS_SCHEMA_VERSION = 1
WORKLOAD_PUBLIC_SCHEMA_VERSION = 2
WORKLOAD_INDEX_SCHEMA_VERSION = 2
WORKLOAD_INGRESS_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM"
WORKLOAD_INGRESS_ENCODING = "base64url-nopad"
WORKLOAD_INGRESS_CONTEXT = "compute_workload_ingress"
WORKLOAD_ATTESTATION_CONTEXT = "compute_workload"
WORKLOAD_RECIPIENT_ACTIVATION_SCHEMA = (
    "dnai.compute.workload-recipient-activation.v3"
)
WORKLOAD_HKDF_INFO = b"dnai-wikigen/compute-workload-ingress/v1"
WORKLOAD_COMMITMENT_DOMAIN = b"dnai-wikigen/compute-workload/v1\0"
WORKLOAD_RECIPIENT_RELEASE_DOMAIN = (
    b"dnai-wikigen/compute-workload-recipient-release/v2\0"
)
WORKLOAD_RECIPIENT_ATTESTATION_DOMAIN = (
    b"dnai-wikigen/compute-workload-recipient-attestation/v1\0"
)
WORKLOAD_STORE_MAC_DOMAIN = b"dnai-wikigen/compute-workload-store/v1\0"
WORKLOAD_BLOB_HASH_DOMAIN = b"dnai-wikigen/compute-workload-envelope/v1\0"
WORKLOAD_EXECUTION_BINDING_DOMAIN = (
    b"dnai-wikigen/compute-workload-execution-binding/v1\0"
)
WORKLOAD_DISPATCH_CLAIM_DOMAIN = (
    b"dnai-wikigen/compute-workload-dispatch-claim/v1\0"
)
WORKLOAD_DSTACK_KEY_PATH = "tinker/compute_workload_ingress"
WORKLOAD_INTEGRITY_DSTACK_KEY_PATH = (
    "tinker/compute_workload_ingress_integrity"
)

INFERENCE_WORKLOAD_SCHEMA = "dnai.compute.workload.inference.v1"
SFT_JSONL_WORKLOAD_SCHEMA = "dnai.compute.workload.sft-jsonl.v1"
INFERENCE_PAYLOAD_SCHEMA = "dnai.compute.inference-prompt.v1"

MAX_CIPHERTEXT_BYTES = 1_048_576
GCM_TAG_BYTES = 16
MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES
MAX_AAD_BYTES = 8_192
MAX_ENVELOPES = 10_000
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_BLOB_FILE_BYTES = 1_500_000
MAX_INFERENCE_PROMPT_BYTES = 262_144
MAX_SFT_EXAMPLES = 256
MAX_SFT_FIELD_BYTES = 32_768
X25519_PUBLIC_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
SEALED_FRAME_MAGIC = b"DNAIWL1\0"
SEALED_BLINDING_BYTES = 32
SEALED_LENGTH_BYTES = 4
SEALED_FRAME_HEADER_BYTES = (
    len(SEALED_FRAME_MAGIC) + SEALED_LENGTH_BYTES + SEALED_BLINDING_BYTES
)
MAX_PRIVATE_PAYLOAD_BYTES = MAX_PLAINTEXT_BYTES - SEALED_FRAME_HEADER_BYTES
PAYLOAD_CLASS_BYTES = {
    "4k": 4_096,
    "16k": 16_384,
    "64k": 65_536,
    "256k": 262_144,
    "1m": MAX_PLAINTEXT_BYTES,
}
EXAMPLE_COUNT_CLASSES = {
    "none": (0, 0),
    "1_8": (1, 8),
    "9_32": (9, 32),
    "33_128": (33, 128),
    "129_256": (129, 256),
}

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_PHALA_APP_ID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_RESOURCE_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_WORKLOAD_ID = re.compile(r"^wrk_[0-9a-f]{32}$")
_OBJECT_ID = re.compile(r"^workload-[0-9a-f]{64}$")
_DSTACK_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class ComputeWorkloadIngressError(ValueError):
    """A bounded workload-ingress value is invalid."""


class ComputeWorkloadIngressConflict(ComputeWorkloadIngressError):
    """An idempotency key or nonce tuple was reused inconsistently."""


class ComputeWorkloadIngressCorrupt(ComputeWorkloadIngressError):
    """Authenticated workload state is missing, unsafe, or inconsistent."""


class ComputeWorkloadIngressUnavailable(RuntimeError):
    """Recipient custody, verification, or durable storage is unavailable."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ComputeWorkloadIngressError(
            "Compute workload value is not canonical JSON"
        ) from exc


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], *, label: str
) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ComputeWorkloadIngressError(
            f"{label} has missing or non-allowlisted fields"
        )


def _string(
    value: Any,
    *,
    label: str,
    maximum: int,
    minimum: int = 1,
) -> str:
    if not isinstance(value, str):
        raise ComputeWorkloadIngressError(f"{label} must be a string")
    size = len(value.encode("utf-8"))
    if size < minimum or size > maximum:
        raise ComputeWorkloadIngressError(f"{label} length is outside its bound")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ComputeWorkloadIngressError(f"{label} contains control characters")
    return value


def _integer(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ComputeWorkloadIngressError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ComputeWorkloadIngressError(f"{label} is outside its bound")
    return value


def _b64_size(byte_count: int) -> int:
    return (byte_count * 8 + 5) // 6


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(
    value: Any,
    *,
    label: str,
    maximum_bytes: int,
    exact_bytes: int | None = None,
) -> bytes:
    encoded = _string(
        value,
        label=label,
        maximum=_b64_size(maximum_bytes),
    )
    if not _B64URL.fullmatch(encoded) or "=" in encoded:
        raise ComputeWorkloadIngressError(
            f"{label} must be canonical base64url without padding"
        )
    if exact_bytes is not None and len(encoded) != _b64_size(exact_bytes):
        raise ComputeWorkloadIngressError(f"{label} has invalid encoded length")
    try:
        decoded = base64.b64decode(
            encoded + "=" * ((-len(encoded)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ComputeWorkloadIngressError(f"{label} is invalid base64url") from exc
    if len(decoded) > maximum_bytes or (
        exact_bytes is not None and len(decoded) != exact_bytes
    ):
        raise ComputeWorkloadIngressError(f"{label} decoded length is invalid")
    if _b64encode(decoded) != encoded:
        raise ComputeWorkloadIngressError(f"{label} is not canonically encoded")
    return decoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ComputeWorkloadIngressError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ComputeWorkloadIngressError(f"{label} must be an object")
    return value


@dataclass(frozen=True)
class ComputeWorkloadManifest:
    """Public shape and exact caps for one encrypted workload."""

    schema: str
    operation: str
    model: str
    recipe: str
    payload_size_class: str
    example_count_class: str
    max_prefill_tokens: int
    max_sample_tokens: int
    max_train_tokens: int

    _FIELDS = frozenset(
        {
            "schema",
            "operation",
            "model",
            "recipe",
            "payload_size_class",
            "example_count_class",
            "max_prefill_tokens",
            "max_sample_tokens",
            "max_train_tokens",
        }
    )

    def __post_init__(self) -> None:
        if self.schema not in {
            INFERENCE_WORKLOAD_SCHEMA,
            SFT_JSONL_WORKLOAD_SCHEMA,
        }:
            raise ComputeWorkloadIngressError("Compute workload schema is unsupported")
        if self.model != "qwen3_8b":
            raise ComputeWorkloadIngressError("Compute workload model is unsupported")
        if self.payload_size_class not in PAYLOAD_CLASS_BYTES:
            raise ComputeWorkloadIngressError(
                "Compute workload payload size class is unsupported"
            )
        if self.example_count_class not in EXAMPLE_COUNT_CLASSES:
            raise ComputeWorkloadIngressError(
                "Compute workload example count class is unsupported"
            )
        for label, value in (
            ("max_prefill_tokens", self.max_prefill_tokens),
            ("max_sample_tokens", self.max_sample_tokens),
            ("max_train_tokens", self.max_train_tokens),
        ):
            _integer(value, label=label, minimum=0, maximum=100_000_000)
        if self.schema == INFERENCE_WORKLOAD_SCHEMA:
            if (
                self.operation != "inference"
                or self.recipe != "qwen3_8b_bounded"
                or self.example_count_class != "none"
                or not 1 <= self.max_prefill_tokens <= 32_768
                or not 1 <= self.max_sample_tokens <= 4_096
                or self.max_train_tokens != 0
            ):
                raise ComputeWorkloadIngressError(
                    "inference workload schema and resource caps do not match"
                )
        elif (
            self.operation != "training"
            or self.recipe != "qwen3_8b_lora_r32"
            or self.example_count_class == "none"
            or self.max_prefill_tokens != 0
            or self.max_sample_tokens != 0
            or not 1 <= self.max_train_tokens <= 10_000_000
        ):
            raise ComputeWorkloadIngressError(
                "SFT workload schema and resource caps do not match"
            )

    @property
    def commitment(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "operation": self.operation,
            "model": self.model,
            "recipe": self.recipe,
            "payload_size_class": self.payload_size_class,
            "example_count_class": self.example_count_class,
            "max_prefill_tokens": self.max_prefill_tokens,
            "max_sample_tokens": self.max_sample_tokens,
            "max_train_tokens": self.max_train_tokens,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ComputeWorkloadManifest":
        _exact_keys(value, cls._FIELDS, label="Compute workload manifest")
        return cls(
            schema=_string(value["schema"], label="schema", maximum=64),
            operation=_string(value["operation"], label="operation", maximum=16),
            model=_string(value["model"], label="model", maximum=32),
            recipe=_string(value["recipe"], label="recipe", maximum=64),
            payload_size_class=_string(
                value["payload_size_class"],
                label="payload_size_class",
                maximum=8,
            ),
            example_count_class=_string(
                value["example_count_class"],
                label="example_count_class",
                maximum=16,
            ),
            max_prefill_tokens=_integer(
                value["max_prefill_tokens"],
                label="max_prefill_tokens",
                minimum=0,
                maximum=100_000_000,
            ),
            max_sample_tokens=_integer(
                value["max_sample_tokens"],
                label="max_sample_tokens",
                minimum=0,
                maximum=100_000_000,
            ),
            max_train_tokens=_integer(
                value["max_train_tokens"],
                label="max_train_tokens",
                minimum=0,
                maximum=100_000_000,
            ),
        )


def compute_workload_commitment(
    manifest: ComputeWorkloadManifest,
    sealed_plaintext: bytes | bytearray,
) -> str:
    """Commit a blinded private payload to public schema/caps.

    The 32-byte blind is inside the encrypted fixed-class frame. It prevents a
    public commitment from becoming a confirmation oracle for guessed prompts
    or small training examples.
    """

    if not isinstance(manifest, ComputeWorkloadManifest):
        raise ComputeWorkloadIngressError("Compute workload manifest is required")
    blinding, payload = _sealed_workload_parts(manifest, sealed_plaintext)
    return _sha256(
        WORKLOAD_COMMITMENT_DOMAIN
        + _canonical_json(manifest.to_dict())
        + b"\0"
        + blinding
        + b"\0"
        + payload
    )


def build_compute_workload_plaintext(
    manifest: ComputeWorkloadManifest,
    payload: bytes | bytearray,
    *,
    blinding: bytes,
    padding: bytes | None = None,
) -> bytes:
    """Build the fixed-class plaintext frame that a client encrypts.

    This helper is an SDK/test primitive, never an HTTP plaintext endpoint.
    Production browser code must generate a fresh cryptographically random
    blind and random padding locally after verifying the recipient evidence.
    """

    raw_payload = bytes(payload)
    if not isinstance(blinding, bytes) or len(blinding) != SEALED_BLINDING_BYTES:
        raise ComputeWorkloadIngressError("Compute workload blinding is malformed")
    if blinding == b"\0" * SEALED_BLINDING_BYTES:
        raise ComputeWorkloadIngressError("Compute workload blinding cannot be zero")
    class_bytes = PAYLOAD_CLASS_BYTES[manifest.payload_size_class]
    if not 1 <= len(raw_payload) <= class_bytes - SEALED_FRAME_HEADER_BYTES:
        raise ComputeWorkloadIngressError(
            "Compute workload payload does not fit its padded size class"
        )
    padding_bytes = class_bytes - SEALED_FRAME_HEADER_BYTES - len(raw_payload)
    if padding is None:
        raw_padding = os.urandom(padding_bytes)
    else:
        raw_padding = bytes(padding)
        if len(raw_padding) != padding_bytes:
            raise ComputeWorkloadIngressError(
                "Compute workload padding length is invalid"
            )
    return (
        SEALED_FRAME_MAGIC
        + len(raw_payload).to_bytes(SEALED_LENGTH_BYTES, "big")
        + blinding
        + raw_payload
        + raw_padding
    )


def _sealed_workload_parts(
    manifest: ComputeWorkloadManifest,
    sealed_plaintext: bytes | bytearray,
) -> tuple[bytes, bytes]:
    raw = bytes(sealed_plaintext)
    expected_bytes = PAYLOAD_CLASS_BYTES[manifest.payload_size_class]
    if len(raw) != expected_bytes or raw[: len(SEALED_FRAME_MAGIC)] != SEALED_FRAME_MAGIC:
        raise ComputeWorkloadIngressError(
            "Compute workload padded frame is malformed"
        )
    length_start = len(SEALED_FRAME_MAGIC)
    length_end = length_start + SEALED_LENGTH_BYTES
    payload_bytes = int.from_bytes(raw[length_start:length_end], "big")
    blind_end = length_end + SEALED_BLINDING_BYTES
    if not 1 <= payload_bytes <= expected_bytes - SEALED_FRAME_HEADER_BYTES:
        raise ComputeWorkloadIngressError(
            "Compute workload private payload length is invalid"
        )
    blinding = raw[length_end:blind_end]
    if blinding == b"\0" * SEALED_BLINDING_BYTES:
        raise ComputeWorkloadIngressError("Compute workload blinding cannot be zero")
    return blinding, raw[blind_end : blind_end + payload_bytes]


@dataclass(frozen=True, repr=False)
class ValidatedComputeWorkload:
    """Fixed internal marker; never a digest/count oracle for private input."""

    valid: bool = True

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ComputeWorkloadIngressError("Compute workload validation failed")

    def __repr__(self) -> str:
        return "ValidatedComputeWorkload(valid=True)"

    def to_bounded_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "raw_workload_egress": False,
        }


def validate_compute_workload_plaintext(
    manifest: ComputeWorkloadManifest,
    plaintext: bytes | bytearray,
    *,
    expected_commitment: str,
) -> ValidatedComputeWorkload:
    """Validate decrypted plaintext inside the execution boundary.

    The returned object is only a fixed validation marker: no plaintext digest
    or exact example count may cross the execution boundary. Callers retain
    ownership of the plaintext buffer and must zero it after use.
    """

    sealed = bytes(plaintext)
    if not isinstance(expected_commitment, str) or not _SHA256.fullmatch(
        expected_commitment
    ) or expected_commitment == "sha256:" + "0" * 64:
        raise ComputeWorkloadIngressError("workload commitment is malformed")
    actual_commitment = compute_workload_commitment(manifest, sealed)
    if not hmac.compare_digest(actual_commitment, expected_commitment):
        raise ComputeWorkloadIngressError("workload commitment mismatch")
    _blinding, raw = _sealed_workload_parts(manifest, sealed)
    if manifest.schema == INFERENCE_WORKLOAD_SCHEMA:
        payload = _strict_json(raw, label="inference workload")
        _exact_keys(
            payload,
            frozenset({"schema", "prompt"}),
            label="inference workload",
        )
        prompt = payload["prompt"]
        if payload["schema"] != INFERENCE_PAYLOAD_SCHEMA or not isinstance(
            prompt, str
        ):
            raise ComputeWorkloadIngressError("inference workload is malformed")
        if not 1 <= len(prompt.encode("utf-8")) <= MAX_INFERENCE_PROMPT_BYTES:
            raise ComputeWorkloadIngressError("inference prompt size is invalid")
        if _canonical_json(payload) != raw:
            raise ComputeWorkloadIngressError(
                "inference workload must use canonical JSON"
            )
    else:
        if not raw.endswith(b"\n"):
            raise ComputeWorkloadIngressError("SFT JSONL must end with one newline")
        lines = raw[:-1].split(b"\n")
        minimum_examples, maximum_examples = EXAMPLE_COUNT_CLASSES[
            manifest.example_count_class
        ]
        if (
            not minimum_examples <= len(lines) <= maximum_examples
            or any(not line for line in lines)
        ):
            raise ComputeWorkloadIngressError("SFT example count is invalid")
        for line in lines:
            payload = _strict_json(line, label="SFT example")
            _exact_keys(
                payload,
                frozenset({"completion", "prompt"}),
                label="SFT example",
            )
            for key in ("prompt", "completion"):
                value = payload[key]
                if not isinstance(value, str) or not 1 <= len(
                    value.encode("utf-8")
                ) <= MAX_SFT_FIELD_BYTES:
                    raise ComputeWorkloadIngressError(
                        "SFT example field size is invalid"
                    )
            if _canonical_json(payload) != line:
                raise ComputeWorkloadIngressError(
                    "SFT examples must use canonical JSONL"
                )
    return ValidatedComputeWorkload()


@dataclass(frozen=True, repr=False)
class ComputeWorkloadRecipient:
    keypair: TEEKeyPair = field(repr=False)
    public_key: bytes
    key_id: str
    report_data: bytes
    custody_mode: str
    recipient_attestation: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @classmethod
    def from_keypair(
        cls,
        keypair: TEEKeyPair,
        *,
        custody_mode: str,
        recipient_attestation: Mapping[str, Any] | None = None,
    ) -> "ComputeWorkloadRecipient":
        public_key = keypair.public_key_bytes
        payload = (
            dict(recipient_attestation)
            if recipient_attestation is not None
            else None
        )
        return cls(
            keypair=keypair,
            public_key=public_key,
            key_id=_sha256(public_key),
            report_data=(
                compute_workload_recipient_attestation_report_data(payload)
                if payload is not None
                else compute_workload_attestation_report_data(public_key)
            ),
            custody_mode=custody_mode,
            recipient_attestation=payload,
        )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.keypair, TEEKeyPair)
            or self.public_key != self.keypair.public_key_bytes
            or len(self.public_key) != X25519_PUBLIC_KEY_BYTES
            or self.key_id != _sha256(self.public_key)
            or self.custody_mode not in {"dstack", "local"}
        ):
            raise ComputeWorkloadIngressError("Compute workload recipient is invalid")
        if self.recipient_attestation is None:
            expected_report_data = compute_workload_attestation_report_data(
                self.public_key
            )
        else:
            payload = validate_compute_workload_recipient_attestation(
                self.recipient_attestation,
                expected_public_key=self.public_key,
            )
            object.__setattr__(self, "recipient_attestation", payload)
            expected_report_data = (
                compute_workload_recipient_attestation_report_data(payload)
            )
        if self.report_data != expected_report_data:
            raise ComputeWorkloadIngressError("Compute workload report data is invalid")

    def __repr__(self) -> str:
        return (
            "ComputeWorkloadRecipient("
            f"key_id={self.key_id!r}, custody_mode={self.custody_mode!r})"
        )

    def to_public_dict(self) -> dict[str, Any]:
        result = {
            "encryption_public_key": self.public_key.hex(),
            "key_id": self.key_id,
            "report_context": WORKLOAD_ATTESTATION_CONTEXT,
            "report_data": self.report_data.hex(),
        }
        if self.recipient_attestation is not None:
            result["recipient_attestation"] = dict(self.recipient_attestation)
        return result

    def with_recipient_attestation(
        self,
        payload: Mapping[str, Any],
    ) -> "ComputeWorkloadRecipient":
        return ComputeWorkloadRecipient.from_keypair(
            self.keypair,
            custody_mode=self.custody_mode,
            recipient_attestation=payload,
        )


def compute_workload_attestation_report_payload(
    public_key: bytes,
) -> dict[str, str]:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ComputeWorkloadIngressError("recipient public key is invalid")
    return {
        "context": WORKLOAD_ATTESTATION_CONTEXT,
        "encryption_public_key": public_key.hex(),
        "key_id": _sha256(public_key),
        "protocol": "compute_workload_ingress_v1",
        "service": "dnai-wikigen",
    }


def compute_workload_attestation_report_data(public_key: bytes) -> bytes:
    return hashlib.sha256(
        _canonical_json(compute_workload_attestation_report_payload(public_key))
    ).digest()


def validate_compute_workload_recipient_attestation(
    payload: Mapping[str, Any],
    *,
    expected_public_key: bytes | None = None,
) -> dict[str, Any]:
    """Validate the exact public context bound into a production quote."""

    fields = {
        "schema",
        "context",
        "audience",
        "service",
        "protocol",
        "encryption_public_key",
        "key_id",
        "activation_signer_address",
        "activation_signer_key_path",
        "activation_signer_custody",
        "chain_id",
        "compute_vault_address",
        "compute_vault_runtime_code_hash",
        "fresh_contract_deployment_receipt_sha256",
    }
    if not isinstance(payload, Mapping) or set(payload) != fields:
        raise ComputeWorkloadIngressError(
            "Compute workload recipient attestation is malformed"
        )
    result = dict(payload)
    literals = {
        "schema": "dnai.compute-workload-recipient-attestation.v1",
        "context": WORKLOAD_ATTESTATION_CONTEXT,
        "audience": "dnai-wikigen:compute-workload-recipient",
        "service": "dnai-wikigen",
        "protocol": "compute_workload_ingress_v1",
        "activation_signer_key_path": (
            "tinker/compute_workload_activation_signer"
        ),
        "activation_signer_custody": (
            "dstack_derived_compute_workload_activation_signer"
        ),
    }
    if any(result.get(key) != value for key, value in literals.items()):
        raise ComputeWorkloadIngressError(
            "Compute workload recipient attestation literals are invalid"
        )
    public_key_hex = result.get("encryption_public_key")
    if not isinstance(public_key_hex, str) or not _HEX_64.fullmatch(
        public_key_hex
    ):
        raise ComputeWorkloadIngressError("recipient public key is invalid")
    public_key = bytes.fromhex(public_key_hex)
    if expected_public_key is not None and public_key != expected_public_key:
        raise ComputeWorkloadIngressError("recipient public key does not match")
    if result.get("key_id") != _sha256(public_key):
        raise ComputeWorkloadIngressError("recipient key ID does not match")
    if result.get("chain_id") != 84_532 or isinstance(
        result.get("chain_id"), bool
    ):
        raise ComputeWorkloadIngressError("recipient chain is invalid")
    for key in ("activation_signer_address", "compute_vault_address"):
        value = result.get(key)
        if (
            not isinstance(value, str)
            or not _ADDRESS.fullmatch(value)
            or int(value[2:], 16) == 0
        ):
            raise ComputeWorkloadIngressError("recipient address is invalid")
    for key in (
        "compute_vault_runtime_code_hash",
        "fresh_contract_deployment_receipt_sha256",
    ):
        value = result.get(key)
        if (
            not isinstance(value, str)
            or not _BYTES32.fullmatch(value)
            or int(value[2:], 16) == 0
        ):
            raise ComputeWorkloadIngressError("recipient release hash is invalid")
    return result


def compute_workload_recipient_attestation_report_data(
    payload: Mapping[str, Any],
) -> bytes:
    exact = validate_compute_workload_recipient_attestation(payload)
    return hashlib.sha256(
        WORKLOAD_RECIPIENT_ATTESTATION_DOMAIN + _canonical_json(exact)
    ).digest()


@dataclass(frozen=True, init=False)
class ComputeWorkloadRecipientActivation:
    """Fresh externally authenticated QVL/release authorization.

    This type intentionally has no public initializer.  The only supported
    construction path is ``authenticate_compute_workload_recipient_activation``,
    which authenticates the signed independent-QVL verdict against exact values
    supplied outside that verdict.  A caller-controlled ``verified=True`` flag
    can therefore never activate ciphertext ingress.
    """

    chain_id: int
    domain: str
    profile: str
    cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    measurement_policy_set_sha256: str
    measurement_policy_sha256: str
    main_runtime_evidence_sha256: str
    recipient_key_id: str
    report_data: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    release_policy_hash: str
    quote_hash: str
    verifier_address: str
    verdict_digest: str
    issued_at: int
    recipient_evidence_lease_expires_at: int
    expires_at: int
    authenticated_at: int
    recipient_attestation: Mapping[str, Any] = field(
        repr=False,
        compare=False,
    )
    authenticated_verdict: IndependentAttestationVerdict = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.chain_id, bool)
            or self.chain_id != 84_532
            or self.domain != "main_runtime_cvm"
            or self.profile != WORKLOAD_ATTESTATION_CONTEXT
            or not _CVM_ID.fullmatch(str(self.cvm_id))
            or not _SHA256.fullmatch(str(self.deployment_intent_sha256))
            or not _SHA256.fullmatch(str(self.release_authority_sha256))
            or not _BYTES32.fullmatch(str(self.ceremony_nonce))
            or self.ceremony_nonce == "0x" + "0" * 64
            or not _SHA256.fullmatch(str(self.measurement_policy_set_sha256))
            or not _SHA256.fullmatch(str(self.measurement_policy_sha256))
            or not _SHA256.fullmatch(str(self.main_runtime_evidence_sha256))
            or not _SHA256.fullmatch(str(self.recipient_key_id))
            or not _BYTES32.fullmatch(str(self.report_data))
            or self.report_data == "0x" + "0" * 64
            or not _BYTES32.fullmatch(str(self.compose_hash))
            or self.compose_hash == "0x" + "0" * 64
            or not _HEX_64.fullmatch(str(self.os_image_hash))
            or self.os_image_hash == "0" * 64
            or not _BYTES32.fullmatch(str(self.release_policy_hash))
            or self.release_policy_hash == "0x" + "0" * 64
            or not _BYTES32.fullmatch(str(self.quote_hash))
            or self.quote_hash == "0x" + "0" * 64
            or not _ADDRESS.fullmatch(str(self.verifier_address))
            or int(self.verifier_address[2:], 16) == 0
            or not _BYTES32.fullmatch(str(self.verdict_digest))
            or self.verdict_digest == "0x" + "0" * 64
            or not isinstance(self.app_id, str)
            or not _PHALA_APP_ID.fullmatch(self.app_id)
            or isinstance(self.issued_at, bool)
            or not isinstance(self.issued_at, int)
            or isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, int)
            or isinstance(self.recipient_evidence_lease_expires_at, bool)
            or not isinstance(self.recipient_evidence_lease_expires_at, int)
            or self.recipient_evidence_lease_expires_at != self.expires_at
            or self.expires_at <= self.issued_at
            or self.expires_at - self.issued_at > 300
            or isinstance(self.authenticated_at, bool)
            or not isinstance(self.authenticated_at, int)
            or self.authenticated_at < self.issued_at - 30
            or self.authenticated_at >= self.expires_at
            or not isinstance(
                self.authenticated_verdict,
                IndependentAttestationVerdict,
            )
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient activation is invalid"
            )
        verdict = self.authenticated_verdict
        try:
            recipient_attestation = (
                validate_compute_workload_recipient_attestation(
                    self.recipient_attestation
                )
            )
        except ComputeWorkloadIngressError as exc:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient attestation is invalid"
            ) from exc
        object.__setattr__(self, "recipient_attestation", recipient_attestation)
        if (
            verdict.chain_id != self.chain_id
            or verdict.domain != self.domain
            or verdict.profile != self.profile
            or verdict.cvm_id != self.cvm_id
            or verdict.deployment_intent_sha256
            != self.deployment_intent_sha256
            or verdict.release_authority_sha256
            != self.release_authority_sha256
            or verdict.ceremony_nonce != self.ceremony_nonce
            or verdict.measurement_policy_sha256
            != self.measurement_policy_sha256
            or verdict.verified is not True
            or verdict.report_data.lower() != self.report_data
            or verdict.compose_hash.lower() != self.compose_hash
            or verdict.app_id != self.app_id
            or verdict.os_image_hash.lower() != self.os_image_hash
            or verdict.release_policy_hash.lower() != self.release_policy_hash
            or verdict.quote_hash.lower() != self.quote_hash
            or verdict.verifier_address.lower() != self.verifier_address
            or verdict.issued_at != self.issued_at
            or verdict.activation_evidence_lease_expires_at
            != self.recipient_evidence_lease_expires_at
            or verdict.expires_at != self.expires_at
            or independent_attestation_verdict_digest(verdict)
            != self.verdict_digest
            or recipient_attestation["key_id"] != self.recipient_key_id
            or "0x"
            + compute_workload_recipient_attestation_report_data(
                recipient_attestation
            ).hex()
            != self.report_data
            or recipient_attestation["activation_signer_address"]
            != verdict.signer_address.lower()
            or recipient_attestation["chain_id"] != verdict.chain_id
            or recipient_attestation["compute_vault_address"]
            != verdict.contract_address.lower()
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient activation verdict binding is invalid"
            )

    @property
    def commitment(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))

    @property
    def recipient_release_commitment(self) -> str:
        """Stable exact recipient/release identity across fresh QVL quotes."""

        verdict = self.authenticated_verdict
        return _sha256(
            WORKLOAD_RECIPIENT_RELEASE_DOMAIN
            + _canonical_json(
                {
                    "schema": "dnai.compute.workload-recipient-release.v2",
                    "chain_id": self.chain_id,
                    "domain": self.domain,
                    "profile": self.profile,
                    "cvm_id": self.cvm_id,
                    "deployment_intent_sha256": (
                        self.deployment_intent_sha256
                    ),
                    "release_authority_sha256": (
                        self.release_authority_sha256
                    ),
                    "ceremony_nonce": self.ceremony_nonce,
                    "measurement_policy_set_sha256": (
                        self.measurement_policy_set_sha256
                    ),
                    "measurement_policy_sha256": (
                        self.measurement_policy_sha256
                    ),
                    "main_runtime_evidence_sha256": (
                        self.main_runtime_evidence_sha256
                    ),
                    "recipient_key_id": self.recipient_key_id,
                    "report_data": self.report_data,
                    "compose_hash": self.compose_hash,
                    "app_id": self.app_id,
                    "os_image_hash": self.os_image_hash,
                    "release_policy_hash": self.release_policy_hash,
                    "verifier_address": self.verifier_address,
                    "verification_method": verdict.verification_method,
                    "signer_address": verdict.signer_address.lower(),
                    "contract_address": verdict.contract_address.lower(),
                    "recipient_attestation": dict(self.recipient_attestation),
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": WORKLOAD_RECIPIENT_ACTIVATION_SCHEMA,
            "chain_id": self.chain_id,
            "domain": self.domain,
            "profile": self.profile,
            "cvm_id": self.cvm_id,
            "deployment_intent_sha256": self.deployment_intent_sha256,
            "release_authority_sha256": self.release_authority_sha256,
            "ceremony_nonce": self.ceremony_nonce,
            "measurement_policy_set_sha256": (
                self.measurement_policy_set_sha256
            ),
            "measurement_policy_sha256": self.measurement_policy_sha256,
            "main_runtime_evidence_sha256": (
                self.main_runtime_evidence_sha256
            ),
            "recipient_key_id": self.recipient_key_id,
            "report_data": self.report_data,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "release_policy_hash": self.release_policy_hash,
            "quote_hash": self.quote_hash,
            "verifier_address": self.verifier_address,
            "verdict_digest": self.verdict_digest,
            "issued_at": self.issued_at,
            "recipient_evidence_lease_expires_at": (
                self.recipient_evidence_lease_expires_at
            ),
            "expires_at": self.expires_at,
            "authenticated_at": self.authenticated_at,
            "recipient_attestation": dict(self.recipient_attestation),
            "recipient_release_commitment": self.recipient_release_commitment,
            "authenticated_verdict": self.authenticated_verdict.to_public_dict(),
        }


def authenticate_compute_workload_recipient_activation(
    *,
    recipient: ComputeWorkloadRecipient,
    verdict: IndependentAttestationVerdict,
    expectation: IndependentAttestationExpectation,
    measurement_policy_set_sha256: str,
    main_runtime_evidence_sha256: str,
    now: int,
) -> ComputeWorkloadRecipientActivation:
    """Return an activation only after exact independent-QVL authentication.

    ``expectation`` is operator/release policy input and must not be populated
    from the verdict being checked.  In particular, it pins the trusted QVL
    signer, release policy, CVM measurements, execution signer, chain, and
    contract independently of the response.
    """

    if (
        not isinstance(recipient, ComputeWorkloadRecipient)
        or not isinstance(verdict, IndependentAttestationVerdict)
        or not isinstance(expectation, IndependentAttestationExpectation)
        or isinstance(now, bool)
        or not isinstance(now, int)
        or expectation.profile != WORKLOAD_ATTESTATION_CONTEXT
        or expectation.chain_id != 84_532
        or expectation.domain != "main_runtime_cvm"
        or not _CVM_ID.fullmatch(str(expectation.cvm_id))
        or not _SHA256.fullmatch(str(measurement_policy_set_sha256))
        or not _SHA256.fullmatch(str(main_runtime_evidence_sha256))
        or expectation.report_data.lower()
        != "0x" + recipient.report_data.hex()
        or recipient.recipient_attestation is None
    ):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload recipient activation expectation is invalid"
        )
    try:
        authenticated = authenticate_independent_attestation_verdict(
            verdict,
            expectation=expectation,
            now=now,
        )
    except (ResultVerifierError, ValueError, TypeError, AttributeError) as exc:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload recipient activation QVL verdict is invalid"
        ) from exc

    activation = object.__new__(ComputeWorkloadRecipientActivation)
    values: dict[str, Any] = {
        "chain_id": expectation.chain_id,
        "domain": expectation.domain,
        "profile": expectation.profile,
        "cvm_id": expectation.cvm_id,
        "deployment_intent_sha256": expectation.deployment_intent_sha256,
        "release_authority_sha256": expectation.release_authority_sha256,
        "ceremony_nonce": expectation.ceremony_nonce,
        "measurement_policy_set_sha256": measurement_policy_set_sha256,
        "measurement_policy_sha256": expectation.measurement_policy_sha256,
        "main_runtime_evidence_sha256": main_runtime_evidence_sha256,
        "recipient_key_id": recipient.key_id,
        "report_data": verdict.report_data.lower(),
        "compose_hash": verdict.compose_hash.lower(),
        "app_id": verdict.app_id,
        "os_image_hash": verdict.os_image_hash.lower(),
        "release_policy_hash": verdict.release_policy_hash.lower(),
        "quote_hash": verdict.quote_hash.lower(),
        "verifier_address": authenticated.verifier_address.lower(),
        "verdict_digest": authenticated.verdict_digest.lower(),
        "issued_at": verdict.issued_at,
        "recipient_evidence_lease_expires_at": (
            verdict.activation_evidence_lease_expires_at
        ),
        "expires_at": verdict.expires_at,
        "authenticated_at": authenticated.verified_at,
        "recipient_attestation": dict(recipient.recipient_attestation),
        "authenticated_verdict": verdict,
    }
    for key, value in values.items():
        object.__setattr__(activation, key, value)
    activation.__post_init__()
    return activation


class ComputeWorkloadActivationProvider(Protocol):
    def verified_activation(
        self,
        recipient: ComputeWorkloadRecipient,
        *,
        now: int,
    ) -> ComputeWorkloadRecipientActivation: ...


class UnavailableComputeWorkloadActivationProvider:
    """Production default until an authenticated QVL feed is integrated."""

    def verified_activation(
        self,
        recipient: ComputeWorkloadRecipient,
        *,
        now: int,
    ) -> ComputeWorkloadRecipientActivation:
        del recipient, now
        raise ComputeWorkloadIngressUnavailable(
            "verified Compute workload recipient activation is unavailable"
        )


@dataclass(frozen=True)
class ComputeWorkloadPrincipal:
    kind: str
    project_id: str
    actor_id: str

    def __post_init__(self) -> None:
        if self.kind not in {"wallet", "credential"}:
            raise ComputeWorkloadIngressError("Compute workload principal is invalid")
        if not _RESOURCE_ID.fullmatch(self.project_id):
            raise ComputeWorkloadIngressError("Compute workload project is invalid")
        if self.kind == "wallet":
            normalized = self.actor_id.lower()
            if not _ADDRESS.fullmatch(normalized):
                raise ComputeWorkloadIngressError("Compute workload wallet is invalid")
            object.__setattr__(self, "actor_id", normalized)
        elif not _RESOURCE_ID.fullmatch(self.actor_id):
            raise ComputeWorkloadIngressError("Compute workload credential is invalid")

    @property
    def actor_commitment(self) -> str:
        return _sha256(
            b"dnai-wikigen/compute-workload-principal/v1\0"
            + _canonical_json(
                {
                    "kind": self.kind,
                    "project_id": self.project_id,
                    "actor_id": self.actor_id,
                }
            )
        )

    @property
    def project_commitment(self) -> str:
        return compute_workload_project_commitment(self.project_id)


def compute_workload_project_commitment(project_id: str) -> str:
    if not isinstance(project_id, str) or not _RESOURCE_ID.fullmatch(project_id):
        raise ComputeWorkloadIngressError("Compute workload project is invalid")
    return _sha256(
        b"dnai-wikigen/compute-workload-project/v1\0"
        + project_id.encode("ascii")
    )


def compute_workload_idempotency_hash(
    principal: ComputeWorkloadPrincipal,
    idempotency_key: str,
) -> str:
    key = _string(
        idempotency_key,
        label="Compute workload Idempotency-Key",
        minimum=8,
        maximum=128,
    )
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise ComputeWorkloadIngressError(
            "Compute workload Idempotency-Key is malformed"
        )
    return _sha256(
        b"dnai-wikigen/compute-workload-idempotency/v1\0"
        + _canonical_json(
            {
                "project_id": principal.project_id,
                "actor_commitment": principal.actor_commitment,
                "idempotency_key": key,
            }
        )
    )


@dataclass(frozen=True)
class ComputeWorkloadBinding:
    project_commitment: str
    actor_kind: str
    actor_commitment: str
    manifest: ComputeWorkloadManifest
    manifest_commitment: str
    workload_commitment: str
    idempotency_hash: str
    recipient_key_id: str
    report_data_sha256: str
    activation_commitment: str
    recipient_release_commitment: str

    _FIELDS = frozenset(
        {
            "service",
            "context",
            "schema_version",
            "project_commitment",
            "actor_kind",
            "actor_commitment",
            "manifest",
            "manifest_commitment",
            "workload_commitment",
            "idempotency_hash",
            "recipient_key_id",
            "report_data_sha256",
            "activation_commitment",
            "recipient_release_commitment",
        }
    )

    def __post_init__(self) -> None:
        for label, value in (
            ("project_commitment", self.project_commitment),
            ("actor_commitment", self.actor_commitment),
            ("manifest_commitment", self.manifest_commitment),
            ("workload_commitment", self.workload_commitment),
            ("idempotency_hash", self.idempotency_hash),
            ("recipient_key_id", self.recipient_key_id),
            ("report_data_sha256", self.report_data_sha256),
            ("activation_commitment", self.activation_commitment),
            (
                "recipient_release_commitment",
                self.recipient_release_commitment,
            ),
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ComputeWorkloadIngressError(f"{label} is malformed")
        if self.workload_commitment == "sha256:" + "0" * 64:
            raise ComputeWorkloadIngressError("workload commitment cannot be zero")
        if self.actor_kind not in {"wallet", "credential"}:
            raise ComputeWorkloadIngressError("actor kind is invalid")
        if not isinstance(self.manifest, ComputeWorkloadManifest):
            raise ComputeWorkloadIngressError("workload manifest is invalid")
        if self.manifest_commitment != self.manifest.commitment:
            raise ComputeWorkloadIngressError("workload manifest commitment mismatch")

    def to_aad_dict(self) -> dict[str, Any]:
        return {
            "service": "dnai-wikigen",
            "context": WORKLOAD_INGRESS_CONTEXT,
            "schema_version": WORKLOAD_INGRESS_SCHEMA_VERSION,
            "project_commitment": self.project_commitment,
            "actor_kind": self.actor_kind,
            "actor_commitment": self.actor_commitment,
            "manifest": self.manifest.to_dict(),
            "manifest_commitment": self.manifest_commitment,
            "workload_commitment": self.workload_commitment,
            "idempotency_hash": self.idempotency_hash,
            "recipient_key_id": self.recipient_key_id,
            "report_data_sha256": self.report_data_sha256,
            "activation_commitment": self.activation_commitment,
            "recipient_release_commitment": self.recipient_release_commitment,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ComputeWorkloadBinding":
        _exact_keys(value, cls._FIELDS, label="Compute workload binding")
        if (
            value["service"] != "dnai-wikigen"
            or value["context"] != WORKLOAD_INGRESS_CONTEXT
            or value["schema_version"] != WORKLOAD_INGRESS_SCHEMA_VERSION
        ):
            raise ComputeWorkloadIngressError("Compute workload binding version is invalid")
        manifest_value = value["manifest"]
        if not isinstance(manifest_value, Mapping):
            raise ComputeWorkloadIngressError("Compute workload manifest is invalid")
        return cls(
            project_commitment=_string(
                value["project_commitment"], label="project_commitment", maximum=71
            ),
            actor_kind=_string(value["actor_kind"], label="actor_kind", maximum=16),
            actor_commitment=_string(
                value["actor_commitment"], label="actor_commitment", maximum=71
            ),
            manifest=ComputeWorkloadManifest.from_mapping(manifest_value),
            manifest_commitment=_string(
                value["manifest_commitment"],
                label="manifest_commitment",
                maximum=71,
            ),
            workload_commitment=_string(
                value["workload_commitment"],
                label="workload_commitment",
                maximum=71,
            ),
            idempotency_hash=_string(
                value["idempotency_hash"], label="idempotency_hash", maximum=71
            ),
            recipient_key_id=_string(
                value["recipient_key_id"], label="recipient_key_id", maximum=71
            ),
            report_data_sha256=_string(
                value["report_data_sha256"],
                label="report_data_sha256",
                maximum=71,
            ),
            activation_commitment=_string(
                value["activation_commitment"],
                label="activation_commitment",
                maximum=71,
            ),
            recipient_release_commitment=_string(
                value["recipient_release_commitment"],
                label="recipient_release_commitment",
                maximum=71,
            ),
        )


def compute_workload_aad(binding: ComputeWorkloadBinding) -> bytes:
    if not isinstance(binding, ComputeWorkloadBinding):
        raise ComputeWorkloadIngressError("Compute workload binding is required")
    encoded = _canonical_json(binding.to_aad_dict())
    if len(encoded) > MAX_AAD_BYTES:
        raise ComputeWorkloadIngressError("Compute workload AAD is oversized")
    return encoded


def compute_workload_execution_binding_payload(
    workload_id: str,
    binding: ComputeWorkloadBinding,
    envelope: "ComputeWorkloadEnvelope",
) -> dict[str, str]:
    """Project one immutable ciphertext/source binding for wallet adoption.

    The actor remains the principal that authenticated the original encrypted
    upload.  A later wallet-funded dispatch claims this exact commitment; it
    never rewrites the AES-GCM AAD or promotes a device credential into a
    spending principal.
    """

    if not isinstance(workload_id, str) or not _WORKLOAD_ID.fullmatch(workload_id):
        raise ComputeWorkloadIngressError("Compute workload ID is malformed")
    if not isinstance(binding, ComputeWorkloadBinding) or not isinstance(
        envelope, ComputeWorkloadEnvelope
    ):
        raise ComputeWorkloadIngressError(
            "Compute workload execution binding inputs are invalid"
        )
    _verify_binding_envelope(binding, envelope)
    return {
        "schema": "dnai.compute.workload-execution-binding.v1",
        "workload_id": workload_id,
        "project_commitment": binding.project_commitment,
        "actor_kind": binding.actor_kind,
        "actor_commitment": binding.actor_commitment,
        "aad_sha256": envelope.aad_sha256,
        "manifest_commitment": binding.manifest_commitment,
        "workload_commitment": binding.workload_commitment,
        "recipient_key_id": binding.recipient_key_id,
        "recipient_release_commitment": binding.recipient_release_commitment,
    }


def compute_workload_execution_binding_commitment(
    workload_id: str,
    binding: ComputeWorkloadBinding,
    envelope: "ComputeWorkloadEnvelope",
) -> str:
    return _sha256(
        WORKLOAD_EXECUTION_BINDING_DOMAIN
        + _canonical_json(
            compute_workload_execution_binding_payload(
                workload_id,
                binding,
                envelope,
            )
        )
    )


@dataclass(frozen=True)
class ComputeWorkloadDispatchClaim:
    job_id: str
    intent_commitment: str
    funding_wallet: str
    execution_binding_commitment: str

    _FIELDS = frozenset(
        {
            "schema",
            "job_id",
            "intent_commitment",
            "funding_wallet",
            "execution_binding_commitment",
        }
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.job_id, str)
            or not _BYTES32.fullmatch(self.job_id)
            or self.job_id == "0x" + "0" * 64
            or not isinstance(self.intent_commitment, str)
            or not _BYTES32.fullmatch(self.intent_commitment)
            or self.intent_commitment == "0x" + "0" * 64
            or not isinstance(self.funding_wallet, str)
            or not _ADDRESS.fullmatch(self.funding_wallet.lower())
            or int(self.funding_wallet[2:], 16) == 0
            or not isinstance(self.execution_binding_commitment, str)
            or not _SHA256.fullmatch(self.execution_binding_commitment)
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload dispatch claim is malformed"
            )
        object.__setattr__(self, "job_id", self.job_id.lower())
        object.__setattr__(
            self,
            "intent_commitment",
            self.intent_commitment.lower(),
        )
        object.__setattr__(self, "funding_wallet", self.funding_wallet.lower())

    @property
    def commitment(self) -> str:
        return _sha256(
            WORKLOAD_DISPATCH_CLAIM_DOMAIN + _canonical_json(self.to_dict())
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": "dnai.compute.workload-dispatch-claim.v1",
            "job_id": self.job_id,
            "intent_commitment": self.intent_commitment,
            "funding_wallet": self.funding_wallet,
            "execution_binding_commitment": (
                self.execution_binding_commitment
            ),
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ComputeWorkloadDispatchClaim":
        _exact_keys(value, cls._FIELDS, label="Compute workload dispatch claim")
        if value.get("schema") != "dnai.compute.workload-dispatch-claim.v1":
            raise ComputeWorkloadIngressError(
                "Compute workload dispatch claim schema is invalid"
            )
        return cls(
            job_id=_string(value["job_id"], label="claim job ID", maximum=66),
            intent_commitment=_string(
                value["intent_commitment"],
                label="claim intent commitment",
                maximum=66,
            ),
            funding_wallet=_string(
                value["funding_wallet"],
                label="claim funding wallet",
                maximum=42,
            ),
            execution_binding_commitment=_string(
                value["execution_binding_commitment"],
                label="claim execution binding",
                maximum=71,
            ),
        )


@dataclass(frozen=True, repr=False)
class ComputeWorkloadEnvelope:
    schema_version: int
    algorithm: str
    encoding: str
    key_id: str
    attestation_report_data: str
    activation_commitment: str
    aad: str
    ephemeral_public_key: str
    nonce: str
    ciphertext: str
    ciphertext_bytes: int = field(init=False)
    ciphertext_sha256: str = field(init=False)
    aad_sha256: str = field(init=False)
    nonce_fingerprint: str = field(init=False)

    _FIELDS = frozenset(
        {
            "schema_version",
            "algorithm",
            "encoding",
            "key_id",
            "attestation_report_data",
            "activation_commitment",
            "aad",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        }
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version != WORKLOAD_INGRESS_SCHEMA_VERSION
            or self.algorithm != WORKLOAD_INGRESS_ALGORITHM
            or self.encoding != WORKLOAD_INGRESS_ENCODING
        ):
            raise ComputeWorkloadIngressError("Compute workload envelope version is unsupported")
        if not _SHA256.fullmatch(str(self.key_id)) or not _SHA256.fullmatch(
            str(self.activation_commitment)
        ):
            raise ComputeWorkloadIngressError("Compute workload envelope binding is malformed")
        if not _HEX_64.fullmatch(str(self.attestation_report_data)):
            raise ComputeWorkloadIngressError("Compute workload report data is malformed")
        aad = _b64decode(self.aad, label="aad", maximum_bytes=MAX_AAD_BYTES)
        ephemeral = _b64decode(
            self.ephemeral_public_key,
            label="ephemeral_public_key",
            maximum_bytes=X25519_PUBLIC_KEY_BYTES,
            exact_bytes=X25519_PUBLIC_KEY_BYTES,
        )
        if ephemeral == b"\0" * 32:
            raise ComputeWorkloadIngressError("ephemeral public key is invalid")
        try:
            X25519PublicKey.from_public_bytes(ephemeral)
        except ValueError as exc:
            raise ComputeWorkloadIngressError("ephemeral public key is invalid") from exc
        nonce = _b64decode(
            self.nonce,
            label="nonce",
            maximum_bytes=AES_GCM_NONCE_BYTES,
            exact_bytes=AES_GCM_NONCE_BYTES,
        )
        ciphertext = _b64decode(
            self.ciphertext,
            label="ciphertext",
            maximum_bytes=MAX_CIPHERTEXT_BYTES,
        )
        if len(ciphertext) <= GCM_TAG_BYTES:
            raise ComputeWorkloadIngressError("Compute workload ciphertext is too short")
        object.__setattr__(self, "ciphertext_bytes", len(ciphertext))
        object.__setattr__(self, "ciphertext_sha256", _sha256(ciphertext))
        object.__setattr__(self, "aad_sha256", _sha256(aad))
        object.__setattr__(
            self,
            "nonce_fingerprint",
            _sha256(
                b"dnai-wikigen/compute-workload-nonce/v1\0"
                + bytes.fromhex(self.key_id[7:])
                + ephemeral
                + nonce
            ),
        )

    def __repr__(self) -> str:
        return (
            "ComputeWorkloadEnvelope("
            f"key_id={self.key_id!r}, ciphertext_bytes={self.ciphertext_bytes})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "encoding": self.encoding,
            "key_id": self.key_id,
            "attestation_report_data": self.attestation_report_data,
            "activation_commitment": self.activation_commitment,
            "aad": self.aad,
            "ephemeral_public_key": self.ephemeral_public_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ComputeWorkloadEnvelope":
        _exact_keys(value, cls._FIELDS, label="Compute workload envelope")
        return cls(
            schema_version=_integer(
                value["schema_version"],
                label="schema_version",
                minimum=1,
                maximum=1,
            ),
            algorithm=_string(value["algorithm"], label="algorithm", maximum=64),
            encoding=_string(value["encoding"], label="encoding", maximum=32),
            key_id=_string(value["key_id"], label="key_id", maximum=71),
            attestation_report_data=_string(
                value["attestation_report_data"],
                label="attestation_report_data",
                maximum=64,
            ),
            activation_commitment=_string(
                value["activation_commitment"],
                label="activation_commitment",
                maximum=71,
            ),
            aad=_string(value["aad"], label="aad", maximum=_b64_size(MAX_AAD_BYTES)),
            ephemeral_public_key=_string(
                value["ephemeral_public_key"],
                label="ephemeral_public_key",
                maximum=_b64_size(32),
            ),
            nonce=_string(value["nonce"], label="nonce", maximum=_b64_size(12)),
            ciphertext=_string(
                value["ciphertext"],
                label="ciphertext",
                maximum=_b64_size(MAX_CIPHERTEXT_BYTES),
            ),
        )


@dataclass(frozen=True)
class ComputeWorkloadIngressResult:
    workload_id: str
    manifest: ComputeWorkloadManifest
    workload_commitment: str
    manifest_commitment: str
    ciphertext_sha256: str
    blob_sha256: str
    key_id: str
    activation_commitment: str
    recipient_release_commitment: str
    source_kind: str
    execution_binding_commitment: str
    created: bool
    _idempotency_hash: str = field(repr=False)
    _request_hash: str = field(repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "compute_workload_ingress_receipt",
            "schema_version": WORKLOAD_PUBLIC_SCHEMA_VERSION,
            "workload_id": self.workload_id,
            "workload_schema": self.manifest.schema,
            "workload_commitment": self.workload_commitment,
            "manifest_commitment": self.manifest_commitment,
            "ciphertext_sha256": self.ciphertext_sha256,
            "blob_sha256": self.blob_sha256,
            "key_id": self.key_id,
            "activation_commitment": self.activation_commitment,
            "recipient_release_commitment": self.recipient_release_commitment,
            "execution_binding": {
                "schema": "dnai.compute.workload-execution-binding.v1",
                "commitment": self.execution_binding_commitment,
                "source_kind": self.source_kind,
                "wallet_adoption_required": self.source_kind == "credential",
                "device_spending_authority": False,
            },
            "dispatch_adoption": {
                "state": (
                    "wallet_adoption_required"
                    if self.source_kind == "credential"
                    else "available_for_wallet_dispatch"
                ),
                "wallet_adoption_eligible": True,
                "dispatch_claimed": False,
                "claim_commitment": None,
                "funding_authority": "wallet_required",
                "device_spending_authority": False,
                "direct_deletion_allowed": True,
            },
            "created": self.created,
            "idempotent_replay": not self.created,
            "ciphertext_egress": False,
            "raw_prompt_egress": False,
            "raw_examples_egress": False,
            "raw_dataset_egress": False,
            "raw_output_egress": False,
            "provider_dispatch_enabled": False,
        }


@dataclass(frozen=True, repr=False)
class StoredComputeWorkload:
    workload_id: str
    binding: ComputeWorkloadBinding
    envelope: ComputeWorkloadEnvelope = field(repr=False)
    lifecycle: str = "sealed"
    dispatch_claim: ComputeWorkloadDispatchClaim | None = None

    @property
    def execution_binding_commitment(self) -> str:
        return compute_workload_execution_binding_commitment(
            self.workload_id,
            self.binding,
            self.envelope,
        )


@dataclass(frozen=True, repr=False)
class ComputeWorkloadExecutionLease:
    """In-boundary replay-safe plaintext view; deliberately not serializable.

    The ciphertext remains durably sealed while this lease is open so an
    ambiguous provider response can be held for separately attested
    reconciliation. It never authorizes an automatic provider replay, even
    with the same dispatch key. ``reauthenticate`` must be called immediately
    before the one at-most-once provider attempt; it re-reads the authenticated
    envelope and obtains a fresh recipient-QVL activation without exposing
    either the plaintext or the quote.
    """

    workload_id: str
    manifest: ComputeWorkloadManifest
    plaintext: bytearray = field(repr=False)
    validated: ValidatedComputeWorkload = field(repr=False)
    _reauthenticate: Callable[[], ValidatedComputeWorkload] = field(
        repr=False,
        compare=False,
    )

    def reauthenticate(self) -> ValidatedComputeWorkload:
        return self._reauthenticate()

    def __repr__(self) -> str:
        return (
            "ComputeWorkloadExecutionLease("
            f"workload_id={self.workload_id!r}, plaintext=<zeroized-on-exit>)"
        )


def _zero_bytearray(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


@dataclass(frozen=True)
class _IndexRecord:
    idempotency_hash: str
    request_hash: str
    workload_id: str
    object_id: str
    blob_sha256: str
    ciphertext_sha256: str
    aad_sha256: str
    nonce_fingerprint: str
    ciphertext_bytes: int
    key_id: str
    project_commitment: str
    actor_commitment: str
    manifest_commitment: str
    workload_commitment: str
    workload_schema: str
    activation_commitment: str
    recipient_release_commitment: str
    lifecycle: str
    dispatch_claim: ComputeWorkloadDispatchClaim | None
    dispatch_claim_commitment: str
    release_checkpoint_commitment: str

    _FIELDS = frozenset(
        {
            "idempotency_hash",
            "request_hash",
            "workload_id",
            "object_id",
            "blob_sha256",
            "ciphertext_sha256",
            "aad_sha256",
            "nonce_fingerprint",
            "ciphertext_bytes",
            "key_id",
            "project_commitment",
            "actor_commitment",
            "manifest_commitment",
            "workload_commitment",
            "workload_schema",
            "activation_commitment",
            "recipient_release_commitment",
            "lifecycle",
            "dispatch_claim",
            "dispatch_claim_commitment",
            "release_checkpoint_commitment",
        }
    )

    def __post_init__(self) -> None:
        for value in (
            self.idempotency_hash,
            self.request_hash,
            self.blob_sha256,
            self.ciphertext_sha256,
            self.aad_sha256,
            self.nonce_fingerprint,
            self.key_id,
            self.project_commitment,
            self.actor_commitment,
            self.manifest_commitment,
            self.workload_commitment,
            self.activation_commitment,
            self.recipient_release_commitment,
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ComputeWorkloadIngressCorrupt("Compute workload index hash is invalid")
        if not _WORKLOAD_ID.fullmatch(self.workload_id) or not _OBJECT_ID.fullmatch(
            self.object_id
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload index ID is invalid")
        if self.workload_schema not in {
            INFERENCE_WORKLOAD_SCHEMA,
            SFT_JSONL_WORKLOAD_SCHEMA,
        }:
            raise ComputeWorkloadIngressCorrupt("Compute workload index schema is invalid")
        if self.lifecycle not in {
            "sealed",
            "dispatch_claimed",
            "deleting",
            "deleting_after_checkpoint",
            "released",
        }:
            raise ComputeWorkloadIngressCorrupt(
                "Compute workload lifecycle is invalid"
            )
        if self.lifecycle in {"sealed", "deleting"}:
            if (
                self.dispatch_claim is not None
                or self.dispatch_claim_commitment != ""
                or self.release_checkpoint_commitment != ""
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "unclaimed Compute workload contains dispatch state"
                )
        else:
            if (
                not isinstance(self.dispatch_claim, ComputeWorkloadDispatchClaim)
                or not isinstance(self.dispatch_claim_commitment, str)
                or not _SHA256.fullmatch(self.dispatch_claim_commitment)
                or not hmac.compare_digest(
                    self.dispatch_claim_commitment,
                    self.dispatch_claim.commitment,
                )
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "claimed Compute workload dispatch binding is invalid"
                )
        if self.lifecycle == "dispatch_claimed":
            if self.release_checkpoint_commitment != "":
                raise ComputeWorkloadIngressCorrupt(
                    "claimed Compute workload contains a release checkpoint"
                )
        elif self.lifecycle in {"deleting_after_checkpoint", "released"} and (
            not isinstance(self.release_checkpoint_commitment, str)
            or not _SHA256.fullmatch(self.release_checkpoint_commitment)
        ):
            raise ComputeWorkloadIngressCorrupt(
                "released Compute workload checkpoint is invalid"
            )
        _integer(
            self.ciphertext_bytes,
            label="ciphertext_bytes",
            minimum=GCM_TAG_BYTES + 1,
            maximum=MAX_CIPHERTEXT_BYTES,
        )

    def to_dict(self) -> dict[str, Any]:
        result = {key: getattr(self, key) for key in sorted(self._FIELDS)}
        result["dispatch_claim"] = (
            self.dispatch_claim.to_dict()
            if self.dispatch_claim is not None
            else None
        )
        return result

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "_IndexRecord":
        _exact_keys(value, cls._FIELDS, label="Compute workload index record")
        fields = dict(value)
        dispatch_claim = fields.get("dispatch_claim")
        if dispatch_claim is not None:
            if not isinstance(dispatch_claim, Mapping):
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload dispatch claim is invalid"
                )
            try:
                fields["dispatch_claim"] = (
                    ComputeWorkloadDispatchClaim.from_mapping(dispatch_claim)
                )
            except ComputeWorkloadIngressError as exc:
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload dispatch claim is invalid"
                ) from exc
        return cls(**fields)


def _secure_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload directory cannot be a symlink"
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink < 2
    ):
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload storage directory metadata is unsafe"
        )
    os.chmod(path, 0o700)


def _open_secure_directory(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload storage directory is unavailable"
        ) from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink < 2
    ):
        os.close(descriptor)
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload storage directory metadata is unsafe"
        )
    return descriptor


def _fsync_directory_fd(descriptor: int) -> None:
    os.fsync(descriptor)


def _read_fd_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ComputeWorkloadIngressCorrupt("Compute workload file is oversized")
    return b"".join(chunks)


def _safe_read(
    path: Path | str,
    *,
    maximum: int,
    label: str,
    dir_fd: int | None = None,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise ComputeWorkloadIngressCorrupt(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size < 2
            or metadata.st_size > maximum
        ):
            raise ComputeWorkloadIngressCorrupt(f"{label} file metadata is unsafe")
        return _read_fd_all(descriptor, maximum)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OSError("short workload write")
        offset += written


class ComputeWorkloadIngressStore:
    """HMAC-authenticated, cross-process-safe ciphertext-only store."""

    def __init__(
        self,
        root_dir: str | Path,
        *,
        integrity_key: bytes,
        max_envelopes: int = MAX_ENVELOPES,
    ) -> None:
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload integrity key is unavailable"
            )
        self.max_envelopes = _integer(
            max_envelopes,
            label="max_envelopes",
            minimum=1,
            maximum=MAX_ENVELOPES,
        )
        self.root_dir = Path(root_dir)
        self.blob_dir = self.root_dir / "envelopes"
        self.index_path = self.root_dir / "index.json"
        self.lock_path = self.root_dir / "index.lock"
        self.execution_lock_path = self.root_dir / "execution.lock"
        self._integrity_key = bytes(integrity_key)
        self._thread_lock = threading.RLock()
        self._execution_thread_lock = threading.RLock()
        _secure_directory(self.root_dir)
        self._root_fd = _open_secure_directory(self.root_dir)
        self._blob_fd = -1
        self._lock_fd = -1
        self._execution_lock_fd = -1
        try:
            try:
                os.mkdir("envelopes", mode=0o700, dir_fd=self._root_fd)
                _fsync_directory_fd(self._root_fd)
            except FileExistsError:
                pass
            _secure_directory(self.blob_dir)
            self._blob_fd = _open_secure_directory(self.blob_dir)
            self._lock_fd = self._open_lock_file("index.lock")
            self._execution_lock_fd = self._open_lock_file("execution.lock")
        except Exception:
            self.close()
            raise
        with self._exclusive_lock():
            if self._index_exists():
                records = self._load_index()
            else:
                records: dict[str, _IndexRecord] = {}
                self._persist_index(records)
            records = self._recover_deletions(records)
            self._verify_records(records)

    def close(self) -> None:
        for name in (
            "_execution_lock_fd",
            "_lock_fd",
            "_blob_fd",
            "_root_fd",
        ):
            descriptor = getattr(self, name, -1)
            if isinstance(descriptor, int) and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, -1)

    def __del__(self) -> None:
        self.close()

    def _index_exists(self) -> bool:
        try:
            os.stat("index.json", dir_fd=self._root_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def put(
        self,
        *,
        binding: ComputeWorkloadBinding,
        envelope: ComputeWorkloadEnvelope,
    ) -> ComputeWorkloadIngressResult:
        _verify_binding_envelope(binding, envelope)
        payload = {
            "surface": "compute_workload_ciphertext_envelope",
            "schema_version": WORKLOAD_INGRESS_SCHEMA_VERSION,
            "binding": binding.to_aad_dict(),
            "envelope": envelope.to_dict(),
            "plaintext_persisted": False,
            "raw_prompt_persisted": False,
            "raw_examples_persisted": False,
            "raw_output_persisted": False,
        }
        encoded = _canonical_json(payload) + b"\n"
        if len(encoded) > MAX_BLOB_FILE_BYTES:
            raise ComputeWorkloadIngressError("Compute workload envelope is oversized")
        request_hash = _sha256(
            _canonical_json(
                {
                    "surface": "compute_workload_ingress_request",
                    "binding": binding.to_aad_dict(),
                    "envelope": envelope.to_dict(),
                }
            )
        )
        object_id = "workload-" + request_hash[7:]
        workload_id = "wrk_" + hashlib.sha256(
            b"dnai-wikigen/compute-workload-id/v1\0"
            + bytes.fromhex(request_hash[7:])
        ).hexdigest()[:32]
        record = _IndexRecord(
            idempotency_hash=binding.idempotency_hash,
            request_hash=request_hash,
            workload_id=workload_id,
            object_id=object_id,
            blob_sha256=_sha256(WORKLOAD_BLOB_HASH_DOMAIN + encoded),
            ciphertext_sha256=envelope.ciphertext_sha256,
            aad_sha256=envelope.aad_sha256,
            nonce_fingerprint=envelope.nonce_fingerprint,
            ciphertext_bytes=envelope.ciphertext_bytes,
            key_id=envelope.key_id,
            project_commitment=binding.project_commitment,
            actor_commitment=binding.actor_commitment,
            manifest_commitment=binding.manifest_commitment,
            workload_commitment=binding.workload_commitment,
            workload_schema=binding.manifest.schema,
            activation_commitment=binding.activation_commitment,
            recipient_release_commitment=binding.recipient_release_commitment,
            lifecycle="sealed",
            dispatch_claim=None,
            dispatch_claim_commitment="",
            release_checkpoint_commitment="",
        )
        with self._exclusive_lock():
            records = self._recover_deletions(self._load_index())
            existing = records.get(binding.idempotency_hash)
            if existing is not None:
                if not hmac.compare_digest(existing.request_hash, request_hash):
                    raise ComputeWorkloadIngressConflict(
                        "Compute workload Idempotency-Key was reused for a different envelope"
                    )
                if existing.lifecycle not in {"sealed", "dispatch_claimed"}:
                    raise ComputeWorkloadIngressConflict(
                        "Compute workload Idempotency-Key names an already released envelope"
                    )
                self._load_blob(existing)
                return self._result(
                    existing,
                    binding,
                    envelope,
                    created=False,
                )
            if any(
                hmac.compare_digest(item.nonce_fingerprint, envelope.nonce_fingerprint)
                for item in records.values()
            ):
                raise ComputeWorkloadIngressConflict(
                    "Compute workload ephemeral-key and nonce tuple was reused"
                )
            if len(records) >= self.max_envelopes:
                raise ComputeWorkloadIngressError("Compute workload store is full")
            target_name = f"{object_id}.json"
            self._write_new_blob(target_name, encoded)
            candidate = dict(records)
            candidate[record.idempotency_hash] = record
            try:
                self._persist_index(candidate)
            except Exception:
                try:
                    os.unlink(target_name, dir_fd=self._blob_fd)
                    _fsync_directory_fd(self._blob_fd)
                except OSError:
                    pass
                raise
            return self._result(
                record,
                binding,
                envelope,
                created=True,
            )

    def get_for_project(
        self,
        workload_id: str,
        *,
        project_commitment: str,
    ) -> StoredComputeWorkload:
        if not isinstance(workload_id, str) or not _WORKLOAD_ID.fullmatch(workload_id):
            raise ComputeWorkloadIngressError("Compute workload ID is malformed")
        if not isinstance(project_commitment, str) or not _SHA256.fullmatch(
            project_commitment
        ):
            raise ComputeWorkloadIngressError("Compute workload project binding is malformed")
        with self._exclusive_lock():
            records = self._recover_deletions(self._load_index())
            matches = [
                item
                for item in records.values()
                if item.workload_id == workload_id
                and item.lifecycle in {"sealed", "dispatch_claimed"}
            ]
            if len(matches) != 1 or not hmac.compare_digest(
                matches[0].project_commitment, project_commitment
            ):
                raise ComputeWorkloadIngressError("Compute workload was not found")
            binding, envelope = self._load_blob(matches[0])
            return StoredComputeWorkload(
                workload_id=workload_id,
                binding=binding,
                envelope=envelope,
                lifecycle=matches[0].lifecycle,
                dispatch_claim=matches[0].dispatch_claim,
            )

    def claim_for_dispatch(
        self,
        workload_id: str,
        *,
        project_commitment: str,
        job_id: str,
        intent_commitment: str,
        funding_wallet: str,
        execution_binding_commitment: str,
    ) -> tuple[ComputeWorkloadDispatchClaim, bool]:
        """Bind one sealed ciphertext to exactly one wallet-funded job.

        The claim is stored beside the authenticated ciphertext index.  It is
        deliberately distinct from the source principal in the AES-GCM AAD:
        the credential remains the uploader while the wallet becomes only the
        bounded on-chain funding authority.
        """

        if not isinstance(workload_id, str) or not _WORKLOAD_ID.fullmatch(workload_id):
            raise ComputeWorkloadIngressError("Compute workload ID is malformed")
        if not isinstance(project_commitment, str) or not _SHA256.fullmatch(
            project_commitment
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload project binding is malformed"
            )
        claim = ComputeWorkloadDispatchClaim(
            job_id=job_id,
            intent_commitment=intent_commitment,
            funding_wallet=funding_wallet,
            execution_binding_commitment=execution_binding_commitment,
        )
        with self._exclusive_lock():
            records = self._recover_deletions(self._load_index())
            matches = [
                item for item in records.values() if item.workload_id == workload_id
            ]
            if len(matches) != 1 or not hmac.compare_digest(
                matches[0].project_commitment,
                project_commitment,
            ):
                raise ComputeWorkloadIngressError("Compute workload was not found")
            record = matches[0]
            if record.lifecycle == "dispatch_claimed":
                if record.dispatch_claim != claim or not hmac.compare_digest(
                    record.dispatch_claim_commitment,
                    claim.commitment,
                ):
                    raise ComputeWorkloadIngressConflict(
                        "Compute workload is claimed by a different dispatch"
                    )
                return claim, False
            if record.lifecycle != "sealed":
                raise ComputeWorkloadIngressConflict(
                    "Compute workload is no longer available for dispatch"
                )
            for other in records.values():
                if (
                    other.dispatch_claim is not None
                    and other.workload_id != workload_id
                    and hmac.compare_digest(other.dispatch_claim.job_id, claim.job_id)
                ):
                    raise ComputeWorkloadIngressConflict(
                        "Compute dispatch job already claims another workload"
                    )
            binding, envelope = self._load_blob(record)
            actual_execution_binding = (
                compute_workload_execution_binding_commitment(
                    workload_id,
                    binding,
                    envelope,
                )
            )
            if not hmac.compare_digest(
                actual_execution_binding,
                claim.execution_binding_commitment,
            ):
                raise ComputeWorkloadIngressConflict(
                    "Compute workload execution binding does not match"
                )
            claimed = dict(records)
            claimed[record.idempotency_hash] = replace(
                record,
                lifecycle="dispatch_claimed",
                dispatch_claim=claim,
                dispatch_claim_commitment=claim.commitment,
            )
            self._persist_index(claimed)
            return claim, True

    def get_claimed_for_execution(
        self,
        workload_id: str,
        *,
        project_commitment: str,
        claim: ComputeWorkloadDispatchClaim,
    ) -> StoredComputeWorkload:
        if not isinstance(claim, ComputeWorkloadDispatchClaim):
            raise ComputeWorkloadIngressError(
                "Compute workload execution claim is invalid"
            )
        stored = self.get_for_project(
            workload_id,
            project_commitment=project_commitment,
        )
        if (
            stored.lifecycle != "dispatch_claimed"
            or stored.dispatch_claim != claim
            or not hmac.compare_digest(
                compute_workload_execution_binding_commitment(
                    stored.workload_id,
                    stored.binding,
                    stored.envelope,
                ),
                claim.execution_binding_commitment,
            )
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dispatch claim is unavailable"
            )
        return stored

    def consume_ciphertext_for_project(
        self,
        workload_id: str,
        *,
        project_commitment: str,
    ) -> StoredComputeWorkload:
        """Atomically take one envelope and durably erase its ciphertext.

        The authenticated ``deleting`` tombstone makes crashes fail closed: a
        restart completes deletion whether the crash occurred immediately
        before or after unlinking the ciphertext object.
        """

        if not isinstance(workload_id, str) or not _WORKLOAD_ID.fullmatch(workload_id):
            raise ComputeWorkloadIngressError("Compute workload ID is malformed")
        if not isinstance(project_commitment, str) or not _SHA256.fullmatch(
            project_commitment
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload project binding is malformed"
            )
        with self._exclusive_lock():
            records = self._recover_deletions(self._load_index())
            matches = [
                item
                for item in records.values()
                if item.workload_id == workload_id
            ]
            if len(matches) != 1 or not hmac.compare_digest(
                matches[0].project_commitment,
                project_commitment,
            ):
                raise ComputeWorkloadIngressError("Compute workload was not found")
            record = matches[0]
            if record.lifecycle == "dispatch_claimed":
                raise ComputeWorkloadIngressConflict(
                    "Compute workload is claimed by a wallet-funded dispatch"
                )
            if record.lifecycle != "sealed":
                raise ComputeWorkloadIngressError("Compute workload was not found")
            binding, envelope = self._load_blob(record)
            deleting = dict(records)
            deleting[record.idempotency_hash] = replace(
                record,
                lifecycle="deleting",
            )
            self._persist_index(deleting)
            try:
                os.unlink(f"{record.object_id}.json", dir_fd=self._blob_fd)
                _fsync_directory_fd(self._blob_fd)
            except FileNotFoundError:
                pass
            remaining = dict(deleting)
            remaining.pop(record.idempotency_hash)
            self._persist_index(remaining)
            return StoredComputeWorkload(
                workload_id=workload_id,
                binding=binding,
                envelope=envelope,
                lifecycle="sealed",
                dispatch_claim=None,
            )

    def release_ciphertext_after_checkpoint(
        self,
        workload_id: str,
        *,
        project_commitment: str,
        actor_commitment: str,
        release_checkpoint_commitment: str,
    ) -> bool:
        """Fail closed for the pre-claim release route.

        Version-two index state requires every checkpointed release to retain
        the exact wallet-funded dispatch claim.  Keeping this legacy method as
        an explicit rejection prevents an older caller from converting an
        unclaimed ``sealed`` record into release state.
        """

        del (
            workload_id,
            project_commitment,
            actor_commitment,
            release_checkpoint_commitment,
        )
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload release requires a confirmed dispatch claim"
        )

    def release_claimed_ciphertext_after_checkpoint(
        self,
        workload_id: str,
        *,
        project_commitment: str,
        claim: ComputeWorkloadDispatchClaim,
        release_checkpoint_commitment: str,
    ) -> bool:
        """Release only the ciphertext claimed by one exact dispatch tuple."""

        if not isinstance(workload_id, str) or not _WORKLOAD_ID.fullmatch(workload_id):
            raise ComputeWorkloadIngressError("Compute workload ID is malformed")
        if (
            not isinstance(project_commitment, str)
            or not _SHA256.fullmatch(project_commitment)
            or not isinstance(claim, ComputeWorkloadDispatchClaim)
            or not isinstance(release_checkpoint_commitment, str)
            or not _SHA256.fullmatch(release_checkpoint_commitment)
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload claimed release binding is malformed"
            )
        with self._exclusive_lock():
            records = self._recover_deletions(self._load_index())
            matches = [
                item for item in records.values() if item.workload_id == workload_id
            ]
            if len(matches) != 1:
                raise ComputeWorkloadIngressError("Compute workload was not found")
            record = matches[0]
            if (
                not hmac.compare_digest(record.project_commitment, project_commitment)
                or record.dispatch_claim != claim
                or not hmac.compare_digest(
                    record.dispatch_claim_commitment,
                    claim.commitment,
                )
            ):
                raise ComputeWorkloadIngressError("Compute workload was not found")
            if record.lifecycle == "released":
                if not hmac.compare_digest(
                    record.release_checkpoint_commitment,
                    release_checkpoint_commitment,
                ):
                    raise ComputeWorkloadIngressConflict(
                        "Compute workload release checkpoint does not match"
                    )
                return False
            if record.lifecycle != "dispatch_claimed":
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload claimed release recovery is incomplete"
                )
            self._load_blob(record)
            deleting = dict(records)
            deleting[record.idempotency_hash] = replace(
                record,
                lifecycle="deleting_after_checkpoint",
                release_checkpoint_commitment=release_checkpoint_commitment,
            )
            self._persist_index(deleting)
            try:
                os.unlink(f"{record.object_id}.json", dir_fd=self._blob_fd)
                _fsync_directory_fd(self._blob_fd)
            except FileNotFoundError:
                pass
            released = dict(deleting)
            released[record.idempotency_hash] = replace(
                deleting[record.idempotency_hash],
                lifecycle="released",
            )
            self._persist_index(released)
            return True

    def public_metadata(
        self,
        workload_id: str,
        *,
        project_commitment: str,
    ) -> dict[str, Any]:
        stored = self.get_for_project(
            workload_id,
            project_commitment=project_commitment,
        )
        return {
            "surface": "compute_workload_metadata",
            "schema_version": WORKLOAD_PUBLIC_SCHEMA_VERSION,
            "workload_id": stored.workload_id,
            "workload_schema": stored.binding.manifest.schema,
            "operation": stored.binding.manifest.operation,
            "model": stored.binding.manifest.model,
            "recipe": stored.binding.manifest.recipe,
            "payload_size_class": stored.binding.manifest.payload_size_class,
            "example_count_class": stored.binding.manifest.example_count_class,
            "resource_caps": {
                "max_prefill_tokens": stored.binding.manifest.max_prefill_tokens,
                "max_sample_tokens": stored.binding.manifest.max_sample_tokens,
                "max_train_tokens": stored.binding.manifest.max_train_tokens,
            },
            "manifest_commitment": stored.binding.manifest_commitment,
            "workload_commitment": stored.binding.workload_commitment,
            "recipient_key_id": stored.binding.recipient_key_id,
            "activation_commitment": stored.binding.activation_commitment,
            "recipient_release_commitment": (
                stored.binding.recipient_release_commitment
            ),
            "execution_binding": {
                "schema": "dnai.compute.workload-execution-binding.v1",
                "commitment": compute_workload_execution_binding_commitment(
                    stored.workload_id,
                    stored.binding,
                    stored.envelope,
                ),
                "source_kind": stored.binding.actor_kind,
                "wallet_adoption_required": (
                    stored.binding.actor_kind == "credential"
                ),
                "device_spending_authority": False,
            },
            "dispatch_adoption": {
                "state": (
                    "claimed_by_wallet_dispatch"
                    if stored.lifecycle == "dispatch_claimed"
                    else "wallet_adoption_required"
                    if stored.binding.actor_kind == "credential"
                    else "available_for_wallet_dispatch"
                ),
                "wallet_adoption_eligible": stored.lifecycle == "sealed",
                "dispatch_claimed": stored.lifecycle == "dispatch_claimed",
                "claim_commitment": (
                    stored.dispatch_claim.commitment
                    if stored.dispatch_claim is not None
                    else None
                ),
                "funding_authority": (
                    "onchain_wallet_job"
                    if stored.lifecycle == "dispatch_claimed"
                    else "wallet_required"
                ),
                "device_spending_authority": False,
                "direct_deletion_allowed": stored.lifecycle == "sealed",
            },
            "ciphertext_egress": False,
            "raw_prompt_egress": False,
            "raw_examples_egress": False,
            "raw_dataset_egress": False,
            "raw_output_egress": False,
            "provider_dispatch_enabled": False,
        }

    def _result(
        self,
        record: _IndexRecord,
        binding: ComputeWorkloadBinding,
        envelope: ComputeWorkloadEnvelope,
        *,
        created: bool,
    ) -> ComputeWorkloadIngressResult:
        return ComputeWorkloadIngressResult(
            workload_id=record.workload_id,
            manifest=binding.manifest,
            workload_commitment=record.workload_commitment,
            manifest_commitment=record.manifest_commitment,
            ciphertext_sha256=record.ciphertext_sha256,
            blob_sha256=record.blob_sha256,
            key_id=record.key_id,
            activation_commitment=record.activation_commitment,
            recipient_release_commitment=record.recipient_release_commitment,
            source_kind=binding.actor_kind,
            execution_binding_commitment=(
                compute_workload_execution_binding_commitment(
                    record.workload_id,
                    binding,
                    envelope,
                )
            ),
            created=created,
            _idempotency_hash=record.idempotency_hash,
            _request_hash=record.request_hash,
        )

    def _open_lock_file(self, name: str) -> int:
        if name not in {"index.lock", "execution.lock"}:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload lock file name is invalid"
            )
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, 0o600, dir_fd=self._root_fd)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ComputeWorkloadIngressUnavailable(
                    "Compute workload lock file is unsafe"
                )
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ComputeWorkloadIngressUnavailable(
                    "Compute workload lock file mode is unsafe"
                )
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._thread_lock.acquire()
        try:
            metadata = os.fstat(self._lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload lock file metadata changed"
                )
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        except Exception:
            self._thread_lock.release()
            raise
        try:
            yield
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            self._thread_lock.release()

    @contextmanager
    def execution_lease(self) -> Iterator[None]:
        """Serialize plaintext provider leases across worker processes."""

        self._execution_thread_lock.acquire()
        try:
            metadata = os.fstat(self._execution_lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload execution lock metadata changed"
                )
            fcntl.flock(self._execution_lock_fd, fcntl.LOCK_EX)
        except Exception:
            self._execution_thread_lock.release()
            raise
        try:
            yield
        finally:
            fcntl.flock(self._execution_lock_fd, fcntl.LOCK_UN)
            self._execution_thread_lock.release()

    def _index_body(self, records: Mapping[str, _IndexRecord]) -> dict[str, Any]:
        return {
            "schema": "dnai.compute.workload-ingress-index.v2",
            "schema_version": WORKLOAD_INDEX_SCHEMA_VERSION,
            "records": [
                item.to_dict()
                for item in sorted(records.values(), key=lambda entry: entry.idempotency_hash)
            ],
            "plaintext_persisted": False,
            "raw_prompt_persisted": False,
            "raw_examples_persisted": False,
            "raw_output_persisted": False,
        }

    def _persist_index(self, records: Mapping[str, _IndexRecord]) -> None:
        body = self._index_body(records)
        mac = hmac.new(
            self._integrity_key,
            WORKLOAD_STORE_MAC_DOMAIN + _canonical_json(body),
            hashlib.sha256,
        ).hexdigest()
        encoded = _canonical_json({"body": body, "mac": mac}) + b"\n"
        if len(encoded) > MAX_INDEX_BYTES:
            raise ComputeWorkloadIngressError("Compute workload index is oversized")
        temporary_name = f".index.{os.urandom(16).hex()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=self._root_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload temporary index is unsafe"
                )
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(
                temporary_name,
                "index.json",
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
            _fsync_directory_fd(self._root_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass

    def _load_index(self) -> dict[str, _IndexRecord]:
        try:
            return self._load_index_untrusted()
        except ComputeWorkloadIngressCorrupt:
            raise
        except (ComputeWorkloadIngressError, TypeError, ValueError) as exc:
            raise ComputeWorkloadIngressCorrupt(
                "Compute workload index is malformed"
            ) from exc

    def _load_index_untrusted(self) -> dict[str, _IndexRecord]:
        raw = _safe_read(
            "index.json",
            maximum=MAX_INDEX_BYTES,
            label="Compute workload index",
            dir_fd=self._root_fd,
        )
        root = _strict_json(raw, label="Compute workload index")
        _exact_keys(root, frozenset({"body", "mac"}), label="Compute workload index")
        body = root["body"]
        supplied_mac = root["mac"]
        if not isinstance(body, Mapping) or not isinstance(supplied_mac, str) or not _HEX_64.fullmatch(
            supplied_mac
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload index envelope is invalid")
        expected_mac = hmac.new(
            self._integrity_key,
            WORKLOAD_STORE_MAC_DOMAIN + _canonical_json(body),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise ComputeWorkloadIngressCorrupt("Compute workload index authentication failed")
        expected_fields = frozenset(
            {
                "schema",
                "schema_version",
                "records",
                "plaintext_persisted",
                "raw_prompt_persisted",
                "raw_examples_persisted",
                "raw_output_persisted",
            }
        )
        _exact_keys(body, expected_fields, label="Compute workload index body")
        if (
            body["schema"] != "dnai.compute.workload-ingress-index.v2"
            or body["schema_version"] != WORKLOAD_INDEX_SCHEMA_VERSION
            or body["plaintext_persisted"] is not False
            or body["raw_prompt_persisted"] is not False
            or body["raw_examples_persisted"] is not False
            or body["raw_output_persisted"] is not False
            or not isinstance(body["records"], list)
            or len(body["records"]) > self.max_envelopes
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload index body is invalid")
        records: dict[str, _IndexRecord] = {}
        workload_ids: set[str] = set()
        nonces: set[str] = set()
        for value in body["records"]:
            if not isinstance(value, Mapping):
                raise ComputeWorkloadIngressCorrupt("Compute workload index record is invalid")
            record = _IndexRecord.from_mapping(value)
            if (
                record.idempotency_hash in records
                or record.workload_id in workload_ids
                or record.nonce_fingerprint in nonces
            ):
                raise ComputeWorkloadIngressCorrupt("Compute workload index contains replayed state")
            records[record.idempotency_hash] = record
            workload_ids.add(record.workload_id)
            nonces.add(record.nonce_fingerprint)
        return records

    def _write_new_blob(self, name: str, encoded: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=self._blob_fd)
        except FileExistsError as exc:
            raise ComputeWorkloadIngressCorrupt("Compute workload object collision") from exc
        complete = False
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ComputeWorkloadIngressCorrupt(
                    "Compute workload object metadata is unsafe"
                )
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            complete = True
        finally:
            os.close(descriptor)
            if not complete:
                try:
                    os.unlink(name, dir_fd=self._blob_fd)
                    _fsync_directory_fd(self._blob_fd)
                except OSError:
                    pass
        _fsync_directory_fd(self._blob_fd)

    def _verify_records(self, records: Mapping[str, _IndexRecord]) -> None:
        if any(
            item.lifecycle not in {"sealed", "dispatch_claimed", "released"}
            for item in records.values()
        ):
            raise ComputeWorkloadIngressCorrupt(
                "Compute workload deletion recovery is incomplete"
            )
        expected_files = {
            f"{item.object_id}.json"
            for item in records.values()
            if item.lifecycle in {"sealed", "dispatch_claimed"}
        }
        actual_files = set(os.listdir(self._blob_fd))
        if actual_files != expected_files:
            raise ComputeWorkloadIngressCorrupt(
                "Compute workload envelope directory contains unindexed state"
            )
        for record in records.values():
            if record.lifecycle in {"sealed", "dispatch_claimed"}:
                self._load_blob(record)

    def _recover_deletions(
        self,
        records: Mapping[str, _IndexRecord],
    ) -> dict[str, _IndexRecord]:
        deleting = [
            record
            for record in records.values()
            if record.lifecycle in {"deleting", "deleting_after_checkpoint"}
        ]
        if not deleting:
            return dict(records)
        remaining = dict(records)
        for record in deleting:
            try:
                os.unlink(f"{record.object_id}.json", dir_fd=self._blob_fd)
                _fsync_directory_fd(self._blob_fd)
            except FileNotFoundError:
                pass
            if record.lifecycle == "deleting":
                remaining.pop(record.idempotency_hash, None)
            else:
                remaining[record.idempotency_hash] = replace(
                    record,
                    lifecycle="released",
                )
        self._persist_index(remaining)
        return remaining

    def _load_blob(
        self,
        record: _IndexRecord,
    ) -> tuple[ComputeWorkloadBinding, ComputeWorkloadEnvelope]:
        try:
            return self._load_blob_untrusted(record)
        except ComputeWorkloadIngressCorrupt:
            raise
        except (ComputeWorkloadIngressError, TypeError, ValueError) as exc:
            raise ComputeWorkloadIngressCorrupt(
                "Compute workload envelope is malformed"
            ) from exc

    def _load_blob_untrusted(
        self,
        record: _IndexRecord,
    ) -> tuple[ComputeWorkloadBinding, ComputeWorkloadEnvelope]:
        encoded = _safe_read(
            f"{record.object_id}.json",
            maximum=MAX_BLOB_FILE_BYTES,
            label="Compute workload envelope",
            dir_fd=self._blob_fd,
        )
        if not hmac.compare_digest(
            _sha256(WORKLOAD_BLOB_HASH_DOMAIN + encoded), record.blob_sha256
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload blob hash mismatch")
        payload = _strict_json(encoded, label="Compute workload envelope")
        _exact_keys(
            payload,
            frozenset(
                {
                    "surface",
                    "schema_version",
                    "binding",
                    "envelope",
                    "plaintext_persisted",
                    "raw_prompt_persisted",
                    "raw_examples_persisted",
                    "raw_output_persisted",
                }
            ),
            label="Compute workload envelope",
        )
        if (
            payload["surface"] != "compute_workload_ciphertext_envelope"
            or payload["schema_version"] != WORKLOAD_INGRESS_SCHEMA_VERSION
            or payload["plaintext_persisted"] is not False
            or payload["raw_prompt_persisted"] is not False
            or payload["raw_examples_persisted"] is not False
            or payload["raw_output_persisted"] is not False
            or not isinstance(payload["binding"], Mapping)
            or not isinstance(payload["envelope"], Mapping)
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload envelope flags are invalid")
        binding = ComputeWorkloadBinding.from_mapping(payload["binding"])
        envelope = ComputeWorkloadEnvelope.from_mapping(payload["envelope"])
        _verify_binding_envelope(binding, envelope)
        comparisons = (
            (record.idempotency_hash, binding.idempotency_hash),
            (record.ciphertext_sha256, envelope.ciphertext_sha256),
            (record.aad_sha256, envelope.aad_sha256),
            (record.nonce_fingerprint, envelope.nonce_fingerprint),
            (record.key_id, envelope.key_id),
            (record.project_commitment, binding.project_commitment),
            (record.actor_commitment, binding.actor_commitment),
            (record.manifest_commitment, binding.manifest_commitment),
            (record.workload_commitment, binding.workload_commitment),
            (record.activation_commitment, binding.activation_commitment),
            (
                record.recipient_release_commitment,
                binding.recipient_release_commitment,
            ),
        )
        if any(not hmac.compare_digest(left, right) for left, right in comparisons):
            raise ComputeWorkloadIngressCorrupt("Compute workload envelope index binding mismatch")
        if (
            record.ciphertext_bytes != envelope.ciphertext_bytes
            or record.workload_schema != binding.manifest.schema
        ):
            raise ComputeWorkloadIngressCorrupt("Compute workload envelope metadata mismatch")
        return binding, envelope


class ComputeWorkloadIngressService:
    """Verify recipient activation, envelope binding, and ciphertext durability."""

    def __init__(
        self,
        store: ComputeWorkloadIngressStore,
        recipient: ComputeWorkloadRecipient,
        activation_provider: ComputeWorkloadActivationProvider | None = None,
        *,
        clock: Any = time.time,
    ) -> None:
        if not isinstance(store, ComputeWorkloadIngressStore) or not isinstance(
            recipient, ComputeWorkloadRecipient
        ):
            raise ComputeWorkloadIngressError("Compute workload ingress dependencies are invalid")
        self.store = store
        self.recipient = recipient
        self.activation_provider = (
            activation_provider or UnavailableComputeWorkloadActivationProvider()
        )
        self.clock = clock

    def current_activation(self) -> ComputeWorkloadRecipientActivation:
        now = int(self.clock())
        activation = self.activation_provider.verified_activation(
            self.recipient,
            now=now,
        )
        if not isinstance(activation, ComputeWorkloadRecipientActivation):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient activation is unavailable"
            )
        if (
            self.recipient.custody_mode != "dstack"
            or not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
            or activation.expires_at <= now
            or activation.issued_at > now + 30
            or activation.recipient_key_id != self.recipient.key_id
            or activation.report_data != "0x" + self.recipient.report_data.hex()
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload recipient activation does not match this CVM"
            )
        return activation

    def binding_for(
        self,
        *,
        principal: ComputeWorkloadPrincipal,
        manifest: ComputeWorkloadManifest,
        workload_commitment: str,
        idempotency_key: str,
        activation: ComputeWorkloadRecipientActivation,
    ) -> ComputeWorkloadBinding:
        if not isinstance(workload_commitment, str) or not _SHA256.fullmatch(
            workload_commitment
        ) or workload_commitment == "sha256:" + "0" * 64:
            raise ComputeWorkloadIngressError("workload commitment is malformed")
        return ComputeWorkloadBinding(
            project_commitment=principal.project_commitment,
            actor_kind=principal.kind,
            actor_commitment=principal.actor_commitment,
            manifest=manifest,
            manifest_commitment=manifest.commitment,
            workload_commitment=workload_commitment,
            idempotency_hash=compute_workload_idempotency_hash(
                principal,
                idempotency_key,
            ),
            recipient_key_id=self.recipient.key_id,
            report_data_sha256=_sha256(self.recipient.report_data),
            activation_commitment=activation.commitment,
            recipient_release_commitment=(
                activation.recipient_release_commitment
            ),
        )

    def ingest(
        self,
        *,
        principal: ComputeWorkloadPrincipal,
        manifest: ComputeWorkloadManifest,
        workload_commitment: str,
        idempotency_key: str,
        envelope: ComputeWorkloadEnvelope | Mapping[str, Any],
    ) -> ComputeWorkloadIngressResult:
        activation = self.current_activation()
        parsed = (
            envelope
            if isinstance(envelope, ComputeWorkloadEnvelope)
            else ComputeWorkloadEnvelope.from_mapping(envelope)
        )
        binding = self.binding_for(
            principal=principal,
            manifest=manifest,
            workload_commitment=workload_commitment,
            idempotency_key=idempotency_key,
            activation=activation,
        )
        if (
            parsed.key_id != self.recipient.key_id
            or parsed.attestation_report_data != self.recipient.report_data.hex()
            or parsed.activation_commitment != activation.commitment
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload envelope targets an unverified recipient"
            )
        actual_aad = _b64decode(parsed.aad, label="aad", maximum_bytes=MAX_AAD_BYTES)
        if not hmac.compare_digest(actual_aad, compute_workload_aad(binding)):
            raise ComputeWorkloadIngressError("Compute workload AAD binding mismatch")
        if (
            parsed.ciphertext_bytes
            != PAYLOAD_CLASS_BYTES[manifest.payload_size_class] + GCM_TAG_BYTES
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload ciphertext length does not match manifest"
            )
        _verify_binding_envelope(binding, parsed)
        return self.store.put(binding=binding, envelope=parsed)

    def public_capability(self) -> dict[str, Any]:
        try:
            activation = self.current_activation()
        except ComputeWorkloadIngressUnavailable:
            activation = None
        return compute_workload_browser_contract(
            self.recipient,
            activation=activation,
            max_envelopes=self.store.max_envelopes,
        )

    @contextmanager
    def consume_for_execution(
        self,
        workload_id: str,
        *,
        project_commitment: str,
    ) -> Iterator[ComputeWorkloadExecutionLease]:
        """One-shot decrypt/validate handoff with best-effort zeroization.

        This method contains no provider call. It first re-authenticates the
        current recipient activation, then durably removes the ciphertext from
        the ingress store, decrypts and validates inside the CVM, and finally
        overwrites the mutable plaintext buffer even when the caller raises.
        """

        activation = self.current_activation()
        preview = self.store.get_for_project(
            workload_id,
            project_commitment=project_commitment,
        )
        if (
            preview.binding.recipient_key_id != self.recipient.key_id
            or preview.binding.recipient_release_commitment
            != activation.recipient_release_commitment
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload activation is no longer current"
            )
        del preview
        stored = self.store.consume_ciphertext_for_project(
            workload_id,
            project_commitment=project_commitment,
        )
        envelope = stored.envelope
        aad = _b64decode(envelope.aad, label="aad", maximum_bytes=MAX_AAD_BYTES)
        encrypted = EncryptedPayload(
            ephemeral_public_key=_b64decode(
                envelope.ephemeral_public_key,
                label="ephemeral_public_key",
                maximum_bytes=X25519_PUBLIC_KEY_BYTES,
                exact_bytes=X25519_PUBLIC_KEY_BYTES,
            ),
            nonce=_b64decode(
                envelope.nonce,
                label="nonce",
                maximum_bytes=AES_GCM_NONCE_BYTES,
                exact_bytes=AES_GCM_NONCE_BYTES,
            ),
            ciphertext=_b64decode(
                envelope.ciphertext,
                label="ciphertext",
                maximum_bytes=MAX_CIPHERTEXT_BYTES,
            ),
        )
        try:
            raw_plaintext = self.recipient.keypair.decrypt(
                encrypted,
                info=WORKLOAD_HKDF_INFO,
                associated_data=aad,
                hkdf_salt=hashlib.sha256(aad).digest(),
            )
        except InvalidTag as exc:
            raise ComputeWorkloadIngressError(
                "Compute workload ciphertext authentication failed"
            ) from exc
        sealed_plaintext = bytearray(raw_plaintext)
        del raw_plaintext
        payload_plaintext = bytearray()
        try:
            validated = validate_compute_workload_plaintext(
                stored.binding.manifest,
                sealed_plaintext,
                expected_commitment=stored.binding.workload_commitment,
            )
            _blinding, private_payload = _sealed_workload_parts(
                stored.binding.manifest,
                sealed_plaintext,
            )
            payload_plaintext = bytearray(private_payload)
            del private_payload
            yield ComputeWorkloadExecutionLease(
                workload_id=stored.workload_id,
                manifest=stored.binding.manifest,
                plaintext=payload_plaintext,
                validated=validated,
                _reauthenticate=lambda: validated,
            )
        finally:
            _zero_bytearray(payload_plaintext)
            _zero_bytearray(sealed_plaintext)

    def claim_for_dispatch(
        self,
        workload_id: str,
        *,
        project_id: str,
        job_id: str,
        intent_commitment: str,
        funding_wallet: str,
        source_kind: str,
        execution_binding_commitment: str,
        recipient_release_commitment: str,
    ) -> tuple[ComputeWorkloadDispatchClaim, bool]:
        """Claim an immutable source-bound envelope for one wallet job."""

        if (
            source_kind not in {"wallet", "credential"}
            or not isinstance(execution_binding_commitment, str)
            or not _SHA256.fullmatch(execution_binding_commitment)
            or not isinstance(recipient_release_commitment, str)
            or not _SHA256.fullmatch(recipient_release_commitment)
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload dispatch authority is malformed"
            )
        activation = self.current_activation()
        project_commitment = compute_workload_project_commitment(project_id)
        stored = self.store.get_for_project(
            workload_id,
            project_commitment=project_commitment,
        )
        actual_execution_binding = compute_workload_execution_binding_commitment(
            stored.workload_id,
            stored.binding,
            stored.envelope,
        )
        if (
            stored.binding.actor_kind != source_kind
            or stored.binding.recipient_key_id != self.recipient.key_id
            or stored.binding.recipient_release_commitment
            != activation.recipient_release_commitment
            or stored.binding.recipient_release_commitment
            != recipient_release_commitment
            or not hmac.compare_digest(
                actual_execution_binding,
                execution_binding_commitment,
            )
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dispatch binding is no longer current"
            )
        return self.store.claim_for_dispatch(
            workload_id,
            project_commitment=project_commitment,
            job_id=job_id,
            intent_commitment=intent_commitment,
            funding_wallet=funding_wallet,
            execution_binding_commitment=execution_binding_commitment,
        )

    @contextmanager
    def lease_for_provider_execution(
        self,
        workload_id: str,
        *,
        project_id: str,
        claim: ComputeWorkloadDispatchClaim,
        source_kind: str,
        recipient_release_commitment: str,
    ) -> Iterator[ComputeWorkloadExecutionLease]:
        """Open a non-destructive, exclusive provider-recovery lease.

        The authenticated ciphertext remains in the store until
        :meth:`release_after_usage_checkpoint` is called after the execution
        journal has durably stored the exact bounded usage/result. This is the
        only lease suitable for an idempotent external provider boundary.
        """

        if (
            source_kind not in {"wallet", "credential"}
            or not isinstance(recipient_release_commitment, str)
            or not _SHA256.fullmatch(recipient_release_commitment)
            or not isinstance(claim, ComputeWorkloadDispatchClaim)
        ):
            raise ComputeWorkloadIngressError(
                "Compute workload execution authority is invalid"
            )
        project_commitment = compute_workload_project_commitment(project_id)
        with self.store.execution_lease():
            activation = self.current_activation()
            stored = self.store.get_claimed_for_execution(
                workload_id,
                project_commitment=project_commitment,
                claim=claim,
            )
            binding = stored.binding
            if (
                binding.actor_kind != source_kind
                or binding.recipient_key_id != self.recipient.key_id
                or binding.recipient_release_commitment
                != activation.recipient_release_commitment
                or binding.recipient_release_commitment
                != recipient_release_commitment
            ):
                raise ComputeWorkloadIngressUnavailable(
                    "Compute workload execution binding is no longer current"
                )
            envelope = stored.envelope
            aad = _b64decode(
                envelope.aad,
                label="aad",
                maximum_bytes=MAX_AAD_BYTES,
            )
            encrypted = EncryptedPayload(
                ephemeral_public_key=_b64decode(
                    envelope.ephemeral_public_key,
                    label="ephemeral_public_key",
                    maximum_bytes=X25519_PUBLIC_KEY_BYTES,
                    exact_bytes=X25519_PUBLIC_KEY_BYTES,
                ),
                nonce=_b64decode(
                    envelope.nonce,
                    label="nonce",
                    maximum_bytes=AES_GCM_NONCE_BYTES,
                    exact_bytes=AES_GCM_NONCE_BYTES,
                ),
                ciphertext=_b64decode(
                    envelope.ciphertext,
                    label="ciphertext",
                    maximum_bytes=MAX_CIPHERTEXT_BYTES,
                ),
            )
            try:
                raw_plaintext = self.recipient.keypair.decrypt(
                    encrypted,
                    info=WORKLOAD_HKDF_INFO,
                    associated_data=aad,
                    hkdf_salt=hashlib.sha256(aad).digest(),
                )
            except InvalidTag as exc:
                raise ComputeWorkloadIngressError(
                    "Compute workload ciphertext authentication failed"
                ) from exc
            sealed_plaintext = bytearray(raw_plaintext)
            del raw_plaintext
            payload_plaintext = bytearray()
            try:
                validated = validate_compute_workload_plaintext(
                    binding.manifest,
                    sealed_plaintext,
                    expected_commitment=binding.workload_commitment,
                )
                _blinding, private_payload = _sealed_workload_parts(
                    binding.manifest,
                    sealed_plaintext,
                )
                payload_plaintext = bytearray(private_payload)
                del private_payload

                def _reauthenticate() -> ValidatedComputeWorkload:
                    latest_activation = self.current_activation()
                    latest = self.store.get_claimed_for_execution(
                        workload_id,
                        project_commitment=project_commitment,
                        claim=claim,
                    )
                    if (
                        latest.binding != binding
                        or latest.envelope != envelope
                        or latest.binding.actor_kind != source_kind
                        or latest.binding.recipient_key_id
                        != self.recipient.key_id
                        or latest.binding.recipient_release_commitment
                        != latest_activation.recipient_release_commitment
                        or latest.binding.recipient_release_commitment
                        != recipient_release_commitment
                    ):
                        raise ComputeWorkloadIngressUnavailable(
                            "Compute workload execution lease changed"
                        )
                    return validate_compute_workload_plaintext(
                        binding.manifest,
                        sealed_plaintext,
                        expected_commitment=binding.workload_commitment,
                    )

                yield ComputeWorkloadExecutionLease(
                    workload_id=stored.workload_id,
                    manifest=binding.manifest,
                    plaintext=payload_plaintext,
                    validated=validated,
                    _reauthenticate=_reauthenticate,
                )
            finally:
                _zero_bytearray(payload_plaintext)
                _zero_bytearray(sealed_plaintext)

    def release_after_usage_checkpoint(
        self,
        workload_id: str,
        *,
        project_id: str,
        claim: ComputeWorkloadDispatchClaim,
        release_checkpoint_commitment: str,
    ) -> bool:
        return self.store.release_claimed_ciphertext_after_checkpoint(
            workload_id,
            project_commitment=compute_workload_project_commitment(project_id),
            claim=claim,
            release_checkpoint_commitment=release_checkpoint_commitment,
        )

    def release_after_cancellation_checkpoint(
        self,
        workload_id: str,
        *,
        project_id: str,
        claim: ComputeWorkloadDispatchClaim,
        cancellation_checkpoint_commitment: str,
    ) -> bool:
        """Erase an unexecuted workload after a serialized wallet cancellation.

        The caller must first commit the cancellation under the execution
        journal's cross-process cycle lease. The store's durable tombstone then
        makes a crash/retry at this boundary exact and no-clobber.
        """

        return self.store.release_claimed_ciphertext_after_checkpoint(
            workload_id,
            project_commitment=compute_workload_project_commitment(project_id),
            claim=claim,
            release_checkpoint_commitment=(
                cancellation_checkpoint_commitment
            ),
        )


def _verify_binding_envelope(
    binding: ComputeWorkloadBinding,
    envelope: ComputeWorkloadEnvelope,
) -> None:
    if (
        not isinstance(binding, ComputeWorkloadBinding)
        or not isinstance(envelope, ComputeWorkloadEnvelope)
        or binding.recipient_key_id != envelope.key_id
        or binding.activation_commitment != envelope.activation_commitment
        or binding.report_data_sha256
        != _sha256(bytes.fromhex(envelope.attestation_report_data))
        or PAYLOAD_CLASS_BYTES[binding.manifest.payload_size_class] + GCM_TAG_BYTES
        != envelope.ciphertext_bytes
    ):
        raise ComputeWorkloadIngressCorrupt("Compute workload envelope binding mismatch")
    actual_aad = _b64decode(envelope.aad, label="aad", maximum_bytes=MAX_AAD_BYTES)
    if not hmac.compare_digest(actual_aad, compute_workload_aad(binding)):
        raise ComputeWorkloadIngressCorrupt("Compute workload envelope AAD mismatch")


def _private_key(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str) and _HEX_64.fullmatch(value):
        raw = bytes.fromhex(value)
    else:
        raise ComputeWorkloadIngressUnavailable("Compute workload key is malformed")
    if len(raw) != 32 or raw == b"\0" * 32:
        raise ComputeWorkloadIngressUnavailable("Compute workload key is malformed")
    return raw


def _read_local_key(path: Path) -> bytes:
    raw = _safe_read(path, maximum=32, label="Compute workload local key")
    if len(raw) != 32:
        raise ComputeWorkloadIngressUnavailable("Compute workload local key is malformed")
    return _private_key(raw)


def _create_local_key(path: Path) -> bytes:
    _secure_directory(path.parent)
    if path.exists() or path.is_symlink():
        return _read_local_key(path)
    raw = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _read_local_key(path)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_descriptor = _open_secure_directory(path.parent)
    try:
        _fsync_directory_fd(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return raw


def _setting(settings: Any, name: str, default: Any = "") -> Any:
    return getattr(settings, name, default) if settings is not None else default


def resolve_compute_workload_recipient(
    settings: Any = None,
    *,
    root_path: str | Path | None = None,
    private_key_override: str | bytes | None = None,
) -> ComputeWorkloadRecipient:
    configured_override = str(
        _setting(settings, "compute_workload_ingress_private_key_hex", "") or ""
    ).strip()
    override = private_key_override or configured_override or None
    if dstack_utils.is_dstack_enabled():
        if override is not None:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload explicit recipient keys are local-only"
            )
        path = str(
            _setting(
                settings,
                "compute_workload_ingress_key_path",
                WORKLOAD_DSTACK_KEY_PATH,
            )
            or ""
        ).strip()
        if (
            not _DSTACK_PATH.fullmatch(path)
            or "compute_workload_ingress" not in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dstack key path is invalid"
            )
        try:
            raw = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload dstack key derivation failed"
            ) from exc
        private = _private_key(raw[:32])
        custody = "dstack"
    elif override is not None:
        private = _private_key(override)
        custody = "local"
    else:
        configured = str(
            _setting(settings, "compute_workload_ingress_local_key_file", "") or ""
        ).strip()
        if configured:
            path = Path(configured)
        elif root_path is not None:
            path = Path(root_path) / "compute-workload-ingress.key"
        else:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload local key path is unavailable"
            )
        private = _create_local_key(path)
        custody = "local"
    return ComputeWorkloadRecipient.from_keypair(
        TEEKeyPair.from_private_key_hex(private.hex()),
        custody_mode=custody,
    )


def compute_workload_integrity_key(settings: Any) -> bytes:
    if dstack_utils.is_dstack_enabled():
        if str(
            _setting(settings, "compute_workload_ingress_integrity_key", "") or ""
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload explicit integrity keys are local-only"
            )
        path = str(
            _setting(
                settings,
                "compute_workload_ingress_integrity_key_path",
                WORKLOAD_INTEGRITY_DSTACK_KEY_PATH,
            )
            or ""
        ).strip()
        if (
            not _DSTACK_PATH.fullmatch(path)
            or "compute_workload_ingress_integrity" not in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload integrity dstack path is invalid"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ComputeWorkloadIngressUnavailable(
                "Compute workload integrity key derivation failed"
            ) from exc
        return hashlib.sha256(
            b"dnai-wikigen/compute-workload-integrity/dstack/v1\0" + material
        ).digest()
    explicit = str(
        _setting(settings, "compute_workload_ingress_integrity_key", "") or ""
    )
    if len(explicit.encode("utf-8")) < 32:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload local integrity key is unavailable"
        )
    return hashlib.sha256(
        b"dnai-wikigen/compute-workload-integrity/local/v1\0"
        + explicit.encode("utf-8")
    ).digest()


def build_compute_workload_ingress(
    settings: Any,
    *,
    activation_provider: ComputeWorkloadActivationProvider | None = None,
) -> ComputeWorkloadIngressService:
    path = str(
        _setting(settings, "compute_workload_ingress_store_path", "") or ""
    ).strip()
    if not path:
        raise ComputeWorkloadIngressUnavailable(
            "Compute workload durable store is not configured"
        )
    recipient = resolve_compute_workload_recipient(settings, root_path=Path(path))
    provider = activation_provider
    if provider is None and dstack_utils.is_dstack_enabled():
        try:
            from tinker_delegate.compute_workload_activation import (
                HttpsComputeWorkloadActivationProvider,
            )

            production_provider = (
                HttpsComputeWorkloadActivationProvider.from_settings(settings)
            )
            recipient = recipient.with_recipient_attestation(
                production_provider.recipient_attestation(recipient.public_key)
            )
            provider = production_provider
        except ComputeWorkloadIngressUnavailable:
            # A partially projected release remains visibly blocked. It never
            # falls back to local keys, simulated evidence, or a reused QVL.
            provider = UnavailableComputeWorkloadActivationProvider()
    store = ComputeWorkloadIngressStore(
        path,
        integrity_key=compute_workload_integrity_key(settings),
        max_envelopes=_setting(
            settings,
            "compute_workload_ingress_max_envelopes",
            MAX_ENVELOPES,
        ),
    )
    return ComputeWorkloadIngressService(
        store,
        recipient,
        activation_provider=provider,
    )


def get_compute_workload_attestation(
    settings: Any,
    *,
    recipient: ComputeWorkloadRecipient,
) -> dict[str, Any]:
    public = {
        **recipient.to_public_dict(),
        "quote": "",
        "quote_report_data": "",
        "app_id": "",
        "compose_hash": "",
        "os_image_hash": "",
        "verified": False,
    }
    if not dstack_utils.is_dstack_enabled():
        return {"mode": "local", **public}
    mode = "simulator" if dstack_utils.is_dstack_simulator() else "tdx"
    try:
        details = dstack_utils.get_attestation_details(recipient.report_data)
    except Exception:
        return {"mode": mode, **public}
    return {
        "mode": mode,
        **public,
        "quote": str(details.get("quote") or ""),
        "quote_report_data": str(details.get("quote_report_data") or ""),
        "app_id": str(details.get("app_id") or ""),
        "compose_hash": str(details.get("compose_hash") or ""),
        "os_image_hash": str(details.get("os_image_hash") or ""),
        "verified": False,
    }


def compute_workload_browser_contract(
    recipient: ComputeWorkloadRecipient,
    *,
    activation: ComputeWorkloadRecipientActivation | None,
    max_envelopes: int,
) -> dict[str, Any]:
    enabled = isinstance(activation, ComputeWorkloadRecipientActivation)
    return {
        "surface": "compute_workload_encryption_contract",
        "schema_version": WORKLOAD_INGRESS_SCHEMA_VERSION,
        "status": "live" if enabled else "blocked",
        "upload_enabled": enabled,
        "reason": (
            "verified_recipient_activation_current"
            if enabled
            else "independent_qvl_recipient_activation_required"
        ),
        "protocol": {
            "algorithm": WORKLOAD_INGRESS_ALGORITHM,
            "encoding": WORKLOAD_INGRESS_ENCODING,
            "hkdf_hash": "SHA-256",
            "hkdf_salt": "SHA-256(canonical_aad_bytes)",
            "hkdf_info_utf8": WORKLOAD_HKDF_INFO.decode("ascii"),
            "aes_gcm_nonce_bytes": AES_GCM_NONCE_BYTES,
            "aes_gcm_tag_bytes": GCM_TAG_BYTES,
            "additional_authenticated_data": "canonical_aad_bytes",
            "sealed_plaintext_frame": {
                "magic_hex": SEALED_FRAME_MAGIC.hex(),
                "payload_length_bytes": SEALED_LENGTH_BYTES,
                "blinding_bytes": SEALED_BLINDING_BYTES,
                "blinding_source": "client_csprng",
                "padding_source": "client_csprng",
                "exact_payload_length_private": True,
                "exact_example_count_private": True,
            },
            "workload_commitment": (
                "SHA-256(domain || canonical_manifest || 0x00 || "
                "secret_blinding || 0x00 || private_payload)"
            ),
        },
        "recipient": {
            **recipient.to_public_dict(),
            "report_data_sha256": _sha256(recipient.report_data),
            "activation_commitment": activation.commitment if enabled else "",
            "recipient_release_commitment": (
                activation.recipient_release_commitment if enabled else ""
            ),
            "activation_expires_at": activation.expires_at if enabled else 0,
            "independent_tdx_verdict_authenticated": enabled,
        },
        "activation": activation.to_dict() if enabled else None,
        "workload_schemas": {
            "inference": {
                "schema": INFERENCE_WORKLOAD_SCHEMA,
                "payload_schema": INFERENCE_PAYLOAD_SCHEMA,
                "recipe": "qwen3_8b_bounded",
                "max_content_bytes": MAX_INFERENCE_PROMPT_BYTES,
                "max_prefill_tokens": 32_768,
                "max_sample_tokens": 4_096,
            },
            "training": {
                "schema": SFT_JSONL_WORKLOAD_SCHEMA,
                "line_fields": ["completion", "prompt"],
                "recipe": "qwen3_8b_lora_r32",
                "max_content_bytes": MAX_PRIVATE_PAYLOAD_BYTES,
                "max_examples": MAX_SFT_EXAMPLES,
                "max_field_bytes": MAX_SFT_FIELD_BYTES,
                "max_train_tokens": 10_000_000,
            },
        },
        "privacy_classes": {
            "payload_size_bytes": dict(PAYLOAD_CLASS_BYTES),
            "example_count_ranges": {
                key: [minimum, maximum]
                for key, (minimum, maximum) in EXAMPLE_COUNT_CLASSES.items()
            },
            "ciphertext_length_reveals_only_payload_size_class": True,
            "commitment_is_secret_blinded": True,
        },
        "limits": {
            "max_aad_bytes": MAX_AAD_BYTES,
            "max_ciphertext_bytes": MAX_CIPHERTEXT_BYTES,
            "max_envelopes": max_envelopes,
            "idempotency_key_max_bytes": 128,
        },
        "gates": {
            "real_dstack_required": True,
            "simulator_rejected": True,
            "fresh_independent_qvl_verdict_required": True,
            "release_and_measurement_binding_required": True,
            "matching_recipient_key_and_report_data_required": True,
            "wallet_or_workloads_create_device_scope_required": True,
            "provider_dispatch_enabled": False,
        },
        "plaintext_fields_accepted": False,
        "ciphertext_egress": False,
        "raw_prompt_egress": False,
        "raw_examples_egress": False,
        "raw_dataset_egress": False,
        "raw_output_egress": False,
    }
