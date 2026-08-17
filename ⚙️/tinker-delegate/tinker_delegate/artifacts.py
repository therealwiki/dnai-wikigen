"""Artifact ingress helpers for bounded, commitment-checked uploads.

``artifactHash`` remains the v2 domain-separated salted commitment to the exact
raw artifact byte sequence.  Transport uses the constant-size v3 envelope so a
network observer learns only the frozen one-mebibyte padding profile, never the
private artifact length.  The length and 32-byte commitment secret are both
inside authenticated ciphertext; there is no legacy/raw compatibility path.
"""

from __future__ import annotations

import hmac
import os
import re

from eth_hash.auto import keccak

from tinker_delegate.crypto import ARTIFACT_HKDF_INFO, EncryptedPayload, TEEKeyPair, encrypt_for_tee


ARTIFACT_COMMITMENT_SCHEME = "dnai-wikigen/artifact-commitment/v2"
ARTIFACT_COMMITMENT_DOMAIN = ARTIFACT_COMMITMENT_SCHEME.encode("ascii")
ARTIFACT_COMMITMENT_SECRET_BYTES = 32
ARTIFACT_ENVELOPE_SCHEME = "dnai-wikigen/artifact-envelope/v3"
ARTIFACT_PADDING_PROFILE = "fixed_1m_v3"
ARTIFACT_ENVELOPE_MAGIC = b"DNAIARTIFACTV3\x00\x00"
ARTIFACT_RAW_MAX_BYTES = 1_048_576
ARTIFACT_LENGTH_BYTES = 4
ARTIFACT_FRAME_HEADER_BYTES = (
    len(ARTIFACT_ENVELOPE_MAGIC)
    + ARTIFACT_LENGTH_BYTES
    + ARTIFACT_COMMITMENT_SECRET_BYTES
)
ARTIFACT_FRAME_BYTES = ARTIFACT_FRAME_HEADER_BYTES + ARTIFACT_RAW_MAX_BYTES
ARTIFACT_GCM_TAG_BYTES = 16
ARTIFACT_CIPHERTEXT_BYTES = ARTIFACT_FRAME_BYTES + ARTIFACT_GCM_TAG_BYTES
ARTIFACT_AAD_PREFIX = b"dnai-wikigen/artifact-envelope-aad/v3"
ARTIFACT_HKDF_VERSION = b"v3"
BASE_SEPOLIA_CHAIN_ID = 84532

if len(ARTIFACT_ENVELOPE_MAGIC) != 16:  # pragma: no cover - release invariant
    raise RuntimeError("artifact v3 envelope magic must be exactly 16 bytes")


def _require_raw_artifact_size(artifact: bytes | bytearray) -> None:
    if not 1 <= len(artifact) <= ARTIFACT_RAW_MAX_BYTES:
        raise ValueError("artifact must be between 1 and 1,048,576 bytes")


def decode_artifact_hex(artifact_hex: str) -> bytearray:
    """Decode the exact-size hex v3 artifact frame into a mutable buffer."""
    if not isinstance(artifact_hex, str):
        raise ValueError("artifact_hex must be a string")
    raw = artifact_hex[2:] if artifact_hex.startswith(("0x", "0X")) else artifact_hex
    if len(raw) != ARTIFACT_FRAME_BYTES * 2:
        raise ValueError("artifact_hex must encode the exact v3 frame size")
    if len(raw) % 2 != 0:
        raise ValueError("artifact_hex must contain an even number of hex characters")
    try:
        return bytearray.fromhex(raw)
    except ValueError as exc:
        raise ValueError("artifact_hex must be valid hex") from exc


def zero_buffer(buffer: bytearray | None) -> None:
    """Best-effort in-place zeroing for mutable artifact buffers."""
    if buffer is None:
        return
    for i in range(len(buffer)):
        buffer[i] = 0


def normalize_artifact_hash(artifact_hash: str) -> str:
    """Normalize a bytes32 commitment string to 0x-prefixed lowercase hex."""
    raw = artifact_hash[2:] if artifact_hash.startswith(("0x", "0X")) else artifact_hash
    if len(raw) != 64:
        raise ValueError("artifact_hash must be a 32-byte hex string")
    try:
        bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("artifact_hash must be valid hex") from exc
    return f"0x{raw.lower()}"


def normalize_artifact_commitment_secret(
    commitment_secret: bytes | bytearray | str,
) -> bytearray:
    """Return a mutable copy of the exact 32-byte v2 commitment secret."""
    if isinstance(commitment_secret, str):
        raw = commitment_secret[2:] if commitment_secret.startswith(("0x", "0X")) else commitment_secret
        if len(raw) != ARTIFACT_COMMITMENT_SECRET_BYTES * 2:
            raise ValueError("commitment_secret must be a 32-byte hex string")
        try:
            result = bytearray.fromhex(raw)
        except ValueError as exc:
            raise ValueError("commitment_secret must be valid hex") from exc
    else:
        result = bytearray(commitment_secret)
    if len(result) != ARTIFACT_COMMITMENT_SECRET_BYTES:
        zero_buffer(result)
        raise ValueError("commitment_secret must be exactly 32 bytes")
    return result


def artifact_commitment(
    artifact: bytes | bytearray,
    commitment_secret: bytes | bytearray | str,
) -> str:
    """Return the v2 commitment for the exact raw artifact byte sequence.

    Formula::

        keccak256(
            UTF8("dnai-wikigen/artifact-commitment/v2")
            || 0x00
            || commitment_secret_32
            || raw_artifact
        )
    """

    _require_raw_artifact_size(artifact)
    secret = normalize_artifact_commitment_secret(commitment_secret)
    try:
        preimage = ARTIFACT_COMMITMENT_DOMAIN + bytes((0,)) + bytes(secret) + bytes(artifact)
        return f"0x{keccak(preimage).hex()}"
    finally:
        zero_buffer(secret)


def verify_artifact_commitment(
    artifact: bytes | bytearray,
    commitment_secret: bytes | bytearray | str,
    artifact_hash: str,
) -> str:
    """Verify raw bytes and their secret against the expected v2 commitment."""
    expected = normalize_artifact_hash(artifact_hash)
    actual = artifact_commitment(artifact, commitment_secret)
    if not hmac.compare_digest(actual, expected):
        raise ValueError("artifact commitment does not match uploaded artifact")
    return expected


def encode_artifact_wrapper(
    artifact: bytes | bytearray,
    commitment_secret: bytes | bytearray | str,
) -> bytearray:
    """Encode the exact constant-size plaintext frame accepted by ingress v3.

    ``os.urandom`` supplies padding for the unused payload area. Python may
    create transient immutable copies while assembling/parsing this frame, so
    callers must treat :func:`zero_buffer` as best-effort hygiene rather than a
    cryptographic memory-erasure guarantee.
    """
    _require_raw_artifact_size(artifact)
    secret = normalize_artifact_commitment_secret(commitment_secret)
    frame = bytearray(ARTIFACT_FRAME_BYTES)
    try:
        frame[:len(ARTIFACT_ENVELOPE_MAGIC)] = ARTIFACT_ENVELOPE_MAGIC
        length_offset = len(ARTIFACT_ENVELOPE_MAGIC)
        frame[length_offset:length_offset + ARTIFACT_LENGTH_BYTES] = len(artifact).to_bytes(
            ARTIFACT_LENGTH_BYTES,
            "big",
        )
        secret_offset = length_offset + ARTIFACT_LENGTH_BYTES
        payload_offset = secret_offset + ARTIFACT_COMMITMENT_SECRET_BYTES
        frame[secret_offset:payload_offset] = secret
        frame[payload_offset:payload_offset + len(artifact)] = artifact
        padding_length = ARTIFACT_RAW_MAX_BYTES - len(artifact)
        if padding_length:
            frame[payload_offset + len(artifact):] = os.urandom(padding_length)
        return frame
    except Exception:
        zero_buffer(frame)
        raise
    finally:
        zero_buffer(secret)


def decode_artifact_wrapper(
    wrapper: bytes | bytearray,
    artifact_hash: str,
) -> tuple[bytearray, bytearray]:
    """Decode and verify an exact v3 frame, returning ``(artifact, secret)``.

    The caller owns both mutable buffers and must zero them after their final use.
    Raw artifact bytes without the versioned wrapper always fail closed.
    """
    if len(wrapper) != ARTIFACT_FRAME_BYTES:
        raise ValueError("artifact frame is not the exact v3 size")
    if bytes(wrapper[:len(ARTIFACT_ENVELOPE_MAGIC)]) != ARTIFACT_ENVELOPE_MAGIC:
        raise ValueError("artifact frame magic is not the required v3 format")
    length_offset = len(ARTIFACT_ENVELOPE_MAGIC)
    artifact_length = int.from_bytes(
        wrapper[length_offset:length_offset + ARTIFACT_LENGTH_BYTES],
        "big",
    )
    if not 1 <= artifact_length <= ARTIFACT_RAW_MAX_BYTES:
        raise ValueError("artifact frame private length is outside the v3 bound")
    secret_offset = length_offset + ARTIFACT_LENGTH_BYTES
    payload_offset = secret_offset + ARTIFACT_COMMITMENT_SECRET_BYTES
    secret = bytearray(wrapper[secret_offset:payload_offset])
    artifact = bytearray(wrapper[payload_offset:payload_offset + artifact_length])
    try:
        verify_artifact_commitment(artifact, secret, artifact_hash)
    except Exception:
        zero_buffer(artifact)
        zero_buffer(secret)
        raise
    return artifact, secret


def _deal_id_ascii(deal_id: str) -> bytes:
    if not isinstance(deal_id, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,77})", deal_id):
        raise ValueError("deal_id must be a canonical uint256 decimal string")
    return deal_id.encode("ascii")


def normalize_diligence_room_address(contract_address: str) -> str:
    if not isinstance(contract_address, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]{40}",
        contract_address,
    ):
        raise ValueError("diligence_room_address must be an Ethereum address")
    normalized = contract_address.lower()
    if normalized == "0x" + "0" * 40:
        raise ValueError("diligence_room_address must be nonzero")
    return normalized


def normalize_evaluator_policy_commitment(commitment: str) -> str:
    normalized = normalize_artifact_hash(commitment)
    if normalized == "0x" + "0" * 64:
        raise ValueError("evaluator_policy_commitment must be nonzero")
    return normalized


def _artifact_context_fields(
    deal_id: str,
    artifact_hash: str,
    *,
    chain_id: int,
    diligence_room_address: str,
    evaluator_policy_commitment: str,
) -> tuple[bytes, ...]:
    if isinstance(chain_id, bool) or chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise ValueError("artifact envelope requires Base Sepolia chain id 84532")
    return (
        str(chain_id).encode("ascii"),
        normalize_diligence_room_address(diligence_room_address).encode("ascii"),
        _deal_id_ascii(deal_id),
        normalize_artifact_hash(artifact_hash).encode("ascii"),
        normalize_evaluator_policy_commitment(evaluator_policy_commitment).encode("ascii"),
        ARTIFACT_ENVELOPE_SCHEME.encode("ascii"),
    )


def artifact_associated_data(
    deal_id: str,
    artifact_hash: str,
    *,
    chain_id: int,
    diligence_room_address: str,
    evaluator_policy_commitment: str,
) -> bytes:
    """Build AES-GCM associated data binding ciphertext to deal and commitment."""
    return b"|".join(
        (
            ARTIFACT_AAD_PREFIX,
            *_artifact_context_fields(
                deal_id,
                artifact_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
        )
    )


def artifact_hkdf_info(
    deal_id: str,
    artifact_hash: str,
    *,
    chain_id: int,
    diligence_room_address: str,
    evaluator_policy_commitment: str,
) -> bytes:
    """Build per-deal/per-commitment HKDF context for artifact payload keys."""
    return b"|".join(
        (
            ARTIFACT_HKDF_INFO,
            ARTIFACT_HKDF_VERSION,
            *_artifact_context_fields(
                deal_id,
                artifact_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
        )
    )


def encrypt_artifact_payload(
    artifact: bytes | bytearray,
    tee_public_key_hex: str,
    *,
    deal_id: str,
    artifact_hash: str,
    commitment_secret: bytes | bytearray | str,
    chain_id: int,
    diligence_room_address: str,
    evaluator_policy_commitment: str,
) -> dict:
    """Encrypt a verified, context-bound constant-size v3 frame to the TEE."""
    expected_hash = verify_artifact_commitment(artifact, commitment_secret, artifact_hash)
    tee_public_key = bytes.fromhex(tee_public_key_hex)
    wrapper = encode_artifact_wrapper(artifact, commitment_secret)
    try:
        payload = encrypt_for_tee(
            bytes(wrapper),
            tee_public_key,
            info=artifact_hkdf_info(
                deal_id,
                expected_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
            associated_data=artifact_associated_data(
                deal_id,
                expected_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
        )
    finally:
        zero_buffer(wrapper)
    result = payload.to_hex()
    result["commitment_scheme"] = ARTIFACT_COMMITMENT_SCHEME
    result["envelope_scheme"] = ARTIFACT_ENVELOPE_SCHEME
    result["padding_profile"] = ARTIFACT_PADDING_PROFILE
    result["artifact_hash"] = expected_hash
    return result


def decrypt_artifact_payload(
    encrypted: EncryptedPayload,
    tee_keypair: TEEKeyPair,
    *,
    deal_id: str,
    artifact_hash: str,
    chain_id: int,
    diligence_room_address: str,
    evaluator_policy_commitment: str,
) -> tuple[bytearray, bytearray]:
    """Decrypt and verify a context-bound v3 frame inside the TEE.

    Returns ``(raw_artifact, commitment_secret)``.  The caller must zero both.
    """
    if len(encrypted.ciphertext) != ARTIFACT_CIPHERTEXT_BYTES:
        raise ValueError("artifact ciphertext is not the exact v3 size")
    wrapper = bytearray(
        tee_keypair.decrypt(
            encrypted,
            info=artifact_hkdf_info(
                deal_id,
                artifact_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
            associated_data=artifact_associated_data(
                deal_id,
                artifact_hash,
                chain_id=chain_id,
                diligence_room_address=diligence_room_address,
                evaluator_policy_commitment=evaluator_policy_commitment,
            ),
        )
    )
    try:
        return decode_artifact_wrapper(wrapper, artifact_hash)
    finally:
        zero_buffer(wrapper)
