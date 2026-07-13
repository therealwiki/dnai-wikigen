"""Envelope encryption for portable, TEE-sealed datasets.

This is the load-bearing primitive for "Sealed Data At Rest" (see PROJECT.md /
ARCHITECTURE.md): a reward dataset can live on untrusted public storage
(Hugging Face Hub, S3, IPFS) while plaintext exists only inside the attested
boundary. The construction reuses the existing X25519 + AES-256-GCM channel
(`crypto.encrypt_for_tee` / `TEEKeyPair`), it is not a new scheme:

    DEK   = fresh random AES-256 key (per dataset)
    blob  = chunked AES-256-GCM(plaintext, DEK)   # large, storage-agnostic
    wrap  = encrypt_for_tee(DEK, recipient CVM pubkey)  # one per measurement
    manifest = bounded { dataset_id, hashes, wrapped-DEK per recipient,
                         data_sensitivity, storage ref, optional signature }

Bounded-output rule: every public function here returns only hashes, sizes,
counts, labels, and ciphertext. The DEK and plaintext never appear in a
manifest or receipt. Storage backends (local/HF/S3/https) are intentionally out
of scope for this module — it produces/consumes the ciphertext blob + manifest;
where those bytes are published is a separate adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.crypto import NONCE_SIZE, EncryptedPayload, TEEKeyPair, encrypt_for_tee

SCHEMA_VERSION = "sealed-dataset-manifest-v1"
DEK_HKDF_INFO_PREFIX = b"tinker-delegate-dataset-dek"
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB


class DataSensitivity(str, Enum):
    PUBLIC_BENCHMARK = "public_benchmark"
    PRIVATE = "private"
    PHI = "phi"


class SealedDatasetError(ValueError):
    """Raised when a sealed-dataset operation cannot be performed safely."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_prefixed(value: str, *, prefix: str) -> str:
    return f"{prefix}_{hashlib.sha256(f'{prefix}:{value}'.encode()).hexdigest()[:48]}"


def generate_dek() -> bytes:
    """Fresh 256-bit data-encryption key. Never logged or placed in a manifest."""

    return AESGCM.generate_key(bit_length=256)


def generate_recipient_keypair() -> tuple[str, str]:
    """Generate a recipient X25519 keypair for sealed-dataset DEK delivery.

    Returns `(private_key_hex, public_key_hex)`. The public key is used as an
    `encrypt-dataset --recipient-pubkey`; the private key is dev/local recipient
    custody (a 0600 key file). Production CVM custody derives this from dstack.
    """

    private_key = X25519PrivateKey.generate()
    private_key_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return private_key_hex, public_key_hex


def recipient_key_hash(public_key_hex: str) -> str:
    """Bounded hash of a recipient public key, matching manifest recipients."""

    return _hash_prefixed(public_key_hex, prefix="recipient")


def _dek_info(dataset_id: str) -> bytes:
    return DEK_HKDF_INFO_PREFIX + b"|" + dataset_id.encode()


def _chunk_aad(dataset_id: str, index: int, total: int) -> bytes:
    return b"|".join((b"dataset-chunk", dataset_id.encode(), str(index).encode(), str(total).encode()))


@dataclass(frozen=True)
class EncryptedBlob:
    """Chunked AES-GCM ciphertext for a dataset, plus bounded chunk metadata."""

    dataset_id: str
    blob: bytes
    plaintext_sha256: str
    ciphertext_sha256: str
    plaintext_size: int
    chunk_size: int
    chunk_count: int
    chunk_nonces: tuple[str, ...]

    def chunk_metadata(self) -> dict[str, Any]:
        return {
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "chunk_nonces": list(self.chunk_nonces),
        }


def encrypt_dataset(
    plaintext: bytes,
    dek: bytes,
    *,
    dataset_id: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> EncryptedBlob:
    """Chunked AES-256-GCM encryption of `plaintext` under `dek`.

    Each chunk gets a fresh nonce and AAD binding dataset_id|index|total, so a
    truncated or reordered blob fails authentication. The wire blob is a length-
    prefixed concatenation of per-chunk ciphertexts.
    """

    if len(dek) != 32:
        raise SealedDatasetError("dek must be 32 bytes")
    if chunk_size <= 0:
        raise SealedDatasetError("chunk_size must be positive")
    aesgcm = AESGCM(dek)
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)] or [b""]
    total = len(chunks)
    nonces: list[str] = []
    parts: list[bytes] = []
    for index, chunk in enumerate(chunks):
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, chunk, _chunk_aad(dataset_id, index, total))
        nonces.append(nonce.hex())
        parts.append(len(ciphertext).to_bytes(8, "big") + ciphertext)
    blob = b"".join(parts)
    return EncryptedBlob(
        dataset_id=dataset_id,
        blob=blob,
        plaintext_sha256=_sha256_hex(plaintext),
        ciphertext_sha256=_sha256_hex(blob),
        plaintext_size=len(plaintext),
        chunk_size=chunk_size,
        chunk_count=total,
        chunk_nonces=tuple(nonces),
    )


def decrypt_dataset(
    blob: bytes,
    dek: bytes,
    *,
    dataset_id: str,
    chunk_nonces: list[str] | tuple[str, ...],
    expected_plaintext_sha256: str | None = None,
) -> bytearray:
    """Decrypt a chunked blob inside the boundary into a mutable buffer."""

    if len(dek) != 32:
        raise SealedDatasetError("dek must be 32 bytes")
    aesgcm = AESGCM(dek)
    total = len(chunk_nonces)
    out = bytearray()
    offset = 0
    for index in range(total):
        if offset + 8 > len(blob):
            raise SealedDatasetError("truncated blob header")
        length = int.from_bytes(blob[offset : offset + 8], "big")
        offset += 8
        ciphertext = blob[offset : offset + length]
        if len(ciphertext) != length:
            raise SealedDatasetError("truncated blob chunk")
        offset += length
        nonce = bytes.fromhex(chunk_nonces[index])
        plaintext = aesgcm.decrypt(nonce, ciphertext, _chunk_aad(dataset_id, index, total))
        out.extend(plaintext)
    if offset != len(blob):
        raise SealedDatasetError("trailing bytes after final chunk")
    if expected_plaintext_sha256 is not None and _sha256_hex(bytes(out)) != expected_plaintext_sha256:
        raise SealedDatasetError("plaintext hash mismatch after decrypt")
    return out


def wrap_dek(dek: bytes, recipient_public_key_hex: str, *, dataset_id: str) -> dict[str, str]:
    """Wrap the DEK to a recipient CVM's attestation-bound X25519 public key."""

    payload = encrypt_for_tee(
        dek,
        bytes.fromhex(recipient_public_key_hex),
        info=_dek_info(dataset_id),
    )
    envelope = payload.to_hex()
    envelope["recipient_key_hash"] = _hash_prefixed(recipient_public_key_hex, prefix="recipient")
    return envelope


def unwrap_dek(envelope: dict[str, str], tee_keypair: TEEKeyPair, *, dataset_id: str) -> bytes:
    """Unwrap the DEK inside the CVM using its attestation-bound private key."""

    payload = EncryptedPayload.from_hex(envelope)
    return tee_keypair.decrypt(payload, info=_dek_info(dataset_id))


_PROVENANCE_REQUIRED = (
    "source_pipeline",
    "upstream_id",
    "license",
    "distribution_claim",
    "benchmark_ref",
)


def build_provenance(
    *,
    source_pipeline: str,
    upstream_id: str,
    license: str,
    distribution_claim: str,
    benchmark_ref: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a bounded dataset-provenance block (public metadata, never plaintext).

    Records where the sealed data came from and, crucially, the *distribution
    claim* the seller makes against a named public benchmark. Placed inside the
    manifest before it is hashed and signed, so the claim is bound to the exact
    committed dataset at seal time — it cannot be attached favorably after the
    fact. All fields are public scalars; no sealed data belongs here.
    """

    provenance: dict[str, Any] = {
        "provenance_version": 1,
        "source_pipeline": str(source_pipeline),
        "upstream_id": str(upstream_id),
        "license": str(license),
        "distribution_claim": str(distribution_claim),
        "benchmark_ref": str(benchmark_ref),
    }
    for key in _PROVENANCE_REQUIRED:
        if not str(provenance[key]).strip():
            raise SealedDatasetError(f"provenance field {key} must be non-empty")
    if extra:
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, (str, int, bool)):
                raise SealedDatasetError("provenance extra must be str -> scalar")
            provenance[key] = value
    return provenance


def build_manifest(
    encrypted: EncryptedBlob,
    *,
    task: str,
    data_sensitivity: DataSensitivity,
    recipients: list[dict[str, str]],
    storage_ref: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the bounded, egress-safe dataset manifest.

    Contains only hashes, sizes, chunk metadata, per-recipient wrapped-DEK
    envelopes, a sensitivity label, an optional storage reference, and optional
    signed provenance. Never the DEK or plaintext.
    """

    if not recipients:
        raise SealedDatasetError("at least one recipient is required")
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": encrypted.dataset_id,
        "task": task,
        "data_sensitivity": DataSensitivity(data_sensitivity).value,
        "ciphertext_sha256": encrypted.ciphertext_sha256,
        "plaintext_sha256": encrypted.plaintext_sha256,
        "plaintext_size": encrypted.plaintext_size,
        "chunk": encrypted.chunk_metadata(),
        "recipients": [
            {
                "recipient_key_hash": r["recipient_key_hash"],
                "ephemeral_public_key": r["ephemeral_public_key"],
                "nonce": r["nonce"],
                "ciphertext": r["ciphertext"],
            }
            for r in recipients
        ],
        "storage_ref": storage_ref,
        "raw_secret_egress": False,
    }
    if provenance is not None:
        if not isinstance(provenance, dict):
            raise SealedDatasetError("provenance must be a mapping")
        # Committed into the manifest before hashing, so any owner/witness
        # signature binds the distribution claim to this exact dataset.
        manifest["provenance"] = dict(provenance)
    return manifest


def seal_receipt(encrypted: EncryptedBlob, manifest: dict[str, Any]) -> dict[str, Any]:
    """Bounded, egress-safe receipt for a seal operation. No DEK/plaintext."""

    return {
        "dataset_id": encrypted.dataset_id,
        "task": manifest.get("task"),
        "data_sensitivity": manifest.get("data_sensitivity"),
        "ciphertext_sha256": encrypted.ciphertext_sha256,
        "plaintext_size": encrypted.plaintext_size,
        "chunk_count": encrypted.chunk_count,
        "recipient_count": len(manifest.get("recipients", [])),
        "recipient_key_hashes": [r["recipient_key_hash"] for r in manifest.get("recipients", [])],
        "manifest_hash": manifest_hash(manifest),
        "storage_ref": manifest.get("storage_ref"),
        "raw_secret_egress": False,
    }


def seal_dataset(
    plaintext: bytes,
    *,
    dataset_id: str,
    task: str,
    data_sensitivity: DataSensitivity | str,
    recipient_public_keys: list[str],
    storage_ref: str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    provenance: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    """Envelope-encrypt a dataset for one or more attested CVM recipients.

    Returns `(ciphertext_blob, manifest, bounded_receipt)`. The DEK is generated,
    used, and dropped here; it never appears in the manifest or receipt. Optional
    `provenance` (see `build_provenance`) is committed into the manifest so a
    later owner/witness signature binds the distribution claim to this dataset.
    """

    if not recipient_public_keys:
        raise SealedDatasetError("at least one recipient public key is required")
    dek = generate_dek()
    encrypted = encrypt_dataset(plaintext, dek, dataset_id=dataset_id, chunk_size=chunk_size)
    recipients = [wrap_dek(dek, pk, dataset_id=dataset_id) for pk in recipient_public_keys]
    manifest = build_manifest(
        encrypted,
        task=task,
        data_sensitivity=DataSensitivity(data_sensitivity),
        recipients=recipients,
        storage_ref=storage_ref,
        provenance=provenance,
    )
    return encrypted.blob, manifest, seal_receipt(encrypted, manifest)


# Fields excluded from the canonical manifest hash: signatures are ABOUT the
# commitment, so they must not change it. The owner and every witness sign the
# same `manifest_hash`, which lets an M-of-N quorum co-sign a fixed commitment.
_SIGNATURE_FIELDS = {"owner_signature", "signer_hash", "witness_signatures"}


def _canonical(manifest: dict[str, Any]) -> str:
    egress_safe = {k: v for k, v in manifest.items() if k not in _SIGNATURE_FIELDS}
    return json.dumps(egress_safe, sort_keys=True, separators=(",", ":"))


def manifest_hash(manifest: dict[str, Any]) -> str:
    return _sha256_hex(_canonical(manifest).encode())


def sign_manifest(
    manifest: dict[str, Any],
    signer_private_key_hex: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Owner/reviewer-sign a sealed-dataset manifest; return signed manifest + receipt.

    The signature is an Ethereum signed-message over the canonical `manifest_hash`
    (which excludes `owner_signature`/`signer_hash`), so signing binds every other
    field — dataset id, hashes, chunking, recipients, sensitivity, storage ref.
    Sign last, after `storage_ref` is stamped: mutating a signed field would break
    the signature (`publish_dataset` already refuses to mutate a signed manifest).
    The receipt returns only hashes; never the private key, signer address, or raw
    signature.
    """

    from eth_account import Account
    from eth_account.messages import encode_defunct

    digest = manifest_hash(manifest)
    account = Account.from_key(signer_private_key_hex)
    signer = account.address
    signed = account.sign_message(encode_defunct(hexstr="0x" + digest))
    signature = "0x" + bytes(signed.signature).hex()
    signed_manifest = {
        **{k: v for k, v in manifest.items() if k not in {"owner_signature", "signer_hash"}},
        "signer_hash": _hash_prefixed(signer.lower(), prefix="dataset_signer"),
        "owner_signature": {
            "kind": "ethereum_signed_message",
            "signer": signer,
            "manifest_hash": "0x" + digest,
            "signature": signature,
        },
    }
    receipt = {
        "surface": "sign_dataset_manifest",
        "success": True,
        "dataset_id": manifest.get("dataset_id"),
        "manifest_hash": digest,
        "signer_hash": _hash_prefixed(signer.lower(), prefix="dataset_signer"),
        "signature_hash": _sha256_hex(signature.encode())[:48],
        "signature_returned": False,
        "signer_address_returned": False,
        "private_key_returned": False,
        "raw_secret_egress": False,
    }
    return signed_manifest, receipt


def _verify_owner_signature(
    manifest: dict[str, Any],
    expected_signer: str | None,
) -> tuple[bool | None, str | None, list[str]]:
    """Return `(verified, signer_hash, problems)` for the manifest owner signature."""

    from eth_account import Account
    from eth_account.messages import encode_defunct

    signature_block = manifest.get("owner_signature")
    if not signature_block:
        if expected_signer:
            return None, None, ["missing_owner_signature"]
        return None, None, []
    if not isinstance(signature_block, dict) or "signature" not in signature_block:
        return False, None, ["malformed_owner_signature"]
    digest = manifest_hash(manifest)
    declared_hash = str(signature_block.get("manifest_hash", "") or "").lower().removeprefix("0x")
    if declared_hash and declared_hash != digest:
        return False, None, ["owner_signature_hash_mismatch"]
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr="0x" + digest),
            signature=signature_block["signature"],
        )
    except Exception:
        return False, None, ["bad_owner_signature"]
    recovered_lower = recovered.lower()
    declared_signer = str(signature_block.get("signer", "")).lower()
    if declared_signer and recovered_lower != declared_signer:
        return False, None, ["owner_signer_mismatch"]
    if expected_signer and recovered_lower != expected_signer.lower():
        return False, None, ["unexpected_owner_signer"]
    return True, _hash_prefixed(recovered_lower, prefix="dataset_signer"), []


def add_witness_signature(
    manifest: dict[str, Any],
    witness_private_key_hex: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Co-sign a sealed-dataset commitment as a neutral witness; append to the quorum.

    A witness (notary) attests only that *this* commitment was sealed — it signs
    the canonical `manifest_hash` exactly like the owner, and never sees plaintext.
    Multiple witnesses each append to `witness_signatures`; because signatures are
    excluded from the canonical hash, every witness signs the same commitment and
    an M-of-N quorum can co-sign one fixed manifest. This defeats the
    "seller crafts data to favor one bidder" collusion: neither side can later
    dispute what entered the boundary. Returns the updated manifest + a bounded
    receipt (hashes only; never the key, address, or raw signature).
    """

    from eth_account import Account
    from eth_account.messages import encode_defunct

    digest = manifest_hash(manifest)
    account = Account.from_key(witness_private_key_hex)
    witness = account.address
    signed = account.sign_message(encode_defunct(hexstr="0x" + digest))
    signature = "0x" + bytes(signed.signature).hex()
    entry = {
        "kind": "ethereum_signed_message",
        "signer": witness,
        "manifest_hash": "0x" + digest,
        "signature": signature,
    }
    existing = list(manifest.get("witness_signatures", []))
    existing.append(entry)
    updated = {**manifest, "witness_signatures": existing}
    receipt = {
        "surface": "witness_sign_dataset_manifest",
        "success": True,
        "dataset_id": manifest.get("dataset_id"),
        "manifest_hash": digest,
        "witness_hash": _hash_prefixed(witness.lower(), prefix="dataset_witness"),
        "witness_count": len(existing),
        "signature_returned": False,
        "witness_address_returned": False,
        "private_key_returned": False,
        "raw_secret_egress": False,
    }
    return updated, receipt


def verify_witness_quorum(
    manifest: dict[str, Any],
    *,
    authorized_witnesses: "set[str] | list[str] | tuple[str, ...]",
    threshold: int,
) -> dict[str, Any]:
    """Verify an M-of-N neutral-witness quorum co-signed this commitment.

    Counts DISTINCT authorized witnesses whose signature over the canonical
    `manifest_hash` recovers correctly. A signature from an unknown address, a
    duplicate signer, or one over a different hash does not count. Fails closed
    (`threshold_met=False`) when fewer than `threshold` distinct authorized
    witnesses signed. Bounded receipt: witness *hashes* only, never addresses.
    """

    from eth_account import Account
    from eth_account.messages import encode_defunct

    authorized = {str(a).lower() for a in authorized_witnesses}
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise SealedDatasetError("threshold must be a positive int")

    digest = manifest_hash(manifest)
    signatures = manifest.get("witness_signatures", [])
    problems: list[str] = []
    valid_signers: set[str] = set()
    if not isinstance(signatures, list):
        problems.append("malformed_witness_signatures")
        signatures = []

    for entry in signatures:
        if not isinstance(entry, dict) or "signature" not in entry:
            problems.append("malformed_witness_entry")
            continue
        declared_hash = str(entry.get("manifest_hash", "") or "").lower().removeprefix("0x")
        if declared_hash and declared_hash != digest:
            problems.append("witness_hash_mismatch")
            continue
        try:
            recovered = Account.recover_message(
                encode_defunct(hexstr="0x" + digest),
                signature=entry["signature"],
            ).lower()
        except Exception:
            problems.append("bad_witness_signature")
            continue
        declared_signer = str(entry.get("signer", "")).lower()
        if declared_signer and recovered != declared_signer:
            problems.append("witness_signer_mismatch")
            continue
        if recovered not in authorized:
            problems.append("unauthorized_witness")
            continue
        valid_signers.add(recovered)

    valid_count = len(valid_signers)
    threshold_met = valid_count >= threshold
    return {
        "surface": "verify_witness_quorum",
        "ok": threshold_met,
        "valid_witness_count": valid_count,
        "authorized_witness_count": len(authorized),
        "threshold": threshold,
        "threshold_met": threshold_met,
        "witness_hashes": sorted(
            _hash_prefixed(signer, prefix="dataset_witness") for signer in valid_signers
        ),
        "problems": sorted(set(problems)),
        "raw_secret_egress": False,
    }


def verify_dataset_provenance(
    manifest: dict[str, Any],
    *,
    expected_signer: str | None = None,
    expected_benchmark: str | None = None,
) -> dict[str, Any]:
    """Verify signed, seal-time provenance is bound to this commitment.

    A distribution claim ("representative of benchmark X") is only trustworthy if
    it was committed at seal time and signed — not asserted afterward. This
    confirms the manifest carries a complete `provenance` block AND a valid owner
    signature over the canonical `manifest_hash` (which includes the provenance),
    so the claim is cryptographically bound to this exact dataset. When
    `expected_benchmark` is given, the provenance's `benchmark_ref` must match it.
    Fails closed on missing/incomplete provenance, an absent/invalid signature, or
    a benchmark mismatch. Bounded receipt (the claim string is public metadata;
    the signer is surfaced only as a hash).
    """

    problems: list[str] = []
    provenance = manifest.get("provenance")
    present = isinstance(provenance, dict)
    if not present:
        problems.append("missing_provenance")
    else:
        for key in _PROVENANCE_REQUIRED:
            if not str(provenance.get(key, "")).strip():
                problems.append("incomplete_provenance")
                break

    # A signature is REQUIRED — unsigned provenance is an unattested assertion.
    signature_verified, signer_hash, signature_problems = _verify_owner_signature(
        manifest, expected_signer
    )
    problems.extend(signature_problems)
    signed = signature_verified is True
    if not signed and "missing_owner_signature" not in signature_problems:
        # No signature block at all (owner-signature helper returns None silently
        # when neither a signature nor an expected_signer is present).
        if manifest.get("owner_signature") is None:
            problems.append("provenance_not_signed")

    benchmark_match: bool | None = None
    if present and expected_benchmark is not None:
        benchmark_match = str(provenance.get("benchmark_ref", "")) == str(expected_benchmark)
        if not benchmark_match:
            problems.append("benchmark_claim_mismatch")

    ok = not problems and signed
    if ok:
        reason_code = "dataset_provenance_verified"
    elif not present:
        reason_code = "missing_dataset_provenance"
    elif "incomplete_provenance" in problems:
        reason_code = "dataset_provenance_incomplete"
    elif "benchmark_claim_mismatch" in problems:
        reason_code = "dataset_benchmark_mismatch"
    elif not signed:
        reason_code = "dataset_provenance_unsigned"
    else:
        reason_code = "dataset_provenance_invalid"
    return {
        "surface": "verify_dataset_provenance",
        "ok": ok,
        "reason_code": reason_code,
        "provenance_present": present,
        "provenance_signed": signed,
        "benchmark_match": benchmark_match,
        "distribution_claim": str(provenance.get("distribution_claim", "")) if present else "",
        "benchmark_ref": str(provenance.get("benchmark_ref", "")) if present else "",
        "signer_hash": signer_hash,
        "manifest_hash": manifest_hash(manifest),
        "problems": sorted(set(problems)),
        "raw_secret_egress": False,
    }


def verify_manifest(
    manifest: dict[str, Any],
    *,
    blob: bytes | None = None,
    expected_signer: str | None = None,
) -> dict[str, Any]:
    """Verify manifest schema/integrity without any plaintext access.

    Checks schema version, sensitivity label, recipient envelope shape, and — if
    the ciphertext blob is supplied — that its sha256 matches. If the manifest
    carries an `owner_signature`, verifies the Ethereum signed-message over
    `manifest_hash`; when `expected_signer` is given, the signature is required
    and must recover to that address. Returns a bounded verification receipt.
    """

    problems: list[str] = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        problems.append("bad_schema_version")
    try:
        DataSensitivity(manifest.get("data_sensitivity"))
    except ValueError:
        problems.append("bad_data_sensitivity")
    recipients = manifest.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        problems.append("no_recipients")
    else:
        for r in recipients:
            if not all(k in r for k in ("recipient_key_hash", "ephemeral_public_key", "nonce", "ciphertext")):
                problems.append("malformed_recipient")
                break
    chunk = manifest.get("chunk", {})
    if not isinstance(chunk, dict) or "chunk_nonces" not in chunk:
        problems.append("missing_chunk_metadata")
    ciphertext_ok = None
    if blob is not None:
        ciphertext_ok = _sha256_hex(blob) == manifest.get("ciphertext_sha256")
        if not ciphertext_ok:
            problems.append("ciphertext_hash_mismatch")
    signature_verified, signer_hash, signature_problems = _verify_owner_signature(
        manifest, expected_signer
    )
    problems.extend(signature_problems)
    return {
        "ok": not problems,
        "problems": problems,
        "dataset_id": manifest.get("dataset_id"),
        "data_sensitivity": manifest.get("data_sensitivity"),
        "recipient_count": len(recipients) if isinstance(recipients, list) else 0,
        "manifest_hash": manifest_hash(manifest),
        "ciphertext_verified": ciphertext_ok,
        "owner_signature_present": bool(manifest.get("owner_signature")),
        "owner_signature_verified": signature_verified,
        "signer_hash": signer_hash,
        "raw_secret_egress": False,
    }
