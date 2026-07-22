"""Pluggable storage backends for portable, TEE-sealed datasets.

The sealed-dataset crypto path (`sealed_dataset.py`) produces a ciphertext blob
plus an exact internal transport manifest; *where* those bytes live is a
separate concern. This adapter keeps publish/fetch of the opaque blob+manifest
strictly outside the crypto path so adding a backend never touches encryption.

Trust boundary: backends move only ciphertext and the internal manifest, which
carry no DEK or plaintext but do contain exact integrity metadata. A backend is
untrusted transport; integrity is re-established after fetch by
`sealed_dataset.verify_manifest` (ciphertext
hash) and, on decrypt, by the per-chunk GCM tags and the plaintext-hash check.
Backend credentials (HF/S3 tokens) come from the environment only and are never
placed in a ref, manifest, or receipt. Public receipts never return a raw ref:
local refs contain absolute paths and remote refs may identify private buckets
or carry capabilities. They expose only a domain-separated ref commitment.

A storage ref is `"<scheme>://<location>/<dataset_id>"`. The backend stores and
fetches two objects under that ref: `<ref-without-scheme>.blob` and
`.manifest.json`.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class StorageBackendError(RuntimeError):
    """Raised when a storage backend cannot publish or fetch safely."""


def _split_ref(ref: str) -> tuple[str, str, str]:
    """Return `(scheme, location, dataset_id)` from a `scheme://location/id` ref."""

    parts = urlsplit(ref)
    scheme = parts.scheme
    if not scheme:
        raise StorageBackendError("storage ref must be scheme://location/dataset_id")
    # urlsplit puts host in netloc for // refs; recombine netloc + path.
    body = (parts.netloc + parts.path) if parts.netloc else parts.path
    body = body.rstrip("/")
    if "/" not in body:
        raise StorageBackendError("storage ref must end with /dataset_id")
    location, dataset_id = body.rsplit("/", 1)
    if not dataset_id:
        raise StorageBackendError("storage ref must end with a non-empty dataset_id")
    return scheme, location, dataset_id


class StorageBackend(ABC):
    scheme: str = ""

    @abstractmethod
    def ref_for(self, dataset_id: str) -> str:
        """Return the storage ref this backend will use for `dataset_id`."""

    @abstractmethod
    def publish(self, dataset_id: str, blob: bytes, manifest: dict[str, Any]) -> str:
        """Store blob+manifest and return the storage ref that fetch() accepts."""

    @abstractmethod
    def fetch(self, ref: str) -> tuple[bytes, dict[str, Any]]:
        """Return `(blob, manifest)` for a previously published ref."""


def _validate_dataset_id(dataset_id: str) -> None:
    if "/" in dataset_id or dataset_id in {"", ".", ".."}:
        raise StorageBackendError("dataset_id must be a plain name, no path separators")


class LocalStorageBackend(StorageBackend):
    """Filesystem backend. Real; the default for local dev and tests."""

    scheme = "local"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root)

    def ref_for(self, dataset_id: str) -> str:
        _validate_dataset_id(dataset_id)
        return f"local://{self._root.resolve()}/{dataset_id}"

    def publish(self, dataset_id: str, blob: bytes, manifest: dict[str, Any]) -> str:
        _validate_dataset_id(dataset_id)
        self._root.mkdir(parents=True, exist_ok=True)
        base = self._root / dataset_id
        base.with_suffix(".blob").write_bytes(blob)
        base.with_suffix(".manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return self.ref_for(dataset_id)

    def fetch(self, ref: str) -> tuple[bytes, dict[str, Any]]:
        scheme, location, dataset_id = _split_ref(ref)
        if scheme != self.scheme:
            raise StorageBackendError(f"local backend cannot fetch scheme '{scheme}'")
        base = Path(location) / dataset_id
        blob_path = base.with_suffix(".blob")
        manifest_path = base.with_suffix(".manifest.json")
        if not blob_path.exists() or not manifest_path.exists():
            raise StorageBackendError("blob or manifest not found at ref")
        blob = blob_path.read_bytes()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return blob, manifest


class HttpsFetchBackend(StorageBackend):
    """Read-only https backend for datasets already hosted on a public URL.

    Publishing over plain https is not supported (there is no generic upload
    verb); use a credentialed backend for that. Fetch is real.
    """

    scheme = "https"

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def ref_for(self, dataset_id: str) -> str:
        raise StorageBackendError("https backend is read-only; publish is not supported")

    def publish(self, dataset_id: str, blob: bytes, manifest: dict[str, Any]) -> str:
        raise StorageBackendError("https backend is read-only; publish is not supported")

    def fetch(self, ref: str) -> tuple[bytes, dict[str, Any]]:
        import httpx  # local import: keeps module import cheap/offline

        scheme, location, dataset_id = _split_ref(ref)
        if scheme != self.scheme:
            raise StorageBackendError(f"https backend cannot fetch scheme '{scheme}'")
        base_url = f"https://{location}/{dataset_id}"
        with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
            blob_resp = client.get(f"{base_url}.blob")
            blob_resp.raise_for_status()
            manifest_resp = client.get(f"{base_url}.manifest.json")
            manifest_resp.raise_for_status()
        return blob_resp.content, manifest_resp.json()


class _UnconfiguredBackend(StorageBackend):
    """Fail-closed placeholder for backends whose adapter is not yet wired.

    HF Hub and S3 require credentialed clients (tokens from env only). Until a
    real adapter lands, both publish and fetch fail closed with clear guidance
    rather than silently succeeding or leaking a token requirement into a ref.
    """

    def __init__(self, scheme: str, env_hint: str) -> None:
        self.scheme = scheme
        self._env_hint = env_hint

    def _fail(self) -> str:
        raise StorageBackendError(
            f"storage backend '{self.scheme}' is not configured; adapter not implemented "
            f"(credentials come from {self._env_hint} only)"
        )

    def ref_for(self, dataset_id: str) -> str:
        return self._fail()

    def publish(self, dataset_id: str, blob: bytes, manifest: dict[str, Any]) -> str:
        raise StorageBackendError(
            f"storage backend '{self.scheme}' is not configured; adapter not implemented "
            f"(credentials come from {self._env_hint} only)"
        )

    def fetch(self, ref: str) -> tuple[bytes, dict[str, Any]]:
        raise StorageBackendError(
            f"storage backend '{self.scheme}' is not configured; adapter not implemented "
            f"(credentials come from {self._env_hint} only)"
        )


_UNCONFIGURED = {
    "hf": "HUGGINGFACE_HUB_TOKEN",
    "s3": "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
}


def resolve_backend(scheme: str, *, local_root: str | os.PathLike[str] | None = None) -> StorageBackend:
    """Return a backend for a scheme, without touching the crypto path.

    `local` requires `local_root`. `https` is fetch-only. `hf`/`s3` fail closed
    until a credentialed adapter is added.
    """

    scheme = scheme.lower()
    if scheme == "local":
        if local_root is None:
            raise StorageBackendError("local backend requires a root directory")
        return LocalStorageBackend(local_root)
    if scheme == "https":
        return HttpsFetchBackend()
    if scheme in _UNCONFIGURED:
        return _UnconfiguredBackend(scheme, _UNCONFIGURED[scheme])
    raise StorageBackendError(f"unknown storage backend scheme '{scheme}'")


def backend_for_ref(ref: str, *, local_root: str | os.PathLike[str] | None = None) -> StorageBackend:
    """Resolve the backend implied by a ref's scheme (for fetch)."""

    scheme, location, _dataset_id = _split_ref(ref)
    if scheme == "local" and local_root is None:
        # A local ref carries its own root; use it.
        return LocalStorageBackend(location)
    return resolve_backend(scheme, local_root=local_root)


# ---------------------------------------------------------------------------
# High-level publish / fetch-decrypt orchestration (bounded receipts only)
# ---------------------------------------------------------------------------


def publish_dataset(
    blob: bytes,
    manifest: dict[str, Any],
    backend: StorageBackend,
) -> dict[str, Any]:
    """Verify manifest binds the blob, publish both, return a public receipt.

    The stored manifest is stamped with the resolved `storage_ref`. A manifest
    that already carries an owner signature is refused (mutating a signed field
    would break the signature); re-seal or sign after publish instead.
    """

    from tinker_delegate.sealed_dataset import (
        manifest_hash,
        storage_ref_commitment,
        verify_manifest,
    )

    verification = verify_manifest(manifest, blob=blob)
    if not verification["ok"]:
        raise StorageBackendError(f"manifest failed verification: {verification['problems']}")
    dataset_id = manifest["dataset_id"]
    ref = backend.ref_for(dataset_id)
    if manifest.get("owner_signature"):
        # A signed manifest must be stored verbatim; mutating storage_ref would
        # break the signature. Require it to already carry the target ref.
        if manifest.get("storage_ref") != ref:
            raise StorageBackendError(
                "signed manifest storage_ref does not match target backend ref; "
                "set storage_ref before signing (or sign after publish)"
            )
        stamped = dict(manifest)
    else:
        stamped = dict(manifest)
        stamped["storage_ref"] = ref
    ref = backend.publish(dataset_id, blob, stamped)
    return {
        "surface": "publish_dataset",
        "ok": True,
        "dataset_id": dataset_id,
        "storage_ref_hash": storage_ref_commitment(ref),
        "storage_ref_returned": False,
        "backend_scheme": backend.scheme,
        "ciphertext_sha256": stamped["ciphertext_sha256"],
        "recipient_count": len(stamped.get("recipients", [])),
        "manifest_hash": manifest_hash(stamped),
        "raw_secret_egress": False,
    }


def fetch_decrypt_dataset(
    ref: str,
    recipient_private_key_hex: str,
    *,
    local_root: str | os.PathLike[str] | None = None,
    backend: StorageBackend | None = None,
) -> tuple[bytearray | None, dict[str, Any]]:
    """Fetch a sealed dataset, verify the manifest, and decrypt it in-boundary.

    Returns `(plaintext_buffer_or_None, bounded_receipt)`. Decryption fails
    closed to `decrypted=False` (no plaintext) on manifest failure, a missing
    recipient envelope, or any GCM/plaintext-hash mismatch. The caller is
    responsible for zeroing the returned buffer after use; on any failure the
    buffer is None.
    """

    from tinker_delegate.crypto import TEEKeyPair
    from tinker_delegate.sealed_dataset import (
        SealedDatasetError,
        bounded_plaintext_size_band,
        decrypt_dataset,
        recipient_key_hash,
        storage_ref_commitment,
        unwrap_dek,
        verify_manifest,
    )

    resolved = backend or backend_for_ref(ref, local_root=local_root)
    blob, manifest = resolved.fetch(ref)
    verification = verify_manifest(manifest, blob=blob)
    dataset_id = manifest.get("dataset_id")
    base_receipt = {
        "surface": "fetch_decrypt_dataset",
        "dataset_id": dataset_id,
        "storage_ref_hash": storage_ref_commitment(ref),
        "storage_ref_returned": False,
        "backend_scheme": resolved.scheme,
        "manifest_ok": verification["ok"],
        "manifest_problems": verification["problems"],
        "data_sensitivity": manifest.get("data_sensitivity"),
        "decrypted": False,
        "plaintext_sha256_verified": False,
        "raw_secret_egress": False,
    }
    if not verification["ok"]:
        base_receipt["reason"] = "manifest_verification_failed"
        return None, base_receipt

    keypair = TEEKeyPair.from_private_key_hex(recipient_private_key_hex)
    my_key_hash = recipient_key_hash(keypair.public_key_bytes.hex())
    base_receipt["recipient_key_hash"] = my_key_hash
    recipients = manifest.get("recipients", [])
    envelope = next(
        (r for r in recipients if r.get("recipient_key_hash") == my_key_hash),
        None,
    )
    if envelope is None:
        base_receipt["reason"] = "no_recipient_envelope_for_key"
        return None, base_receipt

    try:
        dek = unwrap_dek(envelope, keypair, dataset_id=dataset_id)
        plaintext = decrypt_dataset(
            blob,
            dek,
            dataset_id=dataset_id,
            chunk_nonces=manifest["chunk"]["chunk_nonces"],
            expected_plaintext_sha256=manifest.get("plaintext_sha256"),
        )
    except (SealedDatasetError, KeyError, ValueError):
        base_receipt["reason"] = "decrypt_failed"
        return None, base_receipt
    finally:
        # Best-effort scrub of the DEK material from this frame.
        dek = b"\x00" * 32  # noqa: F841

    base_receipt["decrypted"] = True
    base_receipt["plaintext_sha256_verified"] = True
    base_receipt["plaintext_size_band"] = bounded_plaintext_size_band(len(plaintext))
    return plaintext, base_receipt
