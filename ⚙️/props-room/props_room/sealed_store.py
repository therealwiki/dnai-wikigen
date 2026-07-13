"""Generic sealed blob store for TEE-ingested assets."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class SealedAssetRecord:
    asset_id: str
    asset_type: str
    plaintext_sha256: str
    plaintext_bytes: int
    cipher_path: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "plaintext_sha256": self.plaintext_sha256,
            "plaintext_bytes": self.plaintext_bytes,
            "cipher_path": self.cipher_path,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SealedAssetRecord":
        return cls(
            asset_id=payload["asset_id"],
            asset_type=payload["asset_type"],
            plaintext_sha256=payload["plaintext_sha256"],
            plaintext_bytes=payload["plaintext_bytes"],
            cipher_path=payload["cipher_path"],
            metadata=payload.get("metadata", {}),
        )


class SealedBlobStore:
    """AES-256-GCM sealed store with a simple plaintext manifest."""

    def __init__(self, path: str | Path, dstack_enabled: bool = False, key_hex: str = ""):
        self.root = Path(path)
        self.assets_dir = self.root / "sealed"
        self.manifest_path = self.root / "manifest.json"
        self.key_path = self.root / "sealed.key"

        self.root.mkdir(parents=True, exist_ok=True)
        self.assets_dir.mkdir(parents=True, exist_ok=True)

        if dstack_enabled:
            self.key = self._derive_dstack_key()
        elif key_hex:
            self.key = bytes.fromhex(key_hex)
        elif self.key_path.exists():
            self.key = bytes.fromhex(self.key_path.read_text().strip())
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self.key_path.write_text(self.key.hex())

        self._aesgcm = AESGCM(self.key)
        self._manifest = self._load_manifest()

    def list_records(self) -> list[SealedAssetRecord]:
        return [self._manifest[key] for key in sorted(self._manifest)]

    def get_record(self, asset_id: str) -> SealedAssetRecord | None:
        return self._manifest.get(asset_id)

    def put_json(self, asset_id: str, payload: dict[str, Any], metadata: dict[str, Any]) -> SealedAssetRecord:
        blob = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        return self.put_bytes(asset_id, blob, asset_type="json", metadata=metadata)

    def put_bytes(
        self,
        asset_id: str,
        payload: bytes,
        *,
        asset_type: str,
        metadata: dict[str, Any],
    ) -> SealedAssetRecord:
        if asset_id in self._manifest:
            raise ValueError(f"Asset already exists: {asset_id}")

        sha256 = hashlib.sha256(payload).hexdigest()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, payload, None)
        cipher_path = self.assets_dir / f"{asset_id}.bin"
        cipher_path.write_bytes(nonce + ciphertext)

        record = SealedAssetRecord(
            asset_id=asset_id,
            asset_type=asset_type,
            plaintext_sha256=sha256,
            plaintext_bytes=len(payload),
            cipher_path=str(cipher_path),
            metadata=metadata,
        )
        self._manifest[asset_id] = record
        self._persist_manifest()
        return record

    def put_path(
        self,
        asset_id: str,
        source_path: str | Path,
        *,
        metadata: dict[str, Any],
    ) -> SealedAssetRecord:
        path = Path(source_path)
        if not path.exists():
            raise FileNotFoundError(str(path))
        if path.is_dir():
            blob = self._pack_directory(path)
            asset_type = "tar.gz"
        else:
            blob = path.read_bytes()
            asset_type = path.suffix.lstrip(".") or "file"
        merged_metadata = dict(metadata)
        merged_metadata["source_path"] = str(path)
        return self.put_bytes(asset_id, blob, asset_type=asset_type, metadata=merged_metadata)

    def delete(self, asset_id: str) -> bool:
        record = self._manifest.pop(asset_id, None)
        if record is None:
            return False
        cipher_path = Path(record.cipher_path)
        if cipher_path.exists():
            size = cipher_path.stat().st_size
            cipher_path.write_bytes(os.urandom(size))
            cipher_path.unlink()
        self._persist_manifest()
        return True

    @staticmethod
    def _derive_dstack_key() -> bytes:
        from dstack_sdk import DstackClient

        client = DstackClient()
        response = client.derive_key("props-room/assets")
        return bytes.fromhex(response.key[:64])

    @staticmethod
    def _pack_directory(path: Path) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(path, arcname=path.name)
        return buffer.getvalue()

    def _load_manifest(self) -> dict[str, SealedAssetRecord]:
        if not self.manifest_path.exists():
            return {}
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return {
            asset_id: SealedAssetRecord.from_dict(record)
            for asset_id, record in payload.items()
        }

    def _persist_manifest(self) -> None:
        payload = {
            asset_id: record.to_dict()
            for asset_id, record in self._manifest.items()
        }
        self.manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
