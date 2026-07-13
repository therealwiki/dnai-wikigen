"""Reusable sealed-dataset loading for private-reward environments.

Any private-reward environment that sources its sealed data through the
envelope-encryption path (`seal_dataset` -> `publish_dataset` ->
`fetch_decrypt_dataset`) needs the same security-critical in-boundary flow:
fetch, verify the manifest, select the recipient envelope, unwrap the DEK,
AES-GCM decrypt, verify the plaintext hash, parse, and ZERO the plaintext buffer.
This module centralizes that flow so it is written and tested ONCE rather than
re-implemented per environment.

`load_sealed_env_dataset` is fail-closed: it returns `(None, receipt)` without
ever calling the env-specific parser if the plaintext hash is unverified, and it
always zeroes the decrypted buffer after the parser runs (even if the parser
raises). Only the parsed object and the bounded fetch receipt are returned; the
raw plaintext never escapes this function.
"""
from __future__ import annotations

import os
from typing import Any, Callable

from tinker_delegate.dataset_storage import StorageBackend, fetch_decrypt_dataset


def load_sealed_env_dataset(
    ref: str,
    recipient_private_key_hex: str,
    *,
    parse: Callable[[bytes], Any],
    backend: StorageBackend | None = None,
    local_root: str | os.PathLike[str] | None = None,
) -> tuple[Any | None, dict[str, Any]]:
    """Fetch + decrypt a sealed dataset in-boundary and parse it, fail-closed.

    Returns `(parsed_or_None, bounded_receipt)`. The env-specific `parse` callback
    turns the verified plaintext bytes into an environment-ready object; it is
    only ever called on plaintext whose sha256 has been verified. The decrypted
    buffer is zeroed after `parse` runs (even on parser error). On any manifest /
    envelope / decryption / hash failure, returns `(None, receipt)` without
    calling `parse`.
    """
    buffer, receipt = fetch_decrypt_dataset(
        ref, recipient_private_key_hex, backend=backend, local_root=local_root
    )
    if buffer is None or not receipt.get("plaintext_sha256_verified"):
        # Fail closed: never parse unverified plaintext.
        return None, receipt
    try:
        parsed = parse(bytes(buffer))
    finally:
        # Zero the decrypted plaintext buffer immediately after parsing.
        for i in range(len(buffer)):
            buffer[i] = 0
    return parsed, receipt
