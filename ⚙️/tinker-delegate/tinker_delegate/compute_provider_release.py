"""Immutable public inputs for the production Tinker Compute provider.

This module intentionally has no third-party imports so the Docker build can
authenticate the tokenizer bundle before installing or starting any runtime
service.  The three tokenizer files are fetched from one immutable model
revision and are accepted only at their exact byte lengths and SHA-256 hashes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


PROVIDER_ADAPTER_ID = "tinker_sdk_0_22_7_at_most_once_v1"
PINNED_TINKER_SDK_VERSION = "0.22.7"
PINNED_TINKER_SDK_SOURCE_SHA256 = (
    "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62"
)
PINNED_TINKER_REQUEST_CONTRACT_SHA256 = (
    "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d"
)
PINNED_TINKER_BASE_URL = "https://tinker.thinkingmachines.dev/services/tinker-prod"
PINNED_TINKER_BASE_URL_SHA256 = "sha256:" + hashlib.sha256(
    PINNED_TINKER_BASE_URL.encode("ascii")
).hexdigest()

PINNED_QWEN3_TOKENIZER_MODEL = "Qwen/Qwen3-8B"
PINNED_QWEN3_TOKENIZER_REVISION = "b968826d9c46dd6066d109eabc6255188de91218"
PINNED_QWEN3_TOKENIZER_PATH = "/opt/dnai/qwen3-8b-tokenizer"


@dataclass(frozen=True)
class PinnedTokenizerFile:
    path: str
    bytes: int
    sha256: str

    def to_manifest_entry(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


PINNED_QWEN3_TOKENIZER_FILES = (
    PinnedTokenizerFile(
        path="config.json",
        bytes=728,
        sha256="f7c4eadfbbf522470667b797a3c89be2524832d2d599797248dc304fff447c30",
    ),
    PinnedTokenizerFile(
        path="tokenizer.json",
        bytes=11_422_654,
        sha256="aeb13307a71acd8fe81861d94ad54ab689df773318809eed3cbe794b4492dae4",
    ),
    PinnedTokenizerFile(
        path="tokenizer_config.json",
        bytes=9_732,
        sha256="d5d09f07b48c3086c508b30d1c9114bd1189145b74e982a265350c923acd8101",
    ),
)


def pinned_qwen3_tokenizer_manifest() -> dict[str, object]:
    return {
        "schema": "dnai.compute.qwen3-8b-tokenizer-release.v1",
        "files": [item.to_manifest_entry() for item in PINNED_QWEN3_TOKENIZER_FILES],
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


PINNED_QWEN3_TOKENIZER_RELEASE_SHA256 = "sha256:" + hashlib.sha256(
    _canonical_json(pinned_qwen3_tokenizer_manifest())
).hexdigest()


def pinned_tinker_provider_release_manifest() -> dict[str, object]:
    """Return the immutable, non-secret provider adapter release contract.

    This digest identifies the exact SDK source, request grammar, endpoint
    commitment, offline tokenizer bundle, and crash semantics used by the
    Compute worker. It deliberately contains no API key, provider project ID,
    account identifier, mutable URL, or execution claim.
    """

    return {
        "schema": "dnai.compute.tinker-provider-release.v1",
        "adapter_id": PROVIDER_ADAPTER_ID,
        "sdk_version": PINNED_TINKER_SDK_VERSION,
        "sdk_source_sha256": PINNED_TINKER_SDK_SOURCE_SHA256,
        "request_contract_sha256": PINNED_TINKER_REQUEST_CONTRACT_SHA256,
        "base_url_sha256": PINNED_TINKER_BASE_URL_SHA256,
        "tokenizer_path": PINNED_QWEN3_TOKENIZER_PATH,
        "tokenizer_release_sha256": PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
        "idempotency_header_role": "request_commitment_only",
        "idempotent_provider_replay_claimed": False,
        "automatic_provider_redispatch": False,
        "at_most_once_attempt_checkpoint": True,
        "terminal_ambiguity_hold": True,
        "ambiguous_outcome_ciphertext_retained": True,
        "provider_authoritative_invoice": False,
        "raw_secret_egress": False,
    }


PINNED_TINKER_PROVIDER_RELEASE_SHA256 = "sha256:" + hashlib.sha256(
    _canonical_json(pinned_tinker_provider_release_manifest())
).hexdigest()

if (
    PINNED_QWEN3_TOKENIZER_RELEASE_SHA256
    != "sha256:d933156af48aa90a117025537b4291c2e72b62ad14ddcfa7d77f3258928cd2e0"
):  # pragma: no cover - import-time supply-chain invariant
    raise RuntimeError("pinned Qwen3 tokenizer manifest digest drifted")

if (
    PINNED_TINKER_BASE_URL_SHA256
    != "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533"
):  # pragma: no cover - import-time supply-chain invariant
    raise RuntimeError("pinned Tinker base URL digest drifted")

if (
    PINNED_TINKER_PROVIDER_RELEASE_SHA256
    != "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631"
):  # pragma: no cover - import-time supply-chain invariant
    raise RuntimeError("pinned Tinker provider release digest drifted")
