"""End-to-end demo: source the denoising env's data through the sealed-dataset
path so the sealed-data -> environment -> bounded-reward mechanism is exercised
as one flow.

The denoising cells are envelope-encrypted for an attested-CVM recipient
(`seal_dataset`), published to storage (`publish_dataset`), then fetched and
decrypted *inside the boundary* (`fetch_decrypt_dataset`: manifest verify ->
recipient-envelope select -> unwrap DEK -> AES-GCM decrypt -> plaintext-hash
verify). Only then is the `DenoisingHoldoutEnvironment` constructed over the
decrypted cells and run; the plaintext buffer is zeroed immediately after the
cells are parsed. Only bounded bands, hashes, and the bounded fetch receipt
egress — the raw count vectors never leave.

The dataset is labelled `public_benchmark` (it is OpenProblems-style synthetic
data), so this exercises the mechanism WITHOUT making a privacy claim: the same
path carries a `private` / `phi` dataset in production, where the recipient key
is dstack-derived and bound to an approved CVM measurement (the remaining
production work tracked in TODO, gated on cryptographic TDX quote parsing).
"""
from __future__ import annotations

import json
import tempfile
from typing import Any, Iterable

from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.dataset_storage import LocalStorageBackend, publish_dataset
from tinker_delegate.sealed_env_dataset import load_sealed_env_dataset
from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
)
from tinker_delegate.private_reward_envs.denoising_demo import (
    DEFAULT_DENOISERS,
    _build_demo_certificate,
    _demo_cells,
    _demo_policy,
)
from tinker_delegate.sealed_dataset import DataSensitivity, manifest_hash, seal_dataset

# Deterministic local/dev recipient key so the demo is reproducible. In
# production the recipient key is dstack-derived inside the CVM and never
# materialises here (see module docstring / TODO).
_DEMO_RECIPIENT_PRIVATE_KEY_HEX = "11" * 32
_DATASET_ID = "denoising-openproblems-demo"


def _serialize_cells(cells: list[SealedCell]) -> bytes:
    """Canonical JSON for the sealed dataset plaintext (counts stay sealed)."""
    payload = [
        {"cell_id": c.cell_id, "train": list(c.train), "test": list(c.test)}
        for c in cells
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_cells(plaintext: bytes) -> list[SealedCell]:
    payload = json.loads(plaintext.decode("utf-8"))
    return [SealedCell(r["cell_id"], r["train"], r["test"]) for r in payload]


def run_denoising_sealed_dataset_demo(
    denoisers: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Seal the denoising dataset, fetch+decrypt it in-boundary, then run the
    bounded reward loop over the decrypted cells. Returns bounded JSON."""

    requested = tuple(denoisers) if denoisers is not None else DEFAULT_DENOISERS

    keypair = TEEKeyPair.from_private_key_hex(_DEMO_RECIPIENT_PRIVATE_KEY_HEX)
    plaintext = _serialize_cells(_demo_cells())

    blob, manifest, _seal_receipt = seal_dataset(
        plaintext,
        dataset_id=_DATASET_ID,
        task="denoising",
        data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
        recipient_public_keys=[keypair.public_key_bytes.hex()],
    )

    with tempfile.TemporaryDirectory() as root:
        backend = LocalStorageBackend(root)
        # Exact refs are operational capabilities and remain in-boundary. The
        # public publish receipt exposes only a ref commitment.
        internal_ref = backend.ref_for(manifest["dataset_id"])
        publish_receipt = publish_dataset(blob, manifest, backend)
        # Reusable in-boundary flow: fetch -> verify -> decrypt -> parse -> zero,
        # fail-closed if the plaintext hash is unverified.
        cells, fetch_receipt = load_sealed_env_dataset(
            internal_ref,
            _DEMO_RECIPIENT_PRIVATE_KEY_HEX,
            parse=_parse_cells,
            backend=backend,
        )
        if cells is None:
            return {
                "demo": "denoising_sealed_dataset",
                "sealed_fetch_ok": False,
                "sealed_fetch_receipt": fetch_receipt,
                "raw_secret_egress": False,
            }

    env = DenoisingHoldoutEnvironment(cells, holdout_policy=_demo_policy())
    feedback = []
    for label, program in requested:
        bounded = env.evaluate(Candidate(program.encode("utf-8"))).to_public_dict()
        feedback.append({"candidate_label": label, **bounded})
    final_result = env.finalize().to_public_dict()

    from tinker_delegate.reward_transcript import RewardTranscript

    transcript = RewardTranscript.from_round_dicts(
        feedback,
        environment_hash=env.environment_hash,
        final_result_hash=final_result["transcript_hash"],
        transcript_chain_head=env.transcript_chain_head,
    )
    certificate = _build_demo_certificate(
        env, final_result, requested, transcript.commitment.commitment_hash
    )
    return {
        "demo": "denoising_sealed_dataset",
        "sealed_fetch_ok": True,
        # Bounded provenance: the env's data arrived via the sealed envelope path,
        # not from plaintext in code. No raw counts here.
        "sealed_dataset_provenance": {
            "dataset_id": fetch_receipt.get("dataset_id"),
            "data_sensitivity": fetch_receipt.get("data_sensitivity"),
            "backend_scheme": fetch_receipt.get("backend_scheme"),
            "manifest_ok": fetch_receipt.get("manifest_ok"),
            "plaintext_sha256_verified": fetch_receipt.get("plaintext_sha256_verified"),
            "recipient_key_hash": fetch_receipt.get("recipient_key_hash"),
            "publish_ciphertext_sha256": publish_receipt["ciphertext_sha256"],
            # The dataset commitment: a third party who holds the published
            # manifest can bind this run to it (verify_reward_dataset_binding).
            "manifest_hash": manifest_hash(manifest),
        },
        "optimizer_view": env.optimizer_view(),
        "feedback": feedback,
        "final_result": final_result,
        "attestation": env.attest().to_public_dict(),
        "reproducibility_certificate": certificate.to_public_dict(),
        "reward_transcript_commitment": transcript.certified_public_export(),
        "submitted_candidate_count": len(requested),
        "raw_secret_egress": False,
    }
