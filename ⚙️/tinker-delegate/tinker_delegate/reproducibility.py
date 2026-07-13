"""Bounded reproducibility certificates for private-reward / RLVR runs.

A reproducibility certificate binds the inputs and outputs of a sealed-data
evaluation into one recomputable commitment, treating attestation + code + data +
config + result as a single verification chain (a core PROJECT.md invariant).
Everything is a hash or a coarse public identifier — raw hyperparameters, seeds,
sealed data, and reward values never appear, so the certificate itself is a
bounded output. Hyperparameter floats and seeds feed only into ``run_config_hash``
(a digest), never the emitted certificate.

Fields (all bounded):
* ``run_config_hash`` — digest of optimizer, model base, hyperparameters, seeds,
  round budget, and target band.
* ``data_commitment`` — the environment's public data commitment (e.g. its
  ``environment_hash`` / holdout split commitment); the sealed data stays sealed.
* ``code_hash`` — digest of the candidate-space / evaluator code identity.
* ``model_base`` — coarse public model identifier (e.g. ``none``, ``Qwen/Qwen3-8B``).
* ``result_hash`` — the run's bounded result / loop transcript hash.
* ``attestation_quote_hash`` — optional TEE quote hash tying the run to a CVM.
* ``certificate_hash`` — digest over all of the above; anyone can recompute it to
  verify the certificate was not altered.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from tinker_delegate.private_reward import assert_bounded_egress

_ZERO32 = "0x" + "00" * 32


@dataclass(frozen=True)
class RunConfig:
    """Inputs that define a reproducible run. Hashed, never emitted raw."""

    optimizer_name: str
    model_base: str = "none"
    hyperparameters: Mapping[str, Any] = field(default_factory=dict)
    random_seeds: tuple[int, ...] = ()
    max_rounds: int = 0
    target_band: str = ""

    def config_hash(self) -> str:
        return _sha256_json(
            {
                "optimizer_name": self.optimizer_name,
                "model_base": self.model_base,
                "hyperparameters": _stable(self.hyperparameters),
                "random_seeds": list(self.random_seeds),
                "max_rounds": self.max_rounds,
                "target_band": self.target_band,
            }
        )


@dataclass(frozen=True)
class ReproducibilityCertificate:
    run_config_hash: str
    data_commitment: str
    code_hash: str
    model_base: str
    result_hash: str
    attestation_quote_hash: str
    certificate_hash: str
    raw_secret_egress: bool = False
    # Optional binding to the run's proof-carrying reward transcript commitment
    # (Merkle root + env chain head), so one certificate hash covers config,
    # data, code, result, quote, AND the per-round transcript. "" when absent.
    transcript_commitment_hash: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "reproducibility_certificate",
            "run_config_hash": self.run_config_hash,
            "data_commitment": self.data_commitment,
            "code_hash": self.code_hash,
            "model_base": self.model_base,
            "result_hash": self.result_hash,
            "attestation_quote_hash": self.attestation_quote_hash,
            "transcript_commitment_hash": self.transcript_commitment_hash,
            "certificate_hash": self.certificate_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def hash_code_identity(*parts: str) -> str:
    """Digest a code identity (module/class names, methodology class, version)."""
    return _sha256_json({"code_identity": [str(p) for p in parts]})


def hash_source_files(*targets: Any) -> str:
    """Digest the actual source bytes of the reward/evaluator code.

    Each target is a module object (its ``__file__`` is read) or a filesystem
    path. This ties the certificate to the concrete implementation that computed
    the reward — a real code hash that changes iff the code changes. Deterministic
    for a given tree, so it stays replayable inside a TEE.
    """
    import os

    digests: list[list[str]] = []
    for target in targets:
        path = getattr(target, "__file__", None) or str(target)
        with open(path, "rb") as handle:
            body = handle.read()
        digests.append([os.path.basename(path), hashlib.sha256(body).hexdigest()])
    digests.sort()
    return _sha256_json({"source_files": digests})


def build_reproducibility_certificate(
    *,
    run_config: RunConfig,
    data_commitment: str,
    code_hash: str,
    result_hash: str,
    attestation_quote_hash: str = "",
    transcript_commitment_hash: str = "",
) -> ReproducibilityCertificate:
    """Build a bounded, recomputable reproducibility certificate."""
    run_config_hash = run_config.config_hash()
    quote_hash = attestation_quote_hash or _ZERO32
    transcript_hash = str(transcript_commitment_hash or "")
    certificate_hash = _certificate_hash(
        run_config_hash=run_config_hash,
        data_commitment=data_commitment,
        code_hash=code_hash,
        model_base=run_config.model_base,
        result_hash=result_hash,
        attestation_quote_hash=quote_hash,
        transcript_commitment_hash=transcript_hash,
    )
    certificate = ReproducibilityCertificate(
        run_config_hash=run_config_hash,
        data_commitment=str(data_commitment),
        code_hash=str(code_hash),
        model_base=run_config.model_base,
        result_hash=str(result_hash),
        attestation_quote_hash=quote_hash,
        transcript_commitment_hash=transcript_hash,
        certificate_hash=certificate_hash,
    )
    # A certificate is a bounded output; enforce it like any other egress.
    assert_bounded_egress(certificate.to_public_dict())
    return certificate


def certify_loop_run(
    outcome: Any,
    *,
    run_config: RunConfig,
    environment: Any,
    code_hash: str,
    attestation_quote_hash: str = "",
    bind_transcript: bool = True,
) -> ReproducibilityCertificate:
    """Certify a ``run_private_reward_loop`` outcome against its environment.

    Uses the environment's public ``environment_hash`` as the data commitment and
    the loop's ``loop_transcript_hash`` as the result hash. When ``bind_transcript``
    is set (default), the run's proof-carrying reward-transcript commitment
    (per-round Merkle root + the environment's append-only query-chain head) is
    built and its ``commitment_hash`` is bound into the certificate, unifying both
    verification artifacts under one certificate hash.
    """
    data_commitment = environment.environment_hash
    result_hash = getattr(outcome, "loop_transcript_hash", "") or getattr(
        outcome, "transcript_hash", ""
    )
    transcript_commitment_hash = ""
    if bind_transcript:
        from tinker_delegate.reward_transcript import RewardTranscript

        transcript = RewardTranscript.build(
            outcome,
            environment_hash=data_commitment,
            transcript_chain_head=getattr(environment, "transcript_chain_head", ""),
        )
        transcript_commitment_hash = transcript.commitment.commitment_hash
    return build_reproducibility_certificate(
        run_config=run_config,
        data_commitment=data_commitment,
        code_hash=code_hash,
        result_hash=result_hash,
        attestation_quote_hash=attestation_quote_hash,
        transcript_commitment_hash=transcript_commitment_hash,
    )


def verify_reproducibility_certificate(certificate: ReproducibilityCertificate) -> bool:
    """Recompute the binding hash and check the certificate was not altered."""
    expected = _certificate_hash(
        run_config_hash=certificate.run_config_hash,
        data_commitment=certificate.data_commitment,
        code_hash=certificate.code_hash,
        model_base=certificate.model_base,
        result_hash=certificate.result_hash,
        attestation_quote_hash=certificate.attestation_quote_hash,
        transcript_commitment_hash=certificate.transcript_commitment_hash,
    )
    return expected == certificate.certificate_hash


def _certificate_hash(
    *,
    run_config_hash: str,
    data_commitment: str,
    code_hash: str,
    model_base: str,
    result_hash: str,
    attestation_quote_hash: str,
    transcript_commitment_hash: str = "",
) -> str:
    return _sha256_json(
        {
            "run_config_hash": run_config_hash,
            "data_commitment": data_commitment,
            "code_hash": code_hash,
            "model_base": model_base,
            "result_hash": result_hash,
            "attestation_quote_hash": attestation_quote_hash,
            "transcript_commitment_hash": transcript_commitment_hash,
        }
    )


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(_stable(value), sort_keys=True, separators=(",", ":"))
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
