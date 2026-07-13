"""Proof-carrying reward transcripts.

A private-reward run already emits a flat ``loop_transcript_hash`` over its
bounded per-round records. That proves the transcript as a whole was not altered,
but it cannot show an auditor that *one specific round* (a candidate hash → reward
band) belongs to the attested run without revealing every other round.

This module commits the per-round bounded records into a Merkle tree and binds
that root to the rest of the verification chain — environment hash, final result
hash, TDX quote, and (optionally) the settling chain event — as one
``RewardTranscriptCommitment``. Given the commitment plus a single
``RewardInclusionProof``, an auditor can verify that a round is in the run and
*which* run it is, while the other rounds and all raw values stay sealed.

Everything here is hashes and counts: the public dicts pass
``assert_bounded_egress``. Leaf and node hashing are domain-separated (``0x00`` /
``0x01`` prefixes) to prevent second-preimage confusion between a leaf and an
internal node.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from tinker_delegate.private_reward import assert_bounded_egress

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
# Domain-separated root for a transcript with no rounds.
_EMPTY_ROOT = hashlib.sha256(b"dnai-reward-transcript:empty").hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(round_public: dict[str, Any]) -> str:
    """Hash one bounded round record into a domain-separated Merkle leaf."""

    return _sha256_hex(_LEAF_PREFIX + _canonical(round_public))


def _node_hash(left_hex: str, right_hex: str) -> str:
    return _sha256_hex(_NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def merkle_root(leaf_hashes: list[str]) -> str:
    """Merkle root over pre-hashed leaves; odd levels duplicate the last node.

    SECURITY: duplicating the last node makes this root NOT collision-free across
    leaf lists of *different* lengths — e.g. ``[A, B, C]`` and ``[A, B, C, C]``
    produce the identical root (the classic CVE-2012-2459 malleability). Two lists
    of the *same* length cannot collide without a SHA-256 collision. Therefore any
    commitment over a variable-length leaf list MUST also bind the leaf count and a
    verifier MUST check it: `RewardTranscriptCommitment` binds `round_count` into
    `commitment_hash` and `run_verification.verify_reward_run` rejects any packet
    whose `feedback` length differs from the committed `round_count`, which is the
    load-bearing mitigation for this malleability (pinned by
    `tests/test_run_verification.py::...merkle_malleated...`). Do not use this root
    for a length-variable commitment without that count binding.
    """

    if not leaf_hashes:
        return _EMPTY_ROOT
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaf_hashes: list[str], index: int) -> tuple[tuple[str, str], ...]:
    """Audit path for ``index``: ``(sibling_hex, side)`` where side is the sibling's.

    ``side == "L"`` means the sibling is on the left (concatenate sibling+node);
    ``"R"`` means it is on the right (node+sibling). Rebuilding with these rules
    reproduces the root iff the leaf is genuinely at ``index``.
    """

    if not 0 <= index < len(leaf_hashes):
        raise IndexError("round index out of range for transcript")
    path: list[tuple[str, str]] = []
    level = list(leaf_hashes)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            path.append((level[idx + 1], "R"))
        else:
            path.append((level[idx - 1], "L"))
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return tuple(path)


def _root_from_path(leaf_hex: str, audit_path: tuple[tuple[str, str], ...]) -> str:
    node = leaf_hex
    for sibling_hex, side in audit_path:
        if side == "L":
            node = _node_hash(sibling_hex, node)
        elif side == "R":
            node = _node_hash(node, sibling_hex)
        else:  # pragma: no cover - guarded by construction
            raise ValueError("invalid audit-path side")
    return node


@dataclass(frozen=True)
class RewardInclusionProof:
    """Proof that one round's bounded record is committed under a transcript root."""

    round_index: int
    leaf_hash: str
    audit_path: tuple[tuple[str, str], ...]
    transcript_root: str

    def verify(self) -> bool:
        try:
            return _root_from_path(self.leaf_hash, self.audit_path) == self.transcript_root
        except ValueError:  # bad hex in leaf/sibling, or invalid side
            return False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "reward_inclusion_proof",
            "round_index": self.round_index,
            "leaf_hash": self.leaf_hash,
            "audit_path": [[sibling, side] for sibling, side in self.audit_path],
            "transcript_root": self.transcript_root,
            "raw_secret_egress": False,
        }


@dataclass(frozen=True)
class RewardTranscriptCommitment:
    """One bounded commitment binding the transcript root into the trust chain."""

    environment_hash: str
    transcript_root: str
    round_count: int
    final_result_hash: str
    quote_hash: str
    chain_event_hash: str = ""
    # Head of the environment's append-only query hash chain (transcript_log),
    # when the run's environment exposes one. Binds the env-side tamper-evident
    # query log into the same commitment as the per-round Merkle root.
    transcript_chain_head: str = ""

    @property
    def commitment_hash(self) -> str:
        return _sha256_hex(
            _canonical(
                {
                    "environment_hash": self.environment_hash,
                    "transcript_root": self.transcript_root,
                    "round_count": self.round_count,
                    "final_result_hash": self.final_result_hash,
                    "quote_hash": self.quote_hash,
                    "chain_event_hash": self.chain_event_hash,
                    "transcript_chain_head": self.transcript_chain_head,
                }
            )
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "reward_transcript_commitment",
            "environment_hash": self.environment_hash,
            "transcript_root": self.transcript_root,
            "round_count": self.round_count,
            "final_result_hash": self.final_result_hash,
            "quote_hash": self.quote_hash,
            "chain_event_hash": self.chain_event_hash,
            "transcript_chain_head": self.transcript_chain_head,
            "commitment_hash": self.commitment_hash,
            "raw_secret_egress": False,
        }

    @classmethod
    def from_public_dict(cls, data: dict[str, Any]) -> "RewardTranscriptCommitment":
        """Reconstruct a commitment from its bounded public dict (for verification).

        The reconstructed object recomputes ``commitment_hash`` from the bound
        fields, so a verifier can compare it against the published hash to detect
        tampering.
        """

        return cls(
            environment_hash=str(data.get("environment_hash", "")),
            transcript_root=str(data.get("transcript_root", "")),
            round_count=int(data.get("round_count", 0)),
            final_result_hash=str(data.get("final_result_hash", "")),
            quote_hash=str(data.get("quote_hash", "")),
            chain_event_hash=str(data.get("chain_event_hash", "")),
            transcript_chain_head=str(data.get("transcript_chain_head", "")),
        )


class RewardTranscript:
    """A built Merkle transcript: keep the leaves to generate inclusion proofs."""

    def __init__(self, leaf_hashes: list[str], commitment: RewardTranscriptCommitment) -> None:
        self._leaf_hashes = list(leaf_hashes)
        self._commitment = commitment

    @property
    def commitment(self) -> RewardTranscriptCommitment:
        return self._commitment

    @property
    def round_count(self) -> int:
        return len(self._leaf_hashes)

    def prove(self, round_index: int) -> RewardInclusionProof:
        path = merkle_proof(self._leaf_hashes, round_index)
        return RewardInclusionProof(
            round_index=round_index,
            leaf_hash=self._leaf_hashes[round_index],
            audit_path=path,
            transcript_root=self._commitment.transcript_root,
        )

    @classmethod
    def from_round_dicts(
        cls,
        round_dicts: list[dict[str, Any]],
        *,
        environment_hash: str,
        final_result_hash: str,
        quote: bytes = b"",
        chain_event: dict[str, Any] | None = None,
        transcript_chain_head: str = "",
    ) -> "RewardTranscript":
        """Build a transcript from an ordered list of bounded per-round dicts.

        Use this for evaluators that run their own loop (e.g. a program-library
        sweep) instead of ``run_private_reward_loop``. Each dict must already be
        bounded (hashes/bands/counts — no raw payloads or reward values).
        ``transcript_chain_head`` optionally binds the environment's append-only
        query chain head into the commitment.
        """

        leaf_hashes = [leaf_hash(record) for record in round_dicts]
        commitment = RewardTranscriptCommitment(
            environment_hash=str(environment_hash),
            transcript_root=merkle_root(leaf_hashes),
            round_count=len(leaf_hashes),
            final_result_hash=str(final_result_hash),
            quote_hash=_sha256_hex(quote) if quote else "",
            chain_event_hash=_sha256_hex(_canonical(chain_event)) if chain_event else "",
            transcript_chain_head=str(transcript_chain_head or ""),
        )
        return cls(leaf_hashes, commitment)

    @classmethod
    def build(
        cls,
        outcome: Any,
        *,
        environment_hash: str,
        quote: bytes = b"",
        chain_event: dict[str, Any] | None = None,
        transcript_chain_head: str = "",
    ) -> "RewardTranscript":
        """Build a transcript from a bounded ``LoopOutcome``.

        Leaves are the per-round ``to_public_dict`` records; the commitment binds
        the root to the environment hash, the loop's own final result hash, the
        TDX quote, an optional bounded chain event, and the environment's
        append-only query chain head when supplied.
        """

        rounds = getattr(outcome, "rounds", ())
        final_result_hash = getattr(outcome, "loop_transcript_hash", "") or getattr(
            outcome, "transcript_hash", ""
        )
        return cls.from_round_dicts(
            [record.to_public_dict() for record in rounds],
            environment_hash=environment_hash,
            final_result_hash=final_result_hash,
            quote=quote,
            chain_event=chain_event,
            transcript_chain_head=transcript_chain_head,
        )

    def certified_public_export(self) -> dict[str, Any]:
        """Bounded, egress-checked commitment dict for publication."""

        payload = self._commitment.to_public_dict()
        assert_bounded_egress(payload)
        return payload


def verify_round_in_commitment(
    proof: RewardInclusionProof,
    commitment: RewardTranscriptCommitment,
) -> bool:
    """True iff the proof is internally valid and matches the commitment's root."""

    return proof.transcript_root == commitment.transcript_root and proof.verify()
