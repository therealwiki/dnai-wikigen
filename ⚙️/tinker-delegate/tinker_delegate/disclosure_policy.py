"""Final-solution disclosure policy.

When a private-reward run finishes, the winning candidate (code / solution) may be
valuable to publish — but candidate code may be made public only if it cannot
reconstruct the sealed private data and passes the biosecurity and
re-identification screens. Otherwise the system releases strictly less: an
escrowed artifact (sealed, released only under separate authorization), or just a
hash plus score band.

``decide_disclosure`` folds four fail-closed signals into one bounded
``DisclosureDecision`` and the code path enforces it: ``disclosable_payload``
returns the raw candidate bytes only when the mode is ``PUBLIC``.

Severity ladder (most restrictive wins):
    BLOCKED  > HASH_ONLY > ESCROW > PUBLIC
    dual-use   reconstruct  no public   all screens clear
    prohibited or re-id HIGH  permission  + caller allows public
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from tinker_delegate.bio_dual_use import DualUseAssessment
from tinker_delegate.bio_reid import ReidAssessment, ReidRiskBand
from tinker_delegate.redaction import redact_text
from tinker_delegate.run_metadata_store import stable_hash

# A contiguous run of base64/hex-ish characters this long inside candidate code
# is treated as a possible embedded raw-data blob (a reconstruction vector).
_BLOB_RUN = re.compile(r"[A-Za-z0-9+/=]{64,}")


class DisclosureMode(str, Enum):
    PUBLIC = "public"        # full candidate bytes may be released
    ESCROW = "escrow"        # sealed; released only under separate authorization
    HASH_ONLY = "hash_only"  # only candidate hash + score band leave
    BLOCKED = "blocked"      # dual-use prohibited; band + hash only, route to review


_RANK: dict[DisclosureMode, int] = {
    DisclosureMode.PUBLIC: 0,
    DisclosureMode.ESCROW: 1,
    DisclosureMode.HASH_ONLY: 2,
    DisclosureMode.BLOCKED: 3,
}
_BY_RANK = {rank: mode for mode, rank in _RANK.items()}


@dataclass(frozen=True)
class DisclosureDecision:
    mode: DisclosureMode
    reasons: tuple[str, ...]
    candidate_hash: str
    score_band: str

    @property
    def is_public(self) -> bool:
        return self.mode == DisclosureMode.PUBLIC

    def disclosable_payload(self, candidate: bytes) -> bytes | None:
        """Return the raw candidate bytes only if the decision permits it."""

        return bytes(candidate) if self.is_public else None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "disclosure_decision",
            "mode": self.mode.value,
            "reasons": list(self.reasons),
            "candidate_hash": self.candidate_hash,
            "score_band": self.score_band,
            "raw_secret_egress": False,
        }


def _reconstruction_reasons(candidate: bytes) -> list[str]:
    reasons: list[str] = []
    try:
        text = candidate.decode("utf-8")
    except UnicodeDecodeError:
        # Non-text candidate cannot be reviewed as source; never publish it.
        return ["non_text_candidate"]
    if redact_text(text) != text:
        reasons.append("secret_shaped_material")
    if _BLOB_RUN.search(text):
        reasons.append("embedded_raw_data")
    return reasons


def decide_disclosure(
    candidate: bytes,
    *,
    dual_use: DualUseAssessment | None = None,
    reid: ReidAssessment | None = None,
    allow_public: bool = False,
    score_band: str = "withheld",
) -> DisclosureDecision:
    """Decide how a winning candidate may be disclosed (fail-closed).

    ``allow_public`` is the caller's explicit permission to publish; without it
    the best case is ESCROW (sealed, releasable later). Each risk signal raises
    the required restriction; the most restrictive wins.
    """

    reasons: list[str] = []
    # Base posture: sealed escrow unless the caller explicitly permits public.
    required_rank = _RANK[DisclosureMode.PUBLIC if allow_public else DisclosureMode.ESCROW]
    if not allow_public:
        reasons.append("no_public_permission")

    # Reconstruction screen: candidate code must not embed/echo sealed data.
    recon = _reconstruction_reasons(candidate)
    if recon:
        reasons.extend(recon)
        required_rank = max(required_rank, _RANK[DisclosureMode.HASH_ONLY])

    # Re-identification screen.
    if reid is not None:
        band = getattr(reid, "risk_band", ReidRiskBand.WITHHELD)
        if band == ReidRiskBand.HIGH:
            reasons.append("reid_high")
            required_rank = max(required_rank, _RANK[DisclosureMode.HASH_ONLY])
        elif band == ReidRiskBand.MEDIUM:
            reasons.append("reid_medium")
            required_rank = max(required_rank, _RANK[DisclosureMode.ESCROW])
        elif band == ReidRiskBand.WITHHELD:
            reasons.append("reid_withheld")
            required_rank = max(required_rank, _RANK[DisclosureMode.ESCROW])

    # Biosecurity / dual-use screen (can force the strictest outcome).
    if dual_use is None:
        # Unknown dual-use status cannot clear a public release; cap at escrow.
        reasons.append("dual_use_unknown")
        required_rank = max(required_rank, _RANK[DisclosureMode.ESCROW])
    elif dual_use.denies_release:
        reasons.append("dual_use_prohibited")
        required_rank = max(required_rank, _RANK[DisclosureMode.BLOCKED])
    elif dual_use.blocks_release:
        reasons.append("dual_use_review")
        required_rank = max(required_rank, _RANK[DisclosureMode.ESCROW])

    return DisclosureDecision(
        mode=_BY_RANK[required_rank],
        reasons=tuple(sorted(set(reasons))),
        candidate_hash=stable_hash(candidate, prefix="disclosure_candidate"),
        score_band=str(score_band),
    )
