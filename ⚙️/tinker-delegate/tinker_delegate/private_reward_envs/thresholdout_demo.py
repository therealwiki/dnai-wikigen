"""End-to-end Thresholdout demo: DP-noised reusable-holdout access over a stream.

Runs a scripted stream of candidates through a `ThresholdoutGate` composed with a
real `DpAccountant`, showing the mechanism's two paths — a candidate that tracks
the reward-partition statistic is answered for FREE (no DP budget), while a
diverging candidate consults the fresh holdout and spends budget — until the
`total leakage ≤ ε × holdout-accesses` budget is exhausted and the gate fails
closed. Only bounded band indices + counts + public DP config leave; no un-noised
statistic egresses.

The demo uses deterministic (zero) noise for a reproducible packet; production
draws Laplace noise from `os.urandom`.
"""
from __future__ import annotations

from typing import Any

from tinker_delegate.dp_accounting import DpAccountant, PrivacyMode
from tinker_delegate.private_reward import assert_bounded_egress
from tinker_delegate.thresholdout import ThresholdoutGate, ThresholdoutPolicy

# (reward_partition_stat, fresh_holdout_stat) per candidate, in [0, 1]. The first
# three track (small gap → free); the rest diverge (large gap → spend budget).
_DEMO_STREAM: tuple[tuple[float, float], ...] = (
    (0.60, 0.58),
    (0.65, 0.63),
    (0.50, 0.52),
    (0.50, 0.90),
    (0.40, 0.88),
    (0.45, 0.92),
    (0.30, 0.95),
)


def run_thresholdout_demo(max_epsilon: float = 1.5) -> dict[str, Any]:
    """Run the Thresholdout gate over the demo stream; return a bounded packet."""

    accountant = DpAccountant(PrivacyMode.DP, max_epsilon=max_epsilon, max_delta=0.0)
    policy = ThresholdoutPolicy(
        tolerance=0.1, noise_scale=0.0, epsilon_per_access=0.5, step_denominator=10
    )
    gate = ThresholdoutGate(accountant, policy, noise_fn=lambda scale: 0.0)

    releases: list[dict[str, Any]] = []
    for reward_stat, holdout_stat in _DEMO_STREAM:
        release = gate.query(reward_stat=reward_stat, holdout_stat=holdout_stat)
        releases.append(release.to_public_dict())

    # Every per-query release is bounded (ints/bools only); fail fast if not.
    assert_bounded_egress({"releases": releases})

    return {
        "demo": "thresholdout",
        "releases": releases,
        "manifest": gate.public_manifest(),
        # Public DP ledger (epsilon/delta are public config, not reward values).
        "dp_status": {
            "spent_epsilon": accountant.spent_epsilon,
            "max_epsilon": max_epsilon,
            "exhausted": accountant.exhausted,
        },
        "free_release_count": sum(1 for r in releases if not r["used_holdout"] and r["has_release"]),
        "holdout_access_count": gate.holdout_access_count,
        "raw_secret_egress": False,
    }
