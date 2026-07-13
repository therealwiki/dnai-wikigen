import json
import unittest

from tinker_delegate.private_reward import (
    FeedbackMode,
    LeakageBudget,
    OptimizerPolicy,
    RewardBand,
)
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy
from tinker_delegate.private_reward_loop import (
    CandidateSource,
    EvolutionaryOptimizer,
    HillClimbOptimizer,
    LLMRepairOptimizer,
    LoopOutcome,
    PoolCandidateSource,
    RandomSearchOptimizer,
    StopReason,
    band_rank,
    run_private_reward_loop,
)


# Every hidden record contains "alpha", so the keyword "alpha" scores high on
# any partition while decoys score zero. This gives the loop a clean signal.
_RECORDS = {f"rec-{i}": f"the alpha marker {i}".encode("utf-8") for i in range(10)}
_POOL = [b"beta", b"gamma", b"alpha", b"delta"]


class _BreedingKeywordSource(CandidateSource):
    """Source whose winning keyword is only reachable by mutation, not seeds.

    ``seeds`` yields decoys; ``mutate`` deterministically enumerates the ``bred``
    vocabulary so the evolutionary optimizer must breed past its seed pool to
    discover the high-scoring keyword.
    """

    def __init__(self, seeds: list[bytes], bred: list[bytes]) -> None:
        self._seeds = [bytes(s) for s in seeds]
        self._bred = [bytes(b) for b in bred]

    def seeds(self) -> list[bytes]:
        return list(self._seeds)

    def mutate(self, payload: bytes, step: int) -> bytes:
        return self._bred[step % len(self._bred)]


def _make_env(max_queries: int = 16) -> SyntheticHiddenKeywordEnvironment:
    policy = HoldoutSplitPolicy(max_reward_queries=max_queries)
    return SyntheticHiddenKeywordEnvironment(
        _RECORDS,
        holdout_policy=policy,
        query_budget=LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND),
    )


class _ExactRewardEnv(SyntheticHiddenKeywordEnvironment):
    """Env whose optimizer policy would hand out exact rewards."""

    @property
    def optimizer_policy(self) -> OptimizerPolicy:
        return OptimizerPolicy.internal_dense()


class PrivateRewardLoopTest(unittest.TestCase):
    def test_swappable_optimizers_all_run_bounded(self):
        source = PoolCandidateSource(_POOL)
        for optimizer in (
            RandomSearchOptimizer(source, budget=8),
            HillClimbOptimizer(source, budget=8),
            LLMRepairOptimizer(source, budget=8),
            EvolutionaryOptimizer(source, population_size=3, budget=8),
        ):
            with self.subTest(optimizer=optimizer.name):
                env = _make_env()
                outcome = run_private_reward_loop(env, optimizer, max_rounds=8)
                self.assertIsInstance(outcome, LoopOutcome)
                self.assertFalse(outcome.raw_secret_egress)
                self.assertGreater(outcome.rounds_run, 0)
                self.assertEqual(outcome.optimizer_name, optimizer.name)

    def test_swappable_optimizers_all_produce_verifiable_certificates(self):
        # The verification chain must be optimizer-AGNOSTIC: whichever swappable
        # optimizer ran, the outcome certifies and independently verifies. This
        # proves the core claim — any swappable optimizer yields a bounded,
        # verifiable, leakage-safe run — across all four, not just one.
        from tinker_delegate.reproducibility import (
            RunConfig,
            certify_loop_run,
            hash_code_identity,
            verify_reproducibility_certificate,
        )

        source = PoolCandidateSource(_POOL)
        for optimizer in (
            RandomSearchOptimizer(source, budget=8),
            HillClimbOptimizer(source, budget=8),
            LLMRepairOptimizer(source, budget=8),
            EvolutionaryOptimizer(source, population_size=3, budget=8),
        ):
            with self.subTest(optimizer=optimizer.name):
                env = _make_env()
                outcome = run_private_reward_loop(env, optimizer, max_rounds=8)
                cert = certify_loop_run(
                    outcome,
                    run_config=RunConfig(
                        optimizer_name=optimizer.name, model_base="none",
                        hyperparameters={}, max_rounds=8, target_band="high",
                    ),
                    environment=env,
                    code_hash=hash_code_identity("synthetic-hidden-keyword"),
                )
                self.assertTrue(
                    verify_reproducibility_certificate(cert),
                    f"{optimizer.name} outcome did not verify",
                )
                self.assertTrue(cert.transcript_commitment_hash)
                # The certified public export leaks no raw sealed record.
                blob = repr(outcome.certified_public_export()).lower()
                self.assertNotIn("alpha marker", blob)

    def test_seed_sweeping_optimizers_reach_target(self):
        # Random and hill-climb both try the seed pool, which contains "alpha".
        for factory in (RandomSearchOptimizer, HillClimbOptimizer):
            with self.subTest(optimizer=factory.__name__):
                env = _make_env()
                optimizer = factory(PoolCandidateSource(_POOL), budget=8)
                outcome = run_private_reward_loop(
                    env, optimizer, max_rounds=8, target_band=RewardBand.HIGH
                )
                self.assertEqual(outcome.stop_reason, StopReason.TARGET_REACHED)
                self.assertGreaterEqual(band_rank(outcome.best_band), band_rank(RewardBand.HIGH))
                self.assertTrue(outcome.best_candidate_hash)

    def test_evolutionary_optimizer_reaches_target_via_seed_pool(self):
        # The elite "alpha" seed is in the pool, so population selection keeps it
        # and the loop hits HIGH without ever seeing an exact reward.
        env = _make_env()
        optimizer = EvolutionaryOptimizer(PoolCandidateSource(_POOL), population_size=3, budget=8)
        outcome = run_private_reward_loop(
            env, optimizer, max_rounds=8, target_band=RewardBand.HIGH
        )
        self.assertEqual(outcome.stop_reason, StopReason.TARGET_REACHED)
        self.assertGreaterEqual(band_rank(outcome.best_band), band_rank(RewardBand.HIGH))
        self.assertFalse(outcome.raw_secret_egress)

    def test_evolutionary_optimizer_breeds_to_the_winner_beyond_seeds(self):
        # Seeds are decoys; the winning keyword "alpha" is only reachable by
        # breeding (mutation). This proves the optimizer keeps proposing past the
        # seed phase and finds a candidate outside its initial pool.
        source = _BreedingKeywordSource(seeds=[b"beta", b"gamma"], bred=[b"delta", b"alpha"])
        env = _make_env()
        optimizer = EvolutionaryOptimizer(source, population_size=2, budget=16)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=16, target_band=RewardBand.HIGH)
        self.assertEqual(outcome.stop_reason, StopReason.TARGET_REACHED)
        self.assertGreater(outcome.rounds_run, 2)  # past the two seeds
        self.assertFalse(outcome.raw_secret_egress)

    def test_evolutionary_optimizer_halts_when_space_exhausted(self):
        # Dedup guard: a finite in-pool source with no fresh candidates left must
        # halt rather than burn the bounded per-candidate reward-query budget.
        source = PoolCandidateSource([b"beta", b"gamma"])
        env = _make_env()
        optimizer = EvolutionaryOptimizer(source, population_size=2, budget=16)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=16)
        self.assertEqual(outcome.rounds_run, 2)  # only the two unique payloads
        self.assertEqual(outcome.stop_reason, StopReason.OPTIMIZER_HALTED)
        self.assertFalse(outcome.raw_secret_egress)

    def test_evolutionary_optimizer_rejects_empty_population(self):
        with self.assertRaises(ValueError):
            EvolutionaryOptimizer(PoolCandidateSource(_POOL), population_size=0)

    def test_certified_public_export_admits_real_outcome(self):
        # A real bounded outcome must pass the mandatory export gate and return a
        # dict byte-identical to the plain public dict.
        env = _make_env()
        optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=8)
        certified = outcome.certified_public_export()
        self.assertEqual(certified, outcome.to_public_dict())

    def test_certified_public_export_fails_closed_on_leaky_outcome(self):
        # If a reducer regression smuggled an exact reward (a float) into the
        # bounded dict, the mandatory gate must refuse to publish it.
        from tinker_delegate.private_reward import RewardLeakageError

        env = _make_env()
        optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=8)
        leaky = LoopOutcome(
            optimizer_name=outcome.optimizer_name,
            rounds_run=outcome.rounds_run,
            accepted_rounds=outcome.accepted_rounds,
            best_band=outcome.best_band,
            best_candidate_hash=outcome.best_candidate_hash,
            stop_reason=outcome.stop_reason,
            band_histogram={"HIGH": 1, "exact_reward": 0.9137},  # smuggled float
            rounds=outcome.rounds,
            result=outcome.result,
            loop_transcript_hash=outcome.loop_transcript_hash,
        )
        with self.assertRaises(RewardLeakageError):
            leaky.certified_public_export()

    def test_canary_tripped_report_refuses_to_start_the_loop(self):
        from tinker_delegate.canary import CanaryCandidate, CanarySentinel
        from tinker_delegate.private_reward import RewardBand as _RB

        # Screen a FRESH env (so it doesn't consume the run's budget) with a
        # known-junk canary declared max NEGLIGIBLE — the winning keyword "alpha"
        # scores high, tripping the sentinel (simulating a gamed oracle).
        sentinel = CanarySentinel(
            [CanaryCandidate(b"alpha", label="leak", max_band=_RB.NEGLIGIBLE)]
        )
        report = sentinel.screen(_make_env())
        self.assertFalse(report.clear)

        env = _make_env()
        optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=8, canary_report=report)
        # The loop refuses to start: no budget spent, bounded halted outcome.
        self.assertEqual(outcome.stop_reason, StopReason.CANARY_TRIPPED)
        self.assertEqual(outcome.rounds_run, 0)
        self.assertEqual(env.accepted_count, 0)
        self.assertFalse(outcome.raw_secret_egress)

    def test_clear_canary_report_lets_the_loop_run(self):
        from tinker_delegate.canary import CanaryCandidate, CanarySentinel
        from tinker_delegate.private_reward import RewardBand as _RB

        sentinel = CanarySentinel(
            [CanaryCandidate(b"zzzjunk", label="junk", max_band=_RB.LOW)]
        )
        report = sentinel.screen(_make_env())
        self.assertTrue(report.clear)

        env = _make_env()
        optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=8, canary_report=report)
        self.assertNotEqual(outcome.stop_reason, StopReason.CANARY_TRIPPED)
        self.assertGreater(outcome.rounds_run, 0)

    def test_no_raw_secret_in_public_output(self):
        env = _make_env()
        optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=8)
        blob = json.dumps(outcome.to_public_dict())
        # No candidate payloads, keyword text, or raw reward values leak.
        self.assertNotIn("alpha", blob)
        self.assertNotIn("beta", blob)
        self.assertNotIn("raw_count", blob)
        self.assertIn("loop_transcript_hash", blob)
        self.assertIn("band_histogram", blob)

    def test_leakage_guard_blocks_exact_reward_env(self):
        env = _ExactRewardEnv(
            _RECORDS,
            holdout_policy=HoldoutSplitPolicy(max_reward_queries=8),
            query_budget=LeakageBudget(max_queries=8, feedback_mode=FeedbackMode.NONE),
        )
        optimizer = RandomSearchOptimizer(PoolCandidateSource(_POOL), budget=4)
        with self.assertRaises(PermissionError):
            run_private_reward_loop(env, optimizer, max_rounds=4)

    def test_internal_optimizer_opt_in_allows_exact_reward_env(self):
        env = _ExactRewardEnv(
            _RECORDS,
            holdout_policy=HoldoutSplitPolicy(max_reward_queries=8),
            query_budget=LeakageBudget(max_queries=8, feedback_mode=FeedbackMode.NONE),
        )
        optimizer = RandomSearchOptimizer(PoolCandidateSource(_POOL), budget=4)
        outcome = run_private_reward_loop(
            env, optimizer, max_rounds=4, allow_internal_optimizer=True
        )
        self.assertIsInstance(outcome, LoopOutcome)
        self.assertFalse(outcome.raw_secret_egress)

    def test_budget_exhaustion_stops_loop(self):
        env = _make_env(max_queries=2)
        optimizer = RandomSearchOptimizer(PoolCandidateSource([b"zulu", b"yankee"]), budget=8)
        outcome = run_private_reward_loop(
            env, optimizer, max_rounds=8, target_band=RewardBand.EXCEPTIONAL
        )
        self.assertEqual(outcome.stop_reason, StopReason.BUDGET_EXHAUSTED)
        self.assertLessEqual(outcome.accepted_rounds, 2)

    def test_loop_is_deterministic(self):
        def run_once():
            env = _make_env()
            optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
            return run_private_reward_loop(env, optimizer, max_rounds=8)

        first = run_once()
        second = run_once()
        self.assertEqual(first.loop_transcript_hash, second.loop_transcript_hash)
        self.assertEqual(first.best_band, second.best_band)
        self.assertEqual(first.stop_reason, second.stop_reason)

    def test_optimizer_halt_stops_loop(self):
        env = _make_env()

        class HaltingOptimizer(RandomSearchOptimizer):
            name = "halting"

            def propose(self):
                return None

        outcome = run_private_reward_loop(
            env, HaltingOptimizer(PoolCandidateSource(_POOL)), max_rounds=4
        )
        self.assertEqual(outcome.stop_reason, StopReason.NO_CANDIDATE)
        self.assertEqual(outcome.rounds_run, 0)


if __name__ == "__main__":
    unittest.main()
