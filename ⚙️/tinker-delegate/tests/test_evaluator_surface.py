import inspect
import unittest

from tinker_delegate import evaluator


class EvaluatorSurfaceTest(unittest.TestCase):
    def test_sft_evaluator_does_not_reach_raw_tinker_client_or_admin_apis(self):
        source = inspect.getsource(evaluator.sft_evaluate)
        forbidden_fragments = (
            "._sc",
            "create_rest_client",
            "list_training_runs",
            "list_checkpoints",
            "list_user_checkpoints",
            "get_checkpoint_archive_url",
            "publish_checkpoint",
            "publish_checkpoint_from_tinker_path",
            "set_checkpoint_ttl",
            "delete_checkpoint",
        )

        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, source)
        self.assertIn("session.create_base_sampler", source)


if __name__ == "__main__":
    unittest.main()
