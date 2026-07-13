import json
import unittest

from tinker_delegate.bio_evaluators import SyntheticAssay
from tinker_delegate.bio_registry import (
    BioEvaluatorEntry,
    BioEvaluatorRegistry,
    BioRegistryError,
    default_registry,
)
from tinker_delegate.bio_validation import BioReadiness, BioReleaseDecision

_READY = BioReadiness(
    risk_screen_enabled=True,
    reviewer_queue_enabled=True,
    bounded_schema_enabled=True,
    synthetic_or_approved_data_only=True,
)
_ASSAY = SyntheticAssay(
    positive_controls=(100.0, 102.0, 98.0, 101.0),
    negative_controls=(10.0, 9.0, 11.0, 10.5),
    replicates=3,
)


class DefaultRegistryTest(unittest.TestCase):
    def test_lists_shipped_use_cases(self):
        use_cases = default_registry().list_use_cases()
        ids = [u["use_case_id"] for u in use_cases]
        self.assertIn("synthetic_assay_qc", ids)

    def test_metadata_is_bounded(self):
        entry = default_registry().list_use_cases()[0]
        self.assertEqual(
            sorted(entry), ["description", "input_schema", "methodology_class", "use_case_id"]
        )

    def test_runner_preserves_fail_closed_behavior(self):
        runner = default_registry().get_runner("synthetic_assay_qc")
        self.assertEqual(runner(_ASSAY).decision, BioReleaseDecision.HOLD)
        self.assertEqual(runner(_ASSAY, _READY).decision, BioReleaseDecision.RELEASE)

    def test_unknown_use_case_rejected(self):
        registry = default_registry()
        with self.assertRaises(BioRegistryError):
            registry.get_runner("does_not_exist")
        with self.assertRaises(BioRegistryError):
            registry.get_entry("does_not_exist")

    def test_has(self):
        registry = default_registry()
        self.assertTrue(registry.has("synthetic_assay_qc"))
        self.assertFalse(registry.has("nope"))


class RegistrationTest(unittest.TestCase):
    def test_duplicate_registration_rejected(self):
        registry = BioEvaluatorRegistry()
        entry = BioEvaluatorEntry("uc", "cls", "desc", "schema")
        registry.register(entry, lambda *a, **k: None)
        with self.assertRaises(BioRegistryError):
            registry.register(entry, lambda *a, **k: None)

    def test_list_is_sorted_and_egress_safe(self):
        registry = BioEvaluatorRegistry()
        registry.register(BioEvaluatorEntry("b", "c", "d", "s"), lambda *a, **k: None)
        registry.register(BioEvaluatorEntry("a", "c", "d", "s"), lambda *a, **k: None)
        listed = registry.list_use_cases()
        self.assertEqual([u["use_case_id"] for u in listed], ["a", "b"])
        self.assertNotIn("raw", json.dumps(listed))


if __name__ == "__main__":
    unittest.main()
