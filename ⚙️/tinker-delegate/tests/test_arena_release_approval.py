import unittest

from tinker_delegate.arena_release_approval import (
    ArenaReleaseApprovalError,
    normalize_release_approved_challenge_bindings,
    release_approved_challenge_set_sha256,
    require_release_approved_challenge,
)


def _binding(registry_id: str, marker: str) -> dict[str, object]:
    return {
        "registry_challenge_id": registry_id,
        "registry_version": 7,
        "controller_address": "0x" + marker * 40,
        "pending_controller_address": "0x" + "0" * 40,
        "lifecycle": "open",
        "paused": False,
        "configuration_frozen": True,
        "catalog_manifest_hash": "a" * 64,
        "metadata_uri": f"ipfs://approved-{marker}",
        "metadata_hash": "0x" + "a" * 64,
        "sealed_artifact_commitment": "0x" + "b" * 64,
        "evaluator_commitment": "0x" + "c" * 64,
    }


class ArenaReleaseApprovalTest(unittest.TestCase):
    def test_final_authority_known_vector_matches_js_approved_set_digest(self):
        reviewed_binding = {
            "registry_challenge_id": "1",
            "registry_version": 1,
            "controller_address": "0x0000000000000000000000000000000000000001",
            "pending_controller_address": "0x0000000000000000000000000000000000000000",
            "lifecycle": "open",
            "paused": False,
            "configuration_frozen": True,
            "catalog_manifest_hash": "d1" * 32,
            "metadata_uri": "ipfs://bafy-arena-release-core-vector",
            "metadata_hash": "0x" + "d1" * 32,
            "sealed_artifact_commitment": "0x" + "d2" * 32,
            "evaluator_commitment": "0x" + "d3" * 32,
            "release_policy_commitment": "0x" + "d4" * 32,
        }
        catalog_key = "synthetic-bio-assay-qc@1.0.0"

        # The final-authority row commits to the selected release policy, while
        # the approved-set digest deliberately excludes that field to avoid a
        # cycle: the release policy separately commits to this approved-set hash.
        with self.assertRaisesRegex(ArenaReleaseApprovalError, "fields are invalid"):
            normalize_release_approved_challenge_bindings(
                {catalog_key: reviewed_binding}
            )
        approved_binding = {
            field: value
            for field, value in reviewed_binding.items()
            if field != "release_policy_commitment"
        }
        self.assertEqual(
            set(reviewed_binding) - set(approved_binding),
            {"release_policy_commitment"},
        )

        self.assertEqual(
            release_approved_challenge_set_sha256(
                {catalog_key: approved_binding}
            ),
            "sha256:7fca626cfbf6471b6bc9ed9dc7bc66446c71e5ec07be6368c0e441a7ad803764",
        )

    def test_digest_is_order_independent_and_selects_only_explicit_members(self):
        first = _binding("1", "1")
        later_public_row = _binding("2", "2")
        approved = {
            "later-approved@2.1.0": later_public_row,
            "dnaseq-variant-qc-safe-ir@1.0.0": first,
        }
        reversed_approved = dict(reversed(list(approved.items())))

        digest = release_approved_challenge_set_sha256(approved)
        self.assertEqual(
            digest,
            release_approved_challenge_set_sha256(reversed_approved),
        )
        self.assertEqual(
            require_release_approved_challenge(
                approved,
                approved_set_sha256=digest,
                challenge_id="dnaseq-variant-qc-safe-ir",
                challenge_version="1.0.0",
            ),
            normalize_release_approved_challenge_bindings(approved)[
                "dnaseq-variant-qc-safe-ir@1.0.0"
            ],
        )
        with self.assertRaisesRegex(ArenaReleaseApprovalError, "not release-approved"):
            require_release_approved_challenge(
                approved,
                approved_set_sha256=digest,
                challenge_id="new-registry-row",
                challenge_version="1.0.0",
            )

    def test_digest_and_exact_binding_mutations_fail_closed(self):
        approved = {"dnaseq-variant-qc-safe-ir@1.0.0": _binding("1", "1")}
        digest = release_approved_challenge_set_sha256(approved)
        self.assertEqual(
            digest,
            "sha256:868e658d8d7eceed7993a9751ed65ed94806ea8434c985b1f24e13ab2c686780",
        )

        with self.assertRaisesRegex(ArenaReleaseApprovalError, "digest mismatch"):
            require_release_approved_challenge(
                approved,
                approved_set_sha256="sha256:" + "f" * 64,
                challenge_id="dnaseq-variant-qc-safe-ir",
                challenge_version="1.0.0",
            )
        changed = {key: dict(value) for key, value in approved.items()}
        changed["dnaseq-variant-qc-safe-ir@1.0.0"][
            "registry_version"
        ] = 8
        with self.assertRaisesRegex(ArenaReleaseApprovalError, "digest mismatch"):
            require_release_approved_challenge(
                changed,
                approved_set_sha256=digest,
                challenge_id="dnaseq-variant-qc-safe-ir",
                challenge_version="1.0.0",
            )

    def test_unfrozen_or_ambiguous_bindings_are_rejected(self):
        duplicate = {
            "dnaseq-variant-qc-safe-ir@1.0.0": _binding("1", "1"),
            "other@1.0.0": _binding("1", "2"),
        }
        with self.assertRaises(ArenaReleaseApprovalError):
            normalize_release_approved_challenge_bindings(duplicate)

        unfrozen = _binding("1", "1")
        unfrozen["configuration_frozen"] = False
        with self.assertRaisesRegex(ArenaReleaseApprovalError, "not frozen and open"):
            normalize_release_approved_challenge_bindings(
                {"dnaseq-variant-qc-safe-ir@1.0.0": unfrozen}
            )


if __name__ == "__main__":
    unittest.main()
