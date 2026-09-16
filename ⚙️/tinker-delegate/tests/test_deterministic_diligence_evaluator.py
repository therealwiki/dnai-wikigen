from __future__ import annotations

import hashlib
import io
import json
import logging
import socket
import subprocess
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from tinker_delegate.deterministic_diligence_evaluator import (
    COMPILED_RECIPES,
    CSV_TABLE_RECIPE,
    EVALUATOR_LANE,
    EXACT_RESOURCE_CAPS,
    EvaluationRejected,
    MAX_ARTIFACT_BYTES,
    POLICY_COMMITMENT_DOMAIN,
    POLICY_SCHEMA,
    PolicyRejected,
    QUALITY_DELTA_LATTICE,
    SFT_JSONL_RECIPE,
    VCF_STRUCTURAL_QC_RECIPE,
    compile_policy_v1,
    evaluate_artifact_v1,
    parse_policy_v1,
    policy_commitment_sha256,
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode('ascii')).hexdigest()}"


DIGESTS = {
    "evaluator_bundle_digest_sha256": _digest("reviewed-evaluator-bundle"),
    "entrypoint_digest_sha256": _digest("reviewed-entrypoint"),
    "input_schema_digest_sha256": _digest("reviewed-input-schema"),
    "output_schema_digest_sha256": _digest("reviewed-output-schema"),
}
POLICIES = {
    recipe: compile_policy_v1(recipe=recipe, **DIGESTS)
    for recipe in COMPILED_RECIPES
}
POLICY_COMMITMENTS = {
    recipe: policy_commitment_sha256(policy)
    for recipe, policy in POLICIES.items()
}
POLICY = POLICIES[SFT_JSONL_RECIPE]
POLICY_COMMITMENT = policy_commitment_sha256(POLICY)
PRIVATE_SENTINEL = "private-artifact-sentinel-must-not-egress"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _jsonl(records: list[object]) -> bytes:
    return ("\n".join(_canonical_json(record) for record in records) + "\n").encode("ascii")


def _canonical_policy_payload(payload: dict) -> bytes:
    return f"{_canonical_json(payload)}\n".encode("ascii")


def _evaluate(artifact: bytes, recipe: str) -> dict[str, float]:
    policy = POLICIES.get(recipe, POLICY)
    return evaluate_artifact_v1(
        artifact=artifact,
        recipe=recipe,
        canonical_policy_json=policy,
        expected_policy_commitment_sha256=policy_commitment_sha256(policy),
    )


VALID_CSV = (
    "sample_id,value,group\n"
    "alpha,1,case\n"
    "beta,2,control\n"
    "gamma,3,case\n"
    "delta,4,control\n"
).encode("ascii")

VALID_VCF = (
    "##fileformat=VCFv4.3\n"
    "##contig=<ID=chr1,length=1000>\n"
    "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    "chr1\t10\trs1\tA\tG\t50\tPASS\tDP=20\n"
    "chr1\t20\t.\tC\tT\t60\tPASS\tDP=22\n"
).encode("ascii")


class PolicyAuthorityTests(unittest.TestCase):
    def test_compiled_policy_is_exact_canonical_denied_capability_authority(self):
        self.assertTrue(POLICY.endswith(b"\n"))
        self.assertNotIn(b"\r", POLICY)
        payload = json.loads(POLICY)
        self.assertEqual(payload["schema"], POLICY_SCHEMA)
        self.assertEqual(payload["lane"], EVALUATOR_LANE)
        self.assertEqual(payload["policy_version"], 1)
        self.assertEqual(payload["recipe"], SFT_JSONL_RECIPE)
        self.assertEqual(payload["resource_caps"], dict(EXACT_RESOURCE_CAPS))
        self.assertEqual(payload["output_fields"], ["quality_delta"])
        for field in (
            "network_access",
            "remote_provider_access",
            "filesystem_access",
            "subprocess_access",
            "decompression_allowed",
            "arbitrary_code_allowed",
        ):
            self.assertIs(payload[field], False)
        self.assertEqual(POLICY, _canonical_policy_payload(payload))
        parsed = parse_policy_v1(POLICY)
        self.assertEqual(parsed.canonical_json, POLICY)
        self.assertEqual(parsed.commitment_sha256, POLICY_COMMITMENT)
        self.assertEqual(parsed.recipe, SFT_JSONL_RECIPE)
        for field, expected in DIGESTS.items():
            self.assertEqual(getattr(parsed, field), expected)

    def test_policy_commitment_uses_exact_explicit_domain(self):
        expected = hashlib.sha256(POLICY_COMMITMENT_DOMAIN + POLICY).hexdigest()
        self.assertEqual(POLICY_COMMITMENT, f"sha256:{expected}")
        self.assertNotEqual(
            POLICY_COMMITMENT,
            f"sha256:{hashlib.sha256(POLICY).hexdigest()}",
        )

    def test_all_four_authority_digests_are_required_nonzero_canonical_sha256(self):
        invalid = (
            "0" * 64,
            f"sha256:{'0' * 64}",
            f"sha256:{'A' * 64}",
            f"sha512:{'a' * 64}",
            "placeholder",
            "",
        )
        for field in DIGESTS:
            for value in invalid:
                with self.subTest(field=field, value=value):
                    args = dict(DIGESTS)
                    args[field] = value
                    with self.assertRaises(PolicyRejected):
                        compile_policy_v1(recipe=SFT_JSONL_RECIPE, **args)

    def test_each_compiled_recipe_has_one_distinct_canonical_policy_commitment(self):
        self.assertEqual(set(POLICIES), set(COMPILED_RECIPES))
        self.assertEqual(len(set(POLICIES.values())), len(COMPILED_RECIPES))
        self.assertEqual(
            len(set(POLICY_COMMITMENTS.values())),
            len(COMPILED_RECIPES),
        )
        for recipe in COMPILED_RECIPES:
            with self.subTest(recipe=recipe):
                payload = json.loads(POLICIES[recipe])
                self.assertEqual(payload["recipe"], recipe)
                self.assertNotIn("recipes", payload)
                self.assertEqual(parse_policy_v1(POLICIES[recipe]).recipe, recipe)

    def test_policy_json_rejects_ambiguity_and_noncanonical_encodings(self):
        duplicate = b'{"schema":"duplicate",' + POLICY[1:]
        cases = (
            b" " + POLICY,
            POLICY.replace(b"\n", b"\r\n"),
            b"\xef\xbb\xbf" + POLICY,
            duplicate,
            POLICY[:-1],
            POLICY.replace(b'"policy_version":1', b'"policy_version":NaN'),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate[:24]):
                with self.assertRaises(PolicyRejected):
                    parse_policy_v1(candidate)

    def test_policy_rejects_field_capability_recipe_cap_and_digest_drift(self):
        mutations = []
        payload = json.loads(POLICY)
        extra = dict(payload)
        extra["extra"] = False
        mutations.append(extra)
        missing = dict(payload)
        del missing["lane"]
        mutations.append(missing)
        resource = json.loads(POLICY)
        resource["resource_caps"]["max_records"] += 1
        mutations.append(resource)
        boolean_cap = json.loads(POLICY)
        boolean_cap["resource_caps"]["max_records"] = True
        mutations.append(boolean_cap)
        network = json.loads(POLICY)
        network["network_access"] = True
        mutations.append(network)
        remote = json.loads(POLICY)
        remote["remote_provider_access"] = True
        mutations.append(remote)
        recipe = json.loads(POLICY)
        recipe["recipe"] = "remote_provider_recipe"
        mutations.append(recipe)
        output = json.loads(POLICY)
        output["output_fields"].append("diagnostics")
        mutations.append(output)
        digest = json.loads(POLICY)
        digest["evaluator_bundle_digest_sha256"] = f"sha256:{'0' * 64}"
        mutations.append(digest)
        for mutation in mutations:
            with self.subTest(keys=tuple(mutation)):
                with self.assertRaises(PolicyRejected):
                    parse_policy_v1(_canonical_policy_payload(mutation))

    def test_commitment_drift_fails_before_artifact_recipe_execution(self):
        changed = dict(DIGESTS)
        changed["evaluator_bundle_digest_sha256"] = _digest("different-evaluator-bundle")
        changed_policy = compile_policy_v1(recipe=SFT_JSONL_RECIPE, **changed)
        with self.assertRaisesRegex(PolicyRejected, "policy_commitment_mismatch"):
            evaluate_artifact_v1(
                artifact=VALID_CSV,
                recipe=CSV_TABLE_RECIPE,
                canonical_policy_json=changed_policy,
                expected_policy_commitment_sha256=POLICY_COMMITMENT,
            )

    def test_cross_recipe_substitution_fails_before_artifact_parsing(self):
        for committed_recipe in COMPILED_RECIPES:
            for requested_recipe in COMPILED_RECIPES:
                if requested_recipe == committed_recipe:
                    continue
                with self.subTest(
                    committed=committed_recipe,
                    requested=requested_recipe,
                ):
                    with self.assertRaisesRegex(
                        PolicyRejected,
                        "recipe_policy_mismatch",
                    ):
                        evaluate_artifact_v1(
                            artifact=b"\x1f\x8bprivate\n",
                            recipe=requested_recipe,
                            canonical_policy_json=POLICIES[committed_recipe],
                            expected_policy_commitment_sha256=(
                                POLICY_COMMITMENTS[committed_recipe]
                            ),
                        )


class CompiledRecipeTests(unittest.TestCase):
    def test_strict_sft_jsonl_instruction_chat_and_prompt_recipes(self):
        records = [
            {
                "instruction": "Summarize the bounded assay result",
                "response": "The bounded response is structurally complete",
            },
            {
                "completion": "A complete response for the prompt",
                "prompt": "A sufficiently detailed private prompt",
            },
            {
                "messages": [
                    {"content": "Answer only the requested task", "role": "system"},
                    {"content": "Interpret this private assay", "role": "user"},
                    {"content": "A bounded structurally valid answer", "role": "assistant"},
                ],
            },
        ]
        result = _evaluate(_jsonl(records), SFT_JSONL_RECIPE)
        self.assertEqual(result, {"quality_delta": QUALITY_DELTA_LATTICE[1]})

        strong = records * 3
        result = _evaluate(_jsonl(strong), SFT_JSONL_RECIPE)
        self.assertEqual(result, {"quality_delta": QUALITY_DELTA_LATTICE[2]})

    def test_sft_rejects_malformed_duplicate_noncanonical_and_wrong_shapes(self):
        invalid = (
            b'{"instruction":"ok","response":}\n',
            b'{"instruction":"a","instruction":"b","response":"complete response"}\n',
            b'{"instruction": "spacing is not canonical", "response":"complete response"}\n',
            b'{"instruction":"ok","response":NaN}\n',
            _jsonl([{"instruction": "missing response"}]),
            _jsonl([{"instruction": "", "response": "complete response"}]),
            _jsonl([{"messages": [
                {"content": "assistant first is invalid", "role": "assistant"},
                {"content": "user second is invalid", "role": "user"},
            ]}]),
        )
        for artifact in invalid:
            with self.subTest(artifact=artifact[:40]):
                with self.assertRaises(EvaluationRejected):
                    _evaluate(artifact, SFT_JSONL_RECIPE)

    def test_sft_rejects_depth_member_and_field_resource_exhaustion(self):
        nested: object = "leaf"
        for _ in range(int(EXACT_RESOURCE_CAPS["max_json_depth"]) + 1):
            nested = [nested]
        deep = _jsonl([{"messages": nested}])
        with self.assertRaisesRegex(EvaluationRejected, "sft_json_depth_exceeded"):
            _evaluate(deep, SFT_JSONL_RECIPE)

        members = _jsonl([{"messages": ["x"] * (
            int(EXACT_RESOURCE_CAPS["max_json_members_per_record"]) + 1
        )}])
        with self.assertRaisesRegex(EvaluationRejected, "sft_json_member_cap_exceeded"):
            _evaluate(members, SFT_JSONL_RECIPE)

        large_field = _jsonl([{
            "instruction": "i" * (int(EXACT_RESOURCE_CAPS["max_field_bytes"]) + 1),
            "response": "complete response",
        }])
        with self.assertRaisesRegex(EvaluationRejected, "artifact_field_cap_exceeded"):
            _evaluate(large_field, SFT_JSONL_RECIPE)

    def test_csv_integrity_accepts_quoted_values_and_emits_no_counts(self):
        artifact = (
            "sample_id,value,label\n"
            'alpha,"1,2",case\n'
            "beta,3,control\n"
            "gamma,4,case\n"
            "delta,5,control\n"
        ).encode("ascii")
        result = _evaluate(artifact, CSV_TABLE_RECIPE)
        self.assertEqual(result, {"quality_delta": QUALITY_DELTA_LATTICE[2]})
        self.assertEqual(tuple(result), ("quality_delta",))

    def test_csv_rejects_duplicate_headers_shape_drift_and_malformed_quotes(self):
        invalid = (
            b"sample_id,sample_id\na,b\n",
            b"sample id,value\na,b\n",
            b"sample_id,value\na\n",
            b'sample_id,value\na,"unterminated\n',
            b"sample_id,value\n",
        )
        for artifact in invalid:
            with self.subTest(artifact=artifact):
                with self.assertRaises(EvaluationRejected):
                    _evaluate(artifact, CSV_TABLE_RECIPE)

    def test_csv_enforces_column_and_field_caps(self):
        too_many_columns = ",".join(
            f"c{index}" for index in range(int(EXACT_RESOURCE_CAPS["max_columns"]) + 1)
        )
        artifact = f"{too_many_columns}\n" + ",".join("x" for _ in too_many_columns.split(",")) + "\n"
        with self.assertRaisesRegex(EvaluationRejected, "table_column_cap_exceeded"):
            _evaluate(artifact.encode("ascii"), CSV_TABLE_RECIPE)

        large_value = "x" * (int(EXACT_RESOURCE_CAPS["max_field_bytes"]) + 1)
        with self.assertRaisesRegex(EvaluationRejected, "artifact_field_cap_exceeded"):
            _evaluate(f"name\n{large_value}\n".encode("ascii"), CSV_TABLE_RECIPE)

    def test_vcf_structural_qc_accepts_sorted_strict_variants_and_samples(self):
        result = _evaluate(VALID_VCF, VCF_STRUCTURAL_QC_RECIPE)
        self.assertEqual(result, {"quality_delta": QUALITY_DELTA_LATTICE[2]})

        sampled = (
            "##fileformat=VCFv4.2\n"
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSAMPLE_1\n"
            "chr1\t1\t.\tA\tG\t.\tPASS\t.\tGT:DP\t0/1:12\n"
        ).encode("ascii")
        self.assertEqual(
            _evaluate(sampled, VCF_STRUCTURAL_QC_RECIPE),
            {"quality_delta": QUALITY_DELTA_LATTICE[1]},
        )

    def test_vcf_rejects_header_position_order_allele_and_sample_drift(self):
        invalid = (
            VALID_VCF.replace(b"##fileformat=VCFv4.3", b"##fileformat=VCFv4.1"),
            VALID_VCF.replace(b"chr1\t10", b"chr1\t0", 1),
            VALID_VCF.replace(b"chr1\t20", b"chr1\t9", 1),
            VALID_VCF.replace(b"\tA\tG\t", b"\tA\tB\t", 1),
            VALID_VCF.replace(b"\t50\t", b"\tNaN\t", 1),
            VALID_VCF.replace(b"DP=20", b"DP=20;DP=21", 1),
            (
                "##fileformat=VCFv4.3\n"
                "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tS1\n"
                "chr1\t1\t.\tA\tG\t10\tPASS\t.\tGT:DP\t0/1\n"
            ).encode("ascii"),
        )
        for artifact in invalid:
            with self.subTest(artifact=artifact[-80:]):
                with self.assertRaises(EvaluationRejected):
                    _evaluate(artifact, VCF_STRUCTURAL_QC_RECIPE)


class BoundaryAndEgressTests(unittest.TestCase):
    def test_common_bounds_reject_oversized_nonbytes_text_ambiguity_and_record_bombs(self):
        cases = (
            bytearray(VALID_CSV),
            b"",
            b"name\nvalue",
            b"name\n\nvalue\n",
            b"\xef\xbb\xbfname\nvalue\n",
            b"name\r\nvalue\r\n",
            b"name\x00\nvalue\n",
            b"name\x01\nvalue\n",
            b"\xff\n",
            b"x" * (MAX_ARTIFACT_BYTES + 1),
            b"x" * (int(EXACT_RESOURCE_CAPS["max_line_bytes"]) + 1) + b"\n",
            b"x\n" * (int(EXACT_RESOURCE_CAPS["max_records"]) + 1),
        )
        for artifact in cases:
            with self.subTest(type=type(artifact), size=len(artifact)):
                with self.assertRaises(EvaluationRejected):
                    _evaluate(artifact, CSV_TABLE_RECIPE)  # type: ignore[arg-type]

    def test_compressed_and_archive_like_inputs_are_never_decompressed(self):
        magic_values = (
            b"\x1f\x8b",
            b"PK\x03\x04",
            b"BZh",
            b"\xfd7zXZ\x00",
            b"\x28\xb5\x2f\xfd",
            b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07",
            b"\x78\x9c",
        )
        for magic in magic_values:
            with self.subTest(magic=magic):
                with self.assertRaisesRegex(EvaluationRejected, "compressed_artifact_forbidden"):
                    _evaluate(magic + b"private\n", CSV_TABLE_RECIPE)
        tar = bytearray(b"x" * 263)
        tar[257:262] = b"ustar"
        tar[-1:] = b"\n"
        with self.assertRaisesRegex(EvaluationRejected, "compressed_artifact_forbidden"):
            _evaluate(bytes(tar), CSV_TABLE_RECIPE)

    def test_no_filesystem_network_subprocess_provider_or_logging_surface_is_used(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch.object(socket, "socket", side_effect=AssertionError("network access")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess access")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess access")),
            patch.object(urllib.request, "urlopen", side_effect=AssertionError("provider access")),
            patch.object(logging.Logger, "_log", side_effect=AssertionError("logging egress")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = _evaluate(VALID_CSV, CSV_TABLE_RECIPE)
        self.assertEqual(result, {"quality_delta": QUALITY_DELTA_LATTICE[2]})
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_output_is_exact_low_cardinality_scalar_and_never_contains_private_content_or_counts(self):
        artifact = _jsonl([{
            "instruction": f"Inspect {PRIVATE_SENTINEL}",
            "response": "quality_delta=0.99 rows=999999 must remain private",
        }])
        result = _evaluate(artifact, SFT_JSONL_RECIPE)
        self.assertEqual(tuple(result), ("quality_delta",))
        self.assertIn(result["quality_delta"], QUALITY_DELTA_LATTICE)
        rendered = repr(result)
        self.assertNotIn(PRIVATE_SENTINEL, rendered)
        self.assertNotIn("999999", rendered)
        self.assertNotIn("rows", rendered)

        invalid = f"{PRIVATE_SENTINEL},bad header\nvalue,1\n".encode("ascii")
        try:
            _evaluate(invalid, CSV_TABLE_RECIPE)
        except EvaluationRejected as error:
            self.assertNotIn(PRIVATE_SENTINEL, str(error))
            self.assertNotIn("value", str(error))
        else:
            self.fail("private invalid header should have been rejected")

    def test_determinism_and_policy_artifact_immutability(self):
        original_policy = bytes(POLICIES[VCF_STRUCTURAL_QC_RECIPE])
        outputs = [_evaluate(VALID_VCF, VCF_STRUCTURAL_QC_RECIPE) for _ in range(100)]
        self.assertTrue(all(output == outputs[0] for output in outputs))
        self.assertEqual(POLICIES[VCF_STRUCTURAL_QC_RECIPE], original_policy)

    def test_uncompiled_recipe_and_covert_extra_output_request_fail_closed(self):
        for recipe in ("", "python", "remote_provider", "sft_jsonl_integrity_v2"):
            with self.subTest(recipe=recipe):
                with self.assertRaisesRegex(EvaluationRejected, "recipe_not_compiled"):
                    _evaluate(VALID_CSV, recipe)


if __name__ == "__main__":
    unittest.main()
