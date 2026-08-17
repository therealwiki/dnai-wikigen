import ast
import hashlib
import json
import math
import unittest
from collections import Counter
from pathlib import Path

from tinker_delegate.arena_safe_ir import (
    SAFE_IR_MAX_CANDIDATE_BYTES,
    SAFE_IR_MAX_INPUT_ITEMS_PER_LANE,
    SAFE_IR_MAX_INSTRUCTIONS_PER_LANE,
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_SCHEMA,
    SafeIrExecutionError,
    SafeIrInstruction,
    SafeIrPolicyError,
    SafeIrProgram,
    encode_safe_ir_program,
    execute_safe_ir_program,
    parse_safe_ir_program,
    safe_ir_candidate_commitment,
)


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _program(positive=None, negative=None) -> bytes:
    return encode_safe_ir_program(
        positive_pipeline=positive or [],
        negative_pipeline=negative or [],
    )


class ArenaSafeIrParserTest(unittest.TestCase):
    def test_canonical_vector_and_commitments_are_pinned(self):
        source = _program(
            positive=[{"op": "sort"}, {"op": "trim", "low": 1, "high": 1}],
            negative=[{"op": "mad_filter", "threshold_milli": 3000}],
        )
        self.assertEqual(
            source,
            b'{"negative_pipeline":[{"op":"mad_filter","threshold_milli":3000}],'
            b'"positive_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],'
            b'"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
        )
        parsed = parse_safe_ir_program(
            source,
            expected_commitment=safe_ir_candidate_commitment(source),
        )
        self.assertEqual(parsed.source_bytes, len(source))
        self.assertEqual(parsed.instruction_count, 3)
        self.assertEqual(
            SAFE_IR_POLICY_COMMITMENT,
            "sha256:9fcffd04eeece1398970e4a144807df95f31408b2337d71cc8377048b2ec114e",
        )
        self.assertEqual(
            parsed.candidate_commitment,
            "sha256:" + hashlib.sha256(source).hexdigest(),
        )

    def test_rejects_noncanonical_encodings_and_trailing_bytes(self):
        canonical = _program()
        cases = (
            b'{"schema":"dnai.dnaseq-variant-qc-safe-ir.v1", "positive_pipeline":[],"negative_pipeline":[]}',
            canonical + b"\n",
            canonical.replace(b'"schema"', b'"schem\\u0061"'),
            b'{"negative_pipeline":[],"positive_pipeline":[],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1","schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
        )
        for source in cases:
            with self.subTest(source=source[:80]):
                with self.assertRaises(SafeIrPolicyError):
                    parse_safe_ir_program(source)

    def test_rejects_wrong_commitment_before_compilation(self):
        with self.assertRaisesRegex(SafeIrPolicyError, "commitment"):
            parse_safe_ir_program(_program(), expected_commitment="sha256:" + "0" * 64)

    def test_rejects_unknown_or_missing_top_level_fields(self):
        for payload in (
            {
                "schema": SAFE_IR_SCHEMA,
                "positive_pipeline": [],
            },
            {
                "schema": SAFE_IR_SCHEMA,
                "positive_pipeline": [],
                "negative_pipeline": [],
                "source": "open('/etc/passwd').read()",
            },
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(SafeIrPolicyError, "allowlisted"):
                    parse_safe_ir_program(_canonical(payload))

    def test_rejects_code_and_capability_escape_shapes(self):
        cases = (
            {"op": "__import__", "module": "socket"},
            {"op": "open", "path": "/etc/passwd"},
            {"op": "fetch", "url": "https://example.test"},
            {"op": "spawn", "argv": ["sh"]},
            {"op": "env", "name": "SECRET"},
            {"op": "clock"},
            {"op": "random"},
            {"op": "sort", "callback": "lambda x: x"},
        )
        for instruction in cases:
            payload = {
                "schema": SAFE_IR_SCHEMA,
                "positive_pipeline": [instruction],
                "negative_pipeline": [],
            }
            with self.subTest(op=instruction["op"]):
                with self.assertRaises(SafeIrPolicyError):
                    parse_safe_ir_program(_canonical(payload))

    def test_rejects_bad_operand_types_ranges_and_fields(self):
        cases = (
            {"op": "trim", "low": True, "high": 0},
            {"op": "trim", "low": -1, "high": 0},
            {"op": "mad_filter", "threshold_milli": 99},
            {"op": "head", "count": 1},
            {"op": "tail", "count": 513},
            {"op": "stride", "step": 0, "offset": 0},
            {"op": "stride", "step": 2, "offset": 2},
            {"op": "sort", "direction": "descending"},
        )
        for instruction in cases:
            with self.subTest(instruction=instruction):
                with self.assertRaises(SafeIrPolicyError):
                    parse_safe_ir_program(
                        _canonical(
                            {
                                "schema": SAFE_IR_SCHEMA,
                                "positive_pipeline": [instruction],
                                "negative_pipeline": [],
                            }
                        )
                    )

    def test_rejects_instruction_byte_depth_utf8_and_nonfinite_limits(self):
        too_many = [{"op": "sort"}] * (SAFE_IR_MAX_INSTRUCTIONS_PER_LANE + 1)
        cases = (
            _canonical(
                {
                    "schema": SAFE_IR_SCHEMA,
                    "positive_pipeline": too_many,
                    "negative_pipeline": [],
                }
            ),
            b"{" * 9 + b"}" * 9,
            b"\xff",
            b'{"negative_pipeline":[],"positive_pipeline":[{"op":"head","count":NaN}],"schema":"dnai.dnaseq-variant-qc-safe-ir.v1"}',
            b" " * (SAFE_IR_MAX_CANDIDATE_BYTES + 1),
            b"",
        )
        for source in cases:
            with self.subTest(source=source[:50]):
                with self.assertRaises(SafeIrPolicyError):
                    parse_safe_ir_program(source)

    def test_program_repr_never_contains_instruction_details(self):
        source = _program(
            positive=[{"op": "mad_filter", "threshold_milli": 7777}],
            negative=[],
        )
        representation = repr(parse_safe_ir_program(source))
        self.assertIn("instruction_count=1", representation)
        self.assertNotIn("mad_filter", representation)
        self.assertNotIn("7777", representation)


class ArenaSafeIrExecutionTest(unittest.TestCase):
    def test_deterministic_trim_and_mad_filter_select_only_input_values(self):
        source = _program(
            positive=[{"op": "sort"}, {"op": "trim", "low": 1, "high": 1}],
            negative=[{"op": "mad_filter", "threshold_milli": 3000}],
        )
        program = parse_safe_ir_program(source)
        positive = [100.0, 101.0, 99.0, 100.5, 140.0]
        negative = [10.0, 11.0, 9.0, 10.5, 40.0]
        first = execute_safe_ir_program(program, positive, negative)
        second = execute_safe_ir_program(program, positive, negative)
        self.assertEqual(first.positive, (100.0, 100.5, 101.0))
        self.assertEqual(second, first)
        self.assertEqual(first.negative, (10.0, 11.0, 9.0, 10.5))
        self.assertFalse(Counter(first.positive) - Counter(positive))
        self.assertFalse(Counter(first.negative) - Counter(negative))
        self.assertGreater(first.fuel_used, 0)

    def test_all_closed_opcodes_have_bounded_semantics(self):
        source = _program(
            positive=[
                {"op": "sort"},
                {"op": "tail", "count": 5},
                {"op": "head", "count": 4},
                {"op": "stride", "step": 2, "offset": 0},
            ],
            negative=[{"op": "trim", "low": 1, "high": 1}],
        )
        result = execute_safe_ir_program(
            parse_safe_ir_program(source),
            [9, 8, 7, 6, 5, 4],
            [1, 2, 3, 4],
        )
        self.assertEqual(result.positive, (5.0, 7.0))
        self.assertEqual(result.negative, (2.0, 3.0))

    def test_zero_mad_is_identity_not_dataset_dependent_collapse(self):
        program = parse_safe_ir_program(
            _program(
                positive=[{"op": "mad_filter", "threshold_milli": 100}],
                negative=[{"op": "mad_filter", "threshold_milli": 100}],
            )
        )
        result = execute_safe_ir_program(program, [5, 5, 5], [2, 2, 2])
        self.assertEqual(result.positive, (5.0, 5.0, 5.0))
        self.assertEqual(result.negative, (2.0, 2.0, 2.0))

    def test_fuel_exhaustion_is_deterministic_and_bounded(self):
        program = parse_safe_ir_program(
            _program(positive=[{"op": "sort"}], negative=[])
        )
        with self.assertRaisesRegex(SafeIrExecutionError, "fuel"):
            execute_safe_ir_program(program, list(range(32)), [1, 2], fuel_limit=1)
        for bad_limit in (0, True, 100_001):
            with self.subTest(limit=bad_limit):
                with self.assertRaises(SafeIrExecutionError):
                    execute_safe_ir_program(program, [1, 2], [1, 2], fuel_limit=bad_limit)

    def test_rejects_bad_sealed_input_shapes_without_echoing_values(self):
        program = parse_safe_ir_program(_program())
        cases = (
            ([1], [1, 2]),
            ([1, 2], [1, math.nan]),
            ([1, 2], [1, math.inf]),
            ([1, 2], [1, True]),
            ([1, 2], [1, "secret-control"]),
            (list(range(SAFE_IR_MAX_INPUT_ITEMS_PER_LANE + 1)), [1, 2]),
        )
        for positive, negative in cases:
            with self.subTest(size=len(positive)):
                with self.assertRaises(SafeIrExecutionError) as raised:
                    execute_safe_ir_program(program, positive, negative)
                self.assertNotIn("secret-control", str(raised.exception))

    def test_rejects_too_small_output(self):
        program = parse_safe_ir_program(
            _program(
                positive=[{"op": "trim", "low": 2, "high": 2}],
                negative=[],
            )
        )
        with self.assertRaisesRegex(SafeIrExecutionError, "too few"):
            execute_safe_ir_program(program, [1, 2, 3, 4], [1, 2])

    def test_defensive_runtime_rejects_forged_compiled_opcode(self):
        forged = SafeIrProgram(
            candidate_commitment="sha256:" + "0" * 64,
            source_bytes=1,
            positive_pipeline=(SafeIrInstruction("eval", ()),),
            negative_pipeline=(),
        )
        with self.assertRaisesRegex(SafeIrExecutionError, "unsupported"):
            execute_safe_ir_program(forged, [1, 2], [1, 2])

    def test_private_result_repr_omits_controls(self):
        result = execute_safe_ir_program(
            parse_safe_ir_program(_program()),
            [123456.75, 2],
            [987654.25, 3],
        )
        representation = repr(result)
        self.assertIn("positive_count=2", representation)
        self.assertNotIn("123456", representation)
        self.assertNotIn("987654", representation)

    def test_runtime_source_has_no_ambient_capability_or_dynamic_evaluation(self):
        module_path = Path(__file__).parents[1] / "tinker_delegate" / "arena_safe_ir.py"
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        banned_imports = {
            "asyncio",
            "ctypes",
            "importlib",
            "multiprocessing",
            "os",
            "pathlib",
            "random",
            "secrets",
            "socket",
            "subprocess",
            "sys",
            "tempfile",
            "time",
            "urllib",
        }
        imports = set()
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.add(node.func.id)
        self.assertFalse(imports & banned_imports)
        self.assertFalse(calls & {"__import__", "compile", "eval", "exec", "getattr", "open"})


if __name__ == "__main__":
    unittest.main()
