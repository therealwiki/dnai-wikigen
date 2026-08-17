"""Deterministic, capability-free candidate runtime for DNASeq variant QC.

``dnai-safe-ir-v1`` is deliberately *not* a general-purpose programming
language. Candidate bytes are canonical JSON data describing a short,
allowlisted pipeline over two bounded vectors of synthetic per-variant quality
evidence. The positive lane contains truth-supported synthetic variant calls;
the negative lane contains simulated sequencing and calling artifacts. No
candidate-controlled string is resolved as a name, imported, evaluated, or
called.  The interpreter has no filesystem, network, environment, process,
clock, or entropy capability because its opcode dispatch is a closed set of
ordinary data transformations.

This semantic safety property is narrower than a production deployment claim.
The source tree includes ciphertext-only ingress and a leased queue worker, but
the product must continue to report hostile-candidate execution as disabled
until a fresh attested CVM, independently verified measurements, durable
single-worker operation, and exact on-chain evaluator-policy bindings are
deployed. A worker heartbeat is presence evidence, not proof that any result
row executed inside a TDX boundary.

Candidate wire format (canonical JSON only)::

    {
      "negative_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],
      "positive_pipeline":[{"op":"sort"},{"high":1,"low":1,"op":"trim"}],
      "schema":"dnai.dnaseq-variant-qc-safe-ir.v1"
    }

The output is always a subset of the corresponding input multiset. A program
cannot fabricate values, move values between lanes, or emit arbitrary bytes.
It never receives bases, reads, alleles, loci, sample identifiers, phenotypes,
or clinical labels. Exact quality evidence and exact scores remain internal to
the evaluator boundary; public ranking uses only a quantized Ladder release.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Mapping, Sequence


SAFE_IR_SCHEMA = "dnai.dnaseq-variant-qc-safe-ir.v1"
SAFE_IR_RUNTIME = "dnai-safe-ir-v1"
SAFE_IR_ENTRYPOINT = "select_variant_evidence"
SAFE_IR_CANDIDATE_KIND = "json_dnaseq_variant_qc_program"

SAFE_IR_MAX_CANDIDATE_BYTES = 4_096
SAFE_IR_MAX_JSON_DEPTH = 8
SAFE_IR_MAX_INSTRUCTIONS_PER_LANE = 12
SAFE_IR_MAX_INPUT_ITEMS_PER_LANE = 512
SAFE_IR_MAX_OUTPUT_ITEMS = 1_024
SAFE_IR_MAX_FUEL = 100_000
SAFE_IR_MIN_CONTROLS_PER_LANE = 2

_TOP_LEVEL_FIELDS = frozenset(
    {"schema", "positive_pipeline", "negative_pipeline"}
)
_OP_FIELDS: dict[str, frozenset[str]] = {
    "sort": frozenset({"op"}),
    "trim": frozenset({"op", "low", "high"}),
    "mad_filter": frozenset({"op", "threshold_milli"}),
    "head": frozenset({"op", "count"}),
    "tail": frozenset({"op", "count"}),
    "stride": frozenset({"op", "step", "offset"}),
}


class SafeIrError(ValueError):
    """Base error whose messages never include candidate or sealed values."""


class SafeIrPolicyError(SafeIrError):
    """Raised when candidate bytes are not the exact safe-IR language."""


class SafeIrExecutionError(SafeIrError):
    """Raised when bounded execution cannot produce an admissible result."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SafeIrPolicyError("safe-IR candidate is not canonical JSON") from exc


def safe_ir_candidate_commitment(candidate_bytes: bytes | bytearray) -> str:
    if not isinstance(candidate_bytes, (bytes, bytearray)):
        raise SafeIrPolicyError("safe-IR candidate must be bytes")
    return "sha256:" + hashlib.sha256(bytes(candidate_bytes)).hexdigest()


def _policy_commitment() -> str:
    policy = {
        "candidate_kind": SAFE_IR_CANDIDATE_KIND,
        "entrypoint": SAFE_IR_ENTRYPOINT,
        "limits": {
            "max_candidate_bytes": SAFE_IR_MAX_CANDIDATE_BYTES,
            "max_fuel": SAFE_IR_MAX_FUEL,
            "max_input_items_per_lane": SAFE_IR_MAX_INPUT_ITEMS_PER_LANE,
            "max_instructions_per_lane": SAFE_IR_MAX_INSTRUCTIONS_PER_LANE,
            "max_json_depth": SAFE_IR_MAX_JSON_DEPTH,
            "max_output_items": SAFE_IR_MAX_OUTPUT_ITEMS,
            "min_controls_per_lane": SAFE_IR_MIN_CONTROLS_PER_LANE,
        },
        "opcodes": sorted(_OP_FIELDS),
        "runtime": SAFE_IR_RUNTIME,
        "schema": SAFE_IR_SCHEMA,
    }
    digest = hashlib.sha256()
    digest.update(b"dnai_arena_dnaseq_safe_ir_policy_v1\0")
    digest.update(_canonical_json(policy))
    return "sha256:" + digest.hexdigest()


# Registry ``evaluator_commitment`` values for this runtime must bind this exact
# value (in addition to the sealed evaluator/dataset commitment chosen by the
# deployment policy).  Any opcode or limit change requires a new runtime/schema.
SAFE_IR_POLICY_COMMITMENT = _policy_commitment()


@dataclass(frozen=True, repr=False)
class SafeIrInstruction:
    opcode: str
    operands: tuple[int, ...] = ()


@dataclass(frozen=True, repr=False)
class SafeIrProgram:
    """Compiled private program; repr omits its instruction sequence."""

    candidate_commitment: str
    source_bytes: int
    positive_pipeline: tuple[SafeIrInstruction, ...] = field(repr=False)
    negative_pipeline: tuple[SafeIrInstruction, ...] = field(repr=False)

    @property
    def instruction_count(self) -> int:
        return len(self.positive_pipeline) + len(self.negative_pipeline)

    def __repr__(self) -> str:
        return (
            "SafeIrProgram("
            f"candidate_commitment={self.candidate_commitment!r}, "
            f"source_bytes={self.source_bytes}, "
            f"instruction_count={self.instruction_count})"
        )


@dataclass(frozen=True, repr=False)
class SafeIrControls:
    """Private interpreter result.  It intentionally has no public serializer."""

    positive: tuple[float, ...] = field(repr=False)
    negative: tuple[float, ...] = field(repr=False)
    fuel_used: int

    def __repr__(self) -> str:
        return (
            "SafeIrControls("
            f"positive_count={len(self.positive)}, "
            f"negative_count={len(self.negative)}, "
            f"fuel_used={self.fuel_used})"
        )


def encode_safe_ir_program(
    *,
    positive_pipeline: Sequence[Mapping[str, Any]],
    negative_pipeline: Sequence[Mapping[str, Any]],
) -> bytes:
    """Encode and validate the one canonical candidate representation."""

    payload = {
        "schema": SAFE_IR_SCHEMA,
        "positive_pipeline": list(positive_pipeline),
        "negative_pipeline": list(negative_pipeline),
    }
    encoded = _canonical_json(payload)
    # Parsing here makes this helper unable to produce an invalid program.
    parse_safe_ir_program(encoded)
    return encoded


def parse_safe_ir_program(
    candidate_bytes: bytes | bytearray,
    *,
    expected_commitment: str | None = None,
) -> SafeIrProgram:
    """Verify a byte commitment and compile canonical JSON into closed opcodes."""

    if not isinstance(candidate_bytes, (bytes, bytearray)):
        raise SafeIrPolicyError("safe-IR candidate must be bytes")
    size = len(candidate_bytes)
    if size < 1 or size > SAFE_IR_MAX_CANDIDATE_BYTES:
        raise SafeIrPolicyError("safe-IR candidate byte length is outside policy")
    commitment = safe_ir_candidate_commitment(candidate_bytes)
    if expected_commitment is not None:
        if (
            not isinstance(expected_commitment, str)
            or not expected_commitment.startswith("sha256:")
            or len(expected_commitment) != 71
            or not hmac.compare_digest(commitment, expected_commitment)
        ):
            raise SafeIrPolicyError("safe-IR candidate commitment mismatch")
    try:
        source = bytes(candidate_bytes).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SafeIrPolicyError("safe-IR candidate must be UTF-8") from exc
    _check_json_depth(source)
    try:
        payload = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except SafeIrPolicyError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise SafeIrPolicyError("safe-IR candidate JSON is malformed") from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise SafeIrPolicyError("safe-IR candidate fields are not allowlisted")
    if payload["schema"] != SAFE_IR_SCHEMA:
        raise SafeIrPolicyError("safe-IR candidate schema is unsupported")
    # One semantic program has one byte representation.  This pins commitments
    # across browser, queue, worker, registry metadata, and test vectors.
    if not hmac.compare_digest(_canonical_json(payload), bytes(candidate_bytes)):
        raise SafeIrPolicyError("safe-IR candidate must use canonical JSON encoding")
    positive = _compile_pipeline(payload["positive_pipeline"], label="positive")
    negative = _compile_pipeline(payload["negative_pipeline"], label="negative")
    return SafeIrProgram(
        candidate_commitment=commitment,
        source_bytes=size,
        positive_pipeline=positive,
        negative_pipeline=negative,
    )


def execute_safe_ir_program(
    program: SafeIrProgram,
    positive_controls: Sequence[float],
    negative_controls: Sequence[float],
    *,
    fuel_limit: int = SAFE_IR_MAX_FUEL,
) -> SafeIrControls:
    """Interpret a compiled program over sealed controls with bounded resources."""

    if not isinstance(program, SafeIrProgram):
        raise SafeIrExecutionError("compiled safe-IR program is required")
    if (
        isinstance(fuel_limit, bool)
        or not isinstance(fuel_limit, int)
        or fuel_limit < 1
        or fuel_limit > SAFE_IR_MAX_FUEL
    ):
        raise SafeIrExecutionError("safe-IR fuel limit is outside policy")
    positive = _validated_controls(positive_controls, label="positive")
    negative = _validated_controls(negative_controls, label="negative")
    remaining = fuel_limit
    positive, remaining = _execute_pipeline(
        positive, program.positive_pipeline, remaining
    )
    negative, remaining = _execute_pipeline(
        negative, program.negative_pipeline, remaining
    )
    if (
        len(positive) < SAFE_IR_MIN_CONTROLS_PER_LANE
        or len(negative) < SAFE_IR_MIN_CONTROLS_PER_LANE
    ):
        raise SafeIrExecutionError("safe-IR output has too few controls")
    if len(positive) + len(negative) > SAFE_IR_MAX_OUTPUT_ITEMS:
        raise SafeIrExecutionError("safe-IR output exceeds policy")
    return SafeIrControls(
        positive=tuple(positive),
        negative=tuple(negative),
        fuel_used=fuel_limit - remaining,
    )


def _compile_pipeline(value: Any, *, label: str) -> tuple[SafeIrInstruction, ...]:
    if not isinstance(value, list):
        raise SafeIrPolicyError("safe-IR pipelines must be arrays")
    if len(value) > SAFE_IR_MAX_INSTRUCTIONS_PER_LANE:
        raise SafeIrPolicyError("safe-IR pipeline exceeds instruction limit")
    compiled: list[SafeIrInstruction] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise SafeIrPolicyError("safe-IR instruction must be an object")
        opcode = raw.get("op")
        if not isinstance(opcode, str) or opcode not in _OP_FIELDS:
            raise SafeIrPolicyError("safe-IR opcode is unsupported")
        if set(raw) != _OP_FIELDS[opcode]:
            raise SafeIrPolicyError("safe-IR instruction fields are not allowlisted")
        if opcode == "sort":
            operands: tuple[int, ...] = ()
        elif opcode == "trim":
            operands = (
                _bounded_int(raw["low"], minimum=0, maximum=64),
                _bounded_int(raw["high"], minimum=0, maximum=64),
            )
        elif opcode == "mad_filter":
            operands = (
                _bounded_int(raw["threshold_milli"], minimum=100, maximum=10_000),
            )
        elif opcode in {"head", "tail"}:
            operands = (_bounded_int(raw["count"], minimum=2, maximum=512),)
        elif opcode == "stride":
            step = _bounded_int(raw["step"], minimum=1, maximum=16)
            offset = _bounded_int(raw["offset"], minimum=0, maximum=15)
            if offset >= step:
                raise SafeIrPolicyError("safe-IR stride offset must be below step")
            operands = (step, offset)
        else:  # pragma: no cover - closed dispatch above is exhaustively tested.
            raise SafeIrPolicyError("safe-IR opcode is unsupported")
        compiled.append(SafeIrInstruction(opcode=opcode, operands=operands))
    return tuple(compiled)


def _execute_pipeline(
    values: list[float],
    pipeline: tuple[SafeIrInstruction, ...],
    remaining_fuel: int,
) -> tuple[list[float], int]:
    current = values
    for instruction in pipeline:
        opcode = instruction.opcode
        if opcode == "sort":
            # Charge a deterministic upper bound rather than host timing.
            cost = 1 + len(current) * max(1, math.ceil(math.log2(len(current) + 1)))
            remaining_fuel = _consume_fuel(remaining_fuel, cost)
            current = sorted(current)
        elif opcode == "trim":
            remaining_fuel = _consume_fuel(remaining_fuel, 1 + len(current))
            low, high = instruction.operands
            end = len(current) - high
            current = current[low : max(low, end)]
        elif opcode == "mad_filter":
            remaining_fuel = _consume_fuel(remaining_fuel, 1 + 8 * len(current))
            threshold_milli = instruction.operands[0]
            current = _mad_filter(current, threshold_milli)
        elif opcode == "head":
            remaining_fuel = _consume_fuel(remaining_fuel, 1 + len(current))
            current = current[: instruction.operands[0]]
        elif opcode == "tail":
            remaining_fuel = _consume_fuel(remaining_fuel, 1 + len(current))
            current = current[-instruction.operands[0] :]
        elif opcode == "stride":
            remaining_fuel = _consume_fuel(remaining_fuel, 1 + len(current))
            step, offset = instruction.operands
            current = current[offset::step]
        else:  # Defensive against construction outside the compiler.
            raise SafeIrExecutionError("compiled safe-IR opcode is unsupported")
        if len(current) > SAFE_IR_MAX_INPUT_ITEMS_PER_LANE:
            raise SafeIrExecutionError("safe-IR intermediate output exceeds policy")
    return current, remaining_fuel


def _mad_filter(values: list[float], threshold_milli: int) -> list[float]:
    if not values:
        return []
    decimals = [Decimal(str(value)) for value in values]
    median = _median(decimals)
    deviations = [abs(value - median) for value in decimals]
    mad = _median(deviations)
    if mad == 0:
        # Identity avoids dataset-dependent collapse when every control matches.
        return list(values)
    threshold = mad * Decimal(threshold_milli) / Decimal(1_000)
    return [
        original
        for original, value in zip(values, decimals, strict=True)
        if abs(value - median) <= threshold
    ]


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / Decimal(2)


def _validated_controls(value: Sequence[float], *, label: str) -> list[float]:
    if isinstance(value, (str, bytes, bytearray)):
        raise SafeIrExecutionError("safe-IR controls must be numeric sequences")
    try:
        items = list(value)
    except TypeError as exc:
        raise SafeIrExecutionError("safe-IR controls must be numeric sequences") from exc
    if (
        len(items) < SAFE_IR_MIN_CONTROLS_PER_LANE
        or len(items) > SAFE_IR_MAX_INPUT_ITEMS_PER_LANE
    ):
        raise SafeIrExecutionError("safe-IR control count is outside policy")
    output: list[float] = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise SafeIrExecutionError("safe-IR controls must be finite numbers")
        number = float(item)
        if not math.isfinite(number):
            raise SafeIrExecutionError("safe-IR controls must be finite numbers")
        output.append(number)
    return output


def _consume_fuel(remaining: int, cost: int) -> int:
    if cost > remaining:
        raise SafeIrExecutionError("safe-IR fuel exhausted")
    return remaining - cost


def _bounded_int(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SafeIrPolicyError("safe-IR operands must be integers")
    if value < minimum or value > maximum:
        raise SafeIrPolicyError("safe-IR operand is outside policy")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise SafeIrPolicyError("safe-IR candidate contains duplicate keys")
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> Any:
    raise SafeIrPolicyError("safe-IR candidate contains a non-finite number")


def _check_json_depth(source: str) -> None:
    """Bound structural nesting before the generic JSON parser allocates it."""

    depth = 0
    in_string = False
    escaped = False
    for character in source:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > SAFE_IR_MAX_JSON_DEPTH:
                raise SafeIrPolicyError("safe-IR candidate nesting exceeds policy")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise SafeIrPolicyError("safe-IR candidate JSON is malformed")
    if in_string or escaped or depth != 0:
        raise SafeIrPolicyError("safe-IR candidate JSON is malformed")
