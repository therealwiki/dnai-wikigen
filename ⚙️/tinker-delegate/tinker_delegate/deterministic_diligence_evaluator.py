"""Deterministic, bounded, no-I/O diligence evaluation recipes.

This module is deliberately smaller than a general evaluator runtime.  It
accepts bytes already held inside the confidential boundary, validates the one
structural recipe selected by the buyer's committed policy, and returns only
``quality_delta`` for the existing control-plane quantizer.  It has no
filesystem, network, subprocess, clock, randomness, model-provider, or logging
integration.

The policy is an authority artifact, not a bag of defaults.  Its JSON must be
the exact canonical encoding produced by :func:`compile_policy_v1`; every
resource cap and capability denial is fixed for v1.  A domain-separated policy
commitment is required on every evaluation so changing any digest, recipe, cap,
or denied capability fails closed.  Each canonical policy authorizes exactly
one recipe, so the buyer's single policy commitment unambiguously selects the
artifact semantics.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Final, Mapping, NoReturn


POLICY_SCHEMA: Final = "dnai.diligence-evaluator-policy.v1"
EVALUATOR_LANE: Final = "deterministic_bounded_no_network_v1"
POLICY_COMMITMENT_DOMAIN: Final = b"dnai.diligence-evaluator-policy.v1\x00"

SFT_JSONL_RECIPE: Final = "sft_jsonl_integrity_v1"
CSV_TABLE_RECIPE: Final = "csv_table_integrity_v1"
VCF_STRUCTURAL_QC_RECIPE: Final = "vcf_structural_qc_v1"
COMPILED_RECIPES: Final = (
    CSV_TABLE_RECIPE,
    SFT_JSONL_RECIPE,
    VCF_STRUCTURAL_QC_RECIPE,
)

_RESOURCE_CAPS = {
    "max_artifact_bytes": 1_048_576,
    "max_columns": 256,
    "max_field_bytes": 16_384,
    "max_json_depth": 12,
    "max_json_members_per_record": 128,
    "max_line_bytes": 65_536,
    "max_records": 4_096,
}
EXACT_RESOURCE_CAPS: Final[Mapping[str, int]] = MappingProxyType(_RESOURCE_CAPS)

MAX_ARTIFACT_BYTES: Final = _RESOURCE_CAPS["max_artifact_bytes"]
MAX_COLUMNS: Final = _RESOURCE_CAPS["max_columns"]
MAX_FIELD_BYTES: Final = _RESOURCE_CAPS["max_field_bytes"]
MAX_JSON_DEPTH: Final = _RESOURCE_CAPS["max_json_depth"]
MAX_JSON_MEMBERS_PER_RECORD: Final = _RESOURCE_CAPS["max_json_members_per_record"]
MAX_LINE_BYTES: Final = _RESOURCE_CAPS["max_line_bytes"]
MAX_RECORDS: Final = _RESOURCE_CAPS["max_records"]

_DIGEST = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_HEADER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_VCF_CHROM = re.compile(r"^[!-~]{1,255}$")
_VCF_ID = re.compile(r"^(?:\.|[A-Za-z0-9_.:-]+(?:;[A-Za-z0-9_.:-]+)*)$")
_VCF_ALLELE = re.compile(r"^(?:[ACGTN*]+|<[A-Z][A-Z0-9_.:-]*>)$")
_VCF_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")

_COMPRESSED_MAGIC: Final = (
    b"\x1f\x8b",  # gzip
    b"PK\x03\x04",  # zip
    b"PK\x05\x06",  # empty zip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"\x28\xb5\x2f\xfd",  # zstd
    b"7z\xbc\xaf\x27\x1c",  # 7zip
    b"Rar!\x1a\x07",  # rar
    b"\x78\x01",  # zlib, no/fast compression
    b"\x78\x9c",  # zlib, default compression
    b"\x78\xda",  # zlib, best compression
)

_POLICY_KEYS: Final = frozenset({
    "arbitrary_code_allowed",
    "decompression_allowed",
    "entrypoint_digest_sha256",
    "filesystem_access",
    "evaluator_bundle_digest_sha256",
    "input_schema_digest_sha256",
    "lane",
    "network_access",
    "output_fields",
    "output_schema_digest_sha256",
    "policy_version",
    "recipe",
    "remote_provider_access",
    "resource_caps",
    "schema",
    "subprocess_access",
})

# Deliberately low-cardinality values spanning the existing public quantizer's
# negligible/low/medium/high bands.  Recipes select only from this fixed set;
# they never return record, row, variant, token, or field counts.
QUALITY_DELTA_LATTICE: Final = (0.02, 0.06, 0.12)


class PolicyRejected(ValueError):
    """A content-free, stable rejection of policy authority bytes."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EvaluationRejected(ValueError):
    """A content-free, stable rejection of private artifact bytes."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ParsedPolicyV1:
    """Validated public policy authority; contains no artifact information."""

    canonical_json: bytes
    commitment_sha256: str
    recipe: str
    evaluator_bundle_digest_sha256: str
    entrypoint_digest_sha256: str
    input_schema_digest_sha256: str
    output_schema_digest_sha256: str


def _policy_reject(code: str) -> NoReturn:
    raise PolicyRejected(code)


def _evaluation_reject(code: str) -> NoReturn:
    raise EvaluationRejected(code)


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        _policy_reject("policy_json_invalid")
    return f"{encoded}\n".encode("ascii")


def _validate_digest(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _policy_reject(code)
    return value


def compile_policy_v1(
    *,
    recipe: str,
    evaluator_bundle_digest_sha256: str,
    entrypoint_digest_sha256: str,
    input_schema_digest_sha256: str,
    output_schema_digest_sha256: str,
) -> bytes:
    """Compile exact canonical policy bytes for the fixed v1 evaluator lane.

    The evaluator-bundle and three interface digests are mandatory external
    authority. The bundle digest binds a reproducible post-source artifact,
    never the final OCI image that separately contains this policy authority.
    No placeholder or all-zero commitment is accepted.  Recipes, caps, denied
    capabilities, and the sole output field are not caller-configurable.  The
    selected recipe is one of the three compiled implementations and is the
    only recipe authorized by the resulting policy commitment.
    """

    if type(recipe) is not str or recipe not in COMPILED_RECIPES:
        _policy_reject("policy_recipe_invalid")

    digests = {
        "evaluator_bundle_digest_sha256": _validate_digest(
            evaluator_bundle_digest_sha256,
            code="policy_evaluator_bundle_digest_invalid",
        ),
        "entrypoint_digest_sha256": _validate_digest(
            entrypoint_digest_sha256,
            code="policy_entrypoint_digest_invalid",
        ),
        "input_schema_digest_sha256": _validate_digest(
            input_schema_digest_sha256,
            code="policy_input_schema_digest_invalid",
        ),
        "output_schema_digest_sha256": _validate_digest(
            output_schema_digest_sha256,
            code="policy_output_schema_digest_invalid",
        ),
    }
    policy = {
        "schema": POLICY_SCHEMA,
        "lane": EVALUATOR_LANE,
        "policy_version": 1,
        **digests,
        "resource_caps": dict(_RESOURCE_CAPS),
        "recipe": recipe,
        "network_access": False,
        "remote_provider_access": False,
        "filesystem_access": False,
        "subprocess_access": False,
        "decompression_allowed": False,
        "arbitrary_code_allowed": False,
        "output_fields": ["quality_delta"],
    }
    return _canonical_json_bytes(policy)


def policy_commitment_sha256(canonical_policy_json: bytes) -> str:
    """Return the domain-separated SHA-256 policy commitment."""

    if type(canonical_policy_json) is not bytes:  # exact immutable byte input
        _policy_reject("policy_bytes_required")
    digest = hashlib.sha256(
        POLICY_COMMITMENT_DOMAIN + canonical_policy_json,
    ).hexdigest()
    return f"sha256:{digest}"


def _load_policy_json(text: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _policy_reject("policy_json_duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> NoReturn:
        _policy_reject("policy_json_nonfinite_number")

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except PolicyRejected:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        _policy_reject("policy_json_invalid")


def parse_policy_v1(canonical_policy_json: bytes) -> ParsedPolicyV1:
    """Parse only the exact canonical v1 policy representation."""

    if type(canonical_policy_json) is not bytes:
        _policy_reject("policy_bytes_required")
    if not canonical_policy_json or len(canonical_policy_json) > 32_768:
        _policy_reject("policy_size_invalid")
    try:
        text = canonical_policy_json.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _policy_reject("policy_utf8_invalid")
    if text.startswith("\ufeff") or "\r" in text or "\x00" in text:
        _policy_reject("policy_text_encoding_invalid")
    value = _load_policy_json(text)
    if not isinstance(value, dict) or set(value) != _POLICY_KEYS:
        _policy_reject("policy_fields_invalid")
    if canonical_policy_json != _canonical_json_bytes(value):
        _policy_reject("policy_json_not_canonical")
    if (
        value["schema"] != POLICY_SCHEMA
        or type(value["policy_version"]) is not int
        or value["policy_version"] != 1
    ):
        _policy_reject("policy_schema_invalid")
    if value["lane"] != EVALUATOR_LANE:
        _policy_reject("policy_lane_invalid")
    resource_caps = value["resource_caps"]
    if (
        not isinstance(resource_caps, dict)
        or set(resource_caps) != set(_RESOURCE_CAPS)
        or any(type(item) is not int for item in resource_caps.values())
        or resource_caps != _RESOURCE_CAPS
    ):
        _policy_reject("policy_resource_caps_mismatch")
    if type(value["recipe"]) is not str or value["recipe"] not in COMPILED_RECIPES:
        _policy_reject("policy_recipe_invalid")
    for field in (
        "network_access",
        "remote_provider_access",
        "filesystem_access",
        "subprocess_access",
        "decompression_allowed",
        "arbitrary_code_allowed",
    ):
        if value[field] is not False:
            _policy_reject("policy_capability_denial_mismatch")
    if value["output_fields"] != ["quality_delta"]:
        _policy_reject("policy_output_fields_mismatch")

    evaluator_bundle_digest = _validate_digest(
        value["evaluator_bundle_digest_sha256"],
        code="policy_evaluator_bundle_digest_invalid",
    )
    entrypoint_digest = _validate_digest(
        value["entrypoint_digest_sha256"],
        code="policy_entrypoint_digest_invalid",
    )
    input_digest = _validate_digest(
        value["input_schema_digest_sha256"],
        code="policy_input_schema_digest_invalid",
    )
    output_digest = _validate_digest(
        value["output_schema_digest_sha256"],
        code="policy_output_schema_digest_invalid",
    )
    return ParsedPolicyV1(
        canonical_json=canonical_policy_json,
        commitment_sha256=policy_commitment_sha256(canonical_policy_json),
        recipe=value["recipe"],
        evaluator_bundle_digest_sha256=evaluator_bundle_digest,
        entrypoint_digest_sha256=entrypoint_digest,
        input_schema_digest_sha256=input_digest,
        output_schema_digest_sha256=output_digest,
    )


def _reject_compressed_artifact(artifact: bytes) -> None:
    if any(artifact.startswith(magic) for magic in _COMPRESSED_MAGIC):
        _evaluation_reject("compressed_artifact_forbidden")
    # POSIX tar magic is not at byte zero.  Inspecting this fixed public offset
    # does not decompress or parse attacker-controlled archive metadata.
    if len(artifact) >= 262 and artifact[257:262] == b"ustar":
        _evaluation_reject("compressed_artifact_forbidden")


def _bounded_text_lines(artifact: bytes) -> list[str]:
    if type(artifact) is not bytes:
        _evaluation_reject("artifact_bytes_required")
    if not artifact:
        _evaluation_reject("artifact_empty")
    if len(artifact) > MAX_ARTIFACT_BYTES:
        _evaluation_reject("artifact_size_exceeded")
    _reject_compressed_artifact(artifact)
    if artifact.startswith(b"\xef\xbb\xbf") or b"\r" in artifact or b"\x00" in artifact:
        _evaluation_reject("artifact_text_encoding_invalid")
    if any(byte < 32 and byte not in {9, 10} for byte in artifact):
        _evaluation_reject("artifact_text_encoding_invalid")
    if not artifact.endswith(b"\n"):
        _evaluation_reject("artifact_final_newline_required")
    raw_lines = artifact[:-1].split(b"\n")
    if not raw_lines or len(raw_lines) > MAX_RECORDS:
        _evaluation_reject("artifact_record_cap_exceeded")
    if any(not line for line in raw_lines):
        _evaluation_reject("artifact_blank_line_forbidden")
    if any(len(line) > MAX_LINE_BYTES for line in raw_lines):
        _evaluation_reject("artifact_line_cap_exceeded")
    try:
        return [line.decode("utf-8", errors="strict") for line in raw_lines]
    except UnicodeDecodeError:
        _evaluation_reject("artifact_utf8_invalid")


def _load_sft_record(line: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _evaluation_reject("sft_json_duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> NoReturn:
        _evaluation_reject("sft_json_nonfinite_number")

    try:
        value = json.loads(
            line,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except EvaluationRejected:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        _evaluation_reject("sft_json_invalid")
    try:
        canonical = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        _evaluation_reject("sft_json_invalid")
    if line != canonical:
        _evaluation_reject("sft_json_not_canonical")
    return value


def _validate_json_bounds(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    members = 0
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            _evaluation_reject("sft_json_depth_exceeded")
        if isinstance(current, dict):
            members += len(current)
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            members += len(current)
            stack.extend((child, depth + 1) for child in current)
        if members > MAX_JSON_MEMBERS_PER_RECORD:
            _evaluation_reject("sft_json_member_cap_exceeded")


def _validate_private_text(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _evaluation_reject("sft_field_type_invalid")
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        _evaluation_reject("artifact_field_cap_exceeded")
    if "\x00" in value or "\r" in value or any(
        ord(character) < 32 and character not in "\n\t"
        for character in value
    ):
        _evaluation_reject("sft_field_control_character")
    if not allow_empty and not value.strip():
        _evaluation_reject("sft_field_empty")
    return value


def _validate_sft_shape(record: Any) -> bool:
    if not isinstance(record, dict):
        _evaluation_reject("sft_record_shape_invalid")
    keys = set(record)
    if keys == {"instruction", "response"}:
        prompt = _validate_private_text(record["instruction"])
        response = _validate_private_text(record["response"])
        return len(prompt.encode("utf-8")) >= 8 and len(response.encode("utf-8")) >= 8
    if keys == {"instruction", "input", "response"}:
        instruction = _validate_private_text(record["instruction"])
        input_text = _validate_private_text(record["input"], allow_empty=True)
        response = _validate_private_text(record["response"])
        return (
            len((instruction + input_text).encode("utf-8")) >= 8
            and len(response.encode("utf-8")) >= 8
        )
    if keys == {"prompt", "completion"}:
        prompt = _validate_private_text(record["prompt"])
        completion = _validate_private_text(record["completion"])
        return len(prompt.encode("utf-8")) >= 8 and len(completion.encode("utf-8")) >= 8
    if keys != {"messages"} or not isinstance(record["messages"], list):
        _evaluation_reject("sft_record_shape_invalid")

    messages = record["messages"]
    if not 2 <= len(messages) <= 64:
        _evaluation_reject("sft_messages_shape_invalid")
    start = 0
    if isinstance(messages[0], dict) and messages[0].get("role") == "system":
        if set(messages[0]) != {"content", "role"}:
            _evaluation_reject("sft_messages_shape_invalid")
        _validate_private_text(messages[0]["content"])
        start = 1
    conversation = messages[start:]
    if len(conversation) < 2 or len(conversation) % 2 != 0:
        _evaluation_reject("sft_messages_shape_invalid")
    content_bytes = 0
    for index, message in enumerate(conversation):
        if not isinstance(message, dict) or set(message) != {"content", "role"}:
            _evaluation_reject("sft_messages_shape_invalid")
        expected_role = "user" if index % 2 == 0 else "assistant"
        if message["role"] != expected_role:
            _evaluation_reject("sft_messages_role_order_invalid")
        content = _validate_private_text(message["content"])
        content_bytes += len(content.encode("utf-8"))
    return content_bytes >= 16


def _evaluate_sft_jsonl(artifact: bytes) -> float:
    lines = _bounded_text_lines(artifact)
    all_strong = True
    for line in lines:
        record = _load_sft_record(line)
        _validate_json_bounds(record)
        all_strong = _validate_sft_shape(record) and all_strong
    if len(lines) >= 8 and all_strong:
        return QUALITY_DELTA_LATTICE[2]
    if len(lines) >= 2:
        return QUALITY_DELTA_LATTICE[1]
    return QUALITY_DELTA_LATTICE[0]


def _validate_table_field(value: str, *, header: bool = False) -> None:
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        _evaluation_reject("artifact_field_cap_exceeded")
    if "\x00" in value or "\r" in value or any(
        ord(character) < 32 and character != "\t"
        for character in value
    ):
        _evaluation_reject("table_field_control_character")
    if header and _HEADER.fullmatch(value) is None:
        _evaluation_reject("table_header_invalid")


def _parse_csv_line(line: str) -> list[str]:
    try:
        reader = csv.reader([line], dialect="excel", strict=True)
        row = next(reader)
        try:
            next(reader)
        except StopIteration:
            pass
        else:
            _evaluation_reject("table_row_invalid")
        return row
    except (csv.Error, StopIteration):
        _evaluation_reject("table_csv_invalid")


def _evaluate_csv_table(artifact: bytes) -> float:
    lines = _bounded_text_lines(artifact)
    if len(lines) < 2:
        _evaluation_reject("table_data_row_required")
    header = _parse_csv_line(lines[0])
    if not 1 <= len(header) <= MAX_COLUMNS:
        _evaluation_reject("table_column_cap_exceeded")
    for value in header:
        _validate_table_field(value, header=True)
    if len(set(header)) != len(header):
        _evaluation_reject("table_header_duplicate")

    has_missing = False
    for line in lines[1:]:
        row = _parse_csv_line(line)
        if len(row) != len(header):
            _evaluation_reject("table_column_count_mismatch")
        for value in row:
            _validate_table_field(value)
            has_missing = has_missing or value == ""
    data_rows = len(lines) - 1
    if data_rows >= 4 and not has_missing:
        return QUALITY_DELTA_LATTICE[2]
    if not has_missing:
        return QUALITY_DELTA_LATTICE[1]
    return QUALITY_DELTA_LATTICE[0]


def _validate_vcf_info(value: str) -> None:
    if value == ".":
        return
    seen: set[str] = set()
    for component in value.split(";"):
        if not component:
            _evaluation_reject("vcf_info_invalid")
        key, separator, item = component.partition("=")
        if _VCF_TOKEN.fullmatch(key) is None or key in seen:
            _evaluation_reject("vcf_info_invalid")
        seen.add(key)
        if separator and (not item or len(item.encode("utf-8")) > MAX_FIELD_BYTES):
            _evaluation_reject("vcf_info_invalid")
        if separator and any(ord(character) < 33 for character in item):
            _evaluation_reject("vcf_info_invalid")


def _evaluate_vcf(artifact: bytes) -> float:
    lines = _bounded_text_lines(artifact)
    if lines[0] not in {"##fileformat=VCFv4.2", "##fileformat=VCFv4.3"}:
        _evaluation_reject("vcf_fileformat_invalid")
    header_index = -1
    has_contig_metadata = False
    for index, line in enumerate(lines):
        if line.startswith("##"):
            if index > 0 and line.startswith("##fileformat="):
                _evaluation_reject("vcf_fileformat_duplicate")
            if line.startswith("##contig=<ID="):
                has_contig_metadata = True
            if any(ord(character) < 32 or ord(character) > 126 for character in line):
                _evaluation_reject("vcf_metadata_invalid")
            continue
        if line.startswith("#CHROM\t"):
            header_index = index
            break
        _evaluation_reject("vcf_header_invalid")
    if header_index < 0 or header_index == len(lines) - 1:
        _evaluation_reject("vcf_variant_required")

    header = lines[header_index].split("\t")
    required = ["#CHROM", "POS", "ID", "REF", "ALT", "QUAL", "FILTER", "INFO"]
    if header[:8] != required or len(header) > MAX_COLUMNS:
        _evaluation_reject("vcf_header_invalid")
    if len(header) == 9 or (len(header) > 8 and header[8] != "FORMAT"):
        _evaluation_reject("vcf_sample_header_invalid")
    if len(header) > 9:
        samples = header[9:]
        if len(set(samples)) != len(samples) or any(
            _HEADER.fullmatch(sample) is None for sample in samples
        ):
            _evaluation_reject("vcf_sample_header_invalid")

    last_chrom: str | None = None
    last_position = 0
    closed_chromosomes: set[str] = set()
    all_pass = True
    variants = lines[header_index + 1:]
    for line in variants:
        fields = line.split("\t")
        if len(fields) != len(header):
            _evaluation_reject("vcf_column_count_mismatch")
        if any(len(field.encode("utf-8")) > MAX_FIELD_BYTES for field in fields):
            _evaluation_reject("artifact_field_cap_exceeded")
        chrom, position_text, identifier, reference, alternate, quality, filters, info = fields[:8]
        if _VCF_CHROM.fullmatch(chrom) is None or any(character.isspace() for character in chrom):
            _evaluation_reject("vcf_chrom_invalid")
        try:
            position = int(position_text, 10)
        except ValueError:
            _evaluation_reject("vcf_position_invalid")
        if position < 1 or position > 2_147_483_647 or str(position) != position_text:
            _evaluation_reject("vcf_position_invalid")
        if chrom != last_chrom:
            if chrom in closed_chromosomes:
                _evaluation_reject("vcf_order_invalid")
            if last_chrom is not None:
                closed_chromosomes.add(last_chrom)
            last_chrom = chrom
            last_position = 0
        if position < last_position:
            _evaluation_reject("vcf_order_invalid")
        last_position = position
        if _VCF_ID.fullmatch(identifier) is None or _VCF_ALLELE.fullmatch(reference) is None:
            _evaluation_reject("vcf_allele_invalid")
        alternate_values = alternate.split(",")
        if not alternate_values or any(
            _VCF_ALLELE.fullmatch(value) is None for value in alternate_values
        ):
            _evaluation_reject("vcf_allele_invalid")
        if quality != ".":
            try:
                parsed_quality = Decimal(quality)
            except InvalidOperation:
                _evaluation_reject("vcf_quality_invalid")
            if not parsed_quality.is_finite() or parsed_quality < 0:
                _evaluation_reject("vcf_quality_invalid")
        if filters != "PASS":
            all_pass = False
        if filters not in {".", "PASS"}:
            filter_values = filters.split(";")
            if any(_VCF_TOKEN.fullmatch(value) is None for value in filter_values):
                _evaluation_reject("vcf_filter_invalid")
        _validate_vcf_info(info)
        if len(header) > 9:
            format_keys = fields[8].split(":")
            if not format_keys or len(set(format_keys)) != len(format_keys) or any(
                _VCF_TOKEN.fullmatch(value) is None for value in format_keys
            ):
                _evaluation_reject("vcf_format_invalid")
            for sample in fields[9:]:
                if len(sample.split(":")) != len(format_keys):
                    _evaluation_reject("vcf_sample_invalid")

    if len(variants) >= 2 and all_pass and has_contig_metadata:
        return QUALITY_DELTA_LATTICE[2]
    if all_pass:
        return QUALITY_DELTA_LATTICE[1]
    return QUALITY_DELTA_LATTICE[0]


def evaluate_artifact_v1(
    *,
    artifact: bytes,
    recipe: str,
    canonical_policy_json: bytes,
    expected_policy_commitment_sha256: str,
) -> dict[str, float]:
    """Evaluate bounded private bytes and return only internal quality delta.

    This function performs no I/O and accepts no callback, session, provider,
    path, URL, command, logger, or arbitrary evaluator program.  Errors contain
    stable public codes only; they never include artifact bytes, values, or
    artifact-derived counts.
    """

    policy = parse_policy_v1(canonical_policy_json)
    if (
        not isinstance(expected_policy_commitment_sha256, str)
        or _DIGEST.fullmatch(expected_policy_commitment_sha256) is None
        or not hmac.compare_digest(
            policy.commitment_sha256,
            expected_policy_commitment_sha256,
        )
    ):
        _policy_reject("policy_commitment_mismatch")
    if type(recipe) is not str or recipe not in COMPILED_RECIPES:
        _evaluation_reject("recipe_not_compiled")
    if recipe != policy.recipe:
        _policy_reject("recipe_policy_mismatch")
    if policy.recipe == SFT_JSONL_RECIPE:
        quality_delta = _evaluate_sft_jsonl(artifact)
    elif policy.recipe == CSV_TABLE_RECIPE:
        quality_delta = _evaluate_csv_table(artifact)
    else:
        quality_delta = _evaluate_vcf(artifact)
    if (
        isinstance(quality_delta, bool)
        or not isinstance(quality_delta, float)
        or not math.isfinite(quality_delta)
        or quality_delta not in QUALITY_DELTA_LATTICE
    ):
        _evaluation_reject("internal_quality_delta_invalid")
    return {"quality_delta": quality_delta}


__all__ = [
    "COMPILED_RECIPES",
    "CSV_TABLE_RECIPE",
    "EVALUATOR_LANE",
    "EXACT_RESOURCE_CAPS",
    "EvaluationRejected",
    "MAX_ARTIFACT_BYTES",
    "POLICY_COMMITMENT_DOMAIN",
    "POLICY_SCHEMA",
    "ParsedPolicyV1",
    "PolicyRejected",
    "QUALITY_DELTA_LATTICE",
    "SFT_JSONL_RECIPE",
    "VCF_STRUCTURAL_QC_RECIPE",
    "compile_policy_v1",
    "evaluate_artifact_v1",
    "parse_policy_v1",
    "policy_commitment_sha256",
]
