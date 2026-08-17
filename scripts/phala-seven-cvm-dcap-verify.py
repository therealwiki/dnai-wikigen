"""Bounded Intel TDX verifier for the exact seven-CVM release proof.

This source is never opened by pathname in the production child.  The
JavaScript authority opens and authenticates these bytes and the pinned,
root-protected ``dcap_qvl`` abi3 extension first, then inherits those
descriptors into a root-owned system-Python bootstrap.  The bootstrap snapshots
the authenticated native bytes from fd 3 into a random mode-0500 descriptor,
rehashes it, lets macOS validate and load its code signature, unlinks it,
rehashes the unlinked descriptor, and executes these exact source bytes from fd
4.  No uv,
venv, project directory, site-packages path, ``.pth`` file, or user-writable
Python import path participates in production verification.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Tuple

import dcap_qvl


MAX_INPUT_BYTES = 2 * 1024 * 1024
MIN_QUOTE_BYTES = 1024
MAX_QUOTE_BYTES = 16 * 1024
PCCS_URL = "https://pccs.phala.network"
PINNED_DCAP_QVL_VERSION = "0.5.2"
PINNED_PLATFORM = "Darwin"
PINNED_MACHINE = "arm64"
PINNED_SYSTEM_PYTHON_VERSION = "3.9.6"
PINNED_SYSTEM_PYTHON_REPORTED_EXECUTABLE = (
    "/Library/Developer/CommandLineTools/usr/bin/python3"
)
PINNED_SYSTEM_PYTHON_BASE = (
    "/Library/Developer/CommandLineTools/Library/Frameworks/"
    "Python3.framework/Versions/3.9"
)
PINNED_SYSTEM_PYTHON_EXECUTABLE = (
    PINNED_SYSTEM_PYTHON_BASE + "/bin/python3.9"
)
PINNED_SYSTEM_PYTHON_REPORTED_EXECUTABLE_LINK = (
    "../../Library/Frameworks/Python3.framework/Versions/3.9/bin/python3"
)
PINNED_DARWIN_RELEASE = "25.5.0"
PINNED_MACOS_VERSION = "26.5.2"
PINNED_MACOS_BUILD = "25F84"
PINNED_SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist"
PINNED_SYSTEM_VERSION_PLIST_SHA256 = (
    "cbf534776ca9200252e5637787e5d4fc26cf527fb354c19bcbac9688341c7a58"
)
MEASUREMENT_DOMAIN = b"dnai-wikigen/tdx-measurements/v1\x00"
MEASUREMENT_POLICY_SCHEMA = "dnai.phala-qvl-measurement-policy.v1"
MEASUREMENT_POLICY_DIGEST_DOMAIN = (
    b"dnai-wikigen/phala-qvl-measurement-policy/v1\x00"
)
BASE_MEASUREMENT_FIELDS = (
    "tee_tcb_svn",
    "mr_seam",
    "mr_signer_seam",
    "seam_attributes",
    "td_attributes",
    "xfam",
    "mr_td",
    "mr_config_id",
    "mr_owner",
    "mr_owner_config",
    "rt_mr0",
    "rt_mr1",
    "rt_mr2",
    "rt_mr3",
)
V15_MEASUREMENT_FIELDS = ("tee_tcb_svn2", "mr_service_td")
MEASUREMENT_LENGTHS = {
    "tee_tcb_svn": 32,
    "seam_attributes": 16,
    "td_attributes": 16,
    "xfam": 16,
    "tee_tcb_svn2": 32,
}
MEASUREMENT_POLICY_FIELDS = (
    "schema",
    "domain",
    "profile",
    "deployment_intent_sha256",
    "reference_id",
    "mr_td",
    "mr_config_id",
    "mr_owner",
    "mr_owner_config",
    "rt_mr0",
    "rt_mr1",
    "rt_mr2",
    "rt_mr3",
    "td_attributes",
    "td_attributes_required_mask",
    "td_attributes_forbidden_mask",
    "xfam",
    "xfam_required_mask",
    "xfam_forbidden_mask",
)
MEASUREMENT_POLICY_EXACT_FIELDS = (
    "mr_td",
    "mr_config_id",
    "mr_owner",
    "mr_owner_config",
    "rt_mr0",
    "rt_mr1",
    "rt_mr2",
    "rt_mr3",
    "td_attributes",
    "xfam",
)
MEASUREMENT_POLICY_HEX_LENGTHS = {
    "mr_td": 96,
    "mr_config_id": 96,
    "mr_owner": 96,
    "mr_owner_config": 96,
    "rt_mr0": 96,
    "rt_mr1": 96,
    "rt_mr2": 96,
    "rt_mr3": 96,
    "td_attributes": 16,
    "td_attributes_required_mask": 16,
    "td_attributes_forbidden_mask": 16,
    "xfam": 16,
    "xfam_required_mask": 16,
    "xfam_forbidden_mask": 16,
}
QVL_DOMAIN_PROFILES = {
    "diligence_qvl_cvm": "diligence",
    "arena_qvl_cvm": "arena",
    "anchor_writer_qvl_cvm": "execution_policy_anchor_writer",
    "compute_workload_qvl_cvm": "compute_workload",
    "compute_metering_qvl_cvm": "compute_metering",
}
SHA256_RE = re.compile(r"sha256:(?!0{64}$)[0-9a-f]{64}")
REFERENCE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{7,127}")


def _unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def _exact_object(value: Any, fields: Tuple[str, ...]) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _root_owned_restricted(path: Path, *, directory: bool = False) -> None:
    if path.is_symlink():
        raise ValueError
    opened = path.stat()
    if opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) & 0o022:
        raise ValueError
    if directory:
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError
    elif not stat.S_ISREG(opened.st_mode):
        raise ValueError


def _root_owned_reported_executable_symlink(path: Path) -> None:
    opened = path.lstat()
    if (
        not stat.S_ISLNK(opened.st_mode)
        or opened.st_uid != 0
        or stat.S_IMODE(opened.st_mode) & 0o022
        or os.readlink(str(path))
        != PINNED_SYSTEM_PYTHON_REPORTED_EXECUTABLE_LINK
    ):
        raise ValueError


def _runtime_environment_sha256() -> str:
    value = getattr(dcap_qvl, "__runtime_environment_sha256__", None)
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError
    return value


def _opened_fd_sha256(fd: int, maximum: int) -> str:
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum:
        raise ValueError
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = opened.st_size
    while remaining:
        block = os.read(fd, min(128 * 1024, remaining))
        if not block:
            raise ValueError
        digest.update(block)
        remaining -= len(block)
    if os.read(fd, 1):
        raise ValueError
    os.lseek(fd, 0, os.SEEK_SET)
    after = os.fstat(fd)
    if (
        opened.st_dev != after.st_dev
        or opened.st_ino != after.st_ino
        or opened.st_uid != after.st_uid
        or opened.st_mode != after.st_mode
        or opened.st_nlink != after.st_nlink
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError
    return digest.hexdigest()


def _assert_safe_opened_runtime() -> None:
    flags = sys.flags
    if (
        flags.isolated != 1
        or flags.no_site != 1
        or flags.no_user_site != 1
        or flags.ignore_environment != 1
        or sys.dont_write_bytecode is not True
        or "site" in sys.modules
        or "sitecustomize" in sys.modules
        or "usercustomize" in sys.modules
        or os.geteuid() == 0
    ):
        raise ValueError
    if (
        platform.system() != PINNED_PLATFORM
        or platform.machine() != PINNED_MACHINE
        or platform.release() != PINNED_DARWIN_RELEASE
        or platform.mac_ver()[0] != PINNED_MACOS_VERSION
        or platform.python_version() != PINNED_SYSTEM_PYTHON_VERSION
        or sys.executable != PINNED_SYSTEM_PYTHON_REPORTED_EXECUTABLE
        or str(Path(sys.executable).resolve(strict=True)) != PINNED_SYSTEM_PYTHON_EXECUTABLE
        or str(Path(sys.base_prefix).resolve(strict=True)) != PINNED_SYSTEM_PYTHON_BASE
        or sys.prefix != sys.base_prefix
    ):
        raise ValueError
    base = Path(PINNED_SYSTEM_PYTHON_BASE)
    executable = Path(PINNED_SYSTEM_PYTHON_EXECUTABLE)
    reported_executable = Path(PINNED_SYSTEM_PYTHON_REPORTED_EXECUTABLE)
    system_version_plist = Path(PINNED_SYSTEM_VERSION_PLIST)
    _root_owned_restricted(base, directory=True)
    _root_owned_restricted(executable)
    _root_owned_reported_executable_symlink(reported_executable)
    _root_owned_restricted(system_version_plist)
    system_version_bytes = system_version_plist.read_bytes()
    if (
        hashlib.sha256(system_version_bytes).hexdigest()
        != PINNED_SYSTEM_VERSION_PLIST_SHA256
        or plistlib.loads(system_version_bytes).get("ProductBuildVersion")
        != PINNED_MACOS_BUILD
    ):
        raise ValueError
    expected_path = [
        str(base / "lib" / "python39.zip"),
        str(base / "lib" / "python3.9"),
        str(base / "lib" / "python3.9" / "lib-dynload"),
    ]
    if sys.path != expected_path:
        raise ValueError
    native = sys.modules.get("dcap_qvl._dcap_qvl")
    native_spec = getattr(native, "__spec__", None)
    native_snapshot_fd = getattr(dcap_qvl, "__native_snapshot_fd__", None)
    native_snapshot_path = getattr(dcap_qvl, "__native_snapshot_path__", None)
    if (
        dcap_qvl is not sys.modules.get("dcap_qvl")
        or getattr(dcap_qvl, "__version__", None) != PINNED_DCAP_QVL_VERSION
        or native is None
        or native_spec is None
        or not isinstance(native_snapshot_fd, int)
        or not 5 <= native_snapshot_fd <= 64
        or native_snapshot_path != "/dev/fd/%d" % native_snapshot_fd
        or native_spec.origin != native_snapshot_path
        or getattr(native, "__file__", None) != native_snapshot_path
        or getattr(dcap_qvl, "__native_sha256__", None) is None
        or getattr(dcap_qvl, "__verifier_source_sha256__", None) is None
        or getattr(dcap_qvl, "__bootstrap_sha256__", None) is None
    ):
        raise ValueError
    native_authority = os.fstat(native_snapshot_fd)
    if (
        not stat.S_ISREG(native_authority.st_mode)
        or native_authority.st_nlink != 0
        or native_authority.st_uid != os.geteuid()
        or stat.S_IMODE(native_authority.st_mode) != 0o500
        or _opened_fd_sha256(native_snapshot_fd, 32 * 1024 * 1024)
        != dcap_qvl.__native_sha256__
        or _opened_fd_sha256(4, 256 * 1024)
        != dcap_qvl.__verifier_source_sha256__
    ):
        raise ValueError
    for digest in (
        dcap_qvl.__native_sha256__,
        dcap_qvl.__verifier_source_sha256__,
        dcap_qvl.__bootstrap_sha256__,
    ):
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError
    for module in tuple(sys.modules.values()):
        location = getattr(module, "__file__", None)
        if not isinstance(location, str) or location in ("/dev/fd/4", native_snapshot_path):
            continue
        if location.startswith("<") and location.endswith(">"):
            if getattr(getattr(module, "__spec__", None), "origin", None) != "frozen":
                raise ValueError
            continue
        resolved = Path(location).resolve(strict=True)
        if resolved != base and base not in resolved.parents:
            raise ValueError
        _root_owned_restricted(resolved)
    _runtime_environment_sha256()


def _measurements(parsed: Any) -> Dict[str, str]:
    report = parsed.report
    fields = list(BASE_MEASUREMENT_FIELDS)
    has_v15 = any(hasattr(report, field) for field in V15_MEASUREMENT_FIELDS)
    if has_v15:
        if not all(hasattr(report, field) for field in V15_MEASUREMENT_FIELDS):
            raise ValueError
        fields.extend(V15_MEASUREMENT_FIELDS)
    result = {field: bytes(getattr(report, field)).hex() for field in fields}
    for field, value in result.items():
        length = MEASUREMENT_LENGTHS.get(field, 96)
        if re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
            raise ValueError
    return result


def _measurement_policy(value: Any, external_sha256: Any) -> Tuple[Dict[str, str], str]:
    policy = _exact_object(value, MEASUREMENT_POLICY_FIELDS)
    if policy["schema"] != MEASUREMENT_POLICY_SCHEMA:
        raise ValueError
    domain = policy["domain"]
    if not isinstance(domain, str) or domain not in QVL_DOMAIN_PROFILES:
        raise ValueError
    if policy["profile"] != QVL_DOMAIN_PROFILES[domain]:
        raise ValueError
    deployment_intent = policy["deployment_intent_sha256"]
    reference_id = policy["reference_id"]
    if (
        not isinstance(deployment_intent, str)
        or SHA256_RE.fullmatch(deployment_intent) is None
        or not isinstance(reference_id, str)
        or REFERENCE_ID_RE.fullmatch(reference_id) is None
    ):
        raise ValueError
    normalized = {field: policy[field] for field in MEASUREMENT_POLICY_FIELDS}
    for field, length in MEASUREMENT_POLICY_HEX_LENGTHS.items():
        candidate = policy[field]
        if (
            not isinstance(candidate, str)
            or re.fullmatch(r"[0-9a-f]{%d}" % length, candidate) is None
        ):
            raise ValueError
    encoded = _canonical_json_bytes(normalized)
    computed = "sha256:" + hashlib.sha256(
        MEASUREMENT_POLICY_DIGEST_DOMAIN + encoded
    ).hexdigest()
    if (
        not isinstance(external_sha256, str)
        or SHA256_RE.fullmatch(external_sha256) is None
        or external_sha256 != computed
    ):
        raise ValueError
    return normalized, computed


def _enforce_mask(value: str, required: str, forbidden: str) -> None:
    value_bytes = bytes.fromhex(value)
    required_bytes = bytes.fromhex(required)
    forbidden_bytes = bytes.fromhex(forbidden)
    if not (
        len(value_bytes) == len(required_bytes) == len(forbidden_bytes) == 8
    ):
        raise ValueError
    for observed, required_bits, forbidden_bits in zip(
        value_bytes, required_bytes, forbidden_bytes
    ):
        if (
            required_bits & forbidden_bits
            or observed & required_bits != required_bits
            or observed & forbidden_bits
        ):
            raise ValueError


def _appraise_measurements(
    measurements: Dict[str, str],
    policy: Dict[str, str],
) -> None:
    if any(
        measurements[field] != policy[field]
        for field in MEASUREMENT_POLICY_EXACT_FIELDS
    ):
        raise ValueError
    td_attributes = bytes.fromhex(measurements["td_attributes"])
    td_forbidden = bytes.fromhex(policy["td_attributes_forbidden_mask"])
    if td_attributes[0] & 0x01 or not td_forbidden[0] & 0x01:
        raise ValueError
    _enforce_mask(
        measurements["td_attributes"],
        policy["td_attributes_required_mask"],
        policy["td_attributes_forbidden_mask"],
    )
    _enforce_mask(
        measurements["xfam"],
        policy["xfam_required_mask"],
        policy["xfam_forbidden_mask"],
    )


async def _verify(
    raw: bytes,
    policy: Dict[str, str],
    policy_sha256: str,
    verification_time: int,
    collateral_json: Optional[str],
) -> Dict[str, object]:
    parsed = dcap_qvl.parse_quote(raw)
    if not parsed.is_tdx() or parsed.quote_type() != "TDX":
        raise ValueError
    report_data = bytes(parsed.report.report_data)
    if len(report_data) != 64:
        raise ValueError
    measurements = _measurements(parsed)
    _appraise_measurements(measurements, policy)
    if type(verification_time) is not int or not 1 <= verification_time <= 4_102_444_800:
        raise ValueError
    if collateral_json is None:
        collateral = await dcap_qvl.get_collateral(PCCS_URL, raw)
    else:
        if (
            not isinstance(collateral_json, str)
            or not 2 <= len(collateral_json.encode("utf-8")) <= 512 * 1024
            or any(ord(character) < 0x20 or ord(character) > 0x7E
                   for character in collateral_json)
        ):
            raise ValueError
        collateral = dcap_qvl.collateral_from_json(collateral_json)
    normalized_collateral_json = collateral.to_json()
    if (
        not isinstance(normalized_collateral_json, str)
        or not 2 <= len(normalized_collateral_json.encode("utf-8")) <= 512 * 1024
        or any(ord(character) < 0x20 or ord(character) > 0x7E
               for character in normalized_collateral_json)
        or (collateral_json is not None and normalized_collateral_json != collateral_json)
    ):
        raise ValueError
    verified = dcap_qvl.verify_with_collateral(raw, collateral, verification_time)
    if verified.status != "OK":
        raise ValueError
    encoded = _canonical_json_bytes(measurements)
    return {
        "verified": True,
        "quote_type": "TDX",
        "status": "OK",
        "debug": False,
        "report_data": "0x" + report_data.hex(),
        "measurements": measurements,
        "measurements_sha256": "sha256:"
        + hashlib.sha256(MEASUREMENT_DOMAIN + encoded).hexdigest(),
        "measurement_policy_sha256": policy_sha256,
        "measurement_policy_reference_id": policy["reference_id"],
        "measurement_policy_matched": True,
        "collateral_source": PCCS_URL,
        "historical_dcap_replay": {
            "collateral_json": normalized_collateral_json,
            "collateral_sha256": "sha256:"
            + hashlib.sha256(normalized_collateral_json.encode("utf-8")).hexdigest(),
            "verification_time": verification_time,
        },
    }


def main() -> int:
    try:
        _assert_safe_opened_runtime()
        runtime_sha256 = _runtime_environment_sha256()
        body = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(body) < 2 or len(body) > MAX_INPUT_BYTES:
            raise ValueError
        payload = json.loads(body, object_pairs_hook=_unique_object)
        if payload == {"runtime_probe": True}:
            _assert_safe_opened_runtime()
            snapshot = os.fstat(dcap_qvl.__native_snapshot_fd__)
            result = {
                "native_snapshot_authenticated": True,
                "native_snapshot_link_count": snapshot.st_nlink,
                "native_snapshot_mode": "%04o" % stat.S_IMODE(snapshot.st_mode),
                "runtime_environment_sha256": runtime_sha256,
            }
            sys.stdout.write(
                json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
            )
            return 0
        if not isinstance(payload, dict):
            raise ValueError
        live_fields = (
            "quote",
            "measurement_policy",
            "measurement_policy_sha256",
            "verification_time",
        )
        replay_fields = live_fields + (
            "collateral_json",
            "collateral_sha256",
        )
        if set(payload) == set(live_fields):
            parsed = _exact_object(payload, live_fields)
            collateral_json = None
        elif set(payload) == set(replay_fields):
            parsed = _exact_object(payload, replay_fields)
            collateral_json = parsed["collateral_json"]
            if (
                not isinstance(collateral_json, str)
                or not isinstance(parsed["collateral_sha256"], str)
                or SHA256_RE.fullmatch(parsed["collateral_sha256"]) is None
                or parsed["collateral_sha256"]
                != "sha256:"
                + hashlib.sha256(collateral_json.encode("utf-8")).hexdigest()
            ):
                raise ValueError
        else:
            raise ValueError
        quote = parsed["quote"]
        if not isinstance(quote, str) or re.fullmatch(r"0x[0-9a-f]+", quote) is None:
            raise ValueError
        raw = bytes.fromhex(quote[2:])
        if not MIN_QUOTE_BYTES <= len(raw) <= MAX_QUOTE_BYTES:
            raise ValueError
        policy, policy_sha256 = _measurement_policy(
            parsed["measurement_policy"], parsed["measurement_policy_sha256"]
        )
        result = asyncio.run(
            _verify(
                raw,
                policy,
                policy_sha256,
                parsed["verification_time"],
                collateral_json,
            )
        )
        _assert_safe_opened_runtime()
        result["runtime_environment_sha256"] = runtime_sha256
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        sys.stderr.write("seven-CVM Intel TDX verification failed safely\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
