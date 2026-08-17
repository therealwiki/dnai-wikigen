"""One-shot authenticated provisioning for sealed Arena worker policy.

Phala decrypts deployment environment values inside the CVM.  This command
accepts the release manifest, synthetic evaluator, and their authentication
material only through that environment channel.  It has no payload-bearing
CLI options and is intended to run with ``network_mode: none`` before the
Arena worker starts.

The provisioner deliberately reuses the worker's release and evaluator
loaders.  Therefore the exact same schema, Base Sepolia release pins, safe-IR
policy commitment, release-policy commitment, and sealed evaluator
commitment are enforced both before publication and again at worker startup.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence, TextIO

from tinker_delegate.arena_worker_cli import (
    EVALUATOR_SCHEMA,
    MAX_SECURE_JSON_BYTES,
    RELEASE_SCHEMA,
    ArenaWorkerBootstrapError,
    load_release_manifest,
    load_sealed_evaluator,
)
from tinker_delegate.config import Settings


PROVISION_SCHEMA = "dnai.arena.sealed-policy-provision.v1"
PROVISION_STATUS_SCHEMA_VERSION = 1
PROVISION_AUTH_DOMAIN = b"dnai-wikigen/arena-sealed-policy-provision/v1\0"
DEFAULT_OUTPUT_DIR = Path("/sealed/arena")
# Compatibility mount path used by the reviewed Compose overlays. The payload
# itself is validated against RELEASE_SCHEMA (currently v3), not this filename.
RELEASE_FILENAME = "release-v2.json"
EVALUATOR_FILENAME = "sealed-evaluator-v1.json"
LOCK_FILENAME = ".provision.lock"

RELEASE_B64_ENV = "TINKER_ARENA_PROVISION_RELEASE_B64"
EVALUATOR_B64_ENV = "TINKER_ARENA_PROVISION_EVALUATOR_B64"
RELEASE_SHA256_ENV = "TINKER_ARENA_PROVISION_RELEASE_SHA256"
EVALUATOR_SHA256_ENV = "TINKER_ARENA_PROVISION_EVALUATOR_SHA256"
AUTH_KEY_B64_ENV = "TINKER_ARENA_PROVISION_AUTH_KEY_B64"
AUTH_TAG_ENV = "TINKER_ARENA_PROVISION_AUTH_TAG"

PROVISION_ENV_NAMES = (
    RELEASE_B64_ENV,
    EVALUATOR_B64_ENV,
    RELEASE_SHA256_ENV,
    EVALUATOR_SHA256_ENV,
    AUTH_KEY_B64_ENV,
    AUTH_TAG_ENV,
)

MAX_AUTH_KEY_B64_CHARS = 43
AUTH_KEY_BYTES = 32
MAX_B64_JSON_CHARS = (MAX_SECURE_JSON_BYTES * 4 + 2) // 3

_B64URL_NOPAD = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTH_TAG = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")


class ArenaPolicyProvisionError(RuntimeError):
    """Fail-closed error carrying only a non-secret reason code."""

    _REASONS = frozenset(
        {
            "environment_inputs_only",
            "provision_configuration_missing",
            "provision_encoding_invalid",
            "provision_payload_too_large",
            "provision_hash_mismatch",
            "provision_authentication_failed",
            "provision_json_invalid",
            "provision_release_invalid",
            "provision_evaluator_invalid",
            "provision_output_unavailable",
            "provisioning_failed",
        }
    )

    def __init__(self, reason: str):
        if reason not in self._REASONS:
            reason = "provisioning_failed"
        self.reason = reason
        super().__init__(reason)


def build_parser() -> argparse.ArgumentParser:
    """Return the intentionally argument-free production console surface."""

    return argparse.ArgumentParser(
        prog="tinker-arena-provision",
        description=(
            "Provision authenticated Arena policy from Phala encrypted "
            "environment values. No payload CLI arguments are accepted."
        ),
    )


def provision_auth_tag(
    key: bytes | bytearray,
    *,
    release_sha256: str,
    evaluator_sha256: str,
    release_size: int,
    evaluator_size: int,
) -> str:
    """Authenticate the exact two-file provisioning envelope.

    Deployment tooling can use this helper offline.  The secret key itself is
    never written into the sealed volume and is not inherited by the worker.
    """

    if len(key) != AUTH_KEY_BYTES:
        raise ValueError("provision authentication key length is invalid")
    if not _SHA256.fullmatch(release_sha256) or not _SHA256.fullmatch(
        evaluator_sha256
    ):
        raise ValueError("provision hash is invalid")
    if not 2 <= release_size <= MAX_SECURE_JSON_BYTES:
        raise ValueError("release size is invalid")
    if not 2 <= evaluator_size <= MAX_SECURE_JSON_BYTES:
        raise ValueError("evaluator size is invalid")
    envelope = {
        "schema": PROVISION_SCHEMA,
        "release_filename": RELEASE_FILENAME,
        "release_sha256": release_sha256,
        "release_size": release_size,
        "evaluator_filename": EVALUATOR_FILENAME,
        "evaluator_sha256": evaluator_sha256,
        "evaluator_size": evaluator_size,
    }
    digest = hmac.new(
        bytes(key),
        PROVISION_AUTH_DOMAIN + _canonical_json(envelope),
        hashlib.sha256,
    )
    return "hmac-sha256:" + digest.hexdigest()


def provision_from_environment(
    *,
    environ: MutableMapping[str, str] | None = None,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> None:
    """Consume encrypted-env inputs and publish the validated sealed files."""

    source = os.environ if environ is None else environ
    # Remove every secret-bearing value from the process environment as soon
    # as it is copied, even if another required value is missing.
    values = {name: source.pop(name, "") for name in PROVISION_ENV_NAMES}
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ArenaPolicyProvisionError("provision_configuration_missing")

    release = bytearray()
    evaluator = bytearray()
    auth_key = bytearray()
    try:
        release = _decode_base64url_json(values[RELEASE_B64_ENV])
        evaluator = _decode_base64url_json(values[EVALUATOR_B64_ENV])
        auth_key = _decode_base64url_key(values[AUTH_KEY_B64_ENV])

        release_hash = values[RELEASE_SHA256_ENV]
        evaluator_hash = values[EVALUATOR_SHA256_ENV]
        auth_tag = values[AUTH_TAG_ENV]
        if not _SHA256.fullmatch(release_hash) or not _SHA256.fullmatch(
            evaluator_hash
        ):
            raise ArenaPolicyProvisionError("provision_configuration_missing")
        if not _AUTH_TAG.fullmatch(auth_tag):
            raise ArenaPolicyProvisionError("provision_configuration_missing")

        observed_release_hash = "sha256:" + hashlib.sha256(release).hexdigest()
        observed_evaluator_hash = "sha256:" + hashlib.sha256(evaluator).hexdigest()
        if not hmac.compare_digest(observed_release_hash, release_hash) or not (
            hmac.compare_digest(observed_evaluator_hash, evaluator_hash)
        ):
            raise ArenaPolicyProvisionError("provision_hash_mismatch")

        expected_tag = provision_auth_tag(
            auth_key,
            release_sha256=release_hash,
            evaluator_sha256=evaluator_hash,
            release_size=len(release),
            evaluator_size=len(evaluator),
        )
        if not hmac.compare_digest(expected_tag, auth_tag):
            raise ArenaPolicyProvisionError("provision_authentication_failed")

        release_payload = _strict_canonical_json_object(release)
        evaluator_payload = _strict_canonical_json_object(evaluator)
        if release_payload.get("schema") != RELEASE_SCHEMA:
            raise ArenaPolicyProvisionError("provision_release_invalid")
        if evaluator_payload.get("schema") != EVALUATOR_SCHEMA:
            raise ArenaPolicyProvisionError("provision_evaluator_invalid")

        _publish_validated_policy(
            output_dir=Path(output_dir),
            release=release,
            evaluator=evaluator,
            release_sha256=release_hash,
        )
    finally:
        _zero(release)
        _zero(evaluator)
        _zero(auth_key)


def write_bounded_status(
    stream: TextIO,
    *,
    provisioned: bool,
    reason: str | None = None,
) -> None:
    """Emit a fixed-schema status with no payload, hash, or exception detail."""

    if reason is not None and reason not in ArenaPolicyProvisionError._REASONS:
        reason = "provisioning_failed"
    payload: dict[str, Any] = {
        "surface": "arena_policy_provisioner",
        "schema_version": PROVISION_STATUS_SCHEMA_VERSION,
        "provisioned": provisioned,
        "output_files": 2 if provisioned else 0,
        "network_required": False,
        "release_payload_egress": False,
        "sealed_evaluator_egress": False,
        "authentication_secret_egress": False,
        "hash_egress": False,
        "exception_detail_egress": False,
    }
    if reason is not None:
        payload["reason"] = reason
    stream.write(_canonical_json(payload).decode("ascii") + "\n")
    stream.flush()


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: MutableMapping[str, str] | None = None,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    stdout: TextIO | None = None,
) -> int:
    """Run one fail-closed provisioning attempt."""

    args = list(sys.argv[1:] if argv is None else argv)
    stream = sys.stdout if stdout is None else stdout
    if args:
        if args in (["-h"], ["--help"]):
            build_parser().print_help(file=stream)
            return 0
        write_bounded_status(
            stream,
            provisioned=False,
            reason="environment_inputs_only",
        )
        return 64
    try:
        provision_from_environment(environ=environ, output_dir=output_dir)
    except ArenaPolicyProvisionError as exc:
        write_bounded_status(stream, provisioned=False, reason=exc.reason)
        return 78
    except Exception:
        write_bounded_status(
            stream,
            provisioned=False,
            reason="provisioning_failed",
        )
        return 70
    write_bounded_status(stream, provisioned=True)
    return 0


def _decode_base64url_json(value: str) -> bytearray:
    if len(value) > MAX_B64_JSON_CHARS:
        raise ArenaPolicyProvisionError("provision_payload_too_large")
    return _decode_base64url(
        value,
        minimum=2,
        maximum=MAX_SECURE_JSON_BYTES,
    )


def _decode_base64url_key(value: str) -> bytearray:
    if len(value) != MAX_AUTH_KEY_B64_CHARS:
        raise ArenaPolicyProvisionError("provision_encoding_invalid")
    return _decode_base64url(
        value,
        minimum=AUTH_KEY_BYTES,
        maximum=AUTH_KEY_BYTES,
    )


def _decode_base64url(value: str, *, minimum: int, maximum: int) -> bytearray:
    if (
        not isinstance(value, str)
        or not value
        or not _B64URL_NOPAD.fullmatch(value)
        or len(value) % 4 == 1
    ):
        raise ArenaPolicyProvisionError("provision_encoding_invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise ArenaPolicyProvisionError("provision_encoding_invalid") from None
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(canonical, value):
        raise ArenaPolicyProvisionError("provision_encoding_invalid")
    if len(raw) > maximum:
        raise ArenaPolicyProvisionError("provision_payload_too_large")
    if len(raw) < minimum:
        raise ArenaPolicyProvisionError("provision_encoding_invalid")
    return bytearray(raw)


def _strict_canonical_json_object(raw: bytes | bytearray) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON object key")
            output[key] = value
        return output

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        text = bytes(raw).decode("ascii")
        payload = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
        if not isinstance(payload, dict):
            raise ValueError("JSON root must be an object")
        if not hmac.compare_digest(bytes(raw), _canonical_json(payload)):
            raise ValueError("JSON is not canonical")
        return payload
    except (UnicodeDecodeError, ValueError, TypeError):
        raise ArenaPolicyProvisionError("provision_json_invalid") from None


def _publish_validated_policy(
    *,
    output_dir: Path,
    release: bytes | bytearray,
    evaluator: bytes | bytearray,
    release_sha256: str,
) -> None:
    release_stage: Path | None = None
    evaluator_stage: Path | None = None
    lock_fd: int | None = None
    try:
        _ensure_secure_directory(output_dir)
        lock_fd = _open_lock(output_dir / LOCK_FILENAME)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        release_stage = _write_staged_file(output_dir, "release", release)
        evaluator_stage = _write_staged_file(output_dir, "evaluator", evaluator)
        settings = Settings(
            arena_worker_release_manifest_path=str(release_stage),
            arena_worker_release_manifest_sha256=release_sha256,
            arena_worker_evaluator_path=str(evaluator_stage),
        )
        try:
            pins = load_release_manifest(settings)
        except ArenaWorkerBootstrapError:
            raise ArenaPolicyProvisionError("provision_release_invalid") from None
        try:
            load_sealed_evaluator(settings, pins=pins)
        except ArenaWorkerBootstrapError:
            raise ArenaPolicyProvisionError("provision_evaluator_invalid") from None

        # Worker startup is gated on this process exiting successfully.  The
        # evaluator is published first and the hash-pinned release last, then
        # the directory is synced before success is reported.
        os.replace(evaluator_stage, output_dir / EVALUATOR_FILENAME)
        evaluator_stage = None
        os.replace(release_stage, output_dir / RELEASE_FILENAME)
        release_stage = None
        _fsync_directory(output_dir)
        _assert_secure_regular(output_dir / RELEASE_FILENAME)
        _assert_secure_regular(output_dir / EVALUATOR_FILENAME)
    except ArenaPolicyProvisionError:
        raise
    except Exception:
        raise ArenaPolicyProvisionError("provision_output_unavailable") from None
    finally:
        for stage in (release_stage, evaluator_stage):
            if stage is not None:
                try:
                    stage.unlink(missing_ok=True)
                except OSError:
                    pass
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def _ensure_secure_directory(path: Path) -> None:
    if not path.is_absolute() or "\x00" in str(path):
        raise ArenaPolicyProvisionError("provision_output_unavailable")
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        details = path.lstat()
    except OSError:
        raise ArenaPolicyProvisionError("provision_output_unavailable") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.geteuid()
    ):
        raise ArenaPolicyProvisionError("provision_output_unavailable")


def _open_lock(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
        ):
            raise OSError("lock metadata is invalid")
        return fd
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise ArenaPolicyProvisionError("provision_output_unavailable") from None


def _write_staged_file(
    output_dir: Path,
    label: str,
    raw: bytes | bytearray,
) -> Path:
    path = output_dir / f".{label}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError("short secure write")
            written += count
        os.fsync(fd)
    except OSError:
        if fd is not None:
            os.close(fd)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ArenaPolicyProvisionError("provision_output_unavailable") from None
    else:
        os.close(fd)
    _assert_secure_regular(path)
    return path


def _assert_secure_regular(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or not 2 <= details.st_size <= MAX_SECURE_JSON_BYTES
    ):
        raise ArenaPolicyProvisionError("provision_output_unavailable")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ArenaPolicyProvisionError("provision_json_invalid") from None


def _zero(value: bytearray) -> None:
    if value:
        value[:] = b"\x00" * len(value)


if __name__ == "__main__":
    raise SystemExit(main())
