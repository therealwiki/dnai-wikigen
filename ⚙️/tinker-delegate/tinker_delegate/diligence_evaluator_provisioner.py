"""One-shot, networkless provisioning of public Diligence evaluator authority.

The final OCI digest cannot be embedded in a policy inside that same image.
Release tooling therefore builds the image first, compiles the three policies
against a separately reproducible evaluator-bundle digest, and supplies the
canonical public manifest through Phala's reviewed environment channel. This
initializer authenticates those bytes with the independently projected
manifest SHA-256 and Solidity policy-set root before publishing one immutable
file on a dedicated volume. The delegate mounts that volume read-only.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import MutableMapping, Sequence, TextIO

from tinker_delegate.diligence_evaluator_registry import (
    DiligenceEvaluatorRegistryError,
    MAX_RELEASE_MANIFEST_BYTES,
    load_diligence_evaluator_registry_bytes,
)


DEFAULT_OUTPUT_DIR = Path("/sealed/diligence")
MANIFEST_FILENAME = "diligence-evaluator-release-v1.json"
DEFAULT_MANIFEST_PATH = DEFAULT_OUTPUT_DIR / MANIFEST_FILENAME
LOCK_FILENAME = ".provision.lock"

MANIFEST_B64_ENV = "TINKER_DILIGENCE_EVALUATOR_RELEASE_B64"
MANIFEST_PATH_ENV = "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH"
MANIFEST_SHA256_ENV = "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256"
POLICY_SET_ROOT_ENV = "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT"
PROVISION_ENV_NAMES = (
    MANIFEST_B64_ENV,
    MANIFEST_PATH_ENV,
    MANIFEST_SHA256_ENV,
    POLICY_SET_ROOT_ENV,
)

MAX_B64_CHARS = (MAX_RELEASE_MANIFEST_BYTES * 4 + 2) // 3
_B64URL_NOPAD = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")


class DiligenceEvaluatorProvisionError(RuntimeError):
    """Bounded public reason code for a failed provisioning attempt."""

    REASONS = frozenset(
        {
            "environment_inputs_only",
            "provision_configuration_missing",
            "provision_encoding_invalid",
            "provision_payload_too_large",
            "provision_hash_mismatch",
            "provision_release_invalid",
            "provision_output_conflict",
            "provision_output_unavailable",
            "provisioning_failed",
        }
    )

    def __init__(self, reason: str) -> None:
        if reason not in self.REASONS:
            reason = "provisioning_failed"
        self.reason = reason
        super().__init__(reason)


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="tinker-diligence-evaluator-provision",
        description=(
            "Provision the authenticated public Diligence evaluator manifest "
            "from reviewed environment inputs."
        ),
    )


def provision_from_environment(
    *,
    environ: MutableMapping[str, str] | None = None,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    expected_manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> Path:
    """Validate and atomically publish exactly one canonical release manifest."""

    source = os.environ if environ is None else environ
    values = {name: source.pop(name, "") for name in PROVISION_ENV_NAMES}
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise DiligenceEvaluatorProvisionError("provision_configuration_missing")

    output = Path(output_dir)
    expected_path = Path(expected_manifest_path)
    if expected_path != output / MANIFEST_FILENAME:
        raise DiligenceEvaluatorProvisionError("provision_configuration_missing")
    if values[MANIFEST_PATH_ENV] != str(expected_path):
        raise DiligenceEvaluatorProvisionError("provision_configuration_missing")

    expected_sha256 = values[MANIFEST_SHA256_ENV]
    expected_root = values[POLICY_SET_ROOT_ENV]
    if _SHA256.fullmatch(expected_sha256) is None or _BYTES32.fullmatch(expected_root) is None:
        raise DiligenceEvaluatorProvisionError("provision_configuration_missing")

    manifest = bytearray()
    try:
        manifest = _decode_manifest(values[MANIFEST_B64_ENV])
        observed = "sha256:" + hashlib.sha256(manifest).hexdigest()
        if not hmac.compare_digest(observed, expected_sha256):
            raise DiligenceEvaluatorProvisionError("provision_hash_mismatch")
        try:
            load_diligence_evaluator_registry_bytes(
                bytes(manifest),
                expected_manifest_sha256=expected_sha256,
                expected_policy_set_root=expected_root,
            )
        except DiligenceEvaluatorRegistryError:
            raise DiligenceEvaluatorProvisionError(
                "provision_release_invalid"
            ) from None
        return _publish_manifest(
            output_dir=output,
            manifest=manifest,
        )
    finally:
        for index in range(len(manifest)):
            manifest[index] = 0


def _decode_manifest(value: str) -> bytearray:
    if len(value) > MAX_B64_CHARS:
        raise DiligenceEvaluatorProvisionError("provision_payload_too_large")
    if (
        not value
        or _B64URL_NOPAD.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        raise DiligenceEvaluatorProvisionError("provision_encoding_invalid")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise DiligenceEvaluatorProvisionError("provision_encoding_invalid") from None
    if not decoded or len(decoded) > MAX_RELEASE_MANIFEST_BYTES:
        raise DiligenceEvaluatorProvisionError("provision_payload_too_large")
    return bytearray(decoded)


def _publish_manifest(
    *,
    output_dir: Path,
    manifest: bytearray,
) -> Path:
    directory_fd = -1
    try:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_fd = os.open(
            output_dir,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_stat = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise DiligenceEvaluatorProvisionError("provision_output_unavailable")
        os.fchmod(directory_fd, 0o700)
    except DiligenceEvaluatorProvisionError:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise
    except OSError:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise DiligenceEvaluatorProvisionError("provision_output_unavailable") from None

    lock_fd = -1
    temporary_name = ""
    try:
        lock_fd = os.open(
            LOCK_FILENAME,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
            raise DiligenceEvaluatorProvisionError("provision_output_unavailable")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked_stat = os.fstat(lock_fd)
        lock_path_stat = os.stat(
            LOCK_FILENAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(locked_stat.st_mode)
            or locked_stat.st_nlink != 1
            or stat.S_IMODE(locked_stat.st_mode) != 0o600
            or locked_stat.st_dev != lock_path_stat.st_dev
            or locked_stat.st_ino != lock_path_stat.st_ino
        ):
            raise DiligenceEvaluatorProvisionError("provision_output_unavailable")
        final_path = output_dir / MANIFEST_FILENAME
        try:
            existing_fd = os.open(
                MANIFEST_FILENAME,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            existing_fd = -1
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise DiligenceEvaluatorProvisionError("provision_output_unavailable") from None
            raise
        if existing_fd >= 0:
            try:
                existing_stat = os.fstat(existing_fd)
                if (
                    not stat.S_ISREG(existing_stat.st_mode)
                    or existing_stat.st_nlink != 1
                    or stat.S_IMODE(existing_stat.st_mode) != 0o600
                    or existing_stat.st_size <= 0
                    or existing_stat.st_size > MAX_RELEASE_MANIFEST_BYTES
                ):
                    raise DiligenceEvaluatorProvisionError("provision_output_unavailable")
                existing = bytearray()
                while True:
                    chunk = os.read(existing_fd, 65_536)
                    if not chunk:
                        break
                    existing.extend(chunk)
                    if len(existing) > MAX_RELEASE_MANIFEST_BYTES:
                        raise DiligenceEvaluatorProvisionError(
                            "provision_output_unavailable"
                        )
                after_stat = os.fstat(existing_fd)
                if (
                    len(existing) != existing_stat.st_size
                    or existing_stat.st_dev != after_stat.st_dev
                    or existing_stat.st_ino != after_stat.st_ino
                    or existing_stat.st_size != after_stat.st_size
                    or existing_stat.st_mtime_ns != after_stat.st_mtime_ns
                    or existing_stat.st_ctime_ns != after_stat.st_ctime_ns
                ):
                    raise DiligenceEvaluatorProvisionError(
                        "provision_output_unavailable"
                    )
            finally:
                os.close(existing_fd)
            try:
                if not hmac.compare_digest(bytes(existing), bytes(manifest)):
                    raise DiligenceEvaluatorProvisionError("provision_output_conflict")
            finally:
                for index in range(len(existing)):
                    existing[index] = 0
            final_stat = os.stat(
                MANIFEST_FILENAME,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                final_stat.st_dev != existing_stat.st_dev
                or final_stat.st_ino != existing_stat.st_ino
            ):
                raise DiligenceEvaluatorProvisionError(
                    "provision_output_unavailable"
                )
            path_stat = output_dir.lstat()
            if (
                not stat.S_ISDIR(path_stat.st_mode)
                or path_stat.st_dev != directory_stat.st_dev
                or path_stat.st_ino != directory_stat.st_ino
            ):
                raise DiligenceEvaluatorProvisionError(
                    "provision_output_unavailable"
                )
            return final_path

        temporary_name = (
            f".{MANIFEST_FILENAME}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            temporary_stat = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(temporary_stat.st_mode)
                or temporary_stat.st_nlink != 1
            ):
                raise DiligenceEvaluatorProvisionError(
                    "provision_output_unavailable"
                )
            os.fchmod(temporary_fd, 0o600)
            view = memoryview(manifest)
            written = 0
            while written < len(view):
                written += os.write(temporary_fd, view[written:])
            os.fsync(temporary_fd)
            written_stat = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(written_stat.st_mode)
                or written_stat.st_nlink != 1
                or stat.S_IMODE(written_stat.st_mode) != 0o600
                or written_stat.st_size != len(manifest)
            ):
                raise DiligenceEvaluatorProvisionError(
                    "provision_output_unavailable"
                )
        finally:
            os.close(temporary_fd)
        try:
            os.link(
                temporary_name,
                MANIFEST_FILENAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise DiligenceEvaluatorProvisionError(
                "provision_output_conflict"
            ) from None
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = ""
        os.fsync(directory_fd)
        final_stat = os.stat(
            MANIFEST_FILENAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(final_stat.st_mode)
            or final_stat.st_nlink != 1
            or stat.S_IMODE(final_stat.st_mode) != 0o600
            or final_stat.st_size != len(manifest)
            or final_stat.st_dev != written_stat.st_dev
            or final_stat.st_ino != written_stat.st_ino
        ):
            raise DiligenceEvaluatorProvisionError(
                "provision_output_unavailable"
            )
        path_stat = output_dir.lstat()
        if (
            not stat.S_ISDIR(path_stat.st_mode)
            or path_stat.st_dev != directory_stat.st_dev
            or path_stat.st_ino != directory_stat.st_ino
        ):
            raise DiligenceEvaluatorProvisionError(
                "provision_output_unavailable"
            )
        return final_path
    except DiligenceEvaluatorProvisionError:
        raise
    except OSError:
        raise DiligenceEvaluatorProvisionError("provision_output_unavailable") from None
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(directory_fd)


def _status(stream: TextIO, *, provisioned: bool, reason: str | None = None) -> None:
    # Fixed literal JSON avoids accidentally serializing authority payloads.
    if provisioned:
        stream.write(
            '{"authority_payload_egress":false,"network_required":false,'
            '"provisioned":true,"surface":"diligence_evaluator_provisioner"}\n'
        )
    else:
        bounded = (
            reason
            if reason in DiligenceEvaluatorProvisionError.REASONS
            else "provisioning_failed"
        )
        stream.write(
            '{"authority_payload_egress":false,"network_required":false,'
            f'"provisioned":false,"reason":"{bounded}",'
            '"surface":"diligence_evaluator_provisioner"}\n'
        )
    stream.flush()


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: MutableMapping[str, str] | None = None,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    expected_manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    stdout: TextIO | None = None,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    stream = sys.stdout if stdout is None else stdout
    if args:
        if args in (["-h"], ["--help"]):
            build_parser().print_help(file=stream)
            return 0
        _status(stream, provisioned=False, reason="environment_inputs_only")
        return 64
    try:
        provision_from_environment(
            environ=environ,
            output_dir=output_dir,
            expected_manifest_path=expected_manifest_path,
        )
    except DiligenceEvaluatorProvisionError as exc:
        _status(stream, provisioned=False, reason=exc.reason)
        return 78
    except Exception:
        _status(stream, provisioned=False, reason="provisioning_failed")
        return 70
    _status(stream, provisioned=True)
    return 0


__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_OUTPUT_DIR",
    "DiligenceEvaluatorProvisionError",
    "MANIFEST_B64_ENV",
    "MANIFEST_FILENAME",
    "MANIFEST_PATH_ENV",
    "MANIFEST_SHA256_ENV",
    "POLICY_SET_ROOT_ENV",
    "main",
    "provision_from_environment",
]
