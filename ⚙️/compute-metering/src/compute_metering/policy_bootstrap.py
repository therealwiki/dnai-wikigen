"""Materialize a reviewed public policy from Phala's encrypted environment."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import stat
from pathlib import Path

from .errors import MeteringError, StateUnavailable
from .models import MAX_POLICY_BYTES
from .policy import LoadedPolicySet, validate_policy_set_bytes


POLICY_ENV = "METERING_POLICY_SET_B64"
POLICY_TARGET = "/run/compute-metering/policy-set.json"
MAX_POLICY_B64_CHARS = 4 * ((MAX_POLICY_BYTES + 2) // 3)


def decode_policy_environment(encoded: str) -> LoadedPolicySet:
    if not isinstance(encoded, str) or not 4 <= len(encoded) <= MAX_POLICY_B64_CHARS:
        raise StateUnavailable
    try:
        raw = base64.b64decode(encoded.encode("ascii", errors="strict"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise StateUnavailable from exc
    try:
        return validate_policy_set_bytes(raw)
    except MeteringError as exc:
        raise StateUnavailable from exc


def materialize_policy(encoded: str, target_value: str = POLICY_TARGET) -> LoadedPolicySet:
    target = Path(target_value)
    if not target.is_absolute() or target.name != "policy-set.json":
        raise StateUnavailable
    release = decode_policy_environment(encoded)
    parent = target.parent
    try:
        before = os.lstat(parent)
    except OSError as exc:
        raise StateUnavailable from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise StateUnavailable

    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    temporary_name = f".policy-set.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    directory_fd = -1
    file_fd = -1
    created = False
    try:
        directory_fd = os.open(parent, directory_flags)
        opened_directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or opened_directory.st_dev != before.st_dev
            or opened_directory.st_ino != before.st_ino
        ):
            raise StateUnavailable
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(temporary_name, file_flags, 0o444, dir_fd=directory_fd)
        created = True
        os.fchmod(file_fd, 0o444)
        view = memoryview(release.canonical_bytes)
        written = 0
        while written < len(view):
            count = os.write(file_fd, view[written:])
            if count <= 0:
                raise StateUnavailable
            written += count
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1
        os.replace(temporary_name, target.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        created = False
        os.fsync(directory_fd)
    except MeteringError:
        raise
    except OSError as exc:
        raise StateUnavailable from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if created and directory_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd >= 0:
            os.close(directory_fd)
    return release


def main() -> None:
    encoded = os.environ.pop(POLICY_ENV, "")
    try:
        materialize_policy(encoded)
    except Exception:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
