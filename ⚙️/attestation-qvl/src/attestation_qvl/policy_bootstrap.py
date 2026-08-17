"""Materialize a reviewed public policy into the QVL's read-only volume."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import stat
from pathlib import Path

from .errors import QvlServiceError, VerifierUnavailable
from .models import MAX_POLICY_BYTES
from .policy import LoadedReleasePolicy, validate_release_policy_bytes


POLICY_ENV = "QVL_RELEASE_POLICY_B64"
POLICY_TARGET = "/run/qvl/release-policy.json"
MAX_POLICY_B64_CHARS = 4 * ((MAX_POLICY_BYTES + 2) // 3)


def decode_policy_environment(encoded: str) -> LoadedReleasePolicy:
    if not isinstance(encoded, str) or not 4 <= len(encoded) <= MAX_POLICY_B64_CHARS:
        raise VerifierUnavailable
    try:
        ascii_value = encoded.encode("ascii", errors="strict")
        raw = base64.b64decode(ascii_value, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise VerifierUnavailable from exc
    return validate_release_policy_bytes(raw)


def materialize_policy(encoded: str, target_value: str = POLICY_TARGET) -> LoadedReleasePolicy:
    target = Path(target_value)
    if not target.is_absolute() or target.name != "release-policy.json":
        raise VerifierUnavailable
    release = decode_policy_environment(encoded)
    parent = target.parent
    try:
        before = os.lstat(parent)
    except OSError as exc:
        raise VerifierUnavailable from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise VerifierUnavailable

    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    temporary_name = f".release-policy.{os.getpid()}.{secrets.token_hex(8)}.tmp"
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
            raise VerifierUnavailable
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
                raise VerifierUnavailable
            written += count
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        created = False
        os.fsync(directory_fd)
    except QvlServiceError:
        raise
    except OSError as exc:
        raise VerifierUnavailable from exc
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
