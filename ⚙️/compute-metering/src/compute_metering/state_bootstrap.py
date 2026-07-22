"""Prepare the persistent replay volume for the non-root metering process."""

from __future__ import annotations

import os
import stat
from pathlib import Path


STATE_VOLUME = "/var/lib/compute-metering-data"
STATE_DIRECTORY = "/var/lib/compute-metering-data/state"
RUNTIME_UID = 65532
RUNTIME_GID = 65532


def prepare_state_directory(path_value: str = STATE_DIRECTORY) -> None:
    path = Path(path_value)
    if not path.is_absolute() or path.name != "state" or str(path.parent) != STATE_VOLUME:
        raise RuntimeError("invalid state directory")
    parent = path.parent
    parent_before = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_ISLNK(parent_before.st_mode)
        or parent_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError("state volume is not a secure directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, flags)
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=descriptor)
        except FileExistsError:
            pass
        before = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise RuntimeError("state path is not a directory")
        # With every capability dropped except CHOWN, take temporary ownership
        # before chmod; after the final chown root no longer has FOWNER.
        os.chown(path.name, 0, 0, dir_fd=descriptor, follow_symlinks=False)
        os.chmod(path.name, 0o700, dir_fd=descriptor, follow_symlinks=False)
        os.chown(path.name, RUNTIME_UID, RUNTIME_GID, dir_fd=descriptor, follow_symlinks=False)
        after = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o700
            or after.st_uid != RUNTIME_UID
            or after.st_gid != RUNTIME_GID
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
        ):
            raise RuntimeError("state directory ownership did not converge")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    try:
        prepare_state_directory()
    except Exception:
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
