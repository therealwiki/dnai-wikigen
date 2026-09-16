#!/usr/bin/env python3
"""Fetch the exact offline tokenizer release used by the Compute worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import urllib.request
from pathlib import Path

from tinker_delegate.compute_provider_release import (
    PINNED_QWEN3_TOKENIZER_FILES,
    PINNED_QWEN3_TOKENIZER_MODEL,
    PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
    PINNED_QWEN3_TOKENIZER_REVISION,
)


def _download(file_name: str, *, maximum: int, timeout: float = 120.0) -> bytes:
    url = (
        "https://huggingface.co/"
        f"{PINNED_QWEN3_TOKENIZER_MODEL}/resolve/"
        f"{PINNED_QWEN3_TOKENIZER_REVISION}/{file_name}?download=true"
    )
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "dnai-wikigen-reproducible-build/1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.geturl().split(":", 1)[0].lower() != "https":
            raise RuntimeError("tokenizer download left HTTPS")
        body = response.read(maximum + 1)
        if len(body) > maximum or response.read(1):
            raise RuntimeError("tokenizer file exceeds its frozen byte length")
        return body


def install_tokenizer(output: Path, *, source_date_epoch: int) -> dict[str, object]:
    output = output.resolve(strict=False)
    if output.exists():
        raise RuntimeError("tokenizer output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))
    )
    try:
        for expected in PINNED_QWEN3_TOKENIZER_FILES:
            raw = _download(expected.path, maximum=expected.bytes)
            if len(raw) != expected.bytes:
                raise RuntimeError("tokenizer file byte length drifted")
            if hashlib.sha256(raw).hexdigest() != expected.sha256:
                raise RuntimeError("tokenizer file digest drifted")
            destination = temporary / expected.path
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o444,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
            os.chmod(destination, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            os.utime(destination, (source_date_epoch, source_date_epoch))
        os.chmod(temporary, 0o555)
        os.utime(temporary, (source_date_epoch, source_date_epoch))
        os.replace(temporary, output)
        parent_descriptor = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except Exception:
        if temporary.exists():
            os.chmod(temporary, 0o755)
            shutil.rmtree(temporary)
        raise
    return {
        "schema": "dnai.compute.tokenizer-install-receipt.v1",
        "model": PINNED_QWEN3_TOKENIZER_MODEL,
        "revision": PINNED_QWEN3_TOKENIZER_REVISION,
        "release_sha256": PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
        "file_count": len(PINNED_QWEN3_TOKENIZER_FILES),
        "raw_model_weights_downloaded": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()
    if args.source_date_epoch < 0:
        raise SystemExit("source date epoch must be nonnegative")
    receipt = install_tokenizer(
        args.output,
        source_date_epoch=args.source_date_epoch,
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
