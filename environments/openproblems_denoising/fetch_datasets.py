#!/usr/bin/env python3
"""Reproducibly fetch the OpenProblems v1 denoising datasets used by TTT-Discover.

The raw `.h5ad` files are NOT committed. This script downloads them on demand
into the gitignored `data/` directory next to this file and verifies each file
against the committed MD5 in `datasets.json`. Public benchmark data only.

Usage:
    python fetch_datasets.py                # core tier (pancreas + 1k pbmc, ~120MB)
    python fetch_datasets.py --tier all     # core + extended (5k pbmc too)
    python fetch_datasets.py --verify-only  # re-check existing files, no download

This is deliberately dependency-free (stdlib only) so it runs anywhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "datasets.json"
DATA_DIR = HERE / "data"


def _load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _selected(manifest: dict, tier: str) -> dict[str, dict]:
    files = manifest["files"]
    if tier == "all":
        return files
    return {name: meta for name, meta in files.items() if meta.get("tier") == "core"}


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url) as response, tmp.open("wb") as out:  # noqa: S310
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=["core", "all"], default="core")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)

    manifest = _load_manifest()
    http_base = manifest["source"]["http_base"].rstrip("/") + "/"
    selected = _selected(manifest, args.tier)

    failures: list[str] = []
    for name, meta in selected.items():
        dest = DATA_DIR / name
        url = http_base + meta["key"]
        if not dest.exists():
            if args.verify_only:
                print(f"MISSING  {name}")
                failures.append(name)
                continue
            size_mb = meta["size_bytes"] / 1e6
            print(f"fetching {name} ({size_mb:.1f} MB) ...")
            _download(url, dest)
        actual = _md5(dest)
        if actual != meta["md5"]:
            print(f"MD5 MISMATCH {name}: expected {meta['md5']} got {actual}")
            failures.append(name)
        else:
            print(f"OK       {name}  ({dest.stat().st_size} bytes, md5 {actual[:12]})")

    if failures:
        print(f"\n{len(failures)} file(s) failed verification.", file=sys.stderr)
        return 1
    print(f"\nAll {len(selected)} file(s) verified in {DATA_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
