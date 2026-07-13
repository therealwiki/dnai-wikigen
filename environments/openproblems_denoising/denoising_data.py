"""Dataset loading for the OpenProblems denoising env.

Reads the real `.h5ad` splits fetched by `fetch_datasets.py`. `anndata` is an
optional dependency: the module imports without it, and the real-data path
fails closed with a clear message if it is missing or the files are absent.
Unit tests inject numpy arrays directly and never touch this loader.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
MANIFEST = HERE / "datasets.json"

# TTT-Discover mapping: train the policy on pancreas; report on held-out PBMC.
DEFAULT_TRAIN = "pancreas"
DEFAULT_EVAL = "tenx_1k_pbmc"


class DatasetUnavailable(RuntimeError):
    """Raised when the real dataset cannot be loaded (missing dep or files)."""


def _require_anndata():
    try:
        import anndata  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise DatasetUnavailable(
            "anndata is required to read the OpenProblems .h5ad splits. "
            "Install the env extra (anndata, scipy) and run fetch_datasets.py."
        ) from exc
    return anndata


def _counts(adata) -> np.ndarray:
    """Extract a dense count matrix from an AnnData, preferring the counts layer."""

    matrix = adata.layers["counts"] if "counts" in adata.layers else adata.X
    if hasattr(matrix, "toarray"):
        matrix = matrix.toarray()
    return np.asarray(matrix, dtype=np.float64)


def dataset_dir(name: str) -> Path:
    return DATA_DIR / name


def load_counts(name: str, split: str) -> np.ndarray:
    """Load a count matrix for `<name>/<split>.h5ad` (split in {train,test})."""

    path = DATA_DIR / name / f"{split}.h5ad"
    if not path.exists():
        raise DatasetUnavailable(
            f"missing {path}. Run: python environments/openproblems_denoising/"
            "fetch_datasets.py --tier all"
        )
    anndata = _require_anndata()
    adata = anndata.read_h5ad(path)
    return _counts(adata)


def load_split_pair(name: str) -> tuple[np.ndarray, np.ndarray]:
    """Return (train_counts, test_counts) for a dataset name."""

    return load_counts(name, "train"), load_counts(name, "test")


def manifest_datasets() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def available() -> bool:
    """True if the core train/eval files exist locally (no anndata needed)."""

    for name in (DEFAULT_TRAIN, DEFAULT_EVAL):
        for split in ("train", "test"):
            if not (DATA_DIR / name / f"{split}.h5ad").exists():
                return False
    return True
