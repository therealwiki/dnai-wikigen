# Private Verified-Reward Environments

Standard RL environments over sealed reward data. Each environment lives in its
own directory here and follows the **verifiers v0** contract
(`load_environment(**env_args) -> vf.Environment`), which is prime-rl's native
env format and is also reachable from OpenEnv via `vf.OpenEnvEnv`. Targeting one
contract gives both ecosystems.

The project-specific constraint on top of the standard contract: these are
*private* reward environments. Exact rewards and raw data are computed and held
**inside the attested boundary**; only bounded reward bands, hashes, and
attestations leave. See `PROJECT.md` (Private Reward Environment, Sealed Data At
Rest) and `docs/BIO_VALIDATION.md`.

## Layout of an environment

```
environments/<name>/
  <name>.py            # module-level load_environment(**env_args) -> vf.Environment
  <name>_core.py       # framework-free core (numpy only): metrics + bounded reducer
  <name>_data.py       # dataset loading (heavy deps optional, fail closed if absent)
  datasets.json        # provenance manifest: source, license, md5, sensitivity
  fetch_datasets.py    # reproducible download into gitignored data/ (stdlib only)
  data/.gitignore      # raw data is fetched on demand, never committed
  pyproject.toml       # installable env (verifiers convention); heavy deps optional
  tests/               # offline tests for the framework-free core
```

## Design rules (so adding an env stays easy and honest)

1. **Framework-free core.** Put the reward math and the bounded reducer in a
   module that imports with numpy only. `verifiers`, `anndata`, `datasets`, and
   any trainer stack are imported lazily inside the wrapper / data loader, so
   the core is unit-testable offline and CI needs no heavy install.
2. **Bounded egress.** The reward function returns a *quantized band scalar*,
   never the exact continuous metric, and never raw data. Offline helpers
   return only band/sign fields with `raw_secret_egress=False`.
3. **Reproducible data, never committed.** `datasets.json` records source URL,
   md5, size, license, and a `data_sensitivity` label
   (`public_benchmark` / `private` / `phi`). `fetch_datasets.py` downloads into
   the gitignored `data/` dir and verifies md5. Raw `.h5ad`/dataset bytes are
   never committed.
4. **Fail closed.** If the dataset files or a heavy dep are missing, the loader
   raises a clear error rather than silently degrading.

## Current environments

- **`openproblems_denoising/`** — OpenProblems v1 single-cell RNA-seq denoising,
  the biology task from TTT-Discover (arXiv:2601.16175). Train on `pancreas`,
  report on held-out `tenx_1k_pbmc`. Reward is the OpenProblems denoising metric
  (log-normalized MSE gated by a Poisson constraint), banded by improvement over
  the depth-matched baseline. `data_sensitivity=public_benchmark` — encrypting
  it exercises the sealed-data mechanism but is not itself a privacy claim.

## Adding an environment

1. `cp -r openproblems_denoising <new_name>` and adapt, or scaffold with
   `vf init <new_name>` if `verifiers` is installed.
2. Keep the core framework-free; write the metric + bounded reducer there first
   with offline tests.
3. Fill `datasets.json` with real provenance (md5, license, sensitivity) and a
   stdlib `fetch_datasets.py`.
4. Expose `load_environment(**env_args)` returning a `vf.SingleTurnEnv` /
   `vf.MultiTurnEnv` whose rubric calls your bounded reward function.
5. Once the sealed-dataset CLIs land (see `TODO.md` "Sealed Data At Rest"), load
   `private`/`phi` datasets through the encrypted-at-rest path instead of a
   plaintext fetch.
