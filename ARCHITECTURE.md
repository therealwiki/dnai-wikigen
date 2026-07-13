# dnai-wikigen Architecture

This document describes the full `dnai-wikigen` architecture as it exists in this
repository: the attested diligence room, the TEE-hosted email oracle, the Tinker
delegate, the NDAI escrow contracts, the data-room adapters, and the planned
TTT/RL bio-validation layer.

The short version:

```
Email encumbered contract <--> Tinker encumbered contract <--> TTT/RL bio validation
              |                            |                              |
              v                            v                              v
      tee-email-oracle            tinker-delegate                 bounded evaluator
              \                            |                              /
               \                           v                             /
                +-----------------------> DNAI <-------------------------+
                                  attested diligence room
```

In production terms, the project is an **attested diligence room**. A seller or
data controller brings private material into a TEE. A buyer, sponsor, or
delegated scientific agent can inspect it only through an attested evaluator.
Only bounded outputs leave the boundary: score bands, yes/no decisions, hashes,
offers within a budget cap, and audit attestations.

## Status Legend

```
[real]      Code exists and can be compiled, imported, tested, or deployed.
[partial]   Code exists but the end-to-end path is incomplete or externally blocked.
[modeled]   The shape is documented or stubbed, but enforcement is not complete.
[planned]   Architecture target only.
```

## 2026-07-13: Tinker delegate custody + delegation layer — `[real]`, validated live

The `tinker-delegate` middle pillar is no longer scaffold. Validated live on the
deployed CVM (`cvm_1w85mGjo`), all bounded and attested:

- **`[real]` Full upstream API-key lifecycle over in-TEE CDP.** create /
  named-create / list / delete of `tml-...` keys against the real Tinker
  console; bounded receipts; the account email is only ever a hash. Delete
  submits the console's own Remix form via an authenticated in-page fetch.
  (`tinker_delegate/tinker_keys.py`; `POST /tinker/keys/{list,create,delete}`.)
- **`[real]` Encumbered Tinker proxy — scoped, encrypted, revocable.** The
  sealed upstream key stays in the enclave; downstream principals get only
  x25519-enveloped, HS256-signed, scope-limited JWTs. Verified end-to-end:
  issue → decrypt → verify → scope-enforce → revoke.
  (`tinker_delegate/tinker_proxy.py`; `test_tinker_proxy_roundtrip.py`.)
- **`[real]` Governed redeploy preserving sealed custody.** CI reproducible
  build → on-chain `approveComposeHash` (`TinkerAccountEncumbrance`) → Phala
  provision/commit → sealed key survives the new measurement.
  (`scripts/approve-compose-hash.sh`.)
- **`[real]` Delegated training via scoped proxy token.** A spend-limited
  `tinker:train` JWT drives `POST /tinker/train` through the real endpoint:
  verify → scope → spend-limit → create → forward/backward + optim per step →
  checkpoint → bounded receipt (`training_completed`); wrong-scope/over-limit
  tokens refused first. Only the compute backend is synthetic; the live CVM
  reaches the real Tinker SDK inside the TEE.
  (`tinker_delegate/tinker_training.py`; `test_proxy_train_e2e.py`.)
- **`[real]` Adversarially hardened.** Proxy JWT attacks (alg-confusion/none,
  tamper, cross-key forgery, iss/aud/nbf/expiry spoof, ttl/scope abuse) fail
  closed; bounded-output secret-scans found and fixed a full-key egress in the
  key parser; the training meter cap provably aborts runaway spend.
  (`test_tinker_proxy_adversarial.py`, `test_bounded_output_secrets.py`.)

**`[real]` by design: end users reach training only through the proxy, never the
raw account.** The proxy-mediated delegated-training path is built and validated
end-to-end. Running *real* jobs is operational provisioning, not an architectural
gap: the upstream Tinker account must be billing-active (funded $20 with a card
on file; a routine account step activates it) and the CVM must hold a current
valid sealed key. A raw API call to Tinker with the raw upstream key is outside
the product surface and is expected to fail — end users are scoped-JWT holders
who never see the account or its key.

Important current status:

```
[real]      DiligenceRoom.sol escrow state machine and tests. Settles in native
            ETH or an ERC20 stablecoin (per-deal `paymentToken`; `fundDealERC20`
            + `withdraw(token)` with bool-checked safe transfers; identical
            settlement math for both). The protocol fee is a governable `feeBps`
            (default 1%, capped at 10%) behind a 2-day timelock
            (`proposeFeeBps`/`activateFeeBps`/`cancelFeeBpsProposal`) and a
            permanent `freezeFeeBps`; the fee is locked onto each Deal at
            `submitResult` time so changes never retroact on evaluated deals. 110
            Foundry tests incl. ERC20 lifecycles, settlement-conservation fuzz
            (native + ERC20 accept/reject/expire, 256 runs each), fee-governance,
            compose/identity gates, and reentrancy. Compiled with `via_ir`. Note:
            the live-deployed room predates the ERC20/gate/fee ABI and needs a
            redeploy to expose them. The off-chain submitter reads `feeBps()`
            on-chain for its over-budget preflight (falling back to the 1% default
            for pre-governable-fee deployments), so the preflight stays consistent
            with the contract if the fee changes.
[real]      EmailOracleAuth.sol app-auth contract and tests.
[real]      tee-email-oracle FastAPI service, sealed credential store, IMAP OTP path.
[real]      Inbound-email prompt-injection defense (`inbound_email_safety.py`):
            inbound email is untrusted observed content, so
            `extract_inbound_email` pulls ONLY structured tokens, fail-closed — an
            OTP only when exactly one code of an expected length appears (ambiguous
            /none -> none, and a code embedded in a longer number is ignored),
            confirmation links only for allowlisted hosts (no allowlist -> none),
            injection markers (ignore-previous / system:/assistant: / forward /
            api-key / seed-phrase ...) flagged not obeyed, and the raw body hashed,
            never returned. The OTP is retained for in-boundary auth but hashed in
            the bounded output. This enforces "never hand an arbitrary email body
            to an agent" as a pure extractor (`tests/test_inbound_email_safety.py`,
            10). `[partial]`: not yet wired into the deployed oracle inbound path.
[real]      Mailbox retention (`mailbox_retention.py`): the companion that
            minimizes how long secret-bearing email survives —
            `decide_message_disposition` DELETEs a consumed message (once its token
            is extracted), or REDACT_FOR_AUDITs it (raw body dropped, metadata kept)
            only when audit retention is explicitly enabled and within its TTL; an
            unconsumed message is RETAINed briefly then expired. Fail-closed toward
            deletion, clock-skew-safe, bounded output
            (`tests/test_mailbox_retention.py`, 9). `[partial]`: not yet wired into
            the deployed oracle's IMAP delete/redact path.
[partial]   tinker-delegate service, browser automation, billing channel, API key store.
            Local Neko login, OTP, onboarding, API-key provisioning, and
            test-card billing rejection are validated. Deployed CVM login,
            full API-key lifecycle (create / named-create / list / delete) via
            in-TEE CDP, API-key sealing, reauth, bounded card-on-file status, and
            a funded `$20.00` balance (topped from the initial $10 validation
            lane) are real and validated live; production/repeated funding
            remains open.
[partial]   IsolatedTinkerSession and bounded control plane. Artifact ingress
            now has mocked-SDK coverage for one-run enforcement, mandatory
            checkpoint TTL, path-checked sampling, cleanup, and metering.
            Artifact ingress decrypts quote-key-encrypted artifact uploads and
            verifies Ethereum keccak256 against the committed artifactHash
            before storing the upload in memory.
[real]      Local synthetic room harness. `ControlPlane` can accept an injected
            service-client factory for source/model tests while production still
            constructs the real Tinker `ServiceClient` by default. The local
            harness encrypts a synthetic private artifact to the TEE public key,
            uploads it through the encrypted artifact endpoint, evaluates via
            `IsolatedTinkerSession`, and emits a bounded modeled packet with
            artifact hash, size/spend bands, score band, result hash, cleanup
            counts, and explicit no-egress booleans.
[modeled]   `FakeTinkerServiceClient` models training, sampler, checkpoint, and
            REST cleanup calls for CI/offline diligence-room tests. It is not
            deployed Phala evidence, not a real Tinker SDK run, and not on-chain
            settlement evidence.
[real]      PrivateRewardEnvironment interface and leakage accounting types.
            The base contract exposes public problem/schema metadata, query
            budget, optimizer placement policy, reward precision policy,
            bounded feedback, transcript hash, leakage hash, and attestable
            environment metadata.
[real]      Local PythonCandidateSandbox for toy private-reward environments.
            It runs candidate source in a subprocess with scratch cwd,
            stripped environment, deterministic seed, timeout, capped
            stdout/stderr, timing bands, public failure-code buckets, static
            preflight, and runtime import/file guards.
[real]      HiddenHoldoutSet split/accounting contract for private reward
            datasets. It creates train/reward/final-validation partitions,
            exposes public counts and split commitments, tracks reward-query
            counts, caps repeated candidate probes, requires minimum unique
            candidates before final validation, and gates final validation to
            bounded use.
[real]      Ladder-gated reward release (`ladder_release.py`), the overfitting
            defense for a *reused* sealed holdout — separate from the leakage
            axis: an adaptive optimizer can grind a fixed reward oracle into a
            meaningless number without ever reconstructing a record. Implements
            the fixed-`η` Ladder mechanism (Blum & Hardt 2015, §3; grounding
            paper `📄/ladder/paper.md`) in the reward convention: keep the running
            best, advance the leaderboard only when a candidate beats it by more
            than a margin `η = 1/D`, and quantize every released value to the
            `η`-grid. Because rewards live in `[0,1]` there are at most `D` genuine
            improvement steps regardless of how many submissions arrive, so
            leaderboard error grows only logarithmically in the submission count
            `k` (vs the `√k` decay of a release-every-score board) — a fixed-size
            sealed holdout therefore supports effectively unlimited attempts while
            the settled number stays honest. Egress is bounded by construction:
            the candidate's internal score is a float that never leaves; every
            release carries only the integer `leaderboard_step_index` over
            `step_denominator` (the intended public leaderboard number) plus
            counts, so `LadderRelease.to_public_dict()` / `public_manifest()` pass
            `assert_bounded_egress` (no float, array, or smuggled reward). Choosing
            `D` is choosing a point on the utility (finer optimizer signal) /
            safety (less overfitting leakage) frontier. Proven by
            `tests/test_ladder_release.py` (12): quantization, monotonic best, the
            `≤ D` improvement-step cap, the `η`-margin gate, determinism, bounded
            egress, and the paper's adaptive-random-attack property (5000 adaptive
            submissions yield <40 accepted improvements).
[real]      Ladder gate wired into `DenoisingHoldoutEnvironment` (opt-in via
            `ladder_policy`). When set, each reward query feeds the continuous
            internal MSE-improvement score (zeroed when the candidate worsens
            Poisson NLL — the same domain anti-overfitting rule that caps the raw
            band) into the leaderboard, and `output_reducer` releases the
            *running-best leaderboard band* (`_ladder_band`) instead of the raw
            per-candidate band. The released band is therefore monotonic
            non-decreasing: after a strong candidate sets the board, a subsequent
            weak probe re-releases the best rather than a low band, so repeated
            adaptive querying of the reused holdout cannot move the settled number.
            The Ladder policy is folded into `problem()` metadata, `environment_hash`,
            and `leakage_hash` (the mechanism a third party audits), and the
            bounded Ladder manifest (submission/improvement counts, best index) is
            recorded in the `finalize()` attestation. `ladder_policy=None` is fully
            backward-compatible (all pre-existing denoising tests green).
            `tests/test_denoising_ladder_gate.py` (5) prove monotonic-best release,
            weak-after-strong re-release, improvement accounting, audited public
            surfaces, and bounded egress of the gated feedback + final result. The
            same opt-in gate is wired into `SyntheticHiddenKeywordEnvironment`
            (whose internal `value` is already a normalized [0,1] match fraction,
            fed straight to the leaderboard; band mapping via its own `_score_band`
            thresholds), proving the mechanism generalizes across environments with
            different score semantics (`tests/test_synthetic_ladder_gate.py`, 5).
            `[partial]`: both concrete envs are wired; `private_reward_holdout.py`
            itself still exposes only the plain query accounting (envs own the
            score→band mapping, so the gate lives at the env layer by design).
[real]      Parameter-free (paired-t) Ladder variant (`PairedTLadderLeaderboard`,
            §4 of the paper). Removes the awkward fixed-`η` tuning: instead of a
            hand-set margin, it releases a new best only when the candidate's
            per-example score vector is *statistically significantly* above the
            previous best's, by a one-sided paired t-test with the running
            threshold `s/√n` (`s = std(new − prev)`), rounding the released mean to
            `1/n`. It is deterministic (no DP noise), which suits a TEE gate — same
            vectors always yield the same release — and demonstrably overfitting-
            resistant: a candidate that merely jiggles around the previous best
            (zero-mean noise) or has a positive-but-not-significant mean does NOT
            advance the board, while a genuine uniform improvement does. Egress
            stays bounded: the released leaderboard number is the integer
            `leaderboard_numerator` over the per-example vector length
            `denominator`, so `to_public_dict()` / `public_manifest()` pass
            `assert_bounded_egress`. `tests/test_ladder_release.py` (now 21) prove
            the significance gate, noise/high-variance rejection, non-regression,
            determinism, length-stability, validation, and bounded egress.
            Wired into `DenoisingHoldoutEnvironment` (opt-in `paired_t_ladder=True`,
            mutually exclusive with the fixed-η `ladder_policy`): it gates on the
            continuous per-cell MSE-improvement vector (`per_cell_mse_improvement`,
            one entry per cell, zeroed on Poisson-NLL worsening) and releases the
            significance-gated running-best band, so a weak candidate after a strong
            one re-releases the best (monotonic). Folded into the env's audited
            surfaces (problem metadata / `environment_hash` / `leakage_hash` /
            finalize manifest) and backward-compatible (default off; all pre-existing
            denoising tests green). `tests/test_denoising_paired_t_gate.py` (6).
[real]      Thresholdout DP-noised reusable-holdout gate (`thresholdout.py`,
            `ThresholdoutGate`; Dwork et al. 2015), the leakage-axis counterpart to
            the Ladder. Given a candidate's reward-partition statistic (which the
            optimizer already knows) and a fresh holdout statistic, it re-releases
            the reward stat for *free* while they agree within a noisy threshold,
            and consults the holdout — spending DP budget through the shared
            `DpAccountant` — only on divergence (the sign of overfitting). So a
            fixed sealed holdout answers cheaply under adaptive querying and the
            per-record leakage budget composes with the query budget into one
            stated bound: `total leakage ≤ ε × holdout-accesses`. Band-preserving:
            the Laplace noise gates *which partition's band to release* and
            perturbs the value BEFORE quantization, so only a coarse band index +
            counts egress — no un-noised real leaves — and the release passes
            `assert_bounded_egress`. Fails closed (no band) when the DP budget is
            exhausted; requires a DP-mode accountant. Deterministic under an
            injected noise fn (default draws Laplace from `os.urandom`).
            `tests/test_thresholdout.py` (11) prove the free-tracking path, the
            budget-spending divergence path, exhaustion fail-closed,
            threshold-noise gating, determinism, bounded egress, and the
            `ε × accesses` leakage bound. Exercised end-to-end by the
            `thresholdout-demo` CLI (`run_thresholdout_demo`), which runs a scripted
            stream — free-tracking candidates vs. budget-spending divergences until
            exhaustion — and emits a bounded packet (band releases + counts + public
            DP ledger; `tests/test_thresholdout_demo.py`, 5). `[partial]`: the gate
            + demo are real; wiring into a live env's reward/holdout split is a
            follow-up (as with the Ladder). NOTE: previously deferred as "too
            speculative"; a principled band-preserving adaptation exists, so it is
            now built.
[real]      SyntheticHiddenKeywordEnvironment toy private-reward environment.
            It wires HiddenHoldoutSet into bounded reward feedback and
            one-shot final validation over sealed synthetic records.
[real]      DenoisingHoldoutEnvironment concrete private-reward environment
            (`private_reward_envs/denoising.py`). It wires HiddenHoldoutSet
            train/reward/final-validation partitions into the OpenProblems-style
            single-cell denoising reward AND scores candidate *programs* (not
            precomputed matrices): each candidate is a UTF-8 Python
            `denoise(train)` program run through PythonCandidateSandbox with the
            relevant partition's train matrix embedded, its denoised output
            parsed from bounded stdout and scored against held-out test counts
            inside the boundary. Only a coarse `RewardBand` egresses; exact MSE/
            Poisson values stay internal. Domain anti-overfitting rule: a
            candidate that worsens Poisson NLL vs the depth-matched baseline is
            capped to `negligible`. Sandbox failures (banned import, timeout,
            wrong shape, truncated output) fail closed to `negligible`. A pure-
            Python metric core (no numpy) keeps it dependency-free and
            unit-tested (`tests/test_denoising_holdout_env.py`, 11 tests); the
            `denoising-private-reward-demo` CLI emits the bounded packet. This is
            a toy-scale mechanism proof — the sandbox exposes no numpy, so only
            small matrices within the source/stdout caps run here.
[real]      BioAssayRewardEnvironment concrete private-reward environment
            (`private_reward_envs/bio_assay.py`) — the first bio environment the
            optimizer-agnostic RLVR loop drives end-to-end. A candidate is a
            canonical-JSON synthetic assay-QC config (numeric positive/negative
            control replicates only; unknown keys and string values are rejected,
            so no dual-use free text or raw record content can ride in on a
            candidate). The private, TEE-held verifier is the Z'-factor
            screening-assay quality metric (reused from `bio_evaluators`); the
            exact Z' is the internal reward and is discarded — only a coarse
            `RewardBand` egresses, and `internal_reward_for_optimizer()` stays
            denied under the default external-bounded policy. `BioAssayCandidateSource`
            is a deterministic domain search space (tighten control spread / widen
            signal window) so the swappable optimizers all drive it and
            hill-climb converges to a HIGH band. Synthetic-only, no dual-use
            content, consistent with `docs/BIO_VALIDATION.md`'s first safe use
            case. Unit-tested (`tests/test_bio_assay_reward_env.py`, 8 tests);
            `run_bio_assay_reward_demo()` emits the bounded deterministic packet.
            The real (non-synthetic) computational-bio candidate space and a
            Tinker-backed optimizer remain `[planned]`.
[real]      BioAssayProgramEnvironment concrete private-reward environment
            (`private_reward_envs/bio_assay_program.py`) — the program-candidate
            counterpart of BioAssayRewardEnvironment. The candidate is a UTF-8
            Python `process(positive_wells, negative_wells)` QC program run through
            `PythonCandidateSandbox` (math/random only, no I/O), reusing the
            DenoisingHoldoutEnvironment program-execution pattern. It processes
            *sealed* raw plate readings into cleaned controls, and the private
            verifier scores the Z'-factor of the result. Anti-fabrication guard:
            every returned value must be a multiset member of the corresponding
            sealed wells, so a program may drop outliers but cannot fabricate
            values or move positives into the negative set to game the reward —
            fabrication, swaps, too-few controls, and banned-I/O all fail closed
            to `negligible`. Exact Z' and raw readings never egress; only a coarse
            `RewardBand` does. `BioAssayProgramCandidateSource` supplies an
            interchangeable QC-program library so all three optimizers drive it
            and hill-climb selects a robust outlier-removal program to a HIGH band.
            Unit-tested (`tests/test_bio_assay_program_env.py`, 10 tests);
            `run_bio_assay_program_demo()` emits the bounded packet. The
            `bio-assay-qc-reward-demo` operator CLI drives the environment over a
            library of candidate QC programs against sealed plate readings and
            emits only bounded per-candidate reward bands, final result, and
            attestation — the sealed well readings are enforced absent from the
            output by the CLI leakage guard (`bio_assay_program_demo_forbidden_values`),
            same pattern as `denoising-private-reward-demo`
            (`tests/test_bio_assay_program_demo.py` + a CLI subprocess test in
            `tests/test_cli_bounded_outputs.py`). Like the denoising env this is a
            toy-scale mechanism proof — the local sandbox is a dev guardrail, so
            production container isolation for hostile candidate code remains
            `[partial]`.
[real]      Standard-format RL env packaging under `environments/`. The first
            env, `openproblems_denoising/`, is the TTT-Discover biology task
            (OpenProblems v1 single-cell denoising) packaged to the verifiers
            v0 contract (`load_environment(**env_args) -> vf.Environment`),
            which is prime-rl-native and reachable from OpenEnv via
            `vf.OpenEnvEnv`. A framework-free numpy core computes the real
            log-normalized MSE gated by a Poisson constraint and returns only a
            coarse `RewardBand`/quantized scalar banded by improvement over the
            depth-matched baseline; exact metrics and raw expression values stay
            inside the boundary. The real datasets used by TTT-Discover
            (pancreas train, held-out `tenx_1k_pbmc`) are fetched reproducibly
            with md5 verification (`datasets.json` + `fetch_datasets.py`) and
            never committed. `verifiers`/`anndata` are optional extras imported
            lazily so the core is offline-testable. `environments/README.md`
            documents the extensible layout. Real candidate-program execution
            through the sandbox and hidden-holdout wiring are now proven at toy
            scale by DenoisingHoldoutEnvironment (below); for this full-scale
            numpy env, sealed-dataset loading and an actual prime-rl/`vf-eval`
            run over the real matrices remain open. The trainer-facing surface is
            now leakage-bound-verified OFFLINE (without the heavy stack): the reward
            func `bounded_denoising_reward` (called each rollout) records only the
            bounded band on rollout `state` — never exact mse/poisson or raw counts
            — and returns only a quantized band scalar, and the dataset rows
            (`_build_rows`) carry only the public problem + split handle, no raw
            matrices (`environments/openproblems_denoising/tests/test_bounded_reward_egress.py`,
            6). The reward func also fails closed: a malformed/adversarial
            completion earns NEGLIGIBLE (matching the private-reward contract) so a
            bad candidate never crashes a rollout or leaks an error body, while an
            unavailable dataset (infra, not a bad candidate) still propagates. Only
            the actual trainer run under `verifiers`/`prime-rl` remains.
[partial]   Candidate/evaluator sandboxing for arbitrary third-party code. The
            local Python candidate sandbox and process-bound evaluator planner
            are not OS/container isolation and are not sufficient for untrusted
            production execution inside a CVM.
[partial]   Sealed data at rest / portable encrypted datasets. Reward datasets
            (`D`) for private environments must be storable in untrusted public
            hosts — Hugging Face Hub, S3, IPFS — while plaintext exists only
            inside the attested boundary. The envelope-encryption core is now
            source/test-real in `tinker_delegate.sealed_dataset`:
            `encrypt_dataset`/`decrypt_dataset` do chunked AES-256-GCM under a
            fresh random DEK with per-chunk nonce and `dataset_id|index|total`
            AAD; `wrap_dek`/`unwrap_dek` wrap the DEK to attestation-bound CVM
            keys via `crypto.encrypt_for_tee`/`TEEKeyPair`;
            `build_manifest`/`verify_manifest` produce and check a bounded
            `sealed-dataset-manifest-v1`. Tests prove round-trip, wrong-key /
            tamper / wrong-AAD authentication failure, multi-recipient unwrap,
            and a manifest that never carries the DEK or plaintext. Operator
            CLIs `encrypt-dataset` and `verify-dataset-manifest` are now
            source/test-real: `encrypt-dataset` envelope-encrypts a file to one
            or more recipient CVM keys and writes the blob + bounded manifest +
            receipt; `verify-dataset-manifest` externally checks schema,
            sensitivity, recipient shape, chunk metadata, and ciphertext hash
            with no plaintext access; a subprocess round-trip test proves
            encrypt -> recipient-key unwrap -> decrypt back to the exact
            plaintext. Pluggable storage backends are now source/test-real in
            `tinker_delegate.dataset_storage`, kept strictly outside the crypto
            path: a `StorageBackend` ABC (`ref_for`/`publish`/`fetch`) with a
            real `LocalStorageBackend`, a real fetch-only `HttpsFetchBackend`,
            and fail-closed `hf`/`s3` placeholders (credentials from env only,
            adapter not yet wired). `publish-dataset`, `fetch-decrypt-dataset`,
            and `dataset-recipient-keygen` CLIs complete the loop: keygen (0600
            X25519 private key) -> encrypt-dataset -> publish-dataset ->
            fetch-decrypt-dataset round-trips the exact plaintext, with wrong
            key / tampered blob / unconfigured backend all failing closed
            (`tests/test_dataset_storage.py`, 14 tests). `fetch_decrypt_dataset`
            selects the recipient envelope by key hash, unwraps, decrypts with a
            plaintext-hash check, and zeroes the buffer. This sealed path is now
            exercised end-to-end into a private-reward env: the
            `denoising_sealed_dataset` demo (`denoising_sealed_demo.py`) seals the
            denoising cells (`public_benchmark`), publishes them, fetch-decrypts
            in-boundary, zeroes the plaintext buffer after parsing, then runs the
            `DenoisingHoldoutEnvironment` reward loop — failing closed (no env run)
            if the plaintext hash is unverified. The sealed-path reward bands equal
            the direct in-code demo's bands (lossless round-trip), no raw counts
            leak, and the packet passes `verify_reward_run`
            (`tests/test_denoising_sealed_demo.py`, 5) — demonstrating the
            sealed-data -> environment -> bounded-reward mechanism as one flow.
            Exposed as the `denoising-sealed-dataset-demo` operator CLI, so the
            full loop runs end-to-end: `denoising-sealed-dataset-demo | verify-reward-run`
            emits a bounded packet and independently verifies it (`verified:true`).
            The security-critical in-boundary flow (fetch -> manifest verify ->
            envelope select -> unwrap -> decrypt -> plaintext-hash verify -> parse
            -> ZERO buffer) is centralized as the reusable, env-agnostic
            `sealed_env_dataset.load_sealed_env_dataset(ref, key, parse=...)`: it
            fails closed (returns `None`, never calls the parser) on unverified
            plaintext and always zeroes the decrypted buffer after parsing (even if
            the parser raises), so any future env sourcing sealed data reuses one
            tested path (`tests/test_sealed_env_dataset.py`, 5). The denoising demo
            now calls it, and a cross-env test proves the loader is env-agnostic —
            the same loader carries the differently-shaped synthetic hidden-keyword
            env's sealed records end-to-end (fetch -> decrypt -> parse -> env ->
            bounded band) with no raw record text leaking. Owner/reviewer manifest
            signing is now source/test-real: `sealed_dataset.sign_manifest`
            adds an Ethereum signed-message `owner_signature` over the canonical
            `manifest_hash` (which excludes the signature fields, so it binds
            every other field — dataset id, hashes, chunking, recipients,
            sensitivity, storage ref); `verify_manifest(..., expected_signer=)`
            verifies it, flags any tampered signed field, and requires a
            matching signer when one is expected. `sign-dataset-manifest` (signer
            key from env only) and `verify-dataset-manifest --expected-signer`
            expose it with bounded receipts (no key/address/raw-signature egress;
            `tests/test_sealed_dataset_signing.py`, 10 tests). Still `[planned]`:
            `dataset-recipient-pubkey` live attestation fetch, credentialed
            HF/S3 adapters, binding recipient-key custody to the dstack-derived
            CVM measurement (today fetch-decrypt uses a local key file) with a
            sealed-volume write target, and binding the owner signer to a
            governance/reviewer identity source at seal time.
            The chosen construction reuses existing primitives, not a new
            scheme:
            `crypto.encrypt_for_tee()` (X25519 ECDH + HKDF-SHA256 +
            AES-256-GCM to an attestation-bound CVM public key — ECIES with a fresh
            ephemeral keypair per message, so a fresh AES key per message makes
            AES-GCM nonce reuse structurally impossible; HKDF `info` domain-separates
            the card vs artifact channels) wraps a fresh
            random data-encryption key (DEK); the DEK does chunked AES-256-GCM
            over the dataset bytes; `dstack_utils.derive_storage_key()` reseals
            DEK/plaintext under the CVM data volume; `artifacts.zero_buffer()`
            zeroes plaintext after use. The `crypto.py` primitive itself is now
            directly security-tested (`tests/test_crypto.py`, 9): authenticated
            round-trip, ciphertext/nonce tamper rejection (`InvalidTag`),
            associated-data binding, card/artifact channel domain separation,
            wrong-key rejection, and — the load-bearing nonce-safety property —
            that encrypting the same plaintext twice yields distinct ephemeral
            keys, nonces, and ciphertexts. The FIXED-key at-rest stores
            (`api_key_store`, `tinker_proxy_store`, `sealed_retention`,
            `funding_receipt_store`, `run_metadata_store`, `browser_session_store`,
            `tinker_client_config_store`) were systematically audited (2026-07-12):
            all use a fresh `os.urandom(12)` nonce per save prepended to the
            ciphertext, so the catastrophic AES-GCM nonce-reuse-under-a-fixed-key
            mode is absent across the encrypted-store surface — pinned for the most
            sensitive secret by an api-key-store regression test (re-saving the same
            key yields a different nonce/ciphertext). A bounded, owner-signable
            manifest binds
            dataset id, ciphertext hash/size/chunking, plaintext hash,
            per-measurement wrapped-DEK envelopes, a `data_sensitivity` label
            (`public_benchmark` / `private` / `phi`), and the storage backend
            reference. Storage backend is orthogonal to encryption (pluggable
            local / HF / S3 / https adapters). CLIs mirror existing tooling:
            `dataset-recipient-keygen`, `encrypt-dataset`, `publish-dataset`,
            `fetch-decrypt-dataset`, `verify-dataset-manifest` are real;
            `dataset-recipient-pubkey` (live attestation fetch) remains planned
            — all emitting only hashes/status with `raw_secret_egress=false`.
            Security reduces to the existing attestation + on-chain
            compose-approval chain: the dataset is only as sealed as the
            measurement binding of the CVM key derivation, so this inherits the
            same `[partial]` quote-parsing gap. Encrypting public benchmark data
            (the OpenProblems denoising sets) exercises the mechanism and is not
            a privacy claim; only `private`/`phi`-labeled datasets carry one.
[partial]   Deployment manifest. `deployments/base-sepolia.json` now records
            current operator-controlled Base Sepolia `DiligenceRoom` and
            `EmailOracleAuth` deployments plus historical Phala records. BaseScan
            source verification, compose-hash registration, and fresh Phala
            quote evidence remain open. The recorded `DiligenceRoom` deployment
            predates the current verifier-signature `submitResult()` ABI, so a
            fresh deployment with `DILIGENCE_RESULT_VERIFIER` recorded is
            required before live-chain result-verifier enforcement is real.
[real]      Local chain watcher. `tinker_delegate.chain_watcher` can decode
            `DiligenceRoom` lifecycle logs from JSON-RPC, post bounded
            `/deal/chain-event` audit markers, call `/deal/notify-funded` when
            a funded event has matching created-deal context, and call
            `/deal/{deal_id}/resolve` for accept/reject/expire events. It has
            mocked JSON-RPC/API coverage, a `watch-chain` CLI, durable
            `ChainCursorStore` restart state, confirmation-safe polling, and a
            local Anvil proof script that emits real `DealCreated`/`DealFunded`
            logs and verifies bounded control-plane state updates.
[partial]   Chain-watcher operations. The watcher is not yet deployed as a
            Phala/CVM process and does not yet have chain-lag alerting or
            deep-reorg rollback beyond the configured confirmation policy.
[partial]   TEE-to-chain result submission. `tinker_delegate.chain_submitter`
            can derive an Ethereum signer from dstack key material, guard
            `submitResult()` against public `deals(dealId)` state, sign a raw
            transaction without a raw-private-key CLI/env path, broadcast it
            through JSON-RPC, and emit only bounded receipt metadata. The
            submitted `resultHash` is an anti-replay commitment over chain ID,
            contract, deal ID, signer nonce, compose hash, payload result hash,
            score band, compute cost, and expiry. It optionally also binds the
            RLVR proof-carrying `reward_transcript_commitment`: when a run passes
            one to `submit_result`, the commitment uses a v2 domain tag and folds
            the transcript hash into `resultHash`, so the settled on-chain record
            cryptographically commits to the reward-run transcript; when absent it
            is byte-identical v1 (existing submissions unchanged). Any holder of
            the bounded public fields can recompute the digest and check it
            against the on-chain `resultHash`. Exposed on the `submit-result` CLI
            (`--reward-transcript-commitment`) and proven on-chain by
            `prove-chain-submitter-dstack-anvil.py`: with a real dstack-simulator
            TEE key and ephemeral Anvil, the emitted
            `EvaluationSubmitted.result_hash` equals the v2 transcript-bound
            commitment and differs from the unbound v1 digest. `DiligenceRoom.sol`
            now requires a configured result verifier signature over chain ID,
            contract address, deal ID, TEE identity, compose hash, score band,
            compute cost, result commitment, and authorization expiry before
            accepting `submitResult()`. `DiligenceRoom.sol` also has an on-chain
            compose-hash approval gate (`approvedComposeHashes`, developer-only
            `approveComposeHash`/`revokeComposeHash`/`setComposeApprovalRequired`):
            when enabled, `submitResult()` reverts `ComposeHashNotApproved` unless
            the authorized compose hash is a governance-admitted measurement
            on-chain — defense in depth beyond trusting the off-chain verifier
            signer, mirroring `TinkerAccountEncumbrance.approvedComposeHashes`. It
            defaults OFF (verifier-signature-only path preserved) and is
            `[partial]` at the binding level: it is proven by contract tests
            (64 tests total) but not yet enabled-by-default or present on the current
            Base Sepolia deployment, and the bare `teeIdentity` address is still
            not itself bound to an attested app identity at deal creation. The
            `DiligenceRoomSubmitter` preflight now honors this gate: before
            signing it reads `composeApprovalRequired()` and
            `approvedComposeHashes(composeHash)` and fails closed
            (`compose hash is not approved on-chain`) rather than broadcasting a
            transaction that would revert, keeping the bounded receipt honest
            (`tests/test_chain_submitter.py`, 15). The gate is proven end-to-end
            on ephemeral Anvil by `scripts/prove-compose-approval-gate-anvil.py`
            (deploy → enable gate → unapproved `submitResult` reverts
            `ComposeHashNotApproved` → `approveComposeHash` → same call passes the
            gate and reverts on the dummy verifier sig `InvalidResultAuthorization`
            → `revokeComposeHash` reverts again), using Anvil unlocked accounts
            with no raw keys and no dstack; a guarded opt-in test
            (`tests/test_compose_approval_gate_proof.py`, `DNAI_RUN_ANVIL_PROOFS=1`)
            runs it. `DiligenceRoom.sol` additionally binds the TEE identity to an
            attested measurement at deal creation:
            `teeIdentityComposeHash[address]` (developer-only
            `approveTeeIdentity(address,bytes32)`/`revokeTeeIdentity`/
            `setTeeIdentityApprovalRequired`) records the compose hash an identity
            is bound to. When enabled, `createDeal` reverts `TeeIdentityNotApproved`
            for an unapproved identity and `submitResult` reverts
            `ComposeHashIdentityMismatch` unless the submitted compose equals the
            identity's registered measurement — so a deal can only be created for,
            and settled by, a governance-bound TEE identity/measurement pair
            (default OFF; contract tests 64 total). This closes the mechanism gap
            in "bind teeIdentity to an attested compose/app identity"; enabling by
            default and redeploying remain operational follow-ups. The on-chain
            approvals are driven by attestation, not hand-written: given a *verified*
            `ResultAuthorization` (attestation already passed the verifier policy),
            `tinker_delegate.governance_plan` emits a bounded plan of the exact
            `approveComposeHash`/`approveTeeIdentity` calls that admit that
            identity/measurement pair on-chain, with `--account dev` keystore `cast`
            templates (never a raw key). Per the no-self-approval invariant it does
            NOT execute — the developer/governance broadcasts it; the
            `governance-approval-plan` CLI turns an `authorize-result` output into
            the bounded plan (`tests/test_governance_plan.py`, 8). The
            `submit-result` path also fetches
            and verifies signer quote evidence whose report data binds signer
            address, chain ID, and contract address; the bounded receipt
            includes quote hash, report data, quote size, authorization expiry,
            and verifier-signature hash. `scripts/prove-chain-submitter-dstack-anvil.py`
            proves this against the Phala/dstack simulator plus ephemeral Anvil
            and verifies a real `EvaluationSubmitted` event; it also binds an RLVR
            reward-transcript commitment and asserts the emitted `result_hash`
            equals the v2 transcript-bound commitment and differs from the unbound
            v1 digest. This still needs a production verifier service that signs
            only after live Phala quote verification and a deployed-CVM broadcast
            proof.
[real]      Result-verifier authorization policy module.
            `tinker_delegate.result_verifier` validates signer attestation
            evidence against signer address, chain ID, contract address, report
            data, quote report data, approved compose hashes, approved app IDs,
            optional OS image hashes, revoked quote hashes, revoked TEE signers,
            distinct verifier/TEE keys, and a short authorization TTL before it
            signs the exact `DiligenceRoom` authorization digest. Tests prove
            accepted authorization and fail-closed policy, context, revocation,
            self-approval, and non-dstack custody cases.
[real]      Result-verifier operator CLI path. `result-verifier-address` reports
            the dstack-derived verifier address for deployment, and
            `authorize-result` consumes bounded signer-attestation JSON plus
            explicit compose/app/OS-image allowlists and revocation lists before
            emitting bounded authorization metadata and the public verifier
            signature required by the contract. The dstack-simulator Anvil proof
            now uses this CLI path instead of ad hoc Anvil `eth_sign`.
[real]      Local synthetic-room-to-Anvil settlement proof. The
            `scripts/prove-local-synthetic-room-anvil.py` harness composes
            encrypted artifact ingress, `ControlPlane`, `IsolatedTinkerSession`,
            fake Tinker, the result-verifier CLI, the dstack-simulator signer,
            real local `DiligenceRoom.submitResult()`, `acceptDeal()`, settlement
            bands, and cleanup attestations into one bounded proof. Its public
            JSON contains hashes, bands, booleans, and transaction hashes only.
            It is not deployed Phala evidence, Base Sepolia evidence, real
            Tinker SDK training evidence, or frontend quote verification.
[partial]   Production result-verifier service. The policy/signature library and
            operator CLI are real, but not yet deployed as a Phala/CVM service.
            Quote handling is now two layers: (1) bounded dstack envelope checks,
            plus (2) an opt-in STRUCTURAL Intel TDX quote parser (`tdx_quote.py`,
            DCAP v4) that extracts the report_data embedded in the raw quote bytes
            so `verify_attestation_envelope(..., enforce_quote_binding=True)` can
            require it to equal the claimed report_data — closing the gap where a
            submitter paired a real quote with an independently-claimed
            report_data. This is a fail-closed structural check only (a wrong
            offset or unknown format can only reject, never accept); the Intel
            signature/cert-chain trust root and freshness/revocation stay
            delegated to the QVL/dstack SDK and remain the open production gap.
[modeled]   TTT/RL bio validation. Current evaluator is stub/SFT-oriented.
[partial]   Multi-party coordination, corpus policy, royalty metering,
            consent/revocation. The source now has a deterministic pure
            `tinker_delegate.policy_kernel` for per-corpus policy enforcement
            and a pure coordination reducer for strict per-corpus result
            composition, consent matching, reviewer-release flow, revocation,
            joint attestations, and royalty meters. Service wiring, durable
            reviewer queues, M-of-N review, policy authoring/migration/diff
            review, and production governance remain incomplete.
[planned]   Real on-chain quote verification, DLP/egress enforcement, production frontend.
```

## Repository Map

```
dnai-wikigen/
|
|-- README.md                         Product thesis and hackathon overview
|-- ARCHITECTURE.md                   This document
|-- AGENTS.md / CLAUDE.md             Agent instructions and project boundaries
|-- example.env                       Environment template, no secrets
|-- quickstart.sh                     Dependency bootstrap
|
|-- .codex/skills/                    Codex workflow skills
|-- .claude/skills/                   Claude workflow skills
|-- .agents/skills/                   Agent workflow skills
|
|-- gear: services and executable prototypes
|   |
|   |-- cdp-playground/               Neko Chrome + CDP automation sandbox
|   |-- tee-email-oracle/             TEE email account + OTP oracle
|   |-- tinker-delegate/              TEE Tinker account + evaluation + escrow API
|   |-- props-room/                   Source/controller/data-room stub
|   `-- whatsapp-delegate/            Browser-mediated personal-data delegate
|
|-- papers: read-only research/spec material
|   |
|   |-- ndai/                         NDAI paper
|   |-- dstack/                       dstack paper
|   |-- conseca/                      ConSECA paper
|   |-- thinking-machines/            Tinker docs snapshot
|   |-- tee-email-oracle/             Email oracle specs
|   `-- tinker-delegate/              Tinker delegate specs
|
`-- specimens: read-only reference submodules
    |
    |-- dstack, dstack-examples
    |-- amiller/*                     Devproof, dstack, oracle, OpenClaw refs
    |-- thinking-machines/*           Tinker SDK/cookbook/project ideas
    |-- m1k1o/neko, G-structure/neko
    `-- tv                            Corpus/data pipeline reference
```

The directories named with emoji are rendered above as `gear`, `papers`, and
`specimens` for readability. In the repository they are `⚙️/`, `📄/`, and `🔬/`.

## System Overview

```
                         users, agents, reviewers
          seller/data owner     buyer/sponsor      human reviewer
                 |                  |                    |
                 v                  v                    v
        +---------------------------------------------------------+
        |                    web client / API clients             |
        |    room creation, reserve price, budget cap, policy     |
        +--------------------------+------------------------------+
                                   |
                                   v
        +---------------------------------------------------------+
        |                 DNAI coordination layer                  |
        |  access request -> gate -> consent -> execute -> settle |
        |                                                         |
        |  [modeled] multi-party reducer                          |
        |  [modeled] corpus policy and consent grants             |
        |  [real]    bounded result types and escrow primitives   |
        +-------------+----------------------+--------------------+
                      |                      |
                      | notify / OTP / hold | execute / evaluate / settle
                      v                      v
        +----------------------------+   +----------------------------+
        | tee-email-oracle CVM       |   | tinker-delegate CVM        |
        |                            |   |                            |
        | email account sealed in TEE|   | Tinker account sealed in TEE
        | IMAP OTP extraction        |   | browser login automation   |
        | reviewer/owner confirmation|   | API key provisioning       |
        | attestation endpoint       |   | billing automation         |
        +-------------+--------------+   | IsolatedTinkerSession      |
                      |                  | evaluator + cost meter     |
                      |                  +-------------+--------------+
                      |                                |
                      v                                v
        +----------------------------+   +----------------------------+
        | EmailOracleAuth.sol        |   | DiligenceRoom.sol         |
        | app/compose-hash policy    |   | escrow + result hash      |
        | consumer authorization     |   | reserve + budget cap      |
        +----------------------------+   +----------------------------+
                         Base Sepolia / Base-compatible chain
```

The architecture is split into three trust domains:

```
1. Public / user domain
   Browser clients, wallets, reviewers, sellers, buyers, sponsors.

2. Attested compute domain
   dstack CVMs on Phala Cloud. Secrets and raw artifacts are usable only here.

3. Public settlement / verification domain
   Base Sepolia contracts, result hashes, app-auth policy, and withdrawals.
```

## Core Concepts

### Encumbered Account

An encumbered account is an account whose credentials are not held by a human
operator. The account is created, stored, and used inside an attested TEE. Human
users interact with the account through bounded APIs and attestations rather
than through raw credentials.

In this repo there are two main encumbered-account patterns:

```
Email encumbered account
  - TEE creates or stores an email account.
  - TEE reads OTPs over IMAP.
  - TEE exposes bounded OTP/notification APIs.
  - EmailOracleAuth.sol governs measured-code boot / consumer policy.

Tinker encumbered account
  - Current operator-validation slice: the TEE can log into Tinker through
    browser automation, seal credentials, and issue short-lived scoped proxy
    JWTs from CVM-only key material under hash-only policy gates.
  - Target production slice: TINKER_PROJECT_ID, optional provider endpoint,
    browser session, payment state, and proxy signing keys stay inside the CVM
    boundary, and scoped proxy JWTs are delivered encrypted only to approved
    recipients.
  - TEE can check balance and has funded the one-off capped
    operator-validation lane; production/repeated funding remains blocked.
  - TEE exposes only metered, scoped proxy/evaluation APIs with bounded
    receipts.
  - DiligenceRoom.sol settles escrow around bounded evaluation results.
```

The email TEE is not just disposable email or a convenience inbox. Its job is to
eventually hold an email account that no human can access, so OTPs,
confirmations, and future reviewer/owner messages can be consumed by attested
code without giving operators the account credentials. That matters for Tinker
because the Tinker account is intended to become agent-owned: the TEE requests
the magic-code email, the email oracle reads it, and the Tinker delegate uses it
inside the browser session. Current validation still has temporary operator and
debug surfaces that must be removed before production.

The Tinker side is intentionally split between the one-off operator-validation
lane that is now real and the production funding lane that remains incomplete.
The account becomes useful only if it can be funded without leaking card details
or handing account credentials to a human. The current validation path encrypts
card data to the TEE, drives the Tinker/Stripe billing form from inside the TEE,
clears the card payload from memory, and returns only bounded receipts. The
deployed auth/API-key browser posture is working, bounded card-on-file status
can be queried without card details, and the same-context reauth/add-balance
packet reached `add_balance_submitted` with `raw_secret_egress=false`. The
receipt stayed conservative because it did not see explicit success copy, but
an independent bounded balance read returned `$10.00`, so low-value
operator-validation funding is real. Production funding still needs a hardened
CVM posture, compliance approval, and preferably an official tokenized payment
route. The billing control plane also has a bounded card-on-file status path
and admin/operator card-removal path: callers can learn only whether a payment
method appears present and a zero/one-or-more/unknown count band, never card
brand, last4, expiry, billing address, or browser page text.

The next boundary is Tinker compute. Earlier project-aware and client-config
diagnostic delegate images were built through GitHub Actions with
provenance/SBOM attestations, pinned in the funding-validation compose,
redeployed to Phala, attested, and approved on-chain in
`TinkerAccountEncumbrance` for `SPEND_TINKER_COMPUTE`. Those attempts proved
the image/compose/contract policy chain for bounded Tinker spend attempts, but
not real training. The deployed smoke passes the policy check and sealed
API-key load, then fails closed before Tinker training creation at
`sdk_error.failure_site=service_client_create` with
`sdk_error.operator_action=check_sdk_client_configuration`, correct
Qwen/rank-32 request shape, and `project.configured=false`. Receipts include
bounded SDK-error diagnostics and still do not return raw provider text, API
keys, card fields, emails, request IDs, run IDs, samples, or checkpoint paths.
The current hypothesis is missing Tinker project/client configuration or
service-side account entitlement.

[partial] The latest pinned client-config install image set is now live and
attested on Phala CVM `cvm_1w85mGjo` / app
`f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` at app-compose hash
`1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`.
Local verification binds the live TDX envelope to raw compose/image-policy hash
`1db1ee033f333509726d03c325788e0fc5c0803351d6d1496ee42ff14fa83700`,
rendered compose SHA-256
`62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`,
the three pinned GHCR image digests, app ID, and OS image hash. This is not
yet an authorized compute-spend lane: read-only chain state reports
`approvedComposeHashes(0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085)=false`.
The latest approved compute compose is still
`0xe682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`.

[real] The Phala redeploy helper can now bind a runtime env variable to the
provisioned app-compose hash before encrypted env commit. The
`--self-compose-hash-env TINKER_ENCUMBRANCE_COMPOSE_HASH` path fails closed if
that key is not selected, rejects malformed hashes, and preserves the selected
env key set while replacing the stale value with Phala's provisioned compose
hash. This keeps the Tinker proxy/deployment-policy check from minting tokens
against an older compose hash after a redeploy.

A bounded `tinker-smoke-command-plan` CLI turns the remaining smoke path into
an explicit no-secret operator sequence. If the live CVM already exposes the
sealed client-config endpoint, the plan emits `client_config_install_shell` so
an operator can seal `TINKER_PROJECT_ID` and optional `TINKER_BASE_URL` from
local env into the CVM without printing them, then refresh bounded status and
rerun smoke. Redeploy/attest/approve is required only when the live CVM does
not include that source or when a new compose hash is intentionally selected.
The plan uses environment variable names and compose-hash placeholders only; it
does not accept or emit raw project IDs, tokens, API keys, RPC URLs, run IDs,
checkpoints, or samples. Live client-config status on the newest compose still
reports `project_id_configured=false`, encrypted store missing, and
`raw_secret_egress=false`; live use of that installer and a successful
post-install smoke run are still pending. The plan also consumes the account
access gate: `--account-access-state` (from `account-access-status`) makes the
plan not-ready with `next_action=resolve_tinker_account_activation` when the
account is `access_blocked_billing`/`waitlist_or_gated`/`payment_required`
(surfaced above all compose/policy reasons), and warns when the gate is
unverified — so readiness is honest that an unactivated account blocks the smoke
even when every compose/policy gate is green.

The intended external Tinker surface is now the Tinker proxy, not direct
credential sharing. In the target shape, approved users and agents receive
scoped JWTs signed by a key derived from CVM-only dstack material and delivered
as an encrypted X25519/AES-GCM envelope to a recipient public key. The JWT scope
authorizes named proxy operations such as bounded status, payment-method
status, add-balance, or tiny smoke/training requests; it must never authorize a
generic arbitrary Tinker SDK call. The proxy can report configured/missing
booleans, stable hashes, host families, policy decisions, spend bands, and
attestation evidence. It must not return upstream `TINKER_API_KEY`,
`TINKER_PROJECT_ID`, account cookies, card material, raw provider messages,
run IDs, checkpoint paths, samples, or private reward data.

[planned]   Production proxy credential issuance still needs production user
            and agent identity approval, reviewer/governance workflow,
            secure recipient approval/delivery operations, expiration and
            revocation operations, and settlement policy. The hash-only issue
            policy, optional verifier-signed identity registry, and optional
            deployment-policy gate are real approval primitives, but they are
            not yet a production user-management or end-to-end
            spend-governance system.
[real]      Source now includes the first Tinker proxy credential slice:
            `tinker_delegate.tinker_proxy` creates scoped HS256 delegate JWTs
            from explicit local test key material or dstack-derived CVM-only
            key material, encrypts delivery to a recipient X25519 public key
            using AES-256-GCM, and verifies scoped bearer tokens without
            returning the plaintext token. `GET /tinker/proxy/status` and
            `POST /tinker/proxy/token` are disabled by default; token issuance
            additionally requires configured runtime bearer auth.
            Recipient-side CLI tooling can generate an X25519 delivery keypair
            and decrypt an issuance envelope into a local `0600` JWT file
            without printing the private key or token. This implementation is
            now deployed in the temporary funding-validation Phala profile for
            operator validation. Production user identity and governance
            approval remain open; scope and spend approval are source/test-real
            in the policy slices below.
[real]      Proxy-token issuance can now require a hash-only issue policy before
            minting. When `TINKER_PROXY_REQUIRE_ISSUE_POLICY=true` and
            `TINKER_PROXY_ISSUE_POLICY_PATH` points at a schema-v1 policy file,
            issuance fails closed unless a grant matches the subject hash,
            recipient public-key hash, requested scope subset, and TTL cap.
            Successful responses include only bounded `policy_binding` hashes,
            requested/granted scopes, TTL cap, and `raw_secret_egress=false`;
            they still do not return the raw subject, recipient public key, or
            plaintext JWT. Source/API tests cover success, wrong recipient,
            TTL cap denial, and missing required policy. Production identity
            approval remains open, and live deployment evidence depends on the
            active Phala compose.
[real]      Proxy issue-policy grants can now require bounded hash-only
            lifecycle approval before minting. When
            `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE=true`, a matching grant must
            include `lifecycle.status=active`, `approved_by_hash`,
            `approved_at`, and `expires_at`; pending, revoked, expired, missing,
            or future-approved grants fail closed before JWT creation. Policy
            summaries and issuance bindings expose only lifecycle status,
            reviewer/approval-event hashes, timestamps, and
            `raw_secret_egress=false`; they do not expose raw reviewer,
            operator, user, or agent identities. This is source/test-real and
            wired into the funding-validation compose as a disabled-by-default
            env knob.
[real]      Proxy grant lifecycle approval can now be reviewer-signed in
            source/test. When
            `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE_SIGNATURE=true`, an active
            grant lifecycle must carry an Ethereum signed-message signature
            over a canonical hash-only grant approval payload: subject hash,
            recipient public-key hash, scopes, spend caps, TTL cap, lifecycle
            status, approval-event hash, approval time, and expiry. The
            recovered signer address must hash to lifecycle
            `approved_by_hash`, so a JSON policy editor cannot silently assign
            reviewer approval without the reviewer key. Issuance bindings and
            `tinker-proxy-issue-policy` summaries return only approval hash,
            signer hash, signature hash, lifecycle status/timestamps, and
            `raw_secret_egress=false`; raw signer addresses, raw signatures,
            reviewer private keys, subject labels, and plaintext JWTs do not
            leave the signing or CVM boundary. `sign-tinker-proxy-grant-lifecycle`
            is a local bounded helper that reads the reviewer key only from env
            and writes the signed grant to an explicit output file. The Phala
            funding-validation compose exposes only the verification flag, not
            a reviewer private-key env. This is still not production governance
            until reviewer key custody and approval workflow are operationally
            defined and deployed.
[real]      Proxy issuance can now require a hash-only identity registry before
            minting. When `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY=true`, the
            requester's `subject_hash` must be an active user/agent identity,
            and the lifecycle `approved_by_hash` must be an active
            reviewer/admin identity in a schema-v1 registry. Suspended, revoked,
            expired, missing, or wrong-role identities fail closed before JWT
            creation. Issuance bindings expose only registry hash, identity
            hashes, roles, statuses, expiries, and `raw_secret_egress=false`.
            When `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE=true`, the
            registry must also carry an Ethereum signed-message signature over
            its canonical hash-only registry hash from
            `TINKER_PROXY_IDENTITY_REGISTRY_SIGNER`. Missing signatures,
            tampered registries, wrong signers, and malformed signatures fail
            closed before JWT creation. Successful bindings expose only
            registry hash, signer hash, signature hash, verification status,
            and `raw_secret_egress=false`, not signer private material,
            plaintext user identities, or plaintext JWTs.
            `sign-tinker-proxy-identity-registry` and
            `verify-tinker-proxy-identity-registry` provide a bounded local
            verifier workflow for this registry: the signer key is read only
            from an environment variable, the signed registry is written to an
            explicit file, and receipts expose only registry hash, role counts,
            signer hash, signature hash, output path, verification status, and
            `raw_secret_egress=false`. The signed registry artifact necessarily
            contains the verifier signature and signer address, but not raw
            user/reviewer identities; the receipt does not return either value.
            `GET/PUT /tinker/proxy/identity-registry` and
            `tinker-proxy-identity-registry` let a runtime-authenticated
            operator install or inspect that signed registry without SSH or
            image edits. Install verifies the signature when the signature gate
            is required, writes only the normalized hash-only registry artifact
            to the configured CVM path, and returns bounded registry
            hash/count/role/signature-binding evidence. These surfaces are
            source/test-real and the lifecycle/signature-required env gate is
            now live in the operator-validation Phala CVM. A fresh hash-only
            issue policy and signed hash-only identity registry were installed
            through the live runtime-authenticated API on 2026-07-09; after
            `TinkerAccountEncumbrance` approval, live encrypted proxy-token
            issuance, local recipient decrypt, and scoped `proxy:status`
            authorization succeeded with only bounded hashes and
            `raw_secret_egress=false`.
            The current source compose carries lifecycle and signed
            identity-registry env knobs; local raw/image-policy compose hash is
            `e682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`
            and rendered compose SHA-256 is
            `4c99b0f73a14bd40292ee71df343fd5e08f889e1932f4318d64657107e78e595`.
            The signer address is a temporary operator-validation verifier, not
            yet a production verifier/reviewer identity source or governance
            contract.
[real]      Policy-issued proxy JWTs can now carry bounded per-scope spend
            limits. A policy grant may define `scope_limits`, and
            spend-bearing scopes such as `billing:add-balance` require
            `max_amount_usd` when the issue policy is required. The JWT stores
            that bounded limit in a `limits` claim, `verify_proxy_token()`
            returns it as `scope_limits`, and `/billing/add-balance` rejects a
            proxy-authorized request above the cap before browser or payment
            automation starts. This is live in the temporary
            operator-validation Phala deployment for the bounded proxy issuance
            slice; production identity binding remains separate.
[real]      Runtime operators can now install and inspect the hash-only issue
            policy without SSH or image edits. `GET/PUT
            /tinker/proxy/issue-policy` and `tinker-proxy-issue-policy` require
            runtime bearer auth, canonicalize policy JSON, persist it at the
            configured delegate path, and return only bounded policy/grant
            hashes, subject hashes, recipient-key hashes, scopes, TTL caps,
            spend caps, and `raw_secret_egress=false`. The funding-validation
            compose now carries the required policy env knobs and the live
            Phala deployment includes `TINKER_PROXY_REQUIRE_ISSUE_POLICY`,
            `TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY`, and
            `TINKER_ENCUMBRANCE_COMPOSE_HASH` in its attested allowed-env
            surface.
[real]      Proxy-token issuance can now be source-bound to the on-chain Tinker
            encumbrance policy before minting. When
            `TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY=true`,
            `issue_encrypted_proxy_token()` maps requested scopes to bounded
            encumbrance preflights: `billing:add-balance` checks
            `ADD_BALANCE`, `tinker:smoke` checks `SPEND_TINKER_COMPUTE`, and
            read-only proxy scopes perform a zero-amount `MANUAL_PREFUND`
            compose-approval check. Spend checks use only
            `scope_limits.max_amount_usd` from the hash-only issue-policy
            grant. A denied or missing encumbrance policy fails closed before
            JWT creation; successful issuance returns only bounded deployment
            check records and `raw_secret_egress=false`. This is now deployed
            in the operator-validation Phala profile for bounded proxy issuance,
            and remains separate from production user/governance approval.
[real]      The first bounded operation endpoints now accept scoped proxy JWTs:
            `proxy:status` for proxy status, `tinker:smoke` for the paid smoke
            surface, `billing:payment-method-status` for card-on-file status,
            and `billing:add-balance` for the capped add-balance endpoint.
            Operator-only surfaces remain operator-runtime guarded: token
            issuance, Tinker reauth, card add/remove, and funding receipts are
            not delegated to user proxy JWTs in this slice. The `add-balance`
            CLI can now call a deployed delegate with `--api-url` and a scoped
            bearer token, writing bounded JSON and optional receipt files.
            When a proxy JWT authorizes one of these routes, the response now
            includes a top-level bounded `proxy_auth_context` with auth kind,
            required scope, subject hash, JWT-id hash, granted scopes, expiry,
            and `raw_secret_egress=false`. Runtime-operator bearer responses do
            not get this context. Proxy-authorized `POST /tinker/smoke` is
            spend-capped fail-closed: the proxy JWT must carry a finite
            positive `scope_limits["tinker:smoke"].max_amount_usd`, and the
            effective smoke budget (request `max_usd` or the
            `real_sdk_max_usd` default) is rejected with 403 before the smoke
            runner executes when the limit is missing, malformed, or exceeded.
            Runtime-operator bearer smoke requests are unchanged.
[real]      Proxy-token issue/revoke audit is now source/test-real:
            `ProxyTokenStore` stores bounded `issued` and `revoked` records
            under AES-GCM using local test key material or dstack-derived key
            material. Issuance appends an `issued` record; operator-only
            `/tinker/proxy/tokens` and `/tinker/proxy/token/revoke` expose
            bounded audit listing and hash-only revocation; token verification
            rejects revoked `jwt_id_hash` values. Revocation fails closed for
            unknown/non-issued token hashes, and duplicate revocation attempts
            for the same issued token return the existing bounded revocation
            record rather than appending dangling or duplicate audit entries.
[real]      External proxy-token audit replay is source/test-real:
            `verify-tinker-proxy-token-audit` verifies exported bounded audit
            JSON and optional operation receipts without plaintext JWTs. It
            checks record schema, summary counts, issue/revoke chronology,
            supported scopes, expiry windows, revocation timing, receipt
            boundedness, and `proxy_auth_context` binding when present or
            required.
[real]      The proxy-token issue/deployment-policy build is live in the
            temporary Phala funding-validation profile. Source
            `d9807a028702ff2b0ee1c077cc0970cafc334475` built in GitHub
            Actions run `29043212028` into GitHub-attested delegate image
            `tinker-delegate@sha256:b0e7c63d276469d586a574a94bf0fc91feb0a223fa2cdb0dd3d49cd64c41a5ee`;
            provenance and SPDX SBOM attestations were verified before
            deployment. The live CVM `cvm_1w85mGjo` / app
            `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` attests app-compose
            hash
            `40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace`
            with raw/image-policy compose hash
            `a860ba168b0334d8317fc56f0d2a971b79ad13bc206f5b43f3d04833d32f8eb7`
            and rendered compose SHA-256
            `b718208409a73f0bff4f2ab0efdead239111b7ff8fccc688ff889d103aad69d4`.
            `TinkerAccountEncumbrance` approved the live compose in tx
            `0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6`
            at block `43928500`. A live hash-only issue policy was installed
            with policy hash
            `e4db29bfded844e0402e7ce61aba51360eb0fbe2aa1bab2013cd200b0164ea16`
            and grant hash
            `c2b23202b441ad6f9b80565f1b2b6cfc8402113b7c969485c76a7135a8a92a84`.
            Bounded encrypted token issuance proved deployment-policy
            `allowed=true`, emitted only JWT-id hash
            `0891923ea9aa068d058adcdfaf864ec9da88d2027c1cc30f397fb7c111806df7`,
            token hash
            `f795f81f6d399a285fabacb903c3384060f89371d3e918b52d5ce227516ceda4`,
            and encrypted delivery material with `raw_secret_egress=false`;
            the recipient-decrypted scoped proxy JWT successfully called proxy
            status. This still is not a production identity/spend approval
            policy.

### Bounded Output

Bounded output is the safety boundary. Raw artifacts, raw private data, full
model weights, raw samples, card data, and account credentials should not leave
the TEE. Outputs are reduced before egress:

```
raw artifact            -> artifact hash
raw benchmark delta     -> score band
raw model output        -> yes/no or category band
raw deal valuation      -> offer within buyer cap
raw run record          -> result hash + attestation
raw messages / corpus   -> aggregate counts or activity bands
```

### NDAI Diligence Room

The NDAI diligence room maps the paper's mechanism into product primitives:

```
seller reserve price  -> minimum acceptable payment
buyer budget cap      -> maximum spend / overpayment bound
TEE evaluator         -> buyer-side agent inside the boundary
bounded output        -> no direct disclosure of the seller artifact
escrow state machine  -> settle, reject, expire, withdraw
```

## Primary Control Flow

This is the intended end-to-end flow for a private artifact or bio dataset.

```
1. Seller / controller prepares artifact
   |
   |  artifact bytes stay private
   v
2. Seller creates deal
   |
   |  createDeal(reservePrice, expiry, artifactHash, teeIdentity)
   v
3. Buyer funds deal
   |
   |  fundDeal() with ETH as budget cap
   v
4. TEE receives artifact
   |
   |  encrypted to the attestation-exposed TEE public key
   |  ciphertext is bound to deal ID and artifactHash
   |  verify keccak256(rawArtifact) == artifactHash
   |  artifact held in enclave memory or sealed store
   v
5. Gate / coordination layer checks request
   |
   |-- identity and role
   |-- purpose and allowlist
   |-- bio-risk / dual-use screen
   `-- attested execution requirement
   |
   v
6. Tinker delegate starts isolated session
   |
   |-- create one training/evaluation run for the deal
   |-- meter compute cost
   |-- enforce checkpoint TTL
   |-- restrict sampling to session-owned checkpoint paths
   v
7. Evaluator runs bounded assessment
   |
   |  current: stub/SFT evaluator
   |  target: TTT/RL bio-validation loop
   v
8. Control plane bounds raw metrics
   |
   |  raw delta -> ScoreBand
   |  score/budget/reserve -> offer
   |  full result -> resultHash
   v
9. TEE submits result to contract
   |
   |  submitResult(..., resultHash, composeHash, authorizationExpiry, verifierSignature)
   v
10. Buyer accepts, rejects, or deal expires
   |
   |-- acceptDeal(dealPayment)
   |-- rejectDeal()
   `-- expireDeal()
   |
   v
11. Pull-payment settlement
   |
   |-- seller withdraws payment if accepted
   |-- developer withdraws compute + fee
   `-- buyer withdraws refund
```

## Primary Data Flow

```
                         public chain data
             +--------------------------------------+
             | reserve, budget cap, result hash     |
             | score band, state, withdrawals       |
             +------------------+-------------------+
                                ^
                                |
seller artifact                 | bounded result only
or private corpus               |
        |                       |
        v                       |
+-------------------+       +---+-------------------+
| TEE ingress       |       | Tinker delegate TEE   |
|                   |       |                       |
| upload bytes      +------>| raw evaluation        |
| seal/store data   |       | TTT/RL/SFT/stub eval  |
| hash artifact     |       | cost meter            |
+-------------------+       | output bounding       |
                            +---+-------------------+
                                |
                                | no raw data, no weights,
                                | no exact metric leakage
                                v
                       +------------------+
                       | bounded output   |
                       | score band       |
                       | recommendation   |
                       | offer            |
                       | result hash      |
                       | attestation      |
                       +------------------+
```

Sensitive data classes and where they are allowed to exist:

```
email password / IMAP creds      tee-email-oracle sealed store only
email OTP                        tee-email-oracle memory, then bounded OTP response
Tinker session cookies           browser inside TEE only
Tinker API key                   tinker-delegate encrypted key store or Phala encrypted env
payment card details             encrypted-to-TEE payload, transient memory, Stripe iframe
seller artifact                  TEE memory or sealed store, never public
training checkpoints             Tinker run scoped to deal, TTL-enforced, cleaned up
raw model samples                evaluator-internal only
bounded score/offer/result hash  API response and chain
```

## The Four-Part Spine

The user-facing architecture can be read as a four-part chain:

```
        +------------------------+
        | Email encumbrance      |
        | "who may coordinate?"  |
        +-----------+------------+
                    |
                    v
        +------------------------+
        | Tinker encumbrance     |
        | "who may spend/run?"   |
        +-----------+------------+
                    |
                    v
        +------------------------+
        | TTT/RL bio validation  |
        | "what did it prove?"   |
        +-----------+------------+
                    |
                    v
        +------------------------+
        | DNAI settlement        |
        | "what may be revealed |
        |  and who gets paid?"   |
        +------------------------+
```

### 1. Email Encumbered Contract

Current concrete contract:

```
EmailOracleAuth.sol
```

Purpose:

```
authorize which measured TEE app may boot as the email oracle
authorize which consumer app compose hashes may request OTPs
allow owner-managed upgrade delay
allow owner to freeze oracle code authorization
allow separate freeze for consumer registry
allow an immediate emergency consumer kill switch that survives the freeze
support non-escalating delegation through consumer managers
```

Emergency consumer revocation (`[real]`): `emergencyRevokeConsumer(consumerAppId)`
flips `consumerEmergencyRevoked[consumer]` so `isConsumerAuthorized` returns false
for every one of that consumer's compose hashes at once — immediate, no timelock,
and deliberately NOT gated by `whenConsumerRegistryMutable` (per-hash removal is,
so a frozen registry could otherwise never kill a compromised consumer). Owner or
a consumer manager may trigger it (access-reducing); `restoreConsumer` is
owner-only and only while the registry is mutable, so once the registry is frozen
an emergency kill is permanent.

Hashed OTP-delivery audit (`[real]`): `recordOtpDelivery(consumerAppId,
deliveryHash)` emits `OtpDeliveryRecorded(consumer, deliveryHash, sequence,
timestamp)` for dispute resolution — `deliveryHash` is an off-chain commitment to
the delivery context (consumer, request id, OTP hash), never the raw OTP, and a
per-consumer `otpDeliveryCount` supplies an ordered sequence so gaps/duplicates
are detectable. Owner or consumer manager may record; fail-closed on zero
inputs and refuses to record for an emergency-revoked consumer
(`test/EmailOracleAuth.t.sol`, 41). The off-chain pairing is
`tinker_delegate.otp_delivery` (`[real]`): it computes that `deliveryHash` as
`keccak256(domain ‖ consumer ‖ request_id ‖ keccak256(otp))`, hashing the OTP
immediately so the raw code never leaves as anything but a hash, and
`otp_delivery_receipt` returns a bounded receipt (consumer/request hashed, OTP
only as a hash) (`tests/test_otp_delivery.py`, 6).

Runtime service:

```
tee-email-oracle
```

Runtime role:

```
create / load email credentials
seal email credentials with AES-256-GCM or dstack-derived key
connect to IMAP
extract magic-code OTPs for Tinker or other delegated accounts
serve health, inbox, pin, and attestation endpoints
act as future notification / confirmation channel for reviewers and owners
```

Clarification:

```
The email TEE is a no-human-access control channel.
It is used for OTPs and confirmations that an agent-owned account needs.
It is not the funding mechanism, and it does not by itself solve Tinker signup.
```

Diagram:

```
                     Base Sepolia
                 +-------------------+
                 | EmailOracleAuth   |
                 |-------------------|
                 | owner             |
                 | compose hashes    |
                 | device policy     |
                 | consumer hashes   |
                 | freeze flags      |
                 +---------+---------+
                           ^
                           | app auth / policy anchor
                           |
+--------------------------+---------------------------+
| tee-email-oracle CVM                                 |
|                                                      |
|  +-------------+      +-------------+      +-------+ |
|  | Credential  |<---->| IMAP client |<---->| email | |
|  | store       |      | OTP parser  |      | host  | |
|  +------+------+      +------+------+      +-------+ |
|         |                    |                       |
|         v                    v                       |
|  sealed email creds     /pin response                |
|                                                      |
|  endpoints: /health /pin /inbox /attestation         |
|             /credentials/encrypted                   |
+------------------------------------------------------+
```

Implementation status:

```
[real]      EmailOracleAuth.sol and tests.
[real]      email_oracle API, credential store, IMAP client.
[real]      Scoped `/pin` requests require target service, sender scope, nonce,
            caller identity, and reason; released OTP hashes are persisted for
            one-time-use across oracle restarts when the replay ledger decrypts.
[real]      OTP replay ledger is persisted under encrypted/sealed oracle storage.
[real]      Attestation-bound encrypted credential provisioning exists for an
            operator-held mailbox: `GET /attestation?context=oracle-credentials`
            exposes a context-bound public key and report-data hash, while
            `POST /credentials/encrypted` is disabled by default, requires an
            explicit provisioning bearer token, stores only through the sealed
            credential store, and returns hashes/status rather than raw mailbox
            credentials.
[real]      The main running Phala oracle has generated and sealed a mailbox in
            the CVM through a one-shot mailbox-genesis compose, then been
            redeployed back to the normal compose with `ORACLE_AUTO_GENESIS=false`.
            Public health/attestation expose `oracle_email=""`, readiness, and
            `oracle_email_hash`, while unauthenticated `/email` returns 401.
[real]      Live Tinker OTP receipt in the CVM is proven. During a live
            `/auth/reauth` this session the sealed cock.email mailbox oracle read
            the Tinker login code inside the TEE and the console authenticated
            (delegate logs: `[otp] got code` -> `[auth] authenticated`).
            Auto-signup bootstrap remains disabled by choice, not by blocker.
[partial]   App-auth contract is not yet enforced on every OTP API request.
[planned]   Reviewer notification, consent confirmation, outbound bounded-result delivery.
```

### 2. Tinker Encumbered Contract

`TinkerAccountEncumbrance.sol` is now the dedicated on-chain policy/audit
surface for the TEE-owned Tinker account. It does not custody card data,
credentials, or Tinker balances. It records and enforces bounded account
operation policy while the actual browser/API automation remains inside the TEE.
The current repo splits Tinker encumbrance across:

```
TinkerAccountEncumbrance.sol      account policy, manager limits, measurement allowlist, audit events
DiligenceRoom.sol                 on-chain escrow and bounded-result settlement
tinker-delegate service           TEE-held Tinker account and API key
IsolatedTinkerSession             runtime confinement around Tinker SDK usage
card_channel.py / billing.py      encrypted card channel and billing automation
```

Runtime role:

```
use tee-email-oracle OTP to create/sign into a Tinker account
seal Tinker API key
seal Tinker project/client configuration and proxy JWT signing key
issue scoped delegate JWTs only to approved recipients through encrypted delivery
verify signed hash-only identity registries before proxy JWT minting when required
check TinkerAccountEncumbrance deployment policy before minting spend/billing scoped proxy JWTs when required
drive Tinker billing through a browser session once auth/funding is unblocked
add balance using card-on-file or encrypted card payload once Stripe flow works
create a one-deal isolated Tinker session
meter compute and fee
check operation against TinkerAccountEncumbrance policy before funding/spend
clean up checkpoints after resolution
submit bounded result to DiligenceRoom
```

Current concrete policy contract:

```
TinkerAccountEncumbrance.sol
  owner
  accountCommitment = hash/commitment for the TEE-owned Tinker account
  approvedComposeHashes[composeHash] = true/false
  managers[account] = true/false
  maxAddBalanceWei
  maxSpendWei
  emergencyHalted
  measurementsFrozen

  authorizeOperation(operationId, kind, requester, composeHash, amountWei)
      — reverts SelfApprovalNotAllowed if requester == msg.sender (the authorizer
        cannot also be the requester of the funding op it authorizes; agents
        request, they do not self-approve — enforced on-chain, not just by role
        assignment); enforces per-kind caps (AddBalance/ManualPrefund <=
        maxAddBalanceWei, SpendTinkerCompute <= maxSpendWei, AddPaymentMethod == 0)
  settleOperation(operationId, success, receiptHash)   — double-settle-safe
```
Compose-hash approval/revocation and `freezeMeasurements` all require
measurements to be mutable (freeze is one-way and gates them); `setEmergencyHalt`
survives the freeze and blocks `authorizeOperation`
(`test/TinkerAccountEncumbrance.t.sol`, 10 incl. the non-self-approval case).

Diagram:

```
                          Base Sepolia
                 +---------------------------+
                 | DiligenceRoom.sol         |
                 |---------------------------|
                 | deals[dealId]             |
                 | seller / buyer            |
                 | reservePrice / budgetCap  |
                 | artifactHash              |
                 | teeIdentity               |
                 | scoreBand / resultHash    |
                 | pendingWithdrawals        |
                 +-------------+-------------+
                               ^
                               | submitResult / settle
                               |
+------------------------------+------------------------------+
| tinker-delegate CVM                                         |
|                                                             |
|  +----------------+       +----------------------+          |
|  | signup.py      |<----->| tee-email-oracle     |          |
|  | browser OTP    | OTP   | /pin                 |          |
|  +-------+--------+       +----------------------+          |
|          |                                                  |
|          v                                                  |
|  +----------------+      +----------------------+           |
|  | Tinker console |----->| sealed API key store |           |
|  | browser session|----->| sealed browser state |           |
|  +-------+--------+                 |                       |
|          |                          v                       |
|          |              +----------+-----------+             |
|          |              | sealed API key store |             |
|          |              +----------+-----------+             |
|          |                          v                       |
|          |              +--------------------------+        |
|          |              | IsolatedTinkerSession    |        |
|          |              | one training run/deal    |        |
|          |              | TTL checkpoints          |        |
|          |              | path-checked sampling    |        |
|          |              | cost meter               |        |
|          |              +------------+-------------+        |
|          |                           |                      |
|          v                           v                      |
|  +---------------+        +------------------------+        |
|  | billing.py    |        | evaluator/controlPlane |        |
|  | Stripe iframe |        | score band + offer     |        |
|  +---------------+        +------------------------+        |
+-------------------------------------------------------------+
```

Implementation status:

```
[real]      API routes, billing code, encrypted card channel, key store, control plane.
[real]      DiligenceRoom.sol and tests.
[real]      TinkerAccountEncumbrance.sol and tests. The contract stores a
            hashed Tinker account commitment, approved compose hashes,
            owner-managed managers, add-balance/spend caps, emergency halt,
            measurement freeze, operation authorization records, and bounded
            settlement receipt hashes. Managers can authorize/settle only
            operations inside owner-set caps and approved measurements; tests
            prove managers cannot set managers, change caps, approve
            measurements, toggle halt, exceed caps, or bypass compose,
            duplicate, and settlement guards.
[real]      The tinker-delegate runtime has a read-only
            TinkerAccountEncumbrance preflight helper and CLI. When
            `TINKER_ENCUMBRANCE_REQUIRED=true` or an encumbrance contract
            address is configured, payment-method and add-balance automation
            deny before card decryption or browser launch unless public
            contract reads show the compose hash is approved, emergency halt is
            off, and the amount is within cap. Proxy-token issuance can also
            require this deployment-policy preflight before minting
            spend/billing scoped JWTs, so denied compose approval, halt state,
            missing cap, or over-cap spend fails closed before token issuance.
[real]      A no-raw-key Base Sepolia deploy helper exists for
            TinkerAccountEncumbrance. It uses Foundry `--account dev`, validates
            the account commitment, initial compose hash, and caps, defaults the
            initial compose hash from the current Phala manifest, defaults the
            initial account commitment to the bounded `oracleEmailHash` only
            when no stronger Tinker account commitment is provided, runs
            build/tests and a simulation before broadcast, and updates
            `deployments/base-sepolia.json` only after successful on-chain
            reads.
[real]      TinkerAccountEncumbrance is deployed on Base Sepolia and recorded
            in the manifest as operator-controlled at
            `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e` with deployment tx
            `0x7679df09aa2e939d748be0e017f380f5e7e44331a482531380198e93bdcaed01`.
            On-chain reads confirm nonzero bytecode, owner
            `0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, approved compose
            hash
            `0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`,
            emergency halt false, and measurements frozen false. The latest
            operator-approved live policy hash for the deployed proxy
            issue/deployment-policy slice is
            `0x40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace`,
            approved in tx
            `0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6`
            at block `43928500`. A follow-up
            owner transaction
            `0x3ab263bb7cb7758787fa1136dd043cca002db9cf511b29ad20ef4d1216199d3f`
            raised both add-balance and spend caps to `$10`, with read-back
            returning `10000000000000000000` for both policy values. This makes
            the pre-card on-chain policy gate real for the current
            funding-validation and proxy issuance compose hashes.
[real]      Local Neko/CDP Tinker login, email OTP retrieval, onboarding, and API-key provisioning.
[real]      Signup/bootstrap stores captured Tinker API keys in encrypted
            storage and returns only bounded hash/status metadata.
[real]      Startup bootstrap runtime state preserves the bounded
            `api_key_provisioning` attempt record from signup success or
            selector/API-key-capture failure, plus early `tinker_auth`
            failures during account lookup, CDP/browser connection,
            context/page setup, auth, and onboarding. Public `/health` can
            therefore report `last_bootstrap_attempt_record` with outcome,
            furthest stage, hashes, and `raw_secret_egress=false` without
            exposing the mailbox, OTP, browser URL, page text, or API key.
[real]      Signup/signin observable egress is bounded before deployed bootstrap:
            stdout and return payloads expose `email_hash` / `url_hash` rather
            than raw mailbox addresses or Tinker browser URLs, and shared
            Tinker delegate redaction removes email addresses from rendered
            errors.
[real]      API-key provisioning uses a small selector fallback family for
            current Tinker key-creation copy plus aria-label/data-testid
            variants, returns bounded `api_key_provisioning` attempt records,
            including `selector_missing` when no key can be captured, and has
            replayable mock-page tests for successful extraction and selector
            drift failure paths.
[real]      `tinker-delegate selector-map` emits a bounded, machine-readable
            selector/frame/auth-flow contract for email auth, magic-code OTP,
            onboarding, API-key creation, billing payment method, Stripe iframe,
            balance top-up, and auto-reload surfaces. The map exposes declared
            selector families, counts, evidence labels, and a recomputable map
            hash only; it contains no account identifiers, OTPs, API keys, card
            details, cookies, raw page text, or browser session URLs. A summary
            mode omits concrete selectors for compact deployment evidence.
[real]      `tinker-delegate selector-probe` is the read-only live browser
            observation command for that contract. It connects to the configured
            Playwright/CDP browser, inspects current pages and frames without
            navigation, clicking, typing, screenshots, or page-text capture,
            and emits only URL classes, URL hashes, selector match bands, frame
            kinds, selector-map hash, bounded timestamps, and
            `raw_secret_egress=false`. Browser connection failures return
            bounded `browser_unavailable` JSON instead of tracebacks.
[real]      Source/tests also include a raw DevTools-protocol fallback for
            `selector-probe` when Playwright `connect_over_cdp` fails. The
            fallback uses the advertised WebSocket debugger URL in memory only,
            upgrades the raw WebSocket, runs `Target.getTargets`, attaches to
            up to five page targets, reads `Page.getFrameTree`, and emits only
            `probe_backend=raw_cdp`, stage booleans, HTTP status band,
            target/page/frame count bands, URL classes/hashes, frame kinds, and
            bounded error kinds, even when the fallback cannot complete target
            inventory. Source/tests preserve page-level inventory when
            per-page attach or frame-tree commands fail by emitting only
            `attach_error_kind`, `frame_tree_error_kind`, `partial_error_kind`,
            and empty frame observations for the affected page. It performs no
            navigation, clicking, typing, screenshots, page-text capture,
            cookie reads, DOM text extraction, or raw URL egress. It does not
            require successful frame traversal before preserving page identity.
            In source/tests, the raw-CDP fallback now also sends one bounded
            `Runtime.evaluate` command after page attach to count declared
            selector families as `0`, `1`, `2+`, or `probe_error` bands. Python
            maps the returned matrix onto known flow/family names, so public
            output cannot include page text, raw DOM, raw selectors, cookies,
            account identifiers, OTPs, API keys, card data, or arbitrary
            page-controlled strings. Source/tests now precede that selector
            matrix with a constant page-scoped Runtime micro-probe and emit
            only `runtime_micro_probe_command_success`,
            `runtime_micro_probe_success`, and
            `runtime_micro_probe_error_kind`; this bounded diagnostic
            distinguishes Runtime transport failure from selector-expression
            timeout without exposing page-controlled values. A Phala one-shot
            measurement with
            GitHub-attested `50de0a9` images proved the selector command path
            is built into the deployed image and preserves bounded output, but
            the page-scoped Runtime selector command still timed out. A
            follow-up one-shot measurement with GitHub-attested `5943c61`
            images proved that even the constant page-scoped Runtime
            micro-probe times out after page attach:
            `partial_error_kind=runtime_micro_probe_timeout`,
            `runtime_micro_probe_command_success=false`,
            `runtime_micro_probe_error_kind=timeout`,
            `runtime_selector_command_success=false`, and
            `flow_observations=[]`. This narrows the blocker to page-scoped
            Runtime command delivery/evaluation in the deployed Neko/CDP path,
            not selector-expression complexity. Selector-family bands are
            therefore source/test-real but still not Phala-proven; the next
            source/test-real diagnostic now sends `Runtime.enable` before the
            constant micro-probe and emits only bounded runtime/session fields:
            `runtime_enable_command_success`,
            `runtime_execution_context_event_observed`,
            `runtime_enable_success`, `runtime_enable_error_kind`,
            `runtime_event_before_enable_response`,
            `runtime_event_count_band`, and
            `runtime_execution_context_created`. It does not emit event
            payloads, context IDs, frame IDs, raw URLs, page text, selectors,
            cookies, OTPs, API keys, or card material. It still needs a
            GitHub-attested image build and Phala measurement before it can be
            treated as deployed evidence. A follow-up one-shot Phala
            measurement with GitHub-attested `9d69364` images proved
            `Runtime.enable` itself times out on the attached page session:
            `partial_error_kind=runtime_enable_timeout`,
            `runtime_enable_command_success=false`,
            `runtime_execution_context_event_observed=false`,
            `runtime_enable_error_kind=timeout`,
            `runtime_event_count_band=0`,
            `runtime_execution_context_created=false`,
            `runtime_micro_probe_command_success=false`,
            `runtime_selector_command_success=false`, and
            `flow_observations=[]`. Selector-family bands are still not
            Phala-proven; next work is to repair or route around the deployed
            Neko/CDP attached-session Runtime domain timeout. Source/tests now
            add that route-around candidate: if attached-session
            `Runtime.enable` fails, the raw-CDP fallback fetches bounded
            page-target inventory from `/json/list`, connects directly to the
            matching page target WebSocket, and retries `Runtime.enable`, the
            constant micro-probe, and the selector-family matrix. The nested
            `direct_page_runtime` receipt emits only page-list success,
            page-WebSocket availability, Runtime enable/error/event-count
            bands, micro-probe success/error, selector success/error, and
            declared selector-family count bands. It emits no raw page URLs,
            WebSocket URLs, event payloads, context IDs, frame IDs, page text,
            raw selectors, cookies, OTPs, API keys, or card material. A
            follow-up Phala measurement with GitHub-attested `bf39f56` images
            proved the direct route can fetch `/json/list` and reach the page
            target WebSocket, but direct page `Runtime.enable` still timed out:
            `direct_page_runtime_attempted=true`,
            `direct_page_runtime.page_list_success=true`,
            `direct_page_runtime.page_websocket_available=true`,
            `direct_page_runtime_enable_success=false`,
            `direct_page_runtime.runtime_enable_error_kind=timeout`, no
            micro-probe, no selector-family matrix, empty `flow_observations`,
            and `raw_secret_egress=false`. The current deployed blocker is the
            page Runtime domain itself, not just the attached-session routing.
            Source/tests now add one more bounded discriminator before that
            Runtime step: both the attached-session path and direct page-target
            path send `Page.enable` before `Runtime.enable` and emit only
            `page_enable_command_success`,
            `page_enable_success`, and `page_enable_error_kind`. These fields
            reveal whether page-domain CDP commands succeed before the Runtime
            domain hangs, without emitting page text, raw URLs, selectors,
            cookies, OTPs, API keys, card material, event payloads, frame IDs,
            or execution-context IDs. The 2026-07-08 Phala measurement on
            GitHub-attested `556387a` images returned
            `partial_error_kind=page_enable_timeout`,
            `page_enable_command_success=false`, and direct page-target
            `page_enable_success=false` / `page_enable_error_kind=timeout`
            after proving `/json/list` and page-WebSocket availability. The
            deployed blocker is therefore lower than Runtime-specific command
            handling: page-target CDP command delivery through the Phala Neko
            path does not complete even for `Page.enable`.
[real]      `GET /browser/selector-probe` wraps the same probe for deployed
            one-shot evidence capture. It is disabled by default and returns
            403 unless `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true`; when enabled
            it still performs no navigation, clicking, typing, screenshots, or
            page-text capture, and browser failures are reduced to bounded
            `browser_unavailable` JSON. The normal Phala compose keeps this
            endpoint disabled; enabling it is a temporary measurement profile,
            not a widened production interface.
[real]      `tinker-delegate browser-readiness` and `GET /browser/readiness`
            provide bounded browser-control diagnostics for the deployed
            selector-probe failure path. They report endpoint classes/hashes,
            CDP metadata reachability, raw WebSocket upgrade stage bands,
            one-command CDP protocol probe bands, Playwright/CDP handshake
            success bands, and bounded error kinds only. They do not navigate,
            click, type, screenshot, inspect pages/frames, return page text, or
            expose raw CDP/browser URLs. The raw WebSocket diagnostic keeps the
            advertised debugger URL in memory only and emits URL class/hash,
            TCP/TLS/upgrade stage booleans, HTTP status band, and bounded error
            kind. The post-upgrade protocol probe is source/test-real: it sends
            exactly one browser-scoped `Browser.getVersion` command after a
            successful Upgrade and emits only command/response booleans,
            response kind, browser family, URL class/hash, status band, and
            bounded error kind; it does not emit the CDP response body. The HTTP
            endpoint is disabled by default and normal Phala compose binds
            `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=false`; the one-shot
            measurement profile enables it temporarily. The pre-WebSocket-stage
            version is Phala-proven: the one-shot endpoint returned bounded
            `cdp_timeout` after CDP metadata succeeded, and the restored normal
            compose returns 403. The raw WebSocket stage is Phala-proven with
            GitHub-attested `7973b27` images: CDP metadata succeeded, the raw
            WebSocket TCP connect and HTTP Upgrade succeeded with status band
            `101`, and Playwright `connect_over_cdp` still timed out. The
            post-upgrade protocol probe is Phala-proven with GitHub-attested
            `59a9eac` images: after HTTP `101`, one browser-scoped
            `Browser.getVersion` command returned a bounded `result` response
            and Chromium browser-family band, while Playwright
            `connect_over_cdp` still timed out. This narrows the remaining
            deployed browser-control blocker to the Playwright CDP client path.
[partial]   The selector-probe endpoint has been Phala-proven as an endpoint
            gate and fail-closed path using GitHub-attested `7973b27` images:
            one-shot bootstrap compose enabled the endpoint, live response was
            bounded `browser_unavailable` with `raw_secret_egress=false`, and
            the restored normal compose returns 403. The paired readiness
            endpoint showed CDP metadata reachable with Chromium WebSocket
            metadata advertised, raw WebSocket upgrade status `101`, a
            successful bounded one-command CDP protocol response, then
            `connect_over_cdp` timeout. The raw-CDP fallback is Phala-proven
            through target inventory with GitHub-attested `f63dd18` images:
            metadata succeeded, WebSocket Upgrade returned status band `101`,
            `Target.getTargets` succeeded, and the bounded receipt reported
            target count `2+` and page count `1` with no raw URL/page text
            egress. The timeout-preserving page observation path is also
            Phala-proven with GitHub-attested `a384db2` images: the one-shot
            selector probe returned `probe_backend=raw_cdp`, `success=true`,
            target count `2+`, page count `1`, `pages_observed=1`, a bounded
            page URL class/hash, `attached=true`,
            `frame_tree_error_kind=timeout`,
            `partial_error_kind=frame_tree_timeout`, empty frame observations,
            and `raw_secret_egress=false`. The CVM was restored to normal
            compose afterward, and both diagnostic endpoints returned 403.
            `Page.getFrameTree` still times out, so actual frame inventory
            remains open. Source/tests now add bounded raw-CDP Runtime selector
            counting that should capture deployed selector-family bands even
            when frame traversal times out, but the 2026-07-08 Phala
            measurement on `50de0a9` images returned
            `runtime_selector_error_kind=timeout` and empty
            `flow_observations`. The follow-up 2026-07-08 Phala measurement on
            GitHub-attested `5943c61` images added a preceding constant Runtime
            micro-probe and returned
            `partial_error_kind=runtime_micro_probe_timeout`,
            `runtime_micro_probe_command_success=false`,
            `runtime_micro_probe_error_kind=timeout`,
            `runtime_selector_command_success=false`, and empty
            `flow_observations`. The deployed timeout is therefore below the
            selector expression itself. Source/tests now add a bounded
            Runtime/session diagnostic by running `Runtime.enable` before the
            constant micro-probe and recording only success/error/event-count
            bands. The 2026-07-08 Phala measurement on GitHub-attested
            `9d69364` images returned `runtime_enable_timeout`, no Runtime
            execution-context event, no micro-probe, and no selector
            evaluation. The deployed blocker is therefore the attached-session
            Runtime domain itself. Source/tests now add a direct page-target
            WebSocket Runtime route that can recover selector-family bands
            after an attached-session `Runtime.enable` timeout in tests. The
            2026-07-08 Phala measurement on GitHub-attested `bf39f56` images
            proved `/json/list` and page-WebSocket availability, but direct
            page `Runtime.enable` also timed out, so deployed selector-family
            evidence remains blocked on Neko/Chrome Runtime-domain behavior.
            A follow-up Phala measurement on GitHub-attested `556387a` images
            shows `Page.enable` also times out on the deployed page target, so
            selector-family evidence remains blocked on lower-level Neko/Chrome
            CDP command delivery rather than selector expressions.
            A 2026-07-09 one-shot measurement using the tracked
            `docker-compose.selector-diagnostics.phala.yaml` profile and
            GitHub-attested `eb3bde3` images revalidated the same failure mode
            against the current funding-validation image set: browser-level CDP
            metadata, WebSocket upgrade, and `Browser.getVersion` succeed;
            raw-CDP target/page inventory and page attach succeed; both the
            attached-session and direct page-target paths time out at
            `Page.enable` before Runtime or selector-family counting can run.
            The CVM was restored to the funding-validation profile afterward
            and both diagnostic endpoints return 403 disabled.
[real]      Tinker re-auth exists as a bounded OTP refresh path through
            `reauth` and opt-in `POST /auth/reauth`; it returns only
            `tinker_auth` attempt records and does not expose account email,
            OTP, browser URL, API key, or page text.
[real]      Source/tests now persist successful signup/signin/reauth
            Playwright `storage_state` to an encrypted browser-session store
            under the delegate data volume, using a separate
            `tinker/browser_session` dstack key path from API keys and funding
            receipts. Billing creates fresh browser contexts from that sealed
            state when no reusable context exists, so `/auth/reauth` can
            prepare the later encrypted-card/add-balance request without
            exposing cookies, localStorage, raw URLs, OTPs, page text, or card
            data. Compose hardening tests keep the store under `/data`. The
            slice is now Phala-deployed in the funding-validation profile, but
            no useful live session has been saved yet because deployed
            `/auth/reauth` still fails before OTP with bounded
            `auth_access_blocked`.
[real]      `⚙️/tinker-delegate/docs/TINKER-AUTOMATION-ROUTE.md` records the
            acceptable Tinker automation route: prefer official/support-approved
            workflows; use browser automation only as bounded TEE custody for
            this project's own account; fail closed rather than add stealth,
            CAPTCHA-solving, rotating-proxy, or automation-control masking.
            Static tests enforce those no-evasion runtime dependencies/flags.
[real]      Local Stripe test-card billing path reaches submission and returns a bounded decline.
[real]      Billing automation returns bounded payment-method and add-balance
            attempt records: outcome class, furthest stage, issued timestamp,
            evidence hash, amount/balance bands, TDX quote hash when present,
            and card-payload destruction status. Raw card values and page text
            are not returned.
[real]      Billing automation uses explicit selector fallback families for
            Tinker balance/payment controls, payment-method submit controls,
            cardholder/address fields, add-balance amount fields, and top-up
            confirmation controls. Replayable mock-page tests cover current
            selectors plus data-testid/aria-style drift, and missing top-up
            controls return bounded `selector_missing` receipts without page
            text.
[real]      Payment-method debug screenshots are suppressed after card entry
            and payment submission even when debug screenshots are enabled;
            non-secret billing screenshots still require explicit debug opt-in.
[real]      Card submission attempts purge known secret-bearing browser debug
            artifacts (`trace*.zip`, HAR, video, card/Stripe screenshots) from
            an explicitly configured debug artifact directory.
[real]      `verify-deployed-log-safety` scans deployed logs or Phala console
            captures for card-shaped values, unredacted card/CVC fields, Tinker
            API keys, bearer/JWT tokens, OTP fields, and private-key-shaped
            fields. It returns only finding classes/counts and line hashes, not
            log snippets. A live operator-validation scan of the current Phala
            CVM tail found zero findings; this is not production-current until
            the temporary public-log/dev-OS posture is removed.
[real]      Tinker delegate Python entrypoints set `RLIMIT_CORE=0`, and local /
            Phala compose services for the delegate and browser path set
            `ulimits.core: 0` to prevent core dumps from persisting secrets.
[real]      Bounded funding attempt records are persisted in encrypted/sealed
            delegate storage with a separate `tinker/funding_receipts` dstack
            key path and can be read through `GET /billing/funding-receipts`.
            The store rejects unknown fields and `raw_secret_egress=true`.
[real]      Bounded deal/run lifecycle metadata is persisted in a separate
            encrypted/sealed delegate store at `/data/run_metadata.enc` in
            compose profiles, with its own `tinker/run_metadata` dstack key
            path. Control-plane events store hashed deal/account/run handles,
            artifact hashes and size bands, score/offer/cost bands, and
            cleanup counts; raw artifacts, API keys, card fields, checkpoint
            IDs, and raw Tinker run IDs are not allowed in the schema.
[real]      Add-balance automation enforces whole-dollar
            `TINKER_MIN_ADD_BALANCE_USD` / `TINKER_MAX_ADD_BALANCE_USD`
            bounds before launching browser automation. Non-finite,
            non-positive, below-minimum, fractional, and over-cap requests
            return bounded `policy_denied` `add_balance` receipts at
            `not_started` with amount bands, not page text.
[real]      Card-on-file status is exposed only through bounded
            `GET /billing/payment-method-status`: `card_on_file` and
            `payment_method_count_band`. The admin/operator removal surface is
            `POST /billing/card/remove`, emits a bounded removal receipt, and
            does not expose card brand, last4, expiry, billing address, or raw
            page text. The operator `balance` CLI can target a deployed
            delegate with `--api-url` and emits the same bounded response shape
            as `GET /billing/balance`, so balance read-back can be captured
            without exposing card metadata. Read-only billing endpoints also
            classify browser/navigation exceptions into stable outcome labels
            such as `transient_browser_failure`; they must not return raw
            Playwright call logs, Tinker URLs, selectors, page text, or
            screenshots.
[real]      Account access / billing-gate detection is an automated bounded step
            (`account_access.py` + `billing.get_account_access_status` +
            `account-access-status` CLI + operator-authed
            `GET /billing/account-access-status`). It classifies the account page into a
            closed state vocabulary (`active`, `access_blocked_billing`,
            `payment_required`, `waitlist_or_gated`, `unknown`) with an
            `actionable_by_automation` flag, an `operator_action`, and a
            `page_text_hash` to detect gate changes across runs — bounded output
            only. The observed live gate classifies as `access_blocked_billing`,
            `actionable_by_automation=false`,
            `operator_action=contact_provider_for_account_activation`: adding a
            card and $20 balance did not clear it, so it is a Thinking Machines
            server-side account-activation gate that automation can *detect* but
            not force. This is the automated detector; resolving activation is an
            out-of-band provider action (see STATUS.md).
[real]      Session-state classifier (`session_state.py`): before the automation
            refreshes an OTP it decides whether that is safe. It classifies the
            auth page text plus a recent-failed-attempt count into a bounded state
            — `session_active` (proceed), `stale_session` (a single OTP refresh is
            the safe recovery), `login_loop` (rate-limit/lockout text OR
            `recent_failed_attempts >= max_attempts` — fail closed, never hammer
            the OTP / email oracle), `unknown` (fail closed). The attempt count is
            authoritative over the page text, so a loop cannot be masked by a
            normal-looking stale-session page. `session_state_receipt` emits a
            bounded `should_refresh_otp` + page-text hash, no raw text/codes
            (`tests/test_session_state.py`, 12).
[real]      `TINKER_FUNDING_MODE=manual_prefund` is the default production
            funding model and denies card/add-balance browser automation before
            decryption or browser launch. `operator_capped_validation` is
            required for one-off approved operator validation attempts; denied
            requests persist bounded `policy_denied` receipts. The bounded
            policy is inspectable through `GET /billing/funding-policy` and
            the `funding-policy` CLI.
[real]      Operator funding preflight is available through
            `GET /billing/funding-preflight` and the `funding-preflight` CLI.
            It checks funding mode, requested amount cap, optional add-balance
            endpoint flag, encrypted receipt-store availability, and billing
            attestation policy before any card payload or browser launch. The
            CLI can write the bounded preflight JSON directly with `--output`.
[real]      A local FastAPI funding smoke on 2026-07-08 verified the current
            operator guardrails without real card material: `$5` preflight
            passed under `operator_capped_validation`, `$10` preflight failed
            the cap and disabled add-balance endpoint checks, `/attestation`
            returned a context-bound local billing key, encrypted
            `/billing/card/encrypted` posted only ciphertext and returned a
            bounded `payment_method` receipt at `payment_submitted`, and the
            encrypted temp receipt file did not contain the test card number,
            CVC, cardholder name, postal code, or raw card field names.
[real]      Bounded funding validation manifests can be built from saved
            preflight and receipt JSON through the `funding-manifest` CLI. The
            manifest stores hashes, bands, outcome, TDX quote hash, and
            card-destruction/no-raw-egress booleans; it rejects raw card,
            API-key, and secret-shaped inputs and does not store card material.
[real]      Saved funding manifests can be replay-verified with
            `verify-funding-manifest`, which recomputes preflight, receipt,
            validation-ID, attestation-policy, and manifest hashes and returns
            named bounded pass/fail checks without echoing packet contents.
[real]      Billing receipt-producing CLIs can write bounded attempt records
            with `--receipt-output` for later manifest binding. CLI rendering
            fails closed before printing or writing JSON when output contains
            secret-shaped material or submitted card values.
[real]      `funding-validation-packet` generates a bounded operator packet in
            one command: preflight JSON, receipt JSON, manifest JSON,
            verification JSON, and summary JSON. It can bind an existing
            bounded receipt, or run encrypted card submission only when
            `--run-card-attempt` is explicitly set; card fields without that
            flag are rejected before any network or browser path.
[real]      Packet generation supports `--prompt-card` for approved operator
            validation: card fields are prompted interactively instead of
            accepted through command-line arguments, prompt mode is mutually
            exclusive with test-card flags, and deployed compose/app/OS-image
            attestation expectations are required before prompting unless
            local-development attestation is explicitly allowed.
[real]      Prompt-based real-card operator paths can also require the deployed
            TinkerAccountEncumbrance policy before any card field prompt.
            `add-card-encrypted-prompt` and
            `funding-validation-packet --prompt-card --run-card-attempt` accept
            `--require-encumbrance` plus contract/RPC/compose inputs; they run
            read-only contract checks for add-payment-method and, when a top-up
            amount is part of the same packet, add-balance cap approval. Denied
            or unavailable policy exits before card material is entered.
[real]      `funding-command-plan` turns the deployment manifest into a bounded
            operator command plan. It reads only public deployment evidence
            (`delegate` endpoint, compose hash, app ID, OS image hash, and
            TinkerAccountEncumbrance policy) and emits argv/shell templates for
            funding preflight, encumbrance preflight, and the eventual
            prompt-card funding-validation packet. It references
            `TINKER_RUNTIME_AUTH_TOKEN`
            and `BASE_SEPOLIA_RPC_URL` by environment-variable name only and
            never prints bearer tokens, card fields, API keys, OTPs, RPC
            values, cookies, or browser/session material. The deploy helper
            used Foundry `--account` through the encrypted keystore; no raw
            private-key path was emitted. The current manifest-derived plan is
            `ready=true` for the bounded policy/encumbrance checks, with a
            remaining warning that the CVM still reports dev OS.
[real]      `tinker-encumbrance-preflight` reads only public
            `TinkerAccountEncumbrance` state and exits before card prompting
            when the compose hash is not approved, emergency halt is set, or the
            requested amount exceeds the cap. Its bounded JSON renderer marks
            public chain fields (`contract_address`, `compose_hash`,
            `amount_wei`, `max_amount_wei`) as public before generic
            secret-shape checks, so public wei/address values do not create
            false positives while card/API-key/OTP-shaped material still fails
            closed.
[real]      Operator-only mutation endpoints now have delegate runtime bearer
            auth. When `TINKER_RUNTIME_AUTH_REQUIRED=true`,
            `/auth/reauth`, `/billing/card/encrypted`,
            `/billing/add-balance`, `/billing/funding-receipts`, and the
            explicitly local plaintext card endpoint require
            `Authorization: Bearer ...`; missing tokens fail 401, wrong tokens
            fail 403, and misconfigured required auth fails closed. The token
            can be supplied explicitly through `TINKER_RUNTIME_AUTH_TOKEN` for
            operator CLI runs, or derived inside dstack from
            `TINKER_RUNTIME_AUTH_KEY_PATH` for same-TEE callers. The
            `/auth/reauth` endpoint has an API-level fail-closed wrapper so an
            uncaught browser exception still returns a bounded `tinker_auth`
            receipt instead of a non-JSON 500 or raw browser call log.
[real]      Funding validation packets can also include separate add-balance
            evidence: an add-balance receipt, manifest, verification, and
            summary fields. The runner can bind an existing bounded top-up
            receipt, or POST only the amount to `/billing/add-balance` when
            `--run-add-balance-attempt` is explicitly set and `--amount` is
            provided. When a bounded `card_on_file` check already establishes
            that Tinker has a payment method, an add-balance-only packet is
            valid: it writes only the add-balance receipt/manifest/verification
            plus preflight and summary, and replay checking accepts that shape
            with `--require-add-balance`. It still refuses empty packets and
            does not include card details, card metadata, or payment-method
            receipts unless a card attempt is explicitly requested.
[real]      `docker-compose.tinker-funding-validation.phala.yaml` is a
            temporary one-shot Phala profile for capped operator validation.
            It uses registry digest images only, disables signup/bootstrap and
            plaintext card submission, enables reauth/encrypted-card/add-balance
            only behind runtime bearer auth, sets
            `TINKER_FUNDING_MODE=operator_capped_validation`, source defaults
            cap top-ups at the current Tinker minimum `$10`, and routes browser
            work through the custom GitHub-attested `neko-chrome` CDP path with
            the baked proxy on `9222`. The live deployed encumbrance has been
            updated to `$10` add-balance/spend caps, but each refreshed Phala
            compose hash must still be explicitly approved on-chain before
            add-balance can proceed.
[real]      `docker-compose.selector-diagnostics.phala.yaml` is a temporary
            Phala diagnostics profile for the main CVM. It uses registry image
            digests only, disables Tinker bootstrap and all card/funding
            mutations, keeps runtime bearer auth enabled, and enables only the
            read-only bounded browser readiness and selector-probe routes. It
            is not a production or funding posture; it exists to collect
            bounded browser-control evidence and must be reverted immediately
            after each measurement.
[real]      The funding-validation profile was refreshed on Phala on
            2026-07-09 with GitHub-attested source
            `6ff5531aabb952b3266210afa6c0b6bfb8860103` images:
            `tee-email-oracle@sha256:f5c346912f3391e699252dba47c673902d06ffe528a8bab9732a76d551ec42ab`,
            `tinker-delegate@sha256:f9eb714c5630549441636b8a5525b20c9518e863940a3b8e072dff5a5dcab37d`,
            and
            `neko-chrome@sha256:525e43d585828d1d9aa1bceaf7c8cfffc2eec47abf67e0b10550bf05338c4a07`.
            Local image-attestation checks passed for all three images, the
            local image-policy hash is
            `a0045b4a0995f858dde0d473a16b997459a6bd009f78c55b0d5ee471ba58f81f`,
            the rendered compose SHA-256 is
            `e8938c5c3896376df2219ddcee78dd26c82963c6fc57ab98431ce6b39122302f`,
            and the live attested compose hash is
            `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`.
            Health is OK, the email oracle is ready, IMAP is connected, the
            Tinker API key is available from encrypted storage, public logs
            remain disabled, and unauthenticated reauth/add-balance calls fail
            closed with `401 Bearer token required`.
[partial]   The funding-validation profile is live, quote-bound, backed by a
            deployed TinkerAccountEncumbrance policy, and has working
            authenticated `/auth/reauth`. It was refreshed again on 2026-07-09
            from source `8a571347d946fd6c23a84db256fd99f7169061e5` with
            GitHub-attested digest images:
            `tee-email-oracle@sha256:beedfc6c3f1f0c9dca8604d6adf6522110e8dc2f15af1e8a9145e0e3227939a9`,
            `tinker-delegate@sha256:3e03e4dccde8ef732641fdd091597a683674ca3b065b950a983aab16c6b88878`,
            and
            `neko-chrome@sha256:fd6a65a894befc66901ed7b915c792f3a669b74ef4ace01813815e1f1030b456`.
            The existing CVM now attests live compose hash
            `9f0754be7b7bcd3db9c808e5630f7f0aca39a33bbe37f898b8714de6d9aa4d71`;
            the local image-policy hash is
            `880db4987c00ecd8643aedc794415accd83c47a337b4512810d9fe5cadab8e6a`,
            and the rendered compose SHA-256 is
            `962e0352a468460eaa6085a2a32a6b7005798c7e3e5f3ff71e9799fa0cf67ea7`.
            Live `/billing/funding-policy` reports `$10` minimum and `$10` cap,
            `/auth/reauth` succeeds, and bounded payment-method status reports
            `card_on_file=false` / count band `zero`. The owner approved the
            new live compose hash in `TinkerAccountEncumbrance` on Base Sepolia
            in tx
            `0xb7e6d0fc504146d88005339bd859142a5f2d6c3f99315d81cb00742ebc15d48e`
            at block `43905420`; read-only `$10` preflight now returns ready.
            Packet `/tmp/dnai-tinker-funding-validation-packet-20260709T065233Z`
            still timed out before payment-method or add-balance receipts were
            written, and a later bounded card-status probe still reported
            `card_on_file=false`. Local client fix `5ab9e81` adds masked prompt
            echo/backspace support and increases encrypted-card upload timeout
            to 180 seconds; no CVM redeploy is required for that client-only
            change. Packet
            `/tmp/dnai-tinker-funding-validation-packet-20260709T071145Z`
            completed wrapper/manifest generation but did not prove funding:
            payment-method fallback was blocked by an open modal scrim before
            it reached the card form, and add-balance was not confirmed. Local
            source now dismisses open billing dialogs before tab fallback,
            constrains browser-exception receipt messages to bounded outcome
            strings, and fixes prompt newlines; those browser-side source
            changes were built by GitHub Actions run `29001302688` from source
            `658f6020db9972e0f7e1e914f72422ff5d08535f` into verified delegate
            digest
            `35bcc693300644445af40e7d4eb5d488848a2006ed2d42b7f56638c60963c92c`
            and redeployed to the existing CVM. The live TDX envelope now
            reports compose hash
            `7edf41c2b7bec5531639df94b90e2d2b5d1ac181f07db17f012c085d8cdb6476`;
            reauth succeeds, and the operator approved that compose hash
            on-chain. The next deployed packet produced a real `payment_method`
            success at `payment_submitted`, proving the encrypted-card/payment
            method leg. Add-balance remains partial: the
            receipt reached `add_balance_submitted` but was unconfirmed and
            exposed an overly broad billing-error classifier for `Payment
            methods` navigation text. Source now tightens that classifier and
            requires explicit add-balance success copy before returning success.
            That fix was built from source
            `2ab388103817bfbfaa7e20579a79213ed87fd85a`, verified against
            GitHub provenance and SPDX SBOM attestations for delegate digest
            `06c8d0fadd98922f0c6f5bded92b414be2bf423fc3c3e6af1b8e9e36b8c6975f`,
            and redeployed. A later startup-deferred oracle refresh moved live
            TDX attestation to compose hash
            `1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28`;
            oracle health now serves degraded-but-bounded readiness without
            blocking on IMAP startup, and the owner approved that compose hash
            in `TinkerAccountEncumbrance` tx
            `0x9caf683b80b3c06a8b5de0f8ebeffcfd44d5a6f0305c285df9f32fdb687e402e`.
            On-chain add-balance preflight now returns `allowed=true` for
            `$10`. The profile is still not production-final because the CVM
            reports dev OS, quote internals are not parsed, and a successful
            live real-card add-balance receipt has not yet been produced.
[real]      The current funding-validation deployment has since advanced to
            source `b9a962f64fe0ec4a10ce4fe4bc97787a22f82995`, GitHub Actions
            run `29012433267`, and attested Phala compose hash
            `a15af6d8e7262d7d2799fa31968c568933f3468771b808720583a6dc6ed998c5`.
            The verified digest-pinned images are
            `tee-email-oracle@sha256:ce0ea569280a796ce2a3d5517e22d03ad72a9d7a316a550d11bd1b155a85a5ce`,
            `tinker-delegate@sha256:1e3da3a88ef037b85678c7122a1a4a11a01ae687a36a57fd38deb1ed8984461e`,
            and
            `neko-chrome@sha256:7c0795e15e660d4501b6324c7f223fd65f22725a7752b683ae30a2874d373d01`.
            `verify-cvm-attestation` passed against the app ID, OS image hash,
            compose hash, and all three image digests. The owner approved that
            compose hash on-chain in tx
            `0x186d1ea81d9dfbeb0898485defcf427e8155cbcbb0f9e225326092616bd51c34`
            at block `43913068`, and read-only add-balance preflight returns
            `allowed=true` for `$10`.
            Live packet
            `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` proves
            authenticated `/auth/reauth` succeeds, the add-balance browser leg
            reaches `add_balance_submitted`, and all funding evidence remains
            bounded with `raw_secret_egress=false`. The add-balance receipt
            still fails closed as `unknown_failure` because the browser did not
            observe explicit success copy, but an independent bounded balance
            read returned `balance="$10.00"`. Packet replay verification passed
            with the full deployed identity and live attestation requirement, so
            low-value operator-validation funding is real.
[partial]   The live funding-validation CVM is currently in an explicitly
            temporary debugging posture: dev OS (`os.is_dev=true`),
            `secure_time=false`, public logs/sysinfo/TCB info enabled, and
            browser/CDP debug ports exposed. This improves live diagnosis but
            widens observability and must be reverted before any production
            deployment claim.
[real]      Source/tests now distinguish billing selector drift from auth-state
            failure before card fields or top-up controls are touched. The
            payment-method and add-balance flows classify a billing navigation
            that lands on sign-in or magic-code surfaces as bounded
            `auth_required`, and a page containing Tinker's access-blocked
            surface as bounded `auth_access_blocked`, both at
            `billing_page_loaded` without echoing page text. This extends the
            bounded receipt vocabulary with `auth_required`.
[real]      Source/tests and the live Phala funding-validation profile now
            preserve bounded auth-flow stage evidence for Tinker auth blocks.
            `AuthAccessBlockedError`, signup, and `/auth/reauth` carry
            `auth_page_loaded`, `auth_email_submitted`, or
            `auth_otp_page_reached` as the receipt `furthest_stage` rather than
            collapsing every auth block to `not_started`. The 2026-07-08 live
            repro returned `auth_access_blocked` at `auth_email_submitted` with
            `raw_secret_egress=false`. The stage values are enum labels only;
            page text, raw URLs, OTPs, cookies, API keys, and account
            identifiers remain outside the public receipt.
[real]      The billing auth-state classifier was rebuilt by GitHub Actions,
            verified with provenance/SBOM attestations, pinned by digest,
            redeployed to the funding-validation Phala profile, and live-tested
            against encrypted Stripe test-card and `$5` add-balance probes.
            The deployed result proves the blocker is Tinker auth/session
            continuity rather than true billing selector drift.
[real]      `check-funding-validation-packet` replay-checks packet directories:
            required files, payment manifest replay, optional add-balance
            manifest replay, summary hash consistency, and optional deployed
            TDX attestation evidence. It returns only bounded pass/fail checks
            and does not echo packet bodies.
[real]      The FastAPI `POST /billing/add-balance` mutation endpoint is
            disabled by default behind `TINKER_ALLOW_ADD_BALANCE_ENDPOINT`.
            The lower-level CLI/internal handler still requires
            `operator_capped_validation` mode before deliberate capped operator
            validation attempts.
[real]      Stripe/PCI funding stance is documented in
            `⚙️/tinker-delegate/docs/STRIPE-PCI-FUNDING-SCOPE.md`: the
            encrypted raw-card channel is only an operator-owned capped
            validation path, while production or repeated funding should use an
            official Tinker route, Stripe-hosted/tokenized collection,
            SetupIntent / PaymentMethod style reuse with consent, or
            manual/developer prefunding until compliance review approves
            otherwise.
[real]      Plaintext card API is disabled by default and unavailable in dstack mode.
[real]      Central redaction helpers scrub bearer, OTP/password, card, API-key,
            and artifact-shaped values from bounded errors and high-risk logs.
            Coverage includes the Tinker key (`tml-`) AND OpenAI/OpenRouter-style
            `sk-`/`sk-or-v1-` keys (the evaluator's `OPENROUTER_API_KEY`, a
            self-review gap closed 2026-07-12) — `redact_text` also underpins the
            egress guard's `secret_shaped` check, and a benign-output test confirms
            the new pattern adds no false positives.
[real]      Email-oracle genesis, browser signup, IMAP search, and check-command
            logs use stable SHA-256 hashes for generated mailbox identifiers,
            sender filters, and mail subject/sender headers instead of printing
            the raw values. This supports temporary Phala public-log debugging
            after a log-hardened image is built/deployed, but does not change
            `/pin` response contracts.
[real]      Artifact upload verifies Ethereum keccak256 against artifactHash
            before DealContext state changes; mutable API decode buffers and
            stored control-plane artifact buffers are best-effort zeroed.
[real]      `tinker_delegate.destruction_record` produces a bounded, recomputable
            attested destruction record from post-deal cleanup facts (artifact
            deleted, memory zeroed, keys dropped, checkpoints deleted/expired).
            Fail-closed: `complete` is true only when every required step
            succeeded, else `incomplete_destruction:<missing>`. Bounded: the deal
            ref is hashed, the artifact commitment is a hash, only counts/booleans
            leave; `verify_destruction_record` detects tampering
            (`tests/test_destruction_record.py`, 10). Wired into the control plane:
            `ControlPlane.on_deal_resolved` evaluates the room retention policy and
            builds a `DestructionRecord` from the real cleanup (artifact zeroing +
            session checkpoint-delete counts), stores both on the `DealContext`,
            and emits bounded `retention_action`/`destruction_complete`/
            `destruction_record_hash` on the `deal_resolved` metadata event.
            Resolution always destroys (safe default); honoring a retain/archive
            decision needs a sealed-retention store (`[planned]`).
[real]      `tinker_delegate.retention_policy` gives each room a fail-closed
            data-retention policy (`immediate` / `time_boxed` /
            `post_settlement_archive`). `evaluate_retention(policy, settled_at, now)`
            returns a bounded `RetentionDecision` — destroy now, retain sealed
            until a deadline, or keep an encrypted archive — with fail-closed
            defaults (zero window, missing archive key, or unknown mode all
            resolve to destroy). It decides *when* to destroy; `destruction_record`
            proves it *happened*. Bounded output; the policy hash records only that
            an archive key is configured, never the ref
            (`tests/test_retention_policy.py`, 9). Wired into
            `ControlPlane.on_deal_resolved` (its `retention_action` is recorded on
            the bounded resolution event).
[real]      `tinker_delegate.sealed_retention.SealedRetentionStore` honors a
            retain/archive decision: it encrypts each artifact under a
            per-corpus/per-deal key derived by HKDF-SHA256 from the TEE root key
            (HKDF info = domain prefix + length-prefixed `(corpus_ref, deal_id)`)
            — a key hierarchy (root -> per-corpus -> per-deal), not one static
            key, so a ciphertext cannot decrypt under another room or deal; the
            control plane passes `ctx.seller` as the corpus. Fields are
            length-prefixed rather than `":"`-joined so a ref containing the
            separator cannot collide two distinct pairs onto one key (a self-review
            fix). AES-256-GCM with per-deal AAD, held as ciphertext, and
            `sweep(now)` destroys entries whose window expired. `ControlPlane`
            (optional `retention_store`) seals-on-retain (zeroing the plaintext,
            event `artifact_sealed_retained=true`) and `sweep_retention(now)`
            destroys expired sealed artifacts, emitting attested destruction records
            (`retention_swept` event). Bounded (deal refs hashed, ciphertext sizes
            banded; no plaintext or key egress). The store optionally persists its
            entries as an AES-256-GCM-encrypted index under the CVM data volume
            (dstack-derived or `.key`-sidecar key, matching `ApiKeyStore`), so
            retained artifacts survive restart; the persisted file contains no deal
            id or plaintext. `tests/test_sealed_retention.py`. Wired into the
            deployed FastAPI control-plane singleton via `build_retention_store` /
            `build_retention_policy` + `retention_*` settings (opt-in by env; empty
            `retention_store_path` = always-destroy default). The singleton runs an
            on-boot `sweep_retention()` (destroys anything expired while the service
            was down) and exposes operator-authed `POST /retention/sweep` for
            on-demand sweeps, returning bounded destruction records. Now
            retain/archive is real, persisted, deployable, and swept — not just
            destroy.
[real]      `tinker_delegate.source_controller` is the bounded custody-audit
            artifact for TEE-held source accounts (email/Tinker/Stripe/data). A
            `SourceGrant` records controller/approver/scope/expiry/revocation +
            audit hash; `SourceControllerRegistry.authorize` answers fail-closed
            (unknown source, non-active grant, or out-of-scope request all deny).
            Enforces non-self-approval (`approved_by != controller_ref`) and scope
            containment. Source/controller/approver refs are hashed, never echoed
            (`tests/test_source_controller.py`, 12). Wired into the control plane:
            `ControlPlane` (optional `source_registry`) calls `_authorize_source_use`
            in `on_deal_funded` before creating the Tinker session, so the TEE-held
            source account is used only while a valid, non-self-approved grant for
            the scope is active — expired/revoked/out-of-scope raises
            `SourceAccessDenied` and no session is created (fail closed; default
            no-registry preserves prior behavior). Grants are provisioned from a
            JSON file (`source_grants_path`, validated at load so a self-approving
            file is rejected) via `build_source_registry`, and operator-authed
            `GET /source/grants` returns the bounded (hashed-ref) manifest.
[real]      Encrypted artifact upload uses the attestation-exposed TEE public
            key, artifact-specific HKDF context, and deal/hash-bound AES-GCM
            associated data; plaintext artifact upload is disabled by default.
[real]      Artifact upload AES keys are derived with per-deal/per-artifact
            HKDF info, so ciphertexts cannot decrypt under another deal ID or
            artifact hash even with the same TEE public key.
[real]      Attestation report data binds operation context plus the TEE
            encryption public key so verifiers can detect key substitution.
[real]      `/attestation` accepts an explicit bounded context query
            (`ingress`, `artifact`, or `billing`) and rejects unsupported
            contexts. Encrypted artifact and billing clients request their
            context before encrypting payloads.
[real]      Client-side artifact uploader fetches
            `/attestation?context=artifact` and refuses to encrypt or upload
            unless mode, quote presence, compose hash, app ID, public-key shape,
            and report data match policy.
[real]      Client-side encrypted billing uploader fetches context-bound
            billing attestation, refuses local/non-matching evidence unless
            explicitly allowed, encrypts card JSON to `/billing/card/encrypted`,
            wipes its plaintext buffer, and posts only ciphertext.
[real]      `add-card-encrypted-prompt` supports approved operator validation
            attempts without putting card fields in command-line arguments. It
            prompts interactively, requires deployed compose/app/OS-image
            attestation expectations unless explicitly run in local-development
            mode, zeros the in-memory card dictionary after upload, and emits
            only bounded response/receipt JSON.
[real]      Standalone `verify-attestation` CLI live-fetches
            `/attestation?context=...` and checks the public evidence envelope:
            mode, quote presence, compose hash, app ID, OS image hash,
            report-data key binding, exposed quote-report-data equality when
            present, and client fetch freshness.
[real]      Standalone `verify-compose-hash` CLI renders a registry-image
            Docker Compose file with explicit env, rejects local `build:`
            services and mutable tag-only images, emits the digest-pinned image
            manifest, and computes the Phala Cloud-style compose hash over the
            rendered app-compose object. It also has a Phala raw-compose mode
            for deployed CVMs where the local image-policy hash is separate
            from Phala's attested full app-compose hash, because Phala includes
            allowed encrypted env names and platform metadata in the live hash.
            The Phala Playwright sidecar image is pinned by amd64 digest in
            `docker-compose.all.phala.yaml`.
[real]      Current Phala deploy-critical image references are literal
            digest-pinned `image:` entries in `docker-compose.all.phala.yaml`,
            not encrypted-env substitutions. The current deployment also binds
            `ORACLE_AUTO_GENESIS=false`, `TINKER_BOOTSTRAP_SIGNUP=false`,
            `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`, and
            `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=false`, and
            `ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT=false` directly in
            that compose file. This avoids treating encrypted env values as
            quote-bound trust roots; a 2026-07-08 intermediate redeploy showed
            changing only image env values did not by itself change the live
            attested compose hash.
[real]      `scripts/redeploy-phala-cvm.mjs` now defaults to a least-privilege
            runtime-env policy for existing CVM updates. `compose-refs` selects
            only encrypted env keys referenced by the compose source plus any
            operator-approved explicit keys; the legacy broad `.env` behavior
            requires `--runtime-env-policy all`. CLI output is bounded to
            policy, selected-key count, and a SHA-256 of the key set unless
            `--print-runtime-env-keys` is explicitly requested. The current
            normal Phala profile was redeployed with this policy and reports
            `allowed_env_count=7` instead of the earlier broad 90-key surface.
[real]      `.github/workflows/build-tee-images.yml` builds the deploy-critical
            `tee-email-oracle`, `tinker-delegate`, and custom `neko-chrome`
            browser images on GitHub-hosted runners for `linux/amd64`, pushes
            SHA-tagged images to GHCR, asks BuildKit to attach SBOM/provenance
            attestations, generates an SPDX SBOM with Syft, and emits
            GitHub-native signed provenance and SBOM attestations bound to the
            pushed image digest. The delegate/oracle Dockerfiles pin the
            Python runtime image and `uv` helper image by versioned digest; the
            custom Neko browser Dockerfile pins the upstream Neko base by
            linux/amd64 manifest digest.
[real]      `scripts/verify-ghcr-image-attestation.sh` is the pre-Phala image
            gate: it accepts only digest-pinned GHCR image references and uses
            `gh attestation verify` against OCI-attached attestations to enforce
            this repository, `.github/workflows/build-tee-images.yml`, the
            expected source commit, GitHub-hosted runner provenance, SLSA
            provenance predicate, and SPDX SBOM predicate before a digest is
            allowed into the Phala compose file.
[real]      Standalone `verify-cvm-attestation` CLI and
            `scripts/verify-cvm-attestation.sh` render the Phala compose file,
            enforce required digest-pinned image references or sha256 image
            digests, fetch `/attestation?context=...`, and accept only a live
            attestation whose compose hash, app ID, OS image hash, report-data
            key binding, public key, and client freshness match policy. The
            emitted bundle is bounded public evidence and labels Intel TDX
            quote internals as not yet cryptographically parsed.
[real]      Standalone `verify-deployment-bundle` CLI combines the deploy-time
            and runtime gates in one public certificate: it verifies
            GitHub-signed SLSA provenance and SPDX SBOM attestations for each
            digest-pinned GHCR oracle/delegate image, requires those exact image
            refs inside the rendered Phala compose, optionally requires sidecar
            image digests, then verifies the live CVM app/compose/OS-image
            attestation envelope. The bundle records `raw_secret_egress=false`
            and does not include raw quotes, app-compose bodies, secrets, OTPs,
            card material, artifacts, or API keys.
[partial]   Current Phala deployment runs the combined oracle/delegate/browser stack in
            CVM `670b3b21-4338-4d4e-ae72-7c8922579f59` / `cvm_1w85mGjo`
            with app ID `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`,
            digest-pinned GHCR images verified by GitHub attestations,
            delegate `/health` returning `ok`, and live delegate
            deployment-bundle verification passing against local raw compose
            image-policy hash
            `a0045b4a0995f858dde0d473a16b997459a6bd009f78c55b0d5ee471ba58f81f`,
            rendered compose SHA-256
            `e8938c5c3896376df2219ddcee78dd26c82963c6fc57ab98431ce6b39122302f`,
            and live Phala attested compose hash
            `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`.
            The current oracle image is
            `tee-email-oracle@sha256:f5c346912f3391e699252dba47c673902d06ffe528a8bab9732a76d551ec42ab`,
            the current delegate image is
            `tinker-delegate@sha256:f9eb714c5630549441636b8a5525b20c9518e863940a3b8e072dff5a5dcab37d`,
            and the current browser image is
            `neko-chrome@sha256:525e43d585828d1d9aa1bceaf7c8cfffc2eec47abf67e0b10550bf05338c4a07`,
            all built from source commit
            `6ff5531aabb952b3266210afa6c0b6bfb8860103`. Tinker bootstrap,
            selector-probe, browser-readiness, and plaintext card submission
            are disabled in the current funding-validation profile; add-balance
            and reauth are enabled only behind runtime bearer auth for capped
            operator validation.
[partial]   2026-07-09 debug exception: the current main CVM was temporarily
            redeployed with public logs, public sysinfo, dev OS, and SSH key
            injection to diagnose a deployed Python-service gateway timeout.
            This is not production posture and must be reverted before claiming
            a locked-down deployment. The debug redeploy reports live compose
            hash
            `a479a1ca1595e7b717e8c8e28ea60dfcef5430bb7792800180453a6b3790aa89`.
            Container logs show the delegate returning internal `/health` and
            `/attestation?context=billing` `200 OK` responses, while local
            clients still receive zero bytes from the public Phala gateway for
            delegate/oracle ports. Neko and Chrome/CDP public ports respond, so
            the active blocker is the Phala gateway/Python service delivery path
            plus oracle IMAP TLS EOFs, not a broadened trust claim.
[real]      Source now prevents slow synchronous readiness checks from blocking
            the delegate API event loop. `/health`, `/attestation`,
            `/billing/funding-policy`, `/billing/funding-preflight`, and
            `/billing/funding-receipts` are synchronous FastAPI handlers, so
            blocking key-store, oracle-health, local attestation, and preflight
            work is dispatched to FastAPI's worker threadpool instead of
            monopolizing Uvicorn's event loop. A regression test starts the
            real ASGI server, makes oracle health sleep, and proves billing
            attestation still returns promptly.
[real]      Source/tests now make oracle `/health` a non-mutating readiness
            view. It reports cached mailbox connection state and credential
            hashes only; it no longer calls IMAP reconnect logic from a Docker
            or delegate health probe. `/pin` remains the operation that touches
            IMAP, fails closed with a bounded `503 IMAP unavailable` response,
            and updates cached connection state. This prevents healthcheck
            reconnect storms. Source/tests also defer IMAP connection during
            FastAPI startup so a flaky mailbox provider cannot prevent
            `/health` or `/attestation` from serving. The startup-deferred
            oracle image is GitHub-built, pinned, and redeployed in the
            funding-validation Phala compose. Live health now serves in
            degraded mode without IMAP connection, while `/pin` remains the
            fail-closed path that must prove mailbox access before OTP use.
[real]      Main-CVM mailbox genesis has been Phala-proven without enabling
            Tinker bootstrap or billing. A one-shot
            `docker-compose.mailbox-genesis.phala.yaml` deployment reached
            `oracle_ready=true`, `imap_connected=true`, `oracle_email=""`, and
            a non-empty `oracle_email_hash`; unauthenticated `/email` returned
            401. The CVM was then redeployed back to the normal compose with
            `ORACLE_AUTO_GENESIS=false`, and the sealed mailbox remained ready.
[real]      `docker-compose.tinker-bootstrap.phala.yaml` is the explicit
            one-shot profile for deployed Tinker bootstrap attempts. It reuses
            the main `delegate-data` volume, keeps `ORACLE_AUTO_GENESIS=false`,
            keeps credential provisioning and add-balance disabled, enables
            only `TINKER_BOOTSTRAP_SIGNUP=true`, uses fail-open bounded
            evidence mode so selector/posture failures can be inspected through
            `/health` runtime state, and now drives the headed Neko Chrome CDP
            endpoint instead of the headless Playwright sidecar. The Tinker
            bootstrap and selector-diagnostics Phala composes now use the
            GitHub-attested custom `neko-chrome` digest and the baked Nginx CDP
            proxy on port `9222`; they no longer rewrite Chrome/CDP with an
            inline Python TCP proxy at container startup. A Phala bootstrap run
            with the custom browser image succeeded: `/health` reported
            `bootstrap_success=true`, `api_key_configured=true`, and a bounded
            `api_key_captured_and_stored` attempt record with
            `raw_secret_egress=false`.
[real]      Earlier Phala-proven Tinker bootstrap attempts remain useful
            history because they isolated the failure to the old deployed
            browser transport. The first, using the headless Playwright sidecar,
            reached the Tinker auth surface with
            `bootstrap_error_kind=auth_access_blocked`. Later headed-Neko runs
            preserved bounded failure records without exposing raw mailbox,
            OTP, page text, cookies, URLs, or API keys. The custom
            `neko-chrome` run fixed the deployed `Page.enable` timeout and
            sealed the API key in the delegate data volume. Stealth/evasion
            remains out of scope; the accepted browser route is bounded TEE
            custody for this project's own account.
[partial]   Production OS posture is not solved. The main CVM still reports
            `dstack-dev-0.5.9` / `is_dev=true`; earlier attempts to update the
            existing CVM to `dstack-0.5.10*` with `--no-dev-os` failed in the
            Phala CLI/API with a required `correlationId` validation error, and
            a later successful compose/image update with `--no-dev-os` still
            left the live CVM reporting the dev OS.
[real]      The email-oracle source now tracks cock.li's current registration
            form contract: `password_confinm` is filled as the real password
            confirmation field, `password_confirm` is treated as a honeypot and
            left empty, and `csrf_valid` mirrors `csrf` on HTTP submissions.
[real]      A temporary Phala auto-genesis debug CVM using a GitHub-attested
            image from that form-contract fix reached IMAP verification and
            loaded sealed oracle credentials. The temporary public-log/dev-OS
            CVM was deleted after bounded evidence collection.
[real]      Public successful-genesis surfaces are now bounded in source and
            Phala-proven for the standalone oracle-genesis debug compose:
            `/health` and `/attestation` expose `oracle_email=""`, readiness,
            and `oracle_email_hash`; raw address retrieval is isolated to
            runtime-authenticated `/email`, which returned 401 without a bearer
            token in the fresh Phala proof. The temporary public-log/SSH/dev-OS
            debug CVM was deleted after evidence collection.
[partial]   Oracle credential-ingress attestation is live for
            `context=oracle-credentials`, but credential provisioning is
            disabled by default and no real mailbox credentials have been
            sealed into the running CVM.
            The current source commit, image digests, endpoints, and bounded
            quote-envelope fields are recorded in `deployments/base-sepolia.json`.
[real]      In dstack mode `/attestation` includes public dstack evidence fields
            when available: event log, VM config, instance/device IDs,
            aggregated measurement, OS image hash, compose hash, and TCB info.
[real]      Encrypted FastAPI artifact ingress and control-plane evaluation
            dispatch have regression tests that fail on Python file open/write
            calls while raw artifact buffers are in scope.
[real]      A local synthetic room regression now covers the complete
            source-modeled diligence-room path: encrypted artifact upload,
            funded deal cap/reserve, fake Tinker training/checkpoint/sample via
            `IsolatedTinkerSession`, bounded result packet, resolution cleanup,
            artifact zeroing, and no raw artifact/sample/run/checkpoint/API-key
            egress.
[real]      IsolatedTinkerSession has mocked-SDK tests for explicit one training
            run per deal enforcement, TTL clamping on every checkpoint save
            path including save-and-sample, path-checked sampling, state
            checkpoints not being sampleable, cleanup deletion, retry-backed
            cleanup attestations, and metering.
[real]      Upstream Tinker run metadata is now bounded. The isolated session
            still forwards public `deal_id` for orphan cleanup, but arbitrary
            evaluator-supplied `user_metadata` no longer flows to Tinker raw:
            only a small safe-label allowlist can pass, the original metadata
            is represented by a hash/drop count, and oversized or non-JSON
            shapes fail closed.
[real]      Deal resolution stores a bounded cleanup attestation with counts,
            success flag, attempts, error type, and checkpoint-ID hash; raw
            checkpoint IDs are not included in the public record.
[real]      First-party SFT evaluator no longer reaches the raw Tinker
            ServiceClient. It uses wrapper methods only, including a scoped
            base-model sampler for tuned-vs-base comparison, and tests reject
            raw ServiceClient/REST/list/download/publish API usage in evaluator
            source.
[real]      Real Tinker SDK smoke-test harness exists but is disabled by
            default. It requires `TINKER_RUN_REAL_SDK_TESTS=1`,
            `TINKER_API_KEY`, and `TINKER_REAL_SDK_MAX_USD <= 0.50` before it
            will create a tiny training run, save a TTL checkpoint, sample, and
            cleanup.
[real]      A production-shaped bounded SDK smoke surface now exists in source.
            `tinker_delegate.tinker_smoke.run_tinker_sdk_smoke()` uses the
            sealed API-key resolver, checks `TinkerAccountEncumbrance` with
            `SPEND_TINKER_COMPUTE`, enforces a hard `$0.50` smoke cap, runs the
            same tiny train/checkpoint/sample/cleanup pattern through
            `IsolatedTinkerSession`, and returns only bounded hashes, cost
            bands, policy state, sample-observed boolean, and cleanup counts.
            It never returns the API key, raw run ID, raw checkpoint path,
            sample text, checkpoint IDs, or raw model output. The first
            authenticated SDK calls (ServiceClient connect + create_training) are
            wall-clock capped (`smoke_connect_timeout`, default 45s) on a daemon
            thread, so a blocked/unactivated Tinker account fails fast with a
            bounded `sdk_error.bucket=transient_timeout` verdict
            (`operator_action=retry_or_check_tinker_account_activation`) instead of
            hanging on SDK retries; the abandoned thread never blocks process exit.
            The current authoritative blocker to a live end-to-end run is external:
            the Tinker account returns a 402 billing/activation block that credit
            did not clear — see STATUS.md.
[real]      `tinker-smoke` CLI can run the smoke in-process inside the
            CVM/container or call a deployed delegate via `--api-url`. The
            FastAPI `POST /tinker/smoke` endpoint is disabled by default,
            requires runtime bearer auth when enabled, and is intended only for
            explicit funded validation. The temporary
            `docker-compose.tinker-funding-validation.phala.yaml` profile
            enables it with a `$0.05` default cap for the next deployed smoke
            proof; production profiles must leave it disabled unless a governed
            compute-spend route is approved.
[real]      Smoke failure receipts now include bounded SDK diagnostics: an
            allowlisted `sdk_error.bucket`, redacted normalized
            `sdk_error.message_hash`, coarse message-length band, and bounded
            `sdk_diagnostics` for request shape plus capability probing, enum
            `sdk_error.failure_site`, enum `sdk_error.operator_action`, and
            optional `TINKER_PROJECT_ID` configured/hash evidence without
            returning the raw project id. Receipts also carry an enum
            `sdk_error.provider_error_category`
            (invalid/inactive API key, invalid-or-inaccessible project,
            account entitlement, funding/quota, unsupported SDK version,
            endpoint mismatch, or unclassified) plus exact `http_status`;
            the category is classified internally from short allowlisted
            scalar provider-body fields that are never included in the
            receipt, and `service_client_create` failures map each category
            to a concrete `operator_action`.
            Unknown `POST /tinker/smoke` payload fields are rejected so callers
            cannot accidentally send `base_model`/`model_name` and silently use
            defaults. Tests prove API-key-shaped, email-shaped, card-shaped,
            request-ID-shaped, raw provider-message text, raw project ids, and
            raw supported-model lists are not returned.
[real]      The `tinker-delegate` Dockerfile copies `uv.lock` and installs with
            `uv sync --frozen --no-dev --extra agent`, so the packaged delegate
            image includes the optional Tinker SDK. A local build/run of
            `dnai-tinker-delegate-agent-extra:local` returned
            `/health.agent_stack_available=true`.
[real]      `scripts/verify-agent-image.sh` rebuilds the delegate image and
            verifies `import tinker` plus the `agent_stack_available` probe
            inside the image, emitting bounded JSON only.
[partial]   Deployed Phala/CVM browser posture has not been revalidated with
            selector-map capture evidence from the running headed browser path.
[real]      One-off operator-validation funding is live: card data can be
            encrypted to the TEE, bounded attempt receipts are
            returned/persisted, the deployed encumbrance policy approved the
            current compose hash for `$10`, and a bounded balance read reports
            `$10.00`. Payment-method token/reference capture is still missing,
            and production or repeated card funding still needs legal/compliance
            approval plus hardened CVM posture.
[partial]   The smoke-capable source has been built into a GitHub-attested
            delegate image, pinned in the Phala funding-validation compose,
            redeployed, and approved on-chain for `SPEND_TINKER_COMPUTE` under
            compose hash
            `c6b446fe9b7ff656c6db799a7461a2a6dba045ae24de16d365c80a6cb83863da`.
            Deployed real Tinker execution is still not proven because the live
            smoke fails closed with `BadRequestError` at `api_key_loaded` before
            training creation. The current receipt classifies this as
            `invalid_request` / `4xx` from Tinker SDK `0.15.0`; official-model
            retries at Qwen/rank-16 and Qwen/rank-32 failed with the same
            bounded hash. No deployed run ID, checkpoint, sample, cleanup proof,
            or spend proof exists yet.
[partial]   The project-aware smoke diagnostics image is now live and
            policy-approved, but real Tinker training is still unproven. GitHub
            Actions run
            `29020924145` built source
            `6f5d557d1dab6641590c12ad96eecad74a101638` into
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:d7872a09b7fe28e25a53dafa721a355cb0677d42e2939f4babbbff7e167f306d`;
            local `verify-ghcr-image-attestation` verifies SLSA provenance and
            SPDX SBOM predicates for that digest. The local image-policy compose
            hash is
            `d0aea171db3483ae1dae4ff73294548ca5906481166893114ce048688bf2f3f9`;
            Phala now reports live app-compose hash
            `314cd60b093194dcac0480f3586c8979a9734a56c7a521cd8ef043dee9417816`.
            `verify-cvm-attestation` passed against that live hash, app ID, OS
            image hash, and all three digest-pinned images, and
            `TinkerAccountEncumbrance` approved the new compose hash in tx
            `0x17c7064496711ae93c39f0489667fe7555d6455f18f01eae174c1aa5a92fa3f6`.
            The new bounded live smoke receipt still fails before training
            creation at `sdk_error.failure_site=service_client_create` with
            `sdk_error.operator_action=check_sdk_client_configuration` and
            `project.configured=false`.
[real]      Source now exposes Tinker SDK client configuration as a bounded
            diagnostic surface. Smoke receipts include `client_config` booleans
            for API-key/project/base-url argument shape plus only a base-url
            host family and hash. Constructor failures still report whether
            `TINKER_PROJECT_ID` was configured, without returning the raw project
            id or endpoint. The same `TINKER_PROJECT_ID` / `TINKER_BASE_URL`
            settings are wired into `ControlPlane` so future evaluator sessions
            use the same client configuration as smoke validation.
[real]      `tinker_delegate.tinker_client_config_store` provides encrypted
            local/dstack-backed custody for Tinker SDK project/client settings.
            `GET/PUT /tinker/proxy/client-config` require runtime bearer auth;
            `tinker-client-config --install` reads project/base-url values from
            environment variables rather than CLI arguments and can install them
            into a deployed delegate. Bounded receipts/status expose only
            project hash, base-url hash, host-family classification, encrypted
            store state, and `raw_secret_egress=false`. Proxy status,
            `run_tinker_sdk_smoke()`, and lazy `ControlPlane` construction
            resolve project/base-url from this sealed store when direct env
            settings are absent. This is source-real and locally tested; live
            Phala provisioning and successful real Tinker training creation are
            still partial.
[real]      `tinker-smoke-command-plan` provides a bounded operator control
            surface for the next live retry. It reads the deployment manifest,
            treats `TINKER_PROJECT_ID` as optional SDK metadata (a
            `tinker_project_id_not_configured_optional` warning, never a
            readiness blocker), and gates readiness on the currently attested
            compose hash being approved on-chain: when manifest
            compose-approval evidence shows the live compose is unapproved,
            `ready=false` with reason `current_compose_not_approved` and
            `next_action=approve_current_compose`, and the
            `approveComposeHash(bytes32)`, spend-preflight, and smoke templates
            are bound to the current attested compose hash rather than a
            new-compose placeholder. When the operator has `TINKER_PROJECT_ID`
            locally but live evidence shows it unsealed,
            `next_action=seal_client_config` via
            `client_config_install_argv` / `client_config_install_shell`. The
            plan prefers the latest live client-config install/runtime-env
            evidence over stale smoke-receipt evidence, still emits redeploy,
            attestation, compose-approval, spend-preflight, and smoke command
            templates for cases where a new CVM compose is intentionally
            selected, and never includes raw project IDs, bearer tokens, API
            keys, RPC URLs, run IDs, checkpoint paths, or samples.
[partial]   A follow-up GitHub Actions build for commit
            `3bb9ff4b986e95debbe0d13f9a02edb9c0d03f80` completed on run
            `29058135707` and produced digest-pinned funding-validation images:
            `tinker-delegate@sha256:a76c2efb9274d2669b98836fdc30450d79a1c96702150079e1ba13bf2d9b8ac6`,
            `tee-email-oracle@sha256:e663c88eb87e880abbc012befe1948a4a45007ea267ae85ab79a953936de9e99`,
            and
            `neko-chrome@sha256:4b36022cc2d0c50a0080c9f460a7252659a9a201ee2b43d8dfcffd033685a88a`.
            Local `verify-ghcr-image-attestation` checks passed for SLSA
            provenance and SPDX SBOM predicates on all three images. The local
            funding-validation Phala compose is pinned to those images and
            hashes to raw compose candidate
            `5d469e071e416305b032172683616d72efb12e99ca9b3ee5200cfd60d532f07a`
            with rendered compose SHA-256
            `62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`.
            This is source/local evidence only until redeployed, attested by
            Phala, and approved on-chain for the resulting live compose hash.
[partial]   The client-configuration diagnostic source follow-up changes the
            local funding-validation compose to allow `TINKER_BASE_URL` through
            encrypted Phala env selection. GitHub Actions run `29023713771`
            built source `76609fbe6617a8c7162c4dbfbbbc060e9b01322e` into
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:83e58d165cc30374feb70f475dc6bf30da07d63895f6d871feb4f7828926758b`;
            local `verify-ghcr-image-attestation` verifies provenance and SPDX
            SBOM attestations for that digest. The image is now deployed to the
            operator-validation CVM at live app-compose hash
            `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180`.
            `verify-cvm-attestation` passes against raw compose hash
            `60046a718ba13c71f015a8633b4a9ee6892661762414e9e61636a897327a2d82`,
            the live app-compose hash, app ID, OS image hash, and all digest
            pinned images. `TinkerAccountEncumbrance` approved the live
            app-compose in tx
            `0xc597c8e2bbfcc58255c6d407ce615ec4befd992b4e4ef2c34854b99a4d4c52b2`
            at block `43919367`.
            The live smoke receipt still fails before training creation, but it
            now confirms bounded client configuration:
            `api_key_argument=provided`, `project_id_argument=omitted`, and
            `base_url_argument=sdk_default`. The missing `TINKER_PROJECT_ID` or
            equivalent Tinker service/client entitlement remains the blocker.
[partial]   Cleanup attestations are generated by the new bounded smoke path,
            but deployed Tinker deletion and TTL-expiry behavior still need
            real SDK/CVM evidence.
[real]      Source-modeled third-party evaluator code can now run behind a
            process/capability boundary. `SandboxedEvaluatorRunner` starts a
            restricted subprocess with bounded context only; the child emits an
            allowlisted capability plan, and the parent executes that plan
            through `IsolatedTinkerSession`. Tests prove the child does not
            receive the raw session, raw service client, artifact bytes,
            checkpoint paths, run IDs, sample text, or upstream API key in
            public output.
[real]      The evaluator child now also runs under POSIX resource limits
            (defense-in-depth behind the restricted-builtins namespace), applied
            via a `preexec_fn`: `RLIMIT_CPU` (kills a CPU-spinning breakout),
            `RLIMIT_FSIZE=0` (no-filesystem-write policy — stdout is a pipe so
            the bounded result still returns), `RLIMIT_NOFILE` (caps
            file/network descriptors), `RLIMIT_CORE=0` (no memory-spilling core
            dump), and an opt-in `RLIMIT_AS` (off by default; a low cap breaks
            CPython startup, so real memory bounding stays a cgroup concern).
            Limits are best-effort and never raise an existing hard cap. Tests
            prove they take effect in a real child on this host
            (`tests/test_evaluator_sandbox.py`).
[partial]   This evaluator sandbox is still not the full hostile-code production
            boundary. Deployed CVM/container isolation, real Tinker datum
            adapters, a hard no-network policy (netns/seccomp), resource cgroups,
            and audited egress remain required (blocked on a deployed CVM) before
            accepting arbitrary third-party evaluator code; the process-level
            rlimit/no-fs-write layer above is the portion doable without
            deployment.
[partial]   Artifact upload still needs full cryptographic Intel TDX quote
            parsing/freshness validation, downstream evaluator/Tinker/browser
            no-disk audit, and evaluator-side raw-byte lifetime audit. (The
            sealed-retention key hierarchy is now `[real]` — HKDF per-corpus/
            per-deal keys, above.)
[real]      The source-modeled synthetic room is now wired through real local
            escrow settlement. `prove-local-synthetic-room-anvil.py` starts
            ephemeral Anvil, deploys `DiligenceRoom`, creates/funds a deal,
            uploads an encrypted synthetic artifact to the FastAPI ingress,
            evaluates with the fake Tinker backend, authorizes the bounded
            result through `authorize-result`, submits from the dstack simulator
            signer, accepts the deal, reads `EvaluationSubmitted` and
            `DealAccepted`, reports pull-payment bands, and resolves cleanup.
            It keeps the raw artifact, fake API key/project id, run ID,
            checkpoint paths, and sample text out of public output. This is a
            local modeled proof only; deployed CVM execution and real Tinker SDK
            training remain separate blockers.
[real]      `tinker_delegate.policy_kernel` implements the first deterministic
            ConSECA-style corpus policy gate. `AccessRequest` and `CorpusPolicy`
            are frozen source records; `gate_access_request()` is a pure
            function with no network, browser, email, chain, Tinker, clock,
            random, or mutable-store effects. It enforces allowed/denied
            purposes, allowed pipelines, output schemas, operations, known data
            classes, restricted categories, hold/review categories, ambiguous
            categories, and policy version support. Deny beats allow: the
            denied-purpose check runs before the allow-list, so a purpose listed in
            BOTH (an authoring mistake or adversarial policy) is denied — pinned by
            a conflict-resolution test. Strict dict entrypoints
            fail closed on unknown request/policy fields and malformed payloads.
            Public results expose stable decisions, stage, reason code, route,
            policy/request hashes, category hashes/counts, and
            `raw_secret_egress=false`; raw policy clauses, raw private category
            labels, artifacts, reward values, samples, and credentials are not
            returned. `gate_turn_requests()` is the explicit fan-out adapter
            into `coordination.GateResults`; the coordination reducer remains
            event-driven and does not call gates implicitly.
[real]      `tinker-delegate policy-gate` is an operator-exercisable source
            proof path for this kernel. In single-corpus mode it reads one
            `AccessRequest` JSON and one `CorpusPolicy` JSON and emits a bounded
            gate receipt. In coordination mode it reads a `Turn` JSON plus a
            corpus-ref-to-policy JSON map, validates one request/policy per
            corpus, runs deterministic fan-out, and emits a bounded
            `GateResults` summary. The CLI uses the shared bounded JSON renderer
            and returns decisions, actions, route labels, policy/request hashes,
            category hashes/counts, and `raw_*_egress=false`; it does not expose
            raw policy clauses, raw category labels, private artifacts, or
            secrets. This is still a local/operator proof, not a deployed TEE
            governance endpoint.
[real]      `TinkerAccountEncumbrance` is deployed on Base Sepolia at
            `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`. It enforces approved
            compose hashes, operation caps for add-balance and Tinker-compute
            spend, manager authorization, account commitment, and an emergency
            halt. It is still a development/operator-controlled policy surface,
            not a production governance system.
```

### 3. TTT/RL Bio Validation

The target bio-validation layer is the place where Tinker compute becomes
scientific diligence:

```
private bio artifact or corpus
        |
        v
TTT/RL evaluator inside TEE
        |
        v
bounded proof of utility / safety / validation result
```

The repo currently includes Tinker RL docs, an evaluator shape, and the
`tinker_delegate.private_reward` environment contract. The optimizer-agnostic
RLVR *loop harness* is now implemented (`private_reward_loop.py`), but the real
TTT/RL bio-validation binding — a source-controlled program candidate space and a
Tinker-backed optimizer — is not. The current evaluator code is:

```
stub_evaluate()       deterministic synthetic result for testing
sft_evaluate()        LoRA/SFT-oriented evaluator shape using Tinker SDK
```

The private reward contract is:

```
PrivateRewardEnvironment.problem()          public problem text
PrivateRewardEnvironment.candidate_schema   allowed candidate envelope
PrivateRewardEnvironment.reward()           exact internal reward, TEE-only
PrivateRewardEnvironment.output_reducer()   approved bounded feedback
PrivateRewardEnvironment.query_budget       max queries and reward precision
PrivateRewardEnvironment.optimizer_policy   internal / attested remote / external
PrivateRewardEnvironment.optimizer_view()   public optimizer setup view
PrivateRewardEnvironment.internal_reward_for_optimizer()
                                            exact reward only for trusted optimizers
PrivateRewardEnvironment.finalize()         bounded result and hashes
PrivateRewardEnvironment.attest()           environment/transcript metadata
```

The optimizer-agnostic RLVR loop harness is `[real]` (harness + tests), with the
real computational-bio candidate space and a real Tinker RL/TTT optimizer still
`[planned]` (blocked on the Tinker execution/billing blocker). The loop contract
is:

```
run_private_reward_loop(environment, optimizer, max_rounds, target_band,
                        allow_internal_optimizer, canary_report)
  driver:   proposes candidates from a swappable LoopOptimizer, evaluates each
            through environment.evaluate(), stops at target band / max rounds /
            budget exhaustion / optimizer halt
  canary:   optional fail-closed pre-screen — a canary.CanaryReport (produced by
            screening a FRESH env so it doesn't consume this run's budget); if it
            is present and not clear, the loop refuses to start and returns a
            zero-round CANARY_TRIPPED outcome before spending any budget
  boundary: optimizer sees ONLY environment.optimizer_view() (public) and
            per-round BoundedFeedback (decision + score band + hashes); never
            the exact InternalReward, sealed data, or reward-derived gradients
  guard:    fail-closed refusal when the environment's optimizer_policy would
            expose exact rewards unless the caller opts into an in-boundary
            optimizer (allow_internal_optimizer + INTERNAL_TEE/ATTESTED_REMOTE)
  output:   bounded LoopOutcome — rounds run, best band, band histogram, stop
            reason, transcript hash, env BoundedResult/attestation; no candidate
            payloads or raw values (raw_secret_egress=false)

LoopOptimizer (swappable strategy interface)
  RandomSearchOptimizer   feedback-blind baseline
  HillClimbOptimizer      band-guided greedy local search (single-best RL)
  EvolutionaryOptimizer   (mu+lambda) population search: keeps an elite by band,
                          breeds by mutating a top-half parent, dedups to avoid
                          spending the bounded per-candidate query budget, halts
                          when the reachable space is exhausted
  LLMRepairOptimizer      deterministic revise-on-weak-band (LLM repair loop)
CandidateSource           caller-supplied search space (seeds + mutate); keeps
                          optimizers env-agnostic and the loop replayable
```

The optimizer *method* is swappable behind `LoopOptimizer` while the private
verifier and its leakage bound stay fixed — this is the code-level realization of
the PROJECT.md protected-reward-interface claim. The claim is proven end-to-end
and optimizer-AGNOSTIC: a parametrized test runs all four optimizers through the
same env and asserts each produces a bounded run whose reproducibility
certificate independently verifies and whose certified export leaks no sealed
record (`tests/test_private_reward_loop.py`), so the whole verification chain
holds regardless of which optimizer ran. Wiring a real source-controlled program
candidate space and a Tinker-backed RL/TTT optimizer remains open.

The optimizer-export leakage guard (`optimizer_export_guard.py`) is `[real]`: it
audits any proposed "publish this optimizer export" payload and fails closed on
the realistic reward/data leakage vectors — any `float` (exact rewards and
reward-derived gradients are floats; bounded egress is bands/decisions/hashes/
int-counts), numeric arrays over a small cap (gradient/weight/embedding tensors,
even integer-encoded), a single integer wider than 256 bits (`oversized_int` — a
self-review fix: one unbounded scalar int can carry an entire sealed blob via
`int.from_bytes(...)` without ever tripping the per-array numeric cap, and as a
dict *value* it is invisible to the textual reward scan; every legitimate bounded
integer — counts, bands, unix expiries, nonces, uint256 wei amounts/hashes — fits
in 256 bits), an aggregate integer payload over 512 bytes (`aggregate_int_payload`
— many separately-small int fields summing to a bulk exfiltration; a real
LoopOutcome export is ~23 int-bytes, so 512 leaves >20x headroom while making
KB-MB tensor/dataset exfil via aggregated integers infeasible — bounds, does not
eliminate, the channel), oversized hex/byte blobs, secret-shaped material (shared
`redact_text`), an over-deep structure (`structure_too_deep` — a hostile reducer's
deeply nested payload fails closed cleanly instead of raising RecursionError), and
a truthy `raw_secret_egress` self-declaration. It returns a
bounded `ExportAuditResult` (allowed flag, reason code, offending field *paths* —
never values, deterministic leakage hash); `certify_optimizer_export` raises
`ExportLeakageError` unless safe. A real bounded `LoopOutcome.to_public_dict()`
passes; floats/gradients/blobs/oversized-ints/aggregate-int-payloads are rejected
(`tests/test_optimizer_export_guard.py`, 20). It is now also wired as the mandatory pre-publication gate for the loop's own
run export: `LoopOutcome.certified_public_export()` runs the fail-closed egress gate
over the exact bytes that would leave the boundary (checkpoint / on-chain packet /
cross-boundary handoff) and raises `RewardLeakageError` rather than trusting that
`to_public_dict()` is bounded by construction; the already-governed nested
`result.attestation` subtree is excluded from the structural float-ban exactly as
`finalize()` does. It IS also the mandatory egress gate for the reward channel:
`private_reward.assert_bounded_egress`
runs on every `BoundedFeedback` from `evaluate()` and every `BoundedResult` from
`finalize()`, failing closed (`RewardLeakageError`) on any float / numeric array /
oversized blob or any string field that renders a float or long precise integer —
including a scientific-notation float with a signed exponent (`1e-05`, `2e+16`,
how a tiny/huge reward reprs), a self-review gap closed 2026-07-12 that the
decimal-only pattern had missed; the signed-exponent requirement never matches a
bare `1e5` inside a hex hash, so it adds no false positives (full suite green) —
so a misbehaving `output_reducer` cannot smuggle the exact reward value out via
`public_message`. Both layers now cover dict *keys* as well as values (a self-review fix — an exact
reward hidden as a key like `{"0.9731": "high"}` or a raw float/int key
`{0.9731: ...}` is egressed text too): the textual scan stringifies non-string
keys (JSON serializes them via `str()`), and the structural float/array/blob ban
walks keys as well as values. Both layers are also depth-bounded (64) so a hostile
deeply nested payload fails closed cleanly (`RewardLeakageError`) rather than
raising an uncontrolled `RecursionError` — including a deep subtree hidden under
the structurally-ignored `attestation` key (caught by the textual scan's bound). The `attestation` subtree (public env
config, e.g. holdout split fractions) is excluded from the structural float-ban
only; the textual scan still covers it.

Reproducibility certificates (`reproducibility.py`) are `[real]`: a run binds into
one recomputable, bounded commitment — `run_config_hash` (optimizer, model base,
hyperparameters, seeds, round budget, target band), `data_commitment` (the
environment's public `environment_hash` / holdout split commitment, sealed data
stays sealed), `code_hash`, coarse `model_base`, `result_hash` (loop transcript),
optional `attestation_quote_hash`, and a `certificate_hash` over all of them. It is
hashes/coarse identifiers only, so hyperparameter floats, seeds, sealed data, and
reward values never appear — the certificate passes `assert_bounded_egress`.
`verify_reproducibility_certificate` recomputes the binding to detect tampering;
`certify_loop_run` certifies a loop outcome against its environment
(`tests/test_reproducibility.py`, 8). The binding is proven COMPLETE by a
parametrized test that tampers every one of the seven bound fields (run-config /
data / code / model-base / result / quote / transcript-commitment) and asserts
each is detected — guarding against a future certificate field being added but
forgotten in `_certificate_hash` (which would leave it silently tamperable). This
treats attestation + code + data + config + result as one verification chain. The `bio-assay-qc-reward-demo` operator
CLI now emits a `reproducibility_certificate` alongside its bounded outcome, with
`code_hash` derived by `hash_source_files` (a digest of the actual evaluator module
source bytes — deterministic, changes iff the reward code changes); the
certificate passes the demo's leakage guard and verifies. The certificate now
also binds the run's proof-carrying reward-transcript commitment: `certify_loop_run`
(default `bind_transcript=True`) folds the `RewardTranscript.commitment_hash`
(per-round Merkle root + env chain head) into `certificate_hash`, so a single
verified certificate covers config + data + code + result + quote + the
per-round transcript — one verification chain. `verify_reproducibility_certificate`
recomputes the binding including the transcript field. `run_verification.py`
(`verify_reward_run(packet)`) is the one-call verifier for an emitted run packet:
from the bounded public bytes alone (no sealed data) it re-checks that the
certificate hash recomputes, the transcript commitment hash recomputes, and the
certificate's bound `transcript_commitment_hash` equals the commitment's own hash
— fail-closed to `verified=false` with a reason on any missing/mismatched piece.
It also cross-checks that the (verified, mutually-bound) certificate + commitment
agree with the REST of the packet — the packet's own `final_result` transcript
hash and `attestation` env-hash/chain-head, and the certificate's data/result
hashes — so a valid cert+commitment from one run cannot be re-attached to another
run's body (`packet_inconsistent`). It further recomputes the Merkle root over the
packet's own per-round `feedback` and checks it equals the committed
`transcript_root` (and that `round_count` matches), so tampering or dropping a
round record — with an otherwise-valid commitment — is caught. When the
attestation carries a DP budget, `dp_status` is checked for internal consistency
(`remaining == max - spent`, `exhausted` matches the epsilon ledger), so a
tampered privacy claim is caught. It also enforces an INDEPENDENT leakage bound:
the per-round `feedback` (the sealed-data-derived surface — bands/decisions/
candidate hashes) is run through `assert_bounded_egress`, so a packet that smuggles
an exact reward value (float), a gradient (numeric array), or a sealed blob into a
round record is rejected `packet_leaks` even if every hash still binds — "verified"
therefore means both cryptographically consistent AND leakage-safe. It also checks
a MECHANISM-AUDIT dimension (`mechanism_accounting_consistent`): the published
holdout and Ladder manifests must respect the caps in their *own declared policy*
— enforced `reward_query_count ≤ max_reward_queries`, per-candidate probes ≤ the
declared per-candidate cap, `final_validation_count ≤ max_final_validations` (and a
completed final validation must have closed reward queries and met the declared
minimum-unique-candidate gate), and for a Ladder gate the genuine
`improvement_count ≤ max_improvement_steps` (the core `≤ D` guarantee), the
leaderboard index within the grid, and submissions ≤ any declared cap (paired-t:
numerator ≤ denominator, improvements ≤ submissions). A boundary (or tampered
packet) that ran *more than its stated policy allows* is rejected
`mechanism_accounting_violation` — the "declared params match what the boundary
enforced" check a third party needs, which the hash/egress checks do not see. It
is lenient on absent fields (that dimension is simply not checkable) and fails
closed on a present-but-exceeded cap or unparseable count; manifests are read from
`final_result.attestation` (and the top-level `attestation` if present). Public env
config that legitimately carries floats (holdout split fractions, DP epsilon/delta
budget) lives under `attestation`/`optimizer_view` and is not part of the leakage
check.
(`tests/test_run_verification.py`, 26 — against a real demo packet plus tampered /
broken-binding / spliced-body / tampered-feedback / dropped-feedback /
tampered-dp-status / smuggled-float-feedback / smuggled-gradient-feedback variants,
and mechanism-accounting-violation variants (reward-query / final-validation /
not-closed / unparseable, plus direct fixed-η and paired-t Ladder cap checks)). Surfaced as the `verify-reward-run --packet <json>`
operator CLI, which emits the bounded verdict and exits non-zero on failure
(`tests/test_verify_reward_run_cli.py`, 2), and as the auth-gated
`POST /verify/reward-run` operator API endpoint (posts a run packet, returns the
bounded verdict; `tests/test_api_verify_reward_run.py`, 4).

`verify_reward_code_binding(packet, source_targets)` is the complementary
third-party check (point (1) of the mechanism audit — "audit the mechanism, not
the data"): a buyer/sponsor who has independently read the open reward-environment
source recomputes `hash_source_files(...)` over the modules/paths they read and
confirms it equals the packet's certificate `code_hash`, binding *that exact code*
to the attested run. It is a SEPARATE call from `verify_reward_run` because it
takes an external input (the source the reader holds) the packet does not carry;
both operands are SHA-256 digests so the verdict is bounded, and it fails closed on
a missing attested hash (`missing_code_hash`), unreadable source
(`code_source_unreadable`), or mismatch (`code_hash_mismatch`). The demos build
`code_hash` from real source bytes (`hash_source_files(<env module>)`), so a reader
with the env module verifies `code_binding_verified` (`tests/test_run_verification.py`
RewardCodeBindingTest, 5).

`verify_reward_dataset_binding(packet, manifest, *, expected_signer=None)` is point
(2) — binding a run to the sealed dataset it committed to. A sealed run records its
dataset commitment as `sealed_dataset_provenance.manifest_hash`; a third party who
holds the published manifest confirms (a) the manifest's own integrity + owner/
notary signature (`verify_manifest`, requiring `expected_signer` when given), (b)
`manifest_hash(manifest)` equals the run's committed hash, and (c) the run's
declared `dataset_id`/`publish_ciphertext_sha256` match the manifest, so a valid
manifest for a *different* dataset cannot be swapped in. Fails closed on
`missing_dataset_commitment` / `dataset_manifest_invalid` /
`dataset_commitment_mismatch` / `dataset_provenance_mismatch`; verdict is bounded
(hashes + booleans). The `denoising_sealed_dataset` demo now stamps the
`manifest_hash` commitment into its provenance (`tests/test_reward_dataset_binding.py`,
8).

[real]      Neutral sealing-witness M-of-N quorum (`sealed_dataset.add_witness_signature`
            / `verify_witness_quorum`). For adversarial buyer/seller pairs, mutually
            trusted notaries each co-sign the canonical `manifest_hash` (excluded
            from the hash, so every witness signs the same fixed commitment and
            signing never mutates it); `verify_witness_quorum` counts DISTINCT
            authorized signers whose signature recovers over that hash, failing
            closed on an unknown address, a duplicate signer, a wrong-hash
            signature, or a tampered manifest. This closes the "seller crafts data
            to favor one bidder" collusion path: neither side can later dispute
            what entered the boundary. Witnesses never see plaintext (the manifest
            is bounded); receipts carry witness *hashes* only, never raw addresses.
            `verify_reward_dataset_binding(..., witness_quorum={"authorized_witnesses":
            [...], "threshold": M})` enforces the quorum as part of the dataset
            binding (`dataset_witness_quorum_unmet` when unmet)
            (`tests/test_witness_quorum.py`, 11). Threaded through the
            `verify_reward_mechanism` aggregate + CLI (`--witness`/`--witness-threshold`)
            + endpoint (`witness_quorum`). A notary co-signs operationally via the
            `witness-sign-dataset-manifest --manifest --out` CLI (witness key from
            env, never on the command line; receipt hides the key)
            (`tests/test_dataset_provenance_cli.py`).
[real]      Seal-time attested provenance (`sealed_dataset.build_provenance` /
            `verify_dataset_provenance`). A bounded provenance block (source
            pipeline, upstream id, license, distribution claim, and `benchmark_ref`
            vs. a named public benchmark) is committed *into* the manifest before
            it is hashed, so it is covered by `manifest_hash` and any owner/witness
            signature binds the claim to this exact dataset — the claim cannot be
            asserted favorably after the fact. `verify_dataset_provenance` requires
            a complete provenance block AND a valid signature over the canonical
            hash (unsigned provenance is `provenance_not_signed`), and optionally
            that `benchmark_ref` equals an `expected_benchmark`; tampering the claim
            after signing breaks the signature (`owner_signature_hash_mismatch`).
            Backward-compatible: a manifest sealed without provenance omits the key
            and hashes as before. Bounded receipt; the claim is public metadata,
            the signer surfaces only as a hash (`tests/test_dataset_provenance.py`,
            10). Verified operationally via the `verify-dataset-provenance
            --manifest [--expected-signer] [--expected-benchmark]` CLI (bounded
            receipt, non-zero exit on failure) as well as through the
            `verify_reward_mechanism` aggregate/CLI/endpoint
            (`tests/test_dataset_provenance_cli.py`, 5).

`verify_canary_calibration(report)` is point (3): a published `CanaryReport` proves
the oracle is calibrated only if it is internally consistent AND clear. Each
result's outcome is a pure function of its published bands (observed vs min/max
rank; INCONCLUSIVE coincides with a WITHHELD band on budget exhaustion), so the
check re-derives every outcome and confirms the claimed one matches — a report that
forges a "pass" over an out-of-range observation, hides a trip, or lies in its
aggregate `clear`/`tripped_count` is caught (`canary_report_inconsistent`); a
genuinely tripped oracle is `canary_tripped`; an empty report is `no_canaries`.
`verify_reward_mechanism(packet, *, source_targets, manifest, canary_report,
expected_signer, witness_quorum, expected_benchmark, require_provenance)` is the
aggregate entry point that composes every check — the run packet
(`verify_reward_run`) plus the external-input checks: code binding, dataset binding
(optionally requiring an M-of-N `witness_quorum`), canary calibration, and
seal-time provenance (run when `require_provenance`/`expected_benchmark` is set) —
into one bounded nested verdict; each external check runs only when its input is
supplied (else `skipped`), and `verified` is true iff every run check and every
*requested* external check passes (`tests/test_verify_reward_mechanism.py`, 14).
This lands all four points (1)-(4) of the third-party mechanism audit — plus the
witness-quorum and provenance trust layers — as one callable, surfaced as the
`verify-reward-mechanism --packet <json> [--source <path>...] [--manifest <json>]
[--canary-report <json>] [--expected-signer 0x..] [--witness 0x.. --witness-threshold M]
[--expected-benchmark <ref>] [--require-provenance]` operator CLI, which emits the
bounded nested verdict and exits non-zero on failure (`tests/test_verify_reward_mechanism_cli.py`,
4), and as the auth-gated `POST /verify/reward-mechanism` endpoint (which also
accepts `witness_quorum`/`expected_benchmark`/`require_provenance`). The HTTP
surface accepts the *data-safe* external inputs only — the posted sealed-dataset
manifest (point 2), canary report (point 3), witness quorum, and benchmark
expectation — and deliberately excludes
code-source binding (point 1), which would require the server to read a
caller-supplied file path (a local-file-inclusion risk); that check stays
CLI-local via `verify-reward-mechanism --source` (`tests/test_api_verify_reward_mechanism.py`,
6). All three private-reward demos
(`synthetic_hidden_keyword`, `denoising_hidden_holdout`, `bio_assay_program_qc`)
now emit a transcript-bound `reproducibility_certificate` alongside the
commitment, so `verify_reward_run` verifies any of them uniformly end-to-end (the
`dp_bounded_reward` demo included — all four private-reward demos verify).

The reward-loop side is also integration-tested end to end as one cohesive flow
(`tests/test_reward_loop_pipeline_integration.py`): a clear canary pre-screen ->
`run_private_reward_loop` with a DP budget attached (swappable HillClimb optimizer
over a bounded pool) -> `certify_loop_run` -> `verify_reproducibility_certificate`,
asserting the bounded attestation carries `dp_status`, no raw record egress in the
certified public export, and the transcript commitment is folded into the
certificate. A companion case proves a *tripped* canary fails the run closed
before any optimization (`StopReason.CANARY_TRIPPED`, zero rewarded rounds) — the
RLVR counterpart to the bio-diligence pipeline integration test.

Proof-carrying reward transcripts (`reward_transcript.py`) are `[real]`: they
extend the same chain with per-round *inclusion* proofs. The loop's bounded
per-round records (`RoundRecord.to_public_dict` — candidate hash, decision, reward
band) are committed into a domain-separated Merkle tree (leaf `0x00` / node `0x01`
prefixes prevent leaf/node second-preimage confusion), and the root is bound into
one `RewardTranscriptCommitment` with the environment hash, the loop's final
result hash, the TDX quote hash, and an optional chain-event hash. The tree uses
duplicate-last-node for odd levels, which is malleable ACROSS leaf-list lengths
(the CVE-2012-2459 property — `[A,B,C]` and `[A,B,C,C]` share a root; same-length
lists cannot collide without a SHA-256 collision). This is fully mitigated because
the commitment also binds `round_count` and `verify_reward_run` rejects any packet
whose `feedback` length differs from it — the load-bearing mitigation is now
explicit in the `merkle_root` docstring and pinned by a test that demonstrates the
malleated (same-root, +1-length) feedback is rejected `packet_inconsistent`.
`RewardTranscript.prove(round_index)` yields a `RewardInclusionProof` (leaf +
audit path); given only the commitment plus one proof, an auditor verifies that a
single round belongs to the attested run — and which run — while every other round
and all raw values stay sealed. `verify_round_in_commitment` binds the proof to
the commitment root; both public dicts are hashes/counts only and pass
`assert_bounded_egress` (`tests/test_reward_transcript.py`, 12). Its streaming
complement is the append-only transcript logger (`transcript_log.py`,
`[real]`): `TranscriptLogger.append` binds each bounded event to the previous via
`chain_hash = H(prev || event_hash || index)` (domain-separated genesis), so any
insert/delete/reorder breaks the chain from that point; `verify_chain` recomputes
it, and the public dict is hashes/counts only (`tests/test_transcript_log.py`,
10). Together the Merkle commitment (whole-set inclusion proofs) and the hash
chain (append-only streaming verification) cover the "transcript logger" role of
the toy `private_reward_envs` package. The chain is driven live inside
`PrivateRewardEnvironment`: every accepted or rejected query appends to an
internal `TranscriptLogger` (centralized `_append_record`), and the head is
exposed as `transcript_chain_head` / `verify_transcript_chain()` and published in
`EnvironmentAttestation` next to the flat `transcript_hash` — the attested output
carries both the whole-set hash and an append-only chain head. The
`RewardTranscriptCommitment` binds that `transcript_chain_head` into its
`commitment_hash`, so one published commitment ties the per-round Merkle root, env
config hash, final result hash, quote, chain event, and the env's append-only
query-chain head together. All three private-reward demos (`synthetic_hidden_keyword`,
`denoising_hidden_holdout`, `bio_assay_program_qc`) now emit this commitment via
`certified_public_export`. The
`bio_assay_program_qc` demo emits a `reward_transcript_commitment` alongside its
reproducibility certificate, built over the bounded per-candidate feedback via
`RewardTranscript.from_round_dicts`; a test recomputes the root from the emitted
feedback and verifies a per-candidate inclusion proof against it.
[partial] The commitment is not yet bound into the on-chain result packet — that
waits on the live settlement path.

The local candidate sandbox contract is:

```
PythonCandidateSandbox.run(candidate)
  input:  UTF-8 Python source bytes
  guard:  AST preflight blocks file, process, network, import, dunder escapes
  runtime: subprocess, scratch cwd, stripped environment, deterministic seed
  limits: timeout, CPU/memory best-effort, max source bytes, capped stdout/stderr
  output: candidate hash, pass/reject/error/timeout, failure bucket,
          elapsed timing band, exit code, capped traces
```

This sandbox is a real local development guardrail, not the final production
answer for hostile third-party code. Production CVM execution still needs
OS/container isolation, no-network policy, mounted scratch-only filesystem,
resource cgroups/ulimits, and egress auditing.

The hidden holdout contract is:

```
HiddenHoldoutSet(records, policy)
  internal: raw records and record IDs
  split:    train / reward / final_validation
  public:   split commitment, partition counts, query counts, seed hash
  guard:    reward-query budget, per-candidate repeat cap, minimum unique
            reward candidates, and one-shot final validation gate
```

Public holdout manifests intentionally do not include record IDs, payloads, raw
labels, or split membership. Concrete private-reward environments still need to
wire this into their reward/final-validation control flow and add
domain-specific anti-overfitting tests.

Target architecture:

```
+--------------------------------------------------------------+
| TTT/RL Bio Validation                                        |
|--------------------------------------------------------------|
| input: sealed artifact / corpus / assay data / reward fn     |
|                                                              |
|  1. parse and validate artifact schema                       |
|  2. split train/eval or construct environment                |
|  3. run TTT/RL/SFT loop through IsolatedTinkerSession        |
|  4. evaluate against approved benchmark                      |
|  5. screen bio-risk and dual-use constraints                 |
|  6. reduce raw metrics to bounded outputs                    |
|  7. attach result hash and TDX quote                         |
|                                                              |
| output: yes/no, score band, confidence band, offer, hash     |
+--------------------------------------------------------------+
```

Data-flow guardrails:

```
raw sequences, assays, model samples, weights, gradients
        |
        | must stay inside TEE / Tinker session
        v
bounded output reducer
        |
        v
score band, pass/hold/deny, confidence, result hash
```

Optimizer placement guardrails:

```
internal TEE optimizer
  may read exact rewards and reward-derived state inside the attested boundary

attested remote optimizer
  may read exact rewards only when the remote service is separately attested

external optimizer
  receives public problem/schema metadata and bounded feedback only
  exact rewards, reward-derived state, private checkpoints, and holdout data
  are rejected by default policy
```

Implementation status:

```
[real]      PrivateRewardEnvironment base interface, LeakageBudget,
            QueryLeakageRecord, transcript hash, leakage hash, bounded
            feedback/result dataclasses, OptimizerPolicy, external bounded
            default mode, internal dense-reward mode, attested remote policy
            guard, and toy unit tests.
[real]      PythonCandidateSandbox for local toy candidates with preflight,
            subprocess timeout, deterministic seed, capped stdout/stderr, and
            no supported network/filesystem/process access. Defense in depth,
            self-review-verified: the AST preflight bans dangerous import roots and
            literal dunder attribute access, and the subprocess runs under a
            restricted `__builtins__` (no `getattr`/`type`/`vars`/`eval`/`exec`/
            `compile`/`__build_class__`/`open`/`__import__`) exposing only
            `math`/`random`, so AST-passing escapes (`getattr((), "__class__")`,
            `type(())`, a class definition) fail closed at runtime with no stdout —
            locked in by adversarial regression tests
            (`tests/test_private_reward_sandbox.py`). Resource-DoS defenses are
            also pinned: the wrapper sets `RLIMIT_CPU`/`RLIMIT_AS` from the policy,
            an infinite loop hits the wall-clock timeout (bounded `timeout`), and a
            memory-bomb candidate (a huge allocation) fails closed to a bounded
            `runtime_error` — never OOMing the host, hanging, or leaking a raw
            traceback (stderr is bucketed).
[real]      Local sandbox side-channel buckets for elapsed timing, timeout
            normalization, capped output, best-effort memory limits, and
            policy/syntax/runtime/timeout failure codes.
[real]      HiddenHoldoutSet with deterministic private split, public split
            commitment, reward-query accounting, per-candidate repeat caps,
            minimum unique candidates before final validation, and one-shot
            final-validation gating.
[real]      Canary sentinel (`canary.py`) — leaderboard-overfitting defense.
            Known-answer probes carry a [min_band, max_band] window and are
            screened through the environment's own bounded evaluate (sharing the
            holdout accounting): known-junk scoring above its ceiling trips
            TRIPPED_HIGH (oracle leaking / gamed), known-strong below its floor
            trips TRIPPED_LOW (oracle collapsed), budget-exhausted/withheld is
            INCONCLUSIVE (never a false trip). `assert_clear` fails closed; the
            CanaryReport is bounded (per-canary band + payload hash only,
            passes assert_bounded_egress). `flag_surprising_score` routes bands at
            or above a review threshold to expert review instead of auto-settling
            (`tests/test_canary.py`, 11). Wired into the loop:
            `run_private_reward_loop(..., canary_report=...)` refuses to start and
            returns a zero-round `CANARY_TRIPPED` outcome when a pre-screen report
            (from a fresh env) is not clear, before any budget is spent. Adaptive
            budget cuts and a wired reviewer queue remain [planned], blocked on a
            deployed CVM.
[real]      SyntheticHiddenKeywordEnvironment with bounded reward bands,
            hidden reward partition queries, final-validation gating, and
            public manifests that omit record IDs and payloads.
[real]      `synthetic-private-reward-demo` CLI runs the synthetic hidden
            dataset environment and emits a bounded public packet: optimizer
            view, candidate hashes, reward bands, final result, transcript hash,
            leakage hash, and attestation metadata. Hidden records and submitted
            candidate strings are forbidden from the rendered output.
[real]      DenoisingHoldoutEnvironment: concrete denoising private-reward env
            that wires HiddenHoldoutSet into single-cell denoising and scores
            candidate `denoise(train)` programs through PythonCandidateSandbox.
            Domain anti-overfitting rule (Poisson-constraint cap), one-shot
            final validation, and bounded `RewardBand`-only egress; exact MSE/
            Poisson values and raw cell counts never leave the boundary. The
            `denoising-private-reward-demo` CLI emits the bounded packet; the
            program text is never echoed. Toy scale only (no numpy in sandbox).
[real]      Reward-oracle proof tests (`tests/test_reward_oracle_proofs.py`)
            lock the five leakage invariants across BOTH concrete environments:
            no sealed-data egress, no exact-reward egress (bounded key whitelist
            + `internal_reward_for_optimizer()` denied under external policy),
            bounded query-budget exhaustion, sandbox stdout truncation with
            fail-closed banned-I/O, and deterministic transcript/leakage/
            environment hashes. These are regression guards for the properties
            the private-reward pitch depends on.
[modeled]   TTT/RL bio-validation concept.
[partial]   SFT evaluator scaffold.
[real]      Bio release gate (`bio_validation.py`): fail-closed decision
            (release/hold/deny), bounded result schema, forbidden-output screen;
            holds unless every `BioReadiness` capability is enabled. Also accepts
            an optional bounded re-identification assessment and holds for
            biosecurity review when it blocks.
[real]      Bio hold -> review queue bridge (`bio_review_bridge.py`): closes the
            loop between a HELD bio receipt and the human-review queue.
            `enqueue_bio_hold` turns a HELD `BioReleaseReceipt` into a bounded
            ticket (routed to the receipt's review role, keyed by the result hash,
            evaluating agent recorded as submitter so it cannot self-approve, with
            optional per-role M-of-N), and `resolve_bio_release` maps the ticket
            state back to a final decision — only a queue RELEASED promotes the
            hold to RELEASE, DENIED becomes DENY, and pending/expired/missing stays
            HOLD (fail closed). The full pipeline is integration-tested end to end
            (`tests/test_bio_pipeline_integration.py`): a held bio result flows
            `evaluate_bio_release` (HOLD) -> `enqueue_bio_hold` -> two distinct
            biosecurity officers release under M-of-N (submitter self-approval
            rejected, one officer insufficient, a single deny vetoes) ->
            `resolve_bio_release` (RELEASE) -> `decide_disclosure` (ESCROW) ->
            `solution_escrow` seal + authorization-gated release — proving the
            modules compose with all fail-closed properties intact.
            `evaluate_and_route` is the live convenience:
            it evaluates a candidate and auto-enqueues the receipt iff it HOLDs
            (idempotent per result hash; RELEASE/DENY leave the queue untouched),
            so a held result is never left un-queued. Bounded throughout (hashes
            only) (`tests/test_bio_review_bridge.py`, 11).
[real]      Re-identification risk checks (`bio_reid.py`): deterministic
            k-anonymity-style assessment over cohort *metadata* (never records)
            — unsuppressed small cells or below-threshold subgroups in
            non-aggregate output block release; bounded band/boolean/hash only.
            The exact k-anonymity thresholds are pinned by a boundary test
            (unsuppressed `min < k` blocks, exactly `k` is anonymous → MEDIUM,
            `< 2k` MEDIUM, `>= 2k` LOW) so an off-by-one that silently changes the
            privacy guarantee is caught.
[real]      Differential-privacy accounting (`dp_accounting.py`): gives the
            `bio_validation.differential_privacy_marked` flag substance. In DP
            mode a `DpAccountant` tracks a cumulative (epsilon, delta) budget
            across reward releases by basic composition (never under-counts) and
            `charge()` is fail-closed — an over-budget release is denied without
            mutating state. In NON_DP mode releases are admitted but every record
            is stamped `phi_safe=False`, so individual-data releases are never
            silently treated as private; only a DP-tracked accountant reports
            `phi_safe=True`. Bounded record carries DP params/counts/flags only
            (`tests/test_dp_accounting.py`, 12). `evaluate_bio_release` accepts an
            optional `dp_charge`: for individual-level data a live charge takes
            precedence over the asserted `differential_privacy_marked` boolean —
            release proceeds only if the charge is admitted AND phi_safe, else
            HOLD with the bounded DP accounting recorded on the receipt schema
            (an over-budget or NON_DP charge holds even when the boolean is True).
            It is also wired into the reward loop:
            `PrivateRewardEnvironment.set_dp_budget(accountant, params_per_query)`
            charges the accountant per accepted reward query (computing the reward
            reads the sealed individual-level data) and, once epsilon is spent,
            `evaluate` fails closed (`BUDGET_EXHAUSTED` / WITHHELD) — real
            privacy-budget-bounded reward release, off by default; showcased by
            the `dp-bounded-reward-demo` CLI (release then fail-closed exhaustion
            with attested `dp_status`). When a DP budget
            is configured the bounded `dp_status` (mode / phi_safe / spent+max
            epsilon-delta / counts) is recorded in `EnvironmentAttestation`
            (conditional key, so non-DP attestations are byte-identical to before;
            epsilon/delta are public config like the holdout fractions)
            (`tests/test_private_reward_dp_gate.py`, 4).
[real]      Data-quality checks (`bio_data_quality.py`): deterministic
            assessment over a bounded `DatasetProfile` — schema mismatch,
            insufficient samples, and train/test contamination block release;
            missingness/duplicates/class-imbalance degrade the band. Wired into
            the gate as an optional hold. Note the deliberate safety-vs-quality
            separation (pinned by test): only *invalidating* flags set
            `blocks_release`, so `evaluate_bio_release` (the SAFETY gate) releases
            a POOR-but-non-blocking result with its band attached — buyer-value
            quality judgment is the separate concern of the persona `data_quality`
            lens, which maps POOR -> DENY. A misleading result is held; a merely
            low-quality one is released honestly banded.
[real]      Bio evaluator registry (`bio_registry.py`): `default_registry()`
            makes shipped bio use cases discoverable (bounded metadata) and
            returns their fail-closed runners; duplicate/unknown ids rejected.
[real]      Methodology summaries (`bio_methodology.py`): reconstruction-safe by
            construction — composed only from a closed controlled vocabulary of
            method tokens plus coarse magnitude bands, so no raw value can enter;
            out-of-vocabulary tokens are rejected and free-text notes are
            screened to a hash. Bounded, deterministic.
[real]      Dual-use / biosecurity classifier (`bio_dual_use.py`): deterministic
            policy over declared structured signals (not LLM) — gain-of-function
            / de novo design / actionable output in a pathogen-toxin context are
            PROHIBITED (deny); pathogen context, sequence/protocol emission,
            human subjects without IRB, or non-synthetic data are REVIEW (hold).
            Complements the free-text forbidden-output screen. Gate check order:
            forbidden-output (deny) > require-screen (hold) > dual-use (deny/hold)
            > re-id > individual-level > data-quality > readiness. The structured
            dual-use assessment is caller-supplied (its danger signals are declared
            metadata the candidate doesn't carry), so it is skipped when omitted;
            a caller in a dual-use domain sets
            `evaluate_bio_release(..., require_dual_use_screen=True)` to fail
            closed to HOLD (`dual_use_screen_required`) when no assessment is
            supplied — a structurally dangerous task (e.g. gain-of-function) with
            benign-looking text fields then cannot RELEASE by omitting the screen.
            The always-on forbidden-output *text* screen is unaffected. The
            deployed `run_bio_diligence_flow` path does not call
            `evaluate_bio_release` directly — it maps `dual_use.tier` into the
            persona `EvaluationSummary`, where a missing assessment yields an empty
            `dual_use_tier` that the persona panel already treats as fail-closed
            DENY, so settlement cannot proceed without a dual-use screen even
            there (pinned by an isolation test: all-else-clean + dual-use omitted
            -> DENY). Both the persona-panel production path and the direct-gate
            `evaluate_and_route` wrapper (which forwards `require_dual_use_screen`)
            fail closed on an omitted structured screen. The always-on
            forbidden-output text screen (`screen_forbidden_output`) matches
            compound dangerous terms through a shared separator class
            (`_SEP = [-_.\s]*`) so a term cannot be smuggled past by swapping the
            word separator: `gain-of-function`, `gain_of_function` (the form
            code-derived identifiers use), `gain.of.function`, `gain of function`,
            and the concatenated `gainoffunction` all match `pathogen_enhancement`
            (same for `de novo`/`de-novo`/`de_novo`/`denovo` and the `wet lab`
            variants). A self-review gap closed 2026-07-12: the prior `[- ]`/`\s*`
            classes matched only hyphen/space and let underscore and hyphenated
            forms evade the screen entirely. The ordered token sequence is itself
            the dangerous term, so the broadened class adds no false positives
            (benign "the function gain was high" / "novofunction" do not trip it;
            full suite green) (`tests/test_bio_validation.py`).
[real]      Final-solution disclosure policy (`disclosure_policy.py`): decides how
            a winning candidate (code/solution) may be released over a severity
            ladder BLOCKED > HASH_ONLY > ESCROW > PUBLIC (most restrictive wins).
            Base posture is ESCROW (sealed, released only under separate
            authorization) unless the caller passes `allow_public`; a
            reconstruction screen downgrades to HASH_ONLY on secret-shaped
            material (`redact_text`), a long base64/hex blob, or non-text
            candidates; the re-id screen caps at HASH_ONLY (HIGH) / ESCROW
            (MEDIUM); the dual-use screen forces BLOCKED (PROHIBITED) / ESCROW
            (REVIEW). `disclosable_payload()` returns the raw bytes only when the
            mode is PUBLIC; the decision dict is bounded (mode + reasons +
            candidate hash + score band, passes assert_bounded_egress)
            (`tests/test_disclosure_policy.py`, 12). Wired into the diligence
            flow: `run_diligence_flow` / `run_bio_diligence_flow` take an optional
            `disclosure_candidate` (+ `allow_public_disclosure`) and, after the
            review and stage-disclosure gates pass and before settlement, compute
            the decision (reusing the flow's own dual-use/re-id) and record it on
            the `DiligenceFlowReceipt`; a BLOCKED decision holds the flow before
            any payout, while ESCROW/HASH_ONLY settle with the release mode
            recorded. The ESCROW mode is now physical: `solution_escrow.py`
            (`SolutionEscrowStore`) seals an ESCROW-mode candidate under a
            per-escrow HKDF-SHA256 key and releases the plaintext only to a caller
            presenting the authorization secret committed at seal time (its hash
            bound as AES-GCM AAD). Fail-closed — only ESCROW may be sealed,
            wrong-auth / unknown / double-seal raise, receipts are bounded
            (`tests/test_solution_escrow.py`, 9). [partial] The escrow decision is
            not yet emitted on-chain — waits on the live settlement path.
[real]      First concrete bio evaluator (`bio_evaluators.py`): deterministic
            synthetic assay-QC scoring via the standard Z'-factor, emitting only
            coarse score/confidence/utility bands + public data-quality flags
            (exact Z' and control stats stay internal). Synthetic-only, no
            RNG/network/Tinker; feeds the fail-closed gate so it cannot
            self-release. Self-reviewed 2026-07-12: the Z' formula (Zhang 1999) is
            correct; `SyntheticAssay` requires >= 2 finite controls each, and the
            public `z_prime_factor` now also raises `BioValidationError` (not a raw
            `StatisticsError`) on empty controls. `tests/test_bio_evaluators.py`
            (15 tests).
[real]      Output banding and offer computation.
[planned]   Hardened production sandbox and deployed side-channel controls,
            domain-specific bio benchmark, risk classifier, and validation
            report schema.
```

### Third-Party Reward Evaluability (Mechanism Audit)

`[planned]` — the buyer/sponsor/optimizer must be able to *evaluate the RL
environment* (trust the reward is real, honestly computed, un-gamed, and useful)
while never seeing the sealed data. In the threat model they **read the env
code** and may **query the black box** within agreed boundaries. The resolution
is that they audit the **mechanism, not the data**. Formal treatment is in
`PROJECT.md` "Third-Party Reward Evaluability"; backlog is `TODO.md`
"Third-Party Reward Evaluability (Mechanism Audit)"; grounding papers are
`📄/attestable-audits/paper.md` and `📄/ladder/paper.md`.

The trust problem splits into three axes that must not be conflated:

```
trust        honest oracle running the read code over the committed data
leakage      queries + code knowledge reconstructing sealed records
overfitting  grinding a fixed holdout to a meaningless number, no record leaked
```

`leakage` and `overfitting` are bounded by the existing output-reduction / query
budget / DP machinery. `trust` is answered by attestation + commitment +
calibration. The reward-mechanism attestation extends the verification chain:

```
git SHA -> docker digest -> compose hash -> TDX quote
                                              +-> HASH(reward_code)
                                              +-> dataset_commitment (sealed manifest root)
                                              +-> params  -> bounded_result
```

This is the Attestable Audits `A[AC + AD -> R]` shape: bind the reward-code
hash and the committed-dataset hash to the aggregated bounded result, so a party
who read the open env code can verify *that code* ran over *that data*.

Overfitting defense reuses the same noise the leakage bound needs — a
Ladder-gated (significant-improvement-only) or Thresholdout (DP noisy-threshold)
release path over `HiddenHoldoutSet`, giving a fixed-size holdout effectively
unlimited honest attempts.

```
[real]      Verification chain git SHA -> docker digest -> compose hash ->
            TDX quote; HiddenHoldoutSet split/commitment/query accounting;
            sealed-dataset manifest hashes usable as a commitment root.
[planned]   Reward-mechanism attestation binding HASH(reward_code) ||
            dataset_commitment || params -> bounded_result.
[planned]   Public canary / calibration slice per environment (releasable
            known-ground-truth scores anchoring the private scale).
[planned]   Attested dataset provenance signed at seal time (source pipeline,
            upstream id, license, distribution claim vs. named public benchmark).
[planned]   Neutral sealing witness / M-of-N notary co-signing the commitment.
[planned]   Ladder-gated release path in `private_reward_holdout.py`.
[planned]   Thresholdout / DP-noised reward option with composed leakage budget.
[planned]   `verify-reward-mechanism` third-party verification CLI (bounded
            pass/fail + hashes only).
```

Residual gaps stated to counterparties: TEE hardware root (mitigate multi-vendor
attestation, optional ZK dispute backstop), commitment != quality (canary +
provenance + seller stake), and candidate-as-exfiltrator (sandbox +
aggregate-only + quantized/noised band).

### Coordination, Consent, And Review

The coordination layer sits above single-corpus gates. It never merges policies
into a broader permission; it composes independent per-corpus results by
intersection and fails closed.

Implementation status:

```
[real]      `tinker_delegate.coordination` implements a pure source-modeled
            reducer with no network, browser, email, chain, or Tinker effects.
            Events are `SubmitTurn`, `GateResults`, `ReviewerDecision`, and
            `RevokeCorpus`; every transition returns a new `CoordinationState`.
[real]      `tinker_delegate.policy_kernel` supplies the source-real
            deterministic gate beneath this layer. The fan-out boundary validates
            one access request and one policy per corpus, evaluates each pair,
            and emits `GateResults` with `coordination.GateDecision` values.
            Policy denies remain terminal even if consent grants exist; holds
            carry stable reviewer-route labels into hold tickets.
[real]      The `policy-gate` CLI can now produce replayable bounded receipts
            for those single-corpus gates and turn fan-out gates before any
            service or deployed TEE integration exists.
[real]      Strict composition is executable: any deny denies, any hold opens a
            ticket and withholds output, only all-pass can reach consent and
            settlement, and gate results must cover exactly the turn's corpus set.
            Precedence is pinned across the mixed multi-corpus case: when one
            corpus DENIES and another HOLDS, the composed turn is DENIED (most
            restrictive wins, no review ticket opened) — a denied corpus can never
            slip into review, guarding the intersection's deny-beats-hold ordering.
[real]      Delegated agents cannot widen access or self-approve holds in the
            reducer. Agent turns are denied at submit time if they exceed the
            grantor's corpus/purpose/pipeline delegation, and release attempts
            from the turn issuer/requester become bounded `self_approval_denied`
            terminal records.
[real]      Second-confirmation gate for high-risk actions
            (`second_confirmation.py`): a consequential action (large top-up,
            widened access, policy bypass) above a value threshold
            (`requires_confirmation`) must be confirmed OUT OF BAND before it
            proceeds. `evaluate_confirmation` authorizes it only on enough
            distinct, fresh confirmations through approved channels (wallet
            signature / WebAuthn / passkey / device-bound session / human reviewer)
            from a party OTHER than the requester — non-approved channels, expired
            or future-dated confirmations, self-confirms, and duplicate confirmers
            do not count, and a requirement with no approved channels authorizes
            nothing (fail closed). Bounded output; evidence stays hashed. Composes
            with the funding triad (a high-value top-up is gated)
            (`tests/test_second_confirmation.py`, 13). `[partial]`: real channel
            evidence verification (wallet-sig / WebAuthn assertion) and wiring into
            deployed high-risk paths are not yet done.
[real]      Decision explainer (`decision_explainer.py`): the bounded data layer
            behind an "explain why denied/held" surface. `explain_decision` maps the
            system's `reason_code`s (leakage, budget, biosecurity, privacy,
            data-quality, governance, verification, funding, lifecycle) to a fixed
            explanation (category, disposition, plain-language summary, remediation).
            Leak-free BY CONSTRUCTION — it emits only curated registry vocabulary and
            never echoes the input code or its `:suffix`, so an injected private
            suffix cannot leak; unknown codes fall back to a safe generic hold. Tests
            feed REAL codes from `evaluate_bio_release` / `spend_budget` /
            verification to prove coverage (`tests/test_decision_explainer.py`, 9).
            Wired into real surfaces (not deployment-blocked): `verify_reward_run`
            verdicts and `BioReleaseReceipt.to_public_dict` now carry a bounded
            `explanation` (self-explaining verdict/receipt — a held/denied bio
            diligence result explains its own policy reason, with the reason code's
            `:suffix` stripped so no detail leaks), and the
            `explain-decision <reason_code>` operator CLI emits the bounded
            explanation. `[partial]`: the UI rendering them is frontend-gated.
[real]      `tinker_delegate.royalty_settlement` adds multi-owner per-query
            royalty settlement: `split_royalty` divides a per-query royalty among
            co-owners by basis-point weights via largest-remainder (payouts sum to
            exactly the total, deterministic), and `RoyaltyLedger` accrues splits
            into per-owner claimable pull-payment balances preserving the
            three-way conservation invariant `claimable + claimed == accrued`
            (self-review fix 2026-07-12: the meter now tracks the claimed total —
            the previous `claimable == accrued` check falsely reported
            not-conserved after any withdrawal, since claimed funds legitimately
            leave the pool). `public_summary` is bounded (amount bands,
            `total_claimed_band`, `conserved` flag, settlement hash);
            `tests/test_royalty_settlement.py` (12) prove conservation across many
            amounts/weights and after claims. It is wired into coordination: `Corpus.owner_shares`
            (co-ownership weights) makes `_royalty_meters` split a corpus's
            per-query royalty into one conserving `RoyaltyMeter` per co-owner
            (single-owner corpora unchanged; `tests/test_coordination.py`, +2).
            `RoyaltyDistributor.sol` is the on-chain pull-payment rail: it takes a
            query ref plus the conserving per-owner split, credits each co-owner's
            `pending[token][owner]` (native or ERC20; deposited total must equal
            the sum), and `withdraw()`/`withdraw(token)` pull the funds (CEI,
            bool-checked transfers, guards on length/zero/value). Its conservation
            is inherent (deposited == sum of pending; no separate accrued
            accumulator that could desync — the Python meter's audit-flag bug has
            no analog here). 12 Foundry tests incl. a native conservation fuzz and
            a reentrancy-drain test (a malicious co-owner re-entering `withdraw()`
            during its native payout gets exactly its single credit and cannot
            drain other owners — CEI defeats it). Proven
            end-to-end on ephemeral Anvil
            (`scripts/prove-royalty-distributor-anvil.py`: deploy → distribute
            1 ETH 0.7/0.3 → both owners withdraw → contract drains to exactly zero;
            guarded opt-in test `DNAI_RUN_ANVIL_PROOFS=1`). Deploying it to Base
            Sepolia and wiring coordination settlement to it are `[planned]`.
            `tinker_delegate.royalty_distribution_plan` bridges a settled per-owner
            split into the exact `distributeNative`/`distributeERC20` call — bounded
            calldata plus a `--account dev` keystore `cast` template, no broadcast
            (operator executes it, mirroring the governance plan). Its hand-rolled
            dynamic-array ABI encoding is verified byte-identical to `cast calldata`
            (`tests/test_royalty_distribution_plan.py`, 8) and proven to execute
            end-to-end on Anvil (`scripts/prove-royalty-distribution-plan-anvil.py`:
            build plan → broadcast its exact calldata → owners withdraw → contract
            drains to zero; guarded opt-in test). So the royalty path is proven
            from Python split → bounded plan → executed on-chain distribution →
            conserving pull-payment.
[real]      Source-modeled consent, revocation, joint attestations, and royalty
            meters exist. Active consent grants match owner, corpus, requester,
            purpose, pipeline, and expiry. `CollabSession.consent_quorum`
            supports `unanimous` and `<m>-of-<n>` over the turn corpora; missing
            or below-threshold consent leaves the turn `awaiting-consent`, and
            invalid/mismatched quorum policy fails closed as
            `invalid_consent_quorum`. `ConsentDecision` lets only the matching
            corpus owner grant or deny consent for an awaiting turn; grants
            settle only after quorum is met, and denial is terminal as
            `consent_denied`. Revocation fails in-flight/future turns closed
            while preserving already-settled turns; settled turns carry bounded
            meter bands and a joint royalty hash.
[real]      `tinker_delegate.consent_receipt` and the
            `tinker-delegate consent-decision` CLI provide a replayable bounded
            proof path for source-modeled owner consent decisions. The command
            reads a local coordination-state JSON plus a consent-decision JSON,
            applies the pure reducer, and emits receipt fields for before/after
            status, action, quorum grant counts, owner/requester/purpose/pipeline
            hashes, input/output state hashes, signature-binding status/hashes,
            and `raw_secret_egress=false`. Optional `--require-signature`
            verifies an Ethereum signed-message confirmation over a canonical
            hash-only payload containing the receipt schema/surface, input-state
            hash, turn/corpus refs, owner/requester/purpose/pipeline hashes,
            decision, and optional expiry. When `--expected-signer` is provided,
            the recovered signer must match that owner-controlled address before
            the reducer event is accepted. The receipt does not print raw
            purpose, pipeline, owner refs, signer addresses, raw signatures, gate
            reasons, or the full updated coordination state.
[real]      `POST /coordination/consent-decision` exposes the same bounded
            source-modeled consent-decision receipt through the FastAPI service
            boundary. Unlike some local-dev routes, this endpoint requires a
            configured runtime bearer token before it will process a request. It
            may require the same optional signed owner confirmation, but returns
            the bounded receipt only; it does not expose owner notification,
            reviewer UI state, raw signer material, or the updated raw
            coordination state.
[real]      `tinker_delegate.review_queue` adds a bounded source-level human
            review queue. It can ingest coordination `HandoffTicket`s, persist
            and load bounded queue JSON, filter pending tickets by routed role,
            record release/deny decisions with reviewer identity hashes, expire
            stale tickets, and maintain an append-only audit hash. The public
            queue shape contains ticket IDs, turn/corpus refs, route labels,
            reason hashes, reviewer hashes, decision hashes, status counts, and
            `raw_secret_egress=false`; it does not expose raw hold reasons or
            raw reviewer identities. Non-self-approval is now enforced
            *structurally*: each `HandoffTicket` carries the submitting agent
            (`submitter_ref`, the held turn's `by`), the queue stores its hash on
            the ticket, and `decide_review_ticket` rejects any reviewer whose ref
            hashes to the submitter's — so the submitter can never resolve its own
            ticket even if the caller omits `blocked_reviewer_refs`. M-of-N
            approval is also real: `enqueue_handoff_tickets` takes a
            `required_approvals_by_role` map, so a high-risk role (e.g. biosecurity
            review) requires N distinct reviewers to release. A release accumulates
            distinct approvals (`vote_recorded` audit events; the ticket stays
            PENDING until the threshold is met, then RELEASED; a duplicate approver
            is rejected), while a single `deny` denies immediately — fail-closed
            regardless of prior approvals. The queue is operable over the runtime
            API: auth-gated `GET /review/queue` (optionally `?routed_role=`)
            returns the bounded queue/pending tickets, and `POST /review/decide`
            records a reviewer decision at server time and persists it to
            `review_queue_path` (409 on a fail-closed rejection, 503 if the queue
            is unconfigured); `POST /review/expire` runs an on-demand expiry sweep
            (a deployed cron can poll it) that transitions stale pending tickets to
            EXPIRED so they can no longer be released, persisting the result
            (`tests/test_api_review_queue.py`, 8).
[partial]   Human-review service integration remains incomplete. There is no
            tee-email-oracle notification, reviewer UI, distinct per-reviewer
            authentication (the endpoint is runtime-token-gated and the
            `reviewer_ref` is the audit identity), or production reviewer key
            custody yet (expiry is on-demand via `/review/expire`; a scheduled
            worker to poll it is still deployment-side).
[planned]   Wire coordination effects to tee-email-oracle for reviewer/owner
            notification, production owner-key custody, and to
            DiligenceRoom/tinker-delegate for settlement and attested execution.
[real]      `tinker_delegate.evaluator_personas` adds five reviewer lenses
            (buyer-utility, seller-protection, biosecurity, data-quality,
            economics) as deterministic functions over an already-bounded
            `EvaluationSummary` (bands/tiers/booleans, never raw data). Each
            returns a bounded pass/hold/deny `PersonaVerdict`; `evaluate_personas`
            composes the panel by the same strict intersection (any deny denies,
            any hold holds, only all-pass proceeds) and emits a bounded
            `PanelDecision` with a panel hash. Unknown/missing signals fail closed
            to deny inside each lens — every one of the five lenses has an isolated
            fail-closed test (utility unknown band, seller leakage `None`,
            biosecurity missing tier/risk, economics cost `None`, data-quality
            missing band → DENY), so a per-lens regression to fail-open is caught
            (`tests/test_evaluator_personas.py`, 14).
            `summary_from_bio_evidence` / `evaluate_bio_personas` bridge the real
            bounded bio assessments (assay `utility_band`, data-quality band,
            re-id risk, dual-use tier) into an `EvaluationSummary` and run the
            panel — duck-typed so the personas stay free of bio imports; data
            quality maps good→PASS/fair→HOLD/poor→DENY and unknown bands fail
            closed (`tests/test_evaluator_personas_bio.py`, 6).
[real]      `tinker_delegate.rental_stages` is a pure, fail-closed
            progressive-disclosure state machine for staged rental tiers
            (`raw_inspection`→`training`→`inference`→`full_disclosure`), each with
            its own reserve, cap, bounded result type
            (score_band/utility_band/yes_no/artifact), and consent flag.
            `advance_stage` enforces monotonic disclosure (no regression), owner-
            supplied consent (never self-approved), a hard rule that
            `full_disclosure` always requires consent, and reserve/cap bounds;
            every failure DENYs with a bounded reason code and the transition is
            bounded (`tests/test_rental_stages.py`, 13). Wiring these tiers into
            the `DiligenceRoom` deal lifecycle and the consent layer is a
            `[planned]` follow-up.
[real]      `tinker_delegate.diligence_flow.run_diligence_flow` composes the
            bounded primitives into one fail-closed pipeline with a fixed gate
            order: persona review → rental-stage disclosure → royalty settlement.
            A non-PASS panel stops before disclosure/settlement; a denied stage
            transition stops before settlement; the per-owner royalty split
            accrues only on a proceeding flow. Output is a bounded
            `DiligenceFlowReceipt` (flow/panel decisions, reason code, result
            type, stage transition, royalty amount bands, an optional
            `reward_transcript_commitment` — the bounded commitment of a verifiable
            private-reward run, recorded on every receipt and bound into
            `flow_hash` — and panel + flow hashes;
            `tests/test_diligence_flow.py`, 9). `run_bio_diligence_flow` drives the
            same pipeline directly from bounded bio assessments, so a real
            `evaluate_synthetic_assay_qc` candidate flows
            evaluate→review→disclosure→settlement in one call
            (`tests/test_diligence_flow_bio.py`, 9). The seller-protection/economics
            signals are auto-derived (`derive_leakage_signals`):
            `leakage_within_bounds` is grounded in the evaluation's own
            `raw_secret_egress == False` (proven, not asserted), and offer/cost
            bounds from the amounts — so the lenses rest on evaluation evidence,
            with missing evidence failing closed. `distribution_plan_from_flow`
            turns a *proceeding* flow receipt into an executable
            `RoyaltyDistributionPlan` (resolving owner_refs to addresses, delegating
            to the cast-verified/Anvil-proven builder); a hold/deny receipt or
            missing owner address fails closed. So one bio evaluation yields both
            the bounded verdict and the executable on-chain royalty plan
            (`tests/test_diligence_flow_to_plan.py`, 5). The whole pipeline is
            proven end-to-end on ephemeral Anvil
            (`scripts/prove-diligence-flow-settlement-anvil.py`: real assay flow →
            PROCEED → derived plan → deploy distributor → broadcast calldata →
            owners withdraw → contract drains to zero; guarded opt-in test). So
            bio evaluation → verdict → derived plan → on-chain distribution →
            conserving pull-payment is one proven flow. Wiring it to the deployed
            TEE / Base Sepolia is `[planned]`.
```

### 4. DNAI

DNAI is the mechanism layer that composes the previous pieces:

```
DNAI = NDAI economic controls + TEE boundary + bounded evaluator + settlement
```

It answers:

```
Who owns the private artifact?
Who may inspect it?
What may the evaluator do?
What may leave the TEE?
How much can the buyer spend?
What is the seller's reserve?
Who gets paid if the buyer accepts?
What public evidence proves the result was produced by the expected enclave?
```

The current DNAI implementation is distributed:

```
README.md                         product description
getting-started.md                build plan and source map
tinker_delegate/control_plane.py  deal lifecycle inside TEE
tinker_delegate/evaluator.py      stub/SFT evaluator
tinker_delegate/session.py        isolated Tinker session
DiligenceRoom.sol                 escrow and settlement
docs/USER-FUNCTIONS.md            status and user capability catalog
docs/COORDINATION-ENGINE-SPEC.md  multi-party gate and effects model
```

## Smart Contract Architecture

### Contract Map

```
                         Base Sepolia

       +------------------------------------+
       | EmailOracleAuth.sol                |
       |------------------------------------|
       | Governs which email oracle code    |
       | and consumer compose hashes are    |
       | authorized.                        |
       +----------------+-------------------+
                        |
                        | supports app-auth policy
                        v
       +------------------------------------+
       | tee-email-oracle CVM               |
       +------------------------------------+


       +------------------------------------+
       | DiligenceRoom.sol                  |
       |------------------------------------|
       | Governs deal escrow, result hash,  |
       | buyer accept/reject/expire, and    |
       | pull-payment withdrawals.          |
       +----------------+-------------------+
                        |
                        | called by teeIdentity
                        v
       +------------------------------------+
       | tinker-delegate CVM                |
       +------------------------------------+
```

### EmailOracleAuth.sol

State model:

```
+---------------------------------------------------------+
| EmailOracleAuth                                         |
|---------------------------------------------------------|
| owner                                                   |
| ORACLE_UPGRADE_DELAY                                    |
| allowAnyDevice                                          |
| oracleCodeFrozen                                        |
| consumerRegistryFrozen                                  |
| allowedOracleComposeHashes[composeHash]                 |
| pendingOracleComposeHashes[composeHash] -> activatesAt  |
| allowedDeviceIds[deviceId]                              |
| consumerManagers[address]                               |
| allowedConsumerComposeHashes[consumerApp][composeHash]  |
+---------------------------------------------------------+
```

Control flow:

```
owner deploys auth contract
        |
        v
optional initial oracle compose hash is allowed
        |
        v
owner proposes new compose hash
        |
        v
upgrade delay passes
        |
        v
anyone activates pending hash
        |
        v
dstack KMS / boot check calls isAppAllowed(bootInfo)
        |
        |-- appId must equal contract address
        |-- composeHash must be allowed
        |-- deviceId must be allowed unless allowAnyDevice
        v
oracle boot allowed or denied
```

Consumer-management flow:

```
owner
  |
  | setConsumerManager(manager, true)
  v
manager
  |
  | addConsumerComposeHash(consumerApp, composeHash)
  v
consumer app may be recognized by off-chain/oracle policy
```

Freeze flow:

```
freezeOracleCodeAuth()
        |
        v
oracle compose/device policy can no longer mutate

freezeConsumerRegistry()
        |
        v
consumer compose-hash registry can no longer mutate
```

Security intent:

```
oracle policy is controlled by owner
consumer registry can be delegated
manager cannot change oracle boot policy
freezing separates production oracle code from development consumer onboarding
```

Current caveat:

```
The contract exists and is tested. The FastAPI /pin and /inbox paths now have
[real] runtime bearer enforcement for same-CVM deployments: the oracle and
delegate derive the same secret from the dstack key path
oracle/runtime-auth, and local dev can use ORACLE_RUNTIME_AUTH_TOKEN /
TINKER_ORACLE_AUTH_TOKEN. The routes also have [real] optional on-chain
EmailOracleAuth consumer-registry enforcement: when ORACLE_AUTH_REQUIRED=true
or a contract is configured, /pin and /inbox fail closed before IMAP access
unless isConsumerAuthorized(consumerApp, composeHash) returns true. Live
compose-hash registration on Base Sepolia is still [partial]/[planned] until
the final oracle and consumer compose hashes are registered.
```

### DiligenceRoom.sol

Deal state machine:

```
          createDeal()
        +------------+
        |  Created   |
        +-----+------+
              |
              | fundDeal() with msg.value = budgetCap
              v
        +------------+
        |   Funded   |
        +-----+------+
              |
              | submitResult() by teeIdentity
              v
        +------------+
        | Evaluated  |
        +--+------+--+
           |      |
 acceptDeal()   rejectDeal()
           |      |
           v      v
    +----------+ +----------+
    | Accepted | | Rejected |
    +----------+ +----------+

 expiry may move Created/Funded/Evaluated -> Expired
 withdrawals happen after settlement through pendingWithdrawals
```

Storage model:

```
+------------------------------------------------+
| Deal                                           |
|------------------------------------------------|
| seller                                         |
| buyer                                          |
| reservePrice                                   |
| budgetCap                                      |
| expiry                                         |
| state                                          |
| artifactHash                                   |
| teeIdentity                                    |
| scoreBand                                      |
| computeCost                                    |
| fee                                            |
| resultHash                                     |
+------------------------------------------------+
```

Settlement flow:

```
acceptDeal(dealPayment)
        |
        | require buyer
        | require dealPayment >= reservePrice
        | require dealPayment + computeCost + fee <= budgetCap
        v
pendingWithdrawals[seller]    += dealPayment
pendingWithdrawals[developer] += computeCost + fee
pendingWithdrawals[buyer]     += refund
        |
        v
each party calls withdraw()
```

Reject flow:

```
rejectDeal()
        |
        | seller gets nothing
        v
pendingWithdrawals[developer] += computeCost + fee
pendingWithdrawals[buyer]     += budgetCap - computeCost - fee
```

Expire flow:

```
expireDeal()
        |
        | if Created: no funds to return
        | if Funded/Evaluated: buyer refund minus any submitted compute cost
        v
state = Expired
```

Security intent:

```
seller cannot force disclosure outside TEE
buyer cannot exceed budget cap
TEE identity is the only result submitter
result details are represented by bounded scoreBand and resultHash
pull payments avoid recipient reverting during settlement
```

Cost reconciliation (pre-settlement integrity check):

```
[real] tinker_delegate.cost_metering.reconcile_costs ties the four cost views
together before a charge settles: the metered estimate (session.CostMeter,
priced from token counts), the on-chain computeCost the buyer is charged, the
buyer budget cap, and an optional Tinker-reported cost. It returns a bounded,
fail-closed CostReconciliation whose status is assigned buyer-harm first:
OVER_BUDGET (chain charge > budget) > CHAIN_EXCEEDS_ESTIMATE (delegate submits
more than it metered — overcharge protection; a charge below estimate is fine) >
REPORTED_MISMATCH (Tinker's reported cost diverges beyond tolerance_bps) >
RECONCILED. Only RECONCILED is settlement_safe, budget_remaining is floored at
zero, and to_public_dict() bands every wei amount (passes assert_bounded_egress).
[real] ControlPlane.evaluate() calls it before a result can settle: it checks the
developer charge (compute + fee) against the budget headroom left after the seller
offer (mirroring the on-chain offer + computeCost + fee <= budgetCap constraint)
and, when not settlement_safe, fails closed — recommendation flips to reject and
the bounded evaluation_completed run-metadata event records settlement_safe and
reconciliation_status. An over-budget deal is refused in the TEE instead of
reverting on chain. The OVER_BUDGET boundary is strict (`charge > cap`) and now
pinned by a test to match the contract's strict `>` exactly — a charge equal to
the cap is in-budget on both sides — so the off-chain gate and on-chain rule
cannot silently diverge (a divergence would revert valid settlements on chain or
bless over-budget ones off chain). `reconcile_costs` documents its calling
contract: `chain_compute_cost_wei` is the total charge (compute + fee already
included), and `fee_wei` is surfaced as a band but never re-added to the budget
comparison.
[partial] reported_cost_wei stays None until a deployed Tinker SDK path returns
real billing, so today it reconciles the estimate against chain/budget only.
[real] tinker_delegate.spend_budget.SpendLedger is a pure, fail-closed multi-cap
budget enforcer: a proposed spend is authorized only if it fits under EVERY active
cap — buyer / room / operator (cumulative spend-to-date) and daily (per
caller-supplied day bucket, no wall clock). The tightest cap binds (strict
intersection); a rejected charge mutates nothing (no budget consumed on deny); the
boundary is strict (spend > cap denies, exactly-on-cap allowed, matching the
on-chain rule). Output is bounded — allowed, binding cap, reason, and coarse
remaining bands per cap (no raw wei). This is the complement to reconcile_costs:
reconcile checks ONE charge against a single deal budget; SpendLedger enforces
CUMULATIVE spend across charges against multiple standing caps
(tests/test_spend_budget.py, 12).
[partial] SpendLedger is not yet wired into a live Tinker spend path (blocked with
the Tinker account) and is in-memory (a production ledger persists under sealed
delegate storage so caps survive restart).
[real] tinker_delegate.topup_policy.decide_topup is the fail-closed auto-reload
counterpart: given a current balance and a bounded TopUpPolicy (min-balance,
target-balance, max-top-up, auto_reload_enabled default OFF, emergency_disabled
kill switch), it decides whether/how much to reload (full topup_authorized or
partial_topup when the cap binds). A produced top-up is itself a SPEND, so the
caller gates the amount through SpendLedger.authorize before charging — caps still
bind (proven by composition tests). Bounded output bands every amount.
[partial] topup_policy is not yet wired into the live billing/top-up path (blocked
with the Tinker account) and balance state is caller-supplied (production persists
it under sealed storage).
[real] tinker_delegate.funding_failure.classify_funding_failure completes the
funding-control triad: it maps a funding failure (card declined, 3DS, bot check,
rate limit, insufficient funds, billing outage, partial top-up, unknown) to a
bounded fail-closed disposition — transient kinds retry with backoff until a max
attempt count then escalate; card/funds failures escalate AND disable auto-reload;
3DS escalates (interactive auth, never auto-completed); bot checks abort + disable
(never auto-solved, per the CAPTCHA/bot-detection invariant); unknown fails closed
to abort. The `disable_auto_reload` flag flips topup_policy's emergency kill switch
(failure -> kill-switch -> no-more-charges, proven by a composition test). So the
three funding primitives compose: SpendLedger enforces caps, decide_topup decides
reloads, classify_funding_failure reacts to failures — all fail-closed, all
bounded, none yet wired to a live billing path (Tinker-account-blocked).
```

Current caveat:

```
submitResult() no longer trusts only a bare teeIdentity address in the current
contract source. The delegate has partial TEE-held signing plumbing: in dstack
mode it derives an Ethereum key from a dstack key path, preflights
`deals(dealId)` so the signer must match the public teeIdentity, checks funded
state and compute budget, commits the payload result hash to chain ID, contract
address, deal ID, signer nonce, compose hash, score band, compute cost, and
expiry, verifies signer quote evidence whose report data binds the signer
address to the chain ID and contract address, signs the transaction in memory,
and returns bounded receipt metadata. `DiligenceRoom.sol` requires a
result-verifier signature over the same bounded submission context plus
authorization expiry before accepting the call. The result-verifier module now
applies approved compose/app policy, optional OS image policy, revoked
quote/signer lists, distinct verifier/TEE keys, and short authorization TTLs
before signing that digest. The `authorize-result` CLI exposes this as a bounded
operator path, and a local Phala/dstack simulator proof deploys the contract
with the dstack-derived verifier address, gets authorization through that CLI,
broadcasts `submitResult()` to ephemeral Anvil, and verifies
`EvaluationSubmitted` carries the replay-bound commitment rather than the raw
payload hash. The remaining production gap is deployed service integration and
deeper quote verification: full Intel TDX quote parsing/freshness is still
incomplete, and the deployed Phala CVM-origin broadcast path still needs live
validation.
```

## Service Architecture

### cdp-playground

Purpose:

```
generic browser automation sandbox for Neko Chrome + Playwright/CDP
```

Why it exists:

```
the email oracle, Tinker delegate, and WhatsApp delegate all need a browser
inside or adjacent to the TEE; cdp-playground is the minimal reusable probe
for discovering selectors, frames, auth redirects, bot checks, and UI flows.
```

Flow:

```
operator / test agent
        |
        v
cdp-playground API
        |
        v
Neko Chrome over CDP
        |
        v
target website / screenshot / DOM extraction
```

### tee-email-oracle

Purpose:

```
hold an email account inside a TEE and provide bounded OTP extraction
```

Endpoints:

```
GET  /health
POST /pin        runtime bearer required when auth is enabled
GET  /inbox      runtime bearer required when auth is enabled
GET  /attestation?context=attestation|oracle-credentials|pin
POST /credentials/encrypted
     disabled by default; explicit provisioning bearer required
```

Flow:

```
startup
  |
  | load encrypted credentials or wait for genesis
  v
CredentialStore
  |
  | local AES key or dstack-derived key
  v
IMAPClient connects
  |
  v
/pin and /inbox require the same-CVM runtime bearer token
  |
  v
if configured, /pin and /inbox read EmailOracleAuth.isConsumerAuthorized
before mailbox access
  |
  v
/pin request must include target service, expected sender, subject scope,
caller identity, nonce, reason, max age, and bounded extraction regex
  |
  v
PinResponse with OTP, oracle email, sender, subject, request hash,
one-time OTP-use hash, timestamp, optional quote over hashes
  |
  v
Encrypted OTP replay ledger persists released OTP-use hashes across restarts
```

Encrypted mailbox provisioning:

```
operator client
  |
  | fetch /attestation?context=oracle-credentials
  | verify mode, compose hash, app id, OS image hash, report_data/key binding
  v
encrypt username/domain/password to attested X25519 key
  |
  | POST /credentials/encrypted with provisioning bearer
  v
oracle decrypts inside CVM -> sealed CredentialStore -> hash/status response
```

The provisioning endpoint is active only when
`ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT=true` and
`ORACLE_CREDENTIAL_PROVISIONING_TOKEN` is set in the runtime environment. The
credential-ingress attestation context intentionally omits the raw oracle email,
and the response returns credential hashes, IMAP connectivity status,
`raw_secret_egress=false`, and an optional TDX quote hash.

### tinker-delegate

Purpose:

```
create and use a Tinker account from inside a TEE, then expose only scoped,
metered, bounded evaluation behavior
```

Endpoints:

```
GET  /health
GET  /attestation?context=ingress|artifact|billing
POST /auth/reauth opt-in bounded OTP re-auth; disabled by default
GET  /billing/balance
GET  /billing/funding-policy bounded funding-mode policy
GET  /billing/funding-preflight bounded operator funding readiness checks
GET  /billing/funding-receipts bounded funding attempt audit records
POST /billing/card            local-dev plaintext hook, disabled by default
POST /billing/card/encrypted  production encrypted card channel
POST /billing/add-balance
POST /tinker/smoke            opt-in bounded real SDK smoke; disabled by default
POST /deal/chain-event        bounded chain-event audit marker
POST /deal/notify-funded
POST /deal/{deal_id}/artifact/encrypted
POST /deal/{deal_id}/artifact local-dev plaintext hook, disabled by default
POST /deal/{deal_id}/evaluate
GET  /deal/{deal_id}/result
POST /deal/{deal_id}/resolve
GET  /deals
```

Control flow:

```
serve startup
  |
  | if TINKER_API_KEY exists, use it
  | else if encrypted API key exists, decrypt it
  | else if bootstrap enabled, run signup automation
  |   and persist captured key before returning bounded metadata,
  |   or preserve bounded selector/failure receipt in runtime state
  | else run with control plane unavailable
  v
FastAPI app
```

Deal flow:

```
watch-chain CLI
  |
  | JSON-RPC eth_getLogs over DiligenceRoom lifecycle events
  v
ChainCursorStore persists next block + public DealCreated context
  |
  | only scan blocks older than configured confirmations
  v
/deal/chain-event records bounded audit metadata
  |
  | DealFunded with matching DealCreated context
  v
/deal/notify-funded
  |
  v
ControlPlane creates DealContext + IsolatedTinkerSession
  |
  v
/deal/{id}/artifact/encrypted decrypts, verifies artifactHash, then stores bytes in memory
  |
  v
/deal/{id}/evaluate runs evaluator_fn
  |
  v
raw metrics -> bound_output() -> compute_offer()
  |
  v
EvaluationResult returned through bounded response
```

### props-room

Purpose:

```
bridge source-controller approvals, NDAI deals, sealed raw acquisition jobs,
and downstream training/inference permissions
```

Flow:

```
controller registers private source
        |
        v
sponsor opens access deal
        |
        v
controller approves raw scrape scope
        |
        v
TEE job runs raw scrape / tv adapter
        |
        v
outputs sealed in asset store
        |
        v
future cleaning, training, and inference approvals
```

Current status:

```
[partial] FastAPI/control-plane/sealed-store stubs exist.
[planned] real wallet auth, attestation verification, Tinker integration, and
          props-room wiring into the partial tinker-delegate chain watcher.
```

### whatsapp-delegate

Purpose:

```
attested account delegation for WhatsApp Web, with sealed message export and
bounded pipeline queries
```

Flow:

```
owner starts login
        |
        v
Neko Chrome opens WhatsApp Web
        |
        v
owner links device from phone
        |
        v
delegate exports message history
        |
        v
messages sealed in TEE store
        |
        v
owner approves pipeline digest
        |
        v
pipeline query returns bounded output only
```

This service is not the core Tinker/NDAI path, but it demonstrates the same
pattern: browser-mediated account delegation, sealed private data, owner
approval, bounded output.

## TEE Deployment Model

The intended production substrate is Phala Cloud dstack CVMs:

```
Docker image digest
        |
        v
docker-compose file
        |
        v
compose hash
        |
        v
dstack CVM boot
        |
        v
TDX quote
        |
        v
verifier checks quote, app id, compose hash, and runtime measurements
```

Runtime service layout for the Tinker path:

```
+---------------------------------------------------------------+
| dstack CVM                                                    |
|                                                               |
|  service: neko                                                |
|    - headful browser / Chrome CDP                             |
|    - core dumps disabled by compose ulimits                   |
|                                                               |
|  service: oracle                                              |
|    - tee-email-oracle                                         |
|    - IMAP credentials sealed at /data                         |
|    - dstack socket mounted                                    |
|    - core dumps disabled by compose ulimits                   |
|                                                               |
|  service: delegate                                            |
|    - tinker-delegate                                          |
|    - Tinker API key sealed at /data                           |
|    - funding receipts + bounded run metadata sealed at /data  |
|    - dstack socket mounted                                    |
|    - RLIMIT_CORE=0 plus compose core ulimit                   |
|                                                               |
|  volumes: oracle-data, delegate-data                          |
+---------------------------------------------------------------+
```

Deployment artifacts:

```
docker-compose.yaml              local delegate
docker-compose.dstack.yaml       dstack overlay
docker-compose.all.yaml          local all-in-one oracle + browser + delegate
docker-compose.all.dstack.yaml   all-in-one dstack overlay
docker-compose.all.phala.yaml    registry-image Phala deployment
scripts/redeploy-phala-cvm.mjs   update compose/env for existing Phala CVM;
                                  defaults to compose-referenced env keys
```

## Security Boundaries

### What Must Never Leave the TEE

```
raw seller artifact
raw corpus / source data
email password
Tinker session cookies
Tinker API key
payment card number / CVC
raw TTT/RL training data
model checkpoints / weights
unbounded samples
unredacted WhatsApp messages
```

### What May Leave

```
artifact hash
compose hash
TDX quote
score band
yes/no verdict
offer within budget cap
confidence band
methodology summary without raw data
compute cost and fee
result hash
withdrawal events
bounded aggregate results
```

### Current Gaps

```
1. On-chain TDX quote verification is not implemented.
2. EmailOracleAuth's on-chain consumer registry is not yet checked by the
   FastAPI OTP endpoint; same-CVM bearer auth and scoped runtime OTP requests
   are implemented.
3. Tinker browser automation works locally and on the deployed Phala path
   through the custom GitHub-attested Neko/CDP image. Deployed bootstrap now
   seals the Tinker API key and deployed `/auth/reauth` succeeds, with bounded
   receipts and no raw secret egress.
4. Low-value Tinker account funding through Stripe browser automation is real
   for the one-off operator-validation lane: the test-card path reaches Stripe
   and declines as expected, the plaintext card API is disabled by default,
   `manual_prefund` is the default production funding mode, the capped
   validation profile is live, the `$10` compose/amount policy was approved
   on-chain, and bounded balance read-back reports `$10.00`. Production still
   requires non-dev OS, debug-surface removal, compliance approval, and
   quote-internal verification.
5. Real TTT/RL bio-validation is not implemented.
6. DLP/egress enforcement is not implemented.
7. Corpus policy and consent/revocation are modeled but not enforced.
8. Chain watcher wiring is locally implemented: JSON-RPC decoding, API dispatch,
   bounded chain-event audit metadata, CLI entrypoint, durable cursor storage,
   confirmation-safe polling, restart recovery, and local Anvil proof exist.
   Production deployment, chain-lag alerting, and deep-reorg rollback beyond
   confirmation depth remain open.
9. Per-query royalty settlement is not wired to a live chain watcher.
10. The production frontend is not present on this branch.
11. Current-operator Base Sepolia contracts are deployed, but source
    verification and compose-hash/consumer registration are still pending.
```

## Public / Web Client Layer

The current `tinker-deligate` branch does not contain a React/Vite/Cloudflare
Pages app. The architecture expects a web client with these responsibilities:

```
seller/data-owner UI
  - create room
  - upload or register artifact
  - set reserve price
  - inspect attestation / compose hash

buyer/sponsor UI
  - fund deal
  - set budget cap
  - submit access/evaluation request
  - accept/reject bounded result

reviewer UI
  - inspect held request
  - confirm release/deny via attested email channel

verification UI
  - display contract address
  - display docker digest / compose hash
  - display TDX quote
  - display result hash
```

The web client should not hold Tinker, OpenRouter, Phala, or card secrets.
Server-side functions or TEE services should own those secret-bearing calls.

## Example End-to-End Scenario

```
Actors:
  Seller: Bio data owner
  Buyer: Sponsor with model-validation budget
  TEE:    dstack CVM running email oracle + Tinker delegate
  Chain:  Base Sepolia DiligenceRoom

Flow:

1. TEE boots and exposes attestation.
2. Email oracle creates/loads sealed email credentials.
3. Tinker delegate signs into Tinker using email OTP from oracle.
4. Tinker API key is sealed inside the delegate.
5. Seller creates DiligenceRoom deal with artifactHash and teeIdentity.
6. Buyer funds deal with budget cap.
7. Control-plane lifecycle metadata is sealed as bounded event records.
8. Seller uploads private bio artifact to TEE.
9. Gate checks purpose and dual-use risk.
10. Tinker delegate starts an isolated evaluation session.
11. Target future evaluator runs TTT/RL bio-validation.
12. Control plane converts raw metric to score band.
13. TEE submits replay-bound resultHash commitment, scoreBand, and computeCost.
14. Buyer accepts or rejects.
15. Contract accrues seller payment, developer compute+fee, and buyer refund.
16. Parties withdraw.
17. TEE cleans up artifact and Tinker checkpoints.
```

ASCII sequence:

```
Seller          Buyer          Email TEE        Tinker TEE        Chain
  |              |                |                 |               |
  | create deal  |                |                 |-------------->|
  | artifactHash |                |                 |               |
  |              | fund budget    |                 |-------------->|
  |              |                |                 |               |
  | upload artifact ------------->|?                |               |
  | upload artifact ------------------------------->|               |
  |              |                |                 |               |
  |              |                | OTP request     |               |
  |              |                |<----------------|               |
  |              |                | OTP response    |               |
  |              |                |---------------->|               |
  |              |                |                 | Tinker login  |
  |              |                |                 | eval session  |
  |              |                |                 | bounded score |
  |              |                |                 |-------------->|
  |              | accept/reject  |                 |               |
  |              |----------------------------------------------->|
  | withdraw     | withdraw       |                 |               |
  |<--------------------------------------------------------------|
```

## How the Requested Chain Fits

The requested phrase:

```
Email encumbered contract <--> tinker encumbered contract <--> TTT RL Bio validation
                                                                       |
                                                                    DNAI
```

maps to the repo like this:

```
+-----------------------------+
| Email encumbered contract   |
|-----------------------------|
| EmailOracleAuth.sol         |
| tee-email-oracle            |
| OTP and human confirmation  |
+--------------+--------------+
               |
               | magic-code auth / reviewer confirmation
               v
+-----------------------------+
| Tinker encumbered contract  |
|-----------------------------|
| DiligenceRoom.sol           |
| tinker-delegate             |
| IsolatedTinkerSession       |
| billing/card channel        |
+--------------+--------------+
               |
               | scoped compute authority
               v
+-----------------------------+
| TTT/RL Bio validation       |
|-----------------------------|
| target evaluator            |
| current stub/SFT evaluator  |
| bounded bio-risk outputs    |
+--------------+--------------+
               |
               | bounded result, offer, result hash
               v
+-----------------------------+
| DNAI                        |
|-----------------------------|
| NDAI diligence room         |
| reserve + budget cap        |
| disclosure boundary         |
| settlement                  |
+-----------------------------+
```

The important design point is that these are not four unrelated modules. They
are four boundaries on the same transaction:

```
email boundary       proves/coordinates human or delegated identity
tinker boundary      controls paid compute and model access
bio-validation       performs the sensitive evaluation
DNAI boundary        decides what can be disclosed and how payment settles
```

Current project truth:

```
email boundary       real service + contract, but API enforcement is still incomplete
tinker boundary      auth/API-key sealing, low-value funding, and smoke surface are real; deployed training is blocked at ServiceClient creation with project id omitted
bio-validation       target TTT/RL loop is not built; current evaluator is stub/SFT-oriented
DNAI boundary        escrow/result-bounding primitives exist, full live path needs the above
```

## Build and Verification Surfaces

Focused validation currently available:

```
contracts:
  cd "⚙️/tinker-delegate/contracts"
  forge test

tinker-delegate Python:
  cd "⚙️/tinker-delegate"
  uv run python -m compileall tinker_delegate
  uv run python -c 'import tinker_delegate.api as api; print(api.app.title)'

tee-email-oracle Python:
  cd "⚙️/tee-email-oracle"
  uv run python -m compileall email_oracle
  uv run python -c 'import email_oracle.api as api; print(api.app.title)'

props-room Python:
  cd "⚙️/props-room"
  uv run python -m compileall props_room
```

External verification:

```
cast chain-id --rpc-url https://sepolia.base.org
cast code <contract-address> --rpc-url https://sepolia.base.org
phala status
wrangler whoami
```

## Roadmap to a Production-Complete Architecture

```
1. Enforce EmailOracleAuth on OTP consumers.
2. Add the production verifier service that validates live TDX quote evidence
   before issuing result-authorization signatures.
3. Prove deployed-CVM-originated verifier-authorized `submitResult()` broadcast
   and replace local-simulator evidence with live measured-code evidence.
4. Stabilize Tinker browser posture or use an official non-browser account API.
5. Implement the TTT/RL bio-validation evaluator and benchmark schema.
6. Add fail-closed DLP/egress enforcement.
7. Implement corpus policy, consent, revocation, and human-review queue.
8. Wire chain watcher to tinker-delegate control plane.
9. Build/merge the production web client and Cloudflare Pages deployment.
10. Add reproducible image builds and compose-hash release gates.
11. Add transparency log for accepted, rejected, held, denied, and expired runs.
```

## Architecture Invariants

These invariants should hold as the project grows:

```
No raw artifact leaves the TEE.
No Tinker API key leaves the TEE.
No card details are logged or persisted by repo services.
Error and automation logs are passed through service-local redaction helpers
before they become API responses or operator-visible diagnostics.
No result is accepted as "attested" without a quote and compose-hash story.
Every evaluator output is bounded before public release.
Buyer spend is capped by the contract budget cap.
Seller payment cannot be below reserve on accept.
Delegated authority cannot exceed the grantor's authority.
Human-review holds fail closed until released by a separate reviewer.
All settlement uses pull payments.
All deploy secrets live in environment, Phala encrypted env, or TEE-sealed storage.
```
