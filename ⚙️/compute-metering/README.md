# Independent Compute Metering

This service is the independent metering-CVM half of the exact-asset Compute
runtime. It authenticates a bounded execution-TEE usage envelope, verifies the
complete `ComputeCreditVault` release state at one explicit Base Sepolia block,
selects an exact asset/rate card from one immutable canonical policy set,
recomputes the debit with checked integer arithmetic, compares its locally
computed EIP-712 v2 digest with the contract, and raw-signs that digest from a
policy-derived dstack key. For each decision it also obtains a fresh
challenge-bound TDX quote and asks the separately controlled compute-metering
QVL in the intended topology to raw-sign the distinct QVL receipt typehash over
the same exact fields. The vault requires both signatures. Neither service has
been deployed for the fresh project-owned release.

The claim is **attested deterministic metering**, **not a provider-authoritative invoice**.
No provider API or signed provider usage record is accepted by this release.

## Status and trust labels

- **Implemented and locally testable:** strict schemas, the canonical native
  ETH plus Base Sepolia USDC policy set and per-asset rate-card commitments, EIP-191
  execution-envelope authentication, EIP-1898
  pinned chain reads, runtime bytecode/state validation, exact debit
  recomputation, EIP-712 digest parity, distinct low-s raw metering and QVL
  signatures, a ten-minute maximum receipt lifetime, bounded HTTP,
  durable integrity-protected replay storage, and a bearer-authenticated
  production identity-attestation endpoint that obtains an authenticated,
  one-time compute-profile QVL challenge before collecting a real dstack quote.
  The quote binds the signer, Base Sepolia vault, policy-set hash, custody mode,
  and exact challenge digest; the public endpoint returns the QVL's bounded
  signed v4 verdict rather than the raw quote. DCAP appraisal must finish
  strictly before the single-use, at-most-120-second challenge expires. The
  reviewed release's separately policy-bounded activation-evidence lease is
  exactly 900 seconds, may outlive the consumed challenge, and never renews
  challenge freshness.
- **Deployment-ready, not live evidence:** the Phala compose is a reviewed
  production shape, but this directory has not been deployed and contains no
  Intel TDX quote or live Base Sepolia release roots.
- **Roadmap:** provider-authoritative signed usage, externally anchored
  anti-rollback state, multi-RPC quorum, and card-funding adapters.

Do not label a signature from a local test, documented dstack simulator, or
unverified CVM as TDX-attested. Production rejects the supported SDKs'
documented `DSTACK_SIMULATOR_ENDPOINT` and `TAPPD_SIMULATOR_ENDPOINT`
variables, and the checked-in policy is illustrative only. Those environment
checks alone are not TDX evidence; the claim requires independent DCAP
verification of a fresh challenge-bound quote.

## Boundary

```text
execution CVM
  bounded counters + commitments only
  EIP-191 signature from the registered execution teeIdentity
          |
          v
independent metering CVM
  one canonical immutable policy set + one pinned Base Sepolia state snapshot
  checked integer debit + local/on-chain usage/digest equality
  raw ComputeMeteringReceipt EIP-712 signature from a dstack-derived key
          |
          +--> fresh purpose-bound TDX quote --> independent compute-metering QVL
          |                                      verifies quote/evidence and raw-signs
          |                                      the distinct ComputeMeteringQvlReceipt
          |
          v
ComputeCreditVault.submitMeteringReceipt(..., meterSignature, qvlSignature)
```

The request cannot contain a prompt, dataset, example, output, provider
credential, provider account identifier, payment data, caller-supplied debit,
or caller-supplied receipt expiry. Unknown fields are rejected.

## Canonical usage envelope

The execution CVM creates `dnai.compute-usage-envelope.v2`. Every uint256 on
the wire is a canonical decimal string (`"0"` or a non-zero digit followed by
digits) so browser runtimes cannot silently round it. Addresses and bytes32
values are lowercase hexadecimal.

The `usage_commitment` is:

```text
sha256(
  "dnai-wikigen/compute-usage/v1\0" ||
  canonical_json(envelope without usage_commitment and tee_signature)
)
```

Canonical JSON is UTF-8, ASCII-escaped, key-sorted, and compact. The execution
TEE signs those 32 bytes as an EIP-191 personal message. The service requires a
65-byte, low-s, `v` 27/28 signature and recovers the exact `tee_identity`
pinned by policy and chain state. A successful envelope must contain non-zero
usage. A failed envelope may contain zero counters and therefore settle zero,
but its non-zero commitment remains replay protected.

The outer request adds an explicit canonical block:

```json
{
  "schema": "dnai.compute-metering-request.v2",
  "block": {
    "number": 44000000,
    "hash": "0x...64 lowercase hex characters..."
  },
  "usage": {
    "schema": "dnai.compute-usage-envelope.v2",
    "job_id": "0x...",
    "project_id": "0x...",
    "user": "0x...",
    "asset": "0x...",
    "authorization_nonce": "0",
    "max_asset_debit": "1000000",
    "authorization_expiry": 1800000000,
    "rate_policy_commitment": "0x...",
    "workload_commitment": "0x...",
    "manifest_commitment": "0x...",
    "dispatch_intent_commitment": "0x...",
    "tee_identity": "0x...",
    "compose_hash": "0x...",
    "start_commitment": "0x...",
    "model": "tinker-model-v1",
    "recipe": "inference.v1",
    "outcome": "succeeded",
    "prefill_tokens": "2500",
    "sample_tokens": "500",
    "training_tokens": "0",
    "usage_started_at": 1799999600,
    "usage_observed_at": 1799999700,
    "raw_secret_egress": false,
    "usage_commitment": "0x...",
    "tee_signature": "0x...130 lowercase hex characters..."
  }
}
```

## Exact debit and receipt digest

The complete policy set contains exactly two sorted, unique asset policies. The
supported release assets are native ETH
(`0x0000000000000000000000000000000000000000`) and Circle's canonical Base
Sepolia USDC (`0x036cbd53842c5426634e7929541ec2318f3dcf7e`). Both must appear exactly
once. The complete canonical policy-set hash derives
one metering signer. The policy also pins the distinct compute-metering QVL
signer. Release governance must atomically activate the exact
`(metering signer, metering QVL signer, policy-set hash)` tuple through the
vault's delayed binding, freeze it, and leave no pending replacement. None of
the owner, developer, execution TEE, meter, QVL, or provider roles may collapse.

The service decodes the on-chain job before choosing a rate card. It requires
the job's exact `(asset, ratePolicyCommitment)` to identify one policy-set
entry, then requires the signed envelope to match that same pair. Missing,
duplicate, unlisted, or caller-selected alternatives fail closed. Only one
sorted `(model, recipe)` rate within the selected asset policy can match. The
service enforces that entry's maxima, then computes:

```text
numerator = prefillTokens * prefillUnitsPerMillion
          + sampleTokens  * sampleUnitsPerMillion
          + trainingTokens * trainingUnitsPerMillion
debit     = numerator / 1_000_000, rounded up exactly
```

Every multiplication and addition is checked against `uint256`; the ceiling
uses quotient/remainder rather than an overflowing `numerator + 999999`.
The result must be within both the canonical policy maximum and the job's
on-chain exact-asset cap.

Every code/state read uses the EIP-1898 block reference
`{"blockHash": ..., "requireCanonical": true}`. The service checks:

- Base Sepolia chain ID, requested number/hash, confirmation depth, timestamp,
  freshness, and policy validity;
- exact vault runtime `keccak256`, owner, developer, independent metering
  signer, independent metering QVL signer, their distinctness, pause state,
  frozen signer binding, no pending signer replacement, frozen developer fee,
  explicit rate-additions freeze
  state, frozen asset additions, and frozen compose policy;
- exact live registry cardinalities: one allowed ERC20 asset, two active rate
  policies, one approved compose hash, and one registered execution TEE; all
  asset, rate-policy, and compose pending counters must be zero, so active,
  historical TEE, and not-yet-activated surplus admissions fail closed even
  when the required entries are present;
- approved compose hash, execution TEE-to-compose binding, active exact
  asset/provider/fee rate policy, and ERC20 allowlisting when the asset is not
  native ETH;
- the complete 21-field `Started` job tuple, including the signed workload,
  manifest, and dispatch-intent commitments; on-chain-derived start timestamp
  and start commitment; and zero prior debit, billable units, evidence hash,
  receipt expiry, usage end, and usage commitment.

The service derives the contract's usage commitment from the complete on-chain
job plus the computed debit, billable units, exact start/end timestamps,
policy-set hash, and fresh quote-evidence hash; the execution envelope's SHA-256
commitment cannot be substituted into that field. It calls
`usageCommitmentFor`, `meteringReceiptDigest`, and
`meteringQvlReceiptDigest` at the same pinned block and requires all three local
derivations to match. Both receipt digests use the exact EIP-712 domain
(`DNAI Compute Credit Vault`, version `2`, chain ID, vault) and the same fields,
but distinct `ComputeMeteringReceipt` and `ComputeMeteringQvlReceipt`
typehashes. The metering key signs the first digest **raw**—no EIP-191 prefix.
The QVL verifies the fresh challenge-bound TDX quote and evidence hash, enforces
the same ten-minute expiry ceiling, and raw-signs the second digest. Both
signatures must be canonical low-s 65-byte signatures and the two signer
addresses must remain distinct.

## Replay and persistence

The service authenticates the execution signature before consulting replay
state. An identical semantic request returns the exact canonical response bytes
previously stored, even after the job has settled. Reusing the job,
usage commitment, or semantic request hash with different context is rejected.

SQLite runs in WAL mode with `synchronous=FULL`. The service writes the
decision before responding. Policy-set identity, each row, and a contiguous row
hash chain are HMAC-authenticated by a separate dstack-derived key. Startup
runs SQLite integrity checks and validates the complete authenticated chain.
The persistent volume is prepared for UID/GID 65532 and mounted only into the
metering CVM.

This detects modification, deletion, reordering, and cross-policy volume use.
It cannot detect restoration of an entire older, internally valid disk
snapshot. Production anti-rollback stronger than the CVM disk guarantee needs
a future external monotonic anchor or on-chain checkpoint.

## HTTP surface

- `GET /health` — bounded process liveness only.
- `GET /identity` — public `policy_set_hash`, sorted
  `assets: [{asset, provider, rate_policy_commitment}]` descriptors, the derived
  metering address, and the policy-pinned metering-QVL address; this is not
  itself a TDX attestation.
- `GET /attestation` — bearer-authenticated, production-only challenge-first
  attestation. The service authenticates a signed
  `dnai.attestation-qvl-challenge.v2` for the exact
  `independent_metering_cvm` release lineage from the pinned QVL signer and
  release-policy hash, passes exactly 64 report-
  data bytes to dstack, submits the raw quote only over authenticated QVL
  transport, authenticates the returned `dnai.independent-tdx-verdict.v4`
  against the same challenge and exact packet, and returns that bounded verdict.
  Production constructs this route with a real dstack attestor and QVL client
  and has no disable flag; internal test runtimes without either return
  `not_enabled`.
- `POST /meter` — bearer-authenticated metering request.

The service disables OpenAPI/docs, access logs, proxy headers, and server
headers. It enforces JSON content type, no content encoding, a 24 KiB body cap,
strict duplicate-free JSON, fixed public errors, a global token bucket, and a
fail-fast concurrency cap. Responses contain commitments and settlement data
only. Runtime code has no logging sink for request bodies, RPC URLs, workload
metadata, or credentials.

The attestation quote's first 32 report-data bytes are:

```text
sha256(
  "dnai-wikigen/compute-metering-signer-attestation/v1\0" ||
  canonical_json({
    schema: "dnai.compute-metering-signer-attestation.v1",
    chain_id: 84532,
    vault_address,
    metering_verifier,
    policy_set_hash,
    signer_custody: "dstack_derived_independent_cvm"
  })
)
```

Canonical JSON is ASCII, key-sorted, and compact; addresses and the hash are
lowercase. Quote report-data bytes 32–63 must equal the authenticated QVL
challenge digest. The service checks both halves locally, but local quote
parsing proves only that the quote contains the requested binding. The
separate QVL instance using
`release-policy.compute-metering.example.json` must atomically reserve the
same challenge and validate DCAP collateral, exact measurements,
compose/app/OS roots, and the exact `OK` TCB status. The raw quote exists only
in memory between dstack collection and that authenticated QVL request and is
not returned by the metering HTTP service.

## Policy preparation

Copy `policy-set.example.json`, replace every illustrative root with reviewed
release data, keep `asset_policies` sorted by
`(asset, rate_policy_commitment)`, and keep each rate matrix sorted by
`(model, recipe)`. The intended release contains both native ETH and canonical
Base Sepolia USDC. For each asset entry, compute its
`rate_policy_commitment` as:

```text
keccak256(
  "dnai-wikigen/compute-rate-card/v1\0" ||
  canonical_json({
    schema: "dnai.compute-rate-card.v1",
    asset, developer_fee_bps, provider, rates, limits
  })
)
```

Loading fails unless every entry matches and the exact two-entry native
ETH/canonical-USDC set is unique. The policy-set schema is exactly
`dnai.compute-metering-policy-set.v1`. The SHA-256 of the complete canonical
set is `policy_set_hash` and controls both dstack derivation paths. Therefore
any policy-set change rotates both metering and replay keys. Because the vault's
metering binding is frozen for a production release, a changed complete policy
requires an explicitly coordinated new release/vault root; it must never be
silently substituted.

`developer_fee_frozen`, `rate_policy_additions_frozen`,
`asset_additions_frozen`, and `compose_policy_frozen` are literal `true` in the
schema. The policy also fixes `allowed_asset_count` to 1,
`active_rate_policy_count` to 2, `approved_compose_count` to 1,
`approved_tee_identity_count` to 1, and every pending admission counter to 0;
every value is checked at the pinned block. A freshly deployed vault starts with empty registries and unfrozen
asset/rate additions; it is not release-ready. Governance must admit both
reviewed asset/rate entries and the compose/TEE root, then irreversibly freeze
the required registries before production authorization is enabled.

The policy contains only a public HTTPS RPC origin. `METERING_RPC_URL` may hold
a provider path/query credential in Phala's encrypted environment, but its TLS
origin must exactly match the reviewed policy and it is never returned or
logged.

## Local verification

Use `uv`, never pip:

```sh
uv sync --frozen
uv run --frozen python -m pytest
uv lock --check
# Export the required digest, policy, RPC, and auth values from a local
# untracked environment before rendering the production compose.
docker compose -f docker-compose.production.yml config -q
IMAGE_TAG=dnai-compute-metering:local scripts/build-reproducible.sh
```

Production signing deliberately cannot run against the local simulator. Unit
and integration tests inject local test signers, replay keys, and a deterministic
JSON-RPC backend; they do not constitute TDX evidence.

## Phala release procedure

1. Build twice with the same `SOURCE_DATE_EPOCH`; require identical image IDs.
2. Publish by digest and set `METERING_IMAGE_REPOSITORY` plus
   `METERING_IMAGE_DIGEST`; never deploy a mutable tag.
3. Precompute the exact vault address before deployment (for example with a
   reviewed deterministic CREATE2 deployment, or an explicitly reserved
   deployer nonce). The policy set includes the vault address, so this
   counterfactual address step is mandatory and must be proven in the
   deployment rehearsal.
4. Deploy and independently activate the compute-profile QVL first. Record its
   exact HTTPS `/verify` URL, strong bearer, verifier address, and canonical
   release-policy hash. Base64-encode the reviewed canonical metering policy
   set into `METERING_POLICY_SET_B64` and pass it with `METERING_RPC_URL`,
   `METERING_AUTH_TOKEN`, `METERING_QVL_URL`,
   `METERING_QVL_AUTH_TOKEN`, `METERING_QVL_VERIFIER_ADDRESS`, and
   `METERING_QVL_RELEASE_POLICY_HASH`, `METERING_CVM_ID`,
   `METERING_DEPLOYMENT_INTENT_SHA256`,
   `METERING_RELEASE_AUTHORITY_SHA256`, `METERING_CEREMONY_NONCE`, and
   `METERING_QVL_MEASUREMENT_POLICY_SHA256` through Phala's encrypted
   environment handling. The last five values come from the signed release
   ceremony; they must never be copied from a QVL response.
5. Deploy `docker-compose.production.yml` as a separate production Phala CVM,
   with no dev OS, no SSH, and no public logs/sysinfo. The one-shot policy
   bootstrap has no network. The one-shot state bootstrap has only `CHOWN`.
6. Read `/identity`, record the exact metering address and independently pinned
   QVL address, and abort unless the two are distinct and the
   deployed vault address/runtime code and every reviewed state root match the
   policy set. Schedule and activate the exact `(metering signer,
   metering QVL signer, policy_set_hash)` binding only after its delay, then
   freeze it and require every related pending field to be empty. Verify both
   asset/rate entries and every other release root with synthetic native and
   USDC jobs, including rejection when either raw receipt signature is absent,
   prefixed, high-s, stale, replayed, or signed for a different workload,
   manifest, or dispatch intent.
7. Call authenticated `/attestation`. Require a lease-valid
   `dnai.independent-tdx-verdict.v4` under signing domain
   `dnai-wikigen/independent-tdx-verdict/v4\0` whose chain, domain, profile,
   CVM ID,
   deployment intent, release authority, ceremony nonce, QVL measurement
   policy, signer/policy/challenge, quote hash, static report-data digest,
   compose/app/OS roots, metering signer, QVL signer, and vault all match the
   reviewed release. Verify that DCAP appraisal completed strictly before the
   single-use challenge's at-most-120-second expiry and that the separately
   reviewed activation-evidence lease is exactly 900 seconds. The lease may
   outlive the consumed challenge and must never be interpreted as renewed
   challenge freshness.
   Bind that verdict together with git SHA, image digest, compose hash, both
   asset/rate commitments, both signer roles, and vault in release evidence
   before calling the feature live.

This project intentionally does not modify or join the shared Tinker compose.
Integration should happen only after this independent service, its CVM
evidence, and its on-chain verifier root have been reviewed.

Primary references: [EIP-191](https://eips.ethereum.org/EIPS/eip-191),
[EIP-712](https://eips.ethereum.org/EIPS/eip-712),
[EIP-1898](https://eips.ethereum.org/EIPS/eip-1898),
[Base network/RPC documentation](https://docs.base.org/base-chain/quickstart/connecting-to-base),
[Circle's canonical USDC addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses),
and [Phala dstack documentation](https://docs.phala.network/phala-cloud/dstack/getting-started/overview).
