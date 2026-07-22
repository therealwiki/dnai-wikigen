# Wikigen product frontend

The SolidJS application for attested diligence rooms, sealed challenge environments, bounded compute, scoped proxy credentials, funding previews, safeguards, verification, and multi-owner collaboration.

The frontend uses three explicit product states:

- **Live** — backed by the currently configured project-owned contract or service and checked at runtime.
- **Modeled** — a real interaction design or deterministic local primitive without a production mutation path.
- **Roadmap** — a proposed capability with no deployed backing service.

A modeled receipt is never presented as Intel TDX evidence. The safeguards simulator uses the literal `modeled-receipt:` marker and `illustrative-only:not-a-tdx-quote` measurement.

## Product surfaces

| Hash route | Surface | Current behavior |
| --- | --- | --- |
| `#/` | Overview | Runtime deployment readiness, trust architecture, and product entry points |
| `#/arena` | Challenge arena | Canonical DNASeq Safe-IR challenge plus modeled Bio/DNA briefs, ciphertext-only ingress, bounded Ladder ranks, and per-row execution provenance |
| `#/deals` | Diligence rooms | Reads and writes the fresh `DiligenceRoom` contract when configured; otherwise renders an explicit modeled preview |
| `#/review` | Release review | Source-modeled bounded-output queue, hold checklist, reviewer threshold, and audit sequence; no real review or signature authority is connected in this release |
| `#/vaults` | Data vaults | Modeled governed datasets, version lineage, consent/usage boundaries, and sealed-data publication workflow |
| `#/compute` | Compute console | Wallet-owned projects and proxy credentials; modeled service-credit jobs remain distinct from release-gated exact-asset sponsor funding, authorization and nonce revocation, bounded dispatch-intent status, independent metering, provider/developer accrual claims, settlement, and proven onchain exits |
| `#/tinker` | Delegated Tinker account | Release-gated customer lifecycle plus a read-only, finalized-block `TinkerAccountEncumbrance` inspector for the runtime pin, account/policy commitments, unitless per-operation caps, authority roots, pending review, and exact operation IDs; no secret, card, account, funding, spend, or contract-mutation intake |
| `#/safeguards` | Safeguards lab | Deterministic, browser-local four-stage policy simulator with modeled receipts |
| `#/capabilities` | Capability catalog | Locality catalog, pipeline registry, execution architecture, and developer path |
| `#/verify` | Trust center | Six-level evidence vocabulary, one-block bytecode presence and optional runtime-code-hash observations, bounded application-envelope checks, local receipt-shape classification, and finalized-block EmailOracleAuth/KMS dynamic-readiness diagnostics; it does not verify Intel collateral, QVL signatures, or release policy, and the Email panel does not validate historical KMS receipts or restart proofs |
| `#/collaborate` | Multi-owner collaboration | Sovereign-gate workflow, local-only bounded brief composer, and a runtime-pinned RoyaltyDistributor panel for owner pull balances, self-withdrawals, and exact replay-slot inspection; allocation and distribution remain unavailable |

The canonical Arena URL is versioned and shareable:
`#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=rankings`. The `tab` value may be
`rankings`, `queue`, `submissions`, or `spec`; malformed or ambiguous deep links fail
closed instead of silently selecting another challenge. Worker presence and
row evidence are separate signals. A fresh authenticated heartbeat can say a
release-bound worker is present, while each ranking or submission remains
`modeled` until that exact row carries bounded worker-reported provenance.
The worker-capability response is exact schema v2: the browser recomputes its
complete release-binding and heartbeat-binding SHA-256 commitments and rejects
schema v1 rather than synthesizing missing fields. Public submission, queue,
leaderboard, and authenticated owner-submission projections are likewise
bounded schema v2.
That provenance is explicitly not independent browser verification of Intel
TDX: raw quotes, signatures, exact scores, and exact timing do not egress.

## Stack

- SolidJS, TypeScript, and Vite. React is not used.
- `viem` for Base Sepolia reads, writes, hashing, and wallet clients.
- EIP-6963 discovery plus an injected EIP-1193 fallback for MetaMask, Coinbase
  Wallet, Rabby, and compatible wallets.
- WalletConnect as a conditional public configuration; the dialog shows a
  truthful unavailable state when the deployment has no project ID.
- X25519, HKDF-SHA256, and AES-256-GCM through Web Crypto for artifact ingress.
- Local Manrope and JetBrains Mono font assets; no remote font dependency.
- Static Cloudflare Pages output; no secret may use a `VITE_` variable.

## Local development

```bash
cd web
npm ci
npm run dev
npm run check
```

The development server defaults to `http://127.0.0.1:5175` when started with `npm run dev -- --host 127.0.0.1`.

## Public deployment configuration

Copy `example.env` to `.env.local` only for public values. Never place a private key, runtime bearer, API key, Stripe secret, Phala key, or upstream Tinker credential in a Vite variable—Vite embeds it in browser assets.

Production live gates must not be edited by hand. The intended fail-closed
workflow is documented in [`RELEASE-MANIFEST.md`](./RELEASE-MANIFEST.md), but
the live release generator is currently sealed: it authenticates the exact
37-input Model-A boundary and then stops before writing
`.env.production.local`. Until that semantic integration is complete, only the
argument-free modeled-preview command below is supported; there is no valid
production Pages command to copy or improvise.

The release topology is exactly seven CVMs: the main private runtime, five
independently controlled QVL CVMs (Diligence, Arena, anchor writer, Compute
workload, and Compute metering), and the independent deterministic Compute
meter. QVL admission uses signed challenge schema v2 and the active independent
verdict schema/signing domain v4. Each challenge is single-use, valid for at
most 120 seconds, and bound in the quote's exact 64-byte report data; Intel DCAP
appraisal must finish strictly before expiry. The v4 verdict then carries the
separately reviewed exact 900-second activation-evidence lease. That lease may
outlive the consumed challenge, but it is not renewed challenge freshness.
Post-restart Compute-workload recipient activation is exact schema v3 with an
explicit recipient-evidence lease of at most 300 seconds; its stable
recipient-release commitment remains v2 and activation v1 is rejected. The
Diligence QVL also serves the Email/KMS restart-evidence profile, which does not
add a sixth trust root or eighth CVM.

The main runtime's final profile update is exactly
`arena-runtime,compute-execution`. The same-process source coordinator carries
reviewed release authority through signed Stage B, encrypted environment patch,
restart, authenticated Phala observation, Arena worker-capability v2
verification, and fresh Compute recipient activation. Neither the Phala
attestation response nor the HMAC heartbeat is independently verified TDX
evidence, completion grants no live-traffic authority, and this fresh release
has not been activated.

The tested resident source driver keeps that authority chain in one process
from one exact owned canonical mode-`0600` request through the non-live launch,
external proof/signature waits, restart, recipient activation, and bounded
output publication. It cannot reload serialized authority or accept signer
keys, never retries automatically, and always reports
`live_traffic_authorized=false`. It has not been run against a fresh
project-owned production topology.

That driver's bounded post-restart activation observation `O` projects exactly
20 public Compute-workload browser variables. Seven mandatory lineage pins are
`VITE_COMPUTE_WORKLOAD_CVM_ID`,
`VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256`,
`VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256`,
`VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256`, and
`VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256`. The release builder and
browser require the full exact 20-key projection from one branded observation;
missing or drifted lineage keeps upload disabled. These values are bounded
public release configuration, not secrets, serialized mutation authority, or
proof of a live activation.

Important gates:

- `VITE_DILIGENCE_ROOM_ADDRESS` and related addresses must name the fresh project-owned suite.
- `VITE_ENABLE_CONTRACT_WRITES` remains `false` until the runtime bytecode hash,
  developer, result verifier, both mandatory approval flags, approved compose
  measurement, and TEE identity binding match the release manifest.
- `VITE_DELEGATE_URL`, `VITE_PHALA_COMPOSE_HASH`, and deployment identity fields must describe the replacement CVM, not the prior operator's CVM.
- There is intentionally no `VITE_ORACLE_URL`: the email oracle has no public
  host port or browser route and is reachable only from the authenticated
  delegate over the CVM's private compose network.
- `VITE_ENABLE_ARTIFACT_UPLOAD` remains `false` until the browser ingress policy, exact CORS origin, fresh CVM, expected measurements, and independent quote-verification path are approved together.
- `VITE_USDC_ADDRESS` must equal Circle's canonical Base Sepolia USDC address;
  it is the only ERC-20 the frontend will create or fund a room with. Arbitrary
  token input and symbol/decimal lookalikes are intentionally unavailable.
- `VITE_COMPUTE_CREDIT_VAULT_ADDRESS` and
  `VITE_COMPUTE_CREDIT_VAULT_CODE_HASH` must pin the exact vault runtime before
  even the raw-funding gate can become actionable. The browser reads every
  readiness fact and wallet balance from one Base Sepolia block.
- `VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION` additionally requires the pinned
  developer and metering roles, frozen fee, frozen and approved compose policy,
  exact TEE binding, and active exact-asset rate-policy commitments. Missing or
  drifting roots block authorization without hiding a separately verified
  withdrawal path.
- The optional Compute-vault ERC20 is all-or-nothing public configuration:
  address, runtime code hash, symbol, decimals, and authorization policy
  commitment must agree with live chain reads. The capacity UI accepts no
  arbitrary token address and never requests an unlimited allowance.
- Exact-asset funding may name any exact EVM beneficiary because the contract
  supports third-party sponsors. The console continues to display only the
  connected wallet's capacity, and never implies that sponsorship grants the
  sponsor authority over the beneficiary's funds or jobs.
- A connected wallet may advance its project nonce to invalidate older,
  unsubmitted job signatures. Provider/developer accrual withdrawal is a
  separate role-neutral pull-payment path: a wallet can claim only its own
  nonzero balance, and the action neither grants a role nor touches customer
  capacity.
- The checked-in CSP enables injected EIP-6963 wallets by default. When a
  WalletConnect project ID is present, the build adds only the exact connect
  and frame origins used by the pinned WalletConnect/Reown packages. Remote
  script, image, and font sources remain blocked; upgrades to those packages
  require reviewing and updating the origin allowlist without wildcards.

Wallet connection alone is not service authentication. Encrypted seller upload uses the delegate's deal-bound flow:

1. `POST /auth/wallet/challenge` with wallet and deal ID.
2. Sign the returned, Base-Sepolia-bound message.
3. `POST /auth/wallet/token` with the one-time nonce and signature.
4. Verify the artifact attestation envelope against the public deployment manifest.
5. Load the seller-held v2 recovery receipt, recompute
   `keccak256("dnai-wikigen/artifact-commitment/v2" || 0x00 || secret32 || raw)`,
   and require it to equal the on-chain commitment.
6. Build the exact v3 constant-size frame (16-byte magic, private uint32 length,
   secret, up to 1 MiB raw bytes, and CSPRNG padding), bind Base Sepolia, the
   fresh room, deal, artifact, and funded evaluator policy in HKDF/AAD, encrypt
   in the browser, and send only the fixed-size ciphertext to
   `/deal/{id}/artifact/encrypted` with the five-minute `artifact:upload` token.
7. Recompute the ciphertext SHA-256 locally and require the delegate's bounded
   acknowledgement to match it. The acknowledgement contains
   `padding_profile=fixed_1m_v3` and `exact_plaintext_size_egress=false`; its
   fixed public ciphertext size is not the private artifact length.

Tokens and recovery receipts are held in memory for the current operation and
are never written to local storage. The user must explicitly download the
recovery receipt before creating a room; the application has no recovery copy.

## Cloudflare Pages

`wrangler.toml` declares `dist` as the Pages output directory and connects this
checkout to the existing `wikigenme` Pages project, whose production domains
are `wikigenme.pages.dev`, `wikigen.me`, and `www.wikigen.me`. Build and deploy
an argument-free modeled release to the explicit `modeled-preview` preview
branch with:

```bash
npm run deploy:cloudflare
```

Production upload is intentionally unavailable in this revision. The release
generator loads the exact 37 authority inputs and then exits with
`Model-A exact-37 semantic validator integration is incomplete` before it can
write a browser environment or invoke Wrangler. The retired eight-artifact
example is not a fallback: options such as `--authority-review-envelope` are
explicitly rejected. When the exact-37 integration is implemented, live mode
must still bind the in-process semantic receipt to the allowlisted `VITE_*`
environment, the exact clean release SHA, and the reviewed production branch.
Modeled mode accepts no release-evidence arguments and never receives a live
validation receipt.

The stable review URL for the current modeled branch is
`https://modeled-preview.wikigenme.pages.dev`. The edge admits only this
reviewed preview origin and canonical `https://www.wikigen.me`; Cloudflare's
unique per-deployment host redirects to the canonical production origin so it
cannot become another wallet-auth origin. Exact deployment IDs and served-file
manifests are release outputs, not source-code assertions, and are recorded in
the corresponding release handoff after every upload. For historical context,
the 2026-07-21 reference preview was deployment
`f69afba0-81b9-44b2-a4ae-e2d1a0800713`; all 142 of its served files were
verified byte-for-byte and its independent local/remote served-manifest SHA-256
was `604fbce76f4da06029d27a01061585e13bf2793cbc6b020df9c44ce333eb7778`.
The separate production deployment remains
`164b2207-96a9-487f-b4a8-d14bbfbc192d`, and its branch and custom domains were
not changed. The preview
intentionally has no contract/CVM mutation environment and labels its release
identity `unconfigured · modeled`; no working-tree label is allowed to enter a
verification-chain claim. It is a reviewable product preview, not the
provenance-bearing confidential-compute release described in
`RELEASE-MANIFEST.md`.

The deployment script runs the full typecheck, test, build, and dependency-audit
gate before uploading the static output. A no-binding modeled preview may be
published from an active working tree and is explicitly labeled as such. The
moment any release binding or live feature is present, deployment requires the
full generated release SHA to equal a clean `HEAD`, requires all four live
core feature gates plus any requested Compute-vault funding/authorization
gates, and removes Wrangler's dirty-worktree override.

The project seeds `_headers` from `public/`, then regenerates `dist/_headers`
from the exact production environment after every build. A modeled build allows
only self plus the canonical Base Sepolia RPC; a live delegate origin is added
only when the corresponding live feature flags and exact HTTPS origin are
present. Routing is hash-based, so every application route is served from `/`
without a Pages rewrite. `TINKER_CORS_ALLOWED_ORIGINS` must contain only the
three reviewed production origins before enabling any cross-origin mutation.

## Safety boundaries

- No raw artifact enters Cloudflare Pages, public logs, the on-chain contract, or a modeled queue.
- Card details are never collected, returned to, or persisted by this static
  app. Hosted checkout and purchased service credits are outside v1; any later
  integration requires provider-hosted collection and a verified signed webhook.
- Compute Credits are closed-loop, non-transferable, operator-granted noncash
  test units in v1; they are not purchased value, a speculative token, or a
  redeemable claim.
- Base Sepolia Compute capacity is a separate exact-asset ledger: ETH or the
  single release-pinned ERC20 moves directly between the connected wallet and
  the pinned vault. No token is minted, no exchange rate is applied, and no
  deposit is represented as Compute Credits. This is the v1 production
  pay-as-you-go lane: each job reserves a signed asset maximum, independent
  metering may debit only bounded actual usage, and the remainder stays
  withdrawable. Sponsors may fund another exact address without gaining control
  of that address's ledger; users may invalidate older unsubmitted signatures;
  and provider/developer accruals remain separate pull balances. Funding and authorization remain
  hidden unless their live release gates validate; available capacity keeps a
  separately verified withdrawal path.
- The Compute capacity vault is a reviewed, extensively tested testnet
  contract. The interface makes no formal-audit claim. Challenge prizes remain
  separate from both vault capacity and service credits.
- The RoyaltyDistributor panel can read and withdraw only the connected
  wallet's native ETH or canonical Base Sepolia USDC pull balance after the
  configured runtime hash matches. It can inspect an exact
  `(distributor, queryRef)` replay slot, but an unused slot does not prove that
  payment is owed and a consumed slot does not validate a query or allocation.
  Browser distribution is intentionally absent because the contract conserves
  a caller-computed split; it is not an ownership or pricing oracle.
- Synthetic-only Bio/DNA surfaces are analysis and quality-control challenges,
  not clinical, pathogen, synthesis, or wet-lab optimization tools. Data Vaults
  are roadmap architecture; this release accepts no health-data intake.
- Public attestation responses are allowlisted. Compose YAML, container environment, system information, and runtime secrets are rejected and never rendered.
- Contract bytecode presence is not treated as source verification, role verification, measurement matching, or end-to-end receipt verification.
- Email Oracle “ready” means only that the runtime-pinned contract, its exact
  membership/freeze facts, and the frozen external KMS proxy and implementation
  read consistently at one RPC-reported finalized Base Sepolia block. The panel
  is read-only: it does not send email, generate or reveal an OTP, mutate
  governance, validate the historical KMS registration receipt, prove restart
  continuity, or independently verify TDX/QVL evidence.

## Build output

The production build is fully static under `dist/`. Imported cinematic assets
are fingerprinted by Vite. Hash routing keeps navigation on the single-page
shell, and immutable caching applies only to fingerprinted `/assets/*` files.
