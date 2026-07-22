# Tinker-Delegate

Automated Thinking Machines Tinker account signup, sign-in, and API key provisioning inside a TEE. No human ever touches the credentials — the email oracle handles OTP verification, Playwright over CDP handles browser automation.

## Current Status

The current release candidate is source/local evidence only. No fresh
seven-contract Base Sepolia suite or seven-CVM Phala topology has been deployed.
The July 2026 account/browser results below are retained as historical
engineering evidence and do not authorize the new release.

As of 2026-07-08, the local Neko/CDP path works against the live Tinker auth flow: the email oracle creates a mailbox, receives the Thinking Machines magic-code OTP over IMAP, Playwright enters the OTP, onboarding completes, and API-key provisioning reaches the `/keys` page and captures a one-time `tml-...` key.

The March 2026 deployed Phala/headless browser blocker should be treated as historical evidence until re-tested. Local success does not prove the packaged Phala CVM browser posture is production-safe; that still needs a fresh deployed probe.

The email oracle is still required. It is not just a disposable inbox: it is the no-human-access OTP and confirmation channel for a TEE-owned Tinker account. Operators should not hold the Tinker account credentials or the email credentials; the TEE requests the magic-code email, reads it through the oracle, and completes auth inside the browser session.

The acceptable automation route is recorded in `docs/TINKER-AUTOMATION-ROUTE.md`. The short version: prefer an official or support-approved Tinker workflow; use browser automation only as bounded TEE custody for this project's own account; fail closed instead of using stealth plugins, CAPTCHA-solving services, rotating proxies, user-agent spoofing, or automation-control masking.

The oracle's scoped `/pin` and commitment-only `/email` endpoints are protected by runtime bearer auth when enabled. There is deliberately no `/inbox` route: runtime authentication is not permission to export message identifiers, sender/subject headers, dates, or message text. In the combined dstack/Phala deployment, the oracle and delegate derive the bearer token from the same dstack key path (`oracle/runtime-auth`), and the primary compose gives the oracle no host port; only the delegate can reach it on the private compose network. The oracle's public `/health` is a fixed liveness-only response and `/attestation` exposes only service/context/key/code/quote binding evidence; neither returns mailbox values, readiness, IMAP state, or timestamps. `/email` returns only authenticated readiness, a domain-separated mailbox commitment, its scheme, and `raw_email_egress=false`. The delegate must receive `TINKER_EMAIL` through an in-CVM sealed/bootstrap path before account automation; it cannot recover the address from the oracle HTTP API. Local development can use an explicit `ORACLE_RUNTIME_AUTH_TOKEN` / `TINKER_ORACLE_AUTH_TOKEN` pair instead. `/pin` is not a general mailbox query: its wire-compatible target/sender/subject/pattern fields are literal-constrained to Tinker, `no-reply@thinkingmachines.ai`, no subject filter, and one fixed six-digit OTP pattern. The IMAP layer rechecks the parsed sender, and the exact response contains only the six-digit OTP, bounded request hash, quote report data, and quote. Message/header/mailbox hashes, extraction time, and the replay key never egress. The oracle persists its internal replay keys in an encrypted/sealed ledger before release so one-time-use survives restart and fails closed if persistence is unavailable.

### Delegate HTTP and wallet security boundary

The delegate has separate authentication domains for operators, wallets, and
agent compute tokens; one token type is never accepted as another:

- The chain watcher and the internal `chain-event`, `notify-funded`, `evaluate`,
  `resolve`, active-deal listing, internal health, and funding-preflight routes
  require the configured `TINKER_RUNTIME_AUTH_TOKEN`. In dstack mode the same
  bearer value is derived inside the CVM at
  `TINKER_RUNTIME_AUTH_KEY_PATH`, and dstack mode enables these checks even if a
  legacy deployment omitted the boolean flag. The watcher sends the token only
  in the Authorization header.
- A seller requests `POST /auth/wallet/challenge` with their Ethereum address
  and deal ID, signs the returned Base Sepolia (chain ID `84532`), deal-bound
  personal-sign message with MetaMask, another EOA wallet, or an EIP-1271
  contract wallet, and exchanges it at `POST /auth/wallet/token`. The nonce is
  single-use and expiring. The resulting bearer token has only
  `artifact:upload`, expires after five minutes by default, and works for only
  that deal. The encrypted artifact endpoint checks the authenticated address
  against the funded in-TEE `DealContext.seller` before decrypting any bytes.
- EIP-1271 support is one shared verifier used by seller upload, Arena, and
  Compute authentication. It is enabled only when the operator configures
  `TINKER_WALLET_AUTH_RPC_URL` and `TINKER_WALLET_AUTH_RPC_URL_SECONDARY` on
  distinct provider origins; no request can select an RPC. Both providers must
  report Base Sepolia `84532`. The verifier selects the lower reported
  finalized height, requires both providers to return the same block hash and
  exact account bytecode there, hashes the challenge with EIP-191, and calls
  only
  `isValidSignature(bytes32,bytes)`. It accepts only the exact `0x1626ba7e`
  bytes4 result from both providers (including its standard zero-padded ABI
  word). RPC time,
  response size, global concurrency, and `eth_call` gas are bounded;
  wrong-chain, malformed, unavailable, reverted, or wrong-magic responses fail
  closed. Each nonce permits at most three sequential verification attempts and
  only one in-flight attempt, while a successful compare-and-delete still
  consumes it exactly once. Production dstack/Phala compose requires both RPC
  URLs as encrypted bootstrap secrets; local compose may leave both empty to
  retain the historical EOA-only path. A missing, divergent, or unavailable
  secondary provider is denial, never fallback.
- Production wallet tokens are signed with a domain-separated key derived at
  `TINKER_WALLET_AUTH_KEY_PATH`. `TINKER_WALLET_AUTH_SIGNING_KEY` is a local-only
  development fallback and must remain empty in Phala. Pending challenges are
  process-local and intentionally become invalid on restart; deploy the API as
  one worker until a shared sealed nonce store is added.
- Deal, Arena, and Compute challenge issuance share one atomic 600-second
  sliding-window admission gate. Its global capacity (`768`) is below each
  process-local nonce store (`1024`), with subordinate canonical-address (`64`)
  and direct-peer (`256`) buckets. Saturation returns the same bounded `429`
  body and `Retry-After` on every surface. Forwarded client-IP headers are
  ignored unless an approved single-IP header and exact direct-proxy CIDRs are
  both configured; unpinned `X-Forwarded-For` is never trusted.
- Arena submission auth is a fourth, separate token domain. A wallet signs an
  exact challenge ID/version at `POST /auth/arena/challenge`, exchanges the
  nonce at `POST /auth/arena/token`, and receives only the exact pair
  `challenge:submit` plus `challenge:submissions:read`.
  Arena tokens have a distinct issuer, audience, JWT key ID, and dstack-derived
  key path and cannot authorize seller upload, operator routes, or Tinker proxy
  calls. The durable Arena accepts only a SHA-256 candidate commitment, a
  strict browser-generated X25519/HKDF-SHA256/AES-256-GCM envelope, and
  allowlisted metadata; it never accepts plaintext candidate code or a
  caller-supplied object reference. The server generates the internal sealed
  reference after persisting ciphertext. Immutable catalog and submission
  projections remain explicitly `modeled` and
  `projection_only_no_hardened_executor`; an authenticated owner page filters
  by the recovered wallet and omits sealed refs, timing, and evaluator detail.
  The separate
  `dnai-safe-ir-v1` challenge now has a capability-free canonical-JSON
  interpreter and an internal, fail-closed, crash-resumable worker service in
  the dstack overlays. Its operational endpoint projects live presence only
  after an exact release descriptor and fresh authenticated heartbeat match;
  that heartbeat is not TDX evidence and every job still uses independent QVL.
  General Python and hostile execution remain disabled. See
  `docs/ARENA-RUNTIME.md` for the exact language,
  commitment, resource, worker, and residual deployment boundaries.
- Compute Console wallet and device credentials form two additional isolated
  token domains. Wallet-authenticated members manage projects, X25519 device
  keys, and scoped short-lived credentials; plaintext credentials and the
  upstream Tinker key never egress. The durable service-credit ledger is
  append-only/double-entry with idempotent reserve, settle, and release. A
  current owner/admin/developer wallet may atomically cancel only an exactly
  queued, never-dispatched job and return its reservation; device credentials,
  viewers, running work, and settled work cannot use that path. Every job
  remains explicitly `not_dispatched` and every settlement remains
  non-provider-authoritative. Card, ETH, and USDC Compute funding mutations are
  absent until a signed webhook or audited deposit vault exists. See the
  repository-level `docs/compute-console-api.md` for the exact API contract.
- Deal evaluation now has an explicit trust-bearing activation mode rather
  than a hard-coded stub. `TINKER_EVALUATOR_MODE=disabled` is the safe default;
  `stub` enables deterministic local integration only and is rejected whenever
  dstack custody is active. The historical `sft` helper tokenizes seller data
  for a remote Tinker provider, so merely calling it from a CVM would not keep
  the raw artifact inside the attested boundary. It remains research/test code
  but the production runtime rejects `sft` in every custody mode. The rendered
  dstack and Phala releases instead pin `deterministic`: an in-main-CVM,
  release-pinned three-policy registry whose recipes perform no provider,
  network, subprocess, filesystem, clock, randomness, or logging I/O over the
  private artifact. The Deal service remains profile- and release-gated as
  `release_pinned_deterministic_evaluator`; that source capability is not a
  live claim until the clean image, manifest/policy root, topology-v6
  descriptor set, fresh contracts, measured CVM, QVL evidence, and ceremony
  authority all agree. Any unsupported mode returns one fixed 503 before the
  control plane loads credentials or artifact state.
- Deal evaluation, Arena execution, and Compute dispatch now share a durable
  execution-policy gate. Internal bearer possession can record a safer
  hold/deny but cannot create a pass: pass requires an allowlisted independent
  Ethereum signer over the exact hash-only resource/request/policy/expiry
  message and a deployment-unique domain hash. The newest bounded record wins;
  missing, expired, corrupt, held, or denied state fails closed at execution
  time. See `docs/EXECUTION-POLICY.md` for the operator flow and release roots.
- `TINKER_CORS_ALLOWED_ORIGINS` is an optional comma-separated list of exact
  frontend origins. Configure the final Cloudflare Pages/custom HTTPS origin.
  Wildcards are rejected, browser credentials are never enabled, and only
  explicit loopback HTTP origins are accepted for local development.
- The authenticated funding preflight can fetch attestation only from an HTTPS
  DNS host listed exactly in `TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS`. IP
  literals, credentials, wildcard hosts, paths, queries, and fragments are
  rejected before any outbound request.

Public `GET /health` is liveness-only. Public `GET /attestation` remains the
bounded encryption-key/TDX evidence surface, and `GET /deal/{deal_id}/result`
continues to return only the declared bounded evaluation fields. Raw artifact
content, runtime topology, credentials, and active-deal inventories are not
public responses. Artifact upload acknowledgements return a client-verifiable
ciphertext SHA-256 commitment, `padding_profile=fixed_1m_v3`, and
`exact_plaintext_size_egress=false`. Every accepted diligence ciphertext has
the same 1,048,644-byte length, so this public transport size does not reveal
the private artifact length. Arena public receipts similarly retain ciphertext/blob
commitments while exact source and ciphertext lengths remain internal for caps
and cryptographic validation only.

When `DSTACK_SIMULATOR_ENDPOINT` is configured, delegate and Arena attestation
envelopes report `mode=simulator`, never `mode=tdx`, and retain
`verified=false`. Production verifiers accept only independently verified
`mode=tdx`; a simulator envelope cannot be upgraded by setting a claimed
verification flag. This keeps local modeled evidence visibly distinct from an
Intel TDX deployment.

Tinker account funding remains in progress. The production funding model is
manual/developer prefund by default until an official/tokenized route exists.
Raw-card browser automation is denied unless `TINKER_FUNDING_MODE` is set to
`operator_capped_validation` for a one-off approved operator-owned validation
attempt. The current validation path is card data encrypted to the TEE, then
browser automation drives the Tinker/Stripe billing form and clears card
material from memory. The card channel and billing code now reach Stripe in the
local Neko session: a Stripe test card filled the live payment form and was
classified as `card_declined`; the private Stripe sentence is not returned.
Adding balance correctly fails closed with `payment_method_required` when no
real card is on file. On 2026-07-08, the same local session produced bounded `payment_method`
and `add_balance` attempt records with outcome classes, furthest-stage markers,
timestamps, evidence hashes, amount bands, and card-payload destruction status.
The encrypted client harness verifies `/attestation?context=billing`, encrypts
locally, posts only ciphertext to `/billing/card/encrypted`, and locally
reproduced the same bounded test-card decline with a persisted receipt. The
operator CLIs can write bounded validation artifacts directly:
`funding-preflight --output` saves preflight JSON, and billing receipt-producing
commands can save bounded attempt records with `--receipt-output`. The
`funding-manifest` CLI turns a saved funding preflight plus bounded receipt into
a public audit envelope of hashes, bands, outcome, TDX quote hash, and
card-destruction/no-raw-egress booleans without card material.
`verify-funding-manifest` replay-verifies saved packets by recomputing hashes
and emitting named bounded checks. `funding-validation-packet` creates the
preflight, receipt, manifest, verification, and summary JSON artifacts in one
bounded packet directory; it can also include a separate add-balance receipt,
manifest, and verification. It requires explicit `--run-card-attempt` before
card fields are accepted, and explicit `--run-add-balance-attempt` before
posting an amount to `/billing/add-balance`. `check-funding-validation-packet`
replay-checks the packet directory and can require add-balance evidence or live
deployed TDX attestation evidence. CLI output fails closed if a delegate
response tries to echo submitted card material. The
plaintext card API endpoint is disabled by default and unavailable in dstack
mode; it can only be enabled as a local-development test hook with
`TINKER_ALLOW_PLAINTEXT_CARD_ENDPOINT=true`. The add-balance HTTP mutation
endpoint is also disabled by default and requires
`TINKER_ALLOW_ADD_BALANCE_ENDPOINT=true`; the capped CLI/operator path remains
available only in `operator_capped_validation` mode. The Stripe/PCI stance is
recorded in `docs/STRIPE-PCI-FUNDING-SCOPE.md`; the enforceable funding-mode
decision is recorded in `docs/TINKER-FUNDING-MODEL.md`. A capped real-card
validation attempt is still required before funding can be called end-to-end
proven.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        tinker-delegate                          │
│                                                                 │
│  1. Internal bootstrap ──→ email oracle ──→ mailbox custody   │
│  2. CDP ──→ neko Chrome ──→ tinker-console.thinkingmachines.ai  │
│  3. Fill email → Continue → magic-code (OTP) page               │
│  4. POST /pin ──→ email oracle ──→ polls IMAP ──→ 6-digit code  │
│  5. Enter code → authenticated → onboarding → API key           │
│  6. Seal API key → return { email, api_key_hash, stored }       │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

Thinking Machines uses **passwordless magic-code auth** at `auth.thinkingmachines.ai`:

1. **Email entry** — user enters email, clicks Continue
2. **OTP delivery** — 6-digit code sent from `no-reply@thinkingmachines.ai`
3. **Code entry** — 6 individual `<input inputmode="numeric">` boxes, auto-submits on completion
4. **Redirect** — authenticated session, redirected to `tinker-console.thinkingmachines.ai`

For new accounts, there's an additional **onboarding** step after first auth:
- Name (required)
- Affiliation (optional)
- Purpose (optional)
- Terms of Service checkbox (required, custom styled — hidden `<input>`, click label text)

### Historical Domain Notes

Earlier recon suggested Thinking Machines was mainly blocking known disposable domains. Those notes are no longer enough to explain the current behavior.

| Domain | Status |
|--------|--------|
| `cock.li` | historically blocked |
| `airmail.cc` | historically blocked |
| `firemail.cc` | historically blocked |
| `cock.email` | previously observed as allowed |
| `protonmail.com` | previously observed as allowed |
| `outlook.com` | previously observed as allowed |
| `gmail.com` | currently reaches magic-code in headed local Chrome |

Current July 8, 2026 local finding: local Neko Chrome reaches magic-code auth, receives OTP through the oracle, completes onboarding, and provisions API keys. The older March 17, 2026 Phala/headless blocker still needs a fresh deployed probe; email domain selection alone should not be treated as the whole production answer.

## Prerequisites

### Running Services

Both from the `tee-email-oracle` project:

1. **Email oracle** — `http://localhost:8000`
   - Historically tested with `ORACLE_DOMAIN=cock.email`
   - Creates a cock.email account on first boot (genesis)
   - Exposes `/health`, scoped `/pin`, commitment-only `/email`, and `/attestation`
   - Does not expose a mailbox-listing endpoint

2. **Neko Chrome** — `http://localhost:9222` (CDP)
   - Headful Chrome with remote debugging enabled
   - Visual UI at `http://localhost:52000` (optional, for debugging)

### Starting the Services

```bash
cd ⚙️/tee-email-oracle

# Set domain to cock.email (default is firemail.cc which is blocked)
echo "ORACLE_DOMAIN=cock.email" > .env

# Start with browser profile (neko + oracle)
docker compose --profile browser up -d

# Verify
curl http://localhost:8000/health
curl http://localhost:9222/json/version
```

## Usage

```bash
cd ⚙️/tinker-delegate

# Setup (first time)
uv venv && uv pip install playwright httpx pydantic pydantic-settings

# Check oracle is ready
.venv/bin/python -m tinker_delegate.main check

# Full signup: creates account, completes onboarding, generates API key
.venv/bin/python -m tinker_delegate.main signup

# Sign in: returns legacy URL/success metadata for local debugging
.venv/bin/python -m tinker_delegate.main signin

# Re-authenticate existing account via OTP with bounded receipt output
.venv/bin/python -m tinker_delegate.main reauth

# Check balance
.venv/bin/python -m tinker_delegate.main balance

# Add payment method (card details -- use encrypted channel in production)
.venv/bin/python -m tinker_delegate.main add-card \
  --number <stripe-test-card-number> \
  --exp-month 12 --exp-year 2028 \
  --cvc 123 --name "Dev Team" \
  --address-line1 "123 Main St" --address-city "SF" \
  --address-state "CA" --address-postal "94105"

# Add balance (requires card on file)
.venv/bin/python -m tinker_delegate.main add-balance 10

# Exercise the encrypted channel in explicitly allowed local development
.venv/bin/python -m tinker_delegate.main add-card-encrypted http://localhost:8080 \
  --number <stripe-test-card-number> \
  --exp-month 12 --exp-year 2028 \
  --cvc 123 --name "Dev Team" \
  --address-line1 "123 Main St" --address-city "SF" \
  --address-state "CA" --address-postal "94105" \
  --allow-local-attestation \
  --receipt-output ./payment-method-receipt.json

# Operator prompt path for an approved real-card validation attempt
.venv/bin/python -m tinker_delegate.main add-card-encrypted-prompt https://<deployed-tee> \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --receipt-output ./payment-method-receipt.json

# Save a bounded add-balance receipt if the validation reaches top-up
.venv/bin/python -m tinker_delegate.main add-balance 10 \
  --receipt-output ./add-balance-receipt.json

# Query only whether a card is on file; no card metadata is returned
.venv/bin/python -m tinker_delegate.main payment-method-status https://<deployed-tee> \
  --auth-token-env TINKER_RUNTIME_AUTH_TOKEN

# Admin/operator removal path; emits only a bounded removal receipt
.venv/bin/python -m tinker_delegate.main remove-card https://<deployed-tee> \
  --auth-token-env TINKER_RUNTIME_AUTH_TOKEN \
  --receipt-output ./remove-card-receipt.json

# Start API server (for TEE deployment)
.venv/bin/python -m tinker_delegate.main serve --port 8080
```

Before and after a capped validation attempt, save bounded JSON artifacts and
build a public manifest:

```bash
.venv/bin/python -m tinker_delegate.main funding-preflight \
  --amount 10 \
  --api-url https://delegate.example \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --fetch-attestation \
  --output ./preflight.json

.venv/bin/python -m tinker_delegate.main funding-manifest \
  --preflight-json ./preflight.json \
  --receipt-json ./payment-method-receipt.json \
  --validation-id operator-run-1 \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --output ./funding-manifest.json

.venv/bin/python -m tinker_delegate.main verify-funding-manifest \
  --preflight-json ./preflight.json \
  --receipt-json ./payment-method-receipt.json \
  --manifest-json ./funding-manifest.json \
  --validation-id operator-run-1 \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --require-ready

.venv/bin/python -m tinker_delegate.main funding-validation-packet \
  --output-dir ./funding-validation-packet \
  --api-url https://delegate.example \
  --amount 10 \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --validation-id operator-run-1 \
  --receipt-json ./payment-method-receipt.json \
  --add-balance-receipt-json ./add-balance-receipt.json

.venv/bin/python -m tinker_delegate.main check-funding-validation-packet \
  --packet-dir ./funding-validation-packet \
  --validation-id operator-run-1 \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --require-add-balance \
  --require-deployed-attestation
```

The manifest builder and packet runner reject raw card, API-key, and
secret-shaped inputs. To run an encrypted card attempt inside the packet
command for approved operator validation, pass `--run-card-attempt
--prompt-card` with deployed compose/app/OS-image expectations; prompt mode is
mutually exclusive with test-card flags and rejects missing measurement policy
before asking for card material. Add `--require-encumbrance`,
`--encumbrance-contract-address 0x...`, `--encumbrance-rpc-url
"$BASE_SEPOLIA_RPC_URL"`, and `--encumbrance-compose-hash 0x...` to require a
live `TinkerAccountEncumbrance` read before the prompt; same-packet top-ups
also check the requested amount against the deployed cap. To run top-up inside
the packet command, pass `--run-add-balance-attempt` with `--amount`; this posts
only the amount and still requires the delegate add-balance endpoint to be
explicitly enabled.

For the real operator path, prefer generating the command from recorded
deployment evidence:

```bash
uv run python -m tinker_delegate.main funding-command-plan --amount 10
```

The command plan reads `deployments/base-sepolia.json` and emits bounded
preflight, encumbrance-preflight, and prompt-packet command templates. It
references `TINKER_RUNTIME_AUTH_TOKEN` and `BASE_SEPOLIA_RPC_URL` by variable
name only; it does not print token values, RPC values, card fields, OTPs, API
keys, cookies, or browser session material. When the encumbrance contract is
missing, the plan reports `fresh_contract_suite_required` and emits explicit
`BROADCAST=false` and `BROADCAST=true` templates for
`contracts/scripts/deploy-base-sepolia.sh`. This creates a new canonical
seven-contract release; it is not a repair or overwrite of one contract in a
partial deployment ledger. The dry run must be reviewed before the operator
explicitly invokes the broadcast template from an interactive terminal. The
canonical helper uses Foundry `--account dev` through the encrypted keystore,
so the keystore password is never placed in the plan, command line, or repo.
`contracts/scripts/deploy-tinker-encumbrance-base-sepolia.sh` is retained only
as a fail-closed compatibility shim and cannot deploy or mutate the ledger.
Historical standalone addresses remain evidence of earlier releases, not a
current release path. The current deployed encumbrance exists, but the live cap
is still `$5`; the `$10` Tinker-minimum flow remains blocked until a new full
release carries the reviewed cap and compose policy through the current
timelocked activation ceremony.

The CLI card flags are for local test-card development only. Read
`docs/STRIPE-PCI-FUNDING-SCOPE.md` before any real-card attempt. The encrypted
card channel is an operator-owned capped validation path, not the default
production funding model.

### Artifact Upload

Use `upload-artifact` from the seller/controller side after a deal exists. The
command fetches `/attestation?context=artifact`, refuses local/default attestation unless
explicitly allowed, checks the expected compose hash/app ID and report-data-bound
public key, then encrypts the artifact to `POST /deal/{id}/artifact/encrypted`.
The deal-scoped seller wallet token must be supplied through an environment
variable (never a command-line token). Obtain it through the wallet challenge
flow described above and export it as `TINKER_WALLET_AUTH_TOKEN`.
The fourth positional argument is the private commitment receipt produced when
the deal is created. It must remain available to the seller for recovery and
upload, but must never be published, committed, or passed on the command line as
individual secret material. The CLI validates the receipt and exact artifact
bytes before making any attestation or upload request. It prints only bounded
metadata: deal ID, artifact commitment, fixed padding profile, status code, and
server response; the exact plaintext length is not returned.

```bash
uv run python -m tinker_delegate.main upload-artifact \
  https://delegate.example \
  1 \
  ./artifact.jsonl \
  ./artifact-commitment-receipt.json \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --diligence-room-address 0xFRESH_DILIGENCE_ROOM \
  --evaluator-policy-commitment 0xFUNDED_DEAL_POLICY_BYTES32
```

Use `--wallet-token-env ANOTHER_ENV_NAME` if the token is stored in a different
environment variable. The CLI fails before reading or sending the artifact when
the token is absent.

Local development can pass `--allow-local-attestation`, but production uploads
must use the dstack/TDX attestation path.

#### Artifact commitment v2

`DiligenceRoom.artifactHash` remains a `bytes32`, but its one accepted meaning
is the salted v2 commitment below. `ASCII(...)` means the literal ASCII bytes,
`secret32` is exactly 32 cryptographically random bytes, and `rawArtifact` is
the exact non-empty file byte sequence with no JSON or text normalization:

```text
artifactHash = keccak256(
  ASCII("dnai-wikigen/artifact-commitment/v2")
  || 0x00
  || secret32
  || rawArtifact
)
```

The seller privately retains this exact recovery receipt:

```json
{
  "schema_version": 2,
  "scheme": "dnai-wikigen/artifact-commitment/v2",
  "artifact_commitment": "0x<64 lowercase hex characters>",
  "commitment_secret": "0x<64 lowercase hex characters>"
}
```

Artifact transport accepts only envelope v3; there is no v2-wrapper, raw-hash,
or raw-artifact compatibility path. The raw artifact cap is exactly 1,048,576
bytes. The authenticated plaintext frame is always exactly 1,048,628 bytes:

```text
ASCII("DNAIARTIFACTV3\0\0")          # exact 16-byte magic
|| uint32be(privateRawLength)         # 1..1,048,576, ciphertext-private
|| secret32
|| rawArtifact
|| CSPRNG padding                     # fills a fixed 1,048,576-byte payload area
```

The upload JSON uses hex without `0x` for `ephemeral_public_key`, `nonce`, and
`ciphertext`, a lowercase `0x` bytes32 for `artifact_hash`, and the exact
`commitment_scheme`, `envelope_scheme=dnai-wikigen/artifact-envelope/v3`, and
`padding_profile=fixed_1m_v3` literals. AES-GCM adds a 16-byte tag, producing
an exact 1,048,644-byte ciphertext. Key derivation and authenticated encryption
bind the immutable funded context as follows (fields are pipe-delimited):

```text
HKDF info = "tinker-delegate-artifact|v3|84532|<lowercase room>|<deal id>"
            "|<lowercase artifactHash>|<lowercase evaluator policy>"
            "|dnai-wikigen/artifact-envelope/v3"
AES-GCM AAD = "dnai-wikigen/artifact-envelope-aad/v3|84532|<lowercase room>"
              "|<deal id>|<lowercase artifactHash>|<lowercase evaluator policy>"
              "|dnai-wikigen/artifact-envelope/v3"
```

The chain watcher carries `artifactHash` and `evaluatorPolicyCommitment` from
the funded deal into immutable in-TEE context. The deployment supplies the
exact fresh DiligenceRoom address and Base Sepolia chain ID. Ingress derives
AAD/HKDF only from those authoritative values, rejects non-exact ciphertext or
frame sizes before artifact use, verifies the private frame after decryption,
and recomputes the v2 commitment immediately before evaluator code receives
the raw bytes.

### Attestation Verification

Use `verify-attestation` to check the public evidence envelope from a laptop
before sending payment material or artifacts. It live-fetches `/attestation` for
the selected context and
verifies mode, quote presence, expected compose hash, optional app ID, optional
OS image hash, public-key shape, report-data key binding, and client fetch
freshness. This is not a complete Intel quote-chain parser yet; that remains a
separate verifier task.

```bash
.venv/bin/python -m tinker_delegate.main verify-attestation \
  https://delegate.example \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID \
  --os-image-hash 0xEXPECTED_OS_IMAGE_HASH \
  --context artifact
```

Use `verify-compose-hash` before registering or comparing a compose hash. It
renders the selected compose file, rejects local `build:` services and mutable
tag-only images, emits the digest-pinned image manifest, and computes the Phala
Cloud-style compose hash over the rendered app-compose object. For deploy-critical
TEE images, prefer literal digest-pinned `image:` entries in the Phala compose
over encrypted-env image substitutions; the live quote binds the compose
template and Phala app metadata, not a human-readable record of encrypted env
values.

```bash
.venv/bin/python -m tinker_delegate.main verify-compose-hash \
  --compose docker-compose.all.phala.yaml \
  --phala-raw-compose \
  --expected-hash EXPECTED_PHALA_COMPOSE_HASH
```

### API Server

The `serve` command starts a FastAPI server for programmatic access:

```
GET  /health              — public liveness only
GET  /health/internal     — bounded diagnostics; runtime bearer required
GET  /attestation?context=ingress|artifact|billing|arena — context-bound quote + public key
POST /auth/wallet/challenge — issue a one-time deal-bound personal-sign message
POST /auth/wallet/token   — exchange seller signature for artifact-upload token
POST /auth/arena/challenge — issue an exact challenge-version personal-sign message
POST /auth/arena/token    — exchange signature for exact submit + owner-read token
GET  /arena/candidate-encryption-contract — current recipient + exact browser crypto/AAD contract
GET  /arena/challenges    — bounded immutable challenge catalog
GET  /arena/challenges/{id}/versions/{version} — exact public manifest
POST /arena/challenges/{id}/versions/{version}/submissions — authenticated commitment + browser ciphertext
GET  /arena/challenges/{id}/versions/{version}/queue — bounded modeled queue projection
GET  /arena/challenges/{id}/versions/{version}/leaderboard — accepted Ladder releases only
GET  /arena/challenges/{id}/versions/{version}/submissions/mine — authenticated bounded owner page
GET  /arena/challenges/{id}/versions/{version}/worker-capability — release-bound presence, never TDX evidence
GET  /arena/submissions/{submission_id} — bounded public submission projection
POST /auth/reauth         — bounded OTP re-auth, disabled unless explicitly enabled
GET  /billing/balance     — authenticated stable balance band; never exact currency
GET  /billing/funding-policy — bounded funding-mode policy
GET  /billing/funding-preflight — operator bearer + HTTPS host allowlist required
GET  /billing/funding-receipts — bounded funding attempt audit records
GET  /billing/payment-method-status — bounded card-on-file status, no card details
POST /billing/card        — plaintext local-dev hook, disabled by default
POST /billing/card/encrypted — encrypted card ingress; production attestation gate not yet complete
POST /billing/card/remove — admin/operator payment-method removal
POST /billing/add-balance — add credit balance
POST /deal/{id}/artifact/encrypted — funded seller wallet token + TEE ciphertext required
POST /deal/{id}/artifact — plaintext local-dev hook, disabled by default
```

#### Attestation verdict contract

`GET /attestation` transports bounded evidence: the quote returned by dstack,
the context-bound X25519 public key and report data, plus claimed app, compose,
and OS identity fields. The service is the evidence producer, not an independent
verifier. Its `verified` field is therefore always `false`, including when
`mode=tdx` and a quote is present. Successful quote retrieval must never be
presented as Intel TDX verification.

The Python envelope checker validates shape, context, freshness of the HTTP
fetch, claimed identity values, and report-data/key consistency. Its optional
TDX parser only checks structure and report-data bytes. It does **not** validate
the quote signature, Intel collateral/TCB status, certificate chain, or bind the
claimed measurements cryptographically. Consequently the built-in production
artifact, billing, and oracle credential upload helpers fail closed against the
service's `verified=false` response. Local-mode upload remains available only
through the explicit development flags.

Before enabling a production secret upload, integrate an independent DCAP/QVL
verifier, pin the approved source/image/compose/measurement policy, validate a
fresh quote and its report-data binding, and pass the resulting verdict through
a separately authenticated trust boundary. This is a roadmap gate, not a live
security claim.

The same boundary governs result settlement. `submit-result` checks a
signer-produced quote envelope only for internal consistency, then authenticates
the exact result authorization against the immutable `resultVerifier` read from
`DiligenceRoom` before broadcasting. `authorize-result` will not mint that
signature from the service envelope alone: it requires a fresh signed
`intel_tdx_dcap_qvl` verdict from an explicitly trusted verifier address, bound
to the quote hash, report data, compose/app/OS identity, signer, chain, and
contract. No production CLI bypass exists. Until that independent verdict
producer is deployed, live result authorization is intentionally unavailable.

Likewise, `verify-deployment-bundle` verifies GitHub provenance/SBOM signatures
and checks digest-pinned compose plus service-reported CVM identity consistency,
but emits `status=evidence_checked_tdx_unverified`. Its public claims keep Intel
TDX verification, independent-verdict presence, and production authorization
false; quote presence is never labeled as verification.

The browser container in `docker-compose.all.phala.yaml` now uses an existing
project-owned, digest-pinned `neko-chrome` image, has no host-published Neko or
CDP port, requires distinct non-default user/admin credentials, and replaces
the external MCR Playwright sidecar with internal CDP from the delegate image.
That historical Neko digest is **not** release-eligible for a new source commit.
The Dockerfile now pins Chrome `150.0.7871.114-1` by its exact versioned Google
package URL and verifies SHA-256
`0f19e68dca574849632e25229f15853d2beac33fa06498feed43f34628bc2d53`,
matching the signed historical SBOM and official package index. Its Debian
dependencies now resolve only from the immutable `20260406T000000Z` archive
recorded by the digest-pinned Neko base; `openbox` and `nginx` are exact-version
requests and apt/dpkg/update-alternatives wall-clock logs are removed. The Python
runtime images use
the base image's corresponding `20260623T000000Z` archive and normalize their
non-editable lockfile-built virtualenvs. Production release still requires two
uncached matching build subjects plus clean CI publication under the new source
SHA, exact GitHub SLSA/SPDX attestations, and literal substitution of the
resulting digest into the release manifest. No replacement digest should be
inferred from the historical image.

### Signup Output

```json
{
  "email": "d1074e2240b5311d@cock.email",
  "api_key_created": true,
  "api_key_hash": "9b3f...",
  "stored": true,
  "success": true,
  "attempt_record": {
    "surface": "api_key_provisioning",
    "outcome": "success",
    "furthest_stage": "api_key_stored",
    "evidence_hash": "64-lowercase-sha256-hex",
    "account_hash": "sha256...",
    "raw_secret_egress": false
  }
}
```

### Sign-in Output

```json
{
  "email": "d1074e2240b5311d@cock.email",
  "url": "https://tinker-console.thinkingmachines.ai/keys",
  "success": true
}
```

## Private Verified Reward (RLVR substrate)

Beyond the NDAI diligence room, this delegate is a private verified-reward
substrate: sealed data evaluates candidate keywords/code/optimizers behind a
leakage-bound boundary and emits only bounded bands, hashes, attestations, and a
proof-carrying transcript. The optimizer is swappable (random / hill-climb /
evolutionary / LLM-repair); the guarantee is the protected reward interface, not
the method. Each demo emits a certificate + Merkle transcript commitment that
`verify-reward-run` re-checks from public bytes alone.

```bash
# Bounded reward demos (only bands/hashes/attestation leave the boundary):
tinker-delegate synthetic-private-reward-demo        # hidden-keyword reward
tinker-delegate denoising-private-reward-demo         # OpenProblems-style holdout, candidate programs
tinker-delegate bio-assay-qc-reward-demo              # synthetic assay-QC programs (Z'-factor)
tinker-delegate dp-bounded-reward-demo                # DP-budget-bounded release then fail-closed
tinker-delegate thresholdout-demo                     # DP-noised reusable holdout: free-track vs. spend-on-divergence

# Verify a run packet end-to-end (reproducibility cert + transcript binding):
tinker-delegate synthetic-private-reward-demo --output run.json
tinker-delegate verify-reward-run --packet run.json   # exits non-zero on failure

# Full third-party mechanism audit ("audit the mechanism, not the data"): binds
# the run to the exact code you read, the committed sealed dataset (+ optional
# M-of-N notary quorum and signed provenance), and a calibrated oracle:
tinker-delegate denoising-private-reward-demo --output run.json
tinker-delegate verify-reward-mechanism --packet run.json \
    --source tinker_delegate/private_reward_envs/denoising.py \
    [--manifest manifest.json --expected-signer 0x.. \
     --witness 0x.. --witness-threshold 2 \
     --expected-benchmark openproblems-denoising-v1 --require-provenance]

# Neutral-notary co-sign + provenance verification (keys come from env vars):
DATASET_WITNESS_SIGNER_PRIVATE_KEY=... \
  tinker-delegate witness-sign-dataset-manifest --manifest m.json --out m.cosigned.json
tinker-delegate verify-dataset-provenance --manifest m.signed.json \
    --expected-signer 0x.. --expected-benchmark openproblems-denoising-v1
```

Security properties (all fail-closed, tested): the exact reward and sealed data
never egress (`assert_bounded_egress`); a hidden-holdout with one-shot final
validation and per-candidate repeat caps resists adaptive-query overfitting;
canary probes catch a gamed/leaked oracle; an optional differential-privacy
budget is charged per reward query and fails closed when spent; bio/dual-use
results route to a fail-closed human-review queue with non-self-approval and
M-of-N approval; and the winning candidate's disclosure (public / hash-only /
sealed escrow / blocked) is decided by a bounded policy.

Third-party mechanism audit (all verifiable from bounded bytes, no sealed data):
`verify-reward-mechanism` composes (1) attested code-identity binding — the run
used the exact source you read; (2) sealed-dataset commitment binding, with an
optional M-of-N neutral-notary quorum and seal-time signed provenance
(distribution claim vs. a named public benchmark, bound so it can't be asserted
after the fact); (3) canary calibration — a published known-answer report proves
the oracle ranks sensibly; and (4) declared-vs-enforced policy accounting — the
boundary ran no more queries / Ladder improvement steps than its stated policy.
The Ladder mechanism (fixed-η + parameter-free paired-t) bounds adaptive-query
holdout reuse so a fixed sealed holdout supports effectively unlimited attempts
while the settled number stays honest.

## Configuration

All settings use the `TINKER_` env prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `TINKER_CDP_URL` | `http://localhost:9222` | Neko Chrome CDP endpoint |
| `TINKER_ORACLE_URL` | `http://localhost:8000` | Email oracle API |
| `TINKER_ORACLE_AUTH_TOKEN` | *(empty)* | Local-dev bearer token for protected oracle `/pin` and commitment-status calls |
| `TINKER_ORACLE_AUTH_KEY_PATH` | `oracle/runtime-auth` | dstack key path used to derive the same-CVM oracle bearer token |
| `TINKER_TINKER_CONSOLE_URL` | `https://tinker-console.thinkingmachines.ai` | Tinker console URL |
| `TINKER_EMAIL` | *(empty)* | Raw account email injected inside the CVM; never fetched from the oracle API |
| `TINKER_FIRST_NAME` | `Tinker` | First name for signup |
| `TINKER_LAST_NAME` | `Delegate` | Last name for signup |
| `TINKER_OTP_POLL_INTERVAL` | `3.0` | Seconds between OTP polls |
| `TINKER_OTP_POLL_TIMEOUT` | `120.0` | Max seconds to wait for OTP |
| `TINKER_OTP_MAX_AGE` | `300` | Max age of OTP email in seconds |
| `TINKER_FUNDING_RECEIPT_STORE_PATH` | `./data/funding_receipts.enc` | Encrypted bounded funding receipt store |
| `TINKER_FUNDING_RECEIPT_STORE_KEY` | *(empty)* | Local-dev hex key override; dstack should derive the key instead |
| `TINKER_FUNDING_RECEIPT_KEY_PATH` | `tinker/funding_receipts` | dstack key path for funding receipt storage |
| `TINKER_RUN_METADATA_STORE_PATH` | `./data/run_metadata.enc` | Encrypted bounded deal/run lifecycle metadata store |
| `TINKER_RUN_METADATA_STORE_KEY` | *(empty)* | Local-dev hex key override; dstack should derive the key instead |
| `TINKER_RUN_METADATA_KEY_PATH` | `tinker/run_metadata` | dstack key path for run metadata storage |
| `TINKER_ARENA_STORE_PATH` | *(empty)* | Durable bounded Arena JSON path; empty leaves catalog readable but disables submission/queue/leaderboard writes and reads |
| `TINKER_ARENA_WALLET_AUTH_KEY_PATH` | `tinker/arena_wallet_auth` | Distinct dstack key path for challenge-version-bound Arena tokens |
| `TINKER_ARENA_WALLET_AUTH_CHALLENGE_TTL_SECONDS` | `300` | Arena personal-sign nonce lifetime, capped at 600 seconds |
| `TINKER_ARENA_WALLET_AUTH_TOKEN_TTL_SECONDS` | `300` | Exact Arena submit + owner-read token lifetime, capped at 900 seconds |
| `TINKER_ARENA_WALLET_AUTH_MAX_PENDING_CHALLENGES` | `1024` | Process-local pending Arena nonce capacity; new challenges fail closed at capacity |
| `TINKER_WALLET_AUTH_CHALLENGE_LIMIT_WINDOW_SECONDS` | `600` | Shared sliding window; must cover the longest Deal/Arena/Compute challenge TTL |
| `TINKER_WALLET_AUTH_CHALLENGE_GLOBAL_LIMIT` | `768` | Accepted challenges across all three surfaces per window; must remain below every nonce-store capacity |
| `TINKER_WALLET_AUTH_CHALLENGE_ADDRESS_LIMIT` | `64` | Canonical wallet-address challenge admissions per shared window |
| `TINKER_WALLET_AUTH_CHALLENGE_PEER_LIMIT` | `256` | Direct peer (IPv4 or IPv6 /64) challenge admissions per shared window |
| `TINKER_WALLET_AUTH_CHALLENGE_TRUSTED_PROXY_CIDRS` | *(empty)* | Exact direct-proxy CIDRs; forwarded identity remains disabled unless the approved header is also set |
| `TINKER_WALLET_AUTH_CHALLENGE_CLIENT_IP_HEADER` | *(empty)* | Optional `CF-Connecting-IP` or `X-Real-IP`; lists and unpinned forwarding headers are ignored |
| `TINKER_WALLET_AUTH_RPC_URL` | *(empty locally; required in production compose)* | Primary operator-configured HTTPS Base Sepolia JSON-RPC for shared EIP-1271 verification; requests cannot override it |
| `TINKER_WALLET_AUTH_RPC_URL_SECONDARY` | *(empty locally; required in production compose)* | Independent secondary provider origin; disagreement or failure denies auth without fallback |
| `TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS` | `3.0` | Per-phase network timeout for each wallet-auth JSON-RPC request, hard-capped at 10 seconds |
| `TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES` | `131072` | Maximum JSON-RPC response body for wallet verification, hard-capped at 1 MiB |
| `TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES` | `4096` | Maximum decoded EOA/EIP-1271 signature bytes; the hard cap is 4 KiB |
| `TINKER_ARENA_CANDIDATE_INGRESS_STORE_PATH` | *(empty)* | Durable ciphertext-envelope directory; empty disables Arena attestation/contract/submission ingress |
| `TINKER_ARENA_CANDIDATE_INGRESS_KEY_PATH` | `tinker/arena_candidate_ingress` | Distinct dstack key path for the restart-stable Arena X25519 recipient |
| `TINKER_ARENA_CANDIDATE_INGRESS_LOCAL_KEY_FILE` | *(empty)* | Local-only `0600` 32-byte key file; dstack ignores it |
| `TINKER_ARENA_CANDIDATE_INGRESS_MAX_ENVELOPES` | `10000` | Durable ciphertext-envelope cap; decoded ciphertext is separately capped at 65,536 bytes |
| `TINKER_FUNDING_MODE` | `manual_prefund` | Funding mode: `manual_prefund`, `operator_capped_validation`, or reserved `official_tokenized` |
| `TINKER_MIN_ADD_BALANCE_USD` | `10.0` | Minimum whole-dollar add-balance amount accepted before browser automation starts |
| `TINKER_MAX_ADD_BALANCE_USD` | `10.0` | Maximum add-balance amount allowed before browser automation starts |
| `TINKER_ALLOW_ADD_BALANCE_ENDPOINT` | `false` | Enables `POST /billing/add-balance`; leave false unless running a deliberate capped operator validation |
| `TINKER_ALLOW_PLAINTEXT_CARD_ENDPOINT` | `false` | Local-dev only flag for `POST /billing/card`; production uses `/billing/card/encrypted` |
| `TINKER_DEBUG_ARTIFACT_DIR` | *(empty)* | Optional browser debug artifact directory; card submissions purge known secret-bearing trace/HAR/video/card screenshot files here |
| `TINKER_PURGE_SECRET_DEBUG_ARTIFACTS` | `true` | Delete known secret-bearing browser debug artifacts after card submission attempts |

## Architecture

```
tinker_delegate/
├── __init__.py
├── config.py          # Pydantic Settings with TINKER_ prefix
├── oracle_client.py   # HTTP client for /pin, /health, and commitment-only /email
├── signup.py          # Browser automation: auth, onboarding, API key creation
├── billing.py         # Browser automation: Stripe card form, balance, auto-reload
├── card_channel.py    # Secure card delivery channel (encrypted in production)
├── crypto.py          # X25519 + AES-256-GCM encryption for card channel
├── session.py         # IsolatedTinkerSession: sandboxed SDK wrapper + cost meter
├── control_plane.py   # Deal lifecycle orchestration + output bounding
├── evaluator.py       # Stub + SFT evaluator agents
├── arena_auth.py      # Challenge-version wallet auth; exact submit + owner-read tokens
├── arena_ingress.py   # Stable attested recipient + strict browser ciphertext persistence
├── arena_store.py     # Durable bounded modeled queue + Ladder leaderboard projection
├── api.py             # FastAPI server: billing, attestation, deal lifecycle
└── main.py            # CLI: check, signup, signin, reauth, balance, add-card, add-balance, serve

contracts/
├── src/DiligenceRoom.sol       # Escrow state machine (Base Sepolia)
├── test/DiligenceRoom.t.sol    # 22 tests (unit + fuzz)
├── script/DiligenceRoom.s.sol  # Deployment script
└── foundry.toml                # Foundry config for Base networks
```

### signup.py — Key Functions

| Function | Purpose |
|----------|---------|
| `signup()` | Full flow: authenticate → onboarding → create API key |
| `signin()` | Re-authenticate existing account via OTP |
| `reauth()` | Refresh Tinker auth via OTP and return only bounded `tinker_auth` receipt metadata |
| `_authenticate()` | Handle email entry, OTP wait, code entry |
| `_handle_onboarding()` | Fill name, check TOS, submit (skipped if already done) |
| `_create_api_key()` | Navigate to /keys, click "New key", extract `tml-...` token |
| `wait_for_otp()` | Poll email oracle `/pin` endpoint until 6-digit code arrives |
| `enter_otp()` | Fill 6 individual `<input inputmode="numeric">` boxes |

### oracle_client.py — Email Oracle Interface

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `health()` | `GET /health` | Check fixed process liveness only |
| `get_email_status()` | `GET /email` | Return readiness plus a domain-separated mailbox commitment |
| `get_email()` | none | Fails closed; configure `TINKER_EMAIL` inside the CVM |
| `get_pin()` | `POST /pin` | Fetch the allowlisted six-digit OTP with bearer/consumer auth; accepts only the exact code/request-hash/report-data/quote shape |
| `list_inbox()` | none | Permanently disabled; mailbox metadata cannot egress |

## Recon Findings

### auth.thinkingmachines.ai

- **Framework**: Next.js SPA (React)
- **Auth provider**: Custom (not Clerk/WorkOS despite similar UX)
- **Sign-in page**: `input[name="email"]` + `button[type="submit"]` ("Continue")
- **Sign-up page**: `first_name`, `last_name`, `email` fields + Continue
- **OTP page**: URL contains `magic-code`, 6x `input[inputmode="numeric"]`
- **OTP sender**: `Thinking Machines Lab <no-reply@thinkingmachines.ai>`
- **OTP format**: 6-digit numeric code, regex `\b\d{6}\b`
- **OTP arrival**: ~5-8 seconds after form submission

### tinker-console.thinkingmachines.ai

- **Onboarding** (`/onboarding`): `fullName` (text), `affiliation` (text, optional), `whatWillYouCreate` (text, optional), `tos` (checkbox, hidden input — click label)
- **Welcome** (`/welcome`): Quick tips page, "Get started" button
- **API keys** (`/keys`): Table of keys, "New key" button → modal dialog → "Generate key"; automation also accepts aria-label and `data-testid` variants for create/confirm/close controls, with replayable mock-page tests for selector drift
- **Key format**: `tml-[A-Za-z0-9_-]{60+}` (prefix `tml-`, shown once)
- **Key modal**: "This key will ONLY appear once" warning, Copy button, Close button
- **Initial load bug**: Keys page shows "Loading..." on first visit, requires `page.reload()` to render properly

### Billing (tinker-console.thinkingmachines.ai/billing)

- **Payment**: Stripe Elements (cross-origin iframe for PCI compliance)
- **Card iframe**: `input[name="cardnumber"]`, `input[name="exp-date"]`, `input[name="cvc"]`
- **Parent fields**: `#cardholder-name`, `#service-line1`, `#service-city`, `#service-state`, `#service-postal-code`, `#service-country`
- **Selector drift handling**: payment-method and add-balance automation use
  explicit fallback families for balance/payment controls, submit buttons,
  cardholder/address fields, add-balance amount inputs, and top-up confirmation.
  Mock-page tests cover current selectors plus data-testid/aria-style variants,
  card-on-file management copy, and preset amount buttons; missing top-up
  controls return bounded `selector_missing` receipts without returning page
  text.
- **Card-on-file status/removal**: `GET /billing/payment-method-status` returns
  only `card_on_file` and a zero/one-or-more/unknown count band. Authenticated
  `POST /billing/card/remove` can remove the payment method and emits a bounded
  receipt. Neither path returns card brand, last4, expiry, address, or page
  text.
- **Top-up minimum**: Tinker's UI requires whole-dollar amounts from `$10`;
  the delegate rejects below-minimum or fractional add-balance requests before
  browser automation.
- **hCaptcha**: Invisible on form (no manual solve needed in neko)
- **Model**: Prepaid balance (add credit, spend on API usage)
- **Local test-card result**: Stripe test card reaches submission and returns
  only `card_declined`; the raw Stripe/page sentence remains inside the CVM.
- **No-card funding result**: add-balance fails closed with
  `payment_method_required`.
- **Deployed real-card validation**: the first approved real-card validation
  did not top up the account, but the later same-context reauth/add-balance
  packet reached `add_balance_submitted` with `raw_secret_egress=false`, replay
  verification passed with deployed attestation, and bounded balance read-back
  demonstrated a funded balance; the current public read returns only the
  `10_100_usd` band, never `$10.00` or another exact currency string. The add-balance receipt remains
  conservative because explicit success copy was not observed; the balance read
  is the current funding evidence. This is still a one-off operator-owned
  validation path, not production/repeated funding.
- **Attempt records**: payment-method and add-balance responses expose bounded
  `surface`, `outcome`, `furthest_stage`, `issued_at`, `evidence_hash`,
  amount/balance bands, TDX quote hash when present, and card-payload
  destruction status; they do not return raw card fields or browser page bodies.
  `bounded_message` and every public billing `error` are exactly the classified
  `AutomationOutcome` code. `evidence_hash` is deterministic over the canonical
  bounded public projection only; raw/redacted browser sentences, URLs, card
  text, and timestamps cannot influence it.
- **Receipt storage**: bounded funding attempt records are persisted in the
  encrypted delegate store and can be read through `/billing/funding-receipts`.
  The store rejects unknown/missing fields, non-enum messages, invalid bands,
  malformed hashes, projection/hash mismatches, and any receipt claiming raw
  secret egress. Store failures expose only `store_failed`.
- **Balance read**: `GET /billing/balance` requires a configured runtime bearer
  token or a proxy JWT with the read-only `billing:balance` scope and returns
  only `balance_band` plus bounded status/auth metadata.
- **Funding mode**: `manual_prefund` is the default production model and denies
  card/add-balance browser automation. `operator_capped_validation` is required
  before encrypted card or add-balance automation can launch, and denied
  requests persist bounded `policy_denied` receipts. Inspect the bounded policy
  through `/billing/funding-policy` or `python -m tinker_delegate.main
  funding-policy`.
- **Funding preflight**: `GET /billing/funding-preflight` and `python -m
  tinker_delegate.main funding-preflight` check validation mode, amount cap,
  optional add-balance endpoint flag, encrypted receipt-store availability, and
  billing attestation policy before any card payload or browser launch. Passing
  `--fetch-attestation` live-fetches `/attestation?context=billing`; passing
  `--output` writes the bounded preflight JSON. The HTTP endpoint is
  operator-authenticated, and caller-supplied API origins are accepted only
  when they use HTTPS and their exact DNS host is configured in
  `TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS`.
- **Funding receipt artifacts**: `add-card`, `add-card-encrypted`, and
  `add-balance` accept `--receipt-output` to write the bounded `attempt_record`
  JSON for later manifest binding. The CLI refuses to print or write output
  containing submitted card values or secret-shaped fields.
- **Funding validation manifest**: `python -m tinker_delegate.main
  funding-manifest` builds a bounded public manifest from saved preflight and
  receipt JSON. It stores only hashes, bands, outcome, TDX quote hash,
  card-destruction/no-raw-egress booleans, and optional attestation-policy hash;
  raw card/API-key/secret-shaped inputs are rejected.
- **Funding manifest verification**: `python -m tinker_delegate.main
  verify-funding-manifest` recomputes the packet hashes and reports named
  bounded checks for version, manifest hash, preflight hash, receipt hash,
  validation ID hash, attestation policy hash, readiness, and
  no-raw-card-retained status without echoing packet bodies.
- **Funding validation packet**: `python -m tinker_delegate.main
  funding-validation-packet` writes preflight, receipt, manifest, verification,
  and summary JSON into one directory. It can bind an existing bounded receipt
  with `--receipt-json`, or run encrypted card submission only with explicit
  `--run-card-attempt`. It can also bind `--add-balance-receipt-json` or run an
  explicit `--run-add-balance-attempt` to produce separate top-up manifest and
  verification JSON.
- **Funding packet checker**: `python -m tinker_delegate.main
  check-funding-validation-packet` checks required files, replays payment and
  optional top-up manifest hashes, compares saved verification/summary hashes,
  and can fail closed unless add-balance files or live deployed TDX attestation
  evidence are present.
- **Run metadata storage**: deal lifecycle events are persisted in a separate
  encrypted delegate store under `/data/run_metadata.enc` in compose profiles.
  Records contain only bounded metadata such as hashed deal/account/run handles,
  artifact hashes and size bands, score/offer/cost bands, and cleanup counts.
  The store rejects unknown fields and any record claiming raw secret egress.
- **Debug screenshots**: payment-method screenshots after card entry/submission
  are suppressed even when `TINKER_DEBUG_SCREENSHOTS=true`; only non-secret
  billing screenshots may be written. If `TINKER_DEBUG_ARTIFACT_DIR` is set,
  card submission attempts also purge known secret-bearing trace archives, HARs,
  videos, and card/Stripe screenshots from that directory.
- **Core dumps**: delegate Python entrypoints set `RLIMIT_CORE=0`, and the
  local/Phala compose files set `ulimits.core: 0` for the delegate and browser
  path so crash dumps do not persist card/API-key/browser memory.
- **Encrypted client**: `add-card-encrypted` and
  `tinker_delegate.billing_uploader` fetch `/attestation?context=billing`,
  verify policy, encrypt card JSON, wipe the local plaintext buffer, and post
  only ciphertext to `/billing/card/encrypted`.
- **Operator card entry**: `add-card-encrypted-prompt` prompts interactively
  instead of taking card fields as command-line flags, requires deployed
  compose/app/OS-image attestation expectations unless explicitly run with
  local-development attestation, can require live `TinkerAccountEncumbrance`
  approval with `--require-encumbrance` before prompting, zeros the in-memory
  card dictionary after upload, and emits only bounded JSON.
- **Funding model and Stripe/PCI stance**: see `docs/TINKER-FUNDING-MODEL.md`
  and `docs/STRIPE-PCI-FUNDING-SCOPE.md`; production or repeated funding should
  use an official Tinker route, Stripe-hosted/tokenized collection,
  SetupIntent / PaymentMethod reuse with consent, or manual/developer prefunding
  until compliance review approves otherwise.
- **Auto-reload**: Configurable threshold + amount
- **Pricing** (USD/million tokens): Llama-3.2-1B $0.03-$0.09, Llama-3.1-8B $0.13-$0.40, Qwen3-235B $0.68-$2.04
- **Trust model**: Developer encrypts card to TEE's TDX key → TEE fills Stripe form → zeroes memory → card never persisted

### Browser Automation Notes

- **CDP connection**: `playwright.chromium.connect_over_cdp("http://localhost:9222")`
- **Reuse existing tab**: `browser.contexts[0].pages[0]` (neko always has one page)
- **Wait strategy**: `domcontentloaded` (not `networkidle` — SPA redirects cause hangs)
- **Stale state**: Check for leftover OTP page on connect, navigate fresh if found
- **TOS checkbox**: Hidden `<input>` with overlay `<div>` intercepting clicks — use `page.locator('text=I have read and agree').click()` instead
- **Typing vs fill**: Email fields use `type(email, delay=30)` for realistic input; name fields use `fill()` since they don't have bot detection

## TEE Deployment

The production release uses seven purpose-separated Phala CVMs. The delegate,
email oracle, and project-owned Neko browser share only the main runtime CVM.
The Diligence QVL, Arena QVL, anchor-writer QVL, Compute-workload QVL,
Compute-metering QVL, and independent deterministic Compute meter remain outside
that trust domain. The five QVL deployments have distinct policy-derived roots;
the Diligence root's secondary Email/KMS restart profile does not add a sixth
root or eighth CVM.
Each generated QVL descriptor defaults to a five-second request-body phase and
a 20-second verification phase. Their 25-second combined server budget leaves
headroom inside every QVL consumer's 30-second end-to-end request timeout.

Do not deploy the source-development compose directly. Generate the exact
topology-v6, digest-pinned `dnai-main-runtime.phala.yaml` plus its six
independent descriptors from the signed five-image release manifest. The main
descriptor contains the internal service wiring, including:

```yaml
services:
  delegate:
    environment:
      TINKER_CDP_URL: http://neko:9223
      TINKER_ORACLE_URL: http://oracle:8000
      TINKER_EVALUATOR_MODE: deterministic
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock:ro
```

The deterministic Deal evaluator does not consume the upstream Tinker API key;
that credential remains purpose-separated for the product surfaces that need
it. Merely rendering this service does not enable settlement. Production Deal
settlement remains unavailable until the exact deterministic evaluator
manifest and policy root, clean image, topology-v6 descriptor set, fresh
contract bindings, measured main CVM, independent QVL evidence, and ceremony
authority have all been verified.

## What's Next

The complete SolidJS product surface lives in `web/`; it is no longer a React
mockup. It includes wallet authentication, Diligence rooms, the sealed Bio
Arena, Compute funding/authorization, proxy credentials, safeguards,
collaboration, and layered verification. Every surface remains labeled live,
modeled, or roadmap, and the modeled site is not evidence of a deployed TDX
release.

Remaining activation work is operational and deliberately fail-closed:

- publish the exact five reproducible image subjects from one clean source SHA
  with external GitHub SLSA and SPDX attestations;
- deploy a fresh operator-owned Base Sepolia suite, then complete the two-day
  Diligence-QVL, Compute-metering, TEE-admission, and anchor-writer ceremonies;
- deploy and independently verify all seven CVM descriptors and their bounded
  Intel TDX/QVL evidence;
- run the canonical check-only release validator against the exact live chain,
  deployment ledger, five external QVL roots, and evidence artifacts;
- enable Deal settlement only after a separately attested confidential
  evaluator replaces the research-only remote SFT path; and
- rebuild and publish the SolidJS environment only from that successful
  semantic release receipt.
