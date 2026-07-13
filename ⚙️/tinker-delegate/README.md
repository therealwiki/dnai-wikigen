# Tinker-Delegate

Automated Thinking Machines Tinker account signup, sign-in, and API key provisioning inside a TEE. No human ever touches the credentials — the email oracle handles OTP verification, Playwright over CDP handles browser automation.

## Current Status

As of 2026-07-08, the local Neko/CDP path works against the live Tinker auth flow: the email oracle creates a mailbox, receives the Thinking Machines magic-code OTP over IMAP, Playwright enters the OTP, onboarding completes, and API-key provisioning reaches the `/keys` page and captures a one-time `tml-...` key.

The March 2026 deployed Phala/headless browser blocker should be treated as historical evidence until re-tested. Local success does not prove the packaged Phala CVM browser posture is production-safe; that still needs a fresh deployed probe.

The email oracle is still required. It is not just a disposable inbox: it is the no-human-access OTP and confirmation channel for a TEE-owned Tinker account. Operators should not hold the Tinker account credentials or the email credentials; the TEE requests the magic-code email, reads it through the oracle, and completes auth inside the browser session.

The acceptable automation route is recorded in `docs/TINKER-AUTOMATION-ROUTE.md`. The short version: prefer an official or support-approved Tinker workflow; use browser automation only as bounded TEE custody for this project's own account; fail closed instead of using stealth plugins, CAPTCHA-solving services, rotating proxies, user-agent spoofing, or automation-control masking.

The oracle's `/pin`, `/inbox`, and `/email` endpoints are now protected by runtime bearer auth when enabled. In the combined dstack/Phala deployment, the oracle and delegate derive the bearer token from the same dstack key path (`oracle/runtime-auth`). Public `/health` and `/attestation` expose only readiness plus `oracle_email_hash`, not the raw mailbox address. Local development can use an explicit `ORACLE_RUNTIME_AUTH_TOKEN` / `TINKER_ORACLE_AUTH_TOKEN` pair instead. `/pin` requests are scoped: the delegate sends target service, expected sender, caller identity, reason, nonce, max age, and bounded extraction pattern. The oracle persists released OTP hashes in an encrypted/sealed replay ledger so one-time-use survives restart, and logs only bounded metadata, not the OTP value.

Tinker account funding remains in progress. The production funding model is
manual/developer prefund by default until an official/tokenized route exists.
Raw-card browser automation is denied unless `TINKER_FUNDING_MODE` is set to
`operator_capped_validation` for a one-off approved operator-owned validation
attempt. The current validation path is card data encrypted to the TEE, then
browser automation drives the Tinker/Stripe billing form and clears card
material from memory. The card channel and billing code now reach Stripe in the
local Neko session: a Stripe test card filled the live payment form and was
rejected with `Your card was declined.` Adding balance correctly fails closed
with `Payment method required before adding balance` when no real card is on
file. On 2026-07-08, the same local session produced bounded `payment_method`
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
│  1. GET /health ──→ email oracle ──→ cock.email address         │
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
   - Exposes `/health`, `/pin`, `/inbox` endpoints

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

# Add payment method through attestation-verified encrypted channel
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
missing, the same plan also emits absolute dry-run and broadcast commands for
`contracts/scripts/deploy-tinker-encumbrance-base-sepolia.sh`; the broadcast
helper uses Foundry `--account` through the encrypted keystore and must be run
from an interactive terminal so the keystore password is never placed in the
plan, command line, or repo. The current deployed encumbrance exists, but the
live cap is still `$5`; the `$10` Tinker-minimum flow remains blocked until the
owner raises the cap, the updated compose is redeployed, and the new compose
hash is approved.

The CLI card flags are for local test-card development only. Read
`docs/STRIPE-PCI-FUNDING-SCOPE.md` before any real-card attempt. The encrypted
card channel is an operator-owned capped validation path, not the default
production funding model.

### Artifact Upload

Use `upload-artifact` from the seller/controller side after a deal exists. The
command fetches `/attestation?context=artifact`, refuses local/default attestation unless
explicitly allowed, checks the expected compose hash/app ID and report-data-bound
public key, then encrypts the artifact to `POST /deal/{id}/artifact/encrypted`.
It prints only bounded metadata: deal ID, artifact hash, size, status code, and
server response.

```bash
.venv/bin/python -m tinker_delegate.main upload-artifact \
  https://delegate.example \
  1 \
  ./artifact.jsonl \
  --compose-hash 0xEXPECTED_COMPOSE_HASH \
  --app-id 0xEXPECTED_APP_ID
```

Local development can pass `--allow-local-attestation`, but production uploads
must use the dstack/TDX attestation path.

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
GET  /health              — service health + oracle email
GET  /attestation?context=ingress|artifact|billing — context-bound quote + public key
POST /auth/reauth         — bounded OTP re-auth, disabled unless explicitly enabled
GET  /billing/balance     — current Tinker balance
GET  /billing/funding-policy — bounded funding-mode policy
GET  /billing/funding-preflight — bounded operator funding readiness checks
GET  /billing/funding-receipts — bounded funding attempt audit records
GET  /billing/payment-method-status — bounded card-on-file status, no card details
POST /billing/card        — plaintext local-dev hook, disabled by default
POST /billing/card/encrypted — add payment method after attestation-verified encryption
POST /billing/card/remove — admin/operator payment-method removal
POST /billing/add-balance — add credit balance
POST /deal/{id}/artifact/encrypted — upload artifact encrypted to TEE key
POST /deal/{id}/artifact — plaintext local-dev hook, disabled by default
```

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
    "evidence_hash": "sha256...",
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
| `TINKER_ORACLE_AUTH_TOKEN` | *(empty)* | Local-dev bearer token for protected oracle `/pin` and `/inbox` calls |
| `TINKER_ORACLE_AUTH_KEY_PATH` | `oracle/runtime-auth` | dstack key path used to derive the same-CVM oracle bearer token |
| `TINKER_TINKER_CONSOLE_URL` | `https://tinker-console.thinkingmachines.ai` | Tinker console URL |
| `TINKER_EMAIL` | *(auto from oracle)* | Override email address |
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
├── oracle_client.py   # HTTP client for email oracle /pin /health /inbox
├── signup.py          # Browser automation: auth, onboarding, API key creation
├── billing.py         # Browser automation: Stripe card form, balance, auto-reload
├── card_channel.py    # Secure card delivery channel (encrypted in production)
├── crypto.py          # X25519 + AES-256-GCM encryption for card channel
├── session.py         # IsolatedTinkerSession: sandboxed SDK wrapper + cost meter
├── control_plane.py   # Deal lifecycle orchestration + output bounding
├── evaluator.py       # Stub + SFT evaluator agents
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
| `health()` | `GET /health` | Check oracle status, get email address |
| `get_email()` | `GET /health` | Extract oracle email from health response |
| `get_pin()` | `POST /pin` | Poll inbox with scoped OTP metadata and bearer auth; returns one bounded code plus request/use hashes |
| `list_inbox()` | `GET /inbox` | Debug: list recent emails; sends bearer auth when configured |

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
- **Local test-card result**: Stripe test card reaches submission and returns `Your card was declined.`
- **No-card funding result**: add-balance fails closed with `Payment method required before adding balance`
- **Deployed real-card validation**: the first approved real-card validation
  did not top up the account, but the later same-context reauth/add-balance
  packet reached `add_balance_submitted` with `raw_secret_egress=false`, replay
  verification passed with deployed attestation, and bounded balance read-back
  now reports `$10.00` without card details. The add-balance receipt remains
  conservative because explicit success copy was not observed; the balance read
  is the current funding evidence. This is still a one-off operator-owned
  validation path, not production/repeated funding.
- **Attempt records**: payment-method and add-balance responses expose bounded
  `surface`, `outcome`, `furthest_stage`, `issued_at`, `evidence_hash`,
  amount/balance bands, TDX quote hash when present, and card-payload
  destruction status; they do not return raw card fields or browser page bodies.
  Browser exception fallbacks publish only the classified outcome string while
  retaining the redacted exception behind `evidence_hash`.
- **Receipt storage**: bounded funding attempt records are persisted in the
  encrypted delegate store and can be read through `/billing/funding-receipts`.
  The store rejects unknown fields and any receipt claiming raw secret egress.
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
  `--output` writes the bounded preflight JSON.
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

In production (Phala Cloud), this runs alongside the email oracle in the same CVM:

```yaml
# docker-compose.dstack.yaml additions
services:
  delegate:
    environment:
      TINKER_CDP_URL: http://172.30.0.3:9222      # neko on internal network
      TINKER_ORACLE_URL: http://oracle:8000         # oracle service
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock   # TDX attestation
```

The API key is sealed via dstack-KMS after creation — only the same enclave can unseal it.

## What's Next

All core components are implemented. Remaining integration work:

- **Web frontend** — the public publication + interactive gate demo lives in [`web/`](web/) ("The Gate: Health", Vite + React + TS). It renders the deployment-locality spine, the four-stage pre-inference safeguards gate, a live gate simulator (with per-run attestation JSON), the health/bio app catalog, and the capability registry — all against synthetic data. Run `cd web && npm install && npm run dev`. This is the missing "Frontend: TBD" from the root README.
- **Deployment record** — see `docs/DEPLOYMENT-RUNBOOK.md` for the live Base Sepolia contract addresses, verification links, and current Phala CVM state
- **Deploy DiligenceRoom.sol** to Base Sepolia via `/forge-deploy`
- **On-chain watcher** — listen for DiligenceRoom events, call control plane API
- **Docker packaging** — the delegate image installs the `agent` extra from `uv.lock`; a local image run returns `/health.agent_stack_available=true`
- **Test SFT evaluator** end-to-end with real Tinker API key inside a deployed CVM
- **TEE deployment** — merge docker-compose with email oracle, deploy to Phala Cloud
- **API key sealing** — code uses the encrypted key store locally and `dstack_sdk.TappdClient.derive_key("tinker/api_key")` in dstack mode; deployed CVM validation is still pending
