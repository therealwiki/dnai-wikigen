# Compute Console API

The Compute Console backend is a conservative, off-chain service-control
plane. It provides wallet-owned projects, encrypted device credentials,
closed-loop service credits, and bounded job records. It does **not** custody
payment cards, accept ETH or USDC deposits, expose the upstream Tinker key, or
claim provider-authoritative usage settlement.

All JSON request models reject unknown fields. Validation errors omit rejected
input values, so an accidentally submitted prompt, token, card number, or
training example is not reflected into the response.

## Security and capability labels

- Network: wallet messages require Base Sepolia chain ID `84532`.
- Compute wallet scope: `compute:console`.
- Compute credential scopes: `jobs:create`, `jobs:read`, `challenge:submit`,
  `submissions:read`, and `receipts:read`.
- The deal, Arena, Compute-wallet, Compute-credential, proxy, and runtime token
  domains have different JWT headers, issuers/audiences, and dstack key paths.
- Device binding means encrypted credential delivery to an X25519 public key.
  It is not hardware attestation or per-request proof-of-possession.
- Project credits are non-transferable, non-redeemable, off-chain service
  credits. One credit has a nominal display value of one US cent; it is not an
  on-chain token or a claim on the upstream provider account.
- The current job backend records and reserves work but does not dispatch it.
  Training is labeled `existing_tinker_training_proxy`; inference is labeled
  `future_inference_proxy`; both retain `dispatch_status: not_dispatched`.
- Internal settlement is `provisional_internal_metering`, not a provider
  invoice or provider-authoritative reconciliation.

## Authentication

`POST /auth/compute/challenge`

```json
{"address":"0x0000000000000000000000000000000000000000"}
```

The response contains `address`, one-time `nonce`, `message`, `issued_at`,
`expires_at`, `scope: "compute:console"`, and `chain_id: 84532`. The message
states that signing does not trigger a transaction or transfer funds.

`POST /auth/compute/token`

```json
{"nonce":"<32 lowercase hex>","signature":"<bounded hex EOA or EIP-1271 signature>"}
```

The response contains `access_token`, `token_type: "Bearer"`, `address`,
`scopes`, `issued_at`, and `expires_at`. Challenges default to five minutes and
wallet tokens to ten minutes; hard maxima are ten and fifteen minutes,
respectively.

EOAs use local EIP-191 recovery when contract verification is not configured.
When the operator supplies both `TINKER_WALLET_AUTH_RPC_URL` and
`TINKER_WALLET_AUTH_RPC_URL_SECONDARY` on distinct provider origins, the same
verifier used by Deal and Arena auth requires both providers to report Base
Sepolia and agree at one finalized block on its hash and exact wallet bytecode.
For contracts, both must return the exact EIP-1271 `0x1626ba7e` bytes4 result
from `isValidSignature(bytes32,bytes)`. Neither URL is request-selectable;
wrong-chain, divergence, timeout, malformed response, revert, or wrong magic
fails closed without provider fallback.
Response bytes, time, global concurrency, and `eth_call` gas are bounded. Each
nonce permits at most three sequential attempts and only one in-flight network
call outside the challenge-store lock; successful compare-and-delete still
permits exactly one exchange.

Pass the token as `Authorization: Bearer <token>`. Project, membership, device,
credential, balance, and ledger routes require the Compute wallet token. Job
create/read routes accept either a Compute wallet token or an active scoped
Compute device credential.

## Idempotency

Project creation, credit grants, job creation, public pre-dispatch
cancellation, and every internal job transition require `Idempotency-Key`. It must match
`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`. Replaying the same request returns the
original record with `idempotent_replay: true`; reusing a key for different
input returns HTTP `409`.

## Projects and membership

- `POST /compute/projects` with `{"name":"atlas-research"}`.
- `GET /compute/projects`.
- `GET /compute/projects/{project_id}`.
- `POST /compute/projects/{project_id}/members` with an EVM `address` and role
  `admin`, `developer`, or `viewer`.
- `DELETE /compute/projects/{project_id}/members/{address}`.

The signing wallet becomes immutable project owner. Owners and admins manage
non-owner membership. The fixed initial policy is:

```json
{
  "per_job_max_credits": 500,
  "daily_project_max_credits": 2500,
  "credential_max_ttl_seconds": 604800,
  "allowed_operations": ["inference", "training"]
}
```

There is intentionally no public cap-expansion route.

## Devices and Wikigen credentials

Register a locally generated X25519 public key:

`POST /compute/projects/{project_id}/devices`

```json
{
  "label": "local-codex",
  "kind": "developer_device",
  "public_key": "<64 hex characters>"
}
```

Kinds are `developer_device`, `ci_service`, and `autonomous_agent`. Read devices
with `GET /compute/projects/{project_id}/devices`; revoke one with
`POST /compute/projects/{project_id}/devices/{device_id}/revoke`. Revoking a
device immediately revokes all of its credentials.

Issue a credential:

`POST /compute/projects/{project_id}/credentials`

```json
{
  "device_id": "dev_...",
  "name": "atlas-agent-ci",
  "scopes": ["jobs:create", "jobs:read"],
  "expires_in_seconds": 604800,
  "daily_credit_cap": 500
}
```

The response returns the public credential record plus a one-time capsule:

```json
{
  "capsule": {
    "delivery": "x25519_aes_256_gcm_envelope",
    "encrypted_token": {
      "ephemeral_public_key": "...",
      "nonce": "...",
      "ciphertext": "..."
    },
    "associated_data": "...",
    "associated_data_hash": "...",
    "recipient_public_key_hash": "...",
    "plaintext_token_returned": false
  },
  "plaintext_token_returned": false,
  "upstream_tinker_key_exposed": false
}
```

Only the encrypted capsule contains the scoped delegate token. The store keeps
its JWT-ID commitment, generation, scope/cap metadata, and audit timestamps;
it never keeps the plaintext token or the upstream Tinker key.

- `GET /compute/projects/{project_id}/credentials` lists public records.
- `POST /compute/projects/{project_id}/credentials/{credential_id}/rotate`
  takes `{"expires_in_seconds":3600}` and returns a new capsule. The previous
  generation is immediately invalid.
- `POST /compute/projects/{project_id}/credentials/{credential_id}/revoke`
  invalidates the current generation.

Credential statuses are `active`, `expired`, and `revoked`.

## Service-credit balance and ledger

- `GET /compute/projects/{project_id}/balance` returns available, reserved, and
  total service credits and the non-transferable/non-redeemable flags.
- `GET /compute/projects/{project_id}/ledger?limit=100` returns up to 100 newest
  project transactions, their hash-chain links, and balanced postings.

The ledger is append-only through the service API. The durable state has a
full-state HMAC and each transaction commits to its predecessor. Every
transaction is double entry:

- testnet grant: project available / system testnet grant pool;
- job reserve: project available / project reserved;
- job settle: project reserved / service revenue / unused available refund;
- job release: project reserved / project available.

Only a configured runtime bearer may call
`POST /compute/internal/projects/{project_id}/grants`:

```json
{"amount_credits":1000,"reason":"operator_testnet_grant"}
```

The default single-grant cap is `100000` credits and the default total project
balance cap is `1000000`. Operator grants have `cash_value: false` and are for
testnet/product validation only.

## Jobs

Create a bounded metadata-only job with
`POST /compute/projects/{project_id}/jobs`:

```json
{
  "name": "bounded-sample-42",
  "operation": "inference",
  "model": "qwen3_8b",
  "recipe": "qwen3_8b_bounded",
  "max_credits": 100,
  "result_policy": "bounded_summary_receipt",
  "environment_version": "env_v1"
}
```

Training uses recipe `qwen3_8b_lora_r32`. Result policies are
`bounded_summary_receipt` and `score_band_hash`. A create atomically debits
available credits and credits reserved credits, but returns
`provider_dispatch_performed: false`. Raw prompts, examples, datasets, and
outputs are not accepted or stored by this API.

- `GET /compute/projects/{project_id}/jobs?limit=100`.
- `GET /compute/projects/{project_id}/jobs/{job_id}`.

An owner, admin, or developer may release a reservation before any work starts:

`POST /compute/projects/{project_id}/jobs/{job_id}/cancel`

```json
{"reason":"user_requested_before_dispatch"}
```

This route accepts only a Compute **wallet** bearer and a required
`Idempotency-Key`; device credentials and viewers cannot call it. Cancellation
is one atomic store commit containing the terminal job update, a balanced
`project reserved -> project available` ledger transaction, and its replay
record. It succeeds only when the job is exactly `queued`,
`dispatch_status: not_dispatched`, has no start/completion/metering/settlement
fields, and has exactly one open reservation. Running, provider-dispatched,
settled, released, and already-terminal jobs fail without moving credits.

The response is the exact bounded cancellation receipt below. It does not
return the wallet address, job inputs, arbitrary reason text, or current
project balance:

```json
{
  "surface": "compute_job_cancellation",
  "schema_version": 1,
  "project_id": "prj_...",
  "job_id": "job_...",
  "status": "canceled",
  "changed": true,
  "idempotent_replay": false,
  "released_credits": 100,
  "credit_reversal": "reserved_to_available",
  "ledger": {
    "transaction_id": "txn_...",
    "sequence": 3,
    "kind": "job_cancel",
    "transaction_hash": "<64 lowercase hex>",
    "previous_hash": "<64 lowercase hex>",
    "settlement_status": "user_canceled_before_dispatch"
  },
  "provider_dispatch_performed": false,
  "service_settlement_performed": false
}
```

An exact replay returns the same immutable ledger transaction with
`changed: false` and `idempotent_replay: true`. A different idempotency key
cannot release an already-canceled reservation a second time.

Job statuses are exactly `queued`, `running`, `succeeded`, `failed`, and
`canceled`.

Configured-runtime transitions are:

- `POST /compute/internal/projects/{project_id}/jobs/{job_id}/start` with an
  empty body. This records `running`; it does not dispatch work.
- `POST /compute/internal/projects/{project_id}/jobs/{job_id}/settle` with
  `actual_credits` no larger than the reservation,
  `usage_receipt_hash: "sha256:<64 lowercase hex>"`, and
  `metering_source: "operator_bounded_receipt"`. The response always states
  `provider_authoritative_settlement: false`.
- `POST /compute/internal/projects/{project_id}/jobs/{job_id}/release` with
  terminal status `failed` or `canceled` and reason `operator_failed`,
  `operator_canceled`, or `dispatch_unavailable`. This returns the entire open
  reservation.

## Separate exact-asset dispatch intents

The exact-asset execution journal is not the service-credit job store above.
It never reserves or settles Compute Credits and its public routes accept only
wallet-authenticated project metadata:

- `POST /compute/projects/{project_id}/dispatch-intents` creates a bounded
  intent only when the release capability explicitly permits the mutation.
- `GET /compute/projects/{project_id}/dispatch-intents/{job_reference}` returns
  one bounded lifecycle status. There is intentionally no public list route.

The creation model binds the canonical project and job IDs, wallet, exact
asset, authorization nonce, maximum base-unit debit, authorization deadline,
rate-policy commitment, compose hash, compiled operation/model/recipe, result
policy, and resource ceilings. It has no prompt, examples, dataset, arbitrary
program, output, payment receipt, or provider-credential field. The response
always states `legacy_credit_ledger_mutated: false` and
`provider_authoritative: false`.

`GET /compute/funding-capabilities` includes this fail-closed descriptor:

```json
{
  "dispatch_intents": {
    "metadata_intent_creation": false,
    "provider_dispatch": false,
    "independent_metering": false,
    "settlement": false,
    "exact_asset_only": true,
    "mutation_route": null,
    "status_route_template": "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
    "reason": "idempotent_tinker_provider_adapter_unavailable"
  }
}
```

The SolidJS client parses this object with an exact-key schema. It will not
POST unless metadata creation, provider dispatch, independent metering, and
settlement are all explicitly enabled, the mutation route is the compiled
route, and the selected project's `provider_dispatch_enabled` flag is also
true. Unknown fields, dependency inversions, or optimistic partial upgrades
fail closed. Status reads remain available to project members while mutation is
disabled.

The status stages are `intent_created`, `start_prepared`, `start_broadcast`,
`start_confirmed`, `provider_dispatching`, `usage_finalized`,
`metering_pending`, `metering_decided`, `settlement_prepared`,
`settlement_broadcast`, `settled`, and `blocked`. The public record exposes no
provider identifier, private workload, exact timing, actual debit, or meter
signature. Its intent commitment and bounded lifecycle flags are not a
provider-authoritative invoice.

There is no dispatch-journal cancellation route. Before CVM start, the owning
wallet may call the vault's `cancelJob` only after a pinned onchain read proves
state `Authorized`. After the signed deadline, anyone may call `expireJob` only
after the vault proves state `Authorized` or `Started`. The frontend therefore
hands users to the onchain vault tracker for both exits instead of inferring an
action from journal status alone.

## Funding boundaries: service credits versus exact-asset capacity

`GET /compute/funding-capabilities` reports the current capability state.
The delegate still exposes no card-number request model, checkout mutation,
user cash-equivalent grant, transfer, redemption, or browser-submitted payment
receipt. Closed-loop service credits remain an off-chain ledger and must stay
disabled for user funding until a provider-hosted checkout and independently
verified signed webhook are implemented. A redirect or client callback is not
funding evidence.

Base Sepolia exact-asset capacity is a separate on-chain ledger implemented by
`ComputeCreditVault`. The browser can call the release-pinned vault directly to
fund and withdraw ETH or the single release-pinned ERC-20; it does not send
those assets through this API, mint a token, convert them into service credits,
or trust an unconfirmed transaction hash. Job authorization remains fail-closed
until the exact contract runtime, roles, compose/TEE binding, asset policy,
rate-policy commitments, execution CVM, and independent metering CVM all match
the generated release manifest. The vault is reviewed and extensively tested
for testnet use, but this documentation makes no formal-audit claim.

## Deployment configuration

Production CVMs leave explicit keys empty and derive these separate paths:

- `TINKER_COMPUTE_WALLET_AUTH_KEY_PATH=tinker/compute_wallet_auth`
- `TINKER_COMPUTE_CREDENTIAL_KEY_PATH=tinker/compute_credentials`
- `TINKER_COMPUTE_STORE_INTEGRITY_KEY_PATH=tinker/compute_store_integrity`
- `TINKER_COMPUTE_STORE_PATH=/data/compute_console_state.json`
- `TINKER_WALLET_AUTH_RPC_URL=<primary HTTPS Base Sepolia JSON-RPC>` and
  `TINKER_WALLET_AUTH_RPC_URL_SECONDARY=<independent HTTPS Base Sepolia JSON-RPC>`
  are encrypted bootstrap secrets required by production compose to enable
  EIP-1271 for Compute, Arena, and Deal auth; local compose may leave both empty
  for EOA-only development. Partial or same-provider configuration is denied.

Local development must provide separate high-entropy values of at least 32
characters for `TINKER_COMPUTE_WALLET_AUTH_SIGNING_KEY`,
`TINKER_COMPUTE_CREDENTIAL_SIGNING_KEY`, and
`TINKER_COMPUTE_STORE_INTEGRITY_KEY`. An empty store path disables all Compute
writes fail-closed.

Run one API worker with this JSON store. Its lock is process-local; multi-worker
or multi-CVM service requires a shared transactional replacement.
