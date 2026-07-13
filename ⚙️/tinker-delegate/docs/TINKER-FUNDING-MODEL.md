# Tinker Funding Model

Status: local policy enforced; live funding still not proven.

## Decision

The production funding model is **manual/developer prefund by default** until
Tinker exposes an official funding API, Stripe-hosted/tokenized collection, or
another support-approved route that can be verified without raw card custody.

The encrypted raw-card browser path remains only a one-off
operator-owned capped validation mode. It is not the production or repeated
funding model.

## Runtime Modes

`TINKER_FUNDING_MODE=manual_prefund`

- Default.
- Card automation is denied.
- Add-balance browser automation is denied.
- Balance checks and bounded funding receipts remain available.
- Use this for production-like deployments unless there is explicit approval to
  run a validation attempt.

`TINKER_FUNDING_MODE=operator_capped_validation`

- Allows encrypted card submission and add-balance browser automation.
- Must still obey `TINKER_MAX_ADD_BALANCE_USD`.
- The HTTP add-balance mutation endpoint remains separately disabled unless
  `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=true`.
- The plaintext card endpoint remains separately disabled unless
  `TINKER_ALLOW_PLAINTEXT_CARD_ENDPOINT=true`, and is still unavailable in
  dstack mode.
- Use only for an approved operator-owned test-card or real-card validation
  attempt.

`TINKER_FUNDING_MODE=official_tokenized`

- Reserved for a future official/tokenized route.
- Raw-card browser automation remains denied until that route is implemented.

## Public Inspection

Operators and clients can inspect the bounded policy surface without seeing
account, card, or credential state:

```bash
python -m tinker_delegate.main funding-policy
curl http://localhost:8080/billing/funding-policy
```

The response includes the funding mode, whether card/add-balance automation is
allowed, the configured add-balance cap, endpoint flags, raw-card scope, and the
next evidence required to advance funding validation.

Before a one-off operator validation attempt, run the bounded preflight:

```bash
python -m tinker_delegate.main funding-preflight \
  --amount 10 \
  --api-url https://delegate.example \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --fetch-attestation \
  --output ./preflight.json

curl 'http://localhost:8080/billing/funding-preflight?amount_dollars=10&api_url=http://localhost:8080&allow_local_attestation=true'
```

The preflight checks funding mode, amount cap, optional add-balance endpoint
flag, encrypted receipt-store availability, and billing attestation policy. It
does not accept card material and does not launch browser automation. The CLI
`--output` flag writes the same bounded preflight JSON to disk.

After an approved validation attempt, write bounded receipt artifacts directly
from the receipt-producing commands:

```bash
python -m tinker_delegate.main add-card-encrypted-prompt https://delegate.example \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --os-image-hash EXPECTED_OS_IMAGE_HASH \
  --receipt-output ./payment-method-receipt.json

python -m tinker_delegate.main add-balance 10 \
  --receipt-output ./add-balance-receipt.json
```

The prompt command keeps card fields out of shell history and process
arguments, requires deployed compose/app/OS-image attestation expectations
unless explicitly run in local-development mode, and refuses to print or write a
response that contains submitted card values or secret-shaped fields.

The Tinker UI currently accepts whole-dollar top-ups starting at `$10`, so the
delegate enforces `TINKER_MIN_ADD_BALANCE_USD=10.0` before browser launch. To
inspect payment-method state without leaking card metadata, use the bounded
status endpoint:

```bash
python -m tinker_delegate.main payment-method-status https://delegate.example \
  --auth-token-env TINKER_RUNTIME_AUTH_TOKEN

python -m tinker_delegate.main remove-card https://delegate.example \
  --auth-token-env TINKER_RUNTIME_AUTH_TOKEN \
  --receipt-output ./remove-card-receipt.json
```

The status output is limited to `card_on_file` and
`payment_method_count_band`; the removal command writes a bounded receipt. No
card brand, last4, expiry, address, or browser page text is exposed.

Build a bounded public manifest from the saved preflight and bounded receipt:

```bash
python -m tinker_delegate.main funding-manifest \
  --preflight-json ./preflight.json \
  --receipt-json ./payment-method-receipt.json \
  --validation-id operator-run-1 \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --os-image-hash EXPECTED_OS_IMAGE_HASH \
  --output ./funding-manifest.json

python -m tinker_delegate.main verify-funding-manifest \
  --preflight-json ./preflight.json \
  --receipt-json ./payment-method-receipt.json \
  --manifest-json ./funding-manifest.json \
  --validation-id operator-run-1 \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --os-image-hash EXPECTED_OS_IMAGE_HASH \
  --require-ready

python -m tinker_delegate.main funding-validation-packet \
  --output-dir ./funding-validation-packet \
  --api-url https://delegate.example \
  --amount 10 \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --os-image-hash EXPECTED_OS_IMAGE_HASH \
  --validation-id operator-run-1 \
  --receipt-json ./payment-method-receipt.json \
  --add-balance-receipt-json ./add-balance-receipt.json

python -m tinker_delegate.main check-funding-validation-packet \
  --packet-dir ./funding-validation-packet \
  --validation-id operator-run-1 \
  --compose-hash EXPECTED_COMPOSE_HASH \
  --app-id EXPECTED_APP_ID \
  --os-image-hash EXPECTED_OS_IMAGE_HASH \
  --require-add-balance \
  --require-deployed-attestation
```

The manifest publishes only hashes, bands, outcome, TDX quote hash,
card-destruction/no-raw-egress booleans, and the attestation-policy hash. It
rejects raw card, API-key, and secret-shaped inputs and does not prove funding
by itself; it is the audit envelope around the preflight/receipt pair. The
verifier recomputes the saved packet hashes and returns named bounded checks
without echoing the packet bodies. The packet runner writes the bounded
preflight, receipt, manifest, verification, and summary JSON artifacts in one
directory. It can also write a separate add-balance receipt, manifest, and
verification. To include an encrypted card submission, the operator must pass
`--run-card-attempt`; for approved real-card validation, add `--prompt-card` so
card fields are entered interactively instead of through command-line flags.
Prompt mode rejects missing deployed compose/app/OS-image expectations before
asking for card material unless local-development attestation is explicitly
allowed. Card fields without `--run-card-attempt` are rejected, and prompt mode
is mutually exclusive with test-card flags. To include a live top-up attempt,
the operator must pass `--run-add-balance-attempt` and `--amount`; the command
posts only the amount to `/billing/add-balance`. The packet checker
distinguishes an internally consistent local packet from a packet with live
deployed TDX evidence; pass `--require-deployed-attestation` before treating
packet evidence as deployed proof.

## Validation Boundary

What is real:

- The local test-card path reaches Stripe/Tinker submission and returns bounded
  `card_declined`.
- Add-balance fails closed without a payment method.
- Payment-method and add-balance browser automation use selector fallback
  families for Tinker billing controls and return bounded `selector_missing`
  receipts when top-up controls cannot be found.
- `add-card-encrypted-prompt` accepts approved operator card details
  interactively instead of through command-line flags and requires deployed
  attestation expectations unless explicitly run in local-development mode.
- `funding-validation-packet --prompt-card --run-card-attempt` brings the same
  interactive card-entry boundary into one-command packet generation and fails
  before prompting when deployed attestation expectations are missing.
- Funding attempts persist bounded encrypted receipts.
- Policy-denied card and add-balance requests persist bounded receipts without
  launching browser automation.
- Operator funding preflight returns bounded readiness checks before card
  payloads or browser automation.
- Funding preflight and billing receipt CLIs can write bounded validation JSON
  artifacts for later manifest binding.
- Funding validation manifests can be built from already-bounded preflight and
  receipt JSON.
- Funding validation manifests can be replay-verified against saved preflight,
  receipt, validation ID, and attestation policy inputs.
- Funding validation packet generation can produce the full bounded artifact
  directory from one command, either by binding an existing bounded receipt or
  by explicitly running encrypted card submission.
- Funding validation packets can include a separate add-balance evidence lane
  for low-value top-up attempts without merging it into the payment-method
  receipt.
- Funding validation packets can be replay-checked as directories, including
  optional add-balance and deployed-attestation requirements.

What remains partial:

- A live Phala encrypted-card attempt reached bounded payment-method UI copy,
  but it has not yet been proven to leave a usable card on file.
- A real-card low-value top-up was attempted, but the account balance stayed
  `$0.00`; add-balance stopped at a missing amount selector. The source fix is
  local/tested but not yet Phala-deployed.
- The deployed encumbrance still caps add-balance/spend at `$5`; it must be
  raised to `$10` before the next Tinker-minimum top-up attempt.
- No reusable payment-method token/reference is captured or persisted.
- Production or repeated card funding still requires legal/compliance approval.
