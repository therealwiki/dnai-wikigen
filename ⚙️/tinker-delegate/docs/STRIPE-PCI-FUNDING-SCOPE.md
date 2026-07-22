# Stripe / PCI Funding Scope

Status: current technical stance, not legal advice.

Product boundary: the eleven-route frontend does not collect card data. Its card
surface is roadmap-only and describes provider-hosted checkout followed by a
verified signed webhook that may issue closed-loop, non-transferable service
credits. Those credits are not `ComputeCreditVault` deposits or tokens. The
encrypted raw-card path documented below is retained only as a historical,
capped operator-validation mechanism; it is not an enabled customer flow and
is not part of the fresh release.

This note records the project stance for Tinker account funding before any real
card funding attempt. It is based on the official Stripe documentation linked
below and the current `tinker-delegate` implementation.

## Sources Checked

- Stripe Integration security guide:
  https://docs.stripe.com/security/guide
- Stripe Elements overview:
  https://docs.stripe.com/payments/elements
- Stripe Setup Intents:
  https://docs.stripe.com/payments/setup-intents
- Stripe Payment Intents / Setup Intents lifecycle:
  https://docs.stripe.com/payments/paymentintents/lifecycle

## Stripe Guidance That Matters Here

Stripe's security guide says PCI DSS applies to entities that store, process,
or transmit cardholder or sensitive authentication data. Stripe also says that
using low-risk Stripe integrations can collect and transmit card information
directly to Stripe without the data passing through the project's servers,
reducing PCI obligations.

Stripe Elements is designed so Stripe.js tokenizes sensitive payment details
inside the Element without card details touching the merchant server. Stripe's
Setup Intents flow exists for saving payment methods for future use, can trigger
required authentication, and requires appropriate customer permission for future
on-session or off-session use.

## Current Implementation Classification

The current encrypted-card path is safer than plaintext delivery but is not the
preferred production compliance posture:

```text
operator -> independent DCAP/QVL verifier -> encrypted payload -> TEE API
         -> TEE memory -> browser-controlled Stripe Elements iframe -> Stripe
```

[partial] The implementation can encrypt card details to the public key carried
in a context-bound attestation envelope, decrypt inside the delegate process,
fill the Stripe iframe through browser automation, zero the parsed card object,
suppress card-bearing screenshots, purge known secret-bearing browser debug
artifacts, disable core dumps in the delegate/browser compose path, return
bounded receipts, and cap add-balance attempts before browser launch. The
service does not independently validate its own TDX quote, so its public
`verified` field remains `false` even when dstack returns quote bytes.

[partial] Even with those controls, the project's API and TEE process still
process and transmit raw cardholder data before Stripe tokenization. That means
the raw-card encrypted channel should be treated as a tightly controlled
operator validation path, not a default production customer-payment flow.

[planned] Production or repeated funding should prefer one of:

1. An official Tinker-supported funding route that avoids this project handling
   card data.
2. A Stripe-hosted or Stripe-tokenized flow, such as Checkout, Payment Element,
   or SetupIntent/PaymentMethod collection, where raw card details do not pass
   through `tinker-delegate`.
3. A manual invoice or developer-prefunded balance model until an approved
   tokenized path exists.

## Allowed Funding Modes

### Local Test Card

Allowed for development. Use Stripe test cards only. The path may exercise
selectors, iframe filling, error handling, receipt persistence, screenshot
suppression, debug-artifact purging, and add-balance policy checks. It must not
be described as production funding.

### One-Off Operator-Owned Real Card Validation

Allowed only as an explicitly capped validation attempt after all of the
following are true:

- The operator/card owner initiates the attempt and provides details out of
  band.
- The target endpoint is a deployed CVM whose fresh quote has been validated by
  an independent DCAP/QVL verifier, not merely an endpoint returning quote bytes.
- The independent verifier validates quote signature and collateral/TCB status,
  enforces the expected measurements/app/compose/OS policy, and binds the quote's
  report data to the billing public key. The service's own `verified=false`
  value is expected and is never upgraded based on quote presence alone.
- `TINKER_MAX_ADD_BALANCE_USD` is set to the approved cap for the attempt.
- Plaintext card API remains disabled.
- Debug screenshots are off unless a non-secret step is being inspected.
- Secret-bearing traces, HARs, videos, card screenshots, logs, and crash dumps
  are disabled or purged.
- The public result is limited to bounded receipts: outcome class, furthest
  stage, amount/balance band, evidence hash, quote hash when present, and card
  payload destruction status.
- Public billing errors and persisted `bounded_message` values are exact
  `AutomationOutcome` enum codes, never Stripe/browser/page sentences.
- Receipt evidence hashes commit only to the canonical bounded projection;
  private sentences, URLs, selectors, card text, and timestamps cannot affect
  the hash. Persisted receipts are rejected unless that hash recomputes exactly.
- `GET /billing/balance` requires configured runtime or `billing:balance`
  proxy authentication and emits only a stable band. Exact currency remains
  inside the enclave.
- Receipt-store failures emit only `store_failed` and never storage exceptions.

This mode is for proving the system can reach the clear add-payment/add-balance
attempt boundary. It does not authorize broad customer billing or repeated
production top-ups.

The independent quote-verifier handoff is not yet implemented in the bundled
Python upload client. Until it is, deployed-TDX card submission remains blocked
by the client; only the explicit local test-card path is runnable end to end.

### Production / Repeated Funding

Do not use the raw-card encrypted channel as the default production path until a
qualified compliance review approves it. The production funding path should use
official Tinker support, Stripe-hosted/tokenized collection, SetupIntent /
PaymentMethod style reuse with required consent, or manual/developer prefunding.

## Open Follow-Up Work

- Ask Tinker for an approved funding or service-account path.
- Decide whether the product ever accepts third-party customer payment methods,
  or only operator-owned developer funding.
- If Stripe-owned tokenization is possible, build a token/reference handoff that
  stores only Stripe/Tinker safe references and never sends raw card fields to
  the TEE API.
- Add deployed-CVM log verification for the encrypted card path before the
  one-off operator-owned real-card validation.
- Obtain legal/compliance review before production or customer funding.
