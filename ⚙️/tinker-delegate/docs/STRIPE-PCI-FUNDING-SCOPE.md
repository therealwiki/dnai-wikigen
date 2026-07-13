# Stripe / PCI Funding Scope

Status: current technical stance, not legal advice.

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
operator -> attestation verifier -> encrypted payload -> TEE API
         -> TEE memory -> browser-controlled Stripe Elements iframe -> Stripe
```

[real] The implementation encrypts card details to an attestation-bound TEE
public key, decrypts inside the delegate process, fills the Stripe iframe through
browser automation, zeroes the parsed card object, suppresses card-bearing
screenshots, purges known secret-bearing browser debug artifacts, disables core
dumps in the delegate/browser compose path, returns bounded receipts, and caps
add-balance attempts before browser launch.

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
- The target endpoint is a deployed attested CVM endpoint, not an unverified
  local service.
- The client verifies `/attestation?context=billing`, expected compose hash,
  app ID when available, report-data key binding, public-key shape, and fetch
  freshness before encrypting.
- `TINKER_MAX_ADD_BALANCE_USD` is set to the approved cap for the attempt.
- Plaintext card API remains disabled.
- Debug screenshots are off unless a non-secret step is being inspected.
- Secret-bearing traces, HARs, videos, card screenshots, logs, and crash dumps
  are disabled or purged.
- The public result is limited to bounded receipts: outcome class, furthest
  stage, amount/balance band, evidence hash, quote hash when present, and card
  payload destruction status.

This mode is for proving the system can reach the clear add-payment/add-balance
attempt boundary. It does not authorize broad customer billing or repeated
production top-ups.

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
