# Tinker Automation Route

Status: source/local policy is real; deployment observations are historical
prior-operator evidence. The fresh project-owned release is undeployed.

This document records the acceptable automation route for the TEE-owned Tinker
account. It is a project control, not a legal conclusion or vendor approval.
Production use still requires a fresh project-owned CVM probe, independent
challenge-v2 / verdict-v4 quote verification under the exact release lineage,
and the compliance approvals tracked in `TODO.md`.

## Decision

The preferred production route is, in order:

1. An official Tinker API, support-approved account workflow, or approved
   service-account flow.
2. Manual/developer prefunding or invoice-style funding when Tinker provides no
   approved billing automation path.
3. Browser automation only for an account controlled by this project, only
   through ordinary headed/headful browser surfaces, and only when it remains
   explainable to Tinker and Stripe as TEE custody of the project's own account.

Browser automation is acceptable only as a bounded account-custody mechanism:
the TEE requests the magic-code email, reads OTPs through the authenticated
oracle, completes Tinker console flows, stores the API key in sealed storage,
and emits bounded receipts. It is not a mechanism for bypassing access controls,
evading anti-abuse systems, or presenting third-party identities as human
operators.

## No-Evasion Rule

The Tinker delegate must fail closed instead of adding or relying on:

- stealth browser plugins or patched anti-detection drivers,
- `navigator.webdriver` or automation-control masking,
- rotating proxies, residential proxy routing, or IP reputation laundering,
- user-agent spoofing intended to hide automation,
- CAPTCHA-solving services for Tinker or Stripe account/billing flows,
- credential sharing with a human operator outside the TEE boundary.

If Tinker or Stripe blocks the flow, the correct response is to record a bounded
failure receipt, preserve no raw OTP/API-key/card material in logs or artifacts,
and switch to an official/support-approved route or a manual funding route.

## Current Evidence

- Historical prior-operator/local evidence from 2026-07-08 reached the external
  Tinker auth flow: email OTP arrived through the oracle, onboarding completed,
  and API-key provisioning captured a one-time `tml-...` key. This does not
  establish current account custody or fresh-release activation.
- Historical local billing automation reached the Stripe Elements form and a
  Stripe test card returned the bounded `card_declined` outcome.
- Replayable mock-page tests cover auth, OTP entry, onboarding, API-key
  creation, billing, Stripe iframe selection, and add-balance controls.
- Static tests reject common stealth, CAPTCHA-solving, rotating-proxy, and
  automation-control masking dependencies or flags in the runtime package,
  dependency manifest, and compose files.

## Still Not Solved

- The packaged Phala CVM browser posture has not been freshly validated.
- No fresh project-owned endpoint is deployed. The older prior-operator
  endpoint did not establish a current encrypted card-update/add-balance path
  under the fresh release lineage and independent quote-verification gates.
- Production or repeated card funding is not approved by this document; see
  `STRIPE-PCI-FUNDING-SCOPE.md`.
