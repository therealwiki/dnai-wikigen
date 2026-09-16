# Tinker-Delegate — Spec

> **Status**: Draft
> **Date**: 2026-03-08
> **Context**: NDAI / tinker-deligate hackathon
> **Depends on**: TEE Email Oracle (`⚙️/tee-email-oracle/SPEC.md`)

> **Deployment provenance**: Every concrete Base Sepolia address, transaction,
> Phala CVM/app ID, balance, and live probe below is retained as historical
> prior-operator evidence. It is not controlled by the current release
> operator and does not authorize this working tree. No fresh project-owned
> seven-contract suite or seven-CVM topology has been deployed for this release.

## 1. Problem

The NDAI evaluator agent needs to assess the value of private artifacts (datasets, training recipes, reward functions) inside a TEE. Looking at data isn't enough — the most honest evaluation is to **train a model on it and measure the result**. But the trained model is an information-theoretic derivative of the seller's data. If it leaks, the seller loses leverage exactly as if the raw data leaked.

We need:

1. A Tinker account that **exists only inside the TEE** — no human holds credentials
2. An evaluator agent that can **train and sample** from models it creates for a specific deal
3. **Session isolation** — the agent cannot access models from other deals or the wider account
4. **Mandatory cleanup** — all trained models are destroyed when the deal resolves
5. **Bounded outputs only** — quality scores and offer prices leave the TEE, never weights or raw samples

## 2. Key Decisions

| Decision | Resolution |
|---|---|
| **Who pays Tinker compute?** | The buyer. Compute cost is deducted from their escrow alongside the deal payment. |
| **How is the Tinker account funded?** | Pre-funded by the developers (us) is still the intended production model. `TINKER_FUNDING_MODE=manual_prefund` denies raw-card/add-balance browser automation by default; the encrypted raw-card channel is limited to opt-in `operator_capped_validation` for a one-off capped operator-owned validation path. Runtime bearer auth protects operator-only mutation endpoints when `TINKER_RUNTIME_AUTH_REQUIRED=true`: `/auth/reauth`, `/billing/card/encrypted`, `/billing/add-balance`, `/billing/funding-receipts`, and the explicitly local plaintext card endpoint. `GET /billing/balance` always requires configured runtime auth or a proxy JWT with `billing:balance` and returns only a stable band. `TinkerAccountEncumbrance.sol` adds an on-chain policy/audit surface; the Base Sepolia deployment at `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e` has `$10` add-balance/spend caps after tx `0x3ab263bb7cb7758787fa1136dd043cca002db9cf511b29ad20ef4d1216199d3f`. The low-value operator-validation lane has proven funding: bounded packet `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` reached `add_balance_submitted` with `raw_secret_egress=false`, replay verification passed with deployed attestation, and the current public balance read returns `10_100_usd` rather than exact currency. This remains non-production: the live CVM still uses dev/debug posture, production/repeated funding needs official Tinker or Stripe-hosted/tokenized rails plus compliance review, and the latest live client-config compose `0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085` still needs on-chain approval before it can be used for the next compute-smoke lane. |
| **Fee structure** | 1% surcharge on top of raw Tinker API costs, paid to the developer account. |
| **Evaluation protocol** | Up to the agent and its owner (the buyer). The agent decides base model, steps, benchmarks autonomously. |
| **`ttl_seconds` on checkpoints** | Mandatory on every save. Dead man's switch — Tinker auto-deletes even if our cleanup never runs. |
| **Tinker console automation** | **PARTIAL**: Local Neko/CDP + Playwright works for passwordless magic-code auth, onboarding, and API-key provisioning as of 2026-07-08. API-key provisioning now has selector fallback families, aria-label/data-testid variants, bounded `api_key_provisioning` attempt records, and replayable mock-page tests for successful extraction and selector failures. `tinker-delegate selector-map` emits the bounded selector/frame/auth-flow contract for email auth, OTP, onboarding, API-key creation, billing, Stripe iframe, balance top-up, and auto-reload surfaces with a recomputable map hash and no raw account, OTP, API-key, card, page-text, cookie, or browser-session output. `tinker-delegate selector-probe` is the read-only live browser observation command for deployed evidence: it does not navigate, click, type, screenshot, or capture page text, and emits only URL classes/hashes, selector match bands, frame kinds, selector-map hash, and bounded failure JSON. In source/tests and Phala one-shot evidence, selector-probe now falls back to raw CDP when Playwright attachment fails: it uses `Target.getTargets`, `Target.attachToTarget`, `Runtime.evaluate`, and `Page.getFrameTree` to emit bounded target/page/frame/selector-family inventory, URL classes/hashes, frame kinds, stage/error bands, and bounded raw-CDP failure receipts only; per-page attach/frame-tree failures preserve page URL classes/hashes and bounded error kinds without raw URL/page-text egress. The GitHub-attested `a384db2` Phala run returned `success=true`, target count `2+`, page count `1`, `pages_observed=1`, one page observation, `attached=true`, `frame_tree_error_kind=timeout`, `partial_error_kind=frame_tree_timeout`, empty frame observations, and `raw_secret_egress=false`; normal compose was restored and both diagnostic endpoints returned 403. Runtime selector-family counting is source/test-real but not yet Phala-proven; `Page.getFrameTree` still times out before deployed frame inventory. `GET /browser/selector-probe` wraps that same probe for one-shot deployed evidence capture but is disabled by default and returns 403 unless `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true`. `tinker-delegate browser-readiness` and `GET /browser/readiness` now diagnose browser-control availability with endpoint classes/hashes, CDP metadata reachability, raw WebSocket upgrade stage bands, one-command CDP protocol probe bands, Playwright/CDP handshake bands, and bounded error kinds only; they do not navigate, click, type, screenshot, inspect page text, expose raw browser URLs, or return CDP response bodies. The raw WebSocket stage keeps the advertised debugger URL in memory only and emits URL class/hash, TCP/TLS/upgrade stage booleans, HTTP status band, and bounded error kind. The post-upgrade protocol probe sends one browser-scoped `Browser.getVersion` command and emits only command/response booleans, response kind, browser family, URL class/hash, status band, and bounded error kind. The selector and readiness endpoints have now been Phala-proven with GitHub-attested images: `7973b27` proved the raw WebSocket stage reaches HTTP `101`, and `59a9eac` proved the post-upgrade CDP protocol command returns a bounded Chromium `result` response while Playwright `connect_over_cdp` still times out. The selector profile returned bounded `browser_unavailable` JSON with `raw_secret_egress=false`; then normal compose was restored and both endpoints returned 403. Startup bootstrap preserves the last bounded attempt record in `/health.runtime.last_bootstrap_attempt_record` for successful API-key provisioning, selector/API-key failures, and early `tinker_auth` failures across account lookup, CDP/browser connection, context/page setup, auth, and onboarding. Those records expose no raw mailbox, OTP, URL, page text, or API key. A bounded local `reauth` path can refresh OTP auth and returns only `tinker_auth` receipt metadata; source/tests now save successful browser auth `storage_state` into encrypted `/data/browser_session.enc` with a separate `tinker/browser_session` dstack key path, and billing loads that sealed state for fresh contexts. The delegate Docker image now installs the optional Tinker SDK and a local image run reports `/health.agent_stack_available=true`. Phala one-shot bootstrap attempts have now failed closed first at Tinker auth with `auth_access_blocked`, then under headed Neko CDP with generic `bootstrap_error`, then with bounded `tinker_auth` `unknown_failure`; the latest Phala retry preserves that nested outcome in top-level `bootstrap_error_kind`. Production bootstrap is not solved because no API key has been sealed in the CVM, and browser-session persistence still needs GitHub-attested image deployment plus Phala repro. |
| **Plaintext card API** | Disabled by default and unavailable in dstack mode. The normal API path is `/billing/card/encrypted` after quote verification; plaintext card JSON is only an explicit local-development test hook. |
| **Oracle boot authorization** | Governed on-chain by oracle compose hash policy. The oracle's own code authorization is frozen permanently after production sign-off; fresh TDX quotes continue to verify against that frozen policy. |
| **OTP consumer authorization** | Managed separately from oracle code authorization. Current same-CVM runtime enforcement uses a bearer token derived from the shared dstack key path; full on-chain consumer-registry checks remain pending. |

## 3. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        dstack CVM (Intel TDX)                         │
│                                                                        │
│  ┌─────────────────┐    ┌───────────────────┐    ┌────────────────┐  │
│  │ Control Plane    │    │ Evaluator Agent    │    │ Email Oracle    │  │
│  │ (Python)         │    │ (A_B from NDAI)    │    │ (cock.li IMAP) │  │
│  │                  │    │                    │    │                 │  │
│  │ - escrow watcher │    │ - receives artifact│    │ - signup OTP    │  │
│  │ - deal lifecycle │    │ - trains via Tinker│    │ - future OTPs   │  │
│  │ - output bounding│    │ - benchmarks model │    │ - attestation   │  │
│  │ - cleanup        │    │ - emits score+offer│    │                 │  │
│  └────────┬─────────┘    └────────┬───────────┘    └────────────────┘  │
│           │                       │                                     │
│           │    ┌──────────────────┴──────────────────┐                 │
│           │    │      IsolatedTinkerSession           │                 │
│           │    │      (SDK wrapper)                   │                 │
│           │    │                                      │                 │
│           │    │  - one training run per deal          │                 │
│           │    │  - path-checked sampling              │                 │
│           │    │  - no downloads, no publishing        │                 │
│           │    │  - cleanup() deletes all checkpoints  │                 │
│           │    └──────────────────┬──────────────────┘                 │
│           │                       │                                     │
│  ┌────────▼───────────────────────▼──────────┐                         │
│  │           Tinker SDK (ServiceClient)        │                        │
│  │           TINKER_API_KEY from KMS           │                        │
│  └────────────────────┬───────────────────────┘                         │
│                       │                                                  │
│  ┌────────────────────▼───────────────────────┐                         │
│  │           dstack-KMS (sealed storage)        │                        │
│  │  derive_key("tinker/api_key")               │                        │
│  │  derive_key("email/creds")                  │                        │
│  └─────────────────────────────────────────────┘                         │
│                                                                          │
│  tappd.sock → TDX Quote on every response                               │
└──────────────────────────────────────────────────────────────────────────┘
        │                                        │
        │  HTTPS (Tinker API)                    │  HTTPS (Base Sepolia RPC)
        ▼                                        ▼
┌──────────────────┐                  ┌─────────────────────┐
│ Tinker Platform   │                  │ DiligenceRoom.sol   │
│ thinkingmachines  │                  │ (Base Sepolia)      │
│ .ai               │                  │ escrow + lifecycle   │
└──────────────────┘                  └─────────────────────┘
```

## 4. Components

### 4.1 TEE Genesis (One-Shot)

The CVM boots and creates the Tinker account. This runs once, then the signup automation is discarded.

**Sequence:**

```
PHASE 0: EMAIL
  Email oracle creates cock.li account
  → seals credentials via derive_key("email/creds")
  → emits TDX attestation binding email address

PHASE 1: TINKER SIGNUP  LOCAL VALIDATED — deployed CVM validation pending
  Neko browser → tinker-console.thinkingmachines.ai → auth.thinkingmachines.ai
  → enter cock.email address → Continue → magic-code page (6-digit OTP)
  → delegate calls authenticated email oracle POST /pin for the single
    allowlisted Tinker OTP capability (fixed exact sender + fixed six-digit
    pattern; no caller-selected subject or regex); raw mail metadata stays sealed
  → enter code into 6x input[inputmode="numeric"] boxes → authenticated
  → complete onboarding form (name + TOS checkbox) → welcome page
  → navigate to /keys → click "New key" → click "Generate key"
  → capture one-time tml-... API key
  → seal via encrypted key store locally or derive_key("tinker/api_key") in dstack
  → return only bounded key hash/status metadata
  → emit TDX attestation: {email, tinker_account_id, enclave_identity}

  HISTORICAL FINDING: cock.li and firemail.cc domains were blocked by Thinking
  Machines while cock.email was previously observed to pass the blocklist.
  CAPTCHA FINDING: a source-level fix now tracks cock.li's current form
  contract: fill `password_confinm`, leave the `password_confirm` honeypot
  empty, and mirror `csrf_valid`. A fresh Phala auto-genesis debug CVM with the
  fixed, GitHub-attested oracle image reached IMAP verification. That proof also
  showed public `/health` exposed the generated mailbox address, so source now
  bounds public `/health` and `/attestation` to readiness plus
  `oracle_email_hash`. A historical intermediate build moved raw address
  retrieval to runtime-authenticated `/email`; that design is now superseded.
  `/inbox` is absent, and `/email` returns only readiness, a domain-separated
  address commitment, its scheme, and `raw_email_egress=false`. Account
  automation must receive the raw address through an in-CVM sealed/bootstrap
  path rather than an HTTP response. A second Phala debug proof with the older
  bounded-health image confirmed public `/health` and `/attestation` returned
  `oracle_email=""` with hash-only readiness; that proof predates the stronger
  commitment-only `/email` boundary.
  MAIN-CVM MAILBOX FINDING: a one-shot main Phala CVM deployment using
  `docker-compose.mailbox-genesis.phala.yaml` generated and sealed the mailbox
  while Tinker bootstrap, billing, add-balance, API-key provisioning, and
  credential provisioning stayed disabled. The CVM was redeployed back to the
  normal compose with `ORACLE_AUTO_GENESIS=false`; public health still reports
  `oracle_ready=true`, `imap_connected=true`, `oracle_email=""`, and only
  `oracle_email_hash`.
  CURRENT FINDING: the local Neko browser path works end to end through API-key
  capture. The main CVM now has a sealed mailbox ready for OTPs, and the
  one-shot deployed bootstrap profile has been reworked and Phala-tested with
  headed Neko CDP instead of the Playwright sidecar, but production
  OTP/login/API-key bootstrap is still not solved.
  PHALA TINKER BOOTSTRAP FINDING: `docker-compose.tinker-bootstrap.phala.yaml`
  is the bounded one-shot profile for deployed probes. It keeps oracle genesis,
  credential provisioning, and add-balance disabled, enables only
  `TINKER_BOOTSTRAP_SIGNUP=true`, uses headed Neko CDP, and is reverted to the
  normal compose after bounded success/failure evidence is collected. The first
  live Phala run, using the old Playwright sidecar path, reached the Tinker
  auth surface and failed closed with `bootstrap_error_kind=auth_access_blocked`.
  The headed-Neko CDP retry verified the intended packaging and endpoint gates
  but failed closed with generic `bootstrap_error` before a bounded stage
  receipt or API-key capture. A later retry with GitHub-attested `74ad4b6`
  images proved the bounded early-stage receipt path in Phala:
  `/health.runtime.last_bootstrap_attempt_record` reported
  `surface=tinker_auth`, `outcome=unknown_failure`,
  `furthest_stage=not_started`, and `raw_secret_egress=false`. The outer
  `bootstrap_error_kind` still flattened to generic `bootstrap_error` in that
  live run. A follow-up Phala retry with GitHub-attested `8fb6e3a` images
  proved the top-level preservation fix:
  `/health.runtime.bootstrap_error_kind=unknown_failure` now matches the
  bounded nested receipt. No API key was created, no card or add-balance path
  was opened, and the normal compose was restored after each attempt.
  SELECTOR PROBE ENDPOINT FINDING: source now includes a disabled-by-default
  `GET /browser/selector-probe` route for one-shot deployed selector/frame
  capture. It requires `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true`, performs the
  same bounded read-only probe as the CLI, and returns bounded
  `browser_unavailable` JSON on browser errors.
  PHALA SELECTOR PROBE FINDING: GitHub-attested `59a9eac` oracle/delegate images
  were pinned into the one-shot bootstrap profile with
  `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true` and
  `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=true`. The readiness endpoint
  returned bounded `cdp_timeout` after successful CDP metadata discovery, raw
  WebSocket TCP connect, HTTP Upgrade status band `101`, and a successful
  one-command CDP protocol probe: `Browser.getVersion` returned a bounded
  Chromium `result` response. The selector endpoint returned HTTP 503 with
  bounded `browser_unavailable`, `bounded_output=true`, `read_only=true`, and
  `raw_secret_egress=false`. The CVM was restored to normal compose afterward,
  and both endpoints returned 403. This proves the deployed endpoint
  gates/fail-closed paths and the basic DevTools protocol path, but not actual
  selector/frame matches, because Playwright `connect_over_cdp` still times out.
  A later GitHub-attested `f63dd18` one-shot run proved the raw-CDP selector
  fallback reaches metadata, WebSocket Upgrade status band `101`, and
  `Target.getTargets`, returning bounded target count `2+` and page count `1`.
  `Page.getFrameTree` still timed out, so frame inventory and deployed DOM
  selector counts remained incomplete. The CVM was restored to normal compose
  afterward, and both diagnostic endpoints returned 403.
  A later GitHub-attested `a384db2` one-shot run proved the timeout-preserving
  page target receipt on Phala: selector-probe returned `probe_backend=raw_cdp`,
  `success=true`, target count `2+`, page count `1`, `pages_observed=1`, one
  bounded page URL class/hash, `attached=true`,
  `frame_tree_error_kind=timeout`, `partial_error_kind=frame_tree_timeout`,
  empty frame observations, and `raw_secret_egress=false`. The CVM was restored
  to normal compose afterward, and both diagnostic endpoints returned 403.
  Source/tests now add a bounded raw-CDP `Runtime.evaluate` selector-family
  counter that emits only declared flow/family names plus `0`, `1`, `2+`, or
  `probe_error` bands. Source/tests now run a constant page-scoped Runtime
  micro-probe before the selector matrix and emit only
  `runtime_micro_probe_command_success`, `runtime_micro_probe_success`, and
  `runtime_micro_probe_error_kind`; this narrows the next deployed diagnosis
  without exposing page text, raw DOM, selectors, URLs, cookies, OTPs, API keys,
  or card material. A 2026-07-08 Phala one-shot run with GitHub-attested
  `50de0a9` images proved the deployed route still returns bounded raw-CDP
  output, but the page-scoped Runtime selector command timed out. A follow-up
  Phala one-shot run with GitHub-attested `5943c61` images proved that even the
  constant page-scoped Runtime micro-probe times out after page attach:
  `partial_error_kind=runtime_micro_probe_timeout`,
  `runtime_micro_probe_command_success=false`,
  `runtime_micro_probe_error_kind=timeout`,
  `runtime_selector_command_success=false`, and `flow_observations=[]`. This
  narrows the deployed blocker to Runtime command delivery/evaluation in the
  Neko/CDP path, not selector-expression complexity. The CVM was restored to
  normal compose afterward at live hash
  `6ead86a6f857f12210b9dd7656fbd54a2547795538a60f28bb9404165e3166fd`, and
  `/browser/readiness`, `/browser/selector-probe`, and `/billing/add-balance`
  returned 403. Selector-family match capture remains not Phala-proven; next
  source/test-real diagnosis now adds bounded `Runtime.enable` and
  execution-context event bands before the micro-probe:
  `runtime_enable_command_success`,
  `runtime_execution_context_event_observed`, `runtime_enable_success`,
  `runtime_enable_error_kind`, `runtime_event_before_enable_response`,
  `runtime_event_count_band`, and `runtime_execution_context_created`. It emits
  no event payloads, context IDs, frame IDs, raw URLs, page text, selectors,
  cookies, OTPs, API keys, or card material. A 2026-07-08 Phala one-shot run
  with GitHub-attested `9d69364` images proved `Runtime.enable` itself times
  out on the attached page session before any micro-probe or selector
  evaluation: `partial_error_kind=runtime_enable_timeout`,
  `runtime_enable_command_success=false`,
  `runtime_execution_context_event_observed=false`,
  `runtime_enable_error_kind=timeout`, `runtime_event_count_band=0`,
  `runtime_execution_context_created=false`,
  `runtime_micro_probe_command_success=false`,
  `runtime_selector_command_success=false`, `flow_observations=[]`, and
  `raw_secret_egress=false`. The CVM was restored to normal compose afterward
  at live attested compose hash
  `54ee243db5605588550d670fcc767ba17b49407e76613b633ddc7eee44494eb2`, and
  `/browser/readiness`, `/browser/selector-probe`, and `/billing/add-balance`
  returned 403. Source/tests now add a direct page-target WebSocket route for
  that blocker: if attached-session `Runtime.enable` fails, the probe fetches
  bounded page-target inventory from `/json/list`, connects directly to the
  matching page target WebSocket, and retries `Runtime.enable`, the constant
  micro-probe, and selector-family matrix on that direct connection. The nested
  `direct_page_runtime` receipt emits only page-list success, page-WebSocket
  availability, Runtime enable/error/event-count bands, micro-probe
  success/error, selector success/error, and declared selector-family count
  bands. It emits no raw page URLs, WebSocket URLs, event payloads, context IDs,
  frame IDs, page text, selectors, cookies, OTPs, API keys, or card material.
  A 2026-07-08 Phala one-shot run with GitHub-attested `bf39f56` images proved
  the direct page-target route reaches `/json/list` and the page WebSocket, but
  direct page `Runtime.enable` still times out:
  `direct_page_runtime_attempted=true`,
  `direct_page_runtime.page_list_success=true`,
  `direct_page_runtime.page_websocket_available=true`,
  `direct_page_runtime_enable_success=false`,
  `direct_page_runtime.runtime_enable_error_kind=timeout`,
  `direct_page_runtime_micro_probe_success=false`,
  `direct_page_runtime_selector_success=false`, empty `flow_observations`, and
  `raw_secret_egress=false`. The CVM was restored to normal compose afterward
  at live attested compose hash
  `382aa6c881d477724552f4445157afbcd75738ee1feb9603b982b75ec4e82c2c`, and
  `/browser/readiness`, `/browser/selector-probe`, and `/billing/add-balance`
  returned 403 with the current request schema. Selector-family match capture
  remains not Phala-proven; the remaining deployed blocker is Neko/Chrome
  Runtime-domain behavior itself, not just attached-session routing. Source/tests
  now add a bounded `Page.enable` discriminator before `Runtime.enable` on both
  attached-session and direct page-target paths. It emits only
  `page_enable_command_success`, `page_enable_success`, and
  `page_enable_error_kind`, so the next Phala run can distinguish page-domain
  command delivery from Runtime-domain enablement without exposing page text,
  raw URLs, selectors, cookies, OTPs, API keys, card material, event payloads,
  frame IDs, or execution-context IDs. A follow-up 2026-07-08 Phala one-shot
  run with GitHub-attested `556387a` images proved that `Page.enable` itself
  times out on both attached-session and direct page-target paths:
  `partial_error_kind=page_enable_timeout`,
  `page_enable_command_success=false`,
  `direct_page_runtime.page_list_success=true`,
  `direct_page_runtime.page_websocket_available=true`,
  `direct_page_runtime.page_enable_success=false`,
  `direct_page_runtime.page_enable_error_kind=timeout`, no Runtime micro-probe,
  no selector-family matrix, empty `flow_observations`, and
  `raw_secret_egress=false`. The CVM was restored to normal compose afterward
  at live attested compose hash
  `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`, and
  `/browser/readiness`, `/browser/selector-probe`, and `/billing/add-balance`
  returned 403. The remaining deployed blocker is now lower-level page CDP
  command delivery through the Phala Neko path. A 2026-07-09 one-shot run with
  the tracked `docker-compose.selector-diagnostics.phala.yaml` profile repeated
  the measurement against the current GitHub-attested `eb3bde3` funding
  validation images. The diagnostic profile used registry images only,
  disabled Tinker bootstrap and every card/funding mutation, and enabled only
  `/browser/readiness` plus `/browser/selector-probe`. The live one-shot
  attested compose hash was
  `170862495089566bbe75a0c95f8cc8c1267cb6d17e678144119be82a2f1b81d2`.
  Readiness proved CDP metadata, WebSocket upgrade, and a browser-scoped
  DevTools command succeed. Selector-probe returned `success=true`,
  `probe_backend=raw_cdp`, target/page bands, one attached page, then
  `partial_error_kind=page_enable_timeout` before Runtime or selector-family
  counting. The direct page-target route also saw page-list and page-WebSocket
  availability but timed out at `Page.enable`. No raw page URL, page text,
  cookie, OTP, API key, account identifier, or card data left the TEE boundary.
  The CVM was restored to the funding-validation profile afterward, with live
  attested compose hash
  `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`, and
  both diagnostic endpoints now return 403 disabled.
  FUNDING VALIDATION PROFILE: on 2026-07-09 the temporary
  `docker-compose.tinker-funding-validation.phala.yaml` profile was deployed to
  Phala with GitHub-attested images, then refreshed to the custom Neko/CDP path
  at live attested compose hash
  `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`.
  `verify-deployment-bundle` passed with GitHub provenance/SBOM attestations,
  digest-pinned registry images, and live TDX envelope evidence.
  Health is OK, the email oracle is ready, IMAP is connected, public logs remain
  disabled, and unauthenticated funding mutations return `401 Bearer token
  required`. `$5` remote preflight with recorded deployment identity was ready
  under the old deployed cap, authenticated `/auth/reauth` succeeds, and
  `TinkerAccountEncumbrance` approves the current compose hash. The current
  Tinker-minimum `$10` flow still needs the on-chain cap raised before preflight
  and top-up can be considered ready.
  The first approved real-card validation did not fund the account: live
  the historical pre-hardening `/billing/balance` returned `$0.00`; the current
  route returns only a stable balance band. The payment-method receipt reached
  `payment_submitted` and saw bounded card-management copy; add-balance opened
  the modal but returned bounded `selector_missing` because the amount input was
  not found. Source/tests now repair that classification/selector gap, add
  bounded card-on-file status/removal controls, and enforce the `$10` Tinker
  minimum; on-chain policy update, redeploy, and another bounded add-balance
  receipt are still required.
  Source/tests now add a bounded billing auth-state classifier before
  payment-method/add-balance selector searches: sign-in or magic-code surfaces
  return `auth_required`, and Tinker's access-blocked surface returns
  `auth_access_blocked`, both without exposing page text or clicking billing
  controls. This classifier is now Phala-proven with GitHub-attested images.
  Source/tests and Phala also preserve bounded auth-stage evidence for
  `auth_access_blocked` during signup and `/auth/reauth`: receipts can now say
  `auth_page_loaded`, `auth_email_submitted`, or `auth_otp_page_reached` rather
  than collapsing every deployed auth block to `not_started`. These stage labels
  do not include raw page text, URLs, OTPs, cookies, API keys, or account
  identifiers. The live funding-validation CVM now returns
  `auth_access_blocked` at `auth_email_submitted`, proving browser launch and
  email submission work on Phala but Tinker blocks the flow before OTP.
  Browser-session persistence is also source/test-real and Phala-deployed:
  successful auth will save Playwright `storage_state` into encrypted
  `/data/browser_session.enc` under the separate `tinker/browser_session`
  dstack key path, and billing will load that sealed state for fresh contexts.
  No useful live session has been saved yet because deployed reauth still fails
  before OTP with bounded `auth_access_blocked`; the remaining blocker is
  Tinker's auth access-blocked posture before billing.
  BOUNDED BROWSER READINESS FINDING: source now includes
  `tinker-delegate browser-readiness` plus disabled-by-default
  `GET /browser/readiness`. The diagnostic reports only endpoint classes/hashes,
  CDP metadata reachability, raw WebSocket upgrade stage bands, Playwright/CDP
  handshake results, one-command CDP protocol result bands, and bounded error
  kinds; it does not navigate, click, type, screenshot, inspect page text, or
  expose raw browser URLs. The raw WebSocket stage keeps the advertised debugger
  URL in memory only and emits URL class/hash, TCP/TLS/upgrade stage booleans,
  HTTP status band, and bounded error kind. The CDP protocol stage sends one
  browser-scoped `Browser.getVersion` command and emits no response body. Normal
  Phala compose disables the endpoint. The one-shot bootstrap measurement
  profile has proven the route on Phala with bounded `cdp_timeout`, raw
  WebSocket HTTP Upgrade status band `101`, successful CDP protocol result, and
  restored-normal 403 gating.

PHASE 2: READY
  Control plane starts listening for on-chain deal events
  Email oracle stays running (handles future OTPs if Tinker re-challenges)
  Production mode adds on-chain oracle auth:
  → oracle compose hash registered before deployment
  → approved consumer app ID + compose hash registered for OTP access
  → oracle code authorization frozen after final audited deploy
  → consumer registry may remain mutable during development, then freeze separately
```

**Current auth status**: Local recon and automation work. Production signup is
not complete until the same flow is validated in the deployed CVM package. See
`README.md` for current findings. Summary:
- **Framework**: Next.js SPA at `auth.thinkingmachines.ai`
- **Auth**: Passwordless magic-code (6-digit OTP via email)
- **Email domain blocklist**: `cock.li`, `airmail.cc`, `firemail.cc` were historically blocked; `cock.email` was historically allowed
- **Current local result**: local Neko/CDP reaches magic-code auth, receives OTP through the oracle, completes onboarding, and provisions API keys with bounded attempt records
- **Current deployed gap**: Phala/deployed browser posture emits bounded failure
  evidence but still does not complete API-key sealing
- **Onboarding**: Name + TOS checkbox (custom styled — click label, not hidden input)
- **API key**: `/keys` uses "New key" / "Create API key" style actions, then a generate/confirm action; modal shows `tml-...` key once
- **OTP sender**: `Thinking Machines Lab <no-reply@thinkingmachines.ai>`
- **OTP format**: 6 digits, 6 individual `<input inputmode="numeric">` boxes
- **Implementation**: `tinker_delegate/signup.py` — local path validated, deployed CVM validation pending

### 4.2 IsolatedTinkerSession (SDK Wrapper)

The evaluator agent never touches the raw `ServiceClient` or the API key. It receives an `IsolatedTinkerSession` that enforces two invariants:

1. **Session isolation** — only access the training run + checkpoints created for this deal
2. **No exfiltration** — no downloads, no publishing, no listing other runs

```python
class IsolatedTinkerSession:
    """Sandboxed view of a Tinker account for one NDAI deal.

    The evaluator agent receives this instead of the raw ServiceClient.
    All operations are scoped to a single training run. Checkpoints
    are path-checked. Download and publish are not exposed.
    """

    def __init__(self, service_client: tinker.ServiceClient, deal_id: str):
        self._sc = service_client
        self._deal_id = deal_id
        self._training_run_id: str | None = None
        self._training_client: tinker.TrainingClient | None = None
        self._allowed_paths: set[str] = set()
        self._closed = False

    # --- Training ---

    def create_training(
        self,
        base_model: str,
        rank: int = 32,
        **kwargs,
    ) -> tinker.TrainingClient:
        """Start a LoRA training run. One per deal, enforced."""
        if self._closed:
            raise RuntimeError("Session closed")
        if self._training_run_id is not None:
            raise RuntimeError("Only one training run per deal")

        tc = self._sc.create_lora_training_client(
            base_model=base_model,
            rank=rank,
            user_metadata={"deal_id": self._deal_id},
            **kwargs,
        )
        info = tc.get_info()
        self._training_run_id = info.training_run_id
        self._training_client = tc
        return tc

    # --- Sampling ---

    def save_for_sampling(
        self,
        name: str,
        ttl_seconds: int = 3600,
    ) -> str:
        """Save current weights for sampling. Returns the checkpoint path.

        TTL is mandatory — auto-cleanup backstop even if cleanup() never runs.
        """
        if self._closed:
            raise RuntimeError("Session closed")
        if self._training_client is None:
            raise RuntimeError("No training run")
        ttl_seconds = max(MIN_TTL, min(ttl_seconds, MAX_TTL))

        resp = self._training_client.save_weights_for_sampler(
            name=name,
            ttl_seconds=ttl_seconds,
        ).result()
        self._allowed_paths.add(resp.path)
        return resp.path

    def create_sampler(self, model_path: str) -> tinker.SamplingClient:
        """Create a sampling client. Path MUST be from this session."""
        if self._closed:
            raise RuntimeError("Session closed")
        if model_path not in self._allowed_paths:
            raise PermissionError(
                f"Cannot sample from {model_path} — "
                f"only models trained in deal {self._deal_id}"
            )
        return self._sc.create_sampling_client(model_path=model_path)

    def save_and_get_sampler(
        self,
        name: str = "eval",
        ttl_seconds: int = 3600,
    ) -> tinker.SamplingClient:
        """Convenience path that still enforces TTL and path checks."""
        model_path = self.save_for_sampling(name, ttl_seconds)
        return self.create_sampler(model_path)

    # --- State (scoped to this run) ---

    def save_state(self, name: str, ttl_seconds: int = 3600) -> str:
        """Save training state (weights + optimizer) for resumption."""
        if self._closed:
            raise RuntimeError("Session closed")
        if self._training_client is None:
            raise RuntimeError("No training run")
        ttl_seconds = max(MIN_TTL, min(ttl_seconds, MAX_TTL))
        resp = self._training_client.save_state(
            name=name,
            ttl_seconds=ttl_seconds,
        ).result()
        # State paths are tracked but NOT added to allowed sampling paths
        return resp.path

    # --- Cleanup ---

    def cleanup(self):
        """Delete ALL checkpoints from this deal's training run.

        Called by the control plane when the deal resolves.
        Idempotent — safe to call multiple times.
        """
        if self._closed:
            return
        if self._training_run_id is None:
            self._closed = True
            return

        rc = self._sc.create_rest_client()
        checkpoints = rc.list_checkpoints(self._training_run_id).result()
        for cp in checkpoints:
            try:
                rc.delete_checkpoint(
                    self._training_run_id,
                    cp.checkpoint_id,
                ).result()
            except Exception:
                pass  # TTL backstop handles stragglers

        self._allowed_paths.clear()
        self._training_client = None
        self._closed = True

    # --- Explicitly NOT exposed ---
    #
    # The following Tinker SDK operations are intentionally absent:
    #
    # - create_rest_client()          → no access to REST API
    # - list_training_runs()          → no visibility into other deals
    # - get_checkpoint_archive_url()  → no weight downloads
    # - publish_checkpoint()          → no making weights public
    # - unpublish_checkpoint()        → n/a
    # - create_sampling_client() with arbitrary path → path-checked above
```

### 4.3 Evaluator Agent (A_B)

The buyer's agent. Receives the seller's artifact + an `IsolatedTinkerSession`. Produces a bounded output.

**The evaluation protocol is entirely the agent's (and therefore the buyer's) decision.** The control plane does not dictate how the agent evaluates. The agent autonomously selects the base model, training recipe, number of steps, benchmarks, and scoring methodology. See Section 6 for rationale.

**Interface:**

```python
@dataclass
class EvaluationResult:
    """The only thing that leaves the TEE."""
    score_band: str          # e.g. "high", "medium", "low" — not a precise number
    quality_delta: str       # e.g. "+10-15% on benchmark X" — banded, not exact
    offer_price: int         # in wei, within buyer's budget cap
    recommendation: str      # "accept" | "reject"
    confidence: str          # "high" | "medium" | "low"
    methodology_summary: str # brief description of how evaluation was performed
    compute_cost_wei: int    # actual Tinker compute cost metered by the session
    tdx_quote: bytes         # attestation binding this result to the enclave


async def evaluate(
    artifact: bytes,
    artifact_type: str,
    session: IsolatedTinkerSession,
    budget_cap: int,
    reserve_price: int,
) -> EvaluationResult:
    """
    The core evaluation loop. Protocol is agent-defined.

    The agent decides:
    1. Which base model to use
    2. How to prepare data from the artifact
    3. Training recipe (SL, RL, DPO, custom)
    4. Number of steps
    5. How to benchmark the trained model
    6. How to score quality and compute offer price

    The control plane enforces:
    - Session isolation (only this deal's models)
    - Cost metering (every API call tracked)
    - Cleanup (all checkpoints deleted on resolve)
    - Output bounding (raw metrics never leave the TEE)
    """
    ...
```

**Output Bounding:**

The agent's raw measurements (exact loss values, exact benchmark scores, raw samples) never leave the TEE. They're mapped to bands by the control plane:

```python
def bound_output(raw_delta: float) -> str:
    """Map exact quality delta to a score band."""
    if raw_delta >= 0.20: return "exceptional"   # >20% improvement
    if raw_delta >= 0.10: return "high"           # 10-20%
    if raw_delta >= 0.05: return "medium"         # 5-10%
    if raw_delta >= 0.01: return "low"            # 1-5%
    return "negligible"                            # <1%
```

The offer price is computed from the score band and the budget cap — not from the raw delta. This prevents the buyer from reverse-engineering exact quality numbers from the price.

### 4.4 Control Plane

Orchestrates the deal lifecycle. Watches the on-chain escrow contract, creates/destroys `IsolatedTinkerSession` instances, and enforces cleanup.

**Responsibilities:**

1. **On-chain watcher** — monitors `DiligenceRoom.sol` for deal state transitions
2. **Session factory** — creates `IsolatedTinkerSession` when a deal enters `Funded` state
3. **Artifact ingress** — receives seller's encrypted artifact upload (decrypted inside TEE)
4. **Agent orchestration** — runs the evaluator agent with the session and artifact
5. **Output egress** — publishes bounded result to buyer (with TDX quote)
6. **Cleanup enforcement** — calls `session.cleanup()` on ANY deal resolution
7. **Orphan cleanup** — on CVM boot, scans for sessions that weren't cleaned up (crash recovery)

**API:**

```
POST /deal/{deal_id}/artifact/encrypted
  Auth: short-lived, deal-scoped artifact:upload token from seller wallet signature
  Body: constant-size envelope v3 encrypted to the attestation-exposed TEE public key,
        caller artifact_hash, exact commitment/envelope scheme literals, and
        padding_profile=fixed_1m_v3
  → Matches artifact_hash to the immutable DealCreated commitment before
    decrypting; binds Base Sepolia, the fresh room address, deal ID, artifact
    commitment, and immutable funded evaluator policy in HKDF/AAD; verifies the
    private length, secret, and exact bytes inside the fixed frame; and stores
    only the raw artifact in memory (never on disk)

POST /deal/{deal_id}/artifact
  Auth: seller's signature
  Body: plaintext hex artifact payload
  → Local-dev hook only; disabled by default and unavailable in dstack mode

GET /deal/{deal_id}/result
  Auth: buyer's signature
  → Returns EvaluationResult + TDX quote (only after evaluation completes)

GET /attestation?context=ingress|artifact|billing
  → Returns current context-bound TDX quote, compose hash, code measurements

POST /auth/reauth
  → Disabled unless explicitly enabled; refreshes OTP auth and returns only a bounded tinker_auth receipt

GET /health
  → Liveness check + active session count
```

**Lifecycle:**

```
ON-CHAIN EVENT: DealFunded(deal_id, buyer, seller, budget_cap, reserve_price)
  │
  ├─ Create IsolatedTinkerSession(deal_id)
  ├─ Wait for artifact upload from seller
  ├─ Run evaluator agent
  │   ├─ Agent trains model on artifact via session
  │   ├─ Agent benchmarks trained model
  │   ├─ Agent produces EvaluationResult
  │   └─ Control plane publishes bounded result
  │
  ├─ Wait for on-chain resolution (accept / reject / expire)
  │
  └─ session.cleanup()  ← ALWAYS, regardless of outcome
```

### 4.5 DiligenceRoom Smart Contract

Minimal escrow state machine on Base Sepolia. Enforces the NDAI deal lifecycle on-chain.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DiligenceRoom {
    enum State { Created, Funded, Evaluated, Accepted, Rejected, Expired }

    struct Deal {
        address seller;
        address buyer;
        uint256 reservePrice;
        uint256 budgetCap;
        uint256 expiry;
        State state;
        bytes32 artifactHash;       // keccak256(v2 domain || 0x00 || secret32 || raw artifact)
        address teeIdentity;        // dstack-derived address of the CVM
        uint8 scoreBand;            // bounded public policy output
        bytes32 resultHash;         // canonical DiligenceRoomPublicResult commitment
        uint256 computeCost;        // deterministic public tariff, not raw metering
        uint256 fee;                // 1% surcharge on compute cost
    }

    address public developer;       // receives compute cost + fee
    uint256 public feeBps;          // governed then frozen for production

    mapping(uint256 => Deal) public deals;
    uint256 public nextDealId;

    event DealCreated(uint256 indexed dealId, address seller, uint256 reservePrice);
    event DealFunded(uint256 indexed dealId, address buyer, uint256 budgetCap);
    event EvaluationComplete(uint256 indexed dealId, bytes32 resultHash, uint256 computeCost);
    event DealAccepted(uint256 indexed dealId, uint256 sellerPayment, uint256 devPayment);
    event DealRejected(uint256 indexed dealId, uint256 devPayment);
    event DealExpired(uint256 indexed dealId);

    // Seller creates a deal with a reserve price and expiry
    function createDeal(
        uint256 reservePrice,
        uint256 expiry,
        bytes32 artifactHash,
        address teeIdentity
    ) external returns (uint256 dealId);

    // Buyer funds the deal — msg.value covers budget_cap + max compute + fee
    function fundDeal(uint256 dealId) external payable;

    // TEE submits only bounded policy fields after verifier authorization.
    // The contract rejects non-policy compute and derives resultHash itself.
    function submitResult(
        uint256 dealId,
        ScoreBand scoreBand,
        uint256 computeCost,
        bytes32 composeHash,
        uint256 authorizationExpiry,
        bytes calldata verifierSignature
    ) external;  // callable only by teeIdentity with resultVerifier authorization

    function canonicalResultHash(
        uint256 dealId,
        bytes32 composeHash,
        ScoreBand scoreBand,
        uint256 computeCost
    ) external view returns (bytes32);

    // Buyer accepts — three-way settlement:
    //   seller gets deal_payment
    //   developer gets computeCost + fee
    //   buyer gets remainder
    function acceptDeal(uint256 dealId, uint256 dealPayment) external;

    // Buyer rejects — two-way settlement:
    //   developer gets computeCost + fee (training already happened)
    //   buyer gets remainder
    function rejectDeal(uint256 dealId) external;

    // Anyone can expire a timed-out deal
    function expireDeal(uint256 dealId) external;
}
```

## 5. Billing, Cost Metering, and the Encrypted Card Channel

### 5.1 Account Funding Model

The Tinker account is **pre-funded by the developers** (the team running this system). The default runtime funding mode is `manual_prefund`: card and add-balance browser automation are denied unless an operator explicitly switches to `operator_capped_validation` for a one-off approved test. The developers may hold a credit card that pays Tinker's usage-based billing, but the raw-card encrypted browser path is not the production/repeated funding model. The TEE holds the encumbered account — the developers can update billing details only through an approved funding mode and cannot access the API key, training data, or model weights.

### 5.2 Encrypted Card Update Channel

The developers need a way to update the credit card on the Tinker account without gaining access to the account itself. This is a one-way encrypted channel into the TEE:

```
Developer                           TEE Boundary
────────                           ────────────
  │                                     │
  ├─ Encrypt card details to TEE's     │
  │  public key (from TDX attestation)  │
  │                                     │
  ├─ POST /admin/billing ─────────────► │
  │  {encrypted_card_details}           │
  │                                     ├─ Decrypt card details
  │                                     ├─ Automate Tinker billing update
  │                                     │  (browser automation or API)
  │                                     ├─ Discard card details from memory
  │                                     ├─ Emit TDX quote confirming update
  │                                     │
  │ ◄── {success: true, tdx_quote} ────┤
  │                                     │
  │  Developer NEVER sees:              │
  │  - TINKER_API_KEY                   │
  │  - Email credentials                │
  │  - Training data or weights         │
```

**Security properties:**
- Card details are encrypted to the TEE's attested public key — only the TEE can decrypt
- Card details are used once (to update billing) then discarded from memory — never persisted
- The developer cannot use this channel to extract any secrets from the TEE
- The TEE attests that the billing update code is the only code that handles card details

**Implementation**: Tinker billing is console-only (no billing API). Browser automation via Playwright fills the Stripe Elements iframe (PCI-compliant cross-origin iframe for card number/exp/CVC) and parent page fields (cardholder name, address). See `tinker_delegate/billing.py` for the implementation and `tinker_delegate/card_channel.py` for the secure channel wrapper.

### 5.5 Tinker Pricing (as of 2026-03-08)

Tinker uses a **prepaid balance** model with Stripe for payment processing.

| Model | Prefill ($/M tok) | Sample ($/M tok) | Train ($/M tok) |
|-------|-------------------|-------------------|-------------------|
| Llama-3.2-1B | $0.03 | $0.09 | $0.09 |
| Llama-3.1-8B | $0.13 | $0.40 | $0.40 |
| Llama-3.3-70B | $0.40 | $0.90 | $1.10 |
| Qwen3-235B | $0.68 | $1.70 | $2.04 |
| **Storage** | $0.10/GB/month | | |

Features:
- **Auto-reload**: Configurable threshold + amount (e.g., "reload $50 when balance drops below $10")
- **Credit grants**: Eligible accounts may receive promotional credits
- **hCaptcha**: Invisible captcha on Stripe form (no manual solve required in neko)

### 5.3 Buyer Pays for Compute

When a buyer funds a deal, their escrow covers three things:

```
Buyer's Escrow Deposit = Max Deal Payment + Max Compute Cost + 1% Fee
                       = budget_cap     + compute_estimate + (compute_estimate * 0.01)
```

**Cost metering inside the TEE:**

Tinker's pricing is deterministic — it's based on model size and compute consumed. The control plane tracks:

- **Model selected** by the agent (determines per-step cost)
- **Training steps executed** (`forward_backward` + `optim_step` calls)
- **Tokens processed** per step (batch size × sequence length)
- **Sampling calls** (number and token count)

Since we control the `IsolatedTinkerSession` wrapper, every Tinker API call passes through our code. We intercept and meter:

```python
class IsolatedTinkerSession:
    # ... existing code ...

    def __init__(self, ...):
        # ... existing init ...
        self._meter = CostMeter()

    def create_training(self, base_model, ...):
        # ... existing code ...
        self._meter.set_model(base_model)
        return tc

    # The TrainingClient returned to the agent is wrapped to meter calls
    # forward_backward() → meter.record_step(tokens=len(data))
    # optim_step()       → meter.record_optim()
    # sample()           → meter.record_sample(tokens=max_tokens)

    @property
    def compute_cost_wei(self) -> int:
        """Current metered cost in wei (ETH)."""
        return self._meter.total_cost_wei

    @property
    def fee_wei(self) -> int:
        """1% fee on compute cost."""
        return self._meter.total_cost_wei // 100
```

**Cost settlement on deal resolution:**

```
DEAL RESOLVES
  │
  ├─ Compute actual_cost = session.compute_cost_wei
  ├─ Compute fee = actual_cost // 100  (1%)
  │
  ├─ IF ACCEPTED:
  │   ├─ Seller receives: deal_payment
  │   ├─ Developer receives: actual_cost + fee
  │   └─ Buyer receives: escrow - deal_payment - actual_cost - fee  (refund)
  │
  ├─ IF REJECTED or EXPIRED:
  │   ├─ Seller receives: nothing
  │   ├─ Developer receives: actual_cost + fee  (training already happened)
  │   └─ Buyer receives: escrow - actual_cost - fee  (refund)
```

The buyer always pays for compute that was consumed, even on rejection — the training already happened and cost real money. The 1% fee covers the operational cost of running the TEE infrastructure.

### 5.4 Cost Estimation

Before funding a deal, the buyer needs an estimate of compute cost. The control plane provides this:

```
GET /estimate
  Body: { base_model: "Qwen/Qwen3-8B", max_steps: 200, avg_batch_tokens: 4096 }
  → { estimated_cost_wei, estimated_cost_usd, fee_wei }
```

This lets the buyer set their escrow deposit accurately. The estimate is an upper bound — actual cost may be lower if the agent trains for fewer steps than the maximum.

## 6. Evaluation Protocol

**The evaluation protocol is entirely up to the agent and its owner (the buyer).** The control plane and `IsolatedTinkerSession` enforce the hard constraints (session isolation, cleanup, output bounding, cost metering) but do not dictate how the agent evaluates.

The buyer configures or deploys their own evaluator agent, which decides:
- Which base model to fine-tune (from Tinker's supported models)
- LoRA rank and which layers to train
- How many training steps to run
- What loss function to use (cross_entropy, importance_sampling, PPO, DPO, custom)
- What benchmark suite to run against the trained model
- How to interpret results and compute a quality score
- What offer price to recommend

This maps directly to the NDAI paper (Section 5): A_B is the buyer's agent, and its quality affects the buyer's outcomes. Budget caps and acceptance thresholds make the mechanism robust to agent error regardless of evaluation methodology.

**The control plane enforces, the agent decides.**

## 7. Threat Model

### 7.1 Trust Boundaries

```
┌───────────────────────────────────────────────────────┐
│  TRUSTED                                              │
│                                                       │
│  - Code running inside TDX CVM                        │
│  - IsolatedTinkerSession enforcement logic            │
│  - dstack-KMS MPC nodes (each in TEE)                │
│  - DiligenceRoom.sol contract logic                   │
│  - Intel TDX hardware (CPU package)                   │
│                                                       │
├───────────────────────────────────────────────────────┤
│  UNTRUSTED                                            │
│                                                       │
│  - Cloud provider (Phala) — encrypted traffic only    │
│  - Human deployers — no SSH, no console               │
│  - Seller — cannot see agent's evaluation process     │
│  - Buyer — cannot see raw artifact or trained model   │
│  - Network observers — see encrypted traffic          │
│                                                       │
├───────────────────────────────────────────────────────┤
│  PARTIALLY TRUSTED                                    │
│                                                       │
│  - Tinker platform (thinkingmachines.ai)              │
│    CAN see training data sent via API.                │
│    CAN see model weights on their servers.            │
│    Mitigation: Tinker is the compute provider, not    │
│    a party to the deal. Weights are TTL'd and         │
│    deleted. Future: client-side encryption of          │
│    training data before sending to Tinker API.        │
│                                                       │
│  - Email provider (cock.li) — CAN read OTPs.          │
│    Mitigation: OTPs are short-lived, extracted         │
│    in seconds. See email oracle threat model.         │
│                                                       │
└───────────────────────────────────────────────────────┘
```

### 7.2 Threat Matrix

| # | Threat | Attacker | Impact | Mitigation |
|---|--------|----------|--------|------------|
| T1 | Extract Tinker API key from TEE memory | Cloud provider / host root | Full account takeover, access to all past training runs | TDX memory encryption. API key sealed via KMS. Host reads cause page faults. |
| T2 | Agent accesses models from other deals | Buggy or malicious agent code | Cross-deal data leakage | First-party evaluator code uses only IsolatedTinkerSession wrapper methods, which path-check sampling and expose no REST/list/download/publish methods. Arbitrary third-party evaluator code still needs a process/sandbox capability boundary before it is trusted. |
| T3 | Trained model persists after deal resolves | Cleanup failure (crash, network) | Seller's data-derivative persists on Tinker servers | TTL on all checkpoint saves (auto-delete). Cleanup-on-boot. No download path exposed. |
| T4 | Agent emits raw quality scores instead of bands | Agent implementation bug | Buyer learns exact value, gains bargaining leverage | Output bounding is in the control plane, not the agent. Agent returns raw numbers, control plane maps to bands before egress. |
| T5 | Buyer reverse-engineers artifact from bounded output | Sophisticated buyer | Partial disclosure beyond intended band | Score bands are coarse by design. Offer price derived from band, not raw delta. Paper's analysis shows bounded outputs preserve seller leverage. |
| T6 | Tinker platform inspects training data | Tinker insider / compelled access | Sees seller's raw artifact | Tinker sees training data by design (API-based training). Mitigation: Tinker is not a deal party. Future: encrypt training data client-side (requires Tinker support for encrypted compute). |
| T7 | Deploy malicious oracle code to exfiltrate API key or artifact | Compromised developer | Full compromise | Oracle compose hashes are governed on-chain, new oracle code can be timelocked during development, and oracle code authorization is permanently frozen after production sign-off. dstack-KMS only provisions keys to authorized compose hashes. |
| T8 | Tinker account suspended | ToS violation or abuse detection | Service interruption, stuck deals | Monitor account health. Escrow contract has expiry — deals auto-resolve. Backup: pre-register second account during genesis. |
| T9 | Seller uploads poisoned artifact to corrupt evaluation | Malicious seller | Agent produces wrong valuation | Agent uses held-out eval set. Anomaly detection on training metrics (NaN loss, divergence). Does not affect TEE security — only evaluation quality. |
| T10 | Replay a previous deal's evaluation result | Attacker with network access | Fake evaluation for a different artifact | Each result includes TDX quote binding deal_id + artifact_hash + result. On-chain verification. |

### 7.3 The Tinker Trust Gap

The biggest trust assumption: **Tinker (the platform) can see the training data and model weights**. The seller's artifact is sent to Tinker's servers for training. This is inherent to using an API-based training service.

Mitigations (current):
- Tinker is not a party to the deal — they have no economic incentive to exfiltrate
- Weights are TTL'd and actively deleted after the deal
- Tinker's business depends on trust — data exfiltration would be catastrophic for them

Mitigations (future):
- Client-side encryption of training data (requires Tinker to support encrypted/confidential compute)
- Run Tinker's open-source training stack inside a second TEE (eliminates the trust gap entirely but requires GPU-TEE hardware — not yet available on Phala)
- Use a local fine-tuning approach instead of Tinker's API (sacrifices scale but eliminates the third party)

For the hackathon, we accept this trust gap and document it explicitly.

## 8. Deal Lifecycle (End-to-End)

```
1. SELLER CREATES DEAL
   ├─ Seller calls DiligenceRoom.createDeal(reservePrice, expiry, artifactHash, teeIdentity)
   ├─ Seller uploads encrypted artifact to TEE (POST /deal/{id}/artifact)
   └─ On-chain: State = Created

2. BUYER FUNDS DEAL
   ├─ Buyer calls DiligenceRoom.fundDeal{value: budgetCap}(dealId)
   └─ On-chain: State = Funded
       └─ TEE control plane detects DealFunded event

3. EVALUATION (inside TEE)
   ├─ Control plane creates IsolatedTinkerSession(deal_id)
   ├─ Control plane decrypts seller's artifact
   ├─ Evaluator agent receives artifact + session
   │
   ├─ Agent: session.create_training("Qwen/Qwen3-8B")
   ├─ Agent: prepare data from artifact (tokenize, format)
   ├─ Agent: tc.forward_backward(data, "cross_entropy") × N steps
   ├─ Agent: tc.optim_step(AdamParams(lr=1e-4)) × N steps
   ├─ Agent: session.save_for_sampling("eval-checkpoint", ttl_seconds=3600)
   ├─ Agent: sampler = session.create_sampler(checkpoint_path)
   ├─ Agent: run benchmarks via sampler.sample() + sampler.compute_logprobs()
   ├─ Agent: compute quality delta vs base model
   ├─ Agent: return raw metrics to control plane
   │
   ├─ Control plane bounds output → EvaluationResult
   ├─ Control plane submits resultHash on-chain
   ├─ Control plane serves bounded result to buyer (GET /deal/{id}/result)
   └─ On-chain: State = Evaluating

4. RESOLUTION (cost settlement + cleanup)
   │
   │  In ALL cases, compute_cost = session.compute_cost_wei
   │                  fee = compute_cost // 100  (1%)
   │
   ├─ ACCEPT: Buyer calls acceptDeal(dealId)
   │   ├─ On-chain: seller receives deal_payment
   │   ├─ On-chain: developer receives compute_cost + fee
   │   ├─ On-chain: buyer receives escrow - deal_payment - compute_cost - fee
   │   ├─ TEE: session.cleanup() — delete all checkpoints
   │   ├─ TEE: discard artifact from memory
   │   └─ On-chain: State = Accepted
   │
   ├─ REJECT: Buyer calls rejectDeal(dealId)
   │   ├─ On-chain: developer receives compute_cost + fee (training already happened)
   │   ├─ On-chain: buyer receives escrow - compute_cost - fee
   │   ├─ TEE: session.cleanup() — delete all checkpoints
   │   ├─ TEE: discard artifact from memory
   │   └─ On-chain: State = Rejected
   │
   └─ EXPIRE: Anyone calls expireDeal(dealId) after expiry
       ├─ On-chain: developer receives compute_cost + fee (if any training happened)
       ├─ On-chain: buyer receives escrow - compute_cost - fee
       ├─ TEE: session.cleanup() (triggered by on-chain event or TTL backstop)
       ├─ TEE: discard artifact from memory
       └─ On-chain: State = Expired
```

## 9. Cleanup Guarantees

Cleanup is the hardest problem. The trained model contains a compressed representation of the seller's data. It MUST be destroyed.

### What is `ttl_seconds`?

Tinker's `save_weights_for_sampler()` and `save_state()` methods accept an optional `ttl_seconds` parameter. When set, Tinker **automatically deletes the checkpoint after that many seconds**, regardless of whether our code calls `delete_checkpoint()`. The `Checkpoint` type includes an `expiration` field confirming this.

This is our dead man's switch. Even if:
- The CVM crashes and never reboots
- The network goes down during cleanup
- Our cleanup code has a bug
- The TEE is physically destroyed

...the checkpoints self-destruct on Tinker's servers after TTL expires. The trained model cannot outlive the deal.

**Open question**: We need to empirically verify that expired checkpoints are truly inaccessible (not just marked expired but still downloadable via a direct URL).

### Defense in Depth

| Layer | Mechanism | Handles |
|---|---|---|
| **L1: Explicit cleanup** | `session.cleanup()` calls `delete_checkpoint()` for every checkpoint in the training run | Normal deal resolution |
| **L2: TTL backstop** | Every `save_weights_for_sampler()` and `save_state()` call includes `ttl_seconds` | TEE crash, network partition, cleanup code bug |
| **L3: Cleanup-on-boot** | CVM startup scans for active sessions without a corresponding on-chain deal in terminal state | CVM restart after crash |
| **L4: No download path** | `IsolatedTinkerSession` does not expose `get_checkpoint_archive_url()` | Even if checkpoints linger, nobody can fetch them |
| **L5: Account scoping** | Each deal's training run has `user_metadata={"deal_id": ...}` — orphan detection key | Multi-deal cleanup coordination |

### TTL Strategy

```python
# All checkpoint saves use a TTL tied to the deal's on-chain expiry
# plus a grace period for cleanup to run

ttl = (deal.expiry - now()) + GRACE_PERIOD  # e.g. deal_remaining + 1 hour
ttl = min(ttl, MAX_TTL)                      # cap at 24 hours
ttl = max(ttl, MIN_TTL)                      # floor at 1 hour

session.save_for_sampling(name="eval", ttl_seconds=int(ttl))
```

## 10. Implementation Plan

### Phase 1: Tinker Console Recon PARTIAL

- [x] Navigate to `tinker-console.thinkingmachines.ai` via neko/CDP
- [x] Document: Next.js SPA and passwordless magic-code auth
- [x] Test: no phone verification from datacenter IP (neko runs in Docker)
- [x] Document: API key generation — New key → Generate key → copy from modal
- [x] Test: API key can only be generated via console UI (no API endpoint found)
- [x] Historical discovery: `cock.li`/`firemail.cc` domains blocked, `cock.email` observed as allowed
- [x] Confirm Phala oracle-genesis failure evidence: auto-genesis debug CVM
      reached captcha submission, but HTTP signup was rejected and browser
      fallback timed out.
- [x] Repair source-level cock.li form mapping for `password_confinm`,
      `password_confirm` honeypot, and `csrf_valid`.
- [x] Rebuild/pin oracle image and re-run Phala oracle-genesis debug proof;
      HTTP signup reached IMAP verification in Phala.
- [x] Bound public oracle health/attestation email fields in source after
      successful genesis showed raw mailbox egress on `/health`.
- [x] Rebuild/pin bounded-health oracle image and re-run Phala oracle-genesis
      debug proof.
- [x] Implement: full automation in `tinker_delegate/signup.py`
- [x] Validate local Neko/CDP auth, onboarding, and API-key provisioning against the live Tinker UI
- [ ] Revalidate the deployed Phala/CVM browser posture against the live Tinker UI

### Phase 2: Core SDK Wrapper ✅ IMPLEMENTED

- [x] Implement `IsolatedTinkerSession` — `tinker_delegate/session.py`
- [x] Path-checked sampling (only models from this session's training run)
- [x] Scoped base-model sampling for first-party tuned-vs-base comparison
- [x] Mandatory TTL on all checkpoint saves (MIN_TTL=1h, MAX_TTL=24h)
- [x] Cost metering: per-token tracking with model-specific pricing
- [x] Cleanup: retries deletes for all checkpoints from this deal's training run
      and returns a bounded cleanup attestation
- [x] Unit tests: session isolation (cannot access other paths)
- [x] Unit tests: first-party evaluator source does not reach raw ServiceClient,
      REST/list/download/publish/delete APIs, or arbitrary sampling paths
- [x] Unit tests: mandatory cleanup (all checkpoints deleted)
- [x] Unit tests: cleanup retries and bounded cleanup attestation without raw
      checkpoint IDs
- [x] Mocked-SDK integration tests: create run, enforce one-run guard, clamp TTL
      on every save path, sample only approved paths, meter calls, cleanup
      checkpoints
- [x] Gated real SDK integration test harness: create training run → train →
      save TTL checkpoint → sample → cleanup, disabled unless
      `TINKER_RUN_REAL_SDK_TESTS=1` and `TINKER_REAL_SDK_MAX_USD` is low
- [ ] Run real SDK integration test inside deployed CVM:
      create training run → train → sample → cleanup
      → verify deletion

### Phase 3: Evaluator Agent ✅ IMPLEMENTED (stub + SFT)

- [x] Stub evaluator: deterministic synthetic metrics from artifact hash — `tinker_delegate/evaluator.py`
- [x] SFT evaluator: real LoRA fine-tune + perplexity benchmark — `tinker_delegate/evaluator.py`
- [x] Output bounding: raw metrics → score bands — `tinker_delegate/control_plane.py`
- [ ] Test SFT evaluator with a real Tinker API key locally

### Phase 4: Control Plane ✅ IMPLEMENTED (watcher pending)

- [x] Deal lifecycle state machine — `tinker_delegate/control_plane.py`
- [x] Session factory (creates IsolatedTinkerSession per deal)
- [x] Artifact ingress (encrypted, memory-only, zeroed on resolution)
- [x] Output bounding (raw delta → score band → offer price)
- [x] Cleanup enforcement on deal resolution
- [x] Cleanup attestation stored on deal resolution
- [x] Orphan cleanup on boot (scans training runs with deal_id metadata)
- [x] Control plane API endpoints in FastAPI — `tinker_delegate/api.py`
  - POST /deal/notify-funded, POST /deal/{id}/artifact, POST /deal/{id}/evaluate
  - GET /deal/{id}/result, POST /deal/{id}/resolve, GET /deals
- [ ] On-chain event watcher (web3.py listening to DiligenceRoom events)

### Phase 5: Smart Contract ✅ IMPLEMENTED (deployment pending)

- [x] DiligenceRoom.sol — escrow state machine with three-way settlement — `contracts/src/DiligenceRoom.sol`
- [x] 22 tests (unit + fuzz) all passing — `contracts/test/DiligenceRoom.t.sol`
- [x] Deployment script — `contracts/script/DiligenceRoom.s.sol`
- [ ] Deploy to Base Sepolia via `/forge-deploy`
- [ ] Verify on BaseScan via `/forge-verify`

### Phase 6: TEE Integration (partial)

- [x] `docker-compose.yaml` — delegate service with Dockerfile
- [x] `docker-compose.dstack.yaml` — dstack overlay (neko + oracle network, TDX sock)
- [x] Encryption channel: X25519 + AES-256-GCM for card delivery — `tinker_delegate/crypto.py`
- [x] Encrypted artifact ingress: quote-key channel, deal/hash-bound AES-GCM,
      disabled plaintext production path, client-side attestation envelope gate
- [x] Per-deal/per-artifact HKDF context for artifact upload keys under the
      attestation-exposed TEE public key
- [x] No-disk-write regression tests for encrypted FastAPI artifact ingress and
      control-plane evaluation dispatch while raw artifact buffers are in scope
- [x] TDX quote stubs (local) / real generation (dstack) in attestation endpoints
- [x] Client-side attestation envelope verifier: mode, quote presence, compose
      hash, app ID, OS image hash, report-data key binding, and fetch freshness
- [x] Compose-hash verifier CLI renders registry-image Phala compose files,
      rejects local `build:` services and mutable tag-only images, emits the
      digest-pinned image manifest, and computes the Phala Cloud-style compose
      hash over the rendered app-compose object
- [x] Key-store code path uses `dstack_sdk.TappdClient.derive_key()` in dstack mode
- [ ] Full cryptographic Intel TDX quote parsing/freshness verification
- [ ] Validate dstack-derived key sealing in a deployed CVM
- [ ] Local testing with `/phala-simulator`
- [ ] Deploy to Phala Cloud via `/phala-deploy`

### Phase 7: Tinker Account Genesis ✅ LOCAL COMPLETE (TEE sealing pending)

- [x] Signup automation — `tinker_delegate/signup.py`
- [x] Email oracle integration — `tinker_delegate/oracle_client.py` (authenticated POST /pin for OTP)
- [x] API key capture — New key → Generate key → extracted from console modal, `tml-...` format
- [x] API key is stored in encrypted key store and signup returns only hash/status metadata
- [ ] API key sealing via `derive_key("tinker/api_key")` validated in deployed dstack CVM
- [ ] End-to-end genesis test on Phala Cloud using the validated local selector flow

## 11. Decided Questions

| # | Question | Decision |
|---|----------|----------|
| D1 | Who pays Tinker compute? | Buyer pays. Deducted from escrow on deal resolution. |
| D2 | How is the Tinker account funded? | Pre-funded by developers. Card updated via encrypted channel to TEE. |
| D3 | Fee structure? | 1% surcharge on Tinker API costs, paid to developer account. |
| D4 | Evaluation protocol? | Up to the agent and its owner (the buyer). Agent decides autonomously. |
| D5 | `ttl_seconds`? | Mandatory on every checkpoint save. Dead man's switch for cleanup. |

## 12. Open Questions

1. **Tinker console signup flow** — Local Neko/CDP automation works against the live Tinker UI as of 2026-07-08: OTP arrives through the email oracle, onboarding completes, and API-key provisioning captures a one-time `tml-...` key. The deployed one-shot bootstrap profile now uses headed Neko CDP instead of the Playwright sidecar and has been Phala-tested, but production signup is still not complete: the sidecar attempt failed closed with `auth_access_blocked`; the first headed-Neko retry failed closed with generic `bootstrap_error`; the next instrumented headed-Neko retry captured a bounded `tinker_auth` `unknown_failure` receipt at `not_started`; and the latest retry preserves that outcome in top-level `bootstrap_error_kind` without API-key sealing.

2. **Tinker billing settings page** — Browser automation and encrypted card-channel code exist. Local Neko reaches the Stripe Elements payment form, fills the test card, and has returned bounded decline/failure receipts without exposing card details. Add-balance enforces whole-dollar `TINKER_MIN_ADD_BALANCE_USD` / `TINKER_MAX_ADD_BALANCE_USD` policy before browser launch, returning bounded `policy_denied` receipts for non-finite, non-positive, below-minimum, fractional, or over-cap requests. Tinker's current UI minimum is `$10`, so source/config defaults now use `$10` for both min and validation cap. `add-card-encrypted-prompt` and `funding-validation-packet --prompt-card --run-card-attempt` are the intended operator paths for approved real-card validation because they prompt interactively instead of placing card fields in command-line arguments, require deployed attestation expectations unless explicitly run in local-development mode, and can require live `TinkerAccountEncumbrance` approval before prompting. The first approved real-card validation did not top up the account, but the later same-context reauth/add-balance packet did: `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` reached `add_balance_submitted` with `raw_secret_egress=false`, `check-funding-validation-packet --require-deployed-attestation` passed, and the current public balance read returns only `10_100_usd`. Public billing errors and persisted messages are exact `AutomationOutcome` codes, evidence hashes bind only the deterministic bounded projection, malformed/legacy receipts fail closed, and storage failures expose only `store_failed`. Card-on-file status and removal paths return only bounded booleans/bands/receipts, never card brand, last4, expiry, address, or page text. `TINKER_FUNDING_MODE=manual_prefund` remains the default production model and denies encrypted card/add-balance automation before decryption or browser launch; `operator_capped_validation` is required for deliberate capped operator validation. Production/repeated funding should use an official Tinker route, Stripe-hosted/tokenized collection, SetupIntent / PaymentMethod reuse with consent, or manual/developer prefunding until compliance review approves otherwise.

3. **TinkerAccountEncumbrance deployment** — The Base Sepolia contract is deployed at `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e` with owner `0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`. It enforces compose-hash approval, emergency halt, and `$10` add-balance/spend caps for the operator-validation Tinker account. Earlier approved compute/proxy compose `0xe682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7` remains approved from tx `0x3bc992cc2979aa8198923bcaf856d2c82d387646e49e750dada1f5cb203b3d17`. The latest live Phala client-config install compose `0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085` is attested and running but `approvedComposeHashes(...)` currently returns `false`; approve it before using that live compose for the next `SPEND_TINKER_COMPUTE` smoke. The deploy/redeploy helpers and command plans never require raw private-key flags; operator broadcasts use the Foundry keystore account.

4. **TTL reliability** — Does Tinker actually purge expired checkpoints and make them inaccessible after `ttl_seconds`? Or are they just marked expired but still fetchable? Needs empirical testing.

5. ~~**Cost metering precision**~~ — Implemented for the current known pricing table. Pricing is per-million-tokens, split into prefill/sample/train rates per model. See Section 5.5 for the full pricing table. Cost metering in `IsolatedTinkerSession` tracks tokens processed per API call and multiplies by the model-specific rate.

6. **Tinker trust gap** — Training data is sent to Tinker's servers in plaintext. For the hackathon, we accept and document this. Long-term, need encrypted compute or self-hosted training inside a GPU-TEE.

7. **Multiple checkpoints during evaluation** — Should the agent be allowed to save intermediate checkpoints (e.g., every 50 steps) to track training dynamics? More checkpoints = more cleanup surface area, but TTL backstop handles it. Agent's choice per Section 6.

7. **Concurrent deals** — Can the CVM handle multiple deals simultaneously? Each deal gets its own `IsolatedTinkerSession`, and Tinker supports concurrent training runs. The sessions are independent. Main constraint: CVM memory for holding multiple artifacts.

8. **Base model sampling rights** — Should the agent be allowed to sample from the base model (pre-training) for comparison? Currently not allowed (no path in `_allowed_paths`). Probably should be — the base model isn't derived from the seller's data. Add a `_base_model` field to the session that's always accessible.

9. **Escrow contract integration** — The contract needs to handle three-way settlement (seller + developer + buyer refund). The `compute_cost` and `fee` are reported by the TEE and attested via TDX quote. How does the contract verify the TEE's cost report? Options: trust the TEE attestation, or implement on-chain cost bounds.

## 13. References

| Resource | Location |
|----------|----------|
| NDAI paper | `📄/ndai/paper.md` |
| TEE email oracle spec | `⚙️/tee-email-oracle/SPEC.md` |
| Email provider comparison | `📄/tee-email-oracle/PROVIDER-COMPARISON.md` |
| cock.li captcha solver | `⚙️/tee-email-oracle/captcha-solver/` |
| **Tinker signup automation** | **`⚙️/tinker-delegate/tinker_delegate/signup.py`** |
| **Tinker signup README (recon findings)** | **`⚙️/tinker-delegate/README.md`** |
| Tinker API docs | `📄/thinking-machines/` |
| Tinker SDK | `🔬/thinking-machines/tinker` |
| Tinker cookbook | `🔬/thinking-machines/tinker-cookbook` |
| skill-verifier (closest reference) | `🔬/amiller/skill-verifier` |
| dstack-openclaw (domain separation) | `🔬/amiller/dstack-openclaw` |
| devproof-apps-guide (deploy template) | `🔬/amiller/devproof-apps-guide` |
| DelegaTEE paper (USENIX 2018) | https://www.usenix.org/conference/usenixsecurity18/presentation/matetic |
| Setting Your Pet Rock Free (Nous) | https://nousresearch.com/setting-your-pet-rock-free/ |
