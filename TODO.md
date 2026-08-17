# TODO: Full Latent Vision Roadmap

Last updated: 2026-07-23
Branch context: active working tree; deployment items require a clean reviewed release

This is the build backlog for turning `dnai-wikigen` from the current prototype
into the full latent project: a DevProof-style, attested diligence room where
private artifacts, credentials, source accounts, Tinker compute, bio-validation,
private verified rewards, coordination, and settlement all happen through
bounded, auditable, no-human-key control planes.

Current-release note: the repository has moved beyond the original mockup and
now contains the complete routed SolidJS product plus a fresh seven-contract
suite and hardened CVM/runtime release machinery. Open checkboxes below are not
evidence that those source surfaces are absent; many describe the still-pending
fresh Base Sepolia/Phala ceremony, independent trust roots, production provider
accounts, and end-to-end live proof. [STATUS.md](STATUS.md) is authoritative for
what is source-real, modeled, externally blocked, historical, or deployed.

The north star:

```text
Seller/controller keeps raw private data and credentials out of human hands.
Buyer/sponsor funds a capped evaluation.
TEE-owned accounts and agents run the evaluation.
Private reward data can score optimization attempts without being disclosed.
Only bounded outputs, hashes, attestations, and settlement data leave.
Every credential, policy change, run, denial, and payout has a verification path.
```

The current repo already has meaningful pieces:

- A locally rehearsed seven-contract suite: `DiligenceRoom`,
  `TinkerAccountEncumbrance`, `RoyaltyDistributor`, `ChallengeRegistry`,
  `ComputeCreditVault`, `EmailOracleAuth`, and `ExecutionPolicyAnchor`.
- `tee-email-oracle` with fixed OTP capability, dual-RPC finalized authorization,
  exact release configuration, and a restart-preserved checkpoint.
- `tinker-delegate` with bounded wallet/proxy domains, Deal/Arena/Compute
  runtimes, sealed artifact paths, policy anchoring, and an exact two-day frozen
  Tinker release ceremony.
- Five purpose-separated signed challenge-v2 / verdict-v4 QVL profiles/CVM
  definitions plus an independent deterministic Compute meter, for seven
  production CVMs total. Each single-use DCAP challenge is at most 120 seconds
  and appraisal must finish strictly before expiry. The reviewed release uses a
  separate exact 900-second activation-evidence lease, which may outlive the
  consumed challenge but is not renewed challenge freshness. Post-restart
  Compute-workload recipient activation is schema v3 with an explicit lease of
  at most 300 seconds; its stable recipient-release commitment remains v2.
- A source-real, locally tested resident production activation driver that
  preserves the branded authority chain in one process from non-live launch
  through external proof/signature waits, restart, recipient activation, and
  bounded-output publication. It accepts no serialized capability or signer
  key, authorizes no automatic retry or live traffic, and has not run against a
  fresh project-owned production topology.
- `props-room` and `whatsapp-delegate` as source/controller/data-room stubs.
- `ARCHITECTURE.md` with the complete current architecture.
- A complete twelve-route SolidJS product under `web/`, including the modeled,
  no-health-data-intake Health Guide, EIP-6963/injected EIP-1193 wallet
  discovery, conditional WalletConnect, and explicit live/modeled/roadmap
  states.

The honest current gap:

```text
Email encumbrance: source enforcement is substantial; fresh Email/KMS restart
evidence, live bindings, and whole-volume anti-rollback remain open.
Tinker encumbrance: exact policy and rehearsal exist; no fresh Base Sepolia
instance/CVM binding or production provider activation exists for this release.
Bio/private reward: sealed synthetic environments and capability-free safe IR
exist; general hostile code, clinical/wet-lab claims, and live workers do not.
Compute: exact-asset vault and off-chain service-credit lanes exist separately;
the source implements release-gated at-most-once provider execution with a
fresh authenticated process heartbeat and terminal ambiguous-outcome
quarantine, while fresh provider/CVM activation remains open.
DNAI settlement: source and local lifecycle proofs exist; the seven contracts,
seven CVMs, five QVL roots, and multi-day ceremonies are not deployed.
```

Simulator evidence is now a separate `mode=simulator` class across delegate,
Arena, and oracle public envelopes. It remains `verified=false`, and production
verifiers reject it even if an input self-asserts verification. Local modeled
rehearsals must never be labeled `tdx`.

### 2026-07-13 live-runtime build slice

- [x] Make evaluator activation explicit: disabled by default, local-only stub,
      and SFT only in a real non-simulator dstack CVM.
- [x] Add one durable execution-policy store shared by deal evaluation, Arena
      execution, and Compute dispatch. A pass requires both internal auth and
      an allowlisted independent Ethereum signature over a deployment-domain-
      bound hash-only message; the latest hold/deny revokes it.
- [x] Add a confirmation-safe deal runtime that checks policy, avoids duplicate
      evaluation, obtains an independently signed QVL verdict, authorizes the
      bounded result, and submits only with dstack-derived keys.
- [x] Add the single-process-leased, crash-resumable capability-free Arena
      worker seam with fresh cross-process stores, external-QVL activation, and
      a mandatory pre-mutation policy adapter.
- [x] Rehearse the complete fresh seven-contract suite and representative deal,
      challenge, Compute, Tinker-release, and policy-anchor lifecycles on stopped
      ephemeral Anvil without raw key material.
- [x] Wire the deal runtime and Arena worker executables into a disabled-by-
      default hardened CVM process overlay, then test startup failure and
      healthy structural operation. The release renderer now provisions both
      as profile-gated services, fails closed on missing release/QVL authority,
      and exercises their structural boundaries in compose-hardening and
      release-renderer tests. Fresh deployment and post-measurement profile
      activation remain separate open work below.
- [ ] Provision an independent QVL operator/signing root, final policy approver
      wallets, and a deployment-unique approval domain derived from the fresh
      Base Sepolia suite plus reviewed compose commitment.
- [ ] Deploy the fresh suite with Foundry keystore account `dev`, verify source,
      deploy reviewed digest-pinned Phala services, and prove one live bounded
      deal and one live capability-free Arena submission end to end.

## Historical 2026-07-13 prior-release Tinker milestone

The following is preserved as prior-operator engineering evidence. It does not
mean the fresh seven-contract/seven-CVM release is deployed, and its completed
checkboxes do not satisfy current activation tasks.

The load-bearing infrastructure — a TEE-custodied Tinker account whose full
lifecycle and scoped delegation run through bounded, attested control planes —
is **built and validated live on the deployed CVM** (`cvm_1w85mGjo`). What is
now real and demonstrated end-to-end:

- **Full API-key lifecycle via in-TEE CDP automation.** create / named-create /
  list / delete of the upstream `tml-...` keys, driven against the real Tinker
  console from inside the CVM, bounded receipts only, account email hashed never
  raw. Validated live (created `claude-dev-test`, listed it, deleted it). Delete
  uses the console's own Remix form POST via an authenticated in-page fetch.
  (`tinker_keys.py`, `POST /tinker/keys/{list,create,delete}`.)
- **Governed CVM redeploy pipeline, repeatable.** CI reproducible build →
  on-chain `approveComposeHash` in `TinkerAccountEncumbrance` → Phala
  provision/commit → healthy rollout → **sealed key + oracle creds survive the
  new measurement**. Exercised ~10× this session. Helper:
  `scripts/approve-compose-hash.sh`.
- **Tinker proxy: scoped, encrypted, revocable delegation — validated live
  (9/9) and locally (9/9).** issue → x25519-AES envelope → recipient decrypt →
  HS256 verify → scope enforcement → forged/expired/revoked rejection. The
  sealed upstream key never leaves the TEE; downstream principals get only
  scoped JWTs. `tinker:train` scope added. (`tinker_proxy.py`,
  `test_tinker_proxy_roundtrip.py`.)
- **Operator/runtime auth boundary confirmed.** With a runtime token
  configured, operator endpoints are protected and proxy-issuance requires it;
  scoped proxy tokens grant only their operation.
- **Delegated training via scoped proxy tokens executes end-to-end — proven
  through the real endpoint.** A scoped, spend-limited proxy JWT drives
  `POST /tinker/train`: proxy verify → scope check → spend-limit enforce →
  `run_tinker_training` (create → forward/backward + optim per step → checkpoint
  → bounded receipt → `training_completed`). Wrong-scope and over-limit tokens
  are refused before any run. Only the compute backend is synthetic
  (`FakeTinkerServiceClient` via a `service_client_factory` hook); nothing in the
  auth/delegation/training wiring is stubbed. On the live CVM the operator-token
  path reaches the real Tinker SDK inside the TEE. (`test_proxy_train_e2e.py`.)
- **Adversarially hardened.** New attack-the-guarantee tests: 15 proxy JWT
  attacks (alg-confusion/none, payload tamper, cross-key forgery,
  issuer/aud/nbf/expiry spoof, ttl inflation, unknown scope) all fail closed;
  bounded-output secret-scans **found and fixed a real leak** (the `/keys`
  parser could emit a full `tml-` key into a name field — now scrubbed); a
  meter-cap test proves runaway training spend actually aborts. Full suite 1406.

**By design, end users never touch the upstream account — they hold scoped proxy
JWTs. That design is built and validated end-to-end.** The proxy-mediated
delegated-training path works: scoped JWT → verify → scope → spend-limit →
create → forward/backward → checkpoint → bounded receipt. Running *real* jobs is
operational provisioning, not a gap in the system:

- The upstream Tinker account (`CyanFastHeron83`, TEE-owned) must be
  billing-active. It is funded at **$20** with a card on file; a routine
  account/billing step activates it. This is account setup, not a flaw in the
  delegation.
- The live CVM must hold a *current, valid* sealed key. (During key-CRUD
  validation the CVM's sealed key was rotated to a test key that was then
  deleted — re-provision a valid key to restore delegate auth. Self-inflicted
  test artifact, trivially fixed.)

A raw request to Tinker's API with the raw upstream key is **not the product
surface** and is expected to fail — end users are scoped-JWT holders who never
see the account or its key. The system is not waiting on Tinker; it is waiting on
ordinary account provisioning.

## Priority Legend

- `P0` means the project is not real without it.
- `P1` means the project can demo without it, but cannot be trusted or scaled.
- `P2` means it makes the system product-grade, useful, or defensible.
- `P3` means it hardens trust or opens a market once the core is real; deferred
      until P0–P2 land, but scoped so the route is not lost.
- `Research` means first prove the route, then split into implementation tasks.
- `Deploy` means a concrete deployment, account, or operational action.

## Non-Negotiable Invariants

- [ ] `P0` Raw private artifacts never leave the TEE boundary.
- [ ] `P0` Email, Tinker, Phala, chain, Stripe, and source-account credentials are
      never committed, logged, echoed into prompts, or exposed to the browser.
- [ ] `P0` Make the Tinker proxy the only external Tinker access path.
      Done when upstream `TINKER_API_KEY`, `TINKER_PROJECT_ID`, account cookies,
      browser session, card state, and provider endpoint stay sealed inside the
      CVM; approved users/agents receive only scoped, short-lived delegate JWTs
      derived from CVM-only key material; token delivery is encrypted to an
      approved recipient public key; and every proxy operation returns bounded
      receipts instead of raw Tinker identifiers or provider output.
      - [x] Add disabled-by-default proxy status and token issuance surfaces:
            bounded config status, CVM-derived JWT signing, scoped claims,
            encrypted X25519/AES-GCM delivery, optional subject allowlist,
            bearer verification helpers, and tests proving no upstream Tinker
            key/project id/proxy token leaks in normal API or CLI output.
            Done 2026-07-09: `tinker_delegate.tinker_proxy` issues scoped
            HS256 proxy JWTs signed by `TINKER_PROXY_JWT_KEY` locally or
            dstack-derived `TINKER_PROXY_JWT_KEY_PATH` in CVM mode, encrypts
            delivery to a recipient X25519 public key with AES-256-GCM, exposes
            only subject/JWT-id hashes plus scopes/expiry, and verifies scoped
            bearer tokens. `GET /tinker/proxy/status` and
            `POST /tinker/proxy/token` are disabled by default; token issuance
            also requires configured runtime bearer auth. CLI commands
            `tinker-proxy-status` and `issue-tinker-proxy-token` preserve
            bounded output.
      - [x] Add recipient-side proxy-token delivery tooling.
            Done 2026-07-09: `tinker-proxy-recipient-keygen` writes an X25519
            private key to a local `0600` file and emits only the public key and
            hashes; `decrypt-tinker-proxy-token` decrypts an issuance envelope
            into a local `0600` JWT file and emits only token hashes/status.
            CLI tests cover keygen -> encrypted issuance -> recipient decrypt
            without printing the private key or plaintext JWT. Follow-up
            2026-07-09: failed issuance receipts now fail closed with a bounded
            `missing_encrypted_token` decrypt receipt before reading the
            recipient private key.
      - [x] Add a TEE-sealed Tinker SDK client-config store and bounded
            install/status surfaces.
            Done 2026-07-09: `tinker_delegate.tinker_client_config_store`
            persists `TINKER_PROJECT_ID` and optional `TINKER_BASE_URL` under
            local test encryption or dstack-derived CVM storage. `GET/PUT
            /tinker/proxy/client-config` require runtime bearer auth and return
            only project/base-url hashes, host-family classification, store
            status, and `raw_secret_egress=false`. `tinker-client-config
            --install` reads values from env vars instead of CLI args, supports
            deployed `--api-url` installs, and refuses to print the raw values.
            Proxy status, smoke validation, and future `ControlPlane` evaluator
            sessions now resolve SDK client config from this sealed store when
            env settings are absent. Tests cover store resolution, API
            install/status, CLI local/deployed install, proxy status, and smoke
            `ServiceClient(project_id=...)` construction without raw config
            egress. Live Phala provisioning/redeploy/smoke evidence remains
            open.
      - [ ] Bind proxy JWT issuance to production approval policy:
            approved user/agent identity, delivery public key, scopes, spend
            caps, expiration, revocation, audit record, and contract/compose
            policy.
            - [x] Add a hash-only proxy issue policy gate for subject,
                  recipient delivery key, scopes, and TTL cap. Done
                  2026-07-09: `TINKER_PROXY_REQUIRE_ISSUE_POLICY=true` plus
                  `TINKER_PROXY_ISSUE_POLICY_PATH` makes token issuance fail
                  closed unless a JSON policy grant matches the subject hash,
                  recipient public-key hash, requested scope subset, and TTL
                  cap. Issuance responses expose only bounded
                  `policy_binding` hashes/scopes/caps and never the raw subject
                  or recipient public key. Unit/API tests cover success,
                  wrong-recipient denial, TTL-cap denial, and required-policy
                  missing-path denial.
            - [x] Bind policy-issued proxy JWTs to operation spend caps for
                  add-balance. Done 2026-07-09: policy grants can include
                  per-scope `scope_limits` with `max_amount_usd`; spend-bearing
                  scopes such as `billing:add-balance` fail closed when a
                  required issue policy omits the cap. The JWT carries the
                  bounded `limits` claim, verification returns bounded
                  `scope_limits`, and `/billing/add-balance` rejects
                  proxy-authorized requests above the cap before invoking
                  browser/payment automation. Tests cover limit embedding,
                  missing-cap denial, over-cap rejection, and within-cap pass.
            - [x] Add operator-only proxy issue-policy install/status surfaces.
                  Done 2026-07-09: `GET/PUT /tinker/proxy/issue-policy` and
                  `tinker-proxy-issue-policy` install or read canonical
                  hash-only policy grants through runtime bearer auth. Outputs
                  are bounded summaries with policy/grant hashes, subject
                  hashes, recipient-key hashes, scopes, TTL caps, spend caps,
                  and `raw_secret_egress=false`; tests cover local save/status,
                  API install/status, and deployed-API CLI install without
                  leaking bearer tokens or raw subject/public-key material. The
                  funding-validation compose now includes disabled-by-default
                  policy env knobs for the next redeploy.
            - [x] Add a source/test-real deployment-policy gate before proxy
                  JWT minting. Done 2026-07-09:
                  `TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY=true` makes
                  `issue_encrypted_proxy_token()` preflight the configured
                  `TinkerAccountEncumbrance` contract and compose hash before
                  minting. Add-balance and Tinker-smoke scopes use the
                  policy grant's bounded `scope_limits.max_amount_usd`; read
                  scopes still require an approved compose hash through a
                  zero-amount manual-prefund check. Issuance responses include
                  only bounded deployment checks and `raw_secret_egress=false`;
                  tests cover approved compose issuance and denied-compose
                  fail-closed behavior before token creation.
            - [x] Redeploy the proxy issue/deployment policy source slice to
                  Phala, enable the policy flags, install a hash-only issue
                  policy, approve the new compose hash on-chain, and record CVM
                  ID, app ID, image digest, compose hash, quote evidence, policy
                  hash, and bounded issuance evidence.
                  Done 2026-07-09: GitHub Actions run `29043212028` built
                  source `d9807a028702ff2b0ee1c077cc0970cafc334475` into
                  delegate image
                  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:b0e7c63d276469d586a574a94bf0fc91feb0a223fa2cdb0dd3d49cd64c41a5ee`,
                  with provenance and SBOM attestations verified. The existing
                  Phala CVM `cvm_1w85mGjo` / app
                  `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` now attests live
                  app-compose hash
                  `40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace`
                  and OS image hash
                  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`.
                  Local verification binds raw/image-policy hash
                  `a860ba168b0334d8317fc56f0d2a971b79ad13bc206f5b43f3d04833d32f8eb7`,
                  rendered compose SHA-256
                  `b718208409a73f0bff4f2ab0efdead239111b7ff8fccc688ff889d103aad69d4`,
                  allowed policy env keys, app ID, OS image hash, and digest
                  pinned images. `TinkerAccountEncumbrance` approved the live
                  compose hash in tx
                  `0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6`
                  at block `43928500`; preflight returned
                  `allowed=true`, `compose_approved=true`,
                  `max_amount_wei=10000000000000000000`, and
                  `raw_secret_egress=false`. A hash-only issue policy was
                  installed with policy hash
                  `e4db29bfded844e0402e7ce61aba51360eb0fbe2aa1bab2013cd200b0164ea16`
                  and grant hash
                  `c2b23202b441ad6f9b80565f1b2b6cfc8402113b7c969485c76a7135a8a92a84`.
                  Live token issuance returned only encrypted delivery,
                  deployment-policy evidence, JWT-id hash
                  `0891923ea9aa068d058adcdfaf864ec9da88d2027c111806df7`,
                  token hash
                  `f795f81f6d399a285fabacb903c3384060f89371d3e918b52d5ce227516ceda4`,
                  and `raw_secret_egress=false`; the decrypted scoped proxy JWT
                  successfully called `tinker-proxy-status`.
            - [ ] Bind proxy grants to production user/agent identity approval
                  and reviewer-controlled grant lifecycle before treating this
                  as production governance.
                  - [x] Add hash-only grant lifecycle enforcement for
                        proxy issue policies. Done 2026-07-09:
                        `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE=true` makes
                        token issuance fail closed unless the matching policy
                        grant has bounded lifecycle metadata with
                        `status=active`, `approved_by_hash`, `approved_at`,
                        and `expires_at`. Pending, revoked, expired, missing,
                        or future-approved grants are rejected before JWT
                        minting. Policy summaries and issuance bindings expose
                        only lifecycle status, reviewer/approval-event hashes,
                        timestamps, and `raw_secret_egress=false`; tests prove
                        no raw reviewer identity is emitted. The
                        funding-validation compose now carries the disabled
                        `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE` env knob.
                  - [x] Add a hash-only proxy identity-registry gate for
                        requester and lifecycle approver hashes. Done
                        2026-07-09:
                        `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY=true` makes
                        issuance fail closed unless the requester's
                        `subject_hash` is an active user/agent identity and
                        the lifecycle `approved_by_hash` is an active
                        reviewer/admin identity in a schema-v1 hash-only
                        registry. Suspended, revoked, expired, missing, or
                        wrong-role identities fail before JWT minting. Issuance
                        emits only registry hash, identity hashes, roles,
                        statuses, expiries, and `raw_secret_egress=false`.
                        Focused tests cover success, missing registry,
                        suspended requester, and expired reviewer. The
                        funding-validation compose now carries disabled
                        lifecycle and identity-registry env knobs; local
                        `verify-compose-hash --phala-raw-compose` computes
                        raw/image-policy hash
                        `d4144c01872da1501d193f3b0b9936d06ebb04912740fd9b6ef90db420fc373d`
                        and rendered compose SHA-256
                        `a8451734acffd87426d28cdd1d8ba9aa2c2fa8cb2928da1cbb78a649ddfb8ccb`.
                  - [ ] Bind the hash-only identity registry to a production
                        verifier-controlled approval workflow, instead of
                        accepting any operator supplied registry and lifecycle
                        file.
                        - [x] Add a source/test-real verifier-signed identity
                              registry gate. Done 2026-07-09:
                              `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE=true`
                              makes proxy JWT issuance fail closed unless the
                              schema-v1 hash-only registry carries an Ethereum
                              signed-message signature over the canonical
                              registry hash from
                              `TINKER_PROXY_IDENTITY_REGISTRY_SIGNER`.
                              Tampered registries, missing signatures, wrong
                              signers, and malformed signatures fail before
                              JWT minting. Issuance bindings expose only the
                              registry hash, signer hash, signature hash,
                              verification status, and
                              `raw_secret_egress=false`; tests cover valid
                              signed registry issuance, missing signature,
                              tamper rejection, and wrong-signer rejection.
                              The funding-validation compose now carries
                              disabled
                              `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE`
                              and `TINKER_PROXY_IDENTITY_REGISTRY_SIGNER` env
                              knobs; local `verify-compose-hash
                              --phala-raw-compose` computes raw/image-policy
                              hash
                              `e682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`
                              and rendered compose SHA-256
                              `4c99b0f73a14bd40292ee71df343fd5e08f889e1932f4318d64657107e78e595`.
                        - [ ] Bind `TINKER_PROXY_IDENTITY_REGISTRY_SIGNER` to a
                              production verifier/reviewer identity source or
                              governance contract, and define the secure
                              recipient approval workflow that transmits
                              encrypted proxy JWTs only to approved users.
                              - [x] Add bounded verifier CLI tooling for signed
                                    hash-only identity registries. Done
                                    2026-07-09:
                                    `sign-tinker-proxy-identity-registry`
                                    reads an unsigned hash-only registry,
                                    normalizes it to schema-v1
                                    `identity_hash`/role/status/expiry rows,
                                    signs the canonical registry hash with a
                                    verifier key supplied only by environment
                                    variable, writes the signed registry to an
                                    explicit output file, and emits only
                                    registry hash, role counts, signer hash,
                                    signature hash, output path, and
                                    `raw_secret_egress=false`.
                                    `verify-tinker-proxy-identity-registry`
                                    externally verifies a signed registry
                                    against an expected signer address while
                                    returning only bounded hashes/status. CLI
                                    regression coverage signs, verifies, and
                                    uses the signed registry for actual proxy
                                    JWT issuance without printing raw
                                    identities, signer private key, signer
                                    address, raw signature, or plaintext JWT.
                              - [x] Add operator-only signed identity-registry
                                    install/status surfaces. Done 2026-07-09:
                                    `GET/PUT /tinker/proxy/identity-registry`
                                    and `tinker-proxy-identity-registry`
                                    install or inspect a normalized hash-only
                                    signed identity registry through runtime
                                    bearer auth. The install path verifies the
                                    registry signature when
                                    `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY_SIGNATURE=true`,
                                    writes the normalized registry artifact to
                                    the configured CVM path, and returns only
                                    registry hash, identity count, role counts,
                                    signature binding status/hashes, and
                                    `raw_secret_egress=false`. API and CLI
                                    regression coverage proves signed registry
                                    install/status can gate actual proxy JWT
                                    issuance without returning raw identities,
                                    runtime bearer token, signer address, raw
                                    signature, or plaintext JWT.
                              - [x] Add source/test-real reviewer-signed grant
                                    lifecycle approvals. Done 2026-07-09:
                                    `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE_SIGNATURE=true`
                                    makes proxy JWT issuance fail closed unless
                                    the active grant lifecycle carries an
                                    Ethereum signed-message signature over the
                                    canonical hash-only grant approval payload.
                                    The recovered signer address must hash to
                                    lifecycle `approved_by_hash`, so a policy
                                    editor cannot silently name a reviewer
                                    without reviewer key control. Issuance and
                                    policy summaries expose only approval hash,
                                    signer hash, signature hash, lifecycle
                                    status/timestamps, and
                                    `raw_secret_egress=false`.
                                    `sign-tinker-proxy-grant-lifecycle` writes
                                    the signed grant to an explicit output file
                                    using a reviewer key supplied only by env,
                                    and its bounded receipt proves no reviewer
                                    private key, raw signer address, raw
                                    signature, subject label, plaintext JWT, or
                                    upstream Tinker credential egress.
                                    Focused proxy and CLI tests cover valid
                                    signed grant issuance plus missing/wrong
                                    reviewer fail-closed behavior. The Phala
                                    funding-validation compose now carries the
                                    disabled
                                    `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE_SIGNATURE`
                                    env knob; reviewer private-key env is
                                    local-only and is not included in compose.
                                    Local `verify-compose-hash
                                    --phala-raw-compose` computes raw/image
                                    policy hash
                                    `af76ae49abfb8860bed46259de8a631f9f7c6c2056070ea31956f9a034ae0cc8`
                                    and rendered compose SHA-256
                                    `49b353c2b3d974e6f0e055ccde8e28b27cb31814351a5108d773ecbb9b2fd601`.
                  - [x] Redeploy the lifecycle/signature-required proxy issue
                        policy source slice to Phala, approve the resulting
                        compose hash, install an active lifecycle-bound issue
                        policy plus signed hash-only identity registry, and
                        record bounded issuance evidence. Done 2026-07-09:
                        after operator terminal approval tx
                        `0x3bc992cc2979aa8198923bcaf856d2c82d387646e49e750dada1f5cb203b3d17`,
                        live encrypted issuance succeeded for
                        `proxy:status`, local recipient decrypt saved a
                        plaintext JWT without returning it, and the live
                        `tinker-proxy-status` call accepted that scoped JWT
                        with bounded `proxy_auth_context`.
                        - [x] Redeploy the signature-required runtime gate to
                              the live Phala operator-validation CVM. Done
                              2026-07-09: live `tinker-proxy-status` reports
                              `issue_policy_required=true`,
                              `deployment_policy_required=true`,
                              `grant_lifecycle_required=true`,
                              `identity_registry_required=true`,
                              `identity_registry_signature_required=true`,
                              `identity_registry_signer_configured=true`, and
                              `raw_secret_egress=false`.
                        - [x] Install an active lifecycle-bound issue policy
                              plus signed hash-only identity registry through
                              the live runtime-authenticated API. Done
                              2026-07-09: policy hash
                              `47a6c41964ffac98bc90fd03216f419b1c1a0cee7a3a5152f88cbd5a308938d7`,
                              registry hash
                              `162df4185df255268bb03857d37da10c658240ae5b7067b1ff7eee40477bbb6a`,
                              two active identities (`agent`, `reviewer`),
                              signature verified, and
                              `raw_secret_egress=false`.
                        - [x] Approve the current compose hash on-chain and
                              rerun encrypted token issuance/decrypt/status.
                              Done 2026-07-09: operator terminal approved
                              `0xe682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`
                              in tx
                              `0x3bc992cc2979aa8198923bcaf856d2c82d387646e49e750dada1f5cb203b3d17`;
                              `approvedComposeHashes(...)` returned `true`;
                              live encrypted issuance returned
                              `plaintext_token_returned=false` and
                              `raw_secret_egress=false`; decrypt receipt
                              returned only token hash
                              `c77372674ecb06cef9a1a96bf22f2baa18edc980ce9f739e07906a7c16383d7c`;
                              scoped status returned subject hash
                              `979fb71132214bf62a7f332696061f0be32b1e60f00d02256d589df198393af8`
                              and JWT-id hash
                              `0acd4d8ffd865d253d8b200d209213bc7f384b59483f79c95fad240d663d1aee`.
                              Follow-up 2026-07-09: remote
                              `issue-tinker-proxy-token --api-url` now wraps
                              HTTP rejection bodies into bounded
                              `surface=tinker_proxy_token`,
                              `outcome=remote_rejected` receipts instead of
                              writing provider/API error JSON directly.
      - [x] Accept scoped proxy JWTs on the first bounded operation endpoints.
            Done 2026-07-09: `GET /tinker/proxy/status`,
            `POST /tinker/smoke`, `GET /billing/payment-method-status`, and
            `POST /billing/add-balance` now accept either the operator runtime
            bearer token or a proxy JWT with the matching scope:
            `proxy:status`, `tinker:smoke`,
            `billing:payment-method-status`, or `billing:add-balance`.
            Proxy-authorized responses include a top-level bounded
            `proxy_auth_context` for external replay; card mutation, card
            removal, funding receipts, reauth, and token issuance remain
            operator-runtime only.
      - [ ] Convert future approved-user Tinker operations to scoped proxy
            authorization rather than runtime-operator bearer tokens.
            - [x] Require and enforce per-scope spend caps for proxy-authorized
                  paid smoke. Done 2026-07-10: `POST /tinker/smoke` under a
                  proxy JWT now fails closed with 403 unless the token carries
                  a finite positive `scope_limits["tinker:smoke"].max_amount_usd`,
                  and rejects the request before any SDK/browser work when the
                  effective `max_usd` (payload or `real_sdk_max_usd` default)
                  exceeds that cap. Missing, malformed, non-finite, and
                  over-cap limits are all denied without invoking the smoke
                  runner; runtime-operator bearer auth is unchanged. API tests
                  cover within-cap pass, over-cap, missing-limit,
                  malformed-limit, and settings-default enforcement.
      - [x] Add sealed proxy-token issue/revoke audit records and revocation
            enforcement. Done 2026-07-09:
            `tinker_delegate.tinker_proxy_store.ProxyTokenStore` persists
            bounded `issued` and `revoked` records under local or
            dstack-derived AES-GCM encryption; issuance appends a bounded audit
            record; `verify_proxy_token()` rejects revoked `jwt_id_hash`
            values; operator-only API/CLI surfaces can list bounded audit
            records and revoke by hash without accepting or returning plaintext
            JWTs. Follow-up 2026-07-09: revocation now fails closed for
            unknown/non-issued `jwt_id_hash` values before writing a record,
            and repeated revocation of an already-revoked issued token returns
            the existing bounded revocation record instead of creating duplicate
            audit entries. Store, API, and CLI tests cover the no-dangling
            revocation behavior.
      - [x] Add external proxy-token audit-log replay/verifier artifact that
            checks issue/revoke chronology, expiration, scopes, and operation
            receipts without access to plaintext tokens.
            Done 2026-07-09: `verify-tinker-proxy-token-audit` verifies
            exported bounded audit JSON plus optional bounded operation receipt
            JSON. It checks record schema, summary counts, issue/revoke
            chronology, supported scopes, expiry windows, revocation timing,
            receipt `raw_secret_egress=false`, and `proxy_auth_context`
            binding when present or explicitly required. Tests cover happy
            path, revoked-before-operation, missing binding, unsupported scope,
            secret-key rejection, and CLI output.
      - [x] Deploy and attest the proxy-token verifier/context build on Phala,
            then record live bounded audit and operation-receipt replay
            evidence in `STATUS.md`.
            Done 2026-07-09: source
            `7cce6a2bc7897afba7a1599f9b51a381ac09a7dd` built into
            GitHub-attested delegate image
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:3ed351ed41540d7e47970b9b4d6a288d600b3856bc64c6f01996f4507d15b1eb`,
            which is pinned in
            `docker-compose.tinker-funding-validation.phala.yaml`. The live
            Phala funding-validation CVM attests app-compose hash
            `5bea582098b3767eec52d05a4f5a6773c59c44b606776421888479f58324956c`;
            `verify-cvm-attestation` passed for the app ID, OS image hash, raw
            compose hash, and digest-pinned images. The owner approved the
            compose hash in `TinkerAccountEncumbrance` tx
            `0x5af4fd76e922afc821c1db847aa3b65cbd44bc328a48786d6f7cca4a0e41d2cb`.
            Live packet `/tmp/dnai-proxy-audit-live-20260709T182943Z`
            issued an encrypted recipient-bound proxy JWT, used it against
            bounded `GET /billing/payment-method-status`, exported the bounded
            proxy audit log, and replay-verified the operation receipt with
            `verify-tinker-proxy-token-audit --require-operation-binding`
            (`ok=true`, one bound receipt, `raw_secret_egress=false`).
- [ ] `P0` No human operator can access the TEE-owned email account or Tinker
      account once production custody is established.
- [ ] `P0` Card/payment material is encrypted to a verified TEE before use and is
      never stored after the billing operation.
- [ ] `P0` Every production TEE image has a reproducible build story:
      git SHA -> image digest -> compose hash -> TDX quote.
- [ ] `P0` On-chain policy freezes compose/app measurements, not individual quote
      hashes. Quotes are fresh evidence; compose hashes are stable policy.
- [ ] `P0` Agents can request, evaluate, and report; agents cannot self-approve
      holds, widen grants, or bypass policy.
      - [x] Add source-modeled coordination enforcement for delegated-agent
            limits and self-approval denial. Done 2026-07-09:
            `tinker_delegate.coordination` denies delegated turns that exceed
            the grantor's corpus/purpose/pipeline scope at submit time and
            turns attempted self-approval of holds into a bounded terminal
            `self_approval_denied` state.
      - [x] Enforce non-self-approval structurally in the review queue too.
            Done 2026-07-12: a coordination `HandoffTicket` now carries
            `submitter_ref` (the held turn's `by`); `review_queue` hashes it onto
            the ticket as `submitter_ref_hash`, and `decide_review_ticket` rejects
            any reviewer whose ref hashes to the submitter's — so the submitting
            agent can never resolve its own held ticket even if the caller omits
            `blocked_reviewer_refs` (previously the only guard). Bounded (only
            hashes stored/emitted), backward compatible (no submitter_ref -> no
            change). `tests/test_review_queue.py` (+2) prove submitter-self-
            approve fail-closed and independent-reviewer still resolves.
      - [x] Add M-of-N approval for high-risk review roles. Done 2026-07-12:
            `enqueue_handoff_tickets(required_approvals_by_role={...})` sets a
            per-role approval threshold (default 1); a release accumulates
            DISTINCT reviewer approvals (`vote_recorded` audit events, ticket
            stays PENDING) until N is met -> RELEASED, a duplicate approver is
            rejected, and any single `deny` denies immediately (fail-closed).
            Bounded + persisted; `tests/test_review_queue.py` (+3) prove
            two-of-two release, duplicate-approver rejection, and single-deny
            blocks a 3-of-N ticket.
      - [x] Surface the review queue over the release-gated API. The initial
            operator API landed 2026-07-12; the current source exposes
            rate-limited public hash-only `GET /review/queue`, runtime-authenticated
            internal enqueue/expiry, one-time allowlisted reviewer-wallet
            challenges, and signed `POST /review/decide` without accepting a
            caller-supplied reviewer identity. Tests cover bounded pagination,
            role filters, persistence, self-review, duplicate approval,
            M-of-N release, conservative expiry, and unavailable authority.
      - [x] Enforce non-self-approval ON-CHAIN for funding operations. Done
            2026-07-12: `TinkerAccountEncumbrance.authorizeOperation` now reverts
            `SelfApprovalNotAllowed` when `requester == msg.sender` — the
            owner/manager authorizer cannot also be the requester of the funding op
            it authorizes, so the invariant holds structurally on-chain, not just
            by correct role assignment (a compromised delegate-manager can't
            self-authorize funding). `test/TinkerAccountEncumbrance.t.sol`
            +1 (`test_AuthorizerCannotSelfApprove`, owner and manager both
            rejected); full Foundry suite 135 green.
            Remaining activation work: production reviewer roster/key custody,
            email-oracle notification, a scheduled worker to poll
            `/review/expire`, and the fresh deployed release. The wallet-specific
            reviewer authorization path and SolidJS UI are implemented in source.
- [ ] `P0` Coordination composes policies by intersection, never union.
      - [x] Add a pure coordination reducer that combines per-corpus gate
            results by strict intersection. Done 2026-07-09: any deny denies,
            any hold holds, only all-pass can proceed to consent/settlement, and
            gate results must cover exactly the turn's corpus set.
- [ ] `P0` Bounded outputs are the only egress: score bands, yes/no, hashes,
      offers within cap, methodology summaries, cost/fee records, and audit
      attestations.
- [ ] `P0` Private reward values derived from sealed data do not leave the TEE
      unless they are explicitly released through the bounded-output reducer.
      - [x] Close the dict-key leakage bypass in the egress guard. Done
            2026-07-12 (self-review): `assert_bounded_egress`'s textual scan
            recursed dict *values* but not *keys* (and the structural float-ban
            uses keys only for path labels), so an exact reward smuggled as a key
            (`{"0.9731": "high"}`) leaked through both checks. Fixed across both
            layers: `_iter_strings` now scans keys (stringifying non-string keys,
            since JSON serializes a float/long-int key via its `str()`), and the
            structural `optimizer_export_guard._walk` now walks keys too (a float /
            numeric-array / blob key is caught structurally). Covers float-string,
            long-int-string, float, and long-int keys; regression tests added
            (`tests/test_private_reward.py`). Full suite stays green (no legitimate
            bounded output has a numeric-looking key).
      - [x] Fail closed (not RecursionError) on a hostile deeply-nested payload.
            Done 2026-07-12 (self-review): the egress guard's recursive walk had
            no depth bound, so an adversarial reducer returning a 5000-deep dict
            raised an uncontrolled `RecursionError` instead of a clean fail-closed
            rejection. Added a `_MAX_EXPORT_DEPTH=64` bound to
            `audit_optimizer_export._walk` (real bounded outputs nest only a few
            levels); over-deep structures now return `structure_too_deep` (highest
            priority) so `assert_bounded_egress` raises `RewardLeakageError` before
            reaching the unbounded textual scan. The textual scan `_iter_strings`
            is now depth-bounded too (`_MAX_EGRESS_DEPTH=64`), closing the one path
            that skipped the structural check — a deep subtree under the
            structurally-ignored `attestation` key. Regression tests in
            `tests/test_optimizer_export_guard.py` and `tests/test_private_reward.py`.
      - [x] Enforce it at the egress choke points. Done 2026-07-11:
            `private_reward.assert_bounded_egress` runs on every `BoundedFeedback`
            returned by `evaluate()` and every `BoundedResult` from `finalize()`
            (base + `synthetic`/`denoising` overrides). It fails closed with
            `RewardLeakageError` if the bounded dict contains any float / numeric
            array / oversized blob (via the shared `optimizer_export_guard`) or if
            any string field renders a float or long precise integer — closing the
            gap where a misbehaving `output_reducer` could smuggle the exact
            reward value into `public_message`. The `attestation` subtree is
            excluded from the structural float-ban only (it is public, separately
            governed env config such as holdout split fractions); the textual scan
            still covers it. `tests/test_private_reward.py` adds a leaky-reducer
            fail-closed test plus direct egress-assertion tests (16 in that file).
- [ ] `P0` If optimization updates leave the TEE, prove they do not encode
      private reward/data; otherwise keep optimizer state and reward-derived
      gradients inside the attested boundary.
      - [x] Add a fail-closed export guard that audits any proposed optimizer
            export. Done 2026-07-11:
            `tinker_delegate.optimizer_export_guard.audit_optimizer_export`
            recursively rejects the realistic leakage vectors — any `float`
            (exact reward values / reward-derived gradients are floats; bounded
            egress is bands/decisions/hashes/int-counts), numeric arrays over a
            small cap (gradient vectors / weight tensors / embeddings, even
            integer-encoded), oversized hex/byte blobs (could carry raw sealed
            data vs a hash), secret-shaped material (via shared `redact_text`),
            and a truthy `raw_secret_egress` self-declaration. Returns a bounded
            `ExportAuditResult` (allowed flag, reason code, offending field
            *paths* — never values, count, deterministic leakage hash);
            `certify_optimizer_export` is the fail-closed variant. A real bounded
            `LoopOutcome.to_public_dict()` passes; floats/gradients/blobs fail
            closed. `tests/test_optimizer_export_guard.py` (17). Self-review fix
            2026-07-12: also bound single-int magnitude to 256 bits
            (`oversized_int`) — one unbounded scalar int can carry a whole sealed
            blob via `int.from_bytes(...)` without tripping the per-array numeric
            cap, and as a dict VALUE it was invisible to the sibling textual
            reward scan (which only yields strings/keys), so this closed a real
            leak on the mandatory `assert_bounded_egress` publication path too
            (`tests/test_private_reward.py` +1). Legit uint256/counts/expiries
            still pass. Follow-up 2026-07-12: also bound the AGGREGATE integer
            payload to 512 bytes (`aggregate_int_payload`) — many separately-small
            in-bounds int fields (or many under-cap arrays) could still sum to a
            bulk exfil; a real LoopOutcome export is ~23 int-bytes so 512 gives
            >20x headroom while making KB-MB tensor/dataset exfil via aggregated
            ints infeasible. Bounds (does not eliminate) the channel; full suite
            confirms no legit-export false positives (`test_optimizer_export_guard`
            now 20). Self-review fix 2026-07-12: the sibling *textual* reward scan
            in `assert_bounded_egress` matched decimal floats (`\d*\.\d+`) but not
            scientific-notation floats without a decimal point — Python's `repr()`
            renders a very small/large reward as `1e-05` / `2e+16`, which has no
            decimal and no 6-digit run, so it evaded both textual patterns and
            could ride out inside a string. Added `_SCI_FLOAT_TEXT_PATTERN`
            (`\d[eE][+-]\d`); the *signed* exponent that `repr()` always emits is
            the discriminator — a bare `1e5` inside a hex hash has no sign, so the
            pattern adds no false positives (full suite green,
            `tests/test_private_reward.py` +1).
      - [x] Wire the guard as a mandatory gate on the loop's publication path.
            Done 2026-07-12: `LoopOutcome.certified_public_export()` is the
            mandatory choke point for publishing a run (checkpoint / on-chain
            packet / cross-boundary handoff). Instead of *trusting* that
            `to_public_dict()` is bounded by construction, it runs the shared
            fail-closed `assert_bounded_egress` gate over the exact bytes that
            would leave the boundary and raises `RewardLeakageError` if a reducer
            regression smuggled an exact reward (float), a reward-derived
            gradient (numeric array), or raw sealed data (oversized blob). The
            public, separately-governed `result.attestation` subtree (holdout
            split fractions), already egress-checked at `finalize()`, is excluded
            from the structural float-ban exactly as the `BoundedResult` egress
            check does; the returned dict is byte-identical to `to_public_dict()`.
            `tests/test_private_reward_loop.py` adds admit-real-outcome and
            fail-closed-on-smuggled-float tests (14 in that file).
- [ ] `P0` Bio/dual-use outputs must fail closed until the risk screen,
      reviewer queue, and bounded schema are real.
      - [x] Add the fail-closed bounded bio release gate. Done 2026-07-10:
            `tinker_delegate.bio_validation.evaluate_bio_release()` holds for
            human review unless every `BioReadiness` capability is real,
            denies on any forbidden-output match, holds non-DP
            individual-level data, and emits only bounded bands, hashes, and a
            screen verdict (`raw_secret_egress=false`). This is the enforcement
            mechanism; wiring real risk screens, the reviewer queue, and other
            bio egress paths into it keeps this invariant open.
      - [x] Wire the bio HOLD to the human-review queue end-to-end. Done
            2026-07-12: `tinker_delegate.bio_review_bridge` turns a HELD
            `BioReleaseReceipt` into a bounded review ticket (`enqueue_bio_hold`)
            — routed to the receipt's review role, keyed by the result hash, the
            evaluating agent recorded as submitter so it cannot self-approve, with
            optional per-role M-of-N — and `resolve_bio_release` maps the ticket
            state back to a final decision: only a queue RELEASED promotes the
            hold to RELEASE, DENIED becomes DENY, pending/expired/missing stays
            HOLD (fail closed). Bounded throughout (hashes only), and reachable
            over the `/review/*` API. `tests/test_bio_review_bridge.py` (8) prove
            hold-without-ticket, pending-holds, released-promotes, denied-denies,
            submitter-cannot-self-release, M-of-N biosecurity release, and the
            bounded status record. End-to-end integration test added 2026-07-12
            (`tests/test_bio_pipeline_integration.py`): a held bio result flows
            evaluate(HOLD) -> enqueue -> M-of-N release by two distinct officers
            (self-approval rejected, one officer insufficient, single deny vetoes)
            -> resolve(RELEASE) -> disclosure(ESCROW) -> solution_escrow seal +
            authorization-gated release, proving the modules compose with all
            fail-closed properties intact. Live auto-route added 2026-07-12:
            `evaluate_and_route` evaluates a candidate and auto-enqueues the
            receipt iff it HOLDs (idempotent per result hash; RELEASE/DENY leave
            the queue untouched), so a held result is never left un-queued
            (`tests/test_bio_review_bridge.py`, 11).
      - [x] Harden the always-on forbidden-output text screen against separator
            evasion. Done 2026-07-12: `screen_forbidden_output`'s compound
            dangerous-term patterns used `[- ]`/`\s*` classes that matched only
            hyphen/space, so `gain_of_function` (the underscore form ubiquitous in
            code-derived identifiers), `gain.of.function`, `de-novo`, and `de_novo`
            evaded the screen entirely (verified empirically: each returned `()`).
            Introduced a shared separator class `_SEP = [-_.\s]*` and applied it to
            the gain-of-function, de-novo, and wet-lab terms, so every separator
            form (including the concatenated `gainoffunction`) now matches. The
            ordered token sequence is itself the dangerous term, so the broadened
            class adds no false positives (benign "the function gain was high" /
            "novofunction" untouched; full suite green,
            `tests/test_bio_validation.py` +1).

## Milestone 0: Repo Truth, Baseline, And Documentation

- [x] `P0` Commit or otherwise intentionally land `ARCHITECTURE.md`.
      Done when the architecture doc is tracked and reviewers can diff it.
- [x] `P0` Fix stale docs that still say Tinker signup is fully solved by
      `cock.email`, no captcha, or disposable-domain choice.
      Done when `rg "fully working|no captcha|cock.email alone|RESOLVED"` has no
      misleading claims outside historical notes.
- [x] `P0` Update `⚙️/tinker-delegate/SPEC.md` to match current evidence:
      local Neko auth/API-key provisioning works, deployed CVM validation was
      pending at the time, and funding reached test-card decline before later
      one-off capped real funding evidence landed.
- [x] `P0` Add a `STATUS.md` or status block in `README.md` with:
      built, partial, modeled, planned, deployed addresses, current blockers,
      and test commands.
- [x] `P0` Sync `.claude/skills/`, `.codex/skills/`, and `.agents/skills/` if any
      skill instructions changed.
      Done 2026-07-10: `diff -rq` shows all thirteen skill directories are
      byte-identical across the three mirrors; the `test-all-skills.sh`
      helper was copied into `.agents/skills/` so the mirrors match exactly.
- [x] `P1` Add a `docs/DECISIONS.md` log for irreversible architecture choices:
      one CVM vs split CVMs, quote verification model, funding rails, data
      locality policy, and frontend deployment target.
      Done 2026-07-11: all five decisions are now recorded in
      `docs/DECISIONS.md` with honest status labels — result-submission quote
      verification (`[partial]`), single-combined-CVM topology (`[partial]`,
      grounded in the live 2026-07-11 topology verification), encumbrance-gated
      browser-mediated funding rails (`[partial]`), sealed-at-rest data locality
      (`[partial]`), and frontend deployment target (`[planned]`). Each entry
      carries a decision, rationale, and open follow-ups.
- [x] `P1` Add a machine-readable manifest of deployed resources:
      contract addresses, Phala CVM IDs, app IDs, compose hashes, image digests,
      BaseScan links, and gateway endpoints.
      Done in `deployments/base-sepolia.json`: the manifest records the current
      funded operator deployer, legacy Base Sepolia contracts with on-chain
      owner/developer reads, historical Phala/CVM evidence from the runbook, and
      the fresh-deployment helper/status without storing secrets.
- [x] `P1` Add a one-command local verification script that runs:
      contract tests, Python imports, compile checks, lint where available,
      Docker compose config validation, and docs stale-phrase checks.
      Done for the current implemented gates in `scripts/verify-local.sh`: it
      runs the repo secret scan, Foundry build/tests, frozen `uv` sync,
      Python compile checks, and Python unit tests where test suites exist.
      Docker compose validation and docs stale-phrase checks remain candidates
      for a later broader verification pass.

## Milestone 1: Contract And Settlement Foundation

### DiligenceRoom vNext

- [x] `P0` Add a chain watcher that listens for `DealCreated`, `DealFunded`,
      `EvaluationSubmitted`, `DealAccepted`, `DealRejected`, and `DealExpired`
      and calls the TEE control plane.
      Done when a local Anvil or Base Sepolia event creates/updates the matching
      control-plane state without manual curl calls.
      - [x] Add a JSON-RPC DiligenceRoom event decoder/dispatcher, bounded
            `/deal/chain-event` audit endpoint, `watch-chain` CLI, and tests
            proving `DealCreated` + `DealFunded` dispatch can call
            `/deal/notify-funded` while resolution events call
            `/deal/{deal_id}/resolve`.
      - [x] Prove the watcher against a local Anvil or Base Sepolia event so a
            real contract log creates/updates matching control-plane state.
            Done with `⚙️/tinker-delegate/scripts/prove-chain-watcher-anvil.py`:
            it starts ephemeral Anvil, deploys `DiligenceRoom` through an
            unlocked local account, emits real `DealCreated`/`DealFunded`
            logs, runs the watcher over JSON-RPC, and verifies a bounded
            control-plane stub receives deal `0` funded state without manual
            curl calls or raw private-key flags.
      - [x] Add durable cursor storage, restart recovery, and reorg/confirmation
            policy before production use.
            Done with `ChainCursorStore` plus `watch-chain --cursor-store`:
            the watcher persists next block, confirmation depth, contract hash
            summary, and public `DealCreated` context; restart tests prove a
            later `DealFunded` can still notify `/deal/notify-funded`; polling
            advances only after successful dispatch and only over
            confirmation-safe blocks.
      Production note: deployment wiring, chain-lag alerting, and live
      reorg/restart evidence remain covered by later operations tasks. The
      production deal loop now adds canonical block-hash checkpoints,
      conservative private-state quarantine/full rewind, and adversarial
      restart coverage on top of this local watcher P0.
- [ ] `P0` Implement TEE-to-chain transaction signing using a dstack-derived
      Ethereum key or equivalent TEE-held signer.
      Done when `submitResult()` can be broadcast from inside the CVM without raw
      private keys or `--private-key`.
      - [x] Add a dstack-derived Ethereum signer and bounded
            `submit-result` broadcaster for `DiligenceRoom.submitResult()`.
            The submitter has no raw-private-key CLI/env path, derives the
            production signer from dstack key material, preflights the public
            `deals(dealId)` state so the signer must match `teeIdentity`, checks
            funded state and compute budget before signing, broadcasts a raw
            transaction through JSON-RPC, and returns only bounded receipt
            metadata.
      - [x] Prove the submitter from a dstack simulator or deployed CVM against
            Anvil/Base Sepolia so `submitResult()` is actually broadcast from
            inside the attested runtime.
            Done with
            `⚙️/tinker-delegate/scripts/prove-chain-submitter-dstack-anvil.py`:
            it uses the Phala/dstack simulator as the key source, derives the
            TEE Ethereum signer inside the `submit-result` CLI path, funds that
            signer on ephemeral Anvil, creates/funds a DiligenceRoom deal with
            the derived signer as `teeIdentity`, broadcasts `submitResult()`,
            and verifies the real `EvaluationSubmitted` event without accepting
            or printing raw private keys.
      - [x] Prove the local synthetic room can drive real local escrow
            submission, settlement, and cleanup without widening egress.
            Done 2026-07-09 with
            `⚙️/tinker-delegate/scripts/prove-local-synthetic-room-anvil.py`:
            it starts ephemeral Anvil, deploys `DiligenceRoom`, creates/funds a
            deal, uploads an encrypted synthetic artifact through the FastAPI
            ingress, evaluates through `ControlPlane` + `IsolatedTinkerSession`
            + fake Tinker, obtains verifier authorization through the bounded
            `authorize-result` CLI, broadcasts `submit-result` from the
            dstack-simulator signer, accepts the deal, verifies
            `EvaluationSubmitted` and `DealAccepted`, checks pull-payment bands,
            and records cleanup attestations. It emits only hashes, bands,
            booleans, and transaction hashes; it does not prove deployed Phala,
            Base Sepolia, real Tinker SDK, or frontend verification.
      - [ ] Repeat the submitter proof from a deployed Phala CVM before marking
            production CVM signing complete.
- [ ] `P0` Bind `teeIdentity` to an attested compose/app identity instead of a
      bare trusted address.
      Done when result submission proves the signer is controlled by a verified
      measurement.
      - [x] Add an on-chain compose-hash approval gate to `DiligenceRoom`.
            Done 2026-07-11: `DiligenceRoom.sol` gains
            `approvedComposeHashes[bytes32]` plus developer-only
            `approveComposeHash` / `revokeComposeHash` /
            `setComposeApprovalRequired`, and `submitResult` reverts
            `ComposeHashNotApproved` when the gate is on and the authorized
            compose hash is not developer-approved on-chain. This binds a settled
            result to a governance-admitted measurement at the contract level —
            defense in depth beyond trusting the off-chain `resultVerifier`
            signature — mirroring `TinkerAccountEncumbrance.approvedComposeHashes`.
            Default `composeApprovalRequired=false` preserves the existing
            verifier-signature-only path; production deployments enable it.
            Contract tests (`test/DiligenceRoom.t.sol`, now 49 total) prove
            developer-only governance, zero-hash rejection, gate-off backward
            compatibility, unapproved-compose revert when required,
            approved-compose success, and revoke-blocks-submit.
      - [x] Wire the submitter preflight to the on-chain gate. Done 2026-07-11:
            `DiligenceRoomSubmitter` now reads `composeApprovalRequired()` and
            `approvedComposeHashes(composeHash)` before signing/broadcasting and
            fails closed with `compose hash is not approved on-chain` when the gate
            is enabled and the compose is unapproved — so it never spends gas on a
            transaction that would revert `ComposeHashNotApproved`, and the bounded
            receipt stays honest. New selectors/encoders
            (`encode_compose_approval_required_calldata`,
            `encode_approved_compose_hashes_calldata`, `decode_bool_call_result`)
            and reader methods (`read_compose_approval_required`,
            `read_compose_hash_approved`). `tests/test_chain_submitter.py` (+3, now
            15) prove fail-closed-before-broadcast (no tx sent), success when
            approved, and gate-off backward compatibility; the test `FakeRpc` now
            routes eth_call by selector.
      - [x] Prove the gate end-to-end on ephemeral Anvil. Done 2026-07-11:
            `scripts/prove-compose-approval-gate-anvil.py` deploys `DiligenceRoom`
            on a fresh Anvil chain (Anvil unlocked default accounts; no raw keys,
            no dstack), enables `composeApprovalRequired`, funds a deal, and drives
            `submitResult` isolating the gate by revert-reason change: unapproved
            compose reverts `ComposeHashNotApproved`; after `approveComposeHash` the
            same call passes the gate and reverts later on the dummy verifier sig
            (`InvalidResultAuthorization`); after `revokeComposeHash` it reverts
            `ComposeHashNotApproved` again — proving the gate admits exactly
            governance-approved measurements. Emits a bounded JSON summary
            (`raw_secret_egress=false`). Guarded test
            `tests/test_compose_approval_gate_proof.py` runs it when
            `DNAI_RUN_ANVIL_PROOFS=1` and foundry is on PATH (skipped by default;
            verified passing live this cycle).
      - [x] Bind the bare `teeIdentity` address to an attested measurement at
            deal creation. Done 2026-07-11: `DiligenceRoom.sol` gains
            `teeIdentityComposeHash[address]` (nonzero = approved, records the
            bound compose hash) plus developer-only
            `approveTeeIdentity(address,bytes32)` / `revokeTeeIdentity` /
            `setTeeIdentityApprovalRequired`. When enabled, `createDeal` reverts
            `TeeIdentityNotApproved` unless the seller-supplied `teeIdentity` is
            developer-approved, and `submitResult` reverts
            `ComposeHashIdentityMismatch` unless the submitted compose hash equals
            the identity's registered measurement — so a deal can only be created
            for, and settled by, a TEE whose identity governance has bound to a
            specific measurement. Default OFF (bare-address behavior preserved).
            Contract tests (`test/DiligenceRoom.t.sol`, now 58 total) prove
            developer-only governance, zero-address/zero-hash rejection, gate-off
            backward compatibility, create-revert-when-unapproved,
            create-success-when-approved, submit-success on identity/compose match,
            submit-revert on mismatch, and revoke-blocks-create.
      - [x] Drive the on-chain approvals from independently authenticated
            attestation rather than hand-written developer calls. Hardened
            2026-07-13: `build_governance_plan_from_verdict` requires the complete
            signed DCAP/QVL verdict plus externally supplied trusted-verifier
            addresses and exact chain/contract/TEE/compose/app/OS/quote pins. It
            verifies the canonical report-data binding, digest, low-s signature,
            signer independence, exact context, and freshness before emitting the
            bounded calls
            that admit that identity/measurement pair on-chain:
            `approveComposeHash(composeHash)` and
            `approveTeeIdentity(teeIdentity, composeHash)`. It fails closed on an
            unauthorized/zero-compose input. Per the no-self-approval invariant it
            does NOT execute — the plan carries `cast` command templates using
            `--account dev` (keystore, never a raw key) for the developer to
            broadcast. Operator surface: `governance-approval-plan
            <independent-verdict.json>` requires every trust root/release pin as a
            separate CLI argument and prints the bounded plan
            (`raw_secret_egress=false`, signature omitted). The legacy
            authorization-summary/boolean path always rejects. Adversarial tests
            cover forged summaries/signatures, self-declared trust, every context
            pin, missing policy, and expired/future/stale/overlong verdicts.
      Remaining (operational, not mechanism): (1) enable both gates by default for
      production; (2) redeploy — the current Base Sepolia `DiligenceRoom` predates
      both gates and does not expose them. Redeploy is NOT done autonomously: a
      `dev` keystore and `.env` deploy keys exist, but a live testnet deploy is an
      outward-facing, hard-to-reverse action that also needs an interactive
      keystore password — it requires explicit user confirmation (run
      `/forge-deploy` with `--account dev`). Blocked on that confirmation, not on
      code.
- [x] `P0` Make submitted results canonical and non-malleable:
      `DiligenceRoom.submitResult` no longer accepts any caller-provided result
      hash. The contract derives a domain-separated `DiligenceRoomPublicResult`
      commitment over chain/contract/deal identity, immutable funded-deal fields,
      compose hash, bounded score band, and deterministic compute tariff. The
      verifier and submitter recompute this exact commitment and share a fixed
      Solidity/Python parity vector. Payload hashes and reward-transcript
      commitments are absent from the production transaction and receipt path.
- [x] `P0` Define whether quote verification happens on-chain, in a verifier
      contract, through an attestation registry, or through a verified off-chain
      verifier whose signature the contract accepts.
      Decision recorded in `docs/DECISIONS.md`: current path is a verified
      off-chain submitter gate plus a `DiligenceRoom` result-verifier signature.
      The remaining gap is the production verifier service that validates live
      Phala quote evidence, compose/app identity, freshness, and revocation
      before issuing signatures.
- [ ] `P0` Implement the chosen quote-verification path for `submitResult()`.
      Done when a bogus TEE address cannot submit a result even if it knows the
      deal ID.
      - [x] Implement the pre-broadcast off-chain verifier gate in the
            `submit-result` path: dstack mode is required, signer quote evidence
            must match signer address, chain ID, contract address, report data,
            quote report data, and compose hash, and the bounded receipt carries
            quote hash/report-data/size without raw secret egress.
      - [x] Add verifier-signature contract or registry enforcement so a bogus
            bare `teeIdentity` cannot submit through the Solidity entrypoint.
            Done in `DiligenceRoom.sol`: `submitResult()` now requires an
            Ethereum-signed verifier authorization over chain ID, contract
            address, deal ID, TEE identity, compose hash, score band, compute
            cost, result commitment, and authorization expiry. Contract tests
            prove wrong verifier, expired authorization, and zero compose hash
            fail; the dstack-simulator Anvil proof uses an unlocked local
            verifier account to authorize the real CLI submission without raw
            verifier key material.
      - [ ] Build the production verifier service/path that validates live
            Phala quote evidence, approved compose/app identity, freshness, and
            revocation policy before issuing verifier signatures.
            - [x] Add a bounded result-verifier authorization module.
                  Done in `tinker_delegate.result_verifier`: it validates signer
                  attestation evidence against signer address, chain ID,
                  contract, report data, quote report data, approved compose
                  hashes, approved app IDs, optional OS image hashes, revoked
                  quote hashes, revoked TEE signers, and a short authorization
                  TTL before signing the exact `DiligenceRoom` authorization
                  digest. Tests cover accepted authorization, policy mismatch,
                  quote-context mismatch, revocation, self-approval rejection,
                  and dstack-only verifier key custody.
            - [x] Wrap the verifier module as a deployed service or operator
                  path that receives bounded quote evidence from the submitter
                  and returns only authorization metadata/signature.
                  Done as the `result-verifier-address` and `authorize-result`
                  CLIs. `authorize-result` accepts bounded signer-attestation
                  JSON plus explicit compose/app/OS-image allowlists and
                  revocation lists, derives the verifier key from dstack, emits
                  only bounded authorization metadata plus the public verifier
                  signature needed by the contract, and has no raw-private-key
                  flags. The dstack-simulator Anvil proof now deploys
                  `DiligenceRoom` with the dstack-derived verifier address and
                  obtains authorization via this CLI path instead of Anvil
                  `eth_sign`.
            - [ ] Add cryptographic Intel TDX quote parsing/freshness once the
                  production quote evidence format is available.
                  - [x] Add STRUCTURAL TDX quote parsing (report_data binding).
                        Done 2026-07-12 in `tinker_delegate.tdx_quote`: a DCAP v4
                        parser extracts report_data + MRTD/RTMRs from raw quote
                        bytes at spec offsets (report_data [568:632], stable for
                        TD10/TD15), failing closed on unsupported version, non-TDX
                        tee_type, truncated buffers, or non-bytes. Wired into
                        `verify_attestation_envelope(..., enforce_quote_binding=True)`
                        so the report_data embedded IN the quote must equal the
                        claimed report_data — closing the "trust the parallel
                        claimed field" gap. Fail-closed by construction: a wrong
                        offset/unknown format can only reject, never accept.
                        Tests place fields at literal offsets independent of the
                        parser constants (`tests/test_tdx_quote.py`, 9). Default
                        off preserves opaque/simulator-quote behaviour.
                  - [ ] Remaining (blocked on real quote evidence): verify the
                        Intel signature/cert chain + freshness/revocation via
                        QVL/dstack, and cross-check the structural parser against a
                        captured production quote (version 5 layout still fails
                        closed until a sample is available).
      - [ ] Repeat the verifier-authorized submitter proof from a deployed Phala
            CVM against Base Sepolia or an Anvil fork.
- [x] `P1` Add ERC20/USDC support in addition to native ETH.
      Done when buyer deposits and pull payments work with a stablecoin.
      Done 2026-07-11 in `DiligenceRoom.sol`: each `Deal` carries a
      `paymentToken` (`address(0)` = native ETH, else ERC20). `createDeal` has a
      5-arg overload taking `paymentToken` (4-arg overload stays native);
      `fundDealERC20(dealId, amount)` pulls tokens via `transferFrom`
      (checks-effects-interactions: state set before the external call);
      `fundDeal` and `fundDealERC20` cross-guard with `TokenMismatch`.
      `pendingWithdrawals` is now `token => recipient => amount`; `withdraw()`
      keeps native, `withdraw(address token)` pays a token via a bool-checked
      `_safeTransfer`. Settlement math (accept/reject/expire, 1% fee) is
      identical for both. The `Deal` struct appends `paymentToken` LAST so the
      off-chain submitter's positional `deals()` decode of the leading fields is
      unchanged (Python suite still green). `via_ir=true` was enabled to resolve
      the 14-field getter's stack-too-deep. `DiligenceRoom.t.sol` gains a
      `MockERC20` + 8 ERC20 tests (accept/reject/expire lifecycles, conservation,
      token-mismatch both directions, missing approval, nothing-to-withdraw);
      42 contract tests pass. ABI changed → the deployed room needs a redeploy to
      expose the token path.
- [x] `P1` Add protocol-fee configuration with timelock/freeze semantics.
      Done 2026-07-11 in `DiligenceRoom.sol`: `FEE_BPS` became a governable
      `feeBps` state variable (default `DEFAULT_FEE_BPS`=100/1%). Developer-only
      `proposeFeeBps(newBps)` stages a change behind a `FEE_TIMELOCK_DELAY`
      (2 days) and caps it at `MAX_FEE_BPS` (1000/10%); `activateFeeBps()` applies
      it after the timelock; `cancelFeeBpsProposal()` drops a pending proposal;
      `freezeFeeBps()` permanently locks the fee and blocks further proposals.
      The fee is read at `submitResult` time and stored on the `Deal`, so a change
      never retroacts on already-evaluated deals (proven by
      `test_FeeChangeDoesNotRetroactOnEvaluatedDeal`). 9 new tests
      (`DiligenceRoom.t.sol`, 73 total): propose/activate, too-early, too-high,
      only-developer, proposal-exists, cancel, freeze-blocks, default, and
      non-retroaction. Full contract suite: 110 tests, 0 failed.
      Coupling closed 2026-07-11: `DiligenceRoomSubmitter` now reads `feeBps()`
      on-chain (`read_fee_bps`, `encode_fee_bps_calldata`,
      `decode_uint256_call_result`) for the over-budget preflight instead of a
      hardcoded 1%, and falls back to the 1% default for older deployments whose
      contract lacks the getter (empty/zero return). `tests/test_chain_submitter.py`
      (+3, now 18): a raised on-chain fee tightens the budget check, the default
      getter path submits, and the fallback returns 100. Deployed Base Sepolia
      room predates the governable fee and needs a redeploy to expose it.
- [x] `P1` Add staged rental states:
      `raw_inspection`, `training`, `inference`, `full_disclosure`, each with its
      own cap, reserve, result type, and consent requirements.
      Done 2026-07-11: `tinker_delegate.rental_stages` is a pure, fail-closed
      progressive-disclosure state machine. Each `StagePolicy` carries a
      `reserve_wei`, `cap_wei`, bounded `ResultType`
      (`score_band`/`utility_band`/`yes_no`/`artifact`), and `requires_consent`;
      a `RentalLadder` validates the stages are unique and in strictly increasing
      disclosure order. `advance_stage` enforces monotonic disclosure (no
      regression or same-stage re-pay; skipping to a higher tier is allowed only
      if that tier's requirements are met), owner-supplied consent (the requester
      can never self-approve), a hard rule that `full_disclosure` (raw artifact)
      always requires consent, and reserve/cap bounds — every failure DENYs with a
      bounded reason code. Output is a bounded `StageTransition`
      (`raw_secret_egress=false`). `default_rental_ladder()` gives sensible tiers.
      `tests/test_rental_stages.py` (13) cover forward progress, regression/
      same-stage denial, tier-skipping, the full-disclosure consent hard rule,
      per-stage consent, reserve/cap bounds, out-of-ladder targets, boundedness,
      and malformed-ladder rejection. Wiring these tiers into `DiligenceRoom`
      deal lifecycle + the consent layer remains a follow-up.
- [x] `P1` Add per-query royalty settlement for corpus owners.
      Done when a surfaced turn can meter multiple corpus owners and accrue pull
      payments.
      Done 2026-07-11: `tinker_delegate.royalty_settlement` adds multi-owner
      per-query royalty settlement. `split_royalty(total, shares)` divides a
      per-query royalty among co-owners by `OwnerShare` weights (basis points
      summing to 10000) using the largest-remainder method, so payouts sum to
      *exactly* the total (no wei created/lost, deterministic tie-break by
      owner_ref). `RoyaltyLedger` accrues each split into per-owner claimable
      balances and preserves the three-way conservation invariant
      `claimable + claimed == accrued` (self-review fix 2026-07-12: the meter now
      tracks the claimed total and exposes `total_claimed()` /
      `total_claimed_band`; the previous `claimable == accrued` check falsely
      reported not-conserved after any withdrawal, since claimed funds legitimately
      leave the pool — a real bug in the bounded money-path audit signal);
      `claim(owner)` is the pull-payment withdrawal (fails closed
      on nothing-to-claim), and `public_summary()` emits bounded per-owner amount
      bands, an accrual count, a `conserved` boolean, and a settlement hash
      (`raw_secret_egress=false`). `tests/test_royalty_settlement.py` (12) prove
      conservation across many amounts/weights (incl. 0, 1, and 1e18+7), even and
      uneven splits, determinism, weight/uniqueness/negative validation, the
      accrue→claim lifecycle, ledger conservation over 20 uneven accruals, and
      bounded summary. Wired into coordination 2026-07-11: `Corpus` gains an
      optional `owner_shares` ((owner_ref, weight_bps) summing to 10000, validated
      in `__post_init__`); when set, `coordination._royalty_meters` splits the
      corpus's `royalty_per_query` across co-owners via `split_royalty`, emitting
      one conserving `RoyaltyMeter` per owner (single-owner corpora unchanged).
      `tests/test_coordination.py` (+2) prove a co-owned corpus settles into two
      conserving meters (700M/300M of 1e9) and that malformed weights raise.
      Advanced 2026-07-24 (superseding the historical direct-distribution-only
      milestone): `RoyaltyDistributor.sol` v3 now provides deterministic,
      intent-keyed native/ERC20 prefunding reservations. After the complete fresh
      owner-grant set fixes the allocation, the sponsor escrows the exact asset
      and amount under a request that binds the release, room/state, query,
      grants, allocation, sorted owner/amount hash, settlement ID/nonce,
      execution commitment, and refund deadline. Worker admission uses the
      compact reservation getter at one RPC-reported finalized,
      EIP-1898-pinned block; aggregate balance and allowance are not authority.
      After bounded Compute, the exact decision is anchored on demand, the main
      runtime and independent Royalty QVL authorize purpose-separated EIP-712
      digests, the sponsor wallet broadcasts the generated zero-value
      `settleReserved` transaction, and the worker reconciles the finalized
      receipt with the permanent reservation-settlement getter. Reservation
      consumption, replay markers, and all owner credits are atomic; expired
      unused reservations are sponsor-refundable; `totalReserved + totalPending`
      remains solvent per asset. Direct `distributeNative` /
      `distributeERC20` are retained only for compatibility.

      Current local proof: the full Foundry suite passes 444/444; the focused
      Royalty run covers 55 unit tests and five invariant properties, including
      native and ERC20 campaigns at 256 runs/128,000 calls each; the focused
      Python checks pass 35 tests plus 5 subtests; and the guarded Anvil group
      passes 3/3. The distribution-plan proof now executes reservation ->
      zero-value `settleReserved` -> finalized permanent reconciliation ->
      conserving pull-payment. These are source/local protocol proofs, not a
      third-party audit, Base Sepolia deployment, Phala/TDX run, independent QVL
      verdict, or live sponsor payment.
      - [x] Bridge the settled split to the on-chain rail as a bounded plan.
            Advanced 2026-07-24: `tinker_delegate.royalty_distribution_plan`
            recomputes the owner/amount hash and encodes exact `settleReserved`
            calldata for an already dual-authorized, prefunded settlement. The
            strict persisted-plan parser rejects drift before wallet handoff. It
            emits a `--account dev` keystore `cast` template, never a raw key, and
            does not invent entitlement, sign, or broadcast. The authoritative
            source/test sequence is fresh grants -> deterministic reservation ->
            finalized admission -> bounded Compute -> exact anchor plus main/QVL
            authorization -> sponsor-wallet settlement -> finalized
            reconciliation -> conserving owner pull-payment.
- [x] `P1` Add settlement conservation fuzz tests for multi-owner and ERC20
      paths.
      Done 2026-07-11 in `DiligenceRoom.t.sol` (64 tests total): added 6 fuzz
      conservation tests covering every settlement path and both assets. Native:
      `testFuzz_RejectConservation` (dev=compute+fee, dev+buyer=cap) and
      `testFuzz_ExpireEvaluatedConservation`, plus `test_ExpireFundedRefundsFullBudget`
      (no result → buyer refunded the whole cap). ERC20:
      `testFuzz_ERC20AcceptConservation` (3-way seller/dev/buyer split sums to
      cap and equals the room's token balance), `testFuzz_ERC20RejectConservation`,
      and `testFuzz_ERC20EndToEndWithdrawalConservation` (drives the full
      accept → withdraw lifecycle and asserts the room ends with zero balance and
      the sum withdrawn equals the funded cap — nothing created, stuck, or
      destroyed). Each runs 256 fuzz cases. The 3-way accept split IS the
      multi-owner conservation surface today; per-query royalty for additional
      corpus owners remains a separate open feature above. Two fuzz edge cases
      were caught and fixed during authoring (an unbounded-input overflow and a
      zero-payout `NothingToWithdraw` on exact-budget deals).
- [x] `P1` Add contract-level tests for expiry around in-flight evaluations,
      double-submits, stale quote nonces, and over-budget compute.
      Done 2026-07-11 in `DiligenceRoom.t.sol` (34 tests total): expiry from
      Created/Funded/Evaluated (`test_ExpireDeal_*`) and over-budget compute
      (`test_SubmitResult_RevertComputeCostOverBudget`) were already covered;
      added `test_SubmitResult_RevertDoubleSubmit` (a second submit on an
      Evaluated deal reverts on the state guard), `test_SubmitResult_
      RevertCrossDealAuthorizationReplay` (a verifier authorization signed for
      deal A cannot be replayed on deal B because the digest binds dealId), and
      `test_Withdraw_ReentrancyCannotDoublePay` (a re-entrant withdrawer finds a
      zeroed balance and cannot double-withdraw — proves checks-effects-
      interactions ordering). All pass under `forge test`.
- [ ] `P2` Add a public read API or subgraph/indexer for rooms, deals,
      attestations, and payout status.

### TinkerAccountEncumbrance.sol

- [x] `P0` Decide whether to create a dedicated `TinkerAccountEncumbrance.sol` or
      extend `DiligenceRoom.sol` plus `EmailOracleAuth.sol`.
      Decided in code/docs: use a dedicated minimal
      `TinkerAccountEncumbrance.sol` for Tinker account policy/audit, separate
      from `DiligenceRoom` escrow settlement and `EmailOracleAuth` OTP
      consumer policy.
- [x] `P0` Specify the on-chain responsibilities of Tinker encumbrance:
      account identity, funding policy, spend limits, approved measurements,
      allowed billing operations, emergency halt, and audit events.
      Done in `TinkerAccountEncumbrance.sol`: it stores a hashed account
      commitment, approved compose hashes, per-operation add-balance/spend caps,
      manager delegation, measurement freeze, emergency halt, operation
      authorization, and bounded receipt settlement events.
- [x] `P0` Implement a minimal `TinkerAccountEncumbrance.sol` if the separate
      contract route is chosen.
      Done with the dedicated contract under
      `⚙️/tinker-delegate/contracts/src/TinkerAccountEncumbrance.sol`.
- [x] `P0` Add tests proving no manager can exceed owner/deployer-granted
      authority.
      Done in `TinkerAccountEncumbrance.t.sol`: managers can authorize/settle
      bounded operations inside owner-set caps and approved measurements, but
      cannot set managers, change caps, approve measurements, toggle emergency
      halt, exceed caps, or bypass compose/emergency/duplicate guards.
- [x] `P0` Add a local runtime preflight/helper that reads
      `TinkerAccountEncumbrance` before browser-mediated Tinker funding.
      Done with `tinker_encumbrance.py`, the `tinker-encumbrance-preflight`
      CLI, funding-preflight integration, and card/add-balance handler gates.
      When `TINKER_ENCUMBRANCE_REQUIRED=true` or a contract address is
      configured, payment-method and add-balance automation deny before
      decryption/browser launch unless the compose hash is approved, the
      contract is not halted, and the amount is within cap.
- [x] `P0` Add a no-raw-key Base Sepolia deploy helper for
      `TinkerAccountEncumbrance`.
      Done in
      `⚙️/tinker-delegate/contracts/script/TinkerAccountEncumbrance.s.sol`
      and
      `⚙️/tinker-delegate/contracts/scripts/deploy-tinker-encumbrance-base-sepolia.sh`.
      The helper reads `.env`, uses Foundry `--account dev` instead of raw
      private keys, validates bytes32/cap inputs, defaults the initial compose
      hash from the current Phala deployment manifest, defaults the initial
      account commitment to the bounded `oracleEmailHash` when no stronger
      Tinker account commitment is supplied, runs build/tests, dry-runs first,
      and rewrites `deployments/base-sepolia.json` only after a successful
      broadcast plus on-chain reads.
- [ ] `P1` Add funding rail policy:
      developer prefund, buyer compute deposit, crypto top-up, A2A/ACH/card
      path, and manual emergency funding.
- [ ] `P1` Emit events for every funding operation:
      requested, authorized, attempted, succeeded, failed, card payload destroyed.
- [ ] `P1` Connect Tinker spend/cost records to buyer escrow and developer fee.

### EmailOracleAuth Completion

- [x] `P0` Enforce `EmailOracleAuth` at the FastAPI `/pin` endpoint and remove
      general mailbox egress.
      Done: `/inbox` is absent, `/email` is commitment-only, and authenticated
      callers cannot retrieve mailbox identifiers, headers, dates, or raw
      addresses.
      - [x] Add runtime bearer guard for `/pin` so unauthenticated network
            callers cannot retrieve OTPs.
      - [x] Check the caller identity against the on-chain `EmailOracleAuth`
            consumer registry before releasing an OTP.
            Done with `email_oracle.chain_auth` and the FastAPI `/pin` guard.
            When `ORACLE_AUTH_REQUIRED=true` or a contract is configured, the
            service fails closed before IMAP access unless
            `isConsumerAuthorized(ORACLE_AUTH_CONSUMER_APP_ID,
            ORACLE_AUTH_CONSUMER_COMPOSE_HASH)` returns true; optional
            `ORACLE_AUTH_EXPECTED_CALLER_IDENTITY` binds `/pin` request metadata.
- [ ] `P0` Register the final oracle compose hash and consumer compose hash on
      Base Sepolia.
- [ ] `P0` Turn off `allowAnyDevice` for production or document why it remains
      allowed during a specific test phase.
- [x] `P0` Implement same-CVM derived-key bearer auth for the current combined
      deployment.
- [ ] `P1` Implement split-CVM runtime auth with RA-TLS or attestation-backed
      signed requests.
- [x] `P1` Add consumer-manager role tests:
      manager can add/revoke consumers, cannot change oracle code policy, cannot
      unfreeze anything.
      Done 2026-07-11: `EmailOracleAuth.t.sol` expanded 11 -> 28 tests. Existing
      tests already prove a delegated manager can add consumer compose hashes and
      cannot change oracle policy (`test_OwnerCanDelegateConsumerManagement`,
      `test_ManagerCannotChangeOraclePolicy`) and that freezes are permanent
      (`test_FreezeConsumerRegistry_BlocksOwnerAndManager`,
      `test_FreezeOracleCodeAuth_*`). New tests close the untested governance
      paths: oracle compose-hash proposal lifecycle
      (cancel-blocks-activation, cancel/activate `NotPending`, `AlreadyPending`,
      `AlreadyAllowed`, `ZeroHash`), `removeOracleComposeHash` (revokes +
      `NotAllowed`), `setAllowAnyDevice` toggle re-enabling any device,
      add/remove-device `AlreadyAllowed`/`NotAllowed`, `transferOwnership`
      (moves control, old owner loses access, zero-address revert), and
      access-control reverts (non-owner propose / set-manager, manager cannot
      add device, non-manager cannot add consumer). Full contract suite: 95
      tests, 0 failed.
- [x] `P1` Add emergency consumer revocation that is immediate, not timelocked.
      Done 2026-07-12: `EmailOracleAuth.emergencyRevokeConsumer(consumerAppId)` is
      a kill switch — it flips `consumerEmergencyRevoked[consumer]` so
      `isConsumerAuthorized` returns false for EVERY compose hash of that consumer
      at once, immediately, with no timelock. Crucially it is NOT gated by the
      registry freeze (per-hash `removeConsumerComposeHash` is, so a frozen
      registry could otherwise never kill a compromised consumer). Owner or a
      consumer manager may trigger it (access-reducing); `restoreConsumer` is
      owner-only and only while the registry is still mutable, so once frozen an
      emergency kill is permanent. `test/EmailOracleAuth.t.sol` (+7, 36 total)
      prove revoke-all, works-when-frozen, manager-can-trigger, non-manager
      rejected, zero/double rejected, restore-before-freeze-only, and restore
      access-control.
- [x] `P1` Freeze oracle code authorization after the final audited image.
      Already real: `EmailOracleAuth.freezeOracleCodeAuth()` sets `oracleCodeFrozen`
      and the `whenOracleCodeMutable` modifier blocks all oracle compose/device
      mutations thereafter (tested).
- [x] `P1` Optionally freeze the consumer registry after final consumer
      measurements are known. Already real: `freezeConsumerRegistry()` sets
      `consumerRegistryFrozen`; `whenConsumerRegistryMutable` blocks add/remove of
      consumer compose hashes thereafter (tested), while emergency revocation
      still works (above).
- [x] `P2` Add on-chain OTP delivery receipts or hashed audit events if needed
      for dispute resolution.
      Done 2026-07-12: `EmailOracleAuth.recordOtpDelivery(consumerAppId,
      deliveryHash)` emits an `OtpDeliveryRecorded(consumer, deliveryHash,
      sequence, timestamp)` audit event, where `deliveryHash` is an off-chain
      commitment to the delivery context (consumer, request id, OTP hash) — the
      raw OTP never touches the chain. A per-consumer `otpDeliveryCount` gives an
      ordered `sequence` so gaps/duplicates are detectable for disputes. Owner or
      a consumer manager may record; fail-closed on zero address/hash and refuses
      to record for an emergency-revoked consumer. `test/EmailOracleAuth.t.sol`
      (+5, 41 total) prove ordered sequence + event emission, manager-can-record,
      non-manager rejected, zero-input rejection, and revoked-consumer fail-closed.
      Off-chain pairing 2026-07-12: `tinker_delegate.otp_delivery` computes the
      `deliveryHash` the delegate hands to `recordOtpDelivery` —
      `keccak256(domain || consumer || request_id || keccak256(otp))` — hashing
      the OTP immediately so the raw code never leaves as anything but a hash.
      `otp_delivery_receipt` is a bounded receipt (consumer/request hashed, OTP
      only as a hash, `raw_secret_egress=false`). `tests/test_otp_delivery.py` (6)
      prove determinism, input-distinctness, missing-input rejection, and that the
      raw OTP / consumer / request never appear in any output.

## Milestone 2: DevProof TEE Deployment And Verification

- [ ] `P0` Make every service Dockerfile reproducible:
      pin base images by digest, pin package manager versions, normalize
      timestamps, avoid mutable tags, and generate SBOMs.
      - [x] Pin the deploy-critical `tinker-delegate` and `tee-email-oracle`
            Dockerfile Python and `uv` image sources by versioned digest.
      - [x] Add GitHub-hosted image builds for the deploy-critical services
            that push `linux/amd64` GHCR images with BuildKit SBOM/provenance
            attestations plus GitHub-signed provenance and SPDX SBOM
            attestations.
      - [x] Add `scripts/verify-ghcr-image-attestation.sh` to fail deployment
            unless a digest-pinned GHCR image verifies against the expected
            GitHub repo, signer workflow, source commit, SLSA provenance
            predicate, and SPDX SBOM predicate.
      - [ ] Pin apt package versions, normalize timestamps, and generate
            release SBOM evidence for every remaining service Dockerfile.
- [x] `P0` Fix the `tinker-delegate` Dockerfile to install the optional Tinker
      agent dependency, not only the base package.
      Done when the CVM image reports `agent_stack_available=true`.
      `⚙️/tinker-delegate/scripts/verify-agent-image.sh` now rebuilds the image
      and verifies `import tinker` plus the `agent_stack_available` probe inside
      the packaged image.
- [x] `P0` Add a compose-hash verification script that reproduces the Phala
      compose hash from local source and deployed image digests.
- [ ] `P0` Add a TDX quote verifier script for the running CVM.
      Done when a user can verify app ID, compose hash, image digest, report
      data, freshness, and public keys from a laptop.
      - [x] Add an artifact uploader gate that refuses local/default
            attestation, compose-hash mismatch, app-ID mismatch, malformed
            quote/public-key fields, and report-data/key mismatch before
            encryption.
      - [x] Add a standalone `verify-attestation` CLI that live-fetches
            `/attestation?context=...` and verifies mode, quote presence,
            compose hash, app ID, OS image hash, public-key shape, report-data
            key binding, and client fetch freshness before accepting the
            evidence envelope.
      - [x] Reject exposed `quote_report_data` unless it is a 32-byte hex value
            exactly matching the context/key-bound `report_data`; this tightens
            the public quote envelope without claiming full quote parsing.
      - [x] Add `verify-cvm-attestation` and
            `scripts/verify-cvm-attestation.sh` so an operator can tie a live
            CVM attestation to the locally rendered Phala compose hash and
            required digest-pinned images from a laptop.
      - [x] Add `verify-deployment-bundle` so an operator can verify the full
            current deploy chain in one bounded JSON packet: GitHub-signed SLSA
            provenance and SPDX SBOM attestations for digest-pinned GHCR
            oracle/delegate images, those exact image refs in the Phala compose,
            required sidecar digests, and the live CVM app/compose/OS-image
            attestation envelope.
      - [ ] Add cryptographic Intel TDX quote parsing and quote-internal
            freshness checks; current `dstack_sdk` helpers do not expose a
            complete verifier.
      - [x] Run `verify-cvm-attestation` against a real Phala CVM and record
            app ID, compose hash, image digest, report data, public key,
            fetched-at time, and command evidence in `STATUS.md`.
      - [x] Run `verify-deployment-bundle` against the current Phala CVM and
            record the combined GitHub-attestation-to-Phala-attestation evidence
            in `STATUS.md`.
- [x] `P0` Deploy the combined email-oracle + tinker-delegate stack to Phala
      from registry images only, no local `build:` contexts.
      Done 2026-07-08: CVM `670b3b21-4338-4d4e-ae72-7c8922579f59`
      runs app ID `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` from
      digest-pinned GHCR oracle/delegate images plus digest-pinned Neko and
      Playwright sidecars. Oracle is intentionally degraded until email
      credentials are provisioned; delegate health is `ok` with no API key
      configured and `bootstrap_attempted=false`.
- [ ] `P0` Persist only sealed data under the CVM data volume:
      email creds, Tinker API key, funding token state, and run metadata.
      - [x] Persist email-oracle OTP replay hashes in an encrypted/sealed ledger
            so OTP one-time-use survives service restart without storing OTPs.
      - [x] Add attestation-bound encrypted ingress for existing email
            credentials: `GET /attestation?context=oracle-credentials` exposes
            a quote-bound public key, `POST /credentials/encrypted` is disabled
            by default behind an explicit provisioning token, stores credentials
            through the sealed credential store, and returns only hashes/status.
      - [x] Store captured Tinker API keys in the encrypted key store and return
            only bounded hash/status metadata from signup/bootstrap.
      - [x] Bound Tinker signup/signin observable outputs before deployed
            bootstrap: signup/signin stdout and return payloads now expose
            `email_hash` / `url_hash` instead of raw mailbox addresses or
            Tinker URLs, and regression tests cover stdout and result egress.
      - [x] Confirm currently implemented funding state and run metadata are
            sealed/persisted only under the CVM data volume: bounded funding
            receipts use `/data/funding_receipts.enc`, and control-plane deal
            lifecycle metadata now uses `/data/run_metadata.enc` with a
            separate dstack key path and hashed/banded fields only.
      - [x] Persist retained-artifact ciphertext under the sealed data volume.
            Done 2026-07-12: `SealedRetentionStore` now takes an optional `path`
            (+ dstack-derived or `.key`-sidecar key, matching `ApiKeyStore`) and
            persists its entries as an AES-256-GCM-encrypted index
            (`sealed_retention.enc`) so retained artifacts survive service
            restart; seal/destroy/sweep re-persist. Only sealed ciphertext + a
            hashed index leave to disk — the persisted file contains no deal id or
            plaintext (`tests/test_sealed_retention.py` verifies restart reload,
            destroy/sweep persistence, and that the file is encrypted).
            Wired into the deployed control plane 2026-07-12: `Settings` gain
            `retention_store_path` (empty = disabled), `retention_store_key`,
            `retention_dstack_key_path`, `retention_mode`, `retention_seconds`,
            `retention_archive_key_ref`; `build_retention_store` /
            `build_retention_policy` factories construct them, and the FastAPI
            control-plane singleton (`api._get_control_plane`) now passes both, so
            production retention is opt-in via env (default: no store → always
            destroy). Factory tests cover disabled/enabled store, policy build, and
            unknown-mode fail-closed.
            Sweep trigger added 2026-07-12: the control-plane singleton runs an
            on-boot `sweep_retention()` so any artifact whose window expired while
            the service was down is destroyed on startup, and a new operator-authed
            `POST /retention/sweep` triggers a sweep on demand, returning the
            bounded destruction records (`swept_count` + records,
            `raw_secret_egress=false`). `tests/test_api_retention_sweep.py` (3)
            cover the bounded sweep response, auth-required, and graceful
            degradation when the agent stack is absent.
      - [ ] Blocked until official/tokenized funding is available: if a future
            Tinker/Stripe payment-method token or reusable funding reference is
            captured, persist only opaque/token hashes or bounded status under
            sealed delegate storage and never expose raw card material.
- [x] `P0` Add log scrubbing for OTPs, API keys, card data, bearer tokens, and
      raw artifacts.
      - [x] Stop logging extracted OTP values in the email oracle and Tinker
            delegate, and stop binding raw OTP values into quote report data.
      - [x] Add centralized redaction helpers for bearer tokens, card payloads,
            API keys, OTP/password text, and raw artifact-shaped error text;
            wire them into API errors and high-risk automation logs.
      - [x] Hash email-oracle genesis/signup/check log identifiers instead of
            printing raw generated mailbox addresses, generated usernames,
            IMAP sender filters, or mail subject/sender headers. Covered by
            `tee-email-oracle/tests/test_log_hygiene.py`.
      - [x] Hash Tinker signup/signin mailbox and browser URL identifiers in
            stdout/CLI-visible results, and redact email addresses in shared
            Tinker delegate error rendering. Covered by
            `tests.test_signup_key_egress` and `tests.test_redaction`.
      - [x] Keep secret-bearing screenshots disabled by default and behind
            explicit debug flags.
      - [x] Add trace/HAR/video/card-screenshot deletion for configured browser
            debug artifact directories after card submission attempts.
- [x] `P0` Add a deployment runbook section for rollback:
      what is safe to redeploy, what must be frozen, what requires user notice.
      Done in `⚙️/tinker-delegate/docs/DEPLOYMENT-RUNBOOK.md`: rollback rules
      now distinguish safe test redeploys from frozen policy roots, funded
      contracts, published compose/image/app trust roots, and sealed state.
- [ ] `P1` Add health endpoints that separate:
      service up, oracle ready, browser ready, Tinker authenticated, funded,
      evaluator ready, chain signer ready, quote verifiable.
- [ ] `P1` Add structured runtime status to `/health` without leaking secrets.
- [ ] `P1` Add Prometheus/OpenTelemetry-compatible metrics:
      run count, denials, holds, funding attempts, Tinker balance band, compute
      cost, failed quote checks, cleanup failures.
- [ ] `P1` Add alerting for:
      low Tinker balance, failed funding, failed OTP, TEE quote mismatch,
      unexpected compose hash, chain watcher lag, stuck deal.
- [ ] `P1` Add a production custom domain via dstack gateway or Cloudflare,
      with verifier documentation.
- [ ] `P2` Add Proof-of-Cloud / platform provenance checks as they become
      available from providers.
      Alignment: Flashbots' recent Proof-of-Cloud work argues ordinary TEE
      attestation does not prove where the hardware is physically operated.
- [ ] `P2` Add a public verification page that walks users through:
      git SHA, image digest, compose hash, TDX quote, contract policy, and
      currently running endpoint.

## Milestone 3: Email, OTP, Browser, And Tinker Account Custody

### Email TEE

- [ ] `P0` Create a production email account whose credentials are generated or
      sealed inside the TEE and never held by a human.
      - [x] Add the encrypted operator-provisioning path for an existing mailbox
            so credentials can enter the oracle only after the client verifies
            attestation and encrypts to the oracle's context-bound key.
      - [x] Debug current captcha/local-vs-Phala state.
            Done 2026-07-08: local cock.li captcha fetch/parse/solve previously
            worked against live registration pages, but an explicit Phala
            `dnai-wikigen-oracle-genesis-debug` CVM with auto-genesis enabled
            proved a Phala/runtime-specific failure: three HTTP signup attempts
            parsed and solved captchas but cock.li rejected each solution as
            incorrect; the browser fallback then reached the CDP WebSocket but
            timed out in `BrowserType.connect_over_cdp`. The debug CVM used
            public logs/dev OS only for this test and was deleted afterward.
      - [ ] Fix Phala oracle genesis before treating generated TEE mailbox
            custody as real: make captcha solving reproducible inside the
            deployed linux/amd64 image, and repair or replace the Neko/CDP
            browser fallback timeout.
            - [x] Repair the cock.li registration form contract in the oracle
                  source: the real confirmation field is currently
                  `password_confinm`, while `password_confirm` is a tabindex
                  `-1` honeypot that must stay empty; HTTP payloads also mirror
                  `csrf_valid`.
            - [x] Build/push a new oracle image, pin the debug/Phala compose to
                  it, and re-run the explicit auto-genesis debug CVM to prove
                  whether HTTP signup now reaches IMAP verification.
                  Done 2026-07-08: image
                  `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:19c4aae35b0e9ab2758b7f680c2638f838c8c5a08da1c37f7f1b3bd192bfa1e2`
                  from commit `ca1b17c` verified GitHub provenance/SBOM,
                  Phala debug app `4c92eec94e2d7b6e8c8a7940cb0b6eb4a0e8e1bd`
                  reached IMAP verification and healthy oracle state, and the
                  temporary public-log/dev-OS debug CVM was deleted afterward.
            - [x] Stop every HTTP response from exposing the raw generated
                  oracle mailbox when credentials exist; expose readiness plus
                  commitments only, remove `/inbox`, and require an in-CVM
                  sealed/bootstrap path for the delegate's raw address input.
            - [x] Build/push the bounded-health oracle image and re-run the
                  explicit debug proof to confirm public health/attestation do
                  not expose raw mailbox identifiers after successful genesis.
                  Temporary Phala redeploys for this proof may use public logs,
                  SSH, public sysinfo, and dev OS access for observability only
                  while Tinker bootstrap, billing, API-key provisioning, OTP
                  retrieval, and card handling remain disabled; record each use
                  here and delete/revert it before production wrap-up.
                  Done 2026-07-08: image
                  `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:99ce7765558a00699e265a8ca7cdcdc8f402dd93c50cf8ddb52a1ef175dffefe`
                  from commit `64739e4` verified GitHub provenance/SBOM,
                  Phala debug app `18ab03c040c9c327b9333230b6a405bbccd90bec`
                  with compose hash
                  `fe20b736b9db9b3b4b3e8d9ddbcdfffabecc4cdf3311ead6be1fb922a8892c41`
                  reached IMAP verification. Public `/health` returned
                  `oracle_email=""`, `oracle_ready=true`,
                  `imap_connected=true`, and an email hash only; public
                  `/attestation?context=attestation` returned the same bounded
                  email fields plus a verified TDX quote; unauthenticated
                  `/email` returned `401 Bearer token required`. The temporary
                  public-log/SSH/dev-OS debug CVM was deleted afterward.
            - [x] Run bounded mailbox genesis in the main combined Phala CVM
                  without enabling Tinker bootstrap, billing, API-key
                  provisioning, or credential provisioning.
                  Done 2026-07-08: added
                  `docker-compose.mailbox-genesis.phala.yaml` as an explicit
                  one-shot profile with `ORACLE_AUTO_GENESIS=true`,
                  `TINKER_BOOTSTRAP_SIGNUP=false`, and
                  `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`. Updating CVM
                  `670b3b21-4338-4d4e-ae72-7c8922579f59` reached
                  `oracle_ready=true`, `imap_connected=true`,
                  `oracle_email=""`, and
                  `oracle_email_hash=535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`.
                  Unauthenticated `/email` still returned `401 Bearer token
                  required`. The CVM was then redeployed back to
                  `docker-compose.all.phala.yaml`; steady-state compose now has
                  `ORACLE_AUTO_GENESIS=false`, `TINKER_BOOTSTRAP_SIGNUP=false`,
                  public logs/sysinfo disabled, and the sealed mailbox remains
                  ready via hash-only public health.
            - [ ] If HTTP signup regresses, repair the Neko/CDP browser
                  fallback timeout separately.
      - [ ] Run the encrypted provisioning path against the deployed Phala CVM
            with real mailbox credentials and record only bounded hashes/status.
- [ ] `P0` Prove the email TEE can receive Tinker magic-code OTPs in the running
      CVM.
      - [ ] Provision mailbox credentials or run a separate explicit
            auto-genesis debug CVM, then re-test Tinker OTP receipt in Phala.
- [ ] `P0` Add outbound email support for:
      reviewer holds, consent confirmations, revocations, bounded-result
      delivery, and recovery notices.
- [x] `P0` Add scoped OTP request API:
      target service, expected sender, expected subject pattern, max age, nonce,
      caller identity, and reason.
- [x] `P0` Add OTP one-time-use semantics so the same code cannot be replayed.
      Released OTP-use hashes are persisted in an encrypted/sealed replay ledger;
      raw OTPs are not stored.
- [x] `P1` Add mailbox retention policy:
      delete or redact messages after OTP extraction unless retention is
      explicitly required for audit.
      Done 2026-07-12: `tinker_delegate.mailbox_retention.decide_message_disposition`
      is a pure, fail-closed policy that minimizes how long secret-bearing email
      lingers. Once a message is consumed (its structured token extracted via
      `inbound_email_safety`), it is DELETEd — or, only when audit retention is
      explicitly enabled and within its TTL, REDACT_FOR_AUDIT (raw body dropped,
      bounded metadata kept), then deleted past the audit TTL. An unconsumed
      message is RETAINed within a short window then DELETEd (stale OTP mail
      expires, never hoarded). A non-monotonic clock clamps age to 0 so it can't
      spuriously expire or keep a secret alive. Bounded output (disposition +
      reason + booleans, no content). Composes with the extractor: a test shows an
      extracted-OTP message is deleted by default. `tests/test_mailbox_retention.py`
      (9). Remaining: wire into the deployed oracle so IMAP messages are actually
      deleted/redacted per this policy (deployment-gated).
- [x] `P1` Add phishing/prompt-injection handling for inbound email:
      parse only structured OTP and confirmation tokens; never pass arbitrary
      email bodies to an agent without policy checks.
      Done 2026-07-12: `tinker_delegate.inbound_email_safety.extract_inbound_email`
      treats an inbound email as untrusted observed content and extracts ONLY
      structured tokens, fail-closed: an OTP is returned only when exactly one
      code of an expected length appears (ambiguous/none -> no OTP, never guess;
      a code inside a longer number is not matched); confirmation links are kept
      only for allowlisted hosts (no allowlist -> no link trusted); the
      subject+body are scanned for injection markers (ignore-previous, system:/
      assistant:, forward/transfer/wire, api-key/private-key/seed-phrase, ...) and
      FLAGGED, never obeyed; the raw body never leaves the function (only its
      hash). The OTP is retained for in-boundary auth but hashed (never echoed) in
      the bounded `to_public_dict`. `tests/test_inbound_email_safety.py` (10) cover
      clean extraction, OTP-hash-not-echoed, ambiguous fail-closed, duplicate-same-
      code, longer-number non-match, injection-flagged-but-otp-usable, allowlisted-
      links-only, no-allowlist-no-links, body-hashed-not-raw, and empty email.
      Remaining: wire it into the deployed oracle inbound path so bodies are never
      handed to the agent (deployment-gated).
- [x] `P1` Add a second confirmation channel for high-risk actions:
      wallet signature, WebAuthn, passkey, device-bound Teleport-style session,
      or human reviewer approval.
      Done 2026-07-12: `tinker_delegate.second_confirmation` is a pure, fail-closed
      gate. `requires_confirmation(value, threshold_wei=)` decides whether an
      action crosses the high-risk threshold (a zero threshold requires it for
      every action). `evaluate_confirmation` authorizes an action only on enough
      DISTINCT, fresh confirmations through APPROVED channels
      (`ConfirmationChannel`: wallet_signature / webauthn / passkey /
      device_bound_session / human_reviewer) from parties OTHER than the requester
      (non-self-approval; `allow_self_confirm` default False). A confirmation from
      a non-approved channel, an expired or future-dated one, a self-confirm, or a
      duplicate confirmer does not count; a requirement with no approved channels
      authorizes nothing (fail closed). Output is bounded — counts, channel names,
      reason — evidence stays as hashes. Composition test: a top-up above the
      threshold is NOT authorized until a valid out-of-band human confirmation
      arrives. `tests/test_second_confirmation.py` (13). Remaining: bind real
      channel evidence (verify a wallet signature / WebAuthn assertion) and wire
      into the deployed high-risk action paths (deployment/crypto-evidence-gated).
- [ ] `P2` Add branded `wikigen.me` result delivery once the trust path is real.

### Tinker Browser Auth

- [x] `P0` Decide the acceptable route for Tinker automation:
      official API/support path, approved service-account flow, or compliant
      browser automation for an account this project controls.
      Done in `⚙️/tinker-delegate/docs/TINKER-AUTOMATION-ROUTE.md`: prefer an
      official/support-approved Tinker route; allow browser automation only as
      bounded TEE custody for this project's own account, with no evasion.
- [ ] `P0` Reproduce the current Tinker auth blocker in a controlled probe:
      local headed Chrome, local Neko, Phala headed Neko, headless Playwright
      sidecar, same email, same IP class where possible.
      - [x] Local Neko/CDP probe against live Tinker UI succeeds: email OTP
            arrives through the oracle, onboarding completes, and API-key
            provisioning captures a one-time `tml-...` key.
      - [x] Re-test Phala/deployed browser posture with the current selector
            flow before calling production bootstrap solved.
            Done 2026-07-08: a one-shot
            `docker-compose.tinker-bootstrap.phala.yaml` Phala deploy reached
            the Tinker auth surface and failed closed with
            `bootstrap_error_kind=auth_access_blocked`; no API key was created,
            billing/add-balance and credential provisioning remained disabled,
            and the CVM was redeployed back to normal compose.
      - [x] Put the local custom Neko Chrome/CDP image on the same
            GitHub-attested GHCR build path as the delegate and oracle.
            Done 2026-07-09: `.github/workflows/build-tee-images.yml` now
            builds `neko-chrome` from `⚙️/tee-email-oracle/neko-chrome`,
            the Neko base image is pinned to the linux/amd64 manifest digest
            instead of `latest`, tests assert the workflow and digest pin, and
            a local Docker build of the pinned image succeeded. This does not
            yet prove deployed Tinker auth; it creates the browser digest and
            provenance path needed for the next Phala retry.
      - [x] Replace the one-shot Tinker bootstrap/selector diagnostic Phala
            Neko service with the GitHub-attested custom `neko-chrome` digest.
            Done 2026-07-09: GitHub Actions run `28994301855` built
            `neko-chrome@sha256:525e43d585828d1d9aa1bceaf7c8cfffc2eec47abf67e0b10550bf05338c4a07`
            from source `6ff5531aabb952b3266210afa6c0b6bfb8860103`.
            Local `verify-ghcr-image-attestation` accepted both SLSA
            provenance and SPDX SBOM attestations. The Tinker bootstrap and
            selector-diagnostics Phala composes now use that digest, port CDP
            through the baked Nginx proxy on `9222`, and no longer rewrite
            Chrome/CDP with an inline Python proxy at container startup.
      - [x] Rerun deployed Phala browser/auth probes with the custom
            `neko-chrome` compose: `/browser/readiness`,
            `/browser/selector-probe`, and authenticated `/auth/reauth`, then
            record whether `Page.enable`/auth still block.
            Done 2026-07-09: the selector-diagnostics compose using
            `neko-chrome@sha256:525e43d585828d1d9aa1bceaf7c8cfffc2eec47abf67e0b10550bf05338c4a07`
            returned successful readiness and selector probes on Phala. The
            bootstrap profile then sealed a Tinker API key with bounded
            `api_key_captured_and_stored` evidence, and the funding-validation
            profile returned authenticated `/auth/reauth` success with
            `raw_secret_egress=false`.
- [x] `P0` Replace the deployed headless Playwright sidecar in the one-shot
      Tinker bootstrap profile with a headed browser path that survives Phala
      packaging if browser automation remains the route.
      Done 2026-07-09: `docker-compose.tinker-bootstrap.phala.yaml` no longer
      includes the `delegate-browser` Playwright sidecar, points the delegate at
      the custom GitHub-attested Neko Chrome CDP endpoint on `9222`, passed local
      compose/tests, was deployed to the main Phala CVM, and sealed a Tinker API
      key with bounded success evidence. This proves the deployed browser auth
      path for the project-owned Tinker account; production deployment still
      needs non-dev OS and quote-internal verification.
- [x] `P0` Instrument pre-signup, CDP connection, navigation, and onboarding
      exceptions with bounded stage/type receipts so the next deployed bootstrap
      failure preserves useful evidence without raw URL, page text, OTP, email,
      or API-key egress.
      Done in source/tests and Phala-proven 2026-07-08: `signup()` now returns bounded
      `tinker_auth` receipts for account lookup, CDP/browser connection,
      browser context/page setup, auth, and onboarding exceptions. Receipts
      expose only outcome, furthest stage, hashes, bounded message, and
      `raw_secret_egress=false`; tests inject fake email, OTP, URL, and
      key-shaped strings into exceptions and assert they do not appear in
      result/stdout/runtime state. The 2026-07-08 Phala retry with the
      GitHub-attested `74ad4b6` images captured a bounded
      `last_bootstrap_attempt_record` with `surface=tinker_auth`,
      `outcome=unknown_failure`, `furthest_stage=not_started`, and
      `raw_secret_egress=false`; no API key was created and the CVM was
      redeployed back to normal compose.
- [x] `P0` Preserve the bounded deployed-bootstrap attempt outcome in
      `/health.runtime.bootstrap_error_kind` instead of flattening the
      serve-level catch to generic `bootstrap_error`.
      Done in source/tests and Phala-proven 2026-07-08: the instrumented Phala retry recorded
      `last_bootstrap_attempt_record.outcome=unknown_failure`, but the outer
      runtime field still reported `bootstrap_error`. The serve catch now
      preserves the bounded attempt record's `outcome` before falling back to
      `AuthAccessBlockedError` or generic `bootstrap_error`, and
      `test_bootstrap_runtime_state` covers the bubbled failure path without
      leaking raw mailbox, OTP, browser URL, page text, or API-key-shaped
      values. A follow-up one-shot Phala retry using GitHub-attested `8fb6e3a`
      images proved `/health.runtime.bootstrap_error_kind=unknown_failure`
      alongside the bounded nested receipt; the CVM was redeployed back to
      normal compose afterward.
- [ ] `P0` Capture a selector/frame/auth-flow map for:
      email input, magic-code page, OTP boxes, onboarding, keys page, billing,
      Stripe iframe, balance page, and auto-reload settings.
      - [x] Capture current local selectors for email auth, OTP boxes,
            onboarding, keys page, New key -> Generate key, balance page,
            Add payment method modal, and Stripe card iframe.
      - [x] Add selector-repair fallback families and bounded
            `selector_missing` attempt records for API-key provisioning.
      - [x] Add replayable mock-page tests for API-key creation selectors,
            including aria-label/data-testid fallback variants, successful key
            extraction, missing-create-selector, and extraction-failure paths.
      - [x] Preserve bounded deployed-bootstrap selector evidence in runtime
            health state.
            Done locally: startup bootstrap now stores the last bounded
            `api_key_provisioning` attempt record in
            `/health.runtime.last_bootstrap_attempt_record` on success or
            selector/API-key-capture failure, without raw mailbox, OTP, URL,
            page text, or API-key egress.
      - [x] Add a bounded machine-readable selector/frame/auth-flow map for the
            local contract.
            Done 2026-07-08: `tinker-delegate selector-map` emits the declared
            email auth, OTP, onboarding, API-key, billing, Stripe iframe,
            balance top-up, and auto-reload selector families with evidence
            status, selector counts, and a recomputable map hash. The output is
            guarded by the bounded CLI renderer and regression-tested to avoid
            secret-shaped material; `--summary-only` omits concrete selectors.
      - [x] Add a read-only bounded browser probe for deployed selector/frame
            evidence capture.
            Done 2026-07-08: `tinker-delegate selector-probe` connects to the
            configured browser, observes current pages/frames without
            navigation, clicks, typing, screenshots, or page-text capture, and
            emits only URL classes, URL hashes, selector match bands, frame
            kinds, selector-map hash, and `raw_secret_egress=false`. Browser
            connection failures return bounded `browser_unavailable` JSON
            instead of tracebacks.
      - [x] Add a disabled-by-default HTTP selector-probe endpoint for one-shot
            deployed evidence capture.
            Done 2026-07-08: `GET /browser/selector-probe` returns 403 unless
            `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true`; when enabled it invokes
            the same read-only bounded probe and converts browser failures to a
            bounded `browser_unavailable` response without leaking browser URLs,
            account identifiers, page text, cookies, OTPs, API keys, or card
            material. This endpoint is Phala-proven in a one-shot measurement
            profile and remains disabled in the restored steady-state compose.
      - [x] Add bounded browser-control readiness diagnostics for deployed
            selector-probe failures.
            Done 2026-07-08: `tinker-delegate browser-readiness` and
            disabled-by-default `GET /browser/readiness` report only endpoint
            classes/hashes, CDP metadata reachability, Playwright/CDP handshake
            success bands, and bounded error kinds. They do not navigate,
            click, type, screenshot, return page text, or expose raw CDP/browser
            URLs. Normal Phala compose sets
            `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=false`; the one-shot
            bootstrap measurement profile sets it true alongside
            `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true`.
      - [x] Add a bounded raw CDP WebSocket upgrade diagnostic.
            Done 2026-07-08: `browser-readiness` now includes
            `cdp_websocket_handshake`, which fetches the CDP metadata URL,
            keeps the advertised WebSocket URL in memory only, sends a raw HTTP
            Upgrade request, and emits only endpoint class/hash, TCP/TLS/upgrade
            stage booleans, HTTP status band, and bounded error kind. It does
            not navigate, send browser commands, read page data, or return raw
            URLs/headers. Unit tests cover accepted and rejected upgrades and
            rendered-output redaction. A Phala one-shot measurement with
            GitHub-attested `7973b27` images proved the raw upgrade reaches
            HTTP `101`, then Playwright `connect_over_cdp` still times out; the
            normal profile was restored and the readiness endpoint returned 403.
      - [ ] Capture deployed-CVM selector/frame evidence after Phala packaging.
            Attempted 2026-07-08 with GitHub-attested
            `a2e14b542314a16e07f20a17694e9da1a67b1f1c` oracle/delegate
            images and a one-shot Phala profile enabling only
            `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=true` and
            `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true` on top of the existing
            bounded bootstrap profile. The readiness endpoint proved that Neko
            CDP `/json/version` is reachable and advertises Chromium WebSocket
            metadata, but Playwright `connect_over_cdp` times out. The selector
            probe still returned bounded `browser_unavailable` JSON with
            `raw_secret_egress=false`, then the CVM was restored to normal
            compose where both diagnostic endpoints return 403. This proves the
            deployed endpoint gates/fail-closed paths and narrows the blocker to
            the CDP WebSocket handshake, but does not yet capture selector/frame
            match evidence.
            Re-attempted 2026-07-08 with GitHub-attested
            `7973b27d27a3d3fba3a24efcc23c89498e8a04bf` oracle/delegate
            images and the new `cdp_websocket_handshake` diagnostic. The
            readiness endpoint showed CDP metadata reachable, raw WebSocket
            TCP connect true, HTTP Upgrade sent, HTTP status band `101`, and
            Playwright `connect_over_cdp` still timing out. The selector probe
            still returned bounded `browser_unavailable`, and the CVM was
            restored to normal compose where both diagnostic endpoints return
            403.
            Re-attempted 2026-07-08 with GitHub-attested
            `59a9eac5d22f9834d74e3f263de2f46130a0a898` oracle/delegate
            images and the new `cdp_protocol_probe`. The readiness endpoint
            showed CDP metadata reachable, raw WebSocket TCP connect true,
            HTTP Upgrade status band `101`, one browser-scoped
            `Browser.getVersion` command sent, bounded CDP `result` response
            received with Chromium browser-family band, and Playwright
            `connect_over_cdp` still timing out. The selector probe still
            returned bounded `browser_unavailable`, and the CVM was restored to
            normal compose where the readiness and selector endpoints return
            403. Later subitems added and Phala-measured the raw-CDP
            target/page fallback. Source/tests now add bounded Runtime selector
            family counting; deployed DOM selector match evidence remains open
            until that fallback is built into GitHub-attested images and
            measured on Phala.
      - [x] Add a bounded post-upgrade DevTools-protocol probe.
            Done in source/tests and Phala-proven 2026-07-08:
            `browser-readiness` now includes
            `cdp_protocol_probe`. It reuses the CDP metadata URL, keeps the
            advertised WebSocket URL in memory only, performs the HTTP Upgrade,
            sends one browser-scoped `Browser.getVersion` CDP command, and
            emits only URL class/hash, TCP/TLS/upgrade stage booleans, command
            and response booleans, response kind, browser family, HTTP status
            band, and bounded error kind. It does not navigate, click, type,
            screenshot, inspect frames/pages, return page text, expose raw
            browser/CDP URLs, or return the CDP response body. Unit tests cover
            accepted result and CDP error responses and prove rendered output
            omits raw CDP URLs and returned browser strings. A Phala one-shot
            measurement with GitHub-attested `59a9eac` images proved this basic
            DevTools protocol command path succeeds after HTTP `101`, even
            though Playwright `connect_over_cdp` still times out.
      - [x] Add a bounded raw-CDP target/frame inventory fallback.
            Done in source/tests 2026-07-08: if Playwright CDP attachment
            fails, `selector-probe` falls back to a raw DevTools WebSocket path
            that performs `Target.getTargets`, attaches read-only to up to five
            page targets, runs `Page.getFrameTree`, and emits only
            `probe_backend=raw_cdp`, stage booleans, HTTP status band,
            target/page/frame count bands, URL classes/hashes, frame kinds, and
            bounded error kinds, including when the raw-CDP fallback itself
            cannot complete. The raw CDP URL and WebSocket debugger URL stay in
            memory only; tests prove the rendered output omits raw browser URLs,
            query strings, Stripe frame URLs, page text, cookies, account data,
            OTPs, API keys, and card data. A Phala one-shot measurement with
            GitHub-attested `f63dd18` images proved the raw fallback reaches
            CDP metadata, WebSocket HTTP `101`, and `Target.getTargets`,
            returning bounded target count `2+` and page count `1`. It still
            timed out before `Page.getFrameTree`, so frame inventory and DOM
            selector counting remain open.
      - [x] Preserve bounded page-target inventory when raw-CDP frame-tree
            probing times out.
            Done in source/tests and Phala-proven 2026-07-08: per-page
            attach/frame-tree errors now stay inside the page observation,
            preserving page URL classes/hashes, target/page count bands,
            `attached`, `attach_error_kind`, `frame_tree_error_kind`,
            `partial_error_kind`, and zero frame observations when frame
            traversal times out. A GitHub Actions build for `a384db2` produced
            signed GHCR provenance/SBOM attestations for
            `tinker-delegate@sha256:7ddea52df75ab0392defbb35d568649ab21bb67352e6cc55ce1aeb154470c83e`
            and
            `tee-email-oracle@sha256:15085c1dadb2f771f8fa1faeb463413adc9351a5433d939b5155c602d229c9ca`.
            A one-shot Phala diagnostic compose returned
            `probe_backend=raw_cdp`, `success=true`, target count `2+`, page
            count `1`, `pages_observed=1`, one page observation with
            `attached=true`, `frame_tree_error_kind=timeout`,
            `partial_error_kind=frame_tree_timeout`, and
            `raw_secret_egress=false`. Normal compose was restored afterward
            and both diagnostic endpoints returned 403. It still avoids DOM
            text, raw URLs, cookies, account identifiers, OTPs, API keys, and
            card material. Frame inventory and DOM selector counting remain
            open.
      - [ ] Add bounded raw-CDP Runtime selector-family counting for deployed
            selector evidence.
            Done in source/tests 2026-07-08: after `Target.attachToTarget`,
            the raw-CDP fallback sends one `Runtime.evaluate` command that
            counts only declared selector families and returns a matrix of
            `0`, `1`, `2+`, or `probe_error` bands. Python maps that matrix
            onto known flow/family names, so the public receipt cannot include
            page text, raw DOM, raw selectors, cookies, account identifiers,
            OTPs, API keys, card data, or arbitrary page-controlled strings.
            Tests prove selector-family observations survive the same
            `Page.getFrameTree` timeout seen on Phala.
            Follow-up source/tests 2026-07-08: the raw-CDP fallback now sends a
            constant, page-scoped Runtime micro-probe before the selector
            matrix and emits only `runtime_micro_probe_command_success`,
            `runtime_micro_probe_success`, and
            `runtime_micro_probe_error_kind`. This enabled the subsequent
            Phala run to distinguish "Runtime.evaluate is unavailable in the
            attached page" from "the selector-family matrix expression timed
            out" without
            exposing page text, raw DOM, selectors, URLs, cookies, OTPs, API
            keys, or card material.
            Phala attempt 2026-07-08: GitHub Actions built and signed
            source commit `50de0a945e60b0602b5d944c0fa09951da2c3410`
            into
            `tinker-delegate@sha256:10e32c7ac9544b3cdb1bf098038d66b388e07e917b1a4783211246831dc9cc3a`
            and
            `tee-email-oracle@sha256:88fc9e44b12e218a0d8202c7f10f5c6b96cdbdb81c41dcfe69652994e076e0cf`;
            local `verify-ghcr-image-attestation` passed for both
            provenance and SBOM attestations. A one-shot Phala diagnostic
            compose reached live hash
            `cc1d24f096ea62541a52eabafe5c7d0cb43fe05e0d1d8cef70f166cd1cf7d74a`;
            `/browser/selector-probe` returned `success=true`,
            `probe_backend=raw_cdp`, bounded page URL class/hash,
            `attached=true`, `runtime_selector_error_kind=timeout`, empty
            `flow_observations`, and `raw_secret_egress=false`. Normal
            compose was restored afterward at live hash
            `26b3b3a4feba6a2935900fafa733a7e39846f50845317561e1bbccf4ed3e743a`;
            health is OK and `/browser/readiness`, `/browser/selector-probe`,
            and `/billing/add-balance` all return 403. Next step: debug why
            deployed page-scoped `Runtime.evaluate` times out after successful
            target attach by building GitHub-attested images with the Runtime
            micro-probe, measuring one-shot Phala selector-probe output, and
            restoring normal compose.
            Follow-up Phala attempt 2026-07-08: GitHub Actions built and
            signed source commit
            `5943c61a496e81fbd19093f3fced61b14bcd5bb0` into
            `tinker-delegate@sha256:509346d9f232cf49962b0e980a59fc6d3911cce5ede1fa74a71726a48a15577f`
            and
            `tee-email-oracle@sha256:d5512a498f91e7b7470b70dcc93bd5262f483e0d74eacbaeb5626a9eb21086bc`;
            local attestation checks passed for both images. A one-shot Phala
            diagnostic compose reached live hash
            `40728e585a0441843c308ccfc480ea509e2f197ffe6a170f6ad8e64ba6aa1645`;
            `/browser/selector-probe` returned `success=true`,
            `probe_backend=raw_cdp`,
            `partial_error_kind=runtime_micro_probe_timeout`,
            `runtime_micro_probe_command_success=false`,
            `runtime_selector_command_success=false`, bounded page
            `url_class=other`, `attached=true`,
            `runtime_micro_probe_error_kind=timeout`, empty
            `flow_observations`, and `raw_secret_egress=false`. This narrows
            the blocker to page-scoped Runtime command delivery/evaluation in
            the deployed Neko/CDP path, not selector-expression complexity.
            Normal compose was restored afterward at live hash
            `6ead86a6f857f12210b9dd7656fbd54a2547795538a60f28bb9404165e3166fd`;
            health is OK and `/browser/readiness`, `/browser/selector-probe`,
            and `/billing/add-balance` all return 403. Next step: add a
            bounded raw-CDP Runtime/session diagnostic, for example
            `Runtime.enable` plus execution-context event bands, before
            retrying selector-family counts.
            Follow-up source/tests 2026-07-08: the raw-CDP fallback now sends
            `Runtime.enable` before the constant Runtime micro-probe and emits
            only bounded session/runtime fields:
            `runtime_enable_command_success`,
            `runtime_execution_context_event_observed`,
            `runtime_enable_success`, `runtime_enable_error_kind`,
            `runtime_event_before_enable_response`,
            `runtime_event_count_band`, and
            `runtime_execution_context_created`. Tests cover successful
            execution-context observation and a `Runtime.enable` timeout before
            any micro-probe or selector evaluation. No event payloads, context
            IDs, frame IDs, raw URLs, page text, selectors, cookies, OTPs, API
            keys, or card material are emitted. Next step: build
            GitHub-attested images for this source slice, run one-shot Phala
            selector-probe, record whether `Runtime.enable` or the subsequent
            micro-probe times out, then restore normal compose.
            Follow-up Phala attempt 2026-07-08: GitHub Actions built and
            signed source commit
            `9d6936434aab24eb3513abe7b5e862c1802da022` into
            `tinker-delegate@sha256:c6e559feb04f27fd3afafac1e6b26f7f0b23109ebb1d160d54d4588511785d04`
            and
            `tee-email-oracle@sha256:f88457fbde049ed42e75a5f06d06008376f1d313ca3b91db7038df50853d2df6`;
            local attestation checks passed for both images. A one-shot Phala
            diagnostic compose reached app compose hash
            `081ef36b1a2a4d6e84623a524f5a2e0f033516fb6eabdf72a18758e71b4f9fb4`;
            `/browser/selector-probe` returned `success=true`,
            `probe_backend=raw_cdp`,
            `partial_error_kind=runtime_enable_timeout`,
            `runtime_enable_command_success=false`,
            `runtime_execution_context_event_observed=false`,
            `runtime_micro_probe_command_success=false`,
            `runtime_selector_command_success=false`, bounded page
            `url_class=other`, `attached=true`,
            `runtime_enable_error_kind=timeout`,
            `runtime_event_count_band=0`,
            `runtime_execution_context_created=false`, empty
            `flow_observations`, and `raw_secret_egress=false`. This narrows
            the blocker below page-scoped evaluation itself: the deployed
            attached page session does not complete `Runtime.enable`. Normal
            compose was restored afterward at live attested compose hash
            `54ee243db5605588550d670fcc767ba17b49407e76613b633ddc7eee44494eb2`;
            health is OK and `/browser/readiness`, `/browser/selector-probe`,
            and `/billing/add-balance` all return 403. Next step: repair or
            route around the Neko/CDP attached-session Runtime domain timeout
            before retrying selector-family counts.
            Follow-up source/tests 2026-07-08: when the attached-session
            `Runtime.enable` path fails, the raw-CDP fallback now fetches the
            bounded page-target inventory from `/json/list`, connects directly
            to the matching page target WebSocket, and retries
            `Runtime.enable`, the constant micro-probe, and the selector-family
            matrix on that direct page connection. The direct route emits only
            bounded fields under `direct_page_runtime`: page-list success,
            page-WebSocket availability, Runtime enable/error/event-count
            bands, micro-probe success/error, selector success/error, and
            declared selector-family count bands. Tests prove the direct route
            can recover selector-family observations after an attached-session
            `Runtime.enable` timeout without emitting raw page URLs, WebSocket
            URLs, event payloads, context IDs, frame IDs, page text, selectors,
            cookies, OTPs, API keys, or card material. Next step: build
            GitHub-attested images, run one-shot Phala selector-probe, record
            whether direct page Runtime succeeds, then restore normal compose.
            Follow-up Phala attempt 2026-07-08: GitHub Actions built and
            signed source commit
            `bf39f569840f348c639be9fe0a8928f3360d9835` into
            `tinker-delegate@sha256:c43ac01ee461aca4b49bbfe77d55491cfac8bb3dc70907c84a7b40b34657c277`
            and
            `tee-email-oracle@sha256:43bf7d096bdd0e56b8fa95c23325513ba09825114de16e23fb578169cb8a3e42`;
            local attestation checks passed for both provenance and SBOM
            attestations. A one-shot Phala diagnostic compose reached live app
            compose hash
            `5b274e53751af9e6cd1bf03005062f4ffb0e6615b09d781d50934abeec7607e7`;
            `/browser/selector-probe` returned `success=true`,
            `probe_backend=raw_cdp`,
            `partial_error_kind=runtime_enable_timeout`,
            `direct_page_runtime_attempted=true`,
            `direct_page_runtime.page_list_success=true`,
            `direct_page_runtime.page_websocket_available=true`, but
            `direct_page_runtime_enable_success=false`,
            `direct_page_runtime.runtime_enable_error_kind=timeout`,
            `direct_page_runtime_micro_probe_success=false`,
            `direct_page_runtime_selector_success=false`, empty
            `flow_observations`, and `raw_secret_egress=false`. This proves
            the direct page-target WebSocket is reachable in Phala, but the
            deployed page Runtime domain still does not complete
            `Runtime.enable`. Normal compose was restored afterward at live
            attested compose hash
            `382aa6c881d477724552f4445157afbcd75738ee1feb9603b982b75ec4e82c2c`;
            health is OK, `/browser/readiness` and
            `/browser/selector-probe` return 403, and `/billing/add-balance`
            returns 403 when called with the current `amount_dollars` schema.
            Follow-up source/tests 2026-07-08: the raw-CDP probe now sends a
            bounded `Page.enable` command before `Runtime.enable` on both the
            attached page session and the direct page-target WebSocket. It
            emits only `page_enable_command_success` at the top level and
            `page_enable_success` / `page_enable_error_kind` on each page and
            nested `direct_page_runtime` receipt. This should distinguish
            "page-session commands work but Runtime-domain enable hangs" from
            "all page-target commands hang" in the next Phala measurement,
            without exposing page text, raw URLs, selectors, cookies, OTPs, API
            keys, or card material. Follow-up Phala attempt 2026-07-08:
            GitHub Actions built and signed source commit
            `556387a9e673e91d3ea4991cdaee96ead3e52922` into
            `tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38`
            and
            `tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3`;
            local attestation checks passed for both provenance and SBOM
            attestations. A one-shot Phala diagnostic compose reached live app
            compose hash
            `1926b9f99a249dd27f4772a7ffd90deba7b83c402e30aa49e408b8cdcb5db06a`;
            `/browser/selector-probe` returned `success=true`,
            `probe_backend=raw_cdp`,
            `partial_error_kind=page_enable_timeout`,
            `page_enable_command_success=false`,
            `direct_page_runtime.page_list_success=true`,
            `direct_page_runtime.page_websocket_available=true`,
            `direct_page_runtime.page_enable_success=false`,
            `direct_page_runtime.page_enable_error_kind=timeout`, no Runtime
            micro-probe, no selector-family matrix, empty `flow_observations`,
            and `raw_secret_egress=false`. Normal compose was restored
            afterward at live attested compose hash
            `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`;
            health is OK and `/browser/readiness`, `/browser/selector-probe`,
            and `/billing/add-balance` return 403. The remaining blocker is
            lower-level page CDP command delivery through the Phala Neko path;
            next implementation step is to route Tinker automation through the
            Playwright sidecar or repair the Neko CDP transport before trying
            account funding.
            Follow-up Phala attempt 2026-07-09: added
            `⚙️/tinker-delegate/docker-compose.selector-diagnostics.phala.yaml`
            as a tracked one-shot diagnostics profile with registry images
            only, Tinker bootstrap disabled, funding/card mutations disabled,
            and only `/browser/readiness` plus `/browser/selector-probe`
            enabled. The profile used source
            `eb3bde3b5b156dfdd46f701ab2df8f1f19d94120` images already built
            by GitHub Actions:
            `tee-email-oracle@sha256:f6103cd24ba2f63c859b55f5c1caab43fec92db9ac49009c7fdf0a07ffd9a7e3`
            and
            `tinker-delegate@sha256:17f22d8e87f774717a1989f1501ea659ad13bf409e7d601af6cf7b1c1fdc7381`.
            Local raw-compose verification produced image-policy hash
            `455930b6b5e6e0d8119c737becfaa63d09ea939389574e5e845883b37dce5418`
            with rendered compose SHA-256
            `15f67dea7c3ae6bdbac03eda850467c255ea7068e2d8e5cb92117c181f94d67e`;
            the live one-shot attested compose hash was
            `170862495089566bbe75a0c95f8cc8c1267cb6d17e678144119be82a2f1b81d2`.
            `/browser/readiness` proved CDP metadata, WebSocket upgrade, and
            browser-scoped protocol command success, while
            `/browser/selector-probe` again returned `success=true`,
            `probe_backend=raw_cdp`, `fallback_from_backend=playwright`,
            `target_count_band=2+`, `page_count_band=2+`,
            `pages_observed=1`, `attached=true`,
            `partial_error_kind=page_enable_timeout`,
            `runtime_enable_command_success=false`,
            `direct_page_runtime_attempted=true`,
            `direct_page_runtime.page_list_success=true`,
            `direct_page_runtime.page_websocket_available=true`,
            `direct_page_runtime.page_enable_success=false`, no Runtime
            micro-probe, no selector-family matrix, empty
            `flow_observations`, and `raw_secret_egress=false`. The CVM was
            restored to the funding-validation profile afterward and live
            attestation returned
            `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`;
            `/browser/readiness` and `/browser/selector-probe` now both return
            403 disabled. This revalidates that the blocker is deployed
            Neko/page-target CDP command delivery before selectors, not the
            selector-map, email oracle, or billing selectors.
      - [x] Add a tracked one-shot Phala selector-diagnostics compose, run it
            against the main CVM, and verify the funding-validation profile was
            restored afterward.
            Done 2026-07-09 in
            `⚙️/tinker-delegate/docker-compose.selector-diagnostics.phala.yaml`.
            The temporary profile uses registry images only, disables Tinker
            bootstrap and all card/funding mutations, enables only bounded
            readiness/selector diagnostics, produced attested compose hash
            `170862495089566bbe75a0c95f8cc8c1267cb6d17e678144119be82a2f1b81d2`,
            and was restored to funding-validation hash
            `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`
            with both diagnostic endpoints returning 403 disabled.
- [x] `P0` Narrow Phala redeploy runtime env handling to the minimal key set
      needed by each compose profile.
      Historical completion 2026-07-08: the retired helper defaulted to
      `--runtime-env-policy compose-refs`, selecting only keys referenced by the
      compose source plus explicitly allowed keys. The legacy broad behavior
      requires `--runtime-env-policy all`. Default output is bounded to
      `runtime_env_policy`, `runtime_env_key_count`, and
      `runtime_env_keys_sha256`; printing key names requires
      `--print-runtime-env-keys`. Node tests cover compose-reference filtering,
      explicit missing-key fail-closed behavior, allow-file additions, and the
      explicit all-env fallback. The current helper rejects these flags and is
      validation-only for an exact reviewed seven-CVM batch. At that historical checkpoint, the Phala normal
      profile was redeployed
      with this policy: live compose hash
      `54ee243db5605588550d670fcc767ba17b49407e76613b633ddc7eee44494eb2`,
      `allowed_env_count=7`, public logs/sysinfo disabled, health OK, and both
      browser diagnostic endpoints still 403. Deployment-bundle verification
      passed against the narrowed allowed-env policy with `raw_secret_egress=false`.
- [x] `P0` Handle Tinker bot/fingerprint checks without evading legal or service
      boundaries.
      Done when the team can explain the account relationship and automation to
      Tinker/Stripe if asked.
      Current policy: fail closed on blocks, do not use stealth plugins,
      automation-control masking, rotating proxies, user-agent spoofing, or
      CAPTCHA-solving services for Tinker/Stripe account and billing flows.
      `test_automation_route_policy.py` rejects common evasion dependencies and
      flags in the runtime package, dependency manifest, and compose files.
- [ ] `P0` Complete Tinker signup inside the CVM:
      email OTP, onboarding, API key creation, encrypted key sealing.
      - [x] Complete local Neko signup/sign-in path through OTP, onboarding, and
            API-key creation.
      - [x] Store local captured API keys in the encrypted key store without
            returning or logging the raw key.
      - [x] Remove raw mailbox and browser URL egress from signup/signin logs
            and return payloads before enabling deployed-CVM bootstrap.
      - [x] Add a bounded one-shot Phala bootstrap profile for the deployed-CVM
            attempt.
            Done locally: `docker-compose.tinker-bootstrap.phala.yaml` enables
            only `TINKER_BOOTSTRAP_SIGNUP=true`, reuses the main
            `delegate-data` volume for sealed API-key persistence, and keeps
            oracle genesis, credential provisioning, and add-balance disabled.
      - [ ] Resolve deployed Tinker auth access block without evasion.
            Evidence 2026-07-08: the first Phala one-shot bootstrap failed
            closed at Tinker auth with `auth_access_blocked`. A second
            Phala one-shot bootstrap using headed Neko CDP instead of the
            Playwright sidecar verified the packaging and endpoint gates, but
            failed closed with generic `bootstrap_error` before a bounded stage
            receipt or API-key capture. A third retry using GitHub-attested
            `74ad4b6` images captured a bounded `tinker_auth`
            `unknown_failure` receipt at `not_started`, with no raw secret
            egress and no API-key capture. The outer runtime
            `bootstrap_error_kind` preservation fix is now implemented and
            Phala-proven with GitHub-attested `8fb6e3a` images:
            `/health.runtime.bootstrap_error_kind=unknown_failure`.
            Local Neko still works, so next work should either repair the
            supportable headed-browser posture or obtain an official/support-
            approved Tinker service-account/API-key route.
      - [ ] Complete the same flow inside the deployed CVM and seal the API key
            with the dstack-derived key path.
- [x] `P0` Add a Tinker re-auth path for future OTP challenges.
      Done locally via bounded `reauth` CLI/helper and opt-in
      `POST /auth/reauth`; outputs are `tinker_auth` receipts only and do not
      expose account email, OTP, URL, API key, or raw page text. Deployed-CVM
      validation remains covered by the open Phala selector/posture tasks above.
- [ ] `P1` Add browser session recovery:
      stale OTP page detection, cookie/session expiration, login loop detection,
      screenshot artifacts with secrets redacted.
      - [x] Source/test 2026-07-08: persist Playwright `storage_state` from
            successful signup/signin/reauth into an encrypted browser-session
            store under the delegate data volume, using a separate
            `tinker/browser_session` dstack key path, and load that state when
            billing creates a fresh browser context. Tests prove the encrypted
            file does not contain raw cookie/localStorage values and compose
            files keep the store under `/data`.
      - [x] Rebuild/pin/deploy the browser-session store slice to Phala and
            rerun `/auth/reauth`, encrypted test-card, and `$5` add-balance
            probes against the new attested compose hash. Done 2026-07-08:
            source `f553a13da7276d56b5284bb55706887c5766455d` images were
            built by GitHub Actions run `28979167606`, provenance/SBOM checks
            passed, compose was digest-pinned and redeployed to live attested
            hash `f7c78fc75f5f26dd3e0ff7a588e3627c0b275565b1dda0da572ff89a49f8fcf8`,
            deployment-bundle verification passed, and live probes still fail
            closed with `auth_access_blocked` on reauth plus `auth_required` on
            test-card/add-balance because no successful auth session has been
            saved yet.
      - [x] Add bounded stale-session and login-loop classifications before
            deciding whether to refresh OTP or fail closed. Done 2026-07-12:
            `tinker_delegate.session_state` classifies the auth page text plus a
            recent-failed-attempt count into a bounded state — `SESSION_ACTIVE`
            (proceed), `STALE_SESSION` (a single OTP refresh is the safe
            recovery), `LOGIN_LOOP` (rate-limit/lockout text OR
            `recent_failed_attempts >= max_attempts` — fail closed, never hammer
            the OTP/email-oracle), `UNKNOWN` (fail closed). `decide_otp_action`
            maps state -> PROCEED/REFRESH_OTP/FAIL_CLOSED; the attempt count is
            authoritative over the page text so a loop can't be masked by a
            normal-looking stale-session page. `session_state_receipt` emits a
            bounded `should_refresh_otp` + page-text hash (no raw text, codes, or
            credentials). `tests/test_session_state.py` (12) prove the ladder,
            count-forces-loop, fail-closed-on-unknown, and bounded egress.
- [ ] `P1` Add a `cdp-playground` recipe specifically for Tinker auth and
      billing probes.
- [ ] `P1` Add replayable browser tests against mock pages for auth, onboarding,
      key creation, and billing.
      - [x] API-key creation mock-page tests cover selector fallback variants,
            one-time `tml-...` extraction, and bounded missing-selector /
            extraction-failure behavior without a live Tinker account.
      - [x] Auth and OTP mock-page tests.
      - [x] Onboarding mock-page tests.
      - [x] Billing and Stripe-frame mock-page tests.

### Tinker Funding

- [x] `P0` Decide the production funding model:
      production defaults to manual/developer prefund until an official or
      tokenized Tinker/Stripe route exists. Raw-card browser automation is
      limited to opt-in `operator_capped_validation` for one-off approved
      operator-owned validation attempts; `GET /billing/funding-policy` and the
      `funding-policy` CLI expose the bounded mode, and denied card/add-balance
      requests persist bounded `policy_denied` receipts without browser launch.
- [x] `P0` Finish the encrypted card channel:
      verify TEE quote, encrypt card payload to TEE public key, decrypt in memory,
      fill billing form, zero memory, and return only bounded status.
      Done for the one-off operator-owned validation lane on 2026-07-09: the
      live Phala funding-validation CVM accepted encrypted card material behind
      attestation/runtime-auth gates, returned only bounded payment-method and
      add-balance receipts, and the independent balance read now reports
      `$10.00`. Production or repeated card funding remains blocked on
      compliance approval and a non-debug CVM posture.
      - [x] Local plaintext development path fills the Stripe Elements card
            iframe, zeroes card payload objects, and returns bounded failure
            status without logging card details.
      - [x] Disable plaintext `POST /billing/card` by default, disallow it in
            dstack mode, and wipe plaintext card request objects on success and
            failure.
      - [x] Exercise encrypted `/billing/card/encrypted` locally after
            context-bound billing attestation verification; Stripe test-card
            submission returns bounded `card_declined` and the encrypted receipt
            store records the attempt.
      - [x] Gate encrypted card and add-balance automation behind
            `TINKER_FUNDING_MODE=operator_capped_validation`; the default
            `manual_prefund` mode denies those browser paths before card
            decryption or browser launch and records bounded policy receipts.
      - [x] Add bounded operator funding preflight via
            `GET /billing/funding-preflight` and the `funding-preflight` CLI:
            checks funding mode, amount cap, optional add-balance endpoint flag,
            encrypted receipt-store availability, and billing attestation policy
            before any card payload or browser launch.
      - [x] Add a bounded funding validation manifest via the
            `funding-manifest` CLI: hashes saved preflight and receipt JSON,
            binds expected compose/app/OS-image policy by hash, and rejects raw
            card/API-key/secret-shaped inputs.
      - [x] Add durable bounded artifact output for operator validation:
            `funding-preflight --output` writes preflight JSON, and billing
            receipt-producing commands can write attempt records via
            `--receipt-output` for manifest binding.
      - [x] Add one-command bounded validation packet generation:
            `funding-validation-packet` writes preflight, receipt, manifest,
            verification, and summary JSON, with explicit `--run-card-attempt`
            required before card fields are accepted.
      - [x] Extend validation packets with optional add-balance evidence:
            bind an existing bounded add-balance receipt or explicitly run
            `POST /billing/add-balance` with `--run-add-balance-attempt`, and
            write separate top-up manifest/verification JSON.
      - [x] Add a bounded packet-directory checker:
            `check-funding-validation-packet` verifies required files,
            replays payment/top-up manifests, catches tampering, and can require
            add-balance evidence or deployed TDX attestation evidence.
      - [x] Add payment-method and add-balance selector-repair fallback
            families for the Tinker billing UI, with mock-page tests covering
            data-testid/aria-style drift and bounded `selector_missing`
            receipts when top-up controls cannot be found.
      - [x] Add bounded card-on-file status and admin/operator removal controls:
            `GET /billing/payment-method-status` returns only `card_on_file`
            plus a zero/one-or-more/unknown count band, and
            `POST /billing/card/remove` drives the Tinker removal UI with a
            bounded receipt. Neither path returns card brand, last4, expiry,
            billing address, or browser page text.
      - [x] Add `add-card-encrypted-prompt` so approved operator card details
            are entered interactively instead of as command-line flags; the
            prompt path requires deployed compose/app/OS-image attestation
            expectations unless explicitly run in local-dev mode.
      - [x] Extend `funding-validation-packet` with `--prompt-card` so an
            approved real-card validation can create the full bounded packet
            without placing card fields in command-line arguments; prompt mode
            rejects missing deployed attestation expectations before asking for
            card material.
      - [x] Add runtime bearer auth for operator-only Tinker mutation endpoints:
            `/auth/reauth`, `/billing/card/encrypted`,
            `/billing/add-balance`, `/billing/funding-receipts`, and the local
            plaintext card endpoint when explicitly enabled now require a bearer
            token when `TINKER_RUNTIME_AUTH_REQUIRED=true`. The
            `funding-validation-packet`, `add-card-encrypted`, and
            `add-card-encrypted-prompt` CLIs read the token from
            `TINKER_RUNTIME_AUTH_TOKEN` by default and never require it on the
            command line.
      - [x] Add a temporary Phala funding-validation compose profile that keeps
            signup/bootstrap and plaintext card input disabled, enables only
            capped operator reauth/encrypted-card/add-balance endpoints, uses
            the custom GitHub-attested `neko-chrome` CDP path, caps top-up
            attempts at `$10`, and quote-binds the profile through digest-pinned
            registry images plus explicit runtime env policy.
      - [x] Run a fresh local FastAPI encrypted-card smoke with local billing
            attestation and a Stripe test card: `$5` operator preflight returns
            ready, `$10` with add-balance endpoint required returns not ready,
            encrypted `/billing/card/encrypted` reaches bounded
            `payment_submitted` receipt output, and the temp encrypted receipt
            file does not contain the test card number, CVC, name, postal code,
            or raw card field names.
      - [x] Exercise the encrypted `/billing/card/encrypted` path against the
            deployed attested funding-validation endpoint after quote
            verification and GitHub-attested images for the runtime-auth source
            commit are pinned. Done 2026-07-08: source
            `355b8aa7959118f887c2e4a498edee200114c152` images were built by
            GitHub Actions run `28977917896`, local provenance/SBOM checks
            passed, Phala funding-validation compose is live at attested hash
            `34a79c5ad6d16e2f5c0b35ebcbf0f6df4cdcc8b3cff1ded98d4944efd6deff09`,
            billing-context attestation verified, unauthenticated funding
            mutations return `401 Bearer token required`, and an authenticated
            encrypted Stripe test-card submission destroyed the card payload and
            returned a bounded `payment_method` / `auth_required` receipt at
            `billing_page_loaded` with `raw_secret_egress=false`.
      - [ ] Repair deployed Tinker auth/billing automation before any approved
            real-card prompt. Auth/session repair is complete, but this broader
            billing item remains open until the live Phala funding profile
            reaches the payment/add-balance surfaces after reauth and produces a
            bounded test-card or approved-card funding receipt.
            - [x] Source/test 2026-07-08: add a bounded billing auth-state
                  classifier before payment-method/add-balance selector
                  searches. Billing pages that are actually auth-required or
                  access-blocked now return `auth_required` or
                  `auth_access_blocked` receipts at `billing_page_loaded`
                  without clicking billing controls or echoing page text.
            - [x] Rebuild/pin/deploy this classifier to Phala and rerun the
                  live encrypted Stripe test-card and `$5` add-balance probes
                  to distinguish auth-state failure from true billing selector
                  drift. Done 2026-07-08: source
                  `355b8aa7959118f887c2e4a498edee200114c152` images were built
                  by GitHub Actions run `28977917896`, provenance/SBOM checks
                  passed, compose was digest-pinned and redeployed to live
                  attested hash
                  `34a79c5ad6d16e2f5c0b35ebcbf0f6df4cdcc8b3cff1ded98d4944efd6deff09`,
                  and authenticated payment-method plus `$5` add-balance
                  probes now return bounded `auth_required` rather than
                  `selector_missing`.
            - [x] Repair the deployed Tinker auth/session route so
                  `/auth/reauth` reaches OTP and billing navigation reuses an
                  authenticated session before any approved real-card prompt.
                  Done 2026-07-09: after replacing the deployed browser path
                  with the custom GitHub-attested Neko Chrome/CDP image,
                  bootstrap sealed the Tinker API key and authenticated
                  `/auth/reauth` on the funding-validation profile returned
                  success with `raw_secret_egress=false`.
                  - [x] Source/test 2026-07-08: preserve bounded
                        auth-flow furthest-stage evidence for
                        `auth_access_blocked` failures. `/auth/reauth` and
                        signup now return `auth_page_loaded`,
                        `auth_email_submitted`, or `auth_otp_page_reached`
                        instead of flattening deployed auth blocks to
                        `not_started`, without exposing raw page text, URLs,
                        OTPs, or account identifiers.
                  - [x] Rebuild/pin/deploy the auth-stage receipt image to
                        Phala and rerun `/auth/reauth` so the next live blocker
                        is tied to a precise bounded stage. Done 2026-07-08:
                        GitHub-attested source
                        `266264870becc5f697d6375b96341d252317ba94` images
                        were pinned and deployed to live attested compose hash
                        `a43a894e6c0a6e0976f94e86f11050301b46093dad03e065ee91fda98fcf456d`.
                        Authenticated `/auth/reauth` now fails closed with
                        `auth_access_blocked` at `auth_email_submitted`
                        (`raw_secret_egress=false`), proving the deployed
                        browser reaches email submission before Tinker blocks
                        the flow.
                  - [x] Refresh the funding-validation Phala profile with the
                        current GitHub-attested funding-command-plan image and
                        rerun `/auth/reauth`. Done 2026-07-09: source
                        `eb3bde3b5b156dfdd46f701ab2df8f1f19d94120` images were
                        pinned and deployed to live attested compose hash
                        `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`;
                        `verify-deployment-bundle` passed, and authenticated
                        `/auth/reauth` still fails closed with bounded
                        `auth_access_blocked` at `auth_email_submitted`
                        (`raw_secret_egress=false`).
                  - [x] Refresh the funding-validation Phala profile with the
                        custom `neko-chrome` image and rerun `/auth/reauth`.
                        Done 2026-07-09: source
                        `6ff5531aabb952b3266210afa6c0b6bfb8860103` oracle,
                        delegate, and `neko-chrome` images were pinned and
                        deployed to live attested compose hash
                        `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`;
                        authenticated `/auth/reauth` succeeded and the API key
                        is available from the encrypted store.
- [ ] `P0` Prove the Stripe/Tinker billing path end-to-end with a low-value test
      account and a safe test card or approved real card.
      - [x] Stripe test card reaches live Tinker/Stripe submission and returns
            `Your card was declined.`
      - [x] Add-balance fails closed with `Payment method required before adding
            balance` when no real payment method is on file.
      - [x] Enforce `TINKER_MAX_ADD_BALANCE_USD` before launching browser
            automation so real-card top-ups cannot exceed the approved cap by
            caller input alone.
      - [x] Disable the HTTP add-balance mutation endpoint by default behind
            `TINKER_ALLOW_ADD_BALANCE_ENDPOINT`; the capped CLI/internal path
            also requires `TINKER_FUNDING_MODE=operator_capped_validation` for
            deliberate operator validation attempts.
      - [x] Locally verify `POST /billing/add-balance` rejects with 403 while
            `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`, even when
            `operator_capped_validation` mode is enabled.
      - [x] Add a prompt-time encumbrance gate for approved real-card operator
            validation. `add-card-encrypted-prompt` and
            `funding-validation-packet --prompt-card --run-card-attempt` now
            accept `--require-encumbrance` plus contract/RPC/compose inputs and
            run read-only `TinkerAccountEncumbrance` policy checks before
            prompting for card fields. If the contract is missing, the compose
            hash is not approved, emergency halt is on, or the requested
            add-balance amount exceeds the cap, the CLI exits before card
            material is entered.
            Refreshed 2026-07-09: `tinker-encumbrance-preflight` now explicitly
            masks public chain fields (`contract_address`, `compose_hash`,
            `amount_wei`, `max_amount_wei`) before generic secret-shape checks,
            so approved public policy reads can be emitted as bounded JSON
            without weakening card/API-key/OTP leak detection.
      - [x] Add a manifest-driven bounded funding command plan.
            `tinker-delegate funding-command-plan` reads
            `deployments/base-sepolia.json`, extracts the live delegate URL,
            compose hash, app ID, OS image hash, and
            `TinkerAccountEncumbrance` policy, then emits preflight,
            encumbrance-preflight, encumbrance deploy dry-run/broadcast, and
            prompt-packet argv/shell templates
            without card details, bearer tokens, API keys, OTPs, or RPC values.
            The earlier manifest correctly returned `ready=true` for `$5` with
            the deployed encumbrance contract, approved compose hash, and no raw
            secret egress. The current Tinker-minimum `$10` path is blocked
            until the deployed encumbrance caps are raised.
            Refreshed 2026-07-09: the plan now includes absolute
            no-raw-key deploy helper commands for
            `deploy-tinker-encumbrance-base-sepolia.sh`, with a note that the
            broadcast must run from an interactive terminal using Foundry
            `--account` and the encrypted keystore. A fresh helper dry-run
            passed chain checks, build, and 9 encumbrance contract tests,
            predicting deployment address
            `0x9F2616f3F7B0dc363bBa19F7d72b9061f791a06e` against compose hash
            `0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`;
            the operator then broadcast the same helper successfully. The
            manifest records deployed address
            `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`, tx
            `0x7679df09aa2e939d748be0e017f380f5e7e44331a482531380198e93bdcaed01`,
            approved compose hash
            `0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`,
            owner `0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, and `$5`
            add-balance/spend caps.
            Refreshed after the custom Neko deployment: the live
            funding-validation compose hash
            `0xf4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`
            was approved on Base Sepolia in tx
            `0x0e80acc1474fa1aef698f86d7f4fc3cdc700912cdb30aec9ef70d222ff83111f`
            at block `43902526`.
      - [ ] Run a capped real-card add-payment-method and low-value add-balance
            attempt after the funding-validation compose is deployed on Phala,
            its live attested compose hash is recorded, and the operator CLI
            command targets that hash with `--fetch-attestation` and
            `--require-encumbrance`.
            Evidence 2026-07-09: the refreshed Phala funding-validation profile
            is live at attested compose hash
            `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`,
            remote `$5` funding preflight was ready under the old deployed cap,
            `funding-command-plan` returned `ready=true` for that historical
            `$5` validation path, authenticated `/auth/reauth` succeeds, and
            the compose hash is approved by `TinkerAccountEncumbrance`. The
            first approved real-card validation packet reached
            `payment_submitted` and saw bounded card-management copy
            (`This card can be removed at any time.`), but live balance remains
            `$0.00` and add-balance stopped at `add_balance_modal_opened` with
            `selector_missing` / `Add-balance amount input not found`.
            - [x] Source/test fix: treat Tinker card-management copy as
                  payment-method success instead of a card error, add scoped
                  add-balance amount-input fallbacks plus exact preset-amount
                  selectors, and cover both with focused mock-page tests.
            - [x] Source/test fix: enforce Tinker's `$10` whole-dollar minimum,
                  expose bounded card-on-file status, and add an authenticated
                  admin/operator card removal path.
            - [x] Update deployed `TinkerAccountEncumbrance` funding policy from
                  `$5` to `$10` add-balance/spend caps before rerunning live
                  preflight or any add-balance attempt. Done in tx
                  `0x3ab263bb7cb7758787fa1136dd043cca002db9cf511b29ad20ef4d1216199d3f`
                  at block `43904511`; read-back returned `10e18` for both caps.
            - [x] Approve the refreshed funding-validation compose hash and run
                  a bounded `$10` add-card plus add-balance packet.
                  Build/attest/pin/redeploy is done for source
                  `8a571347d946fd6c23a84db256fd99f7169061e5`; GitHub Actions
                  run `28998076083` produced digest-pinned oracle
                  `beedfc6c3f1f0c9dca8604d6adf6522110e8dc2f15af1e8a9145e0e3227939a9`,
                  delegate
                  `3e03e4dccde8ef732641fdd091597a683674ca3b065b950a983aab16c6b88878`,
                  and Neko
                  `fd6a65a894befc66901ed7b915c792f3a669b74ef4ace01813815e1f1030b456`
                  images. The existing Phala CVM now attests compose hash
                  `9f0754be7b7bcd3db9c808e5630f7f0aca39a33bbe37f898b8714de6d9aa4d71`;
                  `verify-cvm-attestation` passed with local image-policy hash
                  `880db4987c00ecd8643aedc794415accd83c47a337b4512810d9fe5cadab8e6a`.
                  `/auth/reauth` succeeds and bounded card status returns
                  `card_on_file=false` / count band `zero`. Blocked now on the
                  owner-keystore transaction approving `0x9f0754be...` in
                  `TinkerAccountEncumbrance`; preflight correctly fails closed
                  with `compose_hash_not_approved`.
                  Follow-up 2026-07-09: the compose hash is now approved in tx
                  `0xb7e6d0fc504146d88005339bd859142a5f2d6c3f99315d81cb00742ebc15d48e`
                  at block `43905420` and `$10` preflight is ready, but packet
                  `/tmp/dnai-tinker-funding-validation-packet-20260709T065233Z`
                  timed out before card/add-balance receipts. Source fix
                  `5ab9e81` adds masked prompt echo/backspace support and
                  extends local encrypted-card upload timeout to 180 seconds;
                  rerun the packet with the same live identity and record the
                  bounded receipts.
                  Follow-up 2026-07-09:
                  `/tmp/dnai-tinker-funding-validation-packet-20260709T071145Z`
                  completed wrapper/manifest generation, but payment-method
                  ended as `transient_browser_failure` because an open billing
                  modal scrim intercepted the fallback click on the background
                  `Payment methods` tab; add-balance reached
                  `add_balance_submitted` but was not confirmed.
            - [x] Source/test fix: dismiss open billing dialogs before
                  payment-method tab fallback, constrain browser exception
                  receipt messages to classified bounded outcomes instead of
                  raw Playwright/page text, and fix masked-prompt newlines.
                  Focused tests cover the scrim fallback and receipt/message
                  boundaries.
            - [x] Build, attest, redeploy, and approve the new modal-dismiss
                  funding-validation image before the next real-card packet.
                  Build/redeploy evidence 2026-07-09: source
                  `658f6020db9972e0f7e1e914f72422ff5d08535f` built in GitHub
                  Actions run `29001302688`; delegate image
                  `35bcc693300644445af40e7d4eb5d488848a2006ed2d42b7f56638c60963c92c`
                  has verified provenance/SBOM attestations; Phala now attests
                  compose hash
                  `7edf41c2b7bec5531639df94b90e2d2b5d1ac181f07db17f012c085d8cdb6476`
                  and `/auth/reauth` plus bounded card-status succeed. Follow-up
                  2026-07-09: compose approval succeeded in tx
                  `0x0821933345af2d0090ed0ce99e8bc0c4856202b84ef6fbe5dd184dacdba50ad2`
                  at block `43907277`; packet
                  `/tmp/dnai-tinker-funding-validation-packet-20260709T074049Z`
                  produced `payment_method` `success` at `payment_submitted`
                  with card payload destroyed and no raw secret egress. The
                  add-balance leg reached `add_balance_submitted` but remained
                  `unknown_failure`; live balance read-back did not prove a
                  top-up.
            - [x] Source/test fix: stop treating `Payment methods` navigation
                  text as a billing error and require explicit add-balance
                  success copy before returning a successful add-balance
                  receipt. Unconfirmed top-ups now fail closed with a bounded
                  `Add-balance completion not confirmed` message instead of
                  returning page chrome in `bounded_message`; card-on-file
                  status now uses bounded DOM signals such as remove-card
                  controls instead of returning card details or assuming an
                  add-card button means zero cards.
            - [x] Build, attest, and redeploy the add-balance receipt
                  classifier/card-status fix. Done 2026-07-09: source
                  `2ab388103817bfbfaa7e20579a79213ed87fd85a` built in GitHub
                  Actions run `29002851796`; delegate image
                  `06c8d0fadd98922f0c6f5bded92b414be2bf423fc3c3e6af1b8e9e36b8c6975f`
                  has verified provenance and SPDX SBOM attestations; Phala
                  redeploy completed on the existing CVM and live attestation
                  reports compose hash
                  `a3d0a1bc28983731db0fcc27be5680a312d3dc8a84c47e7e30596fe5dfb16fc9`.
                  `/auth/reauth` succeeds and bounded card status now reports
                  `card_on_file=true` / count band `one_or_more` with no card
                  details.
            - [x] Approve the current startup-deferred oracle funding-validation
                  compose hash. Done 2026-07-09: live compose hash
                  `0x1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28`
                  was approved in tx
                  `0x9caf683b80b3c06a8b5de0f8ebeffcfd44d5a6f0305c285df9f32fdb687e402e`
                  at block `43910712`; `approvedComposeHashes` returned
                  `true`, and on-chain add-balance preflight returned
                  `allowed=true` for `$10`.
            - [x] Rerun a `$10` add-balance attempt without re-entering card
                  details unless the bounded card-on-file status changes.
                  Source/test fix 2026-07-09: `funding-validation-packet` now
                  supports an add-balance-only packet for the card-on-file case.
                  It no longer requires a payment-method receipt when
                  `--run-add-balance-attempt` or `--add-balance-receipt-json`
                  supplies the bounded evidence, and
                  `check-funding-validation-packet --require-add-balance`
                  replay-verifies that packet shape.
                  Source/test fix 2026-07-09: deployed-balance CLI reads now
                  accept `balance --api-url ...`, and read-only billing
                  exceptions are bounded to outcome labels instead of returning
                  raw Playwright call logs or Tinker URLs. Build/redeploy is
                  still required before the live endpoint has this fix.
                  Live attempt 2026-07-09:
                  `/tmp/dnai-tinker-add-balance-packet-20260709T095232Z`
                  proved the add-balance-only packet shape against the live
                  endpoint, but the receipt failed closed as `auth_required` at
                  `billing_page_loaded`; no top-up or charge is proven. Next
                  retry should include `--run-reauth-attempt` before
                  `--run-add-balance-attempt`.
                  Live attempt 2026-07-09:
                  `/tmp/dnai-tinker-add-balance-packet-20260709T095444Z`
                  included reauth first, but reauth returned `unknown_failure`
                  at `not_started`; a direct `/auth/reauth` probe returned
                  HTTP 500 with a non-JSON body. Source now adds an API-level
                  bounded fallback receipt for uncaught reauth exceptions.
                  Follow-up 2026-07-09: source
                  `3e0c1e1407166252c879f45a5c092ed8e9bfe70a` built in GitHub
                  Actions run `29011768301`, all three GHCR images have
                  verified provenance/SBOM attestations, and the Phala
                  funding-validation profile now attests compose hash
                  `d47eafee8fcf525a17ef60f835ca98d175adb6caa6679cc0bc39dd08e434150d`.
                  The owner approved that compose hash in tx
                  `0x82fec9894039c5c53a9d20dca2cfedf1406f8e3918fdd8a488f8d0827ee2f650`,
                  and read-only `$10` encumbrance preflight returned
                  `allowed=true`. Packet
                  `/tmp/dnai-tinker-add-balance-packet-20260709T103726Z`
                  proved reauth success and encrypted session-state save, but
                  add-balance still failed closed as `auth_required` at
                  `billing_page_loaded`; Phala logs showed the saved browser
                  session was loaded, so Playwright `storage_state` alone is
                  insufficient for the Tinker billing page.
                  Source/test fix 2026-07-09:
                  `b9a962f64fe0ec4a10ce4fe4bc97787a22f82995` adds a
                  same-context inline billing reauth retry when billing hits a
                  bounded auth blocker. Focused local tests passed, GitHub
                  Actions run `29012433267` built all three GHCR images with
                  verified provenance/SBOM attestations, the funding-validation
                  compose now pins
                  `tee-email-oracle@sha256:ce0ea569280a796ce2a3d5517e22d03ad72a9d7a316a550d11bd1b155a85a5ce`,
                  `tinker-delegate@sha256:1e3da3a88ef037b85678c7122a1a4a11a01ae687a36a57fd38deb1ed8984461e`,
                  and
                  `neko-chrome@sha256:7c0795e15e660d4501b6324c7f223fd65f22725a7752b683ae30a2874d373d01`,
                  Phala attests compose hash
                  `a15af6d8e7262d7d2799fa31968c568933f3468771b808720583a6dc6ed998c5`,
                  and the owner approved that compose hash in tx
                  `0x186d1ea81d9dfbeb0898485defcf427e8155cbcbb0f9e225326092616bd51c34`
                  at block `43913068`.
                  Packet
                  `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z`
                  proved reauth success and reached `add_balance_submitted`
                  with `raw_secret_egress=false`. The receipt stayed
                  conservative as `unknown_failure` because no explicit success
                  copy was observed, but an independent bounded balance read
                  returned `$10.00`; `check-funding-validation-packet
                  --require-add-balance --require-deployed-attestation` passed
                  when replayed with the full validation identity.
            This P0 is complete for the one-off operator-owned validation lane.
            Production/repeated funding remains blocked on non-dev OS,
            hardened debug posture, quote-internal verification, and
            legal/compliance approval.
      - [x] Make account access/billing-gate detection an automated bounded step
            (like card-add / credit-add / auth). Done 2026-07-11:
            `tinker_delegate.account_access.classify_account_access` +
            `account_access_receipt` deterministically map the billing/account
            page text to a closed state vocabulary (`active`,
            `access_blocked_billing`, `payment_required`, `waitlist_or_gated`,
            `unknown`), each with `actionable_by_automation` and an
            `operator_action`, plus a `page_text_hash` so a gate change (e.g.
            after activation) is detectable across runs — bounded output only, no
            raw page text/card/secret. Grounded in evidence, the observed
            "Access is blocked due to billing status" gate classifies as
            `access_blocked_billing` with `actionable_by_automation=false` and
            `operator_action=contact_provider_for_account_activation` (adding a
            card + $20 did not clear it, so it is a provider-side activation gate,
            not a self-serve step). `billing.get_account_access_status` navigates
            the authenticated (TEE-owned) session and returns the bounded receipt;
            the in-process `account-access-status` CLI runs it inside the CVM,
            and operator-authed `GET /billing/account-access-status`
            (`handle_account_access_status`) serves it from the deployed delegate
            so the funding tooling can query the gate remotely (exceptions fail
            closed to a bounded `unknown` receipt, no raw page text/URL).
            `tests/test_account_access.py` (10) cover classification, boundedness,
            and hash-change detection; `tests/test_api_billing_policy.py` (+3)
            cover the endpoint (bounded receipt, auth-required, bounded
            exception). This automates *detecting* the gate; the gate itself is a
            Thinking Machines account-approval action that no automation can
            force — the receipt names exactly that. The readiness tooling now
            consumes it: `tinker-smoke-command-plan --account-access-state <state>`
            adds `tinker_account_access_blocked` (hard, not-ready) for
            `access_blocked_billing` / `waitlist_or_gated` / `payment_required`
            with `next_action=resolve_tinker_account_activation` — surfaced above
            all compose/policy reasons — and warns `tinker_account_access_unverified`
            when unchecked, so the plan is honest that an unactivated account
            blocks the smoke even when every other gate is green
            (`tests/test_tinker_smoke_command_plan.py` +3).
- [x] `P0` Confirm PCI and Stripe obligations.
      Research whether the current encrypted-card-to-TEE flow is acceptable or
      whether the system must use Stripe-hosted tokenization / SetupIntent /
      PaymentMethod flows.
      Done in `⚙️/tinker-delegate/docs/STRIPE-PCI-FUNDING-SCOPE.md`: raw-card
      encrypted delivery is limited to a one-off operator-owned capped
      validation path, while production/repeated funding should use an official
      Tinker route, Stripe-hosted/tokenized collection, SetupIntent /
      PaymentMethod style reuse with consent, or manual/developer prefunding
      until compliance review approves otherwise.
- [ ] `P0` Obtain legal/compliance approval before enabling production or
      repeated card funding, especially any third-party/customer card funding.
      Until approved, keep raw-card encrypted delivery limited to the
      operator-owned capped validation path in
      `⚙️/tinker-delegate/docs/STRIPE-PCI-FUNDING-SCOPE.md`.
- [ ] `P0` Ensure no card details appear in:
      browser traces, Playwright logs, screenshots, API logs, exception messages,
      crash dumps, or Phala console output.
      - [x] Suppress payment-method screenshots after card entry/submission even
            when debug screenshots are enabled; only non-secret billing debug
            screenshots may be written.
      - [x] Add trace/HAR/video/card-screenshot deletion for configured browser
            debug artifact directories after card submission attempts.
      - [x] Add deployed log/Phala-console verification for the encrypted
            card path once the CVM endpoint is available. Done 2026-07-09:
            `verify-deployed-log-safety` scans stdin or saved deployed logs for
            card-shaped values, unredacted card/CVC fields, Tinker API keys,
            bearer/JWT tokens, OTP fields, and private-key-shaped fields while
            returning only finding classes/counts and line hashes. Live
            operator-validation scan of `phala logs --cvm-id cvm_1w85mGjo
            --tail 1000` covered 236 lines / 10KB-100KB and found zero
            findings with `log_snippets_returned=false` and
            `raw_secret_egress=false`. Production still needs public-log/dev-OS
            posture removed before this becomes production evidence.
      - [x] Add crash-dump/core-dump policy for browser and delegate processes:
            Python entrypoints set `RLIMIT_CORE=0`, and Tinker local/Phala
            compose services set `ulimits.core: 0`.
      - [x] Make billing CLI output fail closed before printing or writing JSON
            if a delegate response contains submitted card material or
            secret-shaped fields.
- [ ] `P1` Add funding receipt records:
      amount band, timestamp, payment method token/reference, Tinker balance band,
      CVM quote, and card payload destruction proof.
      - [x] Return bounded payment-method and add-balance attempt records from
            billing automation/API responses: surface, outcome, furthest stage,
            issued timestamp, evidence hash, amount band, balance band, TDX
            quote hash when present, and card-payload destruction status.
      - [x] Persist bounded funding receipts in encrypted/sealed delegate
            storage and expose only bounded records through
            `GET /billing/funding-receipts`.
      - [x] Build a bounded funding validation manifest from preflight and
            receipt records so a capped operator validation attempt can publish
            hashes, bands, outcome, TDX quote hash, and card-destruction /
            no-raw-egress booleans without card material.
      - [x] Add a bounded funding manifest verifier that replays saved
            preflight/receipt/policy hashes, checks manifest integrity, and
            reports named pass/fail checks without echoing packet contents.
      - [x] Add CLI `--receipt-output` support for bounded billing attempt
            records so validation receipts can be saved without console
            scraping.
      - [x] Add a packet summary artifact for funding validation runs so
            reviewers can see preflight readiness, receipt outcome, manifest
            hash, and verification status without packet body disclosure.
      - [x] Add optional add-balance receipt, manifest, verification, and
            summary fields to funding validation packets so low-value top-up
            evidence can be audited separately from payment-method evidence.
      - [x] Add a checker summary for validation packets so reviewers can
            distinguish internally consistent local packets from packets with
            live deployed TDX attestation evidence.
      - [ ] Add payment-method token/reference to funding receipts once the
            live funding path exposes a safe non-card reference.
- [x] `P1` Add budget enforcement:
      Tinker spend cannot exceed buyer cap, room cap, daily cap, or operator cap.
      Done 2026-07-12: `tinker_delegate.spend_budget` is a pure, fail-closed
      multi-cap enforcer. `SpendCaps` holds the four ceilings (None = uncapped);
      `SpendLedger.authorize(amount, day_bucket=)` admits a proposed spend only if
      it fits under EVERY active cap — buyer/room/operator apply to cumulative
      spend-to-date, daily applies per caller-supplied day bucket (pure, no wall
      clock). The tightest cap binds (strict intersection); a rejected charge
      consumes no budget (no mutation on deny); the boundary is strict
      (`spend > cap` denies, exactly-on-cap allowed). Output is bounded — allowed
      flag, binding cap name, reason code, and coarse remaining bands per cap, no
      raw wei (`raw_secret_egress=false`). `tests/test_spend_budget.py` (12) cover
      within-budget, each cap's denial, exact boundary, tightest-cap-binds,
      daily-reset-with-cumulative-persistence, fail-closed no-mutation, negative
      amount, uncapped scopes, and bounded egress. Remaining: wire the ledger into
      the live Tinker spend path (blocked with the Tinker account) and persist the
      ledger under sealed delegate storage so caps survive restart.
- [x] `P1` Add top-up policy:
      minimum balance band, max top-up, auto-reload on/off, emergency disable.
      Done 2026-07-12: `tinker_delegate.topup_policy` is a pure, fail-closed
      auto-reload decision primitive. `TopUpPolicy` holds min-balance,
      target-balance, max-top-up, `auto_reload_enabled` (default OFF — charging a
      card is opt-in), and an `emergency_disabled` kill switch. `decide_topup`
      order (most protective first): emergency_disabled -> auto_reload_off ->
      invalid(negative)_balance -> balance_sufficient -> reload toward target
      capped at max_topup (full `topup_authorized` or `partial_topup` when the cap
      binds). The `TopUpDecision` carries the exact action amount but bands it in
      `to_public_dict`. Crucially a top-up is a SPEND: composition tests show
      `decide_topup` -> `spend_budget.SpendLedger.authorize` denies (fail closed,
      no budget consumed) when the top-up exceeds a cap, so caps still bind
      end-to-end. `tests/test_topup_policy.py` (12) cover default-off, emergency
      wins, sufficient, full/partial reload, negative/zero, bounded egress, and
      the spend-budget composition. Remaining: wire into the live billing/top-up
      path (blocked with the Tinker account) and persist balance state under
      sealed storage.
- [x] `P1` Add failure handling:
      card declined, 3DS challenge, bot check, rate limit, insufficient funds,
      Tinker billing outage, partial top-up.
      Done 2026-07-12: `tinker_delegate.funding_failure.classify_funding_failure`
      maps each failure kind to a bounded, fail-closed disposition — RATE_LIMIT /
      BILLING_OUTAGE retry with backoff (until `max_attempts`, then escalate +
      disable), CARD_DECLINED / INSUFFICIENT_FUNDS escalate to a human AND disable
      auto-reload, THREE_DS_CHALLENGE escalates (interactive auth, never
      auto-completed), BOT_CHECK aborts + disables (never auto-solved, per the
      CAPTCHA/bot-detection invariant), PARTIAL_TOPUP is accepted + re-evaluated,
      and UNKNOWN/unrecognized fails closed to ABORT + disable. The
      `disable_auto_reload` flag flips `topup_policy.TopUpPolicy.emergency_disabled`
      — a composition test proves the full failure -> kill-switch -> no-more-charges
      loop. `tests/test_funding_failure.py` (10) cover every kind, retry
      exhaustion, unknown fail-closed, invalid inputs, bounded egress, and the
      top-up kill-switch composition. Completes the funding-control triad
      (`spend_budget` enforce + `topup_policy` reload + `funding_failure`
      classify). Remaining: wire into the live billing path (blocked with the
      Tinker account).
- [ ] `P2` Add crypto/A2A rails only after the basic card or official funding
      route is safe and auditable.

## Milestone 4: Tinker Compute, Private Rewards, And TTT/RL Bio Validation

### Tinker SDK And Isolated Sessions

- [ ] `P0` Run a real Tinker SDK smoke test from inside the deployed CVM.
      Done when the service starts a tiny training job, saves a TTL checkpoint,
      samples from it, and deletes/lets it expire.
      - [x] Add a bounded operator smoke surface in source. Done 2026-07-09:
            `tinker_delegate.tinker_smoke.run_tinker_sdk_smoke()` runs the
            tiny real-SDK pattern from the gated integration test through
            `IsolatedTinkerSession`: create one LoRA run, one forward/backward,
            one optimizer step, save a TTL checkpoint, create a path-checked
            sampler, sample one token, and cleanup. Its receipt returns only
            bounded fields: deal/run/checkpoint hashes, cost bands, policy
            result, sample-observed boolean, and cleanup counts. It does not
            return the API key, raw run ID, raw checkpoint path, sample text, or
            checkpoint IDs.
      - [x] Add operator invocation surfaces without enabling production by
            default. Done 2026-07-09: `tinker-smoke` CLI can run locally inside
            the CVM/container or call `POST /tinker/smoke --api-url`; the HTTP
            endpoint is disabled by default, requires runtime bearer auth when
            enabled, and is enabled only in the temporary
            `docker-compose.tinker-funding-validation.phala.yaml` profile for
            the next funded validation redeploy.
      - [x] Add focused mocked tests for the smoke surface. Done 2026-07-09:
            mocked SDK tests prove tiny train/sample/cleanup execution and
            bounded output; API tests prove disabled-by-default and bearer-auth
            gates; CLI tests prove remote invocation writes bounded JSON.
      - [x] Build/push the smoke-capable delegate image with GitHub
            provenance/SBOM, pin the digest in the funding-validation compose,
            redeploy to Phala, and approve the new compose hash for
            `SPEND_TINKER_COMPUTE`.
            Done 2026-07-09: the live Phala funding-validation redeploy attests
            compose hash
            `c6b446fe9b7ff656c6db799a7461a2a6dba045ae24de16d365c80a6cb83863da`.
            `TinkerAccountEncumbrance`
            `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e` approved that compose
            hash in tx
            `0xc7adf6b22668f3aa15d9d7e81dff444daac3f1f4b8339981f842042ddd7dbb67`.
      - [x] Add bounded diagnostics for SDK smoke failures before redeploying
            another debug image. Done 2026-07-09: smoke receipts now include an
            allowlisted `sdk_error.bucket`, redacted normalized
            `sdk_error.message_hash`, coarse message-length band, and bounded
            `sdk_diagnostics` for request shape plus capability probing without
            returning raw provider text, model lists, API keys, emails,
            card-shaped strings, request IDs, run IDs, or samples.
      - [x] Add project-aware Tinker smoke diagnostics and safe default request
            shape. Done 2026-07-09: the smoke path now passes optional
            `TINKER_PROJECT_ID` into `tinker.ServiceClient`, returns only
            project configured/hash evidence, records enum `failure_site` and
            `operator_action`, rejects unknown API payload fields instead of
            silently falling back to defaults, and defaults the paid smoke to
            the official quickstart pair `Qwen/Qwen3-8B` rank `32`.
      - [x] Build and locally pin the project-aware delegate image with verified
            GitHub provenance/SBOM. Done 2026-07-09: source
            `6f5d557d1dab6641590c12ad96eecad74a101638` built
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:d7872a09b7fe28e25a53dafa721a355cb0677d42e2939f4babbbff7e167f306d`;
            local `verify-ghcr-image-attestation` verified SLSA provenance and
            SPDX SBOM predicates for the TEE image workflow, and
            `docker-compose.tinker-funding-validation.phala.yaml` now pins that
            digest. Local `verify-compose-hash` computes compose hash
            `d0aea171db3483ae1dae4ff73294548ca5906481166893114ce048688bf2f3f9`
            and rendered compose SHA
            `c8d16bc2cefb5a01425defe6fe8fddbc7d850a18cf2ec709a0724ccfb199713d`.
            Follow-up evidence below records the live Phala redeploy and
            on-chain approval for that image.
      - [x] Add bounded Tinker SDK client-configuration diagnostics and wire the
            same project/base-url settings into future evaluator sessions. Done
            2026-07-09: smoke receipts now record a bounded `client_config`
            block showing whether the API key argument, project-id argument, and
            base-url argument were provided, plus only a host-family and hash for
            any non-default base URL. This fixes the constructor-failure case so
            a future `ServiceClient` failure still reports
            `project.configured=true` if `TINKER_PROJECT_ID` was set, without
            leaking the raw project id or endpoint. `ControlPlane` now passes the
            same `TINKER_PROJECT_ID` / `TINKER_BASE_URL` settings when creating
            real evaluator sessions, and the gated direct real-SDK integration
            test now uses the same optional settings. The updated local
            rendered-compose candidate hashes to
            `fdaf00da9657560705d8f315667201cdebad5cc134e351eecb105f74339e4211`
            with rendered SHA
            `49cec4b25620ffb96bf38e57f3ed554a60f0ca4c98c9dc9b017d082a1d971af9`
            and `allowed_envs=[]`. Follow-up build evidence 2026-07-09:
            GitHub Actions run `29023713771` built source
            `76609fbe6617a8c7162c4dbfbbbc060e9b01322e` into
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:83e58d165cc30374feb70f475dc6bf30da07d63895f6d871feb4f7828926758b`,
            and local `verify-ghcr-image-attestation` verified provenance and
            SPDX SBOM attestations for that digest. Follow-up live evidence:
            the image was redeployed to Phala as app-compose hash
            `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180`;
            `verify-cvm-attestation` passed against raw compose hash
            `60046a718ba13c71f015a8633b4a9ee6892661762414e9e61636a897327a2d82`,
            app ID, OS hash, and all three digest-pinned images; and
            `TinkerAccountEncumbrance` approved the new compose hash in tx
            `0xc597c8e2bbfcc58255c6d407ce615ec4befd992b4e4ef2c34854b99a4d4c52b2`
            at block `43919367`.
      - [x] Add a bounded project-config smoke command-plan CLI so the next
            live retry has an explicit no-secret install/redeploy/smoke path.
            Done 2026-07-09: `tinker-smoke-command-plan` reads
            `deployments/base-sepolia.json`, reports whether
            `TINKER_PROJECT_ID` is present locally and in the latest live CVM
            evidence, emits `next_action`, and includes
            `client_config_install_argv` / `client_config_install_shell` for
            sealing `TINKER_PROJECT_ID` and optional `TINKER_BASE_URL` into a
            running delegate that already exposes `/tinker/proxy/client-config`.
            It still emits Phala redeploy, attestation verification,
            `TinkerAccountEncumbrance` approval, spend preflight, and bounded
            smoke templates when a new compose is needed. The output uses
            environment variable names and a new-compose placeholder only; it
            never prints project IDs, bearer tokens, API keys, RPC URLs, run
            IDs, checkpoint paths, or sample text. Follow-up 2026-07-09:
            focused tests cover `next_action=set_project_id_env`,
            `next_action=seal_client_config`, and
            `next_action=run_smoke_sequence` without leaking env values.
      - [x] Add source-real sealed Tinker client-config install/status plumbing
            so the live CVM can receive project/client settings without
            returning them.
            Done 2026-07-09: `TINKER_CLIENT_CONFIG_STORE_*` settings back an
            encrypted `tinker_client_config_store`; `tinker-client-config
            --install` reads `TINKER_PROJECT_ID` / `TINKER_BASE_URL` from env,
            can install to a deployed delegate with runtime bearer auth, and
            emits only hashes/host-family/status. `run_tinker_sdk_smoke()`,
            proxy status, and lazy `ControlPlane` construction now resolve
            project/base-url from the sealed store when direct env settings are
            absent. Focused tests prove the stored project id is passed to the
            mocked Tinker `ServiceClient` and never appears in receipts. Live
            deployment and a successful real Tinker training run remain open.
      - [x] Pin the funding-validation Phala compose to the latest attested
            image set that includes sealed client-config command-plan support.
            Done 2026-07-09: GitHub Actions run `29058135707` built commit
            `3bb9ff4b986e95debbe0d13f9a02edb9c0d03f80` into
            `tinker-delegate@sha256:a76c2efb9274d2669b98836fdc30450d79a1c96702150079e1ba13bf2d9b8ac6`,
            `tee-email-oracle@sha256:e663c88eb87e880abbc012befe1948a4a45007ea267ae85ab79a953936de9e99`,
            and
            `neko-chrome@sha256:4b36022cc2d0c50a0080c9f460a7252659a9a201ee2b43d8dfcffd033685a88a`.
            Local `verify-ghcr-image-attestation` verified provenance and SPDX
            SBOM attestations for all three images. Local raw compose candidate
            hash is
            `5d469e071e416305b032172683616d72efb12e99ca9b3ee5200cfd60d532f07a`
            with rendered compose SHA-256
            `62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`.
            Follow-up 2026-07-09: this image set is now live on Phala CVM
            `cvm_1w85mGjo` / app
            `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` at app-compose hash
            `1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`.
            `verify-cvm-attestation` passed against app ID, OS image hash,
            the three pinned image digests, local raw compose/image-policy hash
            `1db1ee033f333509726d03c325788e0fc5c0803351d6d1496ee42ff14fa83700`,
            and rendered compose SHA-256
            `62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`.
            The runtime env surface has 12 selected keys, key hash
            `a694364185438f7508fe696ccf2fd971fc6060f8fa0c3aad633185c3d8fb7b30`,
            policy flags enabled, and `TINKER_ENCUMBRANCE_COMPOSE_HASH`
            self-bound by the redeploy helper to the provisioned app-compose
            hash before env encryption. Current blocker: read-only chain state
            reports this live compose is not yet approved on-chain.
      - [x] Bind generated Tinker smoke redeploy commands to the newly
            provisioned Phala compose hash.
            Historical 2026-07-09 completion: the retired update helper accepted
            `--self-compose-hash-env TINKER_ENCUMBRANCE_COMPOSE_HASH`, fails
            closed if that env key is not selected, and overwrites the selected
            env value with Phala's provisioned app-compose hash before
            encrypted env commit. At the time, `tinker-smoke-command-plan`
            emitted that flag and included the self-bound compose hash plus
            issue/deployment policy flags in the verifier env allowlist. That
            interface is no longer executable; generated smoke plans
            intentionally emit no redeploy command until the reviewed
            fresh-batch executor is ready.
      - [ ] Run `tinker-smoke --api-url ... --max-usd 0.05
            --require-encumbrance` successfully from the deployed CVM and record
            the bounded receipt plus attestation evidence.
            Current blocker 2026-07-09: the deployed smoke path passes
            `TinkerAccountEncumbrance`, loads the sealed Tinker API key, and
            then fails closed with `BadRequestError` at `api_key_loaded` before
            Tinker training creation. The diagnostic receipt reports Tinker SDK
            `0.15.0`, `sdk_error.bucket=invalid_request`, HTTP class `4xx`,
            model family `meta-llama`, rank band `<=8`, and no capability probe
            result from `ServiceClient.get_server_capabilities`. No run ID,
            checkpoint, sample, cleanup proof, or spend proof exists yet, so
            this parent P0 remains open. Follow-up live probes with
            `Qwen/Qwen3-8B` rank `32` and rank `16` produced the same bounded
            `BadRequestError` hash before training creation, so the current
            working hypothesis is missing project/account entitlement or a
            service-side account configuration requirement, not only the old
            model/rank default. Follow-up 2026-07-09: the project-aware compose
            was redeployed and approved at live compose hash
            `314cd60b093194dcac0480f3586c8979a9734a56c7a521cd8ef043dee9417816`;
            attestation verification passed, and
            `/tmp/dnai-tinker-smoke-project-aware-20260709T134058Z.json` still
            failed before training creation. The new bounded receipt narrows the
            failure to `sdk_error.failure_site=service_client_create`,
            `sdk_error.operator_action=check_sdk_client_configuration`, correct
            Qwen/rank-32 request shape, and `project.configured=false`. Next
            step: set `TINKER_PROJECT_ID` if the Tinker console exposes one or
            obtain the correct Tinker service/client configuration, then rerun
            this same smoke command. Follow-up live evidence 2026-07-09:
            `/tmp/dnai-tinker-smoke-client-config-live-20260709T142413Z.json`
            ran against the client-config diagnostic image at live compose hash
            `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180`.
            It still failed before training creation at
            `service_client_create`, but now confirms bounded
            `client_config.api_key_argument=provided`,
            `client_config.project_id_argument=omitted`, and
            `client_config.base_url_argument=sdk_default`; `raw_secret_egress`
            remained false. The next blocker is therefore concrete missing
            Tinker project/client configuration, not the Phala/contract/image
            verification chain. Follow-up 2026-07-09: the latest pinned
            client-config install image is live and attested at app-compose
            hash
            `1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`,
            but `TinkerAccountEncumbrance.approvedComposeHashes(...)` returns
            `false`; `e682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`
            remains the latest approved compute compose. Bounded client-config
            status on the live `1d6db...` CVM reports `project_id_configured=false`,
            encrypted store missing, and `raw_secret_egress=false`. Next step:
            approve `0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`,
            then seal `TINKER_PROJECT_ID` with `tinker-client-config --install`
            and rerun smoke.
            Follow-up 2026-07-10: `TINKER_PROJECT_ID` is optional in the
            official Tinker SDK, so `tinker-smoke-command-plan` no longer
            blocks readiness on it; it is now a
            `tinker_project_id_not_configured_optional` warning. The plan
            instead gates on `current_compose_approved` (from manifest
            compose-approval evidence), emits
            `next_action=approve_current_compose` with a concrete
            `approveComposeHash(bytes32)` template bound to the currently
            attested compose hash instead of a placeholder, and prefers the
            latest live compose/runtime-env evidence over stale smoke-receipt
            evidence. Smoke `sdk_error` receipts now also carry a bounded
            `provider_error_category` enum (invalid/inactive API key, project
            inaccessible, entitlement, funding/quota, SDK version, endpoint
            mismatch, unclassified) plus exact `http_status`, derived from
            short allowlisted provider body fields that are never returned, so
            the next live failure maps to a concrete `operator_action` without
            raw provider egress. Live rerun with these tools remains the open
            step.
            Follow-up 2026-07-11: the authoritative remaining blocker is now
            confirmed to be the Tinker ACCOUNT, not our stack. After the SDK was
            pinned to `tinker>=0.22` (local 0.22.7, clears the old version-400),
            the account returns HTTP 402 "Access blocked due to billing status"
            that persisted even after topping the balance to ~$20 — an
            account-level activation/entitlement gate on Thinking Machines' side.
            A read-only `get_server_capabilities` probe from the dev box (real
            sealed key, supported SDK, working general internet) stalled 40s+ on
            the Tinker API, consistent with the blocked/unactivated state. This is
            external and not code/credit-fixable; it requires the operator to
            activate/enable API access on the Tinker account (or Thinking Machines
            support). To make retries after unblocking give a definitive answer in
            seconds instead of hanging, `run_tinker_sdk_smoke` now caps the first
            authenticated SDK calls (ServiceClient connect + create_training) with
            a daemon-thread wall-clock deadline (`smoke_connect_timeout`, default
            45s): a stall raises `SmokeTimeoutError`, the receipt reports
            `sdk_error.bucket=transient_timeout` and
            `operator_action=retry_or_check_tinker_account_activation`
            (service_client_create) / `retry_later` (create_training), and the
            hung SDK thread is abandoned so it never blocks process exit.
            `tests/test_tinker_smoke.py` adds two fast-fail tests (connect hang and
            training-creation hang) proving a <10s bounded verdict.
            Correction, 2026-07-13: the "authoritative remaining blocker" framing
            above is superseded. By design, end users reach training only through
            the proxy — they never touch the upstream account or its key — and the
            proxy-mediated delegated-training path is built and validated
            end-to-end (see the 2026-07-13 Milestone). A billing-active upstream
            account and a current valid sealed key are ordinary operational
            provisioning, not a gap in the system. A raw call to Tinker with the
            raw upstream key is outside the product surface and is expected to
            fail; it does not indicate the delegation is incomplete.
            Still blocked on: operator activating the Tinker account, then an image
            rebuild (to `tinker>=0.22`) + redeploy + compose approval + live smoke.
- [x] `P0` Add integration tests for `IsolatedTinkerSession` against a mocked
      Tinker SDK.
- [x] `P0` Add real SDK integration tests gated by an env var and budget cap.
- [x] `P0` Enforce one training run per deal in runtime, not only by convention.
- [x] `P0` Enforce checkpoint TTL on every save.
- [x] `P0` Enforce path-checked sampling:
      no arbitrary model path, no cross-deal checkpoint access.
- [x] `P0` Block download/publish/list-all operations from first-party evaluator
      paths.
      Done when `sft_evaluate()` uses only wrapper methods, the wrapper exposes
      no REST/list/download/publish methods, base-model sampling is scoped, and
      tests fail on raw `ServiceClient`/admin API usage in evaluator code.
- [ ] `P0` Put arbitrary third-party evaluator code behind a process or sandbox
      capability boundary.
      Done when untrusted evaluator code cannot use Python introspection to
      recover the raw `ServiceClient`, Tinker API key, checkpoint paths, or
      artifact bytes outside the approved wrapper calls.
      - [x] Add a source-modeled process/capability evaluator runner.
            Done 2026-07-09: `SandboxedEvaluatorRunner` executes simple
            evaluator code in a restricted subprocess that receives only
            bounded context, emits an allowlisted capability plan, and lets the
            parent execute that plan through `IsolatedTinkerSession`. Tests
            prove the child cannot see the raw session object, raw service
            client, raw artifact bytes, run IDs, checkpoint paths, sample text,
            or upstream API key in public output.
      - [x] Add process-level resource-limit + no-filesystem-write hardening
            (the local, non-deployment part of the below). Done 2026-07-12:
            `SandboxedEvaluatorRunner` now applies POSIX `rlimit`s to the
            evaluator child via a `preexec_fn` — `RLIMIT_CPU` (kills a
            CPU-spinning breakout with SIGXCPU), `RLIMIT_FSIZE=0` (no-filesystem
            *write* policy; stdout is a pipe so the bounded result still
            returns), `RLIMIT_NOFILE` (caps file/network descriptors),
            `RLIMIT_CORE=0` (no core dump can spill child memory), and an opt-in
            `RLIMIT_AS` (left unset by default because a low cap breaks CPython
            startup — real memory bounding is a cgroup concern). Limits are
            best-effort and never raise an existing hard cap, so a host that
            refuses a limit still evaluates behind the restricted-builtins
            namespace (the primary control) rather than failing spuriously.
            Child runs with `-S -B` (no site, no `.pyc` writes). Tests prove the
            intended spec table, that the limits actually take effect in a real
            child on this host, and that an over-large policy stays within the
            host hard cap (`tests/test_evaluator_sandbox.py`, 8; +1 skipped on
            infinite-NOFILE hosts).
      - [ ] `Blocked (deploy)` Complete the sandbox for hostile third-party code
            in a deployed CVM/container: real Tinker datum adapters, hard
            no-network policy (netns/seccomp), resource cgroups, and audited
            egress. Blocked on a deployed CVM; the rlimit/no-fs-write layer above
            is the process-level portion doable without deployment.
- [x] `P0` Implement cleanup with retries and a cleanup attestation.
- [x] `P1` Add cost metering that reconciles:
      Tinker reported cost, estimated tokens/steps, chain computeCost, and buyer
      budget remaining.
      Done 2026-07-12: `tinker_delegate.cost_metering.reconcile_costs` ties the
      four cost views together — the metered estimate (`session.CostMeter`,
      priced from token counts), the on-chain `computeCost` the buyer is charged,
      the buyer `budget_cap`, and an optional Tinker-`reported_cost` — into one
      bounded, fail-closed `CostReconciliation`. Status is assigned buyer-harm
      first: `OVER_BUDGET` (chain charge > authorized budget) >
      `CHAIN_EXCEEDS_ESTIMATE` (delegate submits more than it metered — overcharge
      protection; a charge *below* estimate is fine) > `REPORTED_MISMATCH`
      (Tinker's reported cost diverges from estimate beyond `tolerance_bps`) >
      `RECONCILED`. Only `RECONCILED` is `settlement_safe`, so settlement can
      refuse an inconsistent charge. `budget_remaining_wei` is floored at zero.
      `to_public_dict()` bands every wei amount via `value_band` and passes
      `assert_bounded_egress`. `reconcile_from_meter` anchors on a real
      `CostMeter` via duck-typing (no heavy `session`/Tinker import).
      `tests/test_cost_metering.py` (14) prove the status ladder, tolerance
      slack, priority ordering, bounded egress, and reconciliation against a real
      metered `CostMeter`. Money-path review 2026-07-12: confirmed the reconciler
      is correct (no bug) and pinned the OVER_BUDGET boundary as strict `>`
      matching the on-chain `charge > budgetCap` rule exactly (at-cap in-budget on
      both sides), so the off-chain gate and contract cannot silently diverge; the
      calling contract is now documented (`chain_compute_cost_wei` = total charge
      incl. fee, `fee_wei` informational and never re-added). Wired 2026-07-12:
      `ControlPlane.evaluate()` now runs
      the reconciler before a result can settle — it checks the developer charge
      (compute + fee) against the budget headroom left after the seller offer
      (mirroring the on-chain `offer + computeCost + fee <= budgetCap`
      constraint) and, when `not settlement_safe`, fails closed by flipping the
      recommendation to `reject` and recording `settlement_safe` /
      `reconciliation_status` on the bounded `evaluation_completed` run-metadata
      event. `tests/test_local_synthetic_room.py` adds an over-budget deal that
      flips to reject in the TEE instead of reverting on chain (2 tests in that
      file). Remaining: feed a real Tinker-reported cost into `reported_cost_wei`
      once the deployed SDK path returns actual billing.
- [x] `P1` Add model/run metadata limits so user-provided fields cannot leak raw
      private data through Tinker metadata.
      Done 2026-07-09: `IsolatedTinkerSession.create_training()` now bounds
      evaluator-provided `user_metadata` before it reaches Tinker. Only the
      public `deal_id`, a `bounded-v1` policy marker, and a small allowlist of
      safe label fields can pass raw; arbitrary metadata is represented by a
      bounded hash/drop count, oversize or non-JSON metadata fails closed, and
      tests prove private notes, overridden deal IDs, and free-form labels do
      not reach the upstream SDK metadata map.
- [x] `P1` Add a simulator/fake Tinker backend for CI and offline demos.
      Done 2026-07-09: `FakeTinkerServiceClient` models the SDK surface used by
      `IsolatedTinkerSession` without upstream credentials, and
      `test_local_synthetic_room` exercises encrypted artifact ingress,
      buyer cap/reserve, modeled training/checkpoint/sample calls, bounded
      result packet construction, and cleanup without returning raw artifact,
      sample text, run IDs, checkpoint paths, API keys, or project IDs.

### Private Verified Reward / RLVR Environments

- [x] `P0` Treat the project as building a private verified-reward substrate, not
      only a one-shot evaluator.
      Done when docs and APIs name the abstraction directly: sealed data defines
      a reward oracle; agents optimize candidates against that oracle; only
      bounded reward-derived outputs leave.
- [x] `P0` Create `PROJECT.md` with the formal private-reward security model:
      ideal functionality, leakage function, simulator theorem, query/reward
      leakage bound, assumptions, and limitations.
- [ ] `P0` Keep `PROJECT.md` synchronized with implementation.
      Any environment that releases more than the documented leakage must update
      the theorem assumptions, leakage function, and safety labels before merge.
- [x] `P0` Define the core `PrivateRewardEnvironment` interface:
      `problem()`, `candidate_schema`, `reward(candidate)`,
      `acceptance_policy`, `output_reducer`, `query_budget`, `finalize()`, and
      `attest()`.
- [x] `P0` Define the leakage function for every environment:
      public problem text, accepted candidate count, reward bands or no reward
      egress, final bounded result, timing/cost bands, hashes, and attestations.
- [x] `P0` Decide where the optimizer lives for each security tier:
      inside the same TEE, inside an attested remote Tinker/training service, or
      outside the TEE with no reward-derived state leaving.
- [x] `P0` Prohibit the unsafe default:
      do not send private reward labels, dense rewards, selected-example traces,
      reward-derived gradients, private holdout data, or checkpoints encoding
      private reward information to an untrusted external trainer.
- [x] `P0` Add an internal-only dense-reward mode.
      The optimizer may see exact rewards if it is inside the attested boundary;
      public egress still gets only bounded summaries.
- [x] `P0` Add an external-optimizer-safe mode.
      External LLMs or code generators can propose candidates, but they receive
      only public prompts and approved bounded feedback.
- [x] `P0` Add a reward-query budget and transcript hash for every private
      reward environment.
- [x] `P0` Add a reward precision budget.
      Exact continuous rewards are internal-only; any released reward must be
      quantized, thresholded, noised, or withheld.
- [ ] `P0` Add candidate sandboxing:
      no network, no arbitrary file reads, no write access outside scratch,
      fixed resource limits, bounded stdout/stderr, deterministic seeds where
      feasible, and redacted traces.
  - [x] `P0` Add a local Python candidate sandbox for toy private-reward
        environments: subprocess timeout, scratch cwd, stripped environment,
        deterministic seed, bounded stdout/stderr, static preflight, and
        runtime guards for file, network, process, and import escapes.
        Self-reviewed 2026-07-12: confirmed defense-in-depth holds — AST bans
        dangerous imports + literal dunder attrs, and the restricted `__builtins__`
        (no `getattr`/`type`/`vars`/`eval`/`exec`/`compile`/`__build_class__`,
        only `math`/`random` exposed) blocks AST-passing escapes
        (`getattr((), "__class__")`, `type(())`, class definition) at runtime with
        no stdout. Locked in by adversarial regression tests
        (`tests/test_private_reward_sandbox.py`).
  - [ ] `P0` Harden candidate sandboxing with OS/container isolation suitable
        for untrusted third-party code in a deployed CVM.
- [ ] `P0` Add side-channel controls for reward evaluation:
      timing bands, output-size caps, timeout normalization, memory limits, and
      failure-code bucketing.
  - [x] `P0` Add local sandbox side-channel buckets: elapsed timing bands,
        stdout/stderr caps, timeout normalization, best-effort memory limits,
        and public failure-code buckets.
  - [ ] `P0` Harden deployed reward side-channel controls with CVM/container
        resource limits, timeout normalization, failure bucketing, and egress
        auditing for real evaluator/Tinker/browser paths.
- [ ] `P0` Add hidden-holdout separation:
      train/reward split, final validation split, and anti-overfitting checks
      for adaptive query attacks.
  - [x] `P0` Add a hidden-holdout split/accounting contract with train,
        reward, and final-validation partitions, public commitments, bounded
        reward-query tracking, and one-shot final-validation gating.
  - [x] `P0` Wire hidden-holdout checks into a synthetic private-reward
        environment with bounded reward feedback and final-validation gating.
  - [x] `P0` Add generic anti-overfitting guards for adaptive query attacks:
        per-candidate repeat caps, minimum unique reward candidates before
        final validation, and public aggregate repeat accounting.
  - [x] `P0` Add a bounded synthetic hidden-dataset demo command.
        Done with `synthetic-private-reward-demo`: it runs
        `SyntheticHiddenKeywordEnvironment` over a synthetic sealed dataset and
        emits optimizer view, bounded feedback, final result, transcript hash,
        leakage hash, and attestation metadata without hidden records or
        submitted candidate strings.
  - [x] `P0` Wire hidden-holdout checks into concrete private-reward
        environments and add domain-specific anti-overfitting rules.
        Done 2026-07-11: `tinker_delegate.private_reward_envs.denoising`
        (`DenoisingHoldoutEnvironment`) wires `HiddenHoldoutSet` train/reward/
        final-validation partitions into the OpenProblems-style single-cell
        denoising reward. Reward queries hit the reward partition; `finalize()`
        runs a one-shot final validation on the held-out validation partition;
        the split commitment binds the sealed per-cell counts. Generic
        anti-overfitting guards (per-candidate repeat cap, reward-query budget,
        one-shot final) plus the domain-specific rule (a candidate that worsens
        the Poisson NLL vs the depth-matched baseline is capped to `negligible`)
        are enforced inside the boundary; only a coarse `RewardBand` egresses.
        `tests/test_denoising_holdout_env.py` (11 tests) proves pooling beats
        identity, identity/sandbox-rejected/wrong-shape candidates band
        `negligible`, repeat/budget caps fail closed without raising, final
        validation is one-shot and closes reward queries, and no raw cell counts
        or exact MSE/Poisson values appear in any bounded surface. Full-scale
        real OpenProblems data (numpy) is still scored by the precomputed-matrix
        path in `environments/` and stays `[partial]` (below) pending real
        container isolation for large candidate programs.

### Third-Party Reward Evaluability (Mechanism Audit)

The central pitch problem: a buyer, sponsor, or optimizer must be able to
*evaluate the RL environment* — trust that the reward is real, honestly
computed, un-gamed, and useful for optimization — while never seeing the sealed
data. They see the env **code** and may **query the black box** within agreed
boundaries. The resolution is that they audit the **mechanism, not the data**.

This decomposes the trust problem into three axes that must not be conflated:
`trust` (is the oracle honestly computing the reward the code says, over the
data that was committed?), `leakage` (can queries reconstruct the sealed data?),
and `overfitting` (can an optimizer grind a fixed holdout into a meaningless
number *without* leaking a record?). The leakage and overfitting axes are
governed by the same noise/budget machinery; the trust axis by attestation +
commitment + calibration.

Grounding papers now in-repo: `📄/attestable-audits/paper.md` (attest the
binding `reward-code-hash + dataset-commitment → bounded result`) and
`📄/ladder/paper.md` (bound adaptive-query overfitting on a reused holdout).
The reusable-holdout / Thresholdout DP line (Dwork et al., Science 2015) is the
general form. See `PROJECT.md` "Third-Party Reward Evaluability" and
`ARCHITECTURE.md` for the design.

- [ ] `P3` Attest the reward-mechanism binding, not just the environment.
      Publish an attestation binding `HASH(reward_code) ∥ dataset_commitment ∥
      params → bounded_result` (Attestable Audits `A[AC+AD→R]` shape), so a third
      party who has read the open env code can verify *that exact code* ran over
      *that exact committed dataset*. Extends the existing
      `git SHA → docker digest → compose hash → TDX quote` chain with a
      dataset-commitment link. Reuse `sealed_dataset` manifest hashes as the
      commitment root; emit only hashes/attestation.
- [ ] `P3` Add a public canary / calibration slice per environment.
      A small **public** portion with known ground truth, committed alongside
      the sealed data, so the third party can submit known-good and known-bad
      candidates and confirm the oracle ranks them sensibly and that the private
      reward scale is anchored to a public reference. Converts "trust the data
      is representative" into something testable without exposing private rows.
      Canary scores are releasable; the private/public correlation over a batch
      is itself a bounded, releasable statistic.
- [x] `P3` Sign dataset provenance at seal time. Done 2026-07-12:
      `build_provenance(...)` assembles a bounded provenance block (source
      pipeline, upstream id, license, distribution claim, `benchmark_ref` vs. a
      named public benchmark); `seal_dataset(..., provenance=...)` commits it INTO
      the manifest before hashing, so it is covered by `manifest_hash` and the
      existing owner/witness signatures bind the claim to the exact dataset.
      `verify_dataset_provenance(manifest, *, expected_signer, expected_benchmark)`
      requires a complete block AND a valid signature (unsigned =>
      `provenance_not_signed`), optionally checks `benchmark_ref`, and tampering
      the claim after signing breaks the signature. Backward-compatible (absent
      provenance omits the key, hash unchanged). `tests/test_dataset_provenance.py`
      (10). Threaded through `verify_reward_mechanism` (aggregate + CLI
      `--expected-benchmark`/`--require-provenance` + endpoint) 2026-07-12.
      Operator CLIs added 2026-07-12: `witness-sign-dataset-manifest` (notary
      co-signs; key from env, receipt hides it) and `verify-dataset-provenance`
      (bounded receipt, non-zero exit on failure); `tests/test_dataset_provenance_cli.py`
      (5).
- [x] `P3` Add a neutral sealing witness (notary / quorum). Done 2026-07-12:
      `sealed_dataset.add_witness_signature` lets a mutually-trusted notary
      co-sign the canonical `manifest_hash` (excluded from the hash, so every
      witness signs one fixed commitment and signing never mutates it), and
      `verify_witness_quorum(manifest, *, authorized_witnesses, threshold)` counts
      DISTINCT authorized signers whose signature recovers over that hash —
      failing closed on unknown/duplicate/wrong-hash signatures and on a tampered
      manifest. Closes the "seller crafts data to favor one bidder" collusion.
      Bounded receipt (witness hashes only, never raw addresses); witnesses never
      see plaintext. Enforceable via `verify_reward_dataset_binding(...,
      witness_quorum={"authorized_witnesses": [...], "threshold": M})`
      (`dataset_witness_quorum_unmet` when unmet). `tests/test_witness_quorum.py`
      (11). Threaded through `verify_reward_mechanism` (aggregate + CLI
      `--witness`/`--witness-threshold` + endpoint `witness_quorum`) 2026-07-12.
- [ ] `P3` Upgrade `private_reward_holdout.py` to a Ladder-gated release path.
      Replace the plain train/reward/final split with the Ladder mechanism:
      release a new reward only when a candidate beats the running best by a
      statistically significant margin (parameter-free paired-t variant), giving
      the `O(log^{1/3}(kn)/n^{1/3})` leaderboard-error bound so a fixed-size
      sealed holdout supports effectively unlimited attempts while the settlement
      number stays honest. Ties into the existing reward-query budget and
      anti-overfitting guards.
      - [x] Implement the fixed-`η` Ladder mechanism as a reusable bounded gate.
            Done 2026-07-12: `tinker_delegate.ladder_release` (`LadderLeaderboard`,
            `LadderPolicy`, `LadderRelease`) implements §3 of the paper in the
            reward convention — keep the running best, advance only on a strict
            `> η` margin, quantize every released value to the `η = 1/D` grid.
            Rewards in `[0,1]` admit at most `D` genuine improvement steps, so the
            released sequence has bounded description length and leaderboard error
            grows only logarithmically in `k`. Egress is bounded by construction:
            the internal score is a float that never leaves; releases carry only
            the integer `leaderboard_step_index`/`step_denominator` + counts, so
            `to_public_dict()`/`public_manifest()` pass `assert_bounded_egress`.
            `tests/test_ladder_release.py` (12) prove quantization, monotonic best,
            the `≤ D` step cap, the `η`-margin gate, determinism, bounded egress,
            and the paper's adaptive-random-attack property (5000 adaptive
            submissions -> <40 accepted improvements — the number stays honest
            under unlimited grinding).
      - [x] Wire the Ladder gate into `DenoisingHoldoutEnvironment` so the
            reward-query path releases through the leaderboard instead of the plain
            per-candidate band. Done 2026-07-12: opt-in via `ladder_policy`; each
            reward query feeds the continuous internal MSE-improvement score
            (zeroed on Poisson-NLL worsening, matching the domain anti-overfitting
            rule) into a `LadderLeaderboard`, and `output_reducer` releases the
            running-best leaderboard band (`_ladder_band`) — monotonic
            non-decreasing, so weak-after-strong probing re-releases the best and
            cannot move the settled number. The Ladder policy is folded into
            `problem()` metadata / `environment_hash` / `leakage_hash` (the audited
            mechanism) and the bounded manifest into the `finalize()` attestation.
            `ladder_policy=None` is fully backward-compatible (all pre-existing
            denoising tests green). `tests/test_denoising_ladder_gate.py` (5).
      - [x] Wire the Ladder gate into `SyntheticHiddenKeywordEnvironment` too.
            Done 2026-07-12: same opt-in `ladder_policy`; the synthetic env's
            internal `value` is already a normalized [0,1] match fraction so it
            feeds the leaderboard directly, and the leaderboard band maps back
            through the env's own `_score_band` thresholds. Ladder policy folded
            into problem metadata / `environment_hash` / `leakage_hash` and the
            manifest into the `finalize()` attestation, exactly as denoising. This
            proves the gate generalizes across envs with different score semantics.
            `ladder_policy=None` backward-compatible (11 pre-existing synthetic
            tests green). `tests/test_synthetic_ladder_gate.py` (5). Remaining
            follow-ups: tie the `η`-grid into the reward-query budget + canary
            accounting; add the parameter-free paired-t variant.
      - [x] Add the parameter-free paired-t variant (§4). Done 2026-07-12:
            `PairedTLadderLeaderboard` maintains the previous best's per-example
            score vector and releases a new best only when a candidate's vector is
            statistically significantly above it by a one-sided paired t-test
            (running threshold `s/√n`), rounding the released mean to `1/n`.
            Deterministic (no DP noise) so it suits a TEE gate, and demonstrably
            overfitting-resistant — zero-mean noise or a positive-but-not-
            significant mean does not advance the board; a genuine uniform
            improvement does. Egress bounded: released number is
            `leaderboard_numerator`/`denominator` (small ints), passes
            `assert_bounded_egress`. `tests/test_ladder_release.py` (now 21).
            Wired into `DenoisingHoldoutEnvironment` 2026-07-12 (opt-in
            `paired_t_ladder=True`, mutually exclusive with the fixed-η
            `ladder_policy`): gates on the continuous per-cell MSE-improvement
            vector (`per_cell_mse_improvement`, zeroed on Poisson worsening),
            releases the significance-gated running-best band, folded into the
            audited surfaces + finalize manifest; backward-compatible.
            `tests/test_denoising_paired_t_gate.py` (6).
- [x] `P3` Add a Thresholdout / DP-noised reward option. Done 2026-07-12:
      `thresholdout.py` (`ThresholdoutGate`, Dwork et al. 2015) accesses the
      holdout only through a noisy-threshold DP mechanism — budget is spent only
      when a candidate diverges from the reward-partition statistic the optimizer
      already knows, so `total leakage ≤ ε × holdout-accesses` is a single stated
      bound composed through the shared `DpAccountant`. Band-preserving: the
      Laplace noise gates which partition's band to release and perturbs before
      quantization, so only a coarse band index egresses (no un-noised real);
      fails closed when the budget is exhausted. `tests/test_thresholdout.py` (11).
      (Previously deferred as "too speculative"; a principled band-preserving
      adaptation exists.) Exercised end-to-end by the `thresholdout-demo` CLI
      (`run_thresholdout_demo`; `tests/test_thresholdout_demo.py`, 5) 2026-07-12.
      Follow-up: wire into an env with a reward/holdout split (e.g. denoising
      reward vs. final-validation partitions).
- [x] `P3` Ship a third-party verification CLI (`verify-reward-mechanism`).
      Done 2026-07-12: all four checks are implemented as verifier functions and
      composed by `verify_reward_mechanism`, surfaced as the
      `verify-reward-mechanism --packet [--source ...] [--manifest] [--canary-report]
      [--expected-signer]` operator CLI (bounded nested verdict, non-zero exit on
      failure; `tests/test_verify_reward_mechanism_cli.py`, 3). Verifies (1)
      `HASH(reward_code)` matches the read source, (2) the dataset commitment
      matches the manifest + optional signer, (3) canary calibration passes, and
      (4) declared query/DP/Ladder params match what the boundary enforced.
      Bounded pass/fail + hashes only. Also surfaced as the auth-gated
      `POST /verify/reward-mechanism` endpoint (done 2026-07-12), which accepts the
      data-safe inputs (posted manifest + canary report) and excludes code-source
      binding from the HTTP surface (LFI risk — that check stays CLI-local);
      `tests/test_api_verify_reward_mechanism.py` (6).
      - [x] Point (3) — "canary calibration passes" — and the aggregate entry
            point implemented. Done 2026-07-12:
            `verify_canary_calibration(report)` re-derives each canary's outcome
            from its published bands (outcome is a pure function of observed vs
            min/max rank; INCONCLUSIVE ⟺ WITHHELD band) and confirms the claimed
            outcome + aggregate `clear`/`tripped_count` match, so a forged/hidden
            trip is caught (`canary_report_inconsistent`), a gamed oracle is
            `canary_tripped`, and an empty report is `no_canaries`.
            `verify_reward_mechanism(packet, *, source_targets, manifest,
            canary_report, expected_signer)` composes all four checks into one
            bounded nested verdict (each external check runs only when its input is
            supplied, else `skipped`; `verified` iff every run + requested external
            check passes). `tests/test_verify_reward_mechanism.py` (10). Remaining
            for the item: surface `verify_reward_mechanism` as a
            `verify-reward-mechanism` operator CLI/endpoint (all four sub-verifiers
            + aggregate are done).
      - [x] Point (2) — "the dataset commitment matches the manifest and (if
            present) the notary co-signature" — implemented. Done 2026-07-12:
            `verify_reward_dataset_binding(packet, manifest, *, expected_signer)`
            confirms the sealed run's `sealed_dataset_provenance.manifest_hash`
            commitment equals `manifest_hash(manifest)`, that the manifest itself
            verifies (`verify_manifest`, incl. owner/notary signature when
            `expected_signer` given), and that the run's declared
            `dataset_id`/`publish_ciphertext_sha256` match the manifest (so a valid
            manifest for a different dataset can't be swapped in). Fails closed
            (`missing_dataset_commitment` / `dataset_manifest_invalid` /
            `dataset_commitment_mismatch` / `dataset_provenance_mismatch`, new
            explainer reasons). The `denoising_sealed_dataset` demo now stamps the
            `manifest_hash` commitment into its provenance.
            `tests/test_reward_dataset_binding.py` (8).
      - [x] Point (1) — "`HASH(reward_code)` matches the source the third party
            read" — implemented. Done 2026-07-12:
            `verify_reward_code_binding(packet, source_targets)` recomputes
            `hash_source_files(...)` over the reward-env modules/paths the reader
            independently obtained and checks it equals the packet certificate's
            `code_hash`, binding that exact code to the attested run. Separate call
            from `verify_reward_run` (external input the packet lacks); bounded
            verdict (both operands are digests); fails closed on
            `missing_code_hash` / `code_source_unreadable` / `code_hash_mismatch`
            (new `decision_explainer` reasons). The demos already hash real source
            bytes, so a reader with the env module gets `code_binding_verified`.
            `tests/test_run_verification.py` RewardCodeBindingTest (+5).
      - [x] Point (4) — "declared params match what the boundary enforced" — is
            now enforced inside `verify_reward_run`. Done 2026-07-12:
            `_mechanism_accounting_consistent(packet)` checks the published
            holdout + Ladder manifests respect the caps in their own declared
            policy (reward-query / per-candidate / final-validation caps, the
            final-validation-closes-queries + min-unique gates, and the Ladder
            `improvement_count ≤ D` / index-in-grid / submission-cap guarantees,
            incl. paired-t numerator ≤ denominator). A packet claiming more than
            its stated policy allows is rejected `mechanism_accounting_violation`
            (a new `decision_explainer` reason). Lenient on absent fields, fails
            closed on exceeded/unparseable. Real demo packets stay `verified`;
            `tests/test_run_verification.py` (+10). Still open for the full CLI:
            (1) reward-code-hash binding, (2) dataset-commitment/notary check, and
            (3) canary calibration, then package as a standalone
            `verify-reward-mechanism` entry point.
- [ ] `P3` Document the utility/safety frontier as the negotiated contract.
      The design knobs (output granularity, DP-ε, query budget, Ladder
      threshold, holdout rotation) are simultaneously utility dials (optimizer
      signal) and safety dials (leakage + overfitting). Record that choosing the
      contract *is* choosing a point on this frontier, and map it onto the
      reserve-price / budget-cap / bounded-disclosure economics: the seller is
      selling **feedback bandwidth** about a sealed reward, priced by how much
      the buyer wants. State the residual gaps plainly: TEE hardware root
      (mitigate multi-vendor), commitment ≠ quality (canary + provenance +
      stake), and candidate-as-exfiltrator (sandbox + aggregate-only + noised
      band).

### Sealed Data At Rest (Portable Encrypted Datasets)

Reward datasets must be storable in untrusted public hosts (Hugging Face Hub,
S3, IPFS) while plaintext exists only inside the attested boundary. Design and
trust-boundary reasoning are recorded in `PROJECT.md` "Sealed Data At Rest" and
`ARCHITECTURE.md` (`[planned]` entry). The construction is envelope encryption
reusing existing primitives (`crypto.encrypt_for_tee`,
`dstack_utils.derive_storage_key`, `artifacts.zero_buffer`), not a new scheme.

- [x] `P1` Add a bounded, owner-signable dataset manifest schema:
      dataset id, task metadata, ciphertext hash/size/chunking, plaintext hash,
      per-measurement wrapped-DEK envelopes, `data_sensitivity`
      (`public_benchmark`/`private`/`phi`), storage backend reference, and
      optional owner signature. Emit only hashes/status.
      Done 2026-07-10: `tinker_delegate.sealed_dataset.build_manifest` /
      `verify_manifest` produce and check a bounded `sealed-dataset-manifest-v1`
      with exactly these fields and `raw_secret_egress=false`. Owner/reviewer
      signing is now real (2026-07-11): `sealed_dataset.sign_manifest(manifest,
      signer_private_key)` adds an `owner_signature` (Ethereum signed-message
      over the canonical `manifest_hash`, which excludes the signature fields so
      it binds every other field) plus a bounded `signer_hash`, returning a
      receipt with no private key / signer address / raw signature.
      `verify_manifest(..., expected_signer=...)` verifies the signature,
      detects any tampered signed field (`owner_signature_hash_mismatch`), and
      requires a matching signer when `expected_signer` is set. CLIs
      `sign-dataset-manifest` (signer key from env only) and
      `verify-dataset-manifest --expected-signer` complete the loop.
      `tests/test_sealed_dataset_signing.py` (10 tests) + a live CLI chain.
      Binding the signer to a governance/reviewer identity source at seal time
      remains the P3 provenance item.
- [x] `P1` Implement envelope encryption for datasets: fresh random DEK,
      chunked AES-256-GCM over the dataset bytes with per-chunk nonce and AAD
      binding `dataset_id|chunk|total`, and DEK wrapping to one or more
      attestation-bound CVM public keys via `crypto.encrypt_for_tee`. Never
      print the DEK or plaintext.
      Done 2026-07-10: `sealed_dataset.encrypt_dataset` / `decrypt_dataset`
      chunk AES-256-GCM with per-chunk nonce + dataset/index/total AAD;
      `wrap_dek` / `unwrap_dek` wrap the DEK to attestation-bound CVM keys via
      `crypto.encrypt_for_tee` / `TEEKeyPair`. Tests prove full round-trip,
      wrong-key/tamper/wrong-AAD authentication failure, multi-recipient
      unwrap, and an egress-safe manifest that never contains the DEK or
      plaintext. CLI surface and CVM-side fetch/decrypt wiring remain open.
- [x] `P1` Add an `encrypt-dataset` CLI (and `dataset-recipient-pubkey` to
      fetch/verify a CVM's attestation-bound X25519 key) that produces the
      ciphertext blob plus signed manifest with a bounded receipt.
      Done 2026-07-10 for `encrypt-dataset`: the CLI reads a plaintext file,
      envelope-encrypts to one or more `--recipient-pubkey`/`--recipient-pubkey-file`
      keys, writes the ciphertext blob + bounded manifest, and emits a bounded
      receipt (`raw_secret_egress=false`, hashes/counts only, no DEK/plaintext).
      A subprocess CLI test proves the full round-trip: encrypt → the recipient
      CVM key unwraps the DEK and decrypts back to the exact plaintext.
      `dataset-recipient-pubkey` (live attestation fetch + verify) and owner
      manifest signing remain open sub-steps.
- [x] `P1` Add pluggable storage backends (local, Hugging Face Hub, S3, https)
      behind a publish/fetch adapter interface so adding a backend does not
      touch the crypto path. HF/S3 tokens come from env only, never committed.
      Add `publish-dataset` and `fetch-decrypt-dataset` CLIs.
      Done 2026-07-11: `tinker_delegate.dataset_storage` defines a
      `StorageBackend` ABC (`ref_for`/`publish`/`fetch`) kept strictly outside
      the crypto path. `LocalStorageBackend` (real) writes/reads
      `<root>/<id>.blob` + `.manifest.json`; `HttpsFetchBackend` (real,
      fetch-only) GETs the blob/manifest by URL; `resolve_backend` returns a
      fail-closed `_UnconfiguredBackend` for `hf`/`s3` that refuses publish/fetch
      with a bounded "not configured; credentials from env only" error until a
      credentialed adapter lands. `publish_dataset()` re-verifies the manifest
      binds the blob (ciphertext hash), refuses to mutate a signed manifest, and
      stamps the resolved `storage_ref`. New CLIs: `dataset-recipient-keygen`
      (0600 X25519 private key, emits only public key + hashes),
      `publish-dataset`, and `fetch-decrypt-dataset` (fetch -> verify manifest ->
      select recipient envelope by key hash -> unwrap DEK -> decrypt with
      plaintext-hash check -> write 0600 -> zero buffer). Proven end-to-end:
      keygen -> encrypt-dataset -> publish-dataset -> fetch-decrypt-dataset
      round-trips the exact plaintext; wrong key, tampered blob, and hf/s3 all
      fail closed. `tests/test_dataset_storage.py` (14 tests) + a live CLI chain.
      Added `TEEKeyPair.from_private_key_hex` for local/dev recipient custody.
      - [ ] Add credentialed Hugging Face Hub and S3 publish/fetch adapters
            (tokens from env only) behind the same interface; until then those
            schemes stay fail-closed.
- [ ] `P1` Implement CVM-side unwrap/decrypt inside the boundary: select the
      wrapped-DEK envelope matching the CVM measurement, unwrap with the
      dstack-derived key, decrypt to the sealed data volume, verify the
      plaintext hash, and zero buffers after use. Only bounded bands egress.
      Note: the crypto path (`unwrap_dek`/`decrypt_dataset` with plaintext-hash
      verification) is real and tested. As of 2026-07-11 the fetch -> envelope
      selection (by recipient key hash) -> unwrap -> decrypt -> plaintext-hash
      verify -> buffer-zero flow is also real via
      `dataset_storage.fetch_decrypt_dataset` and the `fetch-decrypt-dataset`
      CLI, but with a *local/dev recipient key file* and a plain `--out` path.
      The remaining production work is: derive the recipient key from dstack and
      bind envelope selection to the approved CVM measurement (not a supplied
      key file), and write to the sealed data volume instead of an operator
      path. Shares the cryptographic-quote-parsing blocker below.
- [x] `P1` Add `verify-dataset-manifest` for external verification of schema,
      hashes, signature, recipient measurements, and sensitivity label without
      any plaintext access.
      Done 2026-07-10: `verify-dataset-manifest --manifest [--blob]` checks
      schema version, sensitivity label, recipient-envelope shape, chunk
      metadata, and (when the blob is supplied) the ciphertext sha256 binding,
      returning a bounded receipt and exit code. Tests cover happy path and
      tampered-ciphertext rejection. Owner-signature verification landed
      2026-07-11: `--expected-signer` requires and checks a valid owner
      signature recovering to the given Ethereum address.
- [x] `P1` Wire the OpenProblems denoising env (`environments/`) to load its
      dataset through the sealed-dataset path so the mechanism is exercised
      end-to-end; keep the `public_benchmark` label so it is not misread as a
      privacy claim.
      Done 2026-07-12: `private_reward_envs.denoising_sealed_demo.run_denoising_sealed_dataset_demo`
      serializes the denoising cells, `seal_dataset`s them (envelope-encrypted for
      an attested-CVM recipient, `data_sensitivity=public_benchmark`),
      `publish_dataset`s to a `LocalStorageBackend`, then `fetch_decrypt_dataset`
      in-boundary (manifest verify -> recipient-envelope select -> unwrap DEK ->
      AES-GCM decrypt -> plaintext-hash verify), parses the cells, zeroes the
      plaintext buffer, and only then constructs `DenoisingHoldoutEnvironment` and
      runs the bounded reward loop. Fails closed (no env run) if the plaintext
      hash is unverified. Refactored 2026-07-12 onto the reusable, env-agnostic
      `sealed_env_dataset.load_sealed_env_dataset(ref, key, parse=...)`, which
      centralizes the security-critical fetch->verify->decrypt->parse->ZERO flow
      (fail-closed on unverified plaintext, buffer zeroed even if the parser
      raises) so any future env sourcing sealed data reuses one tested path
      (`tests/test_sealed_env_dataset.py`, 4). `tests/test_denoising_sealed_demo.py` (4) prove the
      sealed fetch succeeds + is public_benchmark, the round-trip is LOSSLESS (the
      sealed-path reward bands equal the direct in-code demo's bands), no raw count
      vectors leak (forbidden-values scan), and the emitted packet passes
      `verify_reward_run` end-to-end. Exposed as the `denoising-sealed-dataset-demo`
      operator CLI (bounded JSON via `_emit_bounded_json`, +1 subprocess test); the
      full operator loop runs end-to-end — `denoising-sealed-dataset-demo | verify-reward-run`
      returns `verified:true`. Remaining production work is the same shared
      blocker as the sealed store: dstack-derived recipient key bound to an
      approved CVM measurement + write to the sealed data volume (needs
      cryptographic TDX quote parsing).
- [ ] `P0` Do not treat the sealed dataset store as production-private until
      cryptographic TDX quote parsing binds the unwrap key to an approved
      measurement (shared blocker with the quote-verifier work). Until then it
      stays `[partial]` and inherits the attestation + compose-approval chain.

- [x] `P1` Implement a toy `private_reward_envs/` package with:
      environment base class, reward evaluator base class, bounded reducer,
      transcript logger, sandbox runner, and tests.
      Done 2026-07-12 (completing the last component). Component map:
      environment base class = `private_reward.PrivateRewardEnvironment` (ABC:
      `optimizer_view`/`evaluate`/`finalize`/`attest`); reward evaluator base =
      its abstract `reward()` (exact `InternalReward` stays internal); bounded
      reducer = `output_reducer` -> `BoundedFeedback` guarded by
      `assert_bounded_egress`; sandbox runner = `private_reward_sandbox`
      (`PythonCandidateSandbox`, AST preflight + `-S` restricted subprocess) and
      `evaluator_sandbox` (rlimits); the concrete envs live under
      `private_reward_envs/` (synthetic/denoising/bio_assay). The missing piece —
      a standalone tamper-evident transcript logger — is now
      `tinker_delegate.transcript_log.TranscriptLogger`: it appends one bounded
      event at a time and binds each entry to the previous via
      `chain_hash = H(prev || event_hash || index)` (domain-separated genesis), so
      the log is append-only — insert/delete/reorder breaks the chain from that
      point. `verify_chain` recomputes it; `to_public_dict` is hashes/counts only
      and passes `assert_bounded_egress`. It complements the whole-set Merkle
      `reward_transcript` with an ordered, streaming-verifiable chain.
      `tests/test_transcript_log.py` (10) prove chaining, determinism,
      order-sensitivity, tamper/delete/reorder detection, and bounded egress.
      Wired live 2026-07-12: `PrivateRewardEnvironment` now drives the chain from
      its query loop — every accepted or rejected query appends to an internal
      `TranscriptLogger` via a centralized `_append_record`, and the head is
      exposed as `transcript_chain_head` (+ `verify_transcript_chain()`) and
      published in `EnvironmentAttestation` alongside the flat `transcript_hash`.
      So the attested output now carries both the whole-set hash and an
      append-only chain head a verifier can walk. `tests/test_private_reward.py`
      adds live-drive + attestation, determinism, and rejection-also-chains tests
      (19 in that file); the 66-test env/oracle/demo/reproducibility set stays
      green with the new attestation field. Bound into the commitment 2026-07-12:
      `RewardTranscriptCommitment` gains a `transcript_chain_head` field (folded
      into `commitment_hash`), so a single published commitment now ties the
      per-round Merkle root + env config hash + final result hash + quote + chain
      event + the env's append-only query-chain head. The `bio_assay_program_qc`
      demo passes `env.transcript_chain_head`; tests prove the head is bound and
      changes the commitment hash while leaving the Merkle root unchanged. All
      three private-reward demos now emit it 2026-07-12: `synthetic_demo` and
      `denoising_demo` also return a `reward_transcript_commitment` (bound to
      env hash + final result hash + chain head) via
      `RewardTranscript.from_round_dicts` / `certified_public_export`; their demo
      tests assert a 64-hex root and chain head with no sealed-value leak.
      Bound into the reproducibility certificate 2026-07-12: `certify_loop_run`
      (default `bind_transcript=True`) folds the transcript `commitment_hash` into
      the certificate's `certificate_hash`, so one verified certificate covers
      config + data + code + result + quote + the per-round transcript;
      `verify_reproducibility_certificate` recomputes the binding. The
      `bio_assay_program_qc` demo certificate now carries and binds its
      transcript commitment (`tests/test_reproducibility.py` +1,
      `tests/test_bio_assay_program_demo.py` binding assertion).
      One-call verifier added 2026-07-12: `run_verification.verify_reward_run(packet)`
      re-checks the whole chain from the bounded public bytes alone — certificate
      hash recomputes, transcript commitment hash recomputes, and the certificate's
      bound `transcript_commitment_hash` equals the commitment's own hash —
      fail-closed with a `reason_code` on any missing/mismatched/broken-binding
      piece (`RewardTranscriptCommitment.from_public_dict` enables the recompute).
      `tests/test_run_verification.py` (6) verify a real demo packet and reject
      tampered-certificate, tampered-root, broken-binding, and missing-artifact
      cases. Strengthened 2026-07-12: it now also cross-checks the (verified,
      mutually-bound) certificate + commitment against the REST of the packet —
      the packet's own `final_result` transcript hash and `attestation`
      env-hash/chain-head, and the cert's data/result hashes — so a valid
      cert+commitment from one run cannot be spliced onto another run's body
      (`packet_inconsistent`; `tests/test_run_verification.py` +1). It also
      recomputes the Merkle root over the packet's own per-round `feedback` and
      checks it equals the committed `transcript_root` (and `round_count`), so a
      tampered or dropped round record with an otherwise-valid commitment is
      caught (`tests/test_run_verification.py` +2). And when the attestation
      carries a DP budget, `dp_status` is checked for internal consistency
      (`remaining == max - spent`, `exhausted` matches the epsilon ledger), so a
      tampered privacy claim is caught (`tests/test_dp_bounded_demo.py` +1).
      Independent leakage bound added 2026-07-12: the verifier now also runs
      `assert_bounded_egress` over the packet's per-round `feedback` (the
      sealed-data-derived surface), so a packet that smuggles a float reward,
      gradient array, or sealed blob into a round record is rejected
      `packet_leaks` even if every hash still binds — "verified" now means both
      cryptographically consistent AND leakage-safe. Public config floats
      (holdout split fractions, DP budget) live under attestation/optimizer_view
      and are excluded (`tests/test_run_verification.py` +3: real feedback
      bounded, smuggled-float rejected with repaired Merkle root, smuggled-gradient
      rejected). Surfaced as the `verify-reward-run --packet <json>` operator CLI
      (emits the bounded verdict, exits non-zero on failure;
      `tests/test_verify_reward_run_cli.py`, 2) and the auth-gated
      `POST /verify/reward-run` operator API endpoint (posts a packet, returns the
      bounded verdict; `tests/test_api_verify_reward_run.py`, 4). All FOUR
      private-reward demos
      (synthetic/denoising/bio-assay-program/dp-bounded) now emit a transcript-bound
      `reproducibility_certificate`, so `verify-reward-run` verifies any of them
      uniformly end-to-end (`tests/test_run_verification.py`). The commitment
      also flows into settlement: `run_diligence_flow` / `run_bio_diligence_flow`
      accept an optional `reward_transcript_commitment` that is recorded on every
      `DiligenceFlowReceipt` and bound into `flow_hash`, tying the settlement
      outcome to the run's proof-carrying transcript (`tests/test_diligence_flow.py`
      +1). Superseded on-chain note (2026-07-13): reward-transcript commitments
      remain valid private-run/bounded-certificate evidence, but were removed
      from `submitResult`, its CLI, and the chain receipt. Allowing an evaluator
      or caller to choose opaque commitment material made escrow `resultHash`
      non-canonical. The contract now derives the only production result hash
      from public policy fields, while reward-run verification stays off-chain.
      Reward-loop side integration-tested end to end
      2026-07-12 (`tests/test_reward_loop_pipeline_integration.py`): clear canary
      pre-screen -> `run_private_reward_loop` with a DP budget attached (swappable
      HillClimb optimizer) -> `certify_loop_run` -> `verify_reproducibility_certificate`,
      asserting `dp_status` in the bounded attestation, no raw egress in the
      certified public export, and transcript folded into the cert; a companion
      case proves a tripped canary fails the run closed before optimizing
      (CANARY_TRIPPED, zero rewarded rounds) — RLVR counterpart to the bio
      pipeline integration test.
- [ ] `P1` Implement a TTT-Discover-style environment adapter.
      Candidate code is evaluated against private data in the TEE; optimization
      method can be RL, TTT, evolutionary search, or an LLM loop.
      - [x] Package the first env in the standard prime-rl/verifiers v0 format
            so it is trainer-agnostic and easy to extend. Done 2026-07-10:
            `environments/openproblems_denoising/` exposes
            `load_environment(**env_args) -> vf.Environment` (verifiers v0,
            prime-rl-native, reachable from OpenEnv via `vf.OpenEnvEnv`) with a
            framework-free numpy core, optional `data`/`rl` extras,
            installable `pyproject.toml`, and `environments/README.md`
            documenting the extensible layout for adding more envs. `verifiers`
            is imported lazily so the core stays offline-testable.
      - [x] Wire real candidate-program execution through the existing
            candidate sandbox (`private_reward_sandbox`) so a generated
            denoising program, not just a precomputed matrix, is scored inside
            the boundary. Optimizer swap (RL/TTT/evolution/LLM) rides on top.
            Done 2026-07-11: `DenoisingHoldoutEnvironment` runs each candidate
            (a UTF-8 Python program defining `denoise(train)`) through
            `PythonCandidateSandbox`. The environment embeds only the relevant
            holdout partition's train matrix into a harness, runs it under the
            sandbox's `-S` restricted namespace (`math`/`random` only, no I/O),
            parses the denoised matrix from bounded/sentinel-delimited stdout,
            and scores it against the held-out test counts inside the boundary.
            Sandbox failures (banned import, timeout, syntax, wrong shape,
            truncated output) fail closed to `negligible`. This is a toy-scale
            proof: numpy is unavailable in the sandbox, so only small matrices
            within the source/stdout caps run here; a generated (not
            precomputed) program is nonetheless scored end-to-end. The
            OpenProblems `environments/` numpy path for full-scale data remains
            the `[partial]` precomputed-matrix route.
      - [ ] Run the env end-to-end under prime-rl or `vf-eval` and record a
            bounded rollout receipt. (Blocked: `verifiers`/`prime-rl` not
            installed here — heavy stack.)
            - [x] Offline leakage-bound verification of the trainer-facing surface
                  done 2026-07-12: the pieces `load_environment` wires up — the
                  reward func `bounded_denoising_reward` (called each rollout) and
                  the dataset rows `_build_rows` — are pure and tested WITHOUT
                  verifiers. `tests/test_bounded_reward_egress.py` (4) prove the RL
                  path keeps the private-reward contract: the reward returns only a
                  quantized band scalar, records only the bounded band on rollout
                  `state` (no exact mse/poisson, no raw counts), and dataset rows
                  carry only the public problem + split handle (no raw matrices).
                  Fail-closed robustness added 2026-07-12: a malformed/adversarial
                  completion (bad shape, non-numeric, garbage JSON) now earns the
                  NEGLIGIBLE band instead of raising — matching the private-reward
                  contract so a bad candidate never crashes a rollout or leaks an
                  error body; an unavailable dataset (infra, not a bad candidate)
                  still propagates. `test_bounded_reward_egress.py` now 6 tests.
                  Remaining is only the actual trainer run under the heavy stack.
- [x] `P1` Implement a single-cell denoising environment inspired by
      TTT-Discover's biology task.
      Start with public/synthetic OpenProblems-like data, MSE/Poisson-style
      rewards, hidden holdout, and bounded final score bands.
      Done 2026-07-10: `environments/openproblems_denoising` grabs the REAL
      OpenProblems v1 denoising datasets used by TTT-Discover (pancreas train,
      held-out `tenx_1k_pbmc`) via a reproducible md5-verified fetch
      (`datasets.json` + `fetch_datasets.py`, data gitignored, not committed),
      computes the real log-normalized MSE gated by the Poisson constraint
      inside the boundary, and returns only a coarse `RewardBand` /
      quantized scalar banded by improvement over the depth-matched baseline.
      Proven on the real PBMC h5ad (1087 cells x 15098 genes) via an ephemeral
      anndata install: identity and per-gene-mean denoisers correctly band
      `negligible` (trivial methods do not earn credit), and the
      verifiers-style reward func records only the band on state. Offline
      core tests pass with numpy only. Hidden-holdout wiring, candidate-program
      execution, and a real trainer run remain open (above).
- [x] `P1` Add reward-oracle proof tests:
      no direct data reads, no exact reward egress in public mode, query budget
      enforced, sandbox egress capped, transcript hash stable.
      Done 2026-07-11: `tests/test_reward_oracle_proofs.py` (13 tests) asserts
      all five invariants against BOTH concrete environments (synthetic keyword
      + denoising holdout): (1) sealed record payloads / raw cell counts never
      appear in optimizer view, feedback, final result, or attestation; (2)
      `reward_precision_bits == 0` in public feedback modes, the exact
      `InternalReward` cannot be pulled under the default external optimizer
      policy (`internal_reward_for_optimizer()` raises `PermissionError`), and
      public feedback dicts expose only a bounded key whitelist with no
      `value`/`metrics`/`mse` keys; (3) exceeding the query budget returns a
      bounded `BUDGET_EXHAUSTED` decision with a `withheld` band and never
      raises; (4) sandbox stdout is truncated to the policy cap and
      huge-output / banned-I/O (`open`, `import socket`, `__import__('os')`)
      candidates fail closed to `negligible` with no marker leak; (5) identical
      candidate sequences yield identical transcript/leakage/environment hashes
      and a new query changes the transcript hash.
- [x] `P1` Add optional differential-privacy accounting for individual-level
      bio data.
      If rewards are released over real individual data, track epsilon/delta or
      explicitly mark the environment as non-DP and not PHI-safe.
      Done 2026-07-12: `tinker_delegate.dp_accounting.DpAccountant` gives the
      `bio_validation.differential_privacy_marked` flag real substance. In `DP`
      mode it tracks a cumulative `(epsilon, delta)` budget across reward releases
      by basic (sequential) composition — the safe bound that never *under*-counts
      — and `charge(DpParams)` is fail-closed: an over-budget release is denied
      (`dp_budget_exhausted`) and mutates nothing, while a fitting one advances
      `spent_epsilon`/`spent_delta`. In `NON_DP` mode there is no privacy claim —
      releases are always admitted but every record is stamped `phi_safe=False`,
      so nothing pretends individual-data releases are private when they are not
      (only a DP-tracked accountant reports `phi_safe=True`). `snapshot()` reports
      state without charging; `would_exceed()` predicts denial. The bounded
      `DpChargeResult.to_public_dict()` carries only DP parameters/counts/flags
      (epsilon/delta are public DP config, not reward values). `DpParams`
      validates epsilon>0 and delta in [0,1); DP mode requires a positive budget.
      `tests/test_dp_accounting.py` (13) prove composition, fail-closed
      no-mutation on over-budget, delta binding, non-DP never-PHI-safe, and the
      bounded record. Fixed 2026-07-12 (self-review): a pure-epsilon-DP
      accountant (`max_delta=0`, a common config) spuriously reported
      `exhausted=True`/`snapshot().allowed=False` on a fresh budget because
      `exhausted` used `spent_delta >= max_delta` (0>=0). Corrected so epsilon is
      the binding global budget (a delta=0 release always fits while epsilon has
      headroom; per-charge delta feasibility stays in `would_exceed`), with a
      regression test. Wired 2026-07-12: `evaluate_bio_release` accepts an optional
      `dp_charge: DpChargeResult`; for individual-level data a live charge takes
      precedence over the asserted boolean — release proceeds only if the charge
      is admitted AND `phi_safe` (DP mode), otherwise HOLD /
      `individual_level_data_dp_<reason>` with the bounded DP accounting recorded
      on the receipt schema. A denied/over-budget or NON_DP charge holds even when
      `differential_privacy_marked=True`; the legacy boolean remains the fallback
      when no charge is supplied. `tests/test_bio_validation.py` adds live-charge
      release, exhausted-charge hold, and non-DP hold (13 in that file). Wired
      into the reward loop 2026-07-12:
      `PrivateRewardEnvironment.set_dp_budget(accountant, params_per_query)`
      charges the DP accountant per accepted reward query (computing the reward
      reads the sealed individual-level data), and once the epsilon budget is
      exhausted `evaluate` fails closed with a `BUDGET_EXHAUSTED` / `WITHHELD`
      release — privacy-budget-bounded reward release, real end-to-end and
      backward compatible (off by default). `tests/test_private_reward_dp_gate.py`
      (4) prove the DP budget binds before the query budget, no-DP is unchanged,
      no reward leaks when exhausted, and the bounded `dp_status` (mode/phi_safe/
      spent+max epsilon-delta/counts) is recorded in `EnvironmentAttestation` when
      a DP budget is configured (conditional key: non-DP attestations are
      byte-identical to before, so the 66-test env/oracle/demo set stays green).
      Showcased 2026-07-12 by the `dp-bounded-reward-demo` CLI
      (`private_reward_envs.dp_bounded_demo`): runs the synthetic env with a DP
      budget, releases a band for the first queries then fails closed
      (`budget_exhausted`/`withheld`) once epsilon is spent, and emits the bounded
      packet + attested `dp_status` + reward-transcript commitment
      (`tests/test_dp_bounded_demo.py`, 5, incl. a CLI subprocess run). Also fixed
      `DpChargeResult.to_public_dict` to round epsilon/delta (float-subtraction
      noise like `1.0-0.8=0.199999...96` would otherwise render as a long-digit
      run and trip the CLI bounded-output check).
- [x] `P1` Add final-solution disclosure policy.
      Candidate code may be public only if it cannot reconstruct private data
      and passes biosecurity/re-id checks; otherwise release only a hash,
      score band, or escrowed artifact.
      Done 2026-07-12: `tinker_delegate.disclosure_policy.decide_disclosure`
      folds four fail-closed signals into one bounded `DisclosureDecision` over a
      severity ladder `BLOCKED > HASH_ONLY > ESCROW > PUBLIC` (most restrictive
      wins): (1) base posture is `ESCROW` — sealed, releasable only under
      separate authorization — unless the caller passes `allow_public`; (2) a
      reconstruction screen downgrades to `HASH_ONLY` when the candidate embeds
      secret-shaped material (shared `redact_text`), a long base64/hex blob, or
      is non-text; (3) the re-id screen (`bio_reid.ReidAssessment`) caps at
      `HASH_ONLY` on HIGH and `ESCROW` on MEDIUM/withheld; (4) the dual-use
      screen (`bio_dual_use.DualUseAssessment`) forces `BLOCKED` on PROHIBITED and
      caps at `ESCROW` on REVIEW. The code path enforces it —
      `disclosable_payload()` returns the raw candidate bytes only when the mode
      is `PUBLIC`; otherwise `None`. The decision dict is bounded (mode + reasons
      + candidate hash + score band; passes `assert_bounded_egress`).
      `tests/test_disclosure_policy.py` (12) prove public-with-permission,
      escrow-by-default, each downgrade, most-restrictive-wins across combined
      signals, and bounded egress. Wired 2026-07-12: `run_diligence_flow` /
      `run_bio_diligence_flow` accept an optional `disclosure_candidate` (winning
      solution bytes) + `allow_public_disclosure`; after the review + stage
      disclosure gates pass and before settlement, the disclosure decision is
      computed (reusing the flow's own `dual_use`/`reid`) and recorded on the
      `DiligenceFlowReceipt` (`disclosure` field + `flow_hash`). A `BLOCKED`
      decision holds the flow (`disclosure_blocked`) before any payout;
      ESCROW/HASH_ONLY still settle but the release mode is on the receipt.
      `decide_disclosure` now treats a missing `dual_use` as fail-closed
      (`dual_use_unknown`, cap ESCROW). `tests/test_diligence_flow.py` (+2) and
      `tests/test_diligence_flow_bio.py` (+3) prove blocked-holds, public-settles,
      escrow-by-default, and reconstruction-downgrade-still-settles. ESCROW made
      physical 2026-07-12: `tinker_delegate.solution_escrow.SolutionEscrowStore`
      seals an ESCROW-mode winning candidate under a per-escrow HKDF-SHA256 key
      (from a TEE root key) and releases the plaintext only to a caller
      presenting the authorization secret committed at seal time (its hash is
      bound as AES-GCM AAD, so a wrong secret fails authentication). Fail-closed:
      only an ESCROW decision may be sealed (PUBLIC releases plaintext directly;
      HASH_ONLY/BLOCKED retain nothing), double-seal/unknown-release/wrong-auth
      all raise, and receipts/manifests are bounded (hashes/mode only).
      `tests/test_solution_escrow.py` (9) prove the roundtrip, wrong-auth
      fail-closed, mode-gating, per-escrow key isolation, bounded egress, and a
      real `decide_disclosure` ESCROW decision driving a physical seal. Remaining:
      emit the decision on-chain once the settlement path is live.
- [ ] `P2` Add leaderboard-overfitting defenses:
      canary candidates, held-out final verifier, query throttling, adaptive
      budget cuts, and expert review for surprising high scores.
      - [x] Canary candidates + surprising-score review. Done 2026-07-12:
            `tinker_delegate.canary` screens a reward oracle with known-answer
            probes — a `CanaryCandidate` carries a `[min_band, max_band]` window,
            and `CanarySentinel.screen(env)` evaluates each through the env's own
            bounded `evaluate` (so it shares the holdout accounting), tripping
            `TRIPPED_HIGH` when known-junk scores above its ceiling (oracle
            leaking / gamed) or `TRIPPED_LOW` when known-strong collapses below
            its floor (oracle zeroed). Budget exhaustion / withheld bands are
            `INCONCLUSIVE`, never a false trip. `assert_clear` fails closed on any
            trip; the `CanaryReport` is bounded (per-canary band + payload *hash*,
            no payloads) and passes `assert_bounded_egress`. `flag_surprising_score`
            routes bands at/above a review threshold (default HIGH) to expert
            review instead of auto-settling. `tests/test_canary.py` (11) prove
            pass/trip-high/trip-low/inconclusive, fail-closed, bounded egress,
            and the flag ladder. Wired into the reward loop 2026-07-12:
            `run_private_reward_loop(..., canary_report=...)` refuses to start and
            returns a zero-round `CANARY_TRIPPED` outcome (no budget spent) when a
            pre-screen report — produced by screening a FRESH env so it doesn't
            consume the run's budget — is not clear
            (`tests/test_private_reward_loop.py` +2).
      - [x] Held-out final verifier + query throttling already exist: the
            `HiddenHoldoutSet` one-shot final-validation gate and the
            per-candidate repeat cap / reward-query budget (see the hidden-holdout
            separation item above).
      - [ ] `Blocked (deploy)` Adaptive budget cuts on suspicious query patterns
            and a wired expert-review queue for flagged high scores, exercised in
            a deployed CVM with a real reviewer path.
- [x] `P2` Add proof-carrying reward transcripts:
      transcript Merkle root, environment hash, candidate hash, reward band,
      final result hash, quote, and chain event.
      Done 2026-07-12: `tinker_delegate.reward_transcript` commits the loop's
      bounded per-round records (`RoundRecord.to_public_dict` — candidate hash,
      decision, reward band) into a domain-separated Merkle tree (leaf `0x00` /
      node `0x01` prefixes to block leaf/node second-preimage confusion) and
      binds the root into one `RewardTranscriptCommitment` alongside the
      environment hash, the loop's final result hash, the TDX quote hash, and an
      optional bounded chain-event hash.
      Merkle malleability audited 2026-07-12: the tree's duplicate-last-node
      padding is malleable across leaf-list lengths (CVE-2012-2459 — `[A,B,C]` and
      `[A,B,C,C]` share a root; same-length lists cannot collide without a SHA-256
      collision). Confirmed fully mitigated by the `round_count` binding:
      `verify_reward_run` rejects malleated (same-root, +1-length) feedback
      `packet_inconsistent`. Made the implicit safety argument explicit — documented
      in the `merkle_root` docstring as a caller guard-rail and pinned by tests
      (`test_reward_transcript` +1 primitive property, `test_run_verification` +1
      end-to-end mitigation).
      `RewardTranscript.prove(round_index)`
      yields a `RewardInclusionProof` (leaf hash + audit path) so an auditor,
      given only the commitment plus one proof, can verify a single round belongs
      to the attested run — and *which* run — while every other round and all raw
      values stay sealed. `verify_round_in_commitment` checks the proof against
      the commitment root; both public dicts are hashes/counts only and pass
      `assert_bounded_egress`. `tests/test_reward_transcript.py` (12) prove
      deterministic/order-sensitive roots, inclusion for every index incl. odd
      counts, tamper/forged-leaf and wrong-root rejection, empty-transcript root,
      and bounded egress. Emitted 2026-07-12: `run_bio_assay_program_reward_demo`
      now returns a `reward_transcript_commitment` (via
      `RewardTranscript.from_round_dicts` over the bounded per-candidate
      feedback, bound to the environment hash and final result hash); a demo test
      recomputes the root from the emitted feedback and verifies an inclusion
      proof for every candidate against it (`tests/test_bio_assay_program_demo.py`,
      8). On-chain binding added 2026-07-12 (see the reproducibility-certificate
      entry above) was superseded 2026-07-13: transcript commitments remain in
      the private reward/certificate flow only. They are deliberately absent
      from the production `submitResult` ABI and canonical escrow result hash.

### Define The Bio Validation Target

The seven `P0` definitions below are recorded in `docs/BIO_VALIDATION.md` and,
where enforceable, made real in
`⚙️/tinker-delegate/tinker_delegate/bio_validation.py` (fail-closed release
gate, bounded result schema, forbidden-output screen) with
`tests/test_bio_validation.py`. Done 2026-07-10.

- [x] `P0` Treat `TTT` as method-agnostic in product docs.
      The central primitive is private verified reward. Optimization can be
      reinforcement learning, test-time training, evolutionary search, or an LLM
      loop.
      Done: `docs/BIO_VALIDATION.md` "Method Is Not The Claim" states the
      optimizer is swappable and the reward oracle is the claim; nothing in the
      code gate depends on the optimizer.
- [x] `P0` Define the first safe bio-validation use case.
      Candidates:
      synthetic assay QC, de-identified expression classifier, method validation,
      benchmark reproducibility, private reward for computational bio code, or
      non-dual-use model utility scoring.
      Done: first use case is synthetic assay QC scoring over synthetic/public
      toy data, with the listed same-safety-class alternatives.
- [x] `P0` Define what data is allowed in the first demo.
      Prefer synthetic or public toy data until the policy and reviewer path are
      real.
      Done: synthetic/public toy data only; the gate holds fail-closed on
      `individual_level_data` without a DP marking.
- [x] `P0` Define forbidden outputs for bio:
      wetlab protocol details, pathogen enhancement guidance, de novo harmful
      design, identifiable patient-level outputs, raw records, model weights,
      raw samples, and reconstruction-prone statistics.
      Done and enforced: `_FORBIDDEN_PATTERNS` screens every free-text field;
      any match denies with `safety_band=blocked` and routes to
      biosecurity review; free-text is hashed, never returned.
- [x] `P0` Define the bounded result schema:
      score band, confidence band, safety band, utility band, methodology class,
      compute cost, data-quality flags, and result hash.
      Done: `BioReleaseReceipt.result_schema` carries exactly these bounded
      fields plus a per-field screen summary; bands are `withheld` on any
      non-release decision.
- [x] `P0` Define benchmark tasks:
      baseline model, adapted model, held-out evaluation, statistical confidence,
      and failure modes.
      Done as a definition in `docs/BIO_VALIDATION.md`; a real evaluator that
      populates these bands remains a `[planned]` P1 below.
- [x] `P0` Define when results must hold for human review instead of releasing.
      Done and enforced: release is the exception. The gate holds on any missing
      readiness capability or non-DP individual-level data, and denies on
      forbidden output; most-protective check wins.
- [ ] `P1` Add a `bio_validation/` module or package with:
      data loaders, validators, risk screens, evaluator registry, and result
      schema.
      Progress 2026-07-11: nearly all sub-parts are now real as cooperating
      modules — result schema + risk screens (`bio_validation` release gate +
      forbidden-output screen, `bio_dual_use`, `bio_reid`, `bio_data_quality`),
      validators (`bio_evaluators.SyntheticAssay`, `bio_data_quality`
      profile/policy validation), a reconstruction-safe methodology summarizer
      (`bio_methodology`), and an evaluator registry (`bio_registry`:
      `default_registry()` lists shipped use cases and returns their fail-closed
      runners; duplicate/unknown ids are rejected; metadata is bounded).
      Remaining: promote the cooperating modules into a `bio_validation/`
      package namespace and add real (still synthetic/public) data loaders.
- [x] `P1` Implement a deterministic stub bio evaluator over synthetic data.
      Done 2026-07-11: `tinker_delegate.bio_evaluators` implements the first
      concrete evaluator for the `synthetic_assay_qc` use case. It computes the
      standard Z'-factor screening-assay quality score plus confidence/utility
      bands and public data-quality flags (`control_overlap`, `low_replicates`,
      `high_background_cv`, `few_control_wells`) from synthetic toy control
      readings, and returns a bounded `BioResultCandidate` — the exact Z'-factor
      and control statistics stay internal (no exact-value egress). It is
      deterministic (no RNG/network/Tinker), synthetic-only, and fail-closed:
      `run_synthetic_assay_qc` feeds the result through `evaluate_bio_release`,
      which holds unless every readiness capability is enabled. Forbidden
      free-text (e.g. wetlab/reagent) still denies via the gate, and free-text is
      never echoed. `tests/test_bio_evaluators.py` (14 tests) cover Z' banding,
      fail-closed hold, full-readiness release, forbidden-text deny, no-echo, and
      determinism.
- [ ] `P1` Implement a real SFT/LoRA evaluator using Tinker on a toy non-sensitive
      dataset.
- [ ] `P1` Implement the first TTT/RL loop using Tinker docs in
      `📄/thinking-machines/rl/`.
- [x] `P1` Implement an RLVR-style loop where a candidate computational-bio
      program receives reward from a private TEE-held verifier.
      The loop must work even if the optimizer is swapped between RL, TTT,
      evolutionary search, and an LLM repair loop.
      Done 2026-07-11: `tinker_delegate.private_reward_loop.run_private_reward_loop`
      drives any `PrivateRewardEnvironment` (the private TEE-held verifier) with
      a swappable `LoopOptimizer`. The leakage bound is structural — the
      optimizer only ever receives the public `optimizer_view()` and per-round
      `BoundedFeedback` (decision + score band + hashes); it never sees the exact
      `InternalReward`, sealed data, or reward-derived gradients. The loop
      fail-closed refuses an environment whose optimizer policy would hand out
      exact rewards unless the caller opts into an in-boundary optimizer
      (`allow_internal_optimizer=True` + INTERNAL_TEE/ATTESTED_REMOTE location).
      Four interchangeable strategies ship to prove swappability against the
      same env + `CandidateSource`: `RandomSearchOptimizer` (baseline, ignores
      feedback), `HillClimbOptimizer` (band-guided greedy single-best local
      search, stands in for RL), `EvolutionaryOptimizer` (a real (mu+lambda)
      population search that keeps an elite by band, breeds by mutating a
      top-half parent, dedups so it never wastes the bounded per-candidate
      query budget, and halts when the reachable space is exhausted), and
      `LLMRepairOptimizer` (deterministic revise-on-weak-band stand-in for an
      LLM repair loop). Output is a bounded `LoopOutcome`: round count, best
      band, band histogram, stop reason, transcript hash, and the env's own
      `BoundedResult`/attestation — no candidate payloads or raw values
      (`raw_secret_egress=false`). `tests/test_private_reward_loop.py` (17
      tests) prove all four optimizers run bounded, seed-sweeping strategies
      reach the target band, the evolutionary optimizer breeds past its seeds to
      the winning candidate and halts fail-closed when the space is exhausted,
      the public output leaks no keyword/payload/raw reward, the exact-reward
      leakage guard blocks external optimizers and honors the in-boundary
      opt-in, budget exhaustion and optimizer-halt stop reasons, and loop
      determinism. Swappable-optimizer claim proven optimizer-AGNOSTIC end-to-end
      2026-07-12: a parametrized test runs all four optimizers through the same env
      and asserts each produces a run whose reproducibility certificate
      independently verifies (transcript-bound) and whose certified export leaks no
      sealed record — the whole verification chain holds regardless of which
      optimizer ran.
      - [x] Bind the loop to a concrete bio candidate space + sealed verifier.
            Done 2026-07-11:
            `tinker_delegate.private_reward_envs.bio_assay.BioAssayRewardEnvironment`
            is the first end-to-end private reward environment the loop drives.
            Candidates are canonical JSON synthetic assay-QC configs (numeric
            controls only — unknown keys/strings rejected, so no dual-use text can
            ride in); the private, TEE-held verifier is the Z'-factor
            screening-assay quality metric (reused from `bio_evaluators`). The
            exact Z' is the internal reward and is discarded; only a coarse
            `RewardBand` leaves, and `internal_reward_for_optimizer()` stays denied
            under the default external policy. `BioAssayCandidateSource` provides a
            deterministic domain search space (tighten spread / widen window) so
            all three optimizers drive it and hill-climb reaches a HIGH band.
            `run_bio_assay_reward_demo()` is a bounded, deterministic demo.
            `tests/test_bio_assay_reward_env.py` (8 tests) prove clean-vs-overlap
            banding, malformed/dual-use candidate rejection, no raw-measurement or
            Z' egress, exact-reward denial, end-to-end drive by all three
            optimizers, hill-climb convergence, and demo determinism.
      - [x] Drive candidate *programs* (not static configs) through the sandbox
            against the bio verifier. Done 2026-07-11:
            `tinker_delegate.private_reward_envs.bio_assay_program.BioAssayProgramEnvironment`
            scores a candidate Python `process(positive_wells, negative_wells)`
            QC program by the Z'-factor of the controls it selects from sealed raw
            plate readings. The program runs in `PythonCandidateSandbox`
            (math/random only, no I/O), reusing the `DenoisingHoldoutEnvironment`
            program-execution pattern. Anti-fabrication guard: every returned
            value must be a multiset member of the corresponding sealed wells, so
            a program may drop outliers but cannot fabricate values or swap
            positives into the negative set to game Z' — fabrication/swap/too-few
            controls/banned-I/O all fail closed to NEGLIGIBLE. The exact Z' and raw
            readings never egress. `BioAssayProgramCandidateSource` provides an
            interchangeable program library (passthrough / drop-extremes / MAD
            filter) so all three optimizers drive it and hill-climb selects a
            robust outlier-removal program to a HIGH band.
            `tests/test_bio_assay_program_env.py` (10 tests) prove outlier-removal
            beats passthrough, fabrication/swap/underfilled/banned-I/O fail closed,
            no raw-reading or Z' egress, end-to-end drive by all three optimizers,
            hill-climb convergence, and demo determinism.
      - [x] Expose the bio program reward environment through the bounded
            operator CLI. Done 2026-07-11: `bio-assay-qc-reward-demo` runs the
            environment over a candidate QC-program library against sealed plate
            readings and emits only bounded per-candidate reward bands, final
            result, and attestation (`raw_secret_egress=false`); the CLI leakage
            guard enforces that the sealed well readings never appear in the
            output. `run_bio_assay_program_reward_demo` +
            `bio_assay_program_demo_forbidden_values` in
            `private_reward_envs/bio_assay_program_demo.py`, mirroring
            `denoising-private-reward-demo`. Tests:
            `tests/test_bio_assay_program_demo.py` (4) and a CLI subprocess test
            in `tests/test_cli_bounded_outputs.py`.
      Remaining: a real optimizer (Tinker RL/TTT) once the Tinker execution
      blocker clears, and production container isolation for hostile candidate
      programs (the local AST/subprocess sandbox is a dev guardrail, not the
      production answer).
- [x] `P1` Add data-quality checks:
      schema validation, missingness, leakage, duplicates, class imbalance,
      train/test contamination, and sample-size limits.
      Done 2026-07-11: `tinker_delegate.bio_data_quality.assess_data_quality`
      deterministically checks a bounded `DatasetProfile` (counts only, no
      records) for schema mismatch, insufficient samples, train/test
      contamination (leakage), excessive missingness, excessive duplicates,
      class imbalance, and underpopulated classes. Validity-invalidating flags
      (`insufficient_samples`, `train_test_contamination`, `schema_mismatch`)
      set `blocks_release=true` and a POOR band; other flags degrade the band
      (FAIR for one, POOR for two+). Output is bounded (band/flags/boolean/hash,
      `raw_secret_egress=false`, no raw counts). `evaluate_bio_release` now takes
      an optional `data_quality` report and holds fail-closed for expert review
      when it blocks, even at full readiness (backward compatible). Ordered
      after the privacy checks (forbidden > reid > individual-level >
      data-quality > readiness). `tests/test_bio_data_quality.py` (13 tests).
      Review 2026-07-12 (self-review): confirmed correct and pinned the deliberate
      safety-vs-quality separation — a POOR band from DEGRADATION-only flags is
      not `blocks_release`, so the SAFETY gate (`evaluate_bio_release`) releases it
      with the band attached while the persona quality lens maps POOR -> DENY
      (a misleading result is held; a merely low-quality one is released honestly
      banded). Prevents a future change from conflating quality with safety.
- [x] `P1` Add re-identification risk checks for aggregates and small cohorts.
      Done 2026-07-11: `tinker_delegate.bio_reid.assess_reidentification` is a
      deterministic k-anonymity-style checker over bounded cohort *metadata*
      (never records): a reported subgroup below the `min_cohort_size` threshold
      that was not suppressed, or any below-threshold subgroup in a
      non-aggregate output, yields a HIGH risk band with `blocks_release=true`;
      the `[k, 2k)` range is MEDIUM (flag only); otherwise LOW. It emits only a
      risk band, block boolean, reason code, and a bounded report hash
      (`raw_secret_egress=false`, no raw counts). `evaluate_bio_release` now
      takes an optional `reid` assessment and holds fail-closed for
      biosecurity review when it blocks, even at full readiness (backward
      compatible: absent `reid` is unchanged). `tests/test_bio_reid.py` (11
      tests) cover banding, blocking/non-blocking, custom thresholds,
      individual-level small subgroups, boundedness, and gate integration.
      Boundary review 2026-07-12 (self-review): confirmed the exact k-anonymity
      thresholds are correct (unsuppressed `min < k` blocks, exactly `k` is
      anonymous -> MEDIUM, `< 2k` MEDIUM, `>= 2k` LOW) and pinned them with a
      boundary test so an off-by-one that silently changes the privacy guarantee
      is caught.
- [x] `P1` Add dual-use/risk classifier as deterministic policy, not only LLM
      judgment.
      Done 2026-07-11: `tinker_delegate.bio_dual_use.classify_dual_use` maps
      declared structured signals (`DualUseFeatures`: pathogen/toxin context,
      gain-of-function, de novo design, sequence/protocol emission, human
      subjects + IRB, synthetic-vs-real data) to a risk tier via an explicit
      policy — no LLM. PROHIBITED (gain-of-function, de novo design, or
      actionable output in a pathogen/toxin context) denies; REVIEW (dangerous
      context, sequence/protocol emission, human subjects without IRB, or
      non-synthetic data) holds; otherwise CLEARED. Conservative by design:
      ambiguous cases escalate. Wired into `evaluate_bio_release` as the second
      check (after forbidden-output): a prohibited tier DENYs, a review tier
      HOLDs for biosecurity review, even at full readiness. Complements the
      free-text forbidden-output screen along a structured axis. Output is
      bounded (tier/decision/reasons/hash, `raw_secret_egress=false`).
      `tests/test_bio_dual_use.py` (17 tests). Omission hardening 2026-07-12
      (self-review): the structured dual-use assessment is caller-supplied (its
      danger signals are declared metadata the candidate doesn't carry), so a
      dangerous task with benign-looking text could RELEASE by simply *omitting*
      the assessment. Added `evaluate_bio_release(..., require_dual_use_screen=True)`:
      a dual-use-domain caller sets it and a missing assessment fails closed to
      HOLD (`dual_use_screen_required`, BIOSECURITY_REVIEW) rather than clearing
      the structured axis silently. Default False preserves the always-on
      forbidden-output text screen behaviour. Follow-up RESOLVED 2026-07-12: the
      deployed bio path `run_bio_diligence_flow` does NOT call `evaluate_bio_release`
      — it maps `dual_use.tier` into the persona `EvaluationSummary`, and a missing
      assessment yields an empty `dual_use_tier` which the persona panel already
      treats as fail-closed DENY (so settlement cannot proceed without a dual-use
      screen). Pinned by an isolation test (everything clean EXCEPT dual-use
      omitted -> DENY, `tests/test_evaluator_personas_bio.py` +1) guarding against
      a future default-allow regression. The `evaluate_and_route` convenience
      wrapper forwards `require_dual_use_screen` through `**screens`, so a
      dual-use-domain caller gets a fail-closed HOLD + auto-enqueue
      (`tests/test_bio_review_bridge.py` +1). Both the persona-panel production
      path and the direct-gate wrapper now fail closed on an omitted screen.
- [x] `P1` Add methodology summaries that are useful but cannot reconstruct raw
      data.
      Done 2026-07-11: `tinker_delegate.bio_methodology.summarize_methodology`
      produces a bounded summary whose "cannot reconstruct" property is
      structural: it is composed only from a CLOSED controlled vocabulary
      (`ALLOWED_PREPROCESSING` / `ALLOWED_MODEL_CLASSES` / `ALLOWED_PROTOCOLS` /
      allowed hyperparameter names) plus COARSE `MagnitudeBand` sizes — any
      out-of-vocabulary token is rejected (`MethodologyError`), so no raw value
      or per-record content can enter the summary. Optional caller `notes` are
      screened through the forbidden-output screen and reduced to a hash, never
      echoed. Output is deterministic with `reconstruction_safe=true` and
      `raw_secret_egress=false`. `tests/test_bio_methodology.py` (8 tests) prove
      vocabulary enforcement, no-raw-values, notes screening/no-echo, and
      determinism.
- [x] `P2` Add multiple evaluator personas:
      buyer utility, seller protection, biosecurity, data quality, and economics.
      Done 2026-07-11: `tinker_delegate.evaluator_personas` implements the five
      reviewer lenses as deterministic functions over already-bounded signals
      (an `EvaluationSummary` of bands/tiers/booleans — never raw data), each
      returning a bounded `PersonaVerdict` (pass/hold/deny + reason code).
      `evaluate_personas` composes the panel by strict intersection (any DENY
      denies, any HOLD holds, only all-PASS proceeds — the same fail-closed rule
      as the coordination reducer) and emits a bounded `PanelDecision`
      (decision + verdicts + panel hash, `raw_secret_egress=false`). Unknown or
      missing signals fail closed to DENY inside each lens (e.g. unverified
      leakage bound, unrecognized band, missing bio screen). A subset panel runs
      only the selected lenses. `tests/test_evaluator_personas.py` (14) cover each
      lens, the intersection ordering (DENY>HOLD>PASS), fail-closed unknowns,
      subset panels, boundedness, and determinism. Per-lens fail-closed matrix
      completed 2026-07-12 (self-review): every one of the five lenses now has an
      isolated DENY-on-missing-signal test (utility unknown band, seller leakage
      None, biosecurity missing tier/risk, economics cost None, data-quality
      missing band), so a per-lens regression to fail-OPEN is caught — this panel
      is the load-bearing decision authority for the production
      `run_bio_diligence_flow` path.
      - [x] Wire the panel to real bio evaluation outputs. Done 2026-07-11:
            `summary_from_bio_evidence` / `evaluate_bio_personas` bridge the
            already-bounded bio assessments (`BioResultCandidate.utility_band`,
            `DataQualityAssessment.quality_band`, `ReidAssessment.risk_band`,
            `DualUseAssessment.tier`) into an `EvaluationSummary` and run the
            panel. Duck-typed, so `evaluator_personas` stays free of bio imports;
            data-quality bands map into the persona vocabulary (good→PASS,
            fair→HOLD, poor→DENY) and unknown/absent bands fail closed to DENY.
            `tests/test_evaluator_personas_bio.py` (6) drive it with a real
            `evaluate_synthetic_assay_qc` candidate plus the real band enums:
            clean evidence passes all lenses, prohibited dual-use and poor data
            quality deny, fair-quality/review-tier hold, and missing evidence
            fails closed.
      - [x] Compose the bounded primitives into one fail-closed diligence flow.
            Done 2026-07-11: `tinker_delegate.diligence_flow.run_diligence_flow`
            chains the gates in a fixed order — persona review → rental-stage
            disclosure → royalty settlement — so they cannot be skipped or
            reordered. A non-PASS panel stops before any disclosure/settlement; a
            denied stage transition stops before settlement; the per-owner royalty
            split accrues ONLY on a proceeding flow (panel PASS + stage allowed).
            Output is a bounded `DiligenceFlowReceipt` (flow/panel decisions,
            reason code, result type, stage transition, royalty amount bands,
            panel + flow hashes, `raw_secret_egress=false`).
            `tests/test_diligence_flow.py` (8) prove clean proceed+settle, review
            deny/hold blocking disclosure and settlement, disclosure denial (no
            consent / underfunded) blocking settlement even when review passes,
            the full-disclosure consent rule, no-royalty-without-shares, and
            determinism.
      - [x] Drive the flow from a real bio evaluation end-to-end. Done 2026-07-11:
            `run_bio_diligence_flow` bridges bounded bio assessments (assay
            `utility_band`, data-quality band, re-id risk, dual-use tier) into the
            `EvaluationSummary` and runs the same pipeline, so a real
            `evaluate_synthetic_assay_qc` candidate flows evaluate→review→
            disclosure→settlement in one call. `tests/test_diligence_flow_bio.py`
            (5) prove a clean assay proceeds and settles the 0.6/0.4 royalty split,
            prohibited dual-use and poor data quality deny before settlement, no
            consent holds, and missing evidence denies.
      - [x] Auto-derive the leakage/offer/budget signals from bounded evidence.
            Done 2026-07-11: `derive_leakage_signals` grounds
            `leakage_within_bounds` in the evaluation's own
            `raw_secret_egress == False` (a bounded result object/dict — proven, not
            asserted) and computes `offer_within_cap` / `cost_within_budget` from
            offer/cap and cost/budget amounts; missing evidence yields `None`
            (fail-closed downstream). `run_bio_diligence_flow` now accepts a
            `bounded_result` + offer/cost/budget amounts and derives the three
            booleans when they are not passed explicitly, so the
            seller-protection/economics lenses rest on evaluation evidence.
            `tests/test_diligence_flow_bio.py` (+4) prove derived-signals proceed,
            a leaky bounded result denies via seller-protection, over-budget cost
            denies, and the helper's exact mapping (incl. None on missing
            evidence).
      - [x] Emit the executable on-chain settlement plan from a settled receipt.
            Done 2026-07-11: `distribution_plan_from_flow` turns a *proceeding*
            diligence-flow receipt into a `RoyaltyDistributionPlan` — resolving
            each payout's `owner_ref` to an address and delegating to the
            cast-verified / Anvil-proven `build_royalty_distribution_plan`. Fail
            closed: a hold/deny receipt, a proceed with no royalty payouts, or a
            missing owner address all raise `DiligenceFlowError`; only a settled
            flow yields a settlement plan. So one bio evaluation now produces both
            the bounded verdict AND the executable on-chain royalty plan.
            `tests/test_diligence_flow_to_plan.py` (5).
      - [x] Prove the whole pipeline end-to-end on Anvil. Done 2026-07-11:
            `scripts/prove-diligence-flow-settlement-anvil.py` runs a real
            synthetic-assay diligence flow → PROCEED receipt → derives the royalty
            plan → deploys `RoyaltyDistributor` → broadcasts the plan's exact
            calldata → asserts each owner is credited the flow's payout and the
            contract drains to zero after withdrawal. Guarded test
            `tests/test_diligence_flow_settlement_proof.py`
            (`DNAI_RUN_ANVIL_PROOFS=1`, passing live). Net: bio evaluation → verdict
            → derived plan → on-chain distribution → conserving pull-payment is
            proven as one flow.
- [x] `P2` Add reproducibility certificates:
      run config hash, data hash, code hash, model base, hyperparameters, random
      seeds, quote, and result hash.
      Done 2026-07-11: `tinker_delegate.reproducibility` binds a run into one
      recomputable, bounded commitment. `RunConfig` (optimizer, model base,
      hyperparameters, seeds, round budget, target band) folds into a
      `run_config_hash`; the certificate carries `run_config_hash`,
      `data_commitment` (the environment's public `environment_hash` / holdout
      split commitment — sealed data stays sealed), `code_hash`
      (`hash_code_identity`), coarse public `model_base`, `result_hash` (loop
      transcript), optional `attestation_quote_hash`, and a `certificate_hash`
      digesting all of them. Everything is a hash or coarse identifier, so raw
      hyperparameter floats, seeds, sealed data, and reward values never appear —
      the certificate passes `assert_bounded_egress`.
      `verify_reproducibility_certificate` recomputes the binding hash to detect
      tampering; `certify_loop_run` certifies a `run_private_reward_loop` outcome
      against its environment. `tests/test_reproducibility.py` (6) prove bounded
      egress, float/seed non-leakage, determinism, tamper detection, config
      sensitivity, and quote binding.
      - [x] Wire certificates into the operator surface. Done 2026-07-11: the
            `bio-assay-qc-reward-demo` CLI now emits a
            `reproducibility_certificate` alongside the bounded outcome, bound to
            the run's `final_result.transcript_hash` and the env
            `environment_hash`. `code_hash` is derived by `hash_source_files`,
            which hashes the actual evaluator module source bytes (a real code
            hash that changes iff the reward code changes, deterministic per
            tree). The certificate passes the demo's leakage guard
            (`raw_secret_egress=false`, no sealed readings), verifies, and is
            deterministic across runs. `tests/test_bio_assay_program_demo.py`
            adds two certificate tests.

## Milestone 5: DNAI Data Room, Props Room, And Source Custody

### Artifact Ingress And Sealed Storage

- [ ] `P0` Encrypt artifact upload to the TEE public key after verifying the live
      quote.
      - [x] Add encrypted artifact upload endpoint using the attestation-exposed
            TEE public key, artifact-specific HKDF context, and deal/hash-bound
            AES-GCM associated data.
      - [x] Disable plaintext artifact upload by default and in dstack mode.
      - [x] Bind the TEE encryption public key and operation context into
            attestation report data.
      - [x] Add a client-side quote verifier/uploader that refuses to encrypt or
            upload until the live TDX quote, compose hash, and report data pass.
- [x] `P0` Bind ingress and evaluation to the immutable on-chain salted v2
      artifact commitment before a deal can proceed.
      - [x] Define `artifactHash` as
            `keccak256(ASCII("dnai-wikigen/artifact-commitment/v2") || 0x00 || secret32 || rawArtifact)`
            with an exact 32-byte random secret and no raw-keccak fallback.
      - [x] Forward `DealCreated.artifactHash` through the watcher into immutable
            `DealContext`, reject caller-supplied mismatches before decryption,
            verify after wrapper decode, and re-verify immediately before the
            evaluator receives bytes.
      - [x] Require the strict private v2 recovery receipt and versioned encrypted
            wrapper; reject empty artifacts, raw unwrapped bytes, malformed
            receipts, wrong secrets, and self-consistent artifact B uploads for a
            chain commitment to artifact A.
- [ ] `P0` Add per-corpus/per-deal key derivation:
      no single static artifact key for all rooms.
      - [x] Derive artifact upload AES keys with per-deal/per-artifact HKDF
            context so ciphertexts cannot decrypt under another deal or
            artifact hash even under the same TEE public key.
      - [x] Add a sealed-storage key hierarchy for retained corpora/rooms.
            Done 2026-07-12: `SealedRetentionStore` no longer encrypts artifacts
            under one static root key. Each retained artifact is sealed under a
            per-corpus/per-deal key derived by HKDF-SHA256 from the TEE root key
            (`info = dnai-sealed-retention:v1:<corpus_ref>:<deal_id>`), so
            distinct `(corpus_ref, deal_id)` yield cryptographically independent
            keys and a ciphertext cannot decrypt under another room or deal even
            though all descend from the same root. `corpus_ref` scopes the
            hierarchy (root -> per-corpus -> per-deal), is stored on the sealed
            entry, and survives the encrypted persistence round-trip; the control
            plane passes `ctx.seller` as the corpus so each data owner's retained
            corpus lives on its own key branch. `tests/test_sealed_retention.py`
            (+4) prove the root key can't open a derived-key artifact, distinct
            corpus/deal yield distinct deterministic keys, a relabeled entry
            fails authentication, and corpus_ref persists. Hardened 2026-07-12:
            the HKDF info now length-prefixes `(corpus_ref, deal_id)` instead of
            joining them with `":"` — a self-review found a real collision where
            `("a","b:c")` and `("a:b","c")` derived the SAME key (breaking the
            per-corpus isolation claim); the same length-prefix fix was applied to
            `otp_delivery.compute_delivery_hash` (its raw 32-byte otp_hash could
            contain the old `\x1f` separator). Regression tests added in both.
- [ ] `P0` Ensure artifacts never touch disk unencrypted.
      - [x] Add no-disk-write regression tests around encrypted FastAPI ingress
            and control-plane evaluation dispatch so raw artifact buffers in
            this TEE service path cannot call Python file write/open APIs.
      - [ ] Audit the real SFT evaluator, Tinker SDK calls, browser tracing,
            and deployed debug tooling before claiming the full artifact
            lifecycle never touches disk unencrypted.
- [ ] `P0` Add memory zeroing for raw artifact buffers after resolution.
      - [x] Zero mutable API upload decode buffers after ingress and stored
            control-plane artifact buffers after deal resolution.
      - [ ] Audit evaluator copies and Python immutable byte lifetimes before
            making a production-grade memory-destruction claim.
- [x] `P1` Add attested destruction or cleanup records:
      artifact deleted, keys dropped, checkpoints deleted/expired.
      Done 2026-07-11: `tinker_delegate.destruction_record` turns cleanup facts
      (`DestructionEvidence`: artifact_deleted, memory_zeroed, keys_dropped,
      checkpoints_deleted/expired, per-room required-step flags) into a bounded,
      recomputable `DestructionRecord`. Fail-closed: `complete` is true only when
      every required step succeeded (default: artifact deleted AND memory zeroed);
      otherwise `complete=false` with an `incomplete_destruction:<missing>` reason
      — an honest, non-self-approving audit signal. Output is bounded — the deal
      ref is hashed (not echoed), the artifact commitment is already a hash, and
      only counts/booleans/hashes appear (no raw bytes, keys, or checkpoint
      paths); `raw_secret_egress=false`. `verify_destruction_record` recomputes the
      record hash to detect tampering. `tests/test_destruction_record.py` (10)
      cover complete/incomplete cases, relaxed requirements, deal-ref hashing (no
      echo), tamper detection, determinism, and count/hash validation.
      Wired into the control plane 2026-07-12: `ControlPlane.on_deal_resolved`
      now evaluates the room retention policy and builds a `DestructionRecord`
      from the actual cleanup (artifact zeroed → artifact_deleted/memory_zeroed,
      `deleted_checkpoint_count` from the session cleanup attestation), stores the
      retention decision + destruction record on the `DealContext`, and emits
      bounded `retention_action` / `destruction_complete` / `destruction_record_hash`
      fields on the `deal_resolved` metadata event (allowlisted in
      `run_metadata_store`). `tests/test_run_metadata_store.py` asserts a resolved
      deal emits a verifying, complete destruction record with
      `retention_action=destroy_now` and no raw artifact/run-id egress. Honoring a
      retain/archive decision (keeping sealed data) needs a sealed-retention
      store; today resolution always destroys (safe fail-closed default).
- [x] `P1` Add source-controller records:
      who controls the source, what was approved, scope, expiry, revocation, and
      audit hash.
      Done 2026-07-11: `tinker_delegate.source_controller` is the bounded
      custody-audit artifact for TEE-held source accounts. A `SourceGrant` records
      source/controller/approver refs, approved `scopes`, `granted_at`,
      `expires_at`, `revoked_at`, and an `audit_hash`; `status(now)` resolves
      active/not_yet_active/expired/revoked. `SourceControllerRegistry.authorize`
      answers fail-closed: an unknown source, a non-active grant, or an
      out-of-scope request all DENY with a bounded reason. Invariants enforced:
      non-self-approval (`approved_by != controller_ref`, raised at construction)
      and scope containment. Bounded — source/controller/approver refs are hashed
      (never echoed), only statuses/scopes/timestamps/hashes leave
      (`raw_secret_egress=false`). `tests/test_source_controller.py` (12) cover
      self-approval rejection, status transitions, in/out-of-scope and
      unknown/expired/revoked authorization, duplicate rejection, ref hashing (no
      echo), and bounded manifest.
      Wired into the control plane 2026-07-12: `ControlPlane` takes an optional
      `source_registry` (+ `source_ref`, `source_scope`); when configured,
      `on_deal_funded` calls `_authorize_source_use` before creating the Tinker
      session, so the TEE-held source account can only be used while a valid,
      non-self-approved grant for the scope is active — an expired, revoked, or
      out-of-scope grant raises `SourceAccessDenied` and no session/deal is
      created (fail closed). Default (no registry) preserves current behavior.
      `tests/test_source_controller.py` (+4) cover no-registry-allows,
      active-grant-allows, out-of-scope-denies, and revoked-denies.
      Grant provisioning added 2026-07-12: `load_source_registry` /
      `build_source_registry` load grants from a JSON file
      (`source_grants_path` setting; grants validated at load, so a self-approving
      file is rejected), the control-plane singleton constructs the registry from
      it, and operator-authed `GET /source/grants` returns the bounded manifest
      (hashed refs, no raw account ids). `tests/test_source_controller.py` (+3)
      and `tests/test_api_retention_sweep.py` (+3) cover the factory, JSON
      load+authorize, self-approval rejection, and the bounded/auth-gated endpoint.
- [x] `P1` Add data retention policy per room:
      immediate destruction, time-boxed retention, or post-settlement encrypted
      archive.
      Done 2026-07-11: `tinker_delegate.retention_policy` defines a per-room
      `RetentionPolicy` (mode `immediate` / `time_boxed` / `post_settlement_archive`,
      a bounded `retention_seconds`, and an optional `archive_key_ref`).
      `evaluate_retention(policy, settled_at, now)` returns a bounded, fail-closed
      `RetentionDecision`: immediate → `destroy_now`; time_boxed → `retain_sealed`
      until `settled_at + retention_seconds` then `destroy_now` on expiry;
      post_settlement_archive → `archive_encrypted`. Fail-closed choices favor
      destruction — a non-positive window, a missing archive key, or an unknown
      mode all resolve to `destroy_now` rather than leaving unsealed data around.
      Bounded output (mode/action/deadline/booleans/policy hash,
      `raw_secret_egress=false`); the policy hash records only whether an archive
      key is configured, never the key ref. Composes with `destruction_record`
      (this decides *when* to destroy; that proves it *happened*).
      `tests/test_retention_policy.py` (9) cover each mode, window
      expiry/within-window, both fail-closed paths, key-ref non-echo, validation,
      and determinism. Wired into `ControlPlane.on_deal_resolved` 2026-07-12: the
      room's policy is evaluated at resolution and its `retention_action` is
      recorded on the bounded `deal_resolved` event (default IMMEDIATE → always
      destroy).
      Sealed-retention store added + wired 2026-07-12:
      `tinker_delegate.sealed_retention.SealedRetentionStore` encrypts retained
      artifacts under a TEE-held AES-256-GCM key (per-deal associated data),
      holds them as ciphertext, and `sweep(now)` destroys entries whose window
      expired. `ControlPlane` now takes an optional `retention_store`: on a
      `retain_sealed`/`archive_encrypted` decision it seals the artifact and zeroes
      the plaintext (event carries `artifact_sealed_retained=true`, no destruction
      record yet); `sweep_retention(now)` later destroys expired sealed artifacts
      and emits attested destruction records (new `retention_swept` event).
      Bounded throughout (deal refs hashed, ciphertext sizes banded, no plaintext
      or key egress). `tests/test_sealed_retention.py` (11) cover seal/open
      roundtrip, wrong-AAD failure, expiry sweep, destroy, bounded manifest,
      key/hash validation, and the control-plane seal-on-retain + sweep lifecycle.

### Props Room

- [ ] `P0` Connect `props-room` to the on-chain deal lifecycle.
- [ ] `P0` Add real identity/wallet auth to `props-room`.
- [ ] `P0` Add attestation verification for downstream raw scrape, cleaning,
      training, and inference stages.
- [ ] `P1` Wire the `tv` adapter into a real sealed source acquisition demo.
- [ ] `P1` Add a WhatsApp source adapter using `whatsapp-delegate`.
- [ ] `P1` Add staged approvals:
      raw scrape, clean, train, inference, publish, revoke.
- [ ] `P1` Add contributor rights:
      participants receive inference rights or royalty rights on derived models.
- [ ] `P2` Add non-TV adapters:
      FHIR, OMOP, FAIR, GA4GH Beacon, S3/GCS, GitHub private repo, Notion/Drive,
      and arbitrary browser-export sources.

### ConSECA-Style Policy Kernel

- [x] `P0` Keep the gate as a pure function of `(AccessRequest, CorpusPolicy)`.
      Done 2026-07-09: `tinker_delegate.policy_kernel.gate_access_request()`
      takes frozen `AccessRequest` and `CorpusPolicy` records and returns a
      bounded `PolicyGateResult` with no network, browser, email, Tinker, chain,
      clock, random, or mutable-store dependency.
- [x] `P0` Replace hardcoded illustrative gate verdicts with a deterministic
      policy engine. Done 2026-07-09: `tinker_delegate.policy_kernel` enforces
      allowed/denied purposes, pipeline and output-schema allowlists,
      operation allowlists, known data classes, restricted categories, and
      review/ambiguous categories with stable pass/hold/deny outcomes. The
      pure `gate_turn_requests()` fan-out adapter converts per-corpus access
      requests into the existing `coordination.GateResults` shape without
      making the coordination reducer call services or policy code implicitly.
- [ ] `P0` Add LLM-drafted policy authoring only as a drafting step.
      Enforcement must be deterministic and testable.
      Enforcement is now deterministic/tested in `policy_kernel`; LLM
      draft-to-policy compilation remains open.
- [x] `P0` Add fail-closed behavior for unknown policy fields, unknown purposes,
      unsupported pipelines, and ambiguous restricted categories. Done
      2026-07-09: strict dict entrypoints reject unknown request/policy fields
      into bounded deny receipts; unknown purposes, unsupported pipelines,
      unsupported output schemas/operations, unknown data classes, restricted
      categories, and unsupported policy versions fail closed; ambiguous
      categories route to hold/review with bounded category hashes.
- [x] `P1` Add policy tests for the initial source-real allowed purpose, denied
      purpose, hold route, and restricted category. Done 2026-07-09:
      `tests.test_policy_kernel` covers allowed pass, denied/unknown purposes,
      unsupported pipeline/output, unknown fields, unknown data classes,
      restricted-deny, hold-route, ambiguous-review, unsupported policy version,
      coordination `GatedQuery` conversion, fan-out coverage checks, and policy
      deny beating consent.
- [x] `P1` Add an operator-exercisable bounded policy-gate proof path. Done
      2026-07-09: `tinker-delegate policy-gate` evaluates either
      `--request-json` + `--policy-json` or `--turn-json` + `--policies-json`
      and writes bounded receipts with decisions, actions, policy/request
      hashes, coordination fan-out summaries, route labels, and
      `raw_secret_egress=false`. Focused tests cover direct receipt generation
      and CLI `--output` behavior without leaking raw purpose/category text.
- [ ] `P1` Extend policy tests for every additional production purpose, route,
      and restricted category when the production policy catalog exists.
- [ ] `P1` Wire `policy-gate` receipts into a deployed, runtime-authenticated
      TEE service endpoint once policy authoring/review custody is defined.
- [ ] `P1` Add policy versioning and migration.
- [ ] `P1` Add policy diff review for corpus owners and reviewers.

## Milestone 6: Coordination, Consent, Review, And Governance

- [x] `P0` Implement the pure coordination reducer described in
      `⚙️/tinker-delegate/docs/COORDINATION-ENGINE-SPEC.md`.
      Done 2026-07-09: `tinker_delegate.coordination.coordinate()` implements
      source-modeled submit, gate-result, reviewer-decision, and revocation
      events with immutable state records and bounded public turn records.
- [x] `P0` Add tests for:
      all-pass, one-deny, one-hold, restricted-deny, missing consent, revoke
      mid-turn, and delegate-exceeds-scope.
      Done 2026-07-09 in `tests/test_coordination.py`.
- [x] `P0` Implement the source/release-gated Collaboration schema-v2 control
      plane and browser UI.
      Persistent authenticated rooms, wallet-owned invitation decisions,
      membership and owner-role changes, exact-current-query grants,
      snapshot-consistent pagination, idempotent ambiguity recovery,
      joint-consent snapshots, and quiescent archive are implemented across
      the delegate API and SolidJS client. Local HMAC mode is explicitly
      non-monotonic. Live dstack mode now commits every exact schema-v2 state to
      a release/project/domain-bound Base Sepolia `ExecutionPolicyAnchor` under
      the explicit single-RPC reported-finalized model, recovers ambiguous
      commits through a private pending document, and fails closed on witness
      outage, regression, or mismatch before auth, reads, or mutations. This is
      not RPC quorum or a consensus proof.
      - [x] Implement the separate release-gated Collaboration execution and
            Royalty continuation. The source derives the deterministic exact
            funding reservation only after the complete fresh grant set, admits
            its worker only after RPC-reported finalized EIP-1898 reads of that
            reservation and the exact Compute job, runs the bounded one-shot
            Compute path, anchors the exact settlement decision on demand,
            obtains purpose-separated main/QVL authorizations, emits the exact
            sponsor-wallet `settleReserved` plan, and reconciles finalized
            permanent state. Direct distribute calls are compatibility-only.
      - [ ] Activate and prove that path in the fresh release. Required evidence
            remains a project-owned Base Sepolia deployment, seven measured Phala
            CVMs, independent QVL roots/verdicts, real sponsor reservation,
            provider execution, wallet settlement, finalized reconciliation, and
            matching Cloudflare candidate. Local HMAC state, test signers, DTOs,
            heartbeats, and RPC-reported finalized reads are not TDX/QVL or
            consensus evidence.
- [x] `P0` Implement the source/release-gated human-review queue:
      ticket creation, role routing, release/deny, reviewer identity, expiry,
      audit trail.
      - [x] Add source-modeled handoff tickets and reviewer decisions.
            The reducer creates hold tickets with role routing, records reviewer
            release/deny identity, and returns to `gating` after release so the
            turn must be re-gated.
      - [x] Add a bounded source-level review queue with expiry and audit trail.
            Done 2026-07-09: `tinker_delegate.review_queue` can enqueue
            coordination `HandoffTicket`s, persist/load a bounded JSON queue,
            filter pending tickets by reviewer role, record release/deny
            decisions with reviewer hashes, expire stale pending tickets, and
            maintain an append-only bounded audit hash. Tests prove no raw
            review reason or reviewer identity is emitted.
      - [x] Expose the current release-bound reviewer API and SolidJS UI.
            The public strict hash-only queue, internal enqueue/expiry routes,
            one-time allowlisted reviewer-wallet challenge, signed release/deny
            decision, private M-of-N resolution, self-review/duplicate-vote
            rejection, and browser-rechecked Base Sepolia rollback witness are
            implemented. Fresh production reviewer roster/key custody,
            tee-email-oracle notification, scheduled expiry, and deployment
            remain separate open activation work.
- [x] `P0` Enforce that delegated agents cannot resolve their own holds.
      Done 2026-07-09: reviewer decisions from the turn issuer/requester fail
      closed as `self_approval_denied`; tests prove the agent cannot release
      its own ticket.
- [x] `P0` Implement source-level consent grants:
      purpose, pipeline, requester, expiry, revocation, quorum, and owner.
      - [x] Add source-modeled active consent matching for owner, corpus,
            purpose, pipeline, requester, and expiry. Missing consent leaves
            the turn `awaiting-consent` with no meters or surfaced result.
      - [x] Add source-modeled M-of-N consent quorum handling.
            Done 2026-07-09: `CollabSession.consent_quorum` now supports
            `unanimous` and `<m>-of-<n>` over the turn corpora; invalid or
            mismatched quorum policy fails closed as `invalid_consent_quorum`,
            below-threshold grants remain `missing_consent`, and tests prove
            2-of-3 settlement without raw secret egress.
      - [x] Add source-modeled owner consent-confirmation effects.
            Done 2026-07-09: `ConsentDecision` lets only the matching corpus
            owner grant or deny consent for an `awaiting-consent` turn. Grants
            append bounded active `ConsentGrant`s and settle only once the
            session quorum is met; denial is terminal as `consent_denied`.
            Tests prove wrong-owner/non-owner attempts fail closed and public
            turn records do not expose raw purpose or gate reasons. tee-email
            owner notification, reviewer UI, signatures, and deployed service
            wiring remain open.
      - [x] Add an operator-exercisable bounded consent-decision proof path.
            Done 2026-07-09: `tinker-delegate consent-decision` reads a saved
            coordination state JSON plus owner consent-decision JSON, applies
            the reducer event, and emits only bounded receipt fields: before/after
            status, action, quorum grant counts, owner/requester/purpose/pipeline
            hashes, state input/output hashes, and no raw secret egress. Tests
            cover grant-to-settle, grant-below-quorum, denial, malformed state
            fail-closed behavior, and CLI bounded output. Runtime-authenticated
            API exposure, signed owner confirmation, tee-email delivery, and
            production custody are tracked as separate subitems.
      - [x] Expose consent-decision receipts through a runtime-authenticated API.
            Done 2026-07-09: `POST /coordination/consent-decision` requires a
            configured runtime bearer token, accepts coordination state plus
            consent decision JSON, calls the same bounded receipt builder as the
            CLI, and returns no raw purpose, pipeline, owner refs, gate reasons,
            or full updated coordination state. Tests cover missing runtime auth
            config, missing/wrong bearer token, successful bounded receipt, and
            malformed-state redaction. Optional signed owner confirmation,
            tee-email delivery, reviewer UI, and production custody remain
            separate.
      - [x] Add optional signed owner confirmation for consent-decision
            receipts/API.
            Done 2026-07-09: `tinker_delegate.consent_receipt` now computes a
            canonical Ethereum signed-message hash over a hash-only consent
            confirmation payload: schema/surface, input-state hash, turn/corpus
            refs, owner/requester/purpose/pipeline hashes, decision, and optional
            expiry. `tinker-delegate consent-decision --require-signature
            --expected-signer ...` and `POST /coordination/consent-decision`
            can fail closed unless the recovered signer matches the declared
            signer and optional expected owner signer. Receipts expose only
            decision hash, signer hash, signature hash, verification status, and
            `raw_secret_egress=false`; tests cover valid signed CLI/API/unit
            paths plus missing signature, wrong signer, and hash mismatch. This
            is signature binding only; tee-email owner notification, production
            owner-key custody, reviewer UI, and deployed effect wiring remain
            open.
- [x] `P0` Implement revocation:
      future and in-flight turns fail closed; prior settled attestations remain
      valid.
      Done 2026-07-09: owner revocation marks the corpus revoked, converts
      in-flight/future turns touching it to `revoked`, and leaves already
      settled turns unchanged.
- [x] `P1` Implement joint attestations for multi-corpus turns.
      Done 2026-07-09: terminal and held coordination records carry a bounded
      `JointAttestation` with query/ticket/royalty hashes, reviewer refs, corpus
      refs, and `raw_secret_egress=false`.
- [x] `P1` Implement royalty metering for multi-owner surfaced turns.
      Done 2026-07-09: all-pass plus active consent produces per-corpus owner
      `RoyaltyMeter` records with amount bands and a joint royalty hash.
- [x] `P1` Implement source-level M-of-N and two-person review for high-stakes
      routes. Distinct reviewer approvals accumulate privately to the
      role-specific threshold, duplicate votes and self-review fail closed, and
      any deny is terminal. Activating the production reviewer roster and key
      custody remains open.
- [ ] `P1` Add separation-of-duties enforcement:
      data owner, session custodian, reviewer, auditor, requester, sponsor.
- [ ] `P2` Add governance templates:
      one-owner, two-biobank collaboration, CRO agent, clinician request,
      sponsor-funded validation, public-good dataset.
- [ ] `P2` Add legal/ethics escalation workflows:
      IRB, DUA, consent evidence, DURC/biosecurity review, export controls where
      applicable.

## Milestone 7: Frontend, Cloudflare, And User Product

- [x] `P0` Replace the old mockup with the repository-root `web/` product.
      The result is SolidJS, not React, and has twelve canonical routes:
      Overview, Health Guide, Arena, Diligence Rooms, Release Review, Data
      Vaults, Compute, Delegated Tinker Account, Safeguards, Capabilities,
      Verify, and Collaborate. Health Guide is modeled, clears on reload, and
      accepts no health data in this release.
- [ ] `P0` Wire the frontend to real APIs instead of synthetic data:
      health, attestation, rooms, deals, gate verdicts, funding, evaluator status,
      and result verification. The client implementations and fail-closed gates
      exist; this item means activating them only from the fresh live release.
- [x] `P0` Add wallet connection and scoped service authentication.
      EIP-6963 and injected EIP-1193 wallets are supported; WalletConnect is
      conditional on its public project ID. Seller upload, Arena, and Compute
      use separate Base-Sepolia-bound signature/token domains. Reviewer-wallet
      effect authorization is implemented behind the release gate; production
      reviewer roster/custody activation and separate auditor/admin effect
      authorization remain deployment work.
- [x] `P0` Add the seller/controller interaction shape: create room, generate a
      salted recovery receipt, set reserve/policy, and encrypt artifact ingress.
      Mutation remains locked unless the fresh contract/CVM gates pass.
- [x] `P0` Add the buyer/sponsor interaction shape: inspect rooms, verify the
      release, fund with a budget cap, and resolve bounded results. Writes remain
      locked unless the fresh chain release passes.
- [x] `P0` Add the source/release-gated reviewer flow:
      strict hash-only holds queue, release context and rollback witness,
      wallet-signed release/deny, private M-of-N threshold, self-review
      rejection, and bounded audit record. Production reviewer custody,
      notifications, scheduled expiry, and deployment remain open.
- [x] `P0` Add the Trust Center: all seven contract observations, image/compose/
      CVM pins, evidence ladder, bounded receipt classifier, and release gates.
      It never promotes a modeled receipt or producer envelope to Intel TDX.
- [x] `P0` Deploy the frontend to Cloudflare Pages.
      The current source candidate is published only to the explicit
      `modeled-preview` alias. The production branch and custom domains were
      not changed; live mutation remains gated on a fresh independently
      verified contract/CVM release manifest.
- [ ] `P0` Add Cloudflare Worker or API boundary for any server-side frontend
      tasks; no secrets in the static client.
- [ ] `P1` Add optimistic UI and polling for chain/TEE state transitions.
- [x] `P1` Add modeled synthetic data that is clearly labeled and cannot be
      confused with real private bio data or Intel TDX evidence.
- [ ] `P1` Add "explain why denied/held" UI that reveals policy reasons but not
      sensitive internals.
      - [x] Bounded data layer done 2026-07-12:
            `tinker_delegate.decision_explainer.explain_decision` maps the system's
            bounded `reason_code`s (leakage, budget, biosecurity, privacy,
            data-quality, governance, verification, funding, lifecycle) to a fixed
            `DecisionExplanation` (category, disposition denied/held/allowed/info,
            plain-language summary, remediation). Leak-free BY CONSTRUCTION: it only
            ever emits curated registry vocabulary and never echoes the input code
            or any `:suffix` it carries, so a code with an injected private suffix
            cannot leak (tested). Unknown codes fall back to a safe generic HELD.
            Handles exact + prefix codes (`dual_use_*`, `exceeds_*`,
            `funding_failure_*`, ...). `tests/test_decision_explainer.py` (8) cover
            known/prefix/unknown/leak-free plus REAL reason codes emitted by
            `evaluate_bio_release`, `spend_budget`, and verification (proving the
            registry covers the live system). Wired into real surfaces 2026-07-12
            (not deployment-blocked): `verify_reward_run` verdicts now carry a
            bounded `explanation` (self-explaining verdict), and an
            `explain-decision <reason_code>` operator CLI emits the bounded
            explanation (`tests/test_run_verification.py` +1,
            `tests/test_decision_explainer.py` +1 CLI, both proving no suffix echo).
            Extended 2026-07-12 to the most user-facing safety surface:
            `BioReleaseReceipt.to_public_dict` now carries a self-explaining
            `explanation` (a held/denied bio diligence result explains its own
            policy reason, `:suffix` stripped so no detail leaks;
            `tests/test_bio_dual_use.py` +1).
      - [ ] The UI itself (frontend rendering of these explanations) remains
            frontend-gated.
- [x] `P1` Add a bounded verification explorer for image digest, compose hash,
      app/CVM identity, contract policy, quote hash, and signed QVL verdict.
      Raw quotes are not rendered as public product content.
- [ ] `P2` Add guided onboarding:
      create wallet, verify TEE, submit first toy artifact, fund testnet deal.
- [x] `P2` Add branded `wikigen.me` product language while keeping every
      undeployed capability labeled modeled, roadmap, or fail-closed.

## Milestone 8: External Alignment And Design Imports

These are not dependencies to blindly copy. They are alignment targets for the
vision Wiki is reaching for.

### Flashbots / Flashbots X Alignment

- [ ] `Research` Study Flashbots' Proof-of-Cloud/DCEA direction and decide how
      much platform provenance `dnai-wikigen` needs for health/bio private-data
      use cases.
      Reference: https://writings.flashbots.net/mind-the-gap-tee-poc
- [ ] `Research` Study the Sirrah/TEE-coprocessor pattern for keeping as much
      trust logic visible in Solidity as possible.
      Reference: https://writings.flashbots.net/suave-tee-coprocessor
- [ ] `P1` Add a "role separation" threat model mirroring Flashbots-style
      mutually distrusting parties:
      operator, data owner, evaluator owner, sponsor, reviewer, hardware/cloud
      provider, chain verifier.
- [ ] `P1` Add a Proof-of-Cloud placeholder in attestation records so it can be
      filled when provider support exists.
- [ ] `P2` Consider whether the evaluation marketplace should eventually look
      like a confidential coprocessor market:
      private inputs, private strategies/agents, public settlement, verifiable
      bounded output.

### Teleport / Account-Link Alignment

- [ ] `Research` Extract the core pattern from Teleport:
      one-time or scoped use of a web2 account, represented as a transferable or
      programmable commitment, enforced by a TEE.
      Reference: https://github.com/teleport-computer/teleport-gramine-rs
- [ ] `P1` Apply the Teleport pattern to Tinker:
      the Tinker account should expose scoped, one-deal compute authority rather
      than raw credentials.
- [ ] `P1` Apply the Teleport pattern to email:
      one OTP or one confirmation is one use; no skipping policy.
- [ ] `P1` Decide whether account-use rights should be represented on-chain:
      NFT, ERC-1155, signed capability, or non-transferable grant.
- [ ] `P2` Build a small one-time capability demo:
      "run this one bounded evaluation" link that expires after use and can be
      verified against a TEE quote.

### Andrew Miller / outh3 / DevProof Alignment

- [ ] `P0` Treat `🔬/amiller/skill-verifier` as the closest implementation
      reference:
      ephemeral execution, inspection certificates, escrow, and deletion.
- [ ] `P0` Treat `🔬/amiller/devproof-audits-guide` as the audit checklist:
      on-chain attestation, auditable code, reproducible builds, no secret
      access, upgrade notice, no centralized hidden dependencies, no backdoors.
- [ ] `P1` Import the dstack-openclaw domain-separation idea:
      the evaluator cannot forge its own genesis/attestation story.
- [ ] `P1` Study `github-zktls-1--groupauth` for multi-TEE trust federation:
      Sigstore/GitHub Actions, dstack KMS, and future Tinker/Phala attestations
      should be able to join one trust graph.
- [ ] `P1` Study `oauth3-openclaw--conseca-policy-engine` for deterministic
      policy enforcement after LLM-assisted drafting.
- [ ] `P1` Study `dshield` / verifiable egress ideas before claiming DLP.
- [ ] `P2` Build a `devproof verify` command for this repo that an external
      judge can run without trusting Wiki, Codex, or the deployer.

### Wiki Leks / Wikigen Product Alignment

- [ ] `P0` Preserve the product's concrete promise:
      "private technical information can be valued without direct disclosure."
- [ ] `P0` Decide the first market:
      bio validation, bug bounty/code audit, private research memo, source-data
      contribution, model/data-room licensing, or agent skill verification.
- [ ] `P1` Build one tight demo story rather than all markets at once.
      Recommended first real story:
      synthetic/private bio artifact -> TEE ingress -> Tinker toy training ->
      bounded validation band -> Base Sepolia settlement -> verifier page.
- [ ] `P1` Add copy that distinguishes:
      NDAI economics, TEE custody, Tinker compute, email OTP custody, and
      coordination/governance.
- [ ] `P2` Build "catalog" only after the backend trust path can support at least
      one real room end-to-end.

## Milestone 9: Compliance, Safety, And Abuse Resistance

- [ ] `P0` Write a data-classification policy:
      public demo, synthetic, confidential business, PHI/health, biosecurity
      sensitive, dual-use, illegal/forbidden.
- [ ] `P0` Until reviewed, restrict real demos to synthetic or public toy data.
- [ ] `P0` Decide HIPAA/PHI stance:
      not supported, supported only with BAA/compliant infra, or supported only
      for de-identified data.
- [x] `P0` Decide Stripe/PCI stance before real card funding.
      Stance recorded in
      `⚙️/tinker-delegate/docs/STRIPE-PCI-FUNDING-SCOPE.md`: no production or
      repeated raw-card funding path without compliance review; only a capped
      operator-owned validation attempt is allowed before tokenized/official
      funding exists.
- [ ] `P0` Decide Tinker Terms-of-Service stance for browser automation and
      delegated account use.
- [ ] `P0` Add abuse policy for:
      credential theft, spam, bot evasion, account resale, dual-use bio,
      re-identification, malware, exploit sale, and sanctions/export issues.
- [ ] `P1` Add legal terms for:
      seller warranties, buyer usage limits, data retention, dispute process,
      evaluator error, and bounded-output limitations.
- [ ] `P1` Add incident response:
      leaked secret, wrong compose hash, TEE compromise, bad reviewer release,
      result over-disclosure, card data exposure, stuck funds.
- [ ] `P1` Add kill switches:
      pause new rooms, pause Tinker execution, pause funding, revoke consumers,
      freeze oracle code, pause frontend.
- [ ] `P1` Add audit log retention rules and privacy-preserving audit views.
- [ ] `P2` Commission external security review before any real private health or
      payment data.

## Milestone 10: CI, Testing, And Quality Gates

- [x] `P0` Add CI for Foundry contracts:
      `forge build`, `forge test`, gas snapshot, coverage if feasible.
      Done in `.github/workflows/ci.yml`: the Foundry job installs Foundry and
      runs `scripts/verify-local.sh foundry`, which executes `forge build
      --sizes` and `forge test`. Refreshed 2026-07-08: the Foundry checkout no
      longer requests recursive research submodules, because the needed
      `forge-std` files are vendored in the contract package.
- [x] `P0` Add CI for Python packages:
      `uv sync`, import checks, unit tests, compileall, type checks where set up.
      Done in `.github/workflows/ci.yml`: the Python job installs `uv` and runs
      `scripts/verify-local.sh python` across `tinker-delegate`,
      `tee-email-oracle`, `props-room`, `whatsapp-delegate`, and
      `cdp-playground`. Stub packages now have `uv.lock` so CI can use
      `uv sync --frozen`.
- [ ] `P0` Add CI for frontend once merged:
      `npm ci`, `npm test`, `npm run build`, `npm audit --omit=dev`.
- [x] `P0` Add secret scanning in CI.
      Done in `.github/workflows/ci.yml` and `scripts/ci-secret-scan.sh`.
      The scanner excludes read-only reference material and generated lock/build
      outputs, allows only explicit fake test fixtures, and fails on common
      Phala/Tinker/GitHub/OpenAI/token/private-key/card-shaped material.
- [ ] `P0` Add Docker build checks for every service.
- [ ] `P0` Add integration test for local simulator:
      Anvil + Phala simulator + email oracle + tinker fake backend + frontend.
- [ ] `P1` Add property tests for:
      settlement conservation, coordination reducer, policy fail-closed, bounded
      output schema, revocation behavior.
- [ ] `P1` Add browser tests for:
      Tinker auth mock, Stripe mock, reviewer queue, deal creation, result page.
- [ ] `P1` Add load tests for:
      many rooms, many OTP requests, chain watcher reorgs, evaluator timeouts.
- [ ] `P1` Add disaster tests:
      CVM restarts during evaluation, chain watcher misses event, Tinker outage,
      browser crash, cleanup failure.
      - [x] Cover an interrupted evaluation restored from versioned
            dstack-sealed active state, death after signed-transaction prepare,
            exact-hash manual hold on restart, lease contention, canonical
            block-hash reorg quarantine, and a second death between cursor
            rewind and public-state compensation.
- [ ] `P2` Add reproducibility test:
      clean checkout -> build images -> same digest/compose hash or explainable
      delta.

## Milestone 11: Operational Deployment Tasks

- [ ] `Deploy` Create/fill `.env` locally from `example.env` without committing
      secrets.
- [ ] `Deploy` Re-verify and unlock Foundry keystore account `dev` for the fresh
      Base Sepolia release without exposing its password. The alias and a
      historically funded address were confirmed, but the current activation
      run has no usable noninteractive unlock input. The 2026-07-08 balance is
      historical, not proof of present deployment readiness.
- [x] `Deploy` Verify Cloudflare Wrangler login for frontend deployment.
      Reverified 2026-07-13 with Pages write access for account
      `956388df29525b9e06f81581b485a571`.
- [ ] `Deploy` Restore and verify Phala CLI authentication for the new operator
      release. The 2026-07-08 `g-structure` / `wiki` / `wikigen` result is
      historical. Current checks either report unauthenticated or reject the
      available API-key response shape, so no fresh CVM may be deployed yet.
- [x] `Deploy` Verify Docker registry credentials and decide permanent registry.
      - [x] Add GHCR as the CI image publication path for deploy-critical
            TEE images.
      - [x] Run the GitHub image workflow, verify published image attestations,
            and record final image digests.
            Refreshed 2026-07-08 for commit
            `b49ff2ca678d8860cccd69fb38a385dbc853bfbc` with GitHub Actions run
            `28941069823`.
            Refreshed again 2026-07-08 for bounded oracle/delegate commit
            `81e3188591aadba26ab124217624e6341d2def74` with GitHub Actions run
            `28945611577`.
            Refreshed again 2026-07-08 for main-CVM mailbox-genesis evidence
            commit `1acdebd0c1e07c03b57533852985ac174d4f1261` with GitHub
            Actions run `28947685641`.
            Refreshed again 2026-07-08 for bounded Tinker bootstrap evidence
            commit `24ba5edf3b9d56429499bdcd602b3a808e37ba12` with GitHub
            Actions run `28949229390`.
            Refreshed again 2026-07-08 for bounded early-stage bootstrap
            receipts commit `74ad4b6d7359d418507d131a5f30ad7e541987af` with
            GitHub Actions run `28952111920`.
            Refreshed again 2026-07-08 for preserved bounded bootstrap error
            kind commit `8fb6e3a7dac3ef58f1e4c1e902a36ebd612b910e` with
            GitHub Actions run `28954112809`.
            Refreshed again 2026-07-08 for bounded selector-probe endpoint
            commit `ca877db2d02ee4498d30560f19d4d394cf165676` with GitHub
            Actions run `28957360340`.
            Refreshed again 2026-07-08 for bounded browser-readiness diagnostics
            commit `a2e14b542314a16e07f20a17694e9da1a67b1f1c` with GitHub
            Actions build run `28958905325`.
            Refreshed again 2026-07-08 for bounded raw CDP WebSocket diagnostic
            commit `7973b27d27a3d3fba3a24efcc23c89498e8a04bf` with GitHub
            Actions build run `28960362186`.
            Refreshed again 2026-07-08 for bounded post-upgrade CDP protocol
            probe commit `59a9eac5d22f9834d74e3f263de2f46130a0a898` with
            GitHub Actions build run `28961851866`.
            Refreshed again 2026-07-08 for bounded Runtime-enable CDP
            diagnostic commit `9d6936434aab24eb3513abe7b5e862c1802da022`
            with GitHub Actions build run `28971028987`.
            Refreshed again 2026-07-08 for bounded direct page-target Runtime
            diagnostic commit `bf39f569840f348c639be9fe0a8928f3360d9835`
            with GitHub Actions build run `28972610369`.
            Refreshed again 2026-07-08 for bounded `Page.enable`
            discriminator commit `556387a9e673e91d3ea4991cdaee96ead3e52922`
            with GitHub Actions build run `28974675082`.
- [ ] `Deploy` Rebuild and publish pinned images for:
      email oracle, tinker delegate, Neko/browser sidecar, props room, frontend
      worker if any.
      - [x] Refresh deploy-critical oracle/delegate funding-validation images
            from current source. Done 2026-07-09: GitHub Actions run
            `28991312580` published and attested
            `tee-email-oracle@sha256:f6103cd24ba2f63c859b55f5c1caab43fec92db9ac49009c7fdf0a07ffd9a7e3`
            and
            `tinker-delegate@sha256:17f22d8e87f774717a1989f1501ea659ad13bf409e7d601af6cf7b1c1fdc7381`
            from source
            `eb3bde3b5b156dfdd46f701ab2df8f1f19d94120`.
- [ ] `Deploy` Deploy the fresh seven-CVM topology with final image digests and
      five independently controlled QVL roots. The following combined-CVM
      record is historical only and does not satisfy this item.
      Refreshed 2026-07-08: CVM `670b3b21-4338-4d4e-ae72-7c8922579f59` /
      `cvm_1w85mGjo` now
      runs oracle image
      `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:43bf7d096bdd0e56b8fa95c23325513ba09825114de16e23fb578169cb8a3e42`
      and delegate image
      `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:c43ac01ee461aca4b49bbfe77d55491cfac8bb3dc70907c84a7b40b34657c277`.
      Refreshed 2026-07-08 again from source
      `556387a9e673e91d3ea4991cdaee96ead3e52922`: the normal Phala compose now
      runs oracle image
      `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3`
      and delegate image
      `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38`.
      The Phala compose now hardcodes these digests and the disabled
      secret-bearing gates rather than passing them through encrypted env
      values, so the live attested compose hash changes when the deploy-critical
      image refs change. The current normal profile is live at attested compose
      hash `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`
      with narrowed `allowed_env_count=7`. Live update with disabled public
      logs/sysinfo succeeded, but Phala still reports `dstack-dev-0.5.9` /
      `is_dev=true`.
      Refreshed 2026-07-09 for the temporary funding-validation profile from
      source `eb3bde3b5b156dfdd46f701ab2df8f1f19d94120`: CVM
      `cvm_1w85mGjo` now attests compose hash
      `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`
      with oracle image
      `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:f6103cd24ba2f63c859b55f5c1caab43fec92db9ac49009c7fdf0a07ffd9a7e3`
      and delegate image
      `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:17f22d8e87f774717a1989f1501ea659ad13bf409e7d601af6cf7b1c1fdc7381`.
- [ ] `Deploy` Verify CVM endpoints:
      `/health`, `/attestation`, oracle `/pin` auth rejection, delegate status,
      browser CDP internal-only or protected.
      - [x] Delegate `/health` returns `status=ok`, oracle `/health` returns
            `status=ok` with `oracle_ready=true`, `imap_connected=true`, and
            only the sealed mailbox hash, and containers are healthy/running.
      - [x] Delegate `/attestation?context=artifact` verifies with
            `verify-cvm-attestation`.
      - [x] Oracle `/pin` rejects unauthenticated requests with `401 Bearer
            token required`.
      - [x] Public CDP gateway probe returns host-header rejection rather than
            a usable `/json/version` browser-control response.
      - [x] Oracle `/attestation?context=oracle-credentials` returns a live
            TDX credential-ingress envelope, and `POST /credentials/encrypted`
            rejects while disabled by default.
      - [x] `verify-deployment-bundle` passes against the live log-hardened
            Phala deployment with GitHub image provenance/SBOM checks, required
            sidecar digests, local raw compose hash
            `ddd344213f29769cebd3c0caef8ff990628f5422b4295346ee84a8072a3c5adf`,
            and live attested compose hash
            `382aa6c881d477724552f4445157afbcd75738ee1feb9603b982b75ec4e82c2c`.
            Refreshed 2026-07-08: `verify-deployment-bundle` also passes
            against source `556387a9e673e91d3ea4991cdaee96ead3e52922`, oracle
            image
            `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3`,
            delegate image
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38`,
            local raw compose hash
            `1a4870ab818fe2d8d5e59c6c84ada795a36210c3ea5a0d2bc16d342bfdbb87f5`,
            rendered compose SHA-256
            `9c664e88ba1c79108f6f9c2987f667aa2e6ee6fa853b19277c7a8f8abfd43441`,
            and live attested compose hash
            `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`.
            Refreshed 2026-07-09: `verify-deployment-bundle` also passes
            against the temporary funding-validation profile from source
            `eb3bde3b5b156dfdd46f701ab2df8f1f19d94120`, oracle image
            `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:f6103cd24ba2f63c859b55f5c1caab43fec92db9ac49009c7fdf0a07ffd9a7e3`,
            delegate image
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:17f22d8e87f774717a1989f1501ea659ad13bf409e7d601af6cf7b1c1fdc7381`,
            local image-policy hash
            `c6398343e7ab1c82932b1c2ab1e7450626f932016b1939a571e092ee465a22c7`,
            rendered compose SHA-256
            `b87cbfa8b8d956d8b8d3840b3c47394e956940f4eb1412f57f4ea91fa8f6ab2b`,
            and live attested compose hash
            `b3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`.
      - [ ] `Blocker` Fix current Phala public gateway timeout for the Python
            delegate/oracle services before any further real-card top-up
            attempt. Evidence from 2026-07-09: debug redeploy with public
            logs/sysinfo reports live compose hash
            `a479a1ca1595e7b717e8c8e28ea60dfcef5430bb7792800180453a6b3790aa89`;
            delegate logs show internal `/health` and
            `/attestation?context=billing` `200 OK`, but local curl/httpx
            clients receive zero bytes from the public 8080/8000 endpoints
            after 60-90 seconds. Neko 52000 responds and CDP 9222 returns the
            expected host-header rejection. Also resolve oracle IMAP TLS EOFs
            against `mail.cock.li:993`.
            - [x] Reproduced locally and fixed the delegate event-loop
                  starvation cause by moving blocking synchronous API handlers
                  to FastAPI's threadpool (`def` handlers). `tests/test_api_event_loop.py`
                  proves `/attestation` is not blocked by slow oracle health.
            - [x] Build the fixed delegate image on GitHub, verify SLSA/SBOM
                  attestations, pin the digest in the Phala funding-validation
                  compose, and redeploy. Done from source
                  `9e72eec59f5ea784ffbe9d0702e1569bb1ac1a29` with delegate
                  digest
                  `5f53e8d09d53fc76b17155ce40bd51a0333a85c4e77a0e82a511551895f02995`;
                  the pin landed in `d4b325c`.
            - [x] Re-test live public `/attestation?context=billing` after the
                  delegate event-loop fix. Public attestation returned `200` in
                  about 1.7 seconds and public `/health` returned quickly
                  instead of zero-byte timing out.
            - [x] Source/test fix: make oracle `/health` non-mutating so Docker
                  healthchecks and delegate readiness probes do not reconnect
                  IMAP or create reconnect storms when the mailbox provider is
                  flaky. `/pin` now performs the real IMAP operation and updates
                  cached connection state. Follow-up source/test fix also
                  defers IMAP connection during FastAPI startup so a slow
                  mailbox provider cannot prevent `/health` and `/attestation`
                  from serving at all.
            - [x] Build the fixed oracle image on GitHub and verify SLSA/SBOM
                  attestations. Done from source
                  `2f2a7d9f94ca29261ce0f5352e289e5071c7e38e` with oracle
                  digest
                  `e0f8758018ac779fda402fb22a9fbd282fe107bd81222346307f81770869e1f4`.
            - [x] Pin the fixed oracle digest in the Phala funding-validation
                  compose. Local image-policy hash is
                  `40021d9b19956cbe962b8697b04c2f8c6467b80f8f290b2678c8650bd756c71e`,
                  rendered compose SHA-256 is
                  `ba674f8267972b2942aa7243127365aab0973812f8533b8abcdb173f59addd44`,
                  and Phala raw-compose hash is
                  `4124f22bca1ea7a3a6f8117ccdad4079d8d70c5bcfa930b2abff252b35938d5e`.
            - [x] Redeploy the health-only oracle funding-validation compose to
                  Phala and identify the remaining startup blocker. Live
                  `/attestation?context=billing` returned `200` in under a
                  second with compose hash
                  `917caeff047da50b79a4077233ad275d01a5edbbe51b63d19c6a21b58d9f408a`,
                  but oracle `/health` still disconnected because startup was
                  blocked in `IMAPClient.connect()`.
            - [x] Build, verify, and pin the startup-deferred oracle image.
                  Done from source
                  `03e4c356a19e96a51d8027389d99a7ef36c1d48a` with oracle
                  digest
                  `e5d641e1650fe08748017dead5870bf8bb7b844428899da2233030f631b80335`;
                  local image-policy hash is
                  `ecb54f8916b279d1e1968c0ca633aee0f6bef31dc2955af9d8351cbc984ab0fc`,
                  rendered compose SHA-256 is
                  `1ce5d1422b6de881cbc9e2e80063b031d68b815551039c80f5ccc57ec608f587`,
                  and Phala raw-compose hash is
                  `1f16c4a93adb3b09f29f7e6f7c97870ea781c4cca9c2dbf7d72a982a83e5a4b7`.
            - [x] Redeploy the startup-deferred oracle image to Phala.
                  Live compose hash is
                  `1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28`.
            - [x] Re-test live public `/health`, `/attestation?context=billing`,
                  and `/billing/funding-preflight` before approving any new
                  compose hash on-chain. Public delegate attestation returned
                  `200` with a TDX quote, public oracle health returned `200`
                  with `status=degraded` / `imap_connected=false`, delegate
                  health returned `200`, and endpoint-level `$10`
                  funding-preflight returned `ready=true`.
            - [x] Approve live compose hash
                  `0x1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28`
                  in `TinkerAccountEncumbrance` before any add-balance packet.
                  Done in tx
                  `0x9caf683b80b3c06a8b5de0f8ebeffcfd44d5a6f0305c285df9f32fdb687e402e`
                  at block `43910712`; read-back returned `true`, and
                  encumbrance preflight returned `allowed=true`.
      - [ ] `Deploy` Revert the 2026-07-09 public logs/public sysinfo/dev-SSH
            diagnostic exception after collecting enough evidence; record the
            reverted live compose hash and rerun `verify-cvm-attestation`.
            Current exception reopened 2026-07-09 for the Tinker funding and
            proxy issue/deployment-policy validation push:
            `phala cvms get` reports `public_logs=true`,
            `public_sysinfo=true`, `public_tcbinfo=true`, dev OS
            `is_dev=true`, `secure_time=false`, and browser/CDP debug ports
            exposed on the funding-validation CVM. This is explicitly
            temporary and must not be described as production deployment.
      - [x] Redeploy the fresh bounded-signup Tinker delegate image to the
            main CVM and re-run live health, attestation, credential endpoint,
            and add-balance endpoint gates.
            Done 2026-07-08: live delegate image
            `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:c43ac01ee461aca4b49bbfe77d55491cfac8bb3dc70907c84a7b40b34657c277`
            is GitHub-attested from commit
            `bf39f569840f348c639be9fe0a8928f3360d9835`; `/pin` rejects
            unauthenticated requests with `401`, `/browser/readiness` and
            `/browser/selector-probe` reject while disabled with `403`,
            `/credentials/encrypted` is closed on the delegate port with `404`,
            and `/billing/add-balance` rejects while disabled with `403`.
      - [x] Revert temporary Phala public-log debug posture on the main CVM
            before any real mailbox, OTP, Tinker API-key, or card material is
            handled.
            Done 2026-07-08: redeployed the log-hardened pinned compose with
            public logs off, public sysinfo off, and secret-bearing gates still
            disabled.
      - [ ] Move the main Phala CVM off dev OS before production wrap-up.
            Evidence 2026-07-08: `phala cvms get` still reports
            `dstack-dev-0.5.9` / `is_dev=true`; attempts to update with
            `--image dstack-0.5.10-4c9bd024 --no-dev-os` and
            `--image dstack-0.5.10 --no-dev-os --prepare-only` failed in the
            Phala CLI/API with a required `correlationId` validation error. A
            later compose/image update using `--no-dev-os` succeeded, but the
            live CVM still reported the dev OS afterward.
      - [ ] Before production wrap-up, remove or disable every temporary
            Phala debug posture used during oracle genesis work: public logs,
            public sysinfo, SSH/dev OS access, exposed browser/CDP debug ports,
            and the standalone oracle-genesis debug compose.
      - [ ] Verify credential provisioning with real mailbox credentials,
            Tinker API-key capture, and funded billing flow inside the
            deployed CVM.
- [x] `Deploy` Deploy or update Base Sepolia contracts with the chosen vNext
      interfaces.
      - [x] Verify the historical deployed contracts are not controlled by the
            current funded operator deployer and record that evidence in the
            deployment manifest.
      - [x] Add a no-raw-key deploy helper at
            `⚙️/tinker-delegate/contracts/scripts/deploy-base-sepolia.sh` that
            builds, tests, dry-runs, broadcasts with Foundry `--account dev`,
            performs on-chain reads, and rewrites the manifest.
      - [x] Broadcast fresh current-operator `DiligenceRoom` and
            `EmailOracleAuth` contracts from an interactive terminal so Foundry
            can prompt for the encrypted keystore password.
            Done 2026-07-08: `DiligenceRoom` deployed at
            `0x5d8a18628b4c8427eea89aa5498d81ff5ad3f423`
            (`0xfa50ada33f0a2c9f434c58b6cadf98defa01302b7c3e444116c021370d28169e`)
            and `EmailOracleAuth` deployed at
            `0xf52c18a33bd172ae94282132649d80bcd4b872ff`
            (`0xa29d749517a69f868db1785c7f091ea75f60a76ef657badedb0848e44be7a349`).
            On-chain reads confirm the funded `dev` deployer is the
            DiligenceRoom developer and EmailOracleAuth owner.
      - [ ] Redeploy `DiligenceRoom` after the verifier-signature
            `submitResult()` ABI change, set `DILIGENCE_RESULT_VERIFIER`, and
            record `resultVerifier()` in `deployments/base-sepolia.json`.
      - [x] Deploy `TinkerAccountEncumbrance`, set initial account commitment,
            compose hash, add-balance/spend caps, and record the address/policy
            in `deployments/base-sepolia.json`.
            - [x] Source/helper and dry-run are ready. Done 2026-07-08:
                  dry-run used account commitment
                  `0x535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`,
                  compose hash
                  `0xa43a894e6c0a6e0976f94e86f11050301b46093dad03e065ee91fda98fcf456d`,
                  `$5` add-balance/spend caps in policy units, Base Sepolia
                  chain ID `84532`, funded deployer
                  `0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, `forge build
                  --sizes`, 9 focused Foundry tests, and a successful
                  simulation estimating `0.00001471492 ETH`.
                  The manifest now points at refreshed compose hash
                  `0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`;
                  the next interactive helper run will use that current hash.
            - [x] Broadcast the helper from an interactive terminal so Foundry
                  can unlock keystore account `dev`, then verify code and
                  on-chain policy reads. Done 2026-07-09: broadcast tx
                  `0x7679df09aa2e939d748be0e017f380f5e7e44331a482531380198e93bdcaed01`
                  deployed
                  `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`; local
                  `cast code` returned nonzero bytecode, `owner()` returned
                  `0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, and
                  `approvedComposeHashes(0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7)`
                  returned true.
- [ ] `Deploy` Verify contracts on BaseScan.
- [ ] `Deploy` Register compose hashes in `EmailOracleAuth`.
	- [x] `Deploy` Register consumer app/compose hash for Tinker delegate.
	      Done for the current operator-validation Tinker delegate lane on
	      2026-07-09: `TinkerAccountEncumbrance` approved the latest live
	      proxy issue/deployment-policy app-compose hash
	      `0x40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace`
	      in tx
	      `0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6`
	      at block `43928500` after `verify-cvm-attestation` passed for the
	      digest-pinned policy-gated image. Production registration still
	      requires hardened non-dev CVM posture.
- [x] `Deploy` Create a test Tinker account under TEE custody.
      Done for the current operator-validation CVM: live reauth succeeds
      through the TEE-held email oracle path, the delegate has sealed Tinker
      browser/session/API-key state, and bounded card-on-file status can be
      queried without card details. Production custody still requires removing
      the temporary debug posture.
- [x] `Deploy` Fund the Tinker account through the chosen safe route.
      Done for the one-off operator-owned capped validation route on
      2026-07-09: attested compose
      `a15af6d8e7262d7d2799fa31968c568933f3468771b808720583a6dc6ed998c5`
      was approved in `TinkerAccountEncumbrance`, packet
      `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` reached
      `add_balance_submitted` with `raw_secret_egress=false`, packet replay
      verification passed with deployed attestation, and bounded balance read
      returned `$10.00`. The add-balance receipt remains intentionally
      conservative because it did not observe explicit success copy.
- [ ] `Deploy` Run a tiny funded Tinker job and record the attestation.
      Blocked 2026-07-09: client-config diagnostic Phala compose
      `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180`
      is deployed, attested, and approved for `SPEND_TINKER_COMPUTE`, but the
      real smoke still fails before training creation at
      `sdk_error.failure_site=service_client_create` with
      `sdk_error.operator_action=check_sdk_client_configuration`,
      `project.configured=false`, and bounded
      `client_config.project_id_argument=omitted`. Next step: obtain the
      correct Tinker project/client/base-url settings, seal them into the live
      CVM with `tinker-client-config --api-url ... --install`, verify bounded
      proxy status reports `project_id_configured=true`, then rerun smoke. A
      redeploy/compose approval is required only if the running CVM does not yet
      include the sealed client-config store source. Follow-up 2026-07-09: a
      newer pinned client-config install compose is now running and attested at
      `1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`,
      but that live hash is not yet approved on-chain. The account remains
      funded enough for the tiny smoke path: bounded balance read returns
      `$10.00` without card details. Next required actions are approval of
      `0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`
      and sealing `TINKER_PROJECT_ID`.
- [ ] `Deploy` Create a synthetic test room on Base Sepolia.
- [ ] `Deploy` Fund the synthetic test deal.
- [ ] `Deploy` Upload encrypted synthetic artifact.
- [ ] `Deploy` Run evaluator.
- [ ] `Deploy` Submit result on-chain.
- [ ] `Deploy` Accept/reject/expire the deal and withdraw funds.
- [ ] `Deploy` Confirm cleanup of artifact and checkpoints.
- [x] `Deploy` Deploy frontend to Cloudflare Pages.
      The current twelve-route source candidate is available only on the
      explicit `modeled-preview` preview branch. The production branch and
      custom domains remain unchanged.
- [x] `Deploy` Preserve the prior nine-route clean-browser smoke evidence.
      Historical check against `https://wikigen.me`: all then-nine routes, wallet
      dialog/focus behavior, 390x844 responsive navigation, overflow, and
      browser error logs passed. No injected wallet was present; the UI
      truthfully rendered WalletConnect as unavailable when no project ID was
      configured. This does not validate the current twelve-route candidate.
- [ ] `Deploy` Complete in-app-browser visual QA and a clean-browser smoke test
      for all twelve current routes on the modeled preview before promoting any
      production frontend release.
- [ ] `Deploy` Archive deployment evidence:
      git SHA, image digests, compose hash, quote, tx hashes, screenshots, logs
      with secrets redacted.

## Milestone 12: Demo Ladder

### Demo 1: Honest Current Demo

- [ ] `P0` Show contracts deployed and verified.
- [ ] `P0` Show live Phala CVM health and quote.
- [ ] `P0` Show email oracle receives OTPs and the one-off capped Tinker
      funding validation, but do not claim production/repeated Tinker funding
      is solved.
- [x] `P0` Make evaluator activation explicit and prevent synthetic results
      from masquerading as live TDX-backed evidence. Done 2026-07-13:
      `disabled` is the process default, `stub` is local-only and rejected in
      dstack, and `sft` is accepted only in a real non-simulator dstack CVM.
- [ ] `P0` Show local stub evaluation with an unmistakable modeled label, then
      separately prove a real SFT evaluation in the replacement CVM.
- [ ] `P0` Show Base Sepolia fund -> result -> accept/reject/expire.

### Demo 2: End-To-End Synthetic DNAI

- [ ] `P0` Synthetic private artifact upload encrypted to TEE.
- [ ] `P0` Buyer funds escrow with cap.
- [ ] `P0` Evaluator runs inside TEE.
- [ ] `P0` Result hash and bounded band submitted on-chain.
- [ ] `P0` Frontend verifies quote, compose hash, and chain events.
- [ ] `P0` Settlement and cleanup complete.

### Demo 3: Tinker-Funded Training

- [x] `P0` TEE-owned Tinker account exists.
      Done for the current operator-validation CVM; production custody hardening
      remains separate.
- [x] `P0` Tinker account has safe test funding.
      Done for the one-off capped validation lane: bounded balance read reports
      `$10.00` after the attested/approved `$10` add-balance packet.
- [ ] `P0` Isolated session runs tiny training.
      Still open: the deployed smoke reached API-key-loaded state but did not
      create a Tinker training run.
- [ ] `P0` Checkpoints are TTL-limited and cleaned up.
      Still open for deployed evidence: no real Tinker checkpoint exists yet
      because training creation failed before a run ID was issued.
- [ ] `P0` No weights, samples, raw artifact, or API key leave the TEE.
      Source-level bounded receipts are tested, but deployed no-egress proof
      over a real Tinker run is still absent because the run has not started.

### Demo 4: Bio Validation

- [ ] `P1` Use synthetic/non-sensitive bio data.
- [ ] `P1` Run SFT or TTT/RL validation.
- [ ] `P1` Apply dual-use screen.
- [ ] `P1` Release only bounded score/safety/methodology bands.
- [ ] `P1` Route ambiguous result to reviewer hold.

### Demo 5: Multi-Owner Coordination

- [ ] `P1` Two synthetic corpora.
- [ ] `P1` Fan-out gate per corpus.
- [ ] `P1` Unanimous consent for pass.
- [ ] `P1` One hold route to human reviewer.
- [ ] `P1` One restricted deny that consent cannot override.
- [ ] `P1` Joint attestation and per-owner royalty meters.

### Demo 6: DevProof Public Verification

- [ ] `P1` External user verifies:
      source, image digest, compose hash, quote, contract policy, result hash,
      settlement, and cleanup evidence.
- [ ] `P1` Public docs explain what is trusted, what is verified, and what is not
      yet guaranteed.

## Open Questions To Resolve

- [ ] `Research` Which private-reward security tier is acceptable for the first
      demo:
      all optimizer state inside TEE, attested remote trainer, or external LLM
      with only bounded feedback?
- [ ] `Research` If Tinker receives training updates, can it be included in the
      trusted boundary by attestation, contract, or policy? If not, what reward
      signals are forbidden from leaving the TEE?
- [ ] `Research` Which reward leakage budget is acceptable:
      no public reward egress, k-bit reward bands, noisy rewards, only final
      score, or differential privacy?
- [ ] `Research` What exact TTT-Discover biology task should be cloned first:
      OpenProblems-style single-cell denoising, synthetic denoising, or a safer
      toy computational-bio benchmark?
- [ ] `Research` What exact Tinker billing/funding flow is allowed by Tinker and
      Stripe?
- [ ] `Research` Should card details ever be delivered to the TEE, or should the
      system use a Stripe-hosted tokenization flow where the TEE only receives a
      payment method token?
- [ ] `Research` Should the Tinker account be one global TEE-owned account,
      per-sponsor, per-room, or per-corpus?
- [ ] `Research` What is the correct legal owner of the Tinker account and email
      account?
- [ ] `Research` Which jurisdiction/data-residency requirements matter for bio
      data?
- [ ] `Research` What is the minimum bio demo that is useful but cannot enable
      dual-use harm?
- [ ] `Research` When can candidate code be revealed?
      Public release is only safe if the code cannot encode private data,
      exploit reward overfitting, or reveal bio-sensitive methods.
- [ ] `Research` How much quote verification belongs on-chain vs off-chain?
- [ ] `Research` Can Phala/dstack expose enough platform provenance for the
      health/bio trust model, or do we need an explicit Proof-of-Cloud caveat?
- [ ] `Research` What should be represented on-chain:
      rooms, policies, grants, attestations, capabilities, result hashes,
      royalties, or only settlement?
- [ ] `Research` Should `wikigen` support public catalog/search before it can
      enforce private data policy?
- [ ] `Research` Is the first launch a developer demo, bio diligence product,
      private data marketplace, agent credential delegation product, or all of
      those staged separately?

## Suggested Immediate Next Build Order

1. [x] Track `PROJECT.md`, `ARCHITECTURE.md`, and this `TODO.md`.
2. [x] Fix stale Tinker status in `⚙️/tinker-delegate/SPEC.md`.
3. [x] Define the `PrivateRewardEnvironment` interface and leakage model.
4. [x] Build a fake private-reward environment with a synthetic hidden dataset.
       `SyntheticHiddenKeywordEnvironment` plus
       `synthetic-private-reward-demo` now provide a replayable local bounded
       private-reward proof over a synthetic hidden dataset.
5. [x] Fix `tinker-delegate` Docker install so the Tinker SDK path is present in
       the deployed image.
       Dockerfile installs `uv sync --frozen --no-dev --extra agent`, and
       `scripts/verify-agent-image.sh` verifies the optional Tinker SDK import
       inside the built delegate image. Fresh Phala CVM validation remains
       separate because no CVMs are currently deployed.
6. [x] Enforce oracle auth on scoped `/pin`; remove `/inbox`; make `/email`
       commitment-only. Runtime bearer auth and optional on-chain
       `EmailOracleAuth` consumer registry enforcement are implemented locally.
       Base Sepolia compose-hash registration remains a separate deployment
       step.
7. [ ] Add chain watcher + TEE chain signer for `DiligenceRoom`.
       Local watcher, signer/broadcaster plumbing, dstack-simulator
       `submitResult()` broadcast, and a local synthetic-room-to-Anvil
       settlement proof now exist. Remaining proof is deployed Phala
       CVM-originated broadcast plus measured-code binding.
8. [x] Build a fake Tinker backend and full local synthetic room test.
       Done 2026-07-09: source now includes a deterministic fake Tinker backend
       and local synthetic room harness. The focused regression encrypts a
       private artifact to the local TEE key, uploads it through
       `/deal/{deal_id}/artifact/encrypted`, evaluates through
       `IsolatedTinkerSession`, resolves the deal, verifies artifact zeroing
       and checkpoint cleanup, and asserts the public modeled packet contains
       only hashes, bands, counts, booleans, and `raw_secret_egress=false`.
       Companion script
       `⚙️/tinker-delegate/scripts/prove-local-synthetic-room-anvil.py` now
       connects that modeled room to real local `DiligenceRoom` submission,
       `DealAccepted` settlement, pull-payment bands, and cleanup through
       ephemeral Anvil and the dstack simulator. This still does not claim real
       Tinker SDK execution, deployed Phala evidence, Base Sepolia state, or
       frontend verification.
9. [x] Rework the one-shot deployed bootstrap browser path to headed Neko
       inside Phala.
       Done 2026-07-08 for `docker-compose.tinker-bootstrap.phala.yaml`; later
       funding-validation work superseded the initial signup blocker by proving
       deployed Tinker login, API-key sealing, reauth, and one-off capped
       funding through the main CVM. The remaining live Tinker blocker is now
       client configuration for SDK training creation, not browser bootstrap.
10. [ ] Obtain an official Tinker service-account/provider route that preserves
        the confidentiality and bounded-egress contract; do not evade provider
        bot or account controls.
11. [x] Prove safe Tinker account funding with a low-value test.
       Done 2026-07-09 for the one-off operator-owned capped validation lane:
       the deployed compose was attested and approved on-chain, the funding
       packet emitted only bounded receipts with `raw_secret_egress=false`, and
       a bounded balance read returned `$10.00`.
12. [ ] Enable real paid provider work only after the adapter exposes stable
       caller-supplied idempotency for every mutation and exact post-restart
       recovery/lookup semantics. The reproducibly pinned `tinker==0.22.7` does
       not satisfy that production contract. Upstream 0.23.0 was isolated-
       spot-checked after its 2026-07-15 release and still exposes no such key
       through the public paid-workflow signatures; adopting it would also
       require a separate locked upgrade review. Compute dispatch stays
       disabled.
13. [x] Replace the old frontend mockup with the twelve-route SolidJS product,
       including the modeled no-health-data-intake Health Guide.
14. [ ] Generate its live environment only after the fresh seven contracts,
       seven CVMs, five challenge-bound QVL roots, and every timelocked release
       state pass the release validator.

## External Alignment References

- Flashbots, "Mind the Gap - Where TEE Attestations Fall Short and Why Do TEEs
  Need Proof of Cloud": https://writings.flashbots.net/mind-the-gap-tee-poc
- Flashbots, "Sirrah: Speedrunning a TEE Coprocessor":
  https://writings.flashbots.net/suave-tee-coprocessor
- Teleport / Account-Link one-time account delegation:
  https://github.com/teleport-computer/teleport-gramine-rs
- Gramine attestation and secret provisioning reference:
  https://gramine.readthedocs.io/en/latest/attestation.html
- Andrew Miller research profile: https://soc1024.ece.illinois.edu/
