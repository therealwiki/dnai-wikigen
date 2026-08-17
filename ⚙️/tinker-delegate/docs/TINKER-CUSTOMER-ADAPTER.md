# Wallet-owned Tinker customer adapter

Status: **implemented, authenticated, and tested behind an explicit release
gate; production authority material, fresh deployment, and CVM/provider
activation remain pending**.

`tinker_delegate.tinker_customer_adapter` is the fail-closed authority layer
between a Base Sepolia wallet session and the sealed Tinker proxy. It does not
create an upstream account merely because a browser asks for one. It does not
accept or return a Tinker API key, Tinker project id, browser cookie, raw
account identifier, payment card field, provider identifier, prompt, training
example, dataset, checkpoint, raw run id, or provider output.

The customer surface is intentionally separate from all three existing lanes:

- `tinker_proxy.py` remains the operator/runtime proxy and historical scoped
  token implementation;
- Compute Console remains the wallet-owned project, device, service-credit,
  and exact-asset dispatch surface;
- the Compute execution worker continues to use sealed internal Tinker client
  configuration, never a customer credential.

`api.py` now exposes the bounded wallet lifecycle through the existing
`compute:console` wallet session. The complete adapter is assembled lazily by
`tinker_customer_runtime.py`, and only when
`TINKER_CUSTOMER_ENABLED=true`. Assembly requires one exact mode-0600 authority
document whose bytes match `TINKER_CUSTOMER_AUTHORITY_SHA256`, two independent
Base Sepolia RPC origins, a live release-bound `ExecutionPolicyAnchor` writer,
purpose-separated dstack keys, and independently signed runtime,
provisioning, and settlement evidence. Any missing or inconsistent dependency
returns a fixed `503`; there is no modeled-success fallback.

The routes being present is not evidence that the release is active. The
checked-in default and bootstrap descriptor are disabled. The generated
production descriptor accepts the exact `TINKER_CUSTOMER_ENABLED=true` marker
and authority digest only through the signed post-measurement environment
authority; no browser request can supply, override, or weaken the server-owned
authority document.

## Authority chain

Every state-changing call performs all of these checks before mutation:

1. When the call belongs to a customer, verify the existing Compute wallet
   bearer again with scope exactly `compute:console`. That token originates
   from a one-time Base Sepolia personal-sign challenge and the shared EOA / dual
   RPC EIP-1271 verifier.
2. Through `DualRpcTinkerReleaseReader`, require two distinct
   operator-configured HTTPS RPC providers to agree on Base Sepolia, one numeric
   finalized head number **and** hash, the exact `TinkerAccountEncumbrance`
   runtime code, and every release word at that numeric block. There is no
   minimum-head or bounded-lag fallback: a stale endpoint cannot drag the gate
   back to a historical pre-halt block.
3. Compare the live contract to an exact reviewed `ExpectedTinkerRelease`:
   owner, zero pending owner, immutable account commitment, release-policy
   commitment, frozen/not-halted flags, current and release caps, exact compose
   root/count/list/membership, and exact manager root/count/list/membership.
4. Obtain a fresh, at-most-300-second `RuntimeEvidence` lease. It must match the
   reviewed CVM identity, measurement, QVL policy, release authority, roles,
   account commitment, policy tuple, immutable customer-account-policy digest,
   admitted compose and manager, and enabled operation set. The six runtime
   policy digests are canonical, nonzero, and pairwise distinct; a zero
   measurement, QVL, role, or release-authority pin can never configure a
   passing gate. TDX and QVL must both be exact Boolean `true`; strings such as
   `"true"` or `"false"` and integers such as `1` are rejected rather than
   coerced. Raw quote/collateral disclosure and secret egress must each be exact
   Boolean `false`. Evidence timestamps must be exact integers, never Boolean,
   float, or numeric-string substitutes.
5. Account activation additionally consumes a separate, fresh, independently
   attested opaque account-binding handle. Equality with the contract's
   `bytes32` account commitment is necessary but never sufficient. The
   provisioning result must carry the exact shared
   `dnai.tinker-account-binding.v1` scheme, typed commitment/typehash, Base
   Sepolia Thinking Machines namespace, a distinct nonzero account-binding
   receipt digest, a distinct sealed binding-record hash, the exact final
   two-reviewer account-binding-ceremony receipt digest, and the exact reviewed
   deployment-intent digest. Those four commitments and the outer provisioning
   receipt hash must all be nonzero, canonical `sha256:` values and pairwise
   distinct. It must attest that the provider identity was checked and that the
   current provider session was rechecked for this activation. These are checks
   performed inside the independently attested provider boundary; they are not
   a claim that the provider's private internal identity was cryptographically
   disclosed or proven to the browser.
6. The binding result must explicitly set raw provider-account-id, binding-root,
   reviewer-share, provider-auth, provider-session, root/share-digest, and
   secret egress to false. The durable state and public receipt retain only the
   opaque receipt and sealed-record commitments, ceremony and deployment-intent
   lineage, plus bounded truth flags. Every provider Boolean is type-checked
   before projection; an untyped string, integer, list, or object cannot enter a
   public receipt. They never retain the provider identifier, binding root,
   either reviewer share, authentication material, or session material.
   The account record also commits the complete ceremony/deployment lineage.
   Every later active-account operation revalidates that immutable lineage
   against `ExpectedTinkerRelease`; credentials, encrypted associated data,
   reservations, and mutation receipts carry its digest, the normalized
   account-binding-authority digest, and the exact ceremony and deployment
   digests. Adapter construction audits every persisted account before startup
   completes. Restarting with different off-chain lineage therefore fails
   closed before the adapter can reuse an account or credential merely because
   the on-chain policy tuple is unchanged.
7. Treat every wallet, release reader, runtime-evidence, provisioning,
   settlement, and external-anchor exception as untrusted. The adapter replaces
   it with one fixed internal error code outside the originating exception
   context. Provider text, response bodies, identifiers, sessions, and
   authorization data are neither reflected nor persisted. Validation of a
   malformed object returned by those boundaries occurs inside the same fixed
   error wrapper; a hostile field accessor or equality implementation cannot
   reflect its exception.
8. Commit the complete candidate state to an exact mode-0600 authenticated
   pending file, compare-and-set its head through `CustomerStateAnchor`, and
   promote only the externally anchored successor. An ambiguous anchor response
   is reconciled on the next read; the mutation is never blindly replayed. Both
   the active and pending file are rejected on every read unless their mode is
   exactly `0600` (not merely “no group/other access”).

The external anchor is mandatory. A local HMAC alone detects modification but
cannot detect restoration of an older persistent volume. The production anchor
adapter uses a dedicated opaque resource head in the fresh release's
`ExecutionPolicyAnchor`, with the gateway's finalized/confirmation-bound
reconciliation. The contract sequence is global and can skip when unrelated
resources are anchored; the store therefore treats the authenticated 32-byte
resource head as the rollback witness and keeps its own exact local sequence.
There is no unanchored production mode.

The only external-boundary failure strings emitted by this module are
`TC_WALLET_VERIFIER_UNAVAILABLE`, `TC_RELEASE_READER_UNAVAILABLE`,
`TC_RUNTIME_EVIDENCE_PROVIDER_UNAVAILABLE`,
`TC_PROVISIONING_PROVIDER_UNAVAILABLE`,
`TC_SETTLEMENT_PROVIDER_UNAVAILABLE`, `TC_STATE_ANCHOR_READ_UNAVAILABLE`, and
`TC_STATE_ANCHOR_UPDATE_UNAVAILABLE`. Credential-envelope generation has the
same non-reflective boundary and emits
`TC_CREDENTIAL_ENCRYPTION_UNAVAILABLE`. They are stable internal
classifications, not wrappers around an upstream message.
Malformed, noncanonical, low-order, or all-zero X25519 recipient keys are
rejected before any live gate or mutation with the single stable customer-input
code `TC_RECIPIENT_X25519_INVALID`.

## Customer account lifecycle

The account state machine is monotonic:

```text
requested -> active -> revoked
     |
     +--------> cancelled
```

- `request_account(wallet_token, mode, idempotency_key)` accepts only `create`
  or `link_existing`. It derives the account request commitment from the
  authenticated wallet, release tuple, and immutable server policy. The
  receipt explicitly says `upstream_account_exists: false` and
  `provisioning_performed: false`. There is no browser field for an upstream
  identifier or account commitment.
- `activate_account(account_id, idempotency_key)` is an internal method. It
  consumes an independently attested provisioning result from the injected
  `ProvisioningResultProvider`. The result must bind the exact request,
  owner-address hash, mode, frozen on-chain account commitment, exact versioned
  account-binding scheme and Thinking Machines namespace, independent binding
  receipt, sealed binding record, final two-reviewer ceremony receipt, reviewed
  deployment intent, release tuple, compose, manager, and current
  runtime-evidence digest. It must also attest a current provider-session
  recheck and all no-egress flags described above. The result's success,
  upstream-existence, identifier-egress, and account-binding truth fields must
  be exact Booleans. Only a successful result that satisfies this complete
  authority can activate the record. The currently checked-in fake provider
  exists only in local tests; no live Thinking Machines account or session
  success is claimed by this release.
- `revoke_account(...)` is terminal. It revokes all still-active credentials.
  Existing reservations remain explicit liabilities and require attested
  settlement or release; revocation never silently deletes them. A still
  unactivated `requested` account instead becomes terminal `cancelled`, retains
  zero activation/provisioning evidence, and never falsely claims that an
  upstream account existed.
- The same wallet cannot create a second account in the same store, including
  after revocation. A new authority grant requires a separately reviewed
  release/migration, not a reopen endpoint.

All create/link requests are idempotent. An exact retry returns the original
bounded result. Reusing a key with a different request conflicts. The
idempotency record is part of the same anchored transaction as the lifecycle
record.

## Customer credentials

Only an active account can issue a credential. The current release enables
`training` only. `inference` is a named capability but is rejected before
issuance and reservation until a compatible bounded provider adapter is
reviewed into the same release evidence.

The credential is a domain-separated HS256 JWT:

- issuer `dnai-wikigen:tinker-customer`;
- audience `dnai-wikigen:tinker-proxy`;
- key id `dstack-tinker-customer-v1`;
- a maximum 3,600-second lifetime, further capped by the immutable account
  policy;
- exact account, wallet hash, operation/scope, policy-unit cap, release tuple,
  generation-independent JWT id, and timestamps.

Each issuance or rotation can lower `max_operation_policy_units` below the
immutable account ceiling. It can never raise the ceiling. Reservation checks
the credential cap, immutable account cap, live on-chain cap, outstanding cap,
and lifetime cap independently.

The plaintext JWT exists only in memory long enough to encrypt it to the
customer's X25519 device public key. The response and idempotency record contain
the AES-256-GCM capsule, its associated data, and hashes. They never contain the
plaintext token. The durable credential record contains only its JWT-id hash,
recipient-key hash, scopes, caps, release binding, timestamps, and status.
Recipient keys must be canonical lowercase 32-byte hex and must produce a
non-null X25519 shared secret; low-order points such as the all-zero key are
rejected before token generation. The JWT and its encrypted associated data
also bind the exact ceremony digest, deployment-intent digest, release-lineage
digest, and normalized account-binding-authority digest.

`revoke_credential(...)` is terminal. `rotate_credential(...)` validates the
replacement first, revokes the old authority, and only then issues the new
capsule using deterministic child idempotency keys. There is never an
old-and-new overlap. If issuance fails after revocation, the old credential
remains revoked and an exact retry resumes the replacement. The rotation
receipt includes the exact live gate used by issuance, allowing a client to
bind the capsule's associated-data release digest to the outer receipt.

Each credential use checks both its HMAC signature and the active durable
record, so account or credential revocation immediately blocks new
reservations even if the JWT has not expired. Credential-list recovery uses a
schema-v2, newest-first page contract: 16 records by default and at most 64,
with exact total/page counts, `has_more`, `next_cursor`, and authenticated-store
`snapshot_sequence`. Ordering is strictly descending by
`(issued_at, credential_id)`, and revoked or expired durable records remain
page-accessible.

The cursor is an opaque, domain-separated HMAC token bound to the exact account,
store sequence, and last-record ordering anchor. A malformed, tampered,
cross-account, stale-sequence, or missing-anchor cursor returns `409 Conflict`
and requires a restart from the newest page; the service never falls forward
onto a different snapshot. Listing is query-only, caps cursor input at 1,024
bytes, and rejects request bodies. Each canonical response is constrained below
255 KiB (and therefore below the public 256 KiB ceiling). No page includes a
capsule, plaintext token, upstream key, or project identifier.

These customer credentials intentionally use a new authentication domain. The
existing operator `/tinker/train` route does not accept them. The separate
`/tinker/customer/train` route verifies this adapter's credential, re-runs the
live gates, durably reserves and claims authority, and only then enters the
sealed SDK path. They are not Compute worker credentials and do not contain the
upstream Tinker key or project id.

## Spend authority receipts

`reserve_spend(...)` accepts only:

- a customer credential;
- operation `training` in this release;
- an exact positive integer in unitless on-chain policy units;
- a `sha256:` workload commitment;
- an idempotency key.

The local HMAC credential, lifetime, operation, and complete immutable release
lineage are verified before either live RPC/evidence read, so arbitrary invalid
tokens cannot amplify into expensive dual-RPC and QVL work. A valid credential
does not skip safety: the exact live release and runtime-evidence gates are
still re-read under the mutation lock immediately before the anchored
reservation.

The amount must fit all of the current on-chain spend cap, immutable
per-operation customer cap, outstanding cap, and lifetime cap. Admission moves
authority from available headroom into one explicit `reserved` record. It does
not dispatch a provider, move ETH/USDC, mint a token, debit a credit ledger, or
top up the upstream account.

`finalize_reservation(...)` is internal and consumes a one-shot
`AttestedSettlementResult`. A reservation can move only once:

```text
reserved -> settled
reserved -> released
```

The result is bound to the reservation commitment, current release tuple, and
fresh runtime-evidence digest. Actual units cannot exceed reserved units; a
released reservation must settle zero, and every settled/released result must
carry a canonical nonzero usage-receipt commitment. Public receipts state
`provider_authoritative_billing: false` and `authority_accounting_only: true`.
They are exact bounded authorization records, not Tinker invoices or payment
receipts. `provider_dispatch_performed`, `provider_authoritative_billing`, and
`raw_secret_egress` must each be exact Booleans before projection. In
particular, a provider-owned object or string can never occupy the public
`provider_dispatch_performed` field.

### At-most-once customer training

`POST /tinker/customer/train` is the one customer execution surface in this
release. It accepts the lower-authority credential and exactly three strict
integer controls: `max_usd_micros` (1–5,000,000), `steps` (1–50), and
`ttl_seconds` (60–3,600). There is no browser field for a model, prompt,
training example, dataset, checkpoint, provider account, provider credential,
or payment method. The exact release chooses the model, LoRA rank, compose, and
built-in bounded examples; its workload commitment states explicitly that
browser-supplied examples are not accepted.

The execution service reserves the requested micro-USD policy ceiling through
the customer adapter and commits a durable dispatch claim before entering the
sealed Tinker SDK. An exact retry after that claim may only recover a previously
signed training result and finalize it; it never calls the provider again. If
the provider boundary was attempted but no exact success can be proven, or if
result publication/finalization becomes uncertain, the service returns a
bounded `409` reconciliation receipt with
`automatic_provider_redispatch: false`. The reservation remains explicit for
operator reconciliation instead of being guessed settled or released.

A proven pre-dispatch failure signs a zero-actual-unit release. A proven
completed run signs a settlement that consumes the requested fixed ceiling.
That deliberately conservative amount is authority accounting, not metered
provider billing: every receipt states
`provider_authoritative_billing: false`,
`authority_accounting_only: true`, and `fixed_ceiling_accounting: true`.
The public result contains only bounded stage/outcome fields, hashes, bands,
step counts, booleans, reservation commitments, and signed settlement
commitments. It contains no provider response, raw run identifier, output,
checkpoint path, upstream secret, or private training material.

## Public receipt surfaces

All receipts use fixed schemas and set `raw_secret_egress: false`:

| Surface | Producer | Important state |
| --- | --- | --- |
| `tinker_customer_account_request` | wallet request | `requested`; no upstream-existence claim |
| `tinker_customer_account_activation` | attested internal result | `active`; exact account/release binding |
| `tinker_customer_credential_issue` | active wallet owner | encrypted capsule, scope/cap, JWT-id hash |
| `tinker_customer_credential_rotation` | active wallet owner | old authority revoked before encrypted replacement |
| `tinker_customer_credential_revoke` | wallet owner | terminal `revoked` |
| `tinker_customer_spend_reservation` | scoped credential | exact reservation and workload commitments |
| `tinker_customer_spend_finalization` | attested internal result | `settled` or `released`; not provider billing |
| `tinker_customer_training_execution` | at-most-once customer runner | bounded signed result plus settled/released authority accounting |
| `tinker_customer_training_reconciliation` | claimed uncertain execution | durable hold; automatic provider redispatch false |
| `tinker_customer_account_revoke` | wallet owner | terminal account and credential revocation |
| `tinker_customer_account_status` | wallet owner read | bounded counts and policy-unit totals |
| `tinker_customer_credentials` | wallet owner read | bounded status/cap metadata; no capsules |

Each mutation receipt carries the agreed finalized block and hashes of the
release observation, policy tuple, and independent runtime evidence. An account
activation receipt additionally carries the exact ceremony and deployment
intent digests both at the top level and inside its immutable account-binding
authority. Every active-account credential, reservation, finalization,
credential revocation, and account-revocation receipt repeats the release
lineage and normalized authority digests so a replay cannot silently cross an
off-chain ceremony. It does not carry a raw quote, collateral, signature,
wallet address, or upstream provider identity.

## Runtime assembly and authority

The API integration now injects these server-owned objects, never
browser-selectable alternatives:

- the existing singleton `ComputeWalletAuthService` as `CustomerWalletVerifier`;
- two `BoundedJsonRpcClient` instances configured from the private wallet-auth
  Base Sepolia RPC URLs;
- `ExpectedTinkerRelease` built only from the signed exact release authority,
  never from request JSON; it must include the exact final account-binding
  ceremony receipt digest and reviewed deployment-intent digest;
- `SignedRuntimeEvidenceProvider`, backed by an independently signed exact
  runtime/QVL/TDX evidence envelope;
- `SignedProvisioningResultProvider`, backed by account-id-named signed
  provisioning envelopes in a mode-0700 private directory;
- `SignedSettlementResultProvider`, backed by reservation-id-named signed
  settlement envelopes in a separate mode-0700 private directory;
- `ExecutionPolicyCustomerStateAnchor` for the release-pinned
  `ExecutionPolicyAnchor` resource;
- a `TinkerCustomerStore` in a dedicated private persistent directory;
- a dstack-derived, domain-separated customer-store HMAC key at
  `tinker/customer_store_integrity`;
- a different dstack-derived, domain-separated customer-credential signing key
  at `tinker/customer_credentials`;
- a third dstack-derived settlement-evidence Ed25519 key at
  `tinker/customer_settlement_evidence`, whose public key must exactly match the
  final authority before the initializer writes it.

Exact runtime config:

```text
TINKER_CUSTOMER_ENABLED=false
TINKER_CUSTOMER_AUTHORITY_B64=<canonical-base64url-no-padding-authority>
TINKER_CUSTOMER_AUTHORITY_PATH=/sealed/tinker-customer/authority.json
TINKER_CUSTOMER_AUTHORITY_SHA256=sha256:<exact-authority-bytes>
TINKER_CUSTOMER_STORE_PATH=/data/tinker-customer/state.json
TINKER_CUSTOMER_STORE_INTEGRITY_KEY_PATH=tinker/customer_store_integrity
TINKER_CUSTOMER_CREDENTIAL_KEY_PATH=tinker/customer_credentials
TINKER_CUSTOMER_SETTLEMENT_KEY_PATH=tinker/customer_settlement_evidence
```

`TINKER_CUSTOMER_STORE_INTEGRITY_KEY` and
`TINKER_CUSTOMER_CREDENTIAL_SIGNING_KEY` and
`TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY` are explicit local-test-only inputs.
They are forbidden in a real dstack runtime, where all three keys must be
purpose-separated and derived inside the CVM. Before the API starts, the
networkless `tinker-customer-authority-init` process decodes the signed final
environment's canonical base64url authority, verifies its exact SHA-256 and
settlement public key against the dstack-derived signer, and creates the
mode-0600 sealed file exactly once. An exact restart is idempotent; different
bytes fail closed. The initializer never creates or contacts a provider
account and never emits authority bytes. The authority document contains exact top-level
`expected_release`, `account_policy`, `runtime_evidence_policy`, and `evidence`
objects. Its evidence object pins three distinct Ed25519 public keys, absolute
private evidence paths, and the nonzero opaque anchor resource hash.

The existing private
`TINKER_WALLET_AUTH_RPC_URL` and
`TINKER_WALLET_AUTH_RPC_URL_SECONDARY` should be reused. The adapter must not
add a browser-selectable RPC URL. All release identity fields should come from
the exact signed release artifact rather than duplicated mutable environment
variables. In particular, the runtime evidence policy's
`customer_policy_digest` must come from that artifact and exactly equal the
adapter's domain-separated recomputation over operation scope, all three spend
caps, credential TTL, active-credential cap, and the explicit disabled/roadmap
flags. A value assembled independently at process startup is not sufficient.

Implemented wallet/browser routes:

```text
POST /tinker/customer/accounts/requests
GET  /tinker/customer/accounts/current
GET  /tinker/customer/accounts/{account_id}
POST /tinker/customer/accounts/{account_id}/credentials
GET  /tinker/customer/accounts/{account_id}/credentials?limit=16&cursor={opaque}
POST /tinker/customer/accounts/{account_id}/credentials/{credential_id}/rotate
POST /tinker/customer/accounts/{account_id}/credentials/{credential_id}/revoke
POST /tinker/customer/accounts/{account_id}/revoke
POST /tinker/customer/reservations
POST /tinker/customer/train
```

Activation and reservation finalization must remain runtime-authenticated
internal routes or resident worker calls. They are not wallet/browser mutation
surfaces:

```text
POST /tinker/internal/customer/accounts/{account_id}/activate
POST /tinker/internal/customer/reservations/{reservation_id}/finalize
```

Every Pydantic request model must use `extra="forbid"`; error responses must
not reflect rejected values. The account request model has only `mode`. It has
no account commitment, upstream identifier, email, key, project, cookie, or
funding field. All mutations require the existing bounded `Idempotency-Key`
syntax. Internal adapters must preserve the fixed non-reflective error codes
defined by this module; a route or logger must not unwrap an upstream exception
or serialize its original message. All Tinker customer POST bodies are capped
at 4 KiB by ASGI middleware before framework buffering. A missing opaque
account ID and an ID owned by another wallet share the same fixed `404`
classification, so authenticated reads cannot be used as an account-existence
oracle. Every public or internal customer response, including validation,
body-limit, unavailable, conflict, capsule, and settlement responses, carries
`Cache-Control: no-store, max-age=0` and `Pragma: no-cache`.

## Product and funding boundaries

### Current official Tinker provider boundary

Checked against the official Tinker documentation on 2026-07-22. Tinker's
[quick start](https://tinker-docs.thinkingmachines.ai/tinker/quickstart/)
instructs an SDK caller to obtain an API key from the Tinker Console and then
provide it through `TINKER_API_KEY`. The
[data model and permissions guide](https://tinker-docs.thinkingmachines.ai/tinker/data-model/)
describes organization creation, project membership, roles, balance, invoices,
and payment-information management as Console/organization workflows. The
documented
[`RestClient` surface](https://tinker-docs.thinkingmachines.ai/tinker/api-reference/restclient/)
covers sessions, runs, checkpoints, audit logs, and caller identity; the
[pricing page](https://tinker-docs.thinkingmachines.ai/tinker/models/) defines
provider usage prices.

Within those reviewed public docs, no supported API was found for a third-party
service to create a Tinker organization for a wallet, submit payment-card data,
top up an organization balance, or mint a provider API key. This is a bounded
documentation finding, not a claim about undocumented/private provider
capabilities. Consequently, the customer credential in this adapter is only a
WikiGen proxy authorization: it is not a Tinker credential. Provider account
activation, balance funding, and provider-key issuance remain gated on a
documented provider integration or a provider-hosted Console/checkout flow.

- Hosted card checkout remains roadmap and, if built, must be provider hosted.
  This API has no card request model.
- ETH and canonical Base Sepolia USDC capacity remain in
  `ComputeCreditVault`; this adapter does not accept deposits or mint tokens.
- Noncash test grants remain in the separate Compute service-credit ledger.
- There is no exchange rate between ETH/USDC, service credits, Tinker balance,
  or policy units.
- The upstream developer-prefunded Tinker account remains sealed runtime
  configuration. A customer authorization does not represent ownership of that
  provider balance or a redeemable claim.

## Residual blockers before production enablement

1. A fresh reviewed deployment, frozen Tinker release receipt, and live
   release-authority document have not been installed for this runtime.
2. The signed envelope readers are implemented, but the resident
   provisioning/settlement producers and their private directory mounts must
   be included in the reviewed CVM compose and independently activated.
3. The customer training route and durable at-most-once handoff are implemented,
   but no provider dispatch is live until the fresh authority, measured CVM,
   sealed provider account, and release gates are independently activated.
4. There is no compatible bounded inference provider. Inference remains hard
   disabled in policy, credential issuance, and reservations.
5. The generated release compose now pins the customer authority and state
   paths, purpose-separated dstack key paths, empty explicit key overrides, and
   signed post-measurement enable/digest inputs. Its networkless initializer
   installs the exact mode-0600 authority from canonical signed final-runtime
   bytes; the independently signed runtime, provisioning, and settlement
   evidence producers must still be activated. Merely projecting
   `TINKER_CUSTOMER_ENABLED=true` without exact authority/evidence still fails
   closed.
6. The frontend must consume a separately release-derived
   `VITE_ENABLE_TINKER_CUSTOMER` marker bound to that authority/CVM route; it
   must not infer customer-lifecycle readiness from the generic Compute flag.
7. The single-process file lock is not a multi-worker database lock. Production
   must run one API/resident authority process for this store or replace it with
   a shared transactional implementation that preserves the same anchor CAS.

Until those blockers close, the frontend should continue to label customer
account creation, linking, credentials, funding, inference, and customer
training dispatch as live-capable but release-gated. Only an authenticated API
settlement, release, or reconciliation response may receive an observed-live
label; configuration alone may not. A `requested` receipt means only
that the wallet-owned request was durably anchored; only a signed activation
receipt may be displayed as active. This implementation is a tested authority
boundary, not evidence that a customer account, provider key, inference run,
training run, Base Sepolia release, or Phala CVM is live.
