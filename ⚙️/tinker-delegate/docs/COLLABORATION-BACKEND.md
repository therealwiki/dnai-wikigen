# Collaboration backend: schema v2

The Collaboration Console is a wallet-authenticated, commitment-only
coordination authority for multi-owner work. Schema v2 deliberately separates:

1. a creator's invitation declaration;
2. the invited wallet's membership decision;
3. an accepted owner's room-role consent;
4. one current query proposal; and
5. every required owner's signature for that exact query.

A creator cannot enroll another wallet by declaration. Room-level role consent
cannot be inherited by an arbitrary later query. The schema-v2 coordination
routes do not ingest a corpus or health data, call a provider, move funds, mint
a token, settle a royalty, or produce Intel TDX evidence. The optional execution
extension described below is a separate release-gated service and journal; it
does not turn a joint-consent snapshot into execution authority.

`RoyaltyDistributor` v3 is the money boundary for that execution extension.
After a complete fresh execution-grant set fixes the exact allocation, the
sponsor deposits one deterministic native/ERC-20 reservation before Compute
admission. After bounded Compute, the main runtime and independent Royalty QVL
authorize the same globally one-shot, anchor-current EIP-712 settlement, and the
sponsor wallet may broadcast the exact zero-value `settleReserved` call. The
public API never receives the sponsor's private key, calls a provider, or
broadcasts that wallet transaction. The standalone Royalty panel remains
runtime-pinned and read/self-claim only; a Collaboration client may present only
the server-derived reservation and settlement wallet actions. It cannot author
an allocation or substitute direct `distributeNative` / `distributeERC20`,
which remain compatibility paths.

## Exact backend gate

The backend gate defaults closed:

```text
TINKER_COLLABORATION_ENABLED=false
```

Absent or exact `false` configuration makes every
`/auth/collaboration/*` and `/collaboration/*` route return HTTP 503 before
request-body or query validation, challenge admission, token exchange, bearer
parsing, key derivation, store opening, reads, or mutations. Disabled responses
are marked `Cache-Control: no-store`. The settings parser accepts only a
Boolean or the exact lowercase environment literals `true` and `false`; `1`,
`TRUE`, `yes`, and other loose truthy spellings are rejected.

The frontend flag is independent and cannot open the backend:

```text
VITE_ENABLE_COLLABORATION=false
```

The execution extension has an additional default-closed gate:

```text
TINKER_COLLABORATION_EXECUTION_ENABLED=false
```

Both backend gates must be true before the execution-plan routes serve requests. Queue
control is still not proof that a job is executable. Reservation wallet calldata
is withheld unless a fresh HMAC-authenticated, release-matching real-dstack
worker heartbeat also contains an authenticated exact Royalty-QVL capability
observation. That heartbeat proves bounded process presence and QVL endpoint
capability only. It explicitly does not prove a job quote, per-job QVL verdict,
reservation finality, provider execution, or settlement.

The backend is not independently live merely because the website flag is open
or a store path exists. Production may project `true` only from the current
signed release authority's exact Collaboration feature decision. Compute,
Tinker customer, and ambient operator settings do not imply this authority.

## Authentication domain

- `POST /auth/collaboration/challenge`
- `POST /auth/collaboration/token`
- exact bearer scope: `collaboration:console`
- chain: Base Sepolia (`84532`)
- wallet key path: `tinker/collaboration_wallet_auth`
- store-integrity key path: `tinker/collaboration_store_integrity`

The token domain is isolated from Deal, Arena, Compute, Review, proxy, and
runtime bearers. Authentication challenges are process-local, one-time,
expiring, attempt-bounded, and capacity-bounded. EOA and EIP-1271 signatures use
the shared Base Sepolia verifier policy.

## Invitations are not membership

`POST /collaboration/rooms` stores:

- a random 128-bit room ID;
- the authenticated creator;
- no more than 16 declared wallets;
- purpose and pipeline commitments;
- one corpus-policy commitment per allocation owner;
- positive owner allocations totaling exactly 10,000 basis points; and
- a caller-retained idempotency key.

The creator is accepted. Every other declared wallet starts as `invited`.
Invited wallets can see the commitment-only invitation, but they:

- do not consume the 64 accepted-room quota;
- are not ordinary participants;
- cannot activate an owner role;
- cannot propose a query;
- cannot approve a query; and
- cannot record a joint-consent snapshot.

Wallet-authenticated, exact-idempotency operations are:

- `POST /collaboration/rooms/{room_id}/invitations/accept`
- `POST /collaboration/rooms/{room_id}/invitations/decline`
- `POST /collaboration/rooms/{room_id}/invitations/cancel` (creator only)

Decline or creator cancellation removes the target's future room visibility and
authority. Durable membership states are `invited`, `accepted`, `declined`, and
`cancelled`; projections never label a creator declaration as accepted.

Spam is bounded independently:

- 32 pending invitations per target wallet;
- 64 pending invitations across one inviter's active rooms;
- 15 pending invitations in one room;
- 64 active rooms created by one wallet; and
- 64 accepted active rooms per participant.

## Bounded room listing

`GET /collaboration/rooms` returns invited and accepted rooms only. The default
page is 8 rooms and the maximum is 16, keeping each response below the
frontend's 256 KiB public-response cap.

The envelope contains `has_more` and `next_cursor`. The cursor is opaque,
HMAC-authenticated, participant-bound, and exact-snapshot-bound. A tampered
cursor, a cursor from another wallet, a missing anchor, or any intervening
state change returns HTTP 409 and requires a first-page restart. Cursor internals
are not an API contract.

`GET /collaboration/rooms/{room_id}` is available only to an invited or accepted
wallet. Declined, cancelled, and unrelated wallets cannot recover a guessed
room.

## Owner role consent

Membership acceptance and owner-role activation are separate. An accepted
allocation owner uses:

- `POST /collaboration/rooms/{room_id}/consent-challenges`
- `GET /collaboration/consent-challenges/{challenge_id}`
- `POST /collaboration/rooms/{room_id}/consents`

The only role decisions are `activate` and `revoke`. The v2 personal-sign
message binds the owner, Base Sepolia, room ID, immutable room commitment,
current generation, current-state commitment, decision, nonce, and lifetime.
It says explicitly that role activation does not approve a query.

After EOA/EIP-1271 verification, the store keeps only a domain-separated
authorization hash. Raw signature bytes are discarded. Repeating the same
already-consumed challenge with the same owner, decision, and verified
authorization hash is a safe lost-response replay: it returns current state
without another generation increment. Any mismatch fails closed.

## Exact current-query grants

Once every required owner has accepted membership and activated its role, any
accepted participant can create the one current proposal:

- `POST /collaboration/rooms/{room_id}/query-proposals`

A new proposal increments the room generation, replaces the current query, and
invalidates every earlier query grant. Owners then use:

- `POST /collaboration/rooms/{room_id}/query-grant-challenges`
- `GET /collaboration/query-grant-challenges/{challenge_id}`
- `POST /collaboration/rooms/{room_id}/query-grants`

The only query decisions are `approve` and `revoke`. Every signature message
binds:

- exact query commitment;
- room ID, immutable commitment, and generation;
- query-proposal commitment;
- that owner's corpus-policy commitment;
- the exact query-specific allocation commitment;
- action, nonce, and lifetime.

Changing the query cannot inherit an approval from the prior query. Query-grant
consumption has the same exact-hash lost-response replay behavior as owner-role
consumption.

## Joint-consent snapshot, not execution

`POST /collaboration/rooms/{room_id}/runs` succeeds only when the submitted
`query_ref` is the exact current proposal and every required owner's
query-specific approval is current. It records:

```text
surface = collaboration_joint_consent_snapshot
execution_status = joint_consent_snapshot_not_dispatched
execution_authority = false
```

The snapshot binds the room, room state, query proposal, query-grant set,
allocation, requester, and record time. Recovery is available at
`GET /collaboration/runs/{run_id}` while the bounded retention period remains.
It also reports provider dispatch, TDX attestation, settlement, royalty
distribution, and raw-data egress as false.

This snapshot is not a durable execution authorization. The separate execution
extension must create a new non-circular Basis and collect a new, purpose-
separated execution grant from every owner. Query grants are not reused at the
irreversible Compute or payment boundary.

## Dedicated execution and Royalty settlement extension

The source-implemented extension has four participant-facing execution routes:

- `POST /collaboration/runs/{run_id}/execution-plans`
- `POST /collaboration/execution-plans/grant-challenges`
- `POST /collaboration/execution-plans/authorize`
- `GET /collaboration/executions/{execution_id}`

Plan construction binds the current room/query/grant state to the exact sealed
workload, Compute vault/job tuple, maximum Compute debit, exact royalty owner
vector, release identities, and one fresh server-generated settlement ID and
nonzero nonce. The settlement nonce stays a canonical decimal string across
the public plan, signed challenge, plan token, intent, wallet handoff, journal,
and status response, including values above JavaScript's `2^53` safe-integer
boundary. The `refund_after` wallet field is also a canonical decimal string.
No route accepts a raw corpus, prompt, health record, private key, caller-made
execution context, or caller-made royalty allocation.

Only after every fresh execution grant verifies does the coordinator derive the
exact `FundingReservationRequest`, deterministic reservation ID, and one-shot
Compute authorization context. The sponsor wallet uses `reserveNative` or
`reserveERC20`; an ERC-20 approval, aggregate distributor balance, DTO, or
heartbeat is not funding authority. The dedicated worker claims the authorized
intent only when one RPC-reported finalized EIP-1898 block simultaneously
matches the exact active, solvent, unconsumed
`collaborationFundingReservation(bytes32)` result and the exact Compute job. It
then calls only `enqueue_collaboration_one_shot`. The Collaboration worker never
calls the provider; the separately bounded Compute runtime performs provider
execution, independent metering, and Compute settlement.

After the authenticated Compute journal exposes a bounded settled result, the
sponsor controls the Royalty continuation through:

- `POST /collaboration/executions/{execution_id}/royalty-settlement/prepare`
- `GET /collaboration/executions/{execution_id}/royalty-settlement`
- `POST /collaboration/executions/{execution_id}/royalty-settlement/broadcast`

`prepare` is asynchronous and sponsor-only. The worker first rechecks the exact
reservation and unused settlement ID/nonce at a fresh finalized head. It then
requests fresh per-job QVL attestation, creates the exact settlement decision
from the bounded result/usage evidence, compare-and-sets that decision into the
release-pinned `ExecutionPolicyAnchor`, obtains the purpose-separated dstack
main-runtime and independent-QVL EIP-712 signatures, and persists the complete
wallet plan in the authenticated execution-policy store before reporting
`plan_ready`. The API returns only the exact zero-value `settleReserved`
transaction. It never returns either signing key or the raw QVL quote.

The status response schema is
`dnai.collaboration.royalty-settlement-status.v2`. Its durable sponsor-control
states are:

```text
not_requested
prepare_requested -> authorizing -> plan_ready -> broadcast_reported -> settled
                                  |-> expired (authorization expired; retryable)
                                  |-> reservation_expired -> refunded
                                  `-> reconciliation_hold
```

The broadcast route records an advisory transaction hash only. It does not mark
the settlement complete and does not cause a worker rebroadcast. `settled` is
written only after one fresh RPC-reported finalized block matches the pinned
runtime and active release, the exact Compute job is settled, the reservation is
inactive and consumed, and
`fundingReservationSettlementState(bytes32)` proves both the settlement ID and
nonce replay markers consumed with the exact asset, total, and owner-amount
hash. Drift becomes a non-retryable `reconciliation_hold`; temporary RPC
unavailability leaves finality pending.

The three expiry/refund meanings are deliberately distinct:

- `expired` means only that the dual-authorized settlement plan's signature
  window expired at a finalized chain timestamp. It reports
  `failure_code = authorization_expired` and `retryable = true`; the sponsor may
  explicitly request a replacement authorization while the exact reservation
  remains usable. Expiry never invents or automatically broadcasts a replacement
  plan.
- `reservation_expired` means a finalized read has reached `refund_after` while
  the exact reservation remains unconsumed, neither settlement replay marker is
  consumed, and the full prefund remains deposited. It reports
  `failure_code = reservation_expired` and `retryable = false` for settlement:
  the remaining action is the sponsor's separate wallet call to
  `refundFundingReservation(bytes32)`.
- `refunded` means a later finalized read proves that same reservation's storage
  status is `refunded`, its deposited amount is zero, and the settlement and
  nonce replay markers remain unused. It reports
  `failure_code = reservation_refunded` and `retryable = false`.

Finalized expiry/refund is exposed only through this exact bounded
`terminal_evidence` object; numeric values shown here as strings are canonical
decimal strings at the API boundary:

```json
{
  "outcome": "reservation_expired | reservation_refunded",
  "chain_id": 84532,
  "block_number": "<decimal>",
  "block_hash": "0x<32 bytes>",
  "block_timestamp": "<decimal>",
  "funding_reservation_id": "0x<32 bytes>",
  "reservation_storage_status": "active | refunded",
  "reservation_active": false,
  "reservation_consumed": false,
  "reservation_deposited_amount": "<positive prefund | 0>",
  "settlement_processed": false,
  "settlement_nonce_processed": false,
  "source_commitment": "sha256:<32 bytes>"
}
```

For `reservation_expired`, storage status is `active` and the deposited amount
is positive. For `reservation_refunded`, storage status is `refunded` and the
deposited amount is zero. No receipt log, raw transaction, quote, artifact, or
unbounded provider output is included. Finalized reconciliation polling
continues across both authorization `expired` and `reservation_expired`; it ends
only after `settled`, finalized `refunded`, or an explicit non-retryable hold.
The browser's refund transaction is a separate sponsor action. It is never a
Royalty settlement `wallet_plan`, never uses the settlement broadcast-report
route, and both `reservation_expired` and `refunded` expose
`wallet_plan = null`. The refund does not become authoritative until the worker
observes the finalized `refunded` state.

This sequence is implemented and tested in source. The focused combined
core/service/API/worker checkpoint passes 207 tests plus 128 subtests. It is not
evidence of a project-owned Base Sepolia deployment, a measured Phala worker,
Intel TDX, a per-job independent QVL verdict, a real sponsor deposit, a provider
run, a settlement, or a Cloudflare activation. RPC-reported finalized means the
explicit single-RPC observation model; it is not RPC quorum or a consensus
proof.

## Capacity, retention, and explicit archival

Append-only receipts do not live forever:

- terminal or expired role/query challenges become reclaimable after 24 hours;
- never-dispatched joint-consent snapshots become reclaimable after 7 days;
- idempotency records become reclaimable after 7 days; and
- an explicitly archived, quiescent room becomes reclaimable after 7 days.

Compaction is deterministic and runs before mutations, with an explicit store
operation for tests/maintenance. Projections expose their applicable
`reclaimable_after` and retention-policy labels.

One wallet is additionally limited to 64 retained challenges, 64 retained
snapshots, and 128 retained idempotency records; a room is limited to 128
retained challenges, 256 retained snapshots, and 512 idempotency records.

Rooms are never silently pruned. The creator may call:

- `POST /collaboration/rooms/{room_id}/archive`

only after pending invitations were accepted, declined, or explicitly
cancelled; all active owner roles were explicitly revoked; active query grants
were revoked or invalidated; and no non-expired snapshot remains. An active
room has `room_retention_policy = active_not_pruned`. An archived room reports
its public retention boundary and is removed only after that boundary. This
explicit lifecycle prevents the 1,024-room physical cap from being permanently
append-only without weakening active authority.

## Persistence and rollback evidence boundary

The schema-v2 file is canonical JSON, capped at 4 MiB, authenticated with
HMAC-SHA256, atomically replaced through a same-directory temporary file,
fsynced, protected by a cross-process `flock`, and restricted to a regular
file. Schema-v1 files are not reinterpreted as v2.

Local development remains explicitly non-monotonic. Every local projection
reports:

```text
tamper_evident_current_state = true
rollback_protection = false
rollback_witness.mode = local_hmac_current_state_non_monotonic
rollback_witness.monotonic = false
```

An authenticated older local snapshot can still be restored. Local mode does
not project an authority-context hash, state hash, decision hash, anchor
sequence, or chain anchor.

A dstack runtime takes a different, mandatory path. Before issuing a
Collaboration wallet challenge, opening a room projection, or accepting a
mutation, it must construct the writable, release-pinned Base Sepolia
`ExecutionPolicyAnchor` coordinator. The Collaboration authority context binds:

- the main runtime CVM project ID and exact deployment-intent SHA-256;
- the release-authority SHA-256 and ceremony nonce;
- Base Sepolia, `www.wikigen.me`, and `https://www.wikigen.me`;
- the exact Collaboration token issuer, audience, and scope; and
- Collaboration store schema v2.

Only the domain-separated context hash becomes the anchor resource ID. Each
exact HMAC-authenticated schema-v2 state becomes a new hash-only `HOLD` record
with reason `collaboration_state_commitment`. That record is a rollback witness,
never an execution-policy `PASS`.

Mutations use a crash-recoverable order: write a private authenticated pending
document, compare-and-set the new state commitment into the external anchor,
then atomically promote the matching pending document. An ambiguous transport
failure preserves the pending document. A later startup/read promotes it only
when its exact commitment is the current external head. A restored older active
file, a regressed head, an unavailable witness, a foreign release/domain
context, an invalid anchor history, or a non-empty unanchored genesis fails
closed with HTTP 503.

Every release-anchored projection reports:

```text
tamper_evident_current_state = true
rollback_protection = true
rollback_witness.mode = base_sepolia_execution_policy_anchor
rollback_witness.monotonic = true
```

The bounded witness contains only the authority-context, state, and decision
hashes; the anchor sequence; the existing finalized execution-policy anchor
status; and fixed no-raw-egress flags. The nested status truthfully identifies
its `single_rpc_reported_finalized_with_confirmation_depth` verification model
and keeps independent-RPC-quorum and consensus-proof claims false.

This protects Collaboration authority against restoration of an older
persistent-volume snapshot so long as the release-pinned Base Sepolia witness
remains canonical under that stated observation model. It is not by itself TDX
workload evidence, query execution evidence, provider evidence, settlement
evidence, royalty evidence, or hardware anti-rollback for unrelated files.

Production uses a durable CVM volume:

```text
TINKER_COLLABORATION_STORE_PATH=/data/collaboration_state.json
```

Explicit signing and integrity keys are local-development fallbacks. A Phala
CVM should derive the two independent keys at the paths above rather than
receiving raw key values.
