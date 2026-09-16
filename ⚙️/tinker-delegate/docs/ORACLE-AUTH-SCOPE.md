# Oracle API Auth Scoping — TEE Service-to-Service Authentication

## Problem

Historically the email oracle API exposed `/pin`, `/inbox`, and `/attestation`
without a complete authorization boundary. The current implementation removes
`/inbox` entirely, requires runtime bearer auth for scoped `/pin` and
commitment-only `/email`, and checks the on-chain consumer registry before OTP
mailbox access. Two
separate guarantees remain the architectural requirement:

1. **Oracle boot authorization** — only approved oracle code may boot and receive oracle KMS keys.
2. **OTP consumer authorization** — only approved TEE applications may request OTPs from the oracle.

The original design mostly covered runtime service auth. The updated design adds explicit on-chain governance for both code authorization and consumer authorization, plus an irreversible freeze path once development is finished.

## Critical Clarification: Freeze the Policy, Not a Single Quote

The thing we can safely freeze on-chain is **the allowed compose hash / app auth policy**, not a single attestation quote hash.

- A **TDX quote** is per boot / per request evidence and changes over time.
- A **compose hash** is the stable measurement we actually want to authorize.
- After freeze, the oracle should continue producing fresh quotes, but those fresh quotes must verify against the same immutable on-chain compose-hash policy.

If we "burn the attestation hash" literally, we would brick the app on the next fresh quote. The correct primitive is:

- freeze the oracle's **authorized compose-hash set**
- optionally freeze the **consumer registry**
- continue verifying fresh quotes against those frozen reference values

## Threat Model

| Threat | Impact | Current Mitigation |
|--------|--------|-------------------|
| External attacker hits oracle API | OTP theft | Oracle has no published production port; same-CVM dstack-derived bearer plus exact on-chain consumer binding |
| Compromised authorized consumer widens `/pin` query | Mailbox exfiltration / regex DoS | Literal Tinker target/sender/pattern, no subject filter, exact parsed-sender recheck |
| Malicious oracle redeploy or contract substitution | Full trust-boundary break | KMS compose policy plus exact `EmailOracleAuth` address/runtime-code hash and `releaseConfigurationReady()` check |
| Malicious or mistaken consumer upgrade | Wrong app keeps OTP access | Exact nonzero consumer app address and compose hash checked on-chain at one finalized block; immediate revocation and optional registry freeze |
| Reuse of a captured runtime bearer | Reuse of same-CVM authorization material | Private network, fixed signup capability, on-chain binding, and durable OTP replay ledger; the bearer is intentionally reusable, so compromise inside the authorized CVM remains a trust-boundary failure |
| RPC equivocation or stale chain view | Revoked consumer appears authorized | Two distinct HTTPS hosts must agree on Base Sepolia, one common finalized block, exact code and calls; 900-second age and 30-second future-skew bounds |
| Ordinary process/CVM restart presents an older finalized view | Authorization rollback | Monotonic finalized-block/hash checkpoint on the persistent `oracle-data` volume |
| Host restores the entire persistent volume | Checkpoint rollback | Residual: dual-RPC freshness constrains the window, but no hardware-backed monotonic storage currently prevents whole-volume snapshot rollback |
| Owner key compromised after production freeze | Policy rug or silent upgrade | Irreversible oracle-code freeze and optional consumer-registry freeze; any policy deliberately left mutable remains exposed |

## Design Goals

1. **Safe during development** — owner can approve new consumer compose hashes while iterating.
2. **Strong in production** — oracle code authorization can be permanently frozen.
3. **Delegable operations** — deployer may appoint a consumer-policy manager without granting full oracle-governance authority.
4. **Fresh attestation still works after freeze** — immutable policy, fresh quotes.
5. **Minimal trust surface** — on-chain contract decides who may boot and who may request OTPs; oracle runtime only enforces that policy.

## Identity Model

We need to track two identities, not one:

### 1. Oracle Identity

This is the oracle CVM itself, authorized by dstack KMS via `IAppAuth`.

- Key fields: `appId`, `composeHash`, optionally `deviceId`, `osImageHash`, `tcbStatus`
- Enforced by KMS at boot
- Governed on-chain
- Can be permanently frozen

### 2. Consumer Identity

This is the TEE app allowed to call `POST /pin`.

- Key fields: consumer `appId` and consumer `composeHash`
- Enforced by oracle runtime on each request
- Governed on-chain by a consumer registry
- May remain mutable during development even after oracle code is frozen

## Reference Patterns from 🔬

### Pattern 1: dstack `IAppAuth` + `DstackApp`
**Source**: `🔬/dstack/kms/auth-eth/contracts/`, `🔬/dstack-examples/tutorial/08-extending-appauth/README.md`

This is the correct foundation for oracle boot authorization. dstack KMS already expects an `IAppAuth` contract keyed around `composeHash`, device restrictions, and other boot measurements.

### Pattern 2: `disableUpgrades()` as One-Way Freeze
**Source**: `🔬/dstack/kms/auth-eth/contracts/DstackApp.sol`

`disableUpgrades()` is the correct conceptual model for your "burn/lock" requirement. The important point is to apply that irreversible action to the **authorization policy**, not to a single attestation quote.

### Pattern 3: Timelocked Compose-Hash Activation
**Source**: `🔬/dstack-examples/tutorial/08-extending-appauth/README.md`

Development should allow staged upgrades:

- `proposeComposeHash(hash)`
- wait for notice period
- `activateComposeHash(hash)`

This reduces surprise upgrades and gives auditors time to inspect new oracle code before it can receive KMS keys.

### Pattern 4: Same-CVM Derived-Key Bearer Auth
**Source**: synthesized from `derive_key()` patterns in `🔬/dstack-examples/tutorial/02-kms-and-signing/`

This remains the simplest runtime auth mechanism for the single-CVM deployment. It is still useful, but it is no longer the whole design. It becomes the runtime enforcement layer under the stronger on-chain governance layer.

### Pattern 5: Cross-CVM Consumer Auth
**Source**: `🔬/amiller/github-zktls-1--groupauth/`, `📄/tee-email-oracle/TEE-AUTH-SPEC.md`

If oracle and delegate split into separate CVMs, the runtime auth must move from shared derived-key bearer auth to RA-TLS or an attestation-backed signature-chain scheme. The on-chain consumer registry still remains the source of truth.

## Updated Recommended Architecture

### Layer A: Oracle Boot Authorization Contract

An on-chain `EmailOracleAuth` contract implements `IAppAuth` for the oracle CVM.

Responsibilities:

- authorize oracle `composeHash` values for KMS boot
- optionally restrict device IDs / OS image hashes / TCB status
- support timelocked oracle upgrades during development
- support an irreversible production freeze of oracle code authorization

### Layer B: Consumer Registry

The same contract, or a tightly-coupled companion contract, maintains which consumer apps may request OTPs.

Responsibilities:

- map `consumerAppId => allowed compose hashes`
- allow owner or delegated manager to add/remove consumer compose hashes
- optionally allow a separate irreversible freeze for the consumer registry

### Layer C: Runtime Oracle Auth

The oracle runtime enforces that the caller matches an allowed consumer entry.

It also enforces a narrow capability boundary after authentication. `/pin` can
only retrieve a six-digit Tinker login OTP from the exact allowlisted sender.
Caller-selected regexes, sender/subject widening, other target services, and
unknown request fields fail validation before IMAP. The response intentionally
contains the OTP needed by the internal signup flow plus only its bounded
request hash and attestation proof. Email/message identifiers, sender and
subject headers, mailbox identity or commitments, extraction time, and the
internal replay key are absent from the exact response. Private message data
cannot modulate the public response or quote report data. Runtime auth alone is
not treated as authorization to inspect arbitrary mailbox content. There is no
mailbox-listing route. The unauthenticated `/health` route reports fixed process
liveness only. `/email` returns authenticated readiness plus a
domain-separated address commitment and `raw_email_egress=false`; it never
returns the address itself.

The production Phala compose does not publish the oracle port. The delegate is
the only public service and calls the oracle on the private compose network.
Replay keys remain internal and are durably stored before release; an
unavailable or unwritable replay ledger denies the OTP.

### Current production runtime contract

The production compose and startup validator intentionally duplicate the
release-critical policy so either layer rejects configuration drift. These
values are exact, not suggested defaults:

| Control | Required production value |
|---------|---------------------------|
| Runtime mode | `ORACLE_PRODUCTION_RELEASE=true`, dstack enabled |
| Same-CVM transport auth | required; no static token; derived key path `oracle/runtime-auth` |
| On-chain policy | required; nonzero `EmailOracleAuth` address and exact nonzero runtime-code hash |
| Chain view | Base Sepolia `84532`; two HTTPS RPC URLs with different normalized hosts |
| Consumer binding | nonzero app address plus nonzero compose hash |
| Request scope | canonical label `tinker-delegate.signup` |
| Finalized-block bounds | maximum age 900 seconds; maximum future skew 30 seconds in the production compose |
| Monotonic checkpoint | `/data/email_auth_checkpoint.json` on `oracle-data:/data` |
| Credential store | `/data/credentials.enc`; no static key; dstack path `email/creds`; auto-genesis off |
| OTP replay store | `/data/otp_replay.enc`; no static key; dstack path `email/otp_replay` |
| Provisioning | credential-provisioning endpoint off and provisioning token empty |

For each OTP request, the runtime finds the lower of the two finalized heads,
then requires both RPCs to return the same block number, hash, parent hash, and
timestamp for that exact numeric block. At that block it requires the exact
contract bytecode and Ethereum runtime-code hash, identical
`releaseConfigurationReady()` results, and identical
`isConsumerAuthorized(appId, composeHash)` results. It re-reads the block after
the contract calls, atomically records its number and hash before returning an
allow or deny decision, and rejects a later observation below that height or
with another hash at the same height. RPC, ABI, storage, or disagreement errors
deny the request without putting credential-bearing RPC URLs into errors.

`tinker-delegate.signup` is a fixed capability label in the request body, not a
signature, quote, or independently proven service identity. The authenticated
same-CVM bearer proves possession of the shared dstack-derived secret. The
label prevents the delegate client from widening the intended signup scope,
while the app address and compose hash checked on-chain are configured release
identity. All three controls are required; documentation or UI must not present
the label by itself as an attestation.

The checkpoint closes rollback across ordinary requests and restarts only while
the named persistent volume is preserved. It does **not** provide hardware
anti-rollback against an administrator or host restoring the whole volume to an
older snapshot, because that restores the checkpoint with it. Two-provider
agreement and the finalized-block freshness bound reduce how old an accepted
view may be but do not create monotonic storage. Closing that residual requires
an external monotonic anchor or equivalent independently durable state.

### Independent Email/KMS restart evidence

Runtime authorization is necessary but does not prove that a restarted CVM
recovered the reviewed Email/KMS release. The Diligence QVL policy may enable
one secondary `email_oracle_kms_restart` profile. Its
`email_oracle_kms_restart_v1` binding kind commits
the exact `EmailOracleAuth` and KMS proxy/implementation addresses and runtime
hashes, the complete EIP-1967 implementation storage word, KMS registration
transaction/block evidence, target boot-tuple hash, and restart-proof hash.

The workload obtains a fresh signed Diligence-QVL challenge-v2 for the exact
`email_oracle_kms_restart` profile and binds its digest in report-data bytes
32–63. The challenge is single-use, lasts no more than 120 seconds, and requires
Intel DCAP appraisal to complete strictly before expiry. It receives only an
exact release-lineage-bound `dnai.independent-tdx-verdict.v4` under the v4
signing domain. That verdict carries the separately reviewed exact 900-second
activation-evidence lease, which may outlive the consumed challenge but does
not renew challenge freshness. A Diligence-result challenge or verdict cannot
cross-authorize restart evidence. This secondary profile shares
the reviewed Diligence QVL root/CVM; it does not create another root. It also
does not turn the persistent checkpoint into hardware anti-rollback against
restoration of the whole volume.

For same-CVM deployment:

- derived-key bearer auth is acceptable as the transport auth primitive
- because both services share the same compose/app identity

For separate-CVM deployment:

- RA-TLS or signature-chain auth
- caller must present app identity and fresh attestation evidence
- oracle checks that identity against the on-chain consumer registry

## Proposed Contract Responsibilities

### Oracle Policy

The oracle auth contract should own these policy domains:

1. **Oracle code authorization**
2. **Consumer authorization**
3. **Freeze controls**
4. **Optional attestation / delivery logging**

### Roles

We should not use raw `onlyOwner` for every operation forever. The updated spec should distinguish:

- `OWNER_ROLE` or `DEFAULT_ADMIN_ROLE`
  - can grant/revoke manager roles
  - can freeze oracle code policy
  - can freeze consumer policy
- `CONSUMER_MANAGER_ROLE`
  - can add/remove approved consumer compose hashes
  - cannot change oracle compose hashes
  - cannot unfreeze anything
- optional `EMERGENCY_ROLE`
  - can revoke consumers immediately
  - cannot approve new oracle code

This matches your requirement that updates may be done by the deployer or by someone the deployer explicitly approves.

## Freeze Model

We need **two independent irreversible switches**.

### Freeze 1: Oracle Code Freeze

`freezeOracleCodeAuth()`

After this:

- no new oracle compose hashes may be proposed
- no pending oracle compose hashes may be activated
- no oracle compose hashes may be removed or added
- device / OS / TCB policy becomes immutable
- the oracle may continue booting only if its fresh quote matches the already-approved measurements

This is the production "the oracle code can never change again" switch.

### Freeze 2: Consumer Registry Freeze

`freezeConsumerRegistry()`

After this:

- no consumer app IDs may be added
- no consumer compose hashes may be added or removed
- delegated managers lose effective power

This should remain optional. In development, keep it unfrozen. In production, freeze it only after the final consumer app measurement is known.

## Timelock Model

Timelocks are useful for **oracle code upgrades**, but less important for emergency consumer revocation.

Recommended:

- oracle compose-hash additions: timelocked
- oracle compose-hash removals: owner-only, immediate
- consumer compose-hash additions: owner or consumer manager; optionally timelocked
- consumer compose-hash removals: immediate

This avoids the classic bug where a known-bad consumer cannot be revoked quickly because all policy changes are delayed.

## Minimal Safe Storage Model

At the spec level, the contract should track:

```solidity
mapping(bytes32 => bool) public allowedOracleComposeHashes;
mapping(bytes32 => uint256) public pendingOracleComposeHashes;

mapping(address => bool) public allowedConsumerApps;
mapping(address => mapping(bytes32 => bool)) public allowedConsumerComposeHashes;

bool public oracleCodeFrozen;
bool public consumerRegistryFrozen;
uint256 public oracleUpgradeDelay;
```

Optional hardening:

```solidity
mapping(bytes32 => bool) public allowedDeviceIds;
mapping(bytes32 => bool) public allowedOsImageHashes;
bool public allowAnyDevice;
```

## State Machine for Policy Changes

### Development Mode

1. deploy contract
2. register initial oracle compose hash
3. add first consumer app + compose hash
4. iterate on consumer compose hashes as needed
5. optionally timelock and activate new oracle compose hash when oracle changes

### Production Lock-In

1. finalize oracle compose hash
2. call `freezeOracleCodeAuth()`
3. finalize consumer app ID + compose hash
4. optionally call `freezeConsumerRegistry()`

Once step 2 is done, fresh quotes keep working because they are checked against the same frozen compose-hash policy.

## Security Pitfalls to Avoid in the Contract Spec

1. **Do not key authorization by quote hash**
   - Quote hashes are ephemeral.
   - Key by stable measurements such as `composeHash`.

2. **Do not use a single boolean allowlist per consumer app**
   - A consumer `appId` can change code across deployments.
   - Track both `consumerAppId` and `consumerComposeHash`.

3. **Do not let delegated managers modify oracle code policy**
   - Consumer delegation and oracle governance are different trust domains.

4. **Do not make revocation timelocked**
   - New approvals may be delayed.
   - Removals should be immediate.

5. **Do not couple production freeze to local-dev bypass**
   - Local dev may bypass runtime auth with `DSTACK_ENABLED=false`.
   - That bypass must never affect on-chain production policy semantics.

6. **Do not assume same-CVM forever**
   - The contract should describe consumer identity generically enough that we can move from same-CVM bearer auth to separate-CVM RA-TLS later without rewriting governance.

## Updated Implementation Plan

### Phase 1: Spec-First Contract Design

- finalize the `EmailOracleAuth` interface
- define owner vs consumer-manager permissions
- define irreversible freeze semantics
- define whether consumer registry lives in the same contract or a companion contract

### Phase 2: Runtime Auth (same-CVM first)

- keep derived-key bearer auth for the first Phala deployment
- oracle checks runtime caller against the on-chain policy it has fetched or cached

### Phase 3: On-Chain Authorization

- deploy oracle auth contract on Base Sepolia
- register the oracle compose hash before Phala deployment
- use the contract as the source of truth for consumer app authorization

### Phase 4: Production Freeze

- after the final audited oracle image is deployed and verified, call `freezeOracleCodeAuth()`
- after the final consumer app measurement is approved, optionally call `freezeConsumerRegistry()`

## What Can Wait

- on-chain delivery receipts for every OTP
- multi-sig owner
- full RA-TLS split-CVM flow
- device pinning if we initially accept any device on Phala

Those are useful, but the must-have additions to the original design are:

- separate oracle-vs-consumer governance
- delegated consumer updates
- irreversible oracle-code freeze
- correct use of compose hash instead of quote hash
