# TEE Email Oracle — Smart Contract Spec

> **Status**: Draft
> **Date**: 2026-03-08
> **Network**: Base Sepolia (testnet), Base (mainnet)
> **Toolchain**: Foundry (forge/cast)
> **Parent spec**: `📄/tee-email-oracle/SPEC.md`

## 1. Purpose

The email oracle runs inside a dstack CVM. It needs on-chain governance for two things:

1. **Code authorization** — which docker-compose versions (compose hashes) are allowed to boot and receive KMS-derived keys. This is the standard `DstackApp` / `IAppAuth` pattern.
2. **Consumer authorization** — which *other* TEE apps are allowed to request pins from the oracle. This is oracle-specific.

Additionally, the contract provides:

3. **On-chain attestation log** — the oracle posts a signed attestation when it first boots, binding its email address to a TDX-verifiable identity. Anyone can verify.
4. **Timelock governance** — code upgrades require a notice period before activation, giving stakeholders time to audit and exit.
5. **Pin delivery audit trail** — optional on-chain log of pin deliveries (hashed, not plaintext) for accountability.

## 2. Architecture

```
                    On-Chain (Base)
┌──────────────────────────────────────────────────┐
│                                                  │
│  DstackKms (Phala-managed)                       │
│  ├─ registeredApps[EmailOracleAuth] = true       │
│  ├─ allowedOsImages[...] = true                  │
│  └─ isAppAllowed() → delegates to ↓              │
│                                                  │
│  EmailOracleAuth (our contract)                  │
│  ├─ IAppAuth: compose hash allowlist + timelock  │
│  ├─ Consumer registry: who can request pins      │
│  ├─ DStack sig chain verifier: prove TEE origin  │
│  ├─ Attestation log: oracle boot records         │
│  └─ Pin delivery log: hashed delivery receipts   │
│                                                  │
└──────────────────────────────────────────────────┘
         ▲                           ▲
         │                           │
    KMS checks                Oracle posts
    isAppAllowed()            attestations +
    on every boot             delivery receipts
         │                           │
┌────────┴───────────────────────────┴─────────────┐
│            dstack CVM (Intel TDX)                │
│                                                  │
│  email-oracle service                            │
│  ├─ derive_key("email/creds") → sealed creds     │
│  ├─ derive_key("/oracle", "ethereum") → signing  │
│  ├─ IMAP client → mail.cock.li:993               │
│  └─ POST /pin API (mutual attestation)           │
│                                                  │
│  Consumer app (same or separate CVM)             │
│  ├─ Requests pin via attestation API             │
│  └─ Uses pin for third-party signup              │
│                                                  │
└──────────────────────────────────────────────────┘
```

## 3. Contract: `EmailOracleAuth`

### 3.1 Inheritance

```
EmailOracleAuth
├─ IAppAuth            (dstack standard — isAppAllowed)
├─ Ownable             (OpenZeppelin — admin functions)
└─ ERC165              (interface detection)
```

Not using UUPS proxy — the oracle's threat model favors immutability. Once deployed and working, `disableUpgrades()` permanently locks the contract. If a new version is needed, deploy a new contract and re-register with DstackKms.

### 3.2 State

```solidity
// --- Code authorization (IAppAuth) ---
mapping(bytes32 => bool) public allowedComposeHashes;
mapping(bytes32 => bool) public allowedDeviceIds;
bool public allowAnyDevice;

// --- Timelock governance ---
uint256 public noticePeriod;                    // seconds (e.g., 2 days)
mapping(bytes32 => uint256) public proposedAt;  // compose hash → timestamp

// --- Consumer authorization ---
// A consumer is identified by its appId (the address of its own DstackApp contract)
mapping(address => bool) public allowedConsumers;

// --- DStack signature chain verification ---
address public immutable kmsRoot;    // KMS root signing address
bytes32 public immutable appId;      // this oracle's DstackApp address as bytes32

// --- Attestation log ---
struct BootAttestation {
    bytes32 emailHash;               // keccak256(email_address)
    bytes32 composeHash;             // compose hash at boot time
    uint256 timestamp;
    address oracleSigner;            // derived key address
}
BootAttestation[] public attestations;

// --- Pin delivery log ---
struct DeliveryReceipt {
    bytes32 requestHash;             // keccak256(consumer_appId, from, subject_filter)
    address consumer;                // consumer's derived key address
    uint256 timestamp;
    bytes32 pinHash;                 // keccak256(pin) — never the pin itself
}
// Not stored on-chain (gas), only emitted as events
```

### 3.3 Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

interface IEmailOracleAuth {
    // ═══════════════════════════════════════════
    // IAppAuth (required by dstack KMS)
    // ═══════════════════════════════════════════

    /// @notice Called by DstackKms to check if this oracle is allowed to boot
    /// @dev Checks compose hash allowlist + device restriction
    function isAppAllowed(
        IAppAuth.AppBootInfo calldata bootInfo
    ) external view returns (bool isAllowed, string memory reason);

    // ═══════════════════════════════════════════
    // Timelock governance
    // ═══════════════════════════════════════════

    /// @notice Propose a new compose hash (starts notice period clock)
    /// @dev Only owner. Cannot propose an already-active or already-proposed hash.
    function proposeComposeHash(bytes32 hash) external;

    /// @notice Activate a proposed hash after notice period elapsed
    /// @dev Permissionless — anyone can call once the delay has passed
    function activateComposeHash(bytes32 hash) external;

    /// @notice Cancel a pending proposal
    /// @dev Only owner
    function cancelProposal(bytes32 hash) external;

    /// @notice Immediately remove an active compose hash
    /// @dev Only owner. Useful for emergency revocation.
    function removeComposeHash(bytes32 hash) external;

    /// @notice Query when a proposed hash becomes activatable
    function activatesAt(bytes32 hash) external view returns (uint256);

    // ═══════════════════════════════════════════
    // Consumer authorization
    // ═══════════════════════════════════════════

    /// @notice Add a consumer app that is allowed to request pins
    /// @param consumerAppId The DstackApp contract address of the consumer
    function addConsumer(address consumerAppId) external;

    /// @notice Remove a consumer's pin-request authorization
    function removeConsumer(address consumerAppId) external;

    /// @notice Check if a consumer is authorized
    function isConsumerAllowed(address consumerAppId) external view returns (bool);

    // ═══════════════════════════════════════════
    // DStack signature chain verification
    // ═══════════════════════════════════════════

    /// @notice Verify a complete DStack signature chain
    /// @dev 3-step verification:
    ///   1. App key signed derived key → recover app address
    ///   2. KMS root signed app key → confirm KMS root matches
    ///   3. Derived key signed message → confirm derived address matches
    function verifyDstackChain(
        bytes32 messageHash,
        bytes calldata messageSignature,
        bytes calldata appSignature,
        bytes calldata kmsSignature,
        bytes calldata derivedCompressedPubkey,
        bytes calldata appCompressedPubkey,
        string calldata purpose
    ) external view returns (bool isValid);

    // ═══════════════════════════════════════════
    // Attestation log
    // ═══════════════════════════════════════════

    /// @notice Oracle posts a boot attestation with DStack proof
    /// @dev Called by the oracle itself (via its derived key) after first boot.
    ///      Verifies the DStack signature chain before recording.
    /// @param emailHash keccak256 of the email address created inside TEE
    /// @param composeHash compose hash of the oracle at boot time
    /// @param proof DStack signature chain proving TEE origin
    function postBootAttestation(
        bytes32 emailHash,
        bytes32 composeHash,
        DstackProof calldata proof
    ) external;

    /// @notice Get total number of boot attestations
    function attestationCount() external view returns (uint256);

    // ═══════════════════════════════════════════
    // Pin delivery log
    // ═══════════════════════════════════════════

    /// @notice Oracle logs a pin delivery with DStack proof
    /// @dev Called by oracle after delivering a pin to a consumer.
    ///      On-chain record proves the oracle delivered to an authorized consumer.
    function logPinDelivery(
        bytes32 requestHash,
        address consumer,
        bytes32 pinHash,
        DstackProof calldata proof
    ) external;

    // ═══════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════

    event ComposeHashProposed(bytes32 indexed hash, uint256 activatesAt);
    event ComposeHashActivated(bytes32 indexed hash);
    event ComposeHashCancelled(bytes32 indexed hash);
    event ComposeHashRemoved(bytes32 indexed hash);

    event ConsumerAdded(address indexed consumerAppId);
    event ConsumerRemoved(address indexed consumerAppId);

    event BootAttestationPosted(
        uint256 indexed index,
        bytes32 indexed emailHash,
        bytes32 composeHash,
        address oracleSigner
    );

    event PinDelivered(
        bytes32 indexed requestHash,
        address indexed consumer,
        bytes32 pinHash,
        uint256 timestamp
    );
}
```

### 3.4 DstackProof Struct

Reused from `TeeOracle.sol` and `GroupAuth.sol` patterns:

```solidity
struct DstackProof {
    bytes32 messageHash;
    bytes messageSignature;          // derived key signs message (EIP-191)
    bytes appSignature;              // app key signs "purpose:derivedPubkeyHex"
    bytes kmsSignature;              // KMS root signs "dstack-kms-issued:" + appId + appPubkey
    bytes derivedCompressedPubkey;   // 33-byte SEC1 compressed
    bytes appCompressedPubkey;       // 33-byte SEC1 compressed
    string purpose;                  // key derivation purpose (e.g., "ethereum")
}
```

### 3.5 Verification Logic

Ported directly from the proven `TeeOracle.verify()` pattern in `🔬/amiller/dstack-tutorial/05-onchain-authorization/TeeOracle.sol`:

```
Step 1: App signature over derived key
  message = purpose + ":" + hex(derivedCompressedPubkey)
  recoveredApp = ecrecover(keccak256(message), appSignature)

Step 2: KMS signature over app key
  message = "dstack-kms-issued:" + bytes20(appId) + appCompressedPubkey
  recoveredKms = ecrecover(keccak256(message), kmsSignature)
  REQUIRE: recoveredKms == kmsRoot

Step 3: Derived key signature over message
  ethHash = keccak256("\x19Ethereum Signed Message:\n32" + messageHash)
  messageSigner = ecrecover(ethHash, messageSignature)
  REQUIRE: messageSigner == address(derivedCompressedPubkey)

Step 4: App key consistency
  REQUIRE: recoveredApp == address(appCompressedPubkey)
```

Utility functions (`_compressedPubkeyToAddress`, `_modExp`, `_bytesToHex`, `_recoverSigner`) are identical to those in `TeeOracle.sol` — they use the secp256k1 curve equation and the `0x05` modular exponentiation precompile.

## 4. Flows

### 4.1 Deployment

```
Deployer (multisig or EOA)
│
├─ 1. Deploy EmailOracleAuth(kmsRoot, appId, noticePeriod, initialComposeHash)
│     - kmsRoot: address of the Phala KMS root signer (from DstackKms.kmsInfo)
│     - appId: bytes32, will become this contract's own address after registration
│     - noticePeriod: e.g., 2 days (172800 seconds)
│     - initialComposeHash: SHA-256 of the oracle's docker-compose.yaml
│
├─ 2. Register with DstackKms
│     DstackKms.registerApp(address(emailOracleAuth))
│     Now KMS will provision keys to this app when isAppAllowed() returns true
│
├─ 3. Add initial consumers
│     emailOracleAuth.addConsumer(signupAgentAppId)
│     emailOracleAuth.addConsumer(authAgentAppId)
│
└─ 4. (Optional) Transfer ownership to multisig / DAO
      emailOracleAuth.transferOwnership(multisigAddress)
```

Note: `appId` is the address of this contract itself once deployed. Use `CREATE2` or the `DstackKms.deployAndRegisterApp()` factory (if adapting to UUPS) to predict the address. Alternatively, deploy first, then set `appId` via an initializer.

### 4.2 Oracle Boot

```
CVM boots → dstack guest-agent
│
├─ 1. Guest agent generates TDX quote with AppBootInfo
│     { appId, composeHash, instanceId, deviceId, mrAggregated, ... }
│
├─ 2. KMS calls DstackKms.isAppAllowed(bootInfo)
│     → DstackKms checks: app registered? OS image allowed?
│     → DstackKms delegates: EmailOracleAuth.isAppAllowed(bootInfo)
│       → checks allowedComposeHashes[bootInfo.composeHash]
│       → checks device restriction
│       → returns (true, "")
│
├─ 3. KMS provisions keys to the CVM
│     derive_key("email/creds") → email credentials AES key
│     derive_key("/oracle", "ethereum") → secp256k1 signing key
│
├─ 4. Oracle decrypts email credentials, connects IMAP
│
└─ 5. Oracle posts boot attestation on-chain
      emailOracleAuth.postBootAttestation(
          keccak256("a3f8c1d9@firemail.cc"),
          composeHash,
          dstackProof    // proves this call came from inside the TEE
      )
      → contract verifies DStack signature chain
      → emits BootAttestationPosted event
      → stores attestation record
```

### 4.3 Pin Request (Off-Chain, with On-Chain Audit)

```
Consumer CVM                          Email Oracle CVM
│                                     │
├─ 1. derive_key("/consumer", "ethereum")
│     → get consumer's signing key     │
│                                     │
├─ 2. POST /pin                       │
│     { from, subject_contains,        │
│       max_age_seconds, appId }       │
│     + DStack signature chain         │
│                                     │
│                            ┌────────┤
│                            │ 3. Verify consumer's DStack proof
│                            │    - signature chain valid?
│                            │    - kmsRoot matches?
│                            │
│                            │ 4. Check on-chain:
│                            │    EmailOracleAuth.isConsumerAllowed(consumerAppId)
│                            │    → true
│                            │
│                            │ 5. Poll IMAP inbox, extract pin
│                            │
│                            │ 6. Return pin + oracle's DStack proof
│                            └────────┤
│                                     │
│◀── { pin: "482917", proof: ... } ──│
│                                     │
├─ 7. Verify oracle's DStack proof    │
├─ 8. Use pin for signup              │
│                                     │
│                            ┌────────┤
│                            │ 9. (Optional) Log delivery on-chain
│                            │    emailOracleAuth.logPinDelivery(
│                            │        requestHash, consumer, pinHash, proof
│                            │    )
│                            │    → emits PinDelivered event
│                            └────────┘
```

### 4.4 Code Upgrade (Timelocked)

```
Day 0: Owner builds new docker image, computes new compose hash

Day 0: emailOracleAuth.proposeComposeHash(0xnew...)
       → emits ComposeHashProposed(0xnew..., activatesAt)
       → stakeholders see the proposal on-chain

Day 0-N: Anyone can:
         - Inspect the proposed compose hash
         - Rebuild the docker image and verify it produces the same hash
         - Audit the code changes
         - Exit (stop using the oracle) if they disagree

Day N: emailOracleAuth.activateComposeHash(0xnew...)
       → permissionless call (anyone can trigger after delay)
       → emits ComposeHashActivated(0xnew...)
       → KMS now provisions keys to the new code

Day N+: (Optional) emailOracleAuth.removeComposeHash(0xold...)
        → old code can no longer boot
```

### 4.5 Emergency Revocation

```
Owner detects compromised code version or rogue consumer:

emailOracleAuth.removeComposeHash(0xcompromised...)
→ immediate effect, no timelock
→ KMS stops provisioning keys to that code version
→ running instances continue until reboot (KMS re-check)

emailOracleAuth.removeConsumer(rogueAppId)
→ immediate effect
→ oracle stops serving pins to that consumer
```

## 5. Design Decisions

### 5.1 Why Not Use `DstackApp` Directly?

`DstackApp` (from `🔬/dstack/kms/auth-eth/contracts/DstackApp.sol`) provides compose hash + device allowlisting. We could deploy a vanilla `DstackApp` and manage the consumer allowlist off-chain inside the TEE.

We extend it instead because:

| Concern | DstackApp alone | EmailOracleAuth |
|---------|-----------------|-----------------|
| Consumer allowlist | Config file inside TEE (opaque) | On-chain mapping (transparent, auditable) |
| Code upgrade notice | Instant (owner calls `addComposeHash`) | Timelocked (N-day delay, stakeholders can exit) |
| Boot attestation | Not recorded on-chain | On-chain record with DStack proof |
| Pin delivery audit | No visibility | On-chain events with hashed receipts |
| Verifiability | Trust the operator | Verify the chain |

The oracle's value proposition is *trustlessness*. Putting governance on-chain makes the trust model explicit and auditable.

### 5.2 Why Timelock?

From `🔬/amiller/dstack-tutorial/08-extending-appauth/TimelockAppAuth.sol`:

> Trust model: "I can exit in time" vs "trust the operator"

Without timelock, the owner can instantly push a malicious code update that exfiltrates email credentials. With timelock, consumers have N days to:
- Audit the proposed code
- Verify the compose hash matches the published source
- Stop relying on the oracle if they disagree

Emergency revocation (removing a hash) remains instant — the timelock only applies to *adding* new code.

### 5.3 Why On-Chain Consumer Allowlist?

The alternative is an off-chain config file inside the TEE listing `(compose_hash, deployer_id)` tuples. Problems:

1. **Opaque** — no one outside the TEE can verify who is authorized
2. **Bundled with code** — changing the allowlist requires a new compose hash (and a timelock cycle)
3. **No audit trail** — no record of when consumers were added/removed

On-chain allowlist means:
- Anyone can call `isConsumerAllowed(appId)` to check authorization
- `ConsumerAdded` / `ConsumerRemoved` events provide a full audit trail
- Allowlist changes are independent of code changes

### 5.4 Why Log Attestations On-Chain?

The boot attestation record serves as a public proof that:
- A specific email address (hashed) is controlled by a specific TEE
- The TEE was running a specific compose hash at boot time
- The DStack signature chain is valid (verified by the contract)

This enables third parties to verify the oracle's identity without direct TEE interaction. They can check the contract events and verify the chain: `kmsRoot → appKey → derivedKey → emailHash`.

### 5.5 Why Not UUPS Proxy?

The `DstackApp` reference uses UUPS for upgradability. We choose a non-upgradable deployment because:

1. The oracle's security depends on code immutability — if the contract can be upgraded, the owner can silently change the rules
2. Timelock governance applies to *compose hashes* (TEE code), not the contract itself
3. If the contract needs changes, deploy a new one and re-register — the timelock ensures transparency
4. Simpler attack surface — no proxy storage collision risks

### 5.6 Gas Considerations

| Operation | Estimated Gas | Frequency |
|-----------|--------------|-----------|
| Deploy | ~2M | Once |
| proposeComposeHash | ~50K | Rare (code upgrades) |
| activateComposeHash | ~30K | Rare |
| addConsumer / removeConsumer | ~50K | Rare |
| postBootAttestation | ~150K | Once per oracle boot |
| logPinDelivery | ~50K | Per pin delivery |
| isAppAllowed (view) | ~5K | Every boot (KMS calls) |
| isConsumerAllowed (view) | ~3K | Every pin request |

Pin delivery logging is optional. At ~50K gas per log on Base (~$0.001 at current gas prices), it's feasible for moderate volumes. For high-throughput scenarios, batch logs or skip on-chain logging entirely (the off-chain mutual attestation already provides accountability).

## 6. Security Analysis

### 6.1 Contract Threats

| # | Threat | Mitigation |
|---|--------|------------|
| C1 | Owner instantly pushes malicious compose hash | Timelock requires N-day notice. Emergency removal is instant (safe direction). |
| C2 | Owner adds rogue consumer | On-chain event trail. Consumers monitor `ConsumerAdded` events. Timelock could be extended to consumer adds if needed. |
| C3 | Fake boot attestation (non-TEE origin) | DStack signature chain verified on-chain. Requires valid kmsRoot → appKey → derivedKey chain. Cannot be forged without KMS compromise. |
| C4 | Replay of old attestation/delivery proof | Each DStack proof contains a unique `messageHash`. Attestations are append-only. Deliveries use unique `requestHash`. |
| C5 | Contract upgrade changes rules silently | No UUPS proxy. Contract is immutable after deployment. |
| C6 | Owner key compromise | Transfer ownership to multisig (Gnosis Safe). Consider 2-of-3 or 3-of-5 threshold. |
| C7 | KMS root key rotation | `kmsRoot` is immutable in the contract. If Phala rotates the KMS root, deploy a new contract. This is intentional — the trust anchor shouldn't change silently. |

### 6.2 Interaction with TEE Threat Model

The contract complements the TEE threat model from `SPEC.md`:

| SPEC Threat | Contract Role |
|-------------|---------------|
| T2 (malicious code deployment) | Contract enforces compose hash allowlist with timelock |
| T4 (pin interception in transit) | Delivery receipts on-chain prove correct routing |
| T6 (rogue consumer) | On-chain consumer allowlist, transparent and auditable |
| T7 (provider reads email) | Out of scope for contract — mitigated by pin ephemerality |
| T10 (TEE crash, credential loss) | Boot attestation log shows oracle recovery history |

## 7. Implementation Plan

### Phase 1: Core Contract

```
contracts/
├── src/
│   ├── EmailOracleAuth.sol         Main contract
│   ├── IDstackVerifier.sol         DStack sig chain verification (extracted)
│   └── IEmailOracleAuth.sol        Interface
├── test/
│   ├── EmailOracleAuth.t.sol       Unit tests
│   ├── Timelock.t.sol              Timelock-specific tests
│   └── DstackVerifier.t.sol        Signature chain verification tests
├── script/
│   └── Deploy.s.sol                Deployment script
├── foundry.toml
└── .env.example
```

### Phase 2: Testing

- Unit tests for all state transitions (propose/activate/cancel/remove)
- Fuzz tests for signature verification edge cases
- Integration test with forked Base Sepolia (verify against live DstackKms)
- Gas snapshot for all operations

### Phase 3: Deployment

1. Deploy to Base Sepolia via `/forge-deploy`
2. Register with DstackKms on Base Sepolia
3. Verify on BaseScan via `/forge-verify`
4. Add initial compose hash + consumers
5. Test full flow: oracle boot → attestation post → pin delivery → log

### Phase 4: Production

1. Deploy to Base mainnet
2. Transfer ownership to multisig
3. Set notice period to production value (e.g., 2 days)
4. Register with production DstackKms

## 8. Reference Contracts

| Contract | Location | What We Take From It |
|----------|----------|---------------------|
| `DstackApp` | `🔬/dstack/kms/auth-eth/contracts/DstackApp.sol` | `isAppAllowed` pattern, compose hash + device allowlist |
| `DstackKms` | `🔬/dstack/kms/auth-eth/contracts/DstackKms.sol` | Registration flow, `isAppAllowed` delegation |
| `IAppAuth` | `🔬/dstack/kms/auth-eth/contracts/IAppAuth.sol` | `AppBootInfo` struct, interface ID `0x1e079198` |
| `TimelockAppAuth` | `🔬/amiller/dstack-tutorial/08-extending-appauth/TimelockAppAuth.sol` | Timelock pattern: propose → wait → activate |
| `TeeOracle` | `🔬/amiller/dstack-tutorial/05-onchain-authorization/TeeOracle.sol` | DStack signature chain verification (`verify()`) |
| `GroupAuth` | `🔬/amiller/github-zktls-1/contracts/examples/GroupAuth.sol` | `DstackProof` struct, `_verifyDstackChain()` |

## 9. Open Questions

1. **Timelock for consumer adds?** Currently `addConsumer` is instant. Should it also be timelocked? Pro: prevents owner from instantly routing pins to a rogue app. Con: slower incident response if a legitimate consumer needs urgent access.

2. **Notice period duration?** 2 days is used in the tutorial demos. Production could be 7 days for higher assurance. Tradeoff: longer notice = more safety but slower iteration.

3. **Pin delivery logging frequency?** Every delivery (~$0.001/log on Base) or batched? Could accumulate hashes in a Merkle tree off-chain and post roots periodically.

4. **KMS root rotation?** Currently `kmsRoot` is immutable. If Phala rotates the KMS root key, we need a new contract. Alternative: make it owner-settable with its own timelock. Risk: adds an attack surface.

5. **Same-compose consumer shortcut?** If the consumer is a service in the same `docker-compose.yaml`, they share `app_id` and don't need on-chain consumer auth (they share derived keys). Should the contract distinguish this case, or leave it to the TEE layer?
