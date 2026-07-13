# On-Chain Attestation Logging Spec

**Status**: Not started
**Depends on**: DiligenceRoom.sol, dstack KMS, TDX quote generation

## Problem

Currently, TDX attestation quotes are generated but never published on-chain. The `control_plane.py:_get_tdx_quote()` creates a quote and attaches it to `EvaluationResult.tdx_quote`, but this is only returned via the HTTP API. There's no permanent, auditable record that a specific evaluation was performed by a specific TEE instance running verified code.

## What EXISTS

### TDX Quote Generation (control_plane.py:319-331)

```python
def _get_tdx_quote(deal_id, result):
    report_data = f"{deal_id}:{result.score_band.value}:{result.offer_price}"
    quote = TappdClient().tdx_quote(report_data)
    return quote
```

- Quote binds `deal_id + score_band + offer_price` to the enclave identity
- Only runs when `DSTACK_ENABLED=true`

### Card Channel Attestation (card_channel.py:108-138)

```python
def get_attestation():
    quote = TappdClient().tdx_quote("billing-attestation")
    return {"quote": quote.hex(), "encryption_public_key": keypair.public_key_bytes.hex()}
```

- Billing attestation available via `GET /attestation`
- Includes encryption public key for card channel

### Email Oracle Attestation (email_oracle/api.py:179-199)

- `GET /attestation` returns TDX quote + app_id + compose_hash
- Stub in local mode

### DiligenceRoom.sol

- `resultHash` field in Deal struct — currently just `keccak256(result)` submitted by TEE
- No TDX quote stored on-chain

## Design

### Option A: On-Chain Quote Storage (Simple)

Add a mapping in DiligenceRoom.sol to store TDX quotes alongside results:

```solidity
mapping(uint256 => bytes) public attestationQuotes;

function submitResult(
    uint256 dealId,
    ScoreBand scoreBand,
    uint256 computeCost,
    bytes32 resultHash,
    bytes calldata tdxQuote  // NEW: raw TDX quote bytes
) external {
    // ... existing validation ...
    attestationQuotes[dealId] = tdxQuote;
    // ... rest of function
}
```

**Pros**: Simple, all data on-chain
**Cons**: TDX quotes are ~5KB, expensive to store on-chain (~0.1 ETH at current gas prices on mainnet, cheap on Base)

### Option B: Quote Hash On-Chain, Full Quote Off-Chain (Recommended)

Store only the hash on-chain, publish the full quote to IPFS or a data availability layer:

```solidity
struct Deal {
    // ... existing fields ...
    bytes32 attestationHash;  // keccak256(tdxQuote)
}

function submitResult(
    uint256 dealId,
    ScoreBand scoreBand,
    uint256 computeCost,
    bytes32 resultHash,
    bytes32 attestationHash  // keccak256 of the TDX quote
) external {
    d.attestationHash = attestationHash;
}
```

The TEE publishes the full quote to:
1. IPFS (via Pinata or similar) — content-addressed, permanent
2. The TEE's own API endpoint: `GET /deal/{deal_id}/attestation`
3. Both (belt and suspenders)

Anyone can verify: fetch quote from IPFS/API, check `keccak256(quote) == attestationHash`, then verify the TDX quote cryptographically.

### Option C: Separate Attestation Log Contract

A dedicated contract for attestation logging, independent of the escrow:

```solidity
contract AttestationLog {
    struct Attestation {
        address reporter;        // TEE identity
        bytes32 dealId;
        bytes32 resultHash;
        bytes32 quoteHash;
        uint256 timestamp;
    }

    Attestation[] public attestations;
    mapping(bytes32 => uint256) public dealToAttestation;

    event AttestationLogged(
        uint256 indexed index,
        bytes32 indexed dealId,
        address reporter,
        bytes32 quoteHash
    );

    function log(bytes32 dealId, bytes32 resultHash, bytes32 quoteHash) external {
        uint256 idx = attestations.length;
        attestations.push(Attestation({
            reporter: msg.sender,
            dealId: dealId,
            resultHash: resultHash,
            quoteHash: quoteHash,
            timestamp: block.timestamp
        }));
        dealToAttestation[dealId] = idx;
        emit AttestationLogged(idx, dealId, msg.sender, quoteHash);
    }
}
```

**Pros**: Clean separation of concerns, reusable for other TEE apps
**Cons**: Extra contract deployment, two transactions per result submission

### Recommendation: Option B for v1

Cheapest gas, simplest change to existing contract. Add `attestationHash` field to Deal struct and `submitResult` parameters. Publish full quotes to the TEE's API.

## What to Log

Each attestation record should bind:

| Field | Source | Purpose |
|---|---|---|
| deal_id | DiligenceRoom | Links to specific deal |
| score_band | EvaluationResult | What the TEE reported |
| offer_price | EvaluationResult | Computed offer |
| compute_cost_wei | CostMeter | Metered API costs |
| result_hash | keccak256(EvaluationResult) | Full result integrity |
| tdx_quote | TappdClient.tdx_quote() | Enclave identity proof |
| app_id | TappdClient.info() | Which app (compose hash) |
| timestamp | block.timestamp | When submitted |

## Implementation Plan

### Phase 1: Add attestationHash to DiligenceRoom
1. Add `bytes32 attestationHash` to Deal struct
2. Add parameter to `submitResult()`
3. Update tests
4. Update Python side to compute and submit hash

### Phase 2: Full Quote Publication
1. Add `GET /deal/{deal_id}/attestation` endpoint to tinker-delegate API
2. Store TDX quotes in memory (or disk) keyed by deal_id
3. Optional: publish to IPFS

### Phase 3: Verification Tooling
1. CLI tool to verify an attestation: fetch quote → verify TDX signature → check result hash
2. On-chain verifier (optional): verify TDX quote components on-chain using precompile or off-chain oracle

## Gas Cost Estimates (Base)

| Operation | Gas | Cost (at 0.01 gwei on Base) |
|---|---|---|
| Store bytes32 hash | ~22,000 | ~$0.001 |
| Store 5KB quote | ~800,000 | ~$0.04 |
| Emit event with hash | ~2,000 | ~$0.0001 |

Base is cheap enough that even Option A (full quote on-chain) is viable. But Option B is cleaner architecturally.

## Files to Create/Modify

| File | Action |
|---|---|
| `contracts/src/DiligenceRoom.sol` | Add `attestationHash` to struct and `submitResult` |
| `contracts/test/DiligenceRoom.t.sol` | Update tests |
| `tinker_delegate/control_plane.py` | Compute attestation hash, submit with result |
| `tinker_delegate/api.py` | Add `GET /deal/{id}/attestation` endpoint |
